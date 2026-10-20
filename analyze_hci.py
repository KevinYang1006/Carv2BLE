"""Offline pcapng Bluetooth H4/ATT analysis. Never connects to devices."""
import argparse
from collections import defaultdict
import json
import struct
import uuid


class CaptureError(ValueError):
    pass


def pcapng_packets(path):
    """Yield (seconds, linktype, packet) from EPBs; bound blocks to 64 MiB.

    Supports multiple sections, either byte order, and per-interface tsresol.
    Bluetooth H4 linktypes: 187 (H4), 201 (direction prefix + H4).
    """
    endian = None
    interfaces = []
    next_interface = 0
    with open(path, 'rb') as stream:
        while True:
            header = stream.read(8)
            if not header:
                return
            if len(header) != 8:
                raise CaptureError('truncated block header')
            if header[:4] == b'\x0a\x0d\x0d\x0a':
                magic = stream.read(4)
                endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(magic)
                if endian is None:
                    raise CaptureError('invalid section byte order')
                prefix = magic
                interfaces = []
            else:
                if endian is None:
                    raise CaptureError('missing section header')
                prefix = b''
            kind, size = struct.unpack(endian + 'II', header)
            if size < 12 + len(prefix) or size % 4 or size > 64 * 1024 * 1024:
                raise CaptureError('invalid block size')
            rest = stream.read(size - 8 - len(prefix))
            if len(rest) != size - 8 - len(prefix):
                raise CaptureError('truncated block')
            body = prefix + rest[:-4]
            if struct.unpack(endian + 'I', rest[-4:])[0] != size:
                raise CaptureError('block length trailer mismatch')
            if kind == 1:
                if len(body) < 8:
                    raise CaptureError('short interface block')
                linktype = struct.unpack_from(endian + 'H', body)[0]
                resolution, offset = 1e-6, 0
                pos = 8
                while pos + 4 <= len(body):
                    code, length = struct.unpack_from(endian + 'HH', body, pos)
                    pos += 4
                    if pos + length > len(body):
                        raise CaptureError('truncated interface option')
                    value = body[pos:pos + length]
                    if code == 9 and length == 1:
                        v = value[0]
                        resolution = 2 ** -(v & 127) if v & 128 else 10 ** -v
                    if code == 14 and length == 8:
                        offset = struct.unpack(endian + 'q', value)[0]
                    pos += (length + 3) & ~3
                    if code == 0:
                        break
                interfaces.append((next_interface, linktype, resolution, offset))
                next_interface += 1
            elif kind == 6:
                if len(body) < 20:
                    raise CaptureError('short enhanced packet block')
                interface, high, low, captured, original = struct.unpack_from(endian + '5I', body)
                if interface >= len(interfaces) or 20 + ((captured + 3) & ~3) > len(body):
                    raise CaptureError('invalid enhanced packet block')
                if captured < original:
                    raise CaptureError('snaplen-truncated packet; use a full capture')
                identity, linktype, resolution, offset = interfaces[interface]
                yield offset + ((high << 32) | low) * resolution, (identity, linktype), body[20:20 + captured]
            elif kind in (2, 3):
                raise CaptureError('obsolete/simple packet blocks unsupported; convert to enhanced packet blocks')


def uuid_text(raw):
    if len(raw) == 2:
        return f'{int.from_bytes(raw, "little"):04x}'
    if len(raw) == 16:
        return str(uuid.UUID(bytes=raw[::-1]))
    raise CaptureError('invalid ATT UUID width')


class Analyzer:
    def __init__(self, burst_count=5, burst_window=1.0):
        self.active = {}
        self.connections = []
        self.buffers = {}
        self.pending = {}
        self.warnings = []
        self.burst_count = burst_count
        self.burst_window = burst_window

    def connection(self, interface, handle):
        key = (interface, handle)
        if key not in self.active:
            connection = {'id': len(self.connections) + 1, 'interface': interface,
                          'hci_handle': f'0x{handle:04x}', 'events': [],
                          'characteristics': {}, 'descriptors': {}, 'services': []}
            self.connections.append(connection)
            self.active[key] = connection
        return self.active[key]

    def close(self, interface, handle):
        connection = self.active.pop((interface, handle), None)
        if connection:
            cid = connection['id']
            self.buffers = {k: v for k, v in self.buffers.items() if k[0] != cid}
            self.pending = {k: v for k, v in self.pending.items() if k[0] != cid}

    def feed(self, timestamp, interface, linktype, packet):
        direction = 'unknown'
        if linktype == 201:
            if len(packet) < 5:
                raise CaptureError('short H4 direction packet')
            flag = int.from_bytes(packet[:4], 'big')
            if flag not in (0, 1):
                raise CaptureError('invalid H4 direction flag')
            direction = 'host_to_controller' if flag == 0 else 'controller_to_host'
            packet = packet[4:]
        elif linktype != 187:
            raise CaptureError(f'unsupported linktype {linktype}; use Bluetooth H4 (187/201)')
        if not packet:
            raise CaptureError('empty H4 packet')
        if packet[0] == 4:  # HCI events: disconnect and successful LE connection complete
            if len(packet) < 3 or len(packet) != 3 + packet[2]:
                raise CaptureError('invalid HCI event length')
            payload = packet[3:]
            if packet[1] == 5 and len(payload) >= 4 and payload[0] == 0:
                self.close(interface, int.from_bytes(payload[1:3], 'little') & 0xfff)
            elif packet[1] == 0x3e and len(payload) >= 4 and payload[0] in (1, 10, 41) and payload[1] == 0:
                handle = int.from_bytes(payload[2:4], 'little') & 0xfff
                self.close(interface, handle)
                self.connection(interface, handle)
            return
        if packet[0] != 2:
            return
        if len(packet) < 5:
            raise CaptureError('short ACL header')
        flags, length = struct.unpack_from('<HH', packet, 1)
        if len(packet) != length + 5:
            raise CaptureError('ACL length mismatch')
        handle, boundary = flags & 0xfff, (flags >> 12) & 3
        connection = self.connection(interface, handle)
        key = (connection['id'], direction)
        payload = packet[5:]
        if boundary == 1:
            if key not in self.buffers:
                self.warnings.append(f'orphan ACL continuation at {timestamp}')
                return
            self.buffers[key][1].extend(payload)
        else:
            if key in self.buffers:
                self.warnings.append(f'incomplete ACL message replaced at {timestamp}')
            self.buffers[key] = [timestamp, bytearray(payload)]
        started, data = self.buffers[key]
        if len(data) < 4:
            return
        size, channel = struct.unpack_from('<HH', data)
        if len(data) < size + 4:
            return
        del self.buffers[key]
        if len(data) != size + 4:
            self.warnings.append(f'L2CAP size mismatch at {timestamp}')
            return
        if channel == 4:
            self.att(connection, direction, started, timestamp, bytes(data[4:]))
        # Other fixed/dynamic channels, including EATT, are not decoded.

    def att(self, connection, direction, started, completed, data):
        if not data:
            raise CaptureError('empty ATT PDU')
        opcode = data[0]
        cid = connection['id']
        reverse = {'host_to_controller': 'controller_to_host', 'controller_to_host': 'host_to_controller', 'unknown': 'unknown'}[direction]
        names = {1: 'error_response', 2: 'mtu_request', 3: 'mtu_response',
                 4: 'find_information_request', 5: 'find_information_response',
                 8: 'read_by_type_request', 9: 'read_by_type_response',
                 10: 'read_request', 11: 'read_response', 12: 'read_blob_request', 13: 'read_blob_response',
                 16: 'read_by_group_request', 17: 'read_by_group_response',
                 18: 'write_request', 19: 'write_response', 22: 'prepare_write_request',
                 23: 'prepare_write_response', 24: 'execute_write_request', 25: 'execute_write_response',
                 27: 'notification', 29: 'indication', 30: 'confirmation', 82: 'write_command', 210: 'signed_write_command'}
        event = {'time': started, 'completed_time': completed, 'direction': direction,
                 'operation': names.get(opcode, f'att_0x{opcode:02x}'), 'opcode': f'0x{opcode:02x}', 'att_length': len(data)}
        connection['events'].append(event)
        request_key = (cid, direction)
        response_key = (cid, reverse)
        if opcode in (4, 8, 10, 12, 16):
            minimum = {4: 5, 8: 7, 10: 3, 12: 5, 16: 7}[opcode]
            if len(data) < minimum:
                raise CaptureError('short ATT request')
            self.pending[request_key] = data
        if opcode in (10, 12, 18, 22, 23, 27, 29, 82, 210):
            if len(data) < 3:
                raise CaptureError('short handle-bearing ATT PDU')
            handle = int.from_bytes(data[1:3], 'little')
            event['handle'] = f'0x{handle:04x}'
            if opcode not in (10, 12):
                offset = 5 if opcode in (22, 23) else 3
                signature = 12 if opcode == 210 else 0
                if len(data) < offset + signature:
                    raise CaptureError('short ATT value')
                value = data[offset:len(data) - signature if signature else len(data)]
                event['value_length'] = len(value)
                # Never emit raw value bytes, even for notifications/read responses.
                if opcode in (18, 22, 82, 210) and len(value) == 33:
                    event['sensitive'] = 'potential session/authentication payload; value omitted'
                event['_value'] = value
        request = self.pending.get(response_key)
        matching = {5: 4, 9: 8, 11: 10, 13: 12, 17: 16}
        if opcode in matching and request and request[0] == matching[opcode]:
            del self.pending[response_key]
            if opcode in (11, 13):
                event['handle'] = f'0x{int.from_bytes(request[1:3], "little"):04x}'
                event['value_length'] = len(data) - 1
            elif opcode in (9, 17):
                if len(data) < 2:
                    raise CaptureError('short discovery response')
                width = data[1]
                if width == 0 or (len(data) - 2) % width:
                    raise CaptureError('invalid discovery entry length')
                kind = uuid_text(request[5:])
                for pos in range(2, len(data), width):
                    row = data[pos:pos + width]
                    if opcode == 9 and kind == '2803' and width in (7, 21):
                        declaration, properties, handle = struct.unpack_from('<HBH', row)
                        connection['characteristics'][f'0x{handle:04x}'] = {
                            'uuid': uuid_text(row[5:]), 'declaration_handle': declaration, 'properties': properties}
                    elif opcode == 17 and kind in ('2800', '2801') and width in (6, 20):
                        start, end = struct.unpack_from('<HH', row)
                        connection['services'].append({'start': start, 'end': end, 'uuid': uuid_text(row[4:])})
            elif opcode == 5:
                self.discovery_descriptors(connection, data)
        elif opcode == 5:
            # Find Information is self-describing, even if capture starts mid-discovery.
            self.discovery_descriptors(connection, data)
        if opcode == 1:
            if len(data) != 5:
                raise CaptureError('invalid ATT error response')
            event['failed_opcode'] = f'0x{data[1]:02x}'
            event['handle'] = f'0x{int.from_bytes(data[2:4], "little"):04x}'
            event['error_code'] = data[4]
            self.pending.pop(response_key, None)

    def discovery_descriptors(self, connection, data):
        if len(data) < 2 or data[1] not in (1, 2):
            raise CaptureError('invalid find information response')
        width = 4 if data[1] == 1 else 18
        if (len(data) - 2) % width:
            raise CaptureError('truncated find information entry')
        for pos in range(2, len(data), width):
            handle = int.from_bytes(data[pos:pos + 2], 'little')
            connection['descriptors'][f'0x{handle:04x}'] = uuid_text(data[pos + 2:pos + width])

    def report(self):
        for connection in self.connections:
            characteristics = connection['characteristics']
            descriptors = connection['descriptors']
            streams = defaultdict(list)
            onset = None
            for event in connection['events']:
                handle = event.get('handle')
                if handle in characteristics:
                    event['characteristic_uuid'] = characteristics[handle]['uuid']
                if handle in descriptors:
                    event['attribute_uuid'] = descriptors[handle]
                value = event.pop('_value', None)
                if descriptors.get(handle) == '2902' and value is not None and len(value) == 2:
                    event['cccd_bits'] = int.from_bytes(value, 'little')
                if event['operation'] in ('notification', 'indication'):
                    samples = streams[handle]
                    samples.append(event['completed_time'])
                    if len(samples) >= self.burst_count and samples[-1] - samples[-self.burst_count] <= self.burst_window:
                        candidate = samples[-self.burst_count]
                        onset = candidate if onset is None else min(onset, candidate)
            for event in connection['events']:
                event['before_stream_estimate'] = None if onset is None else event['completed_time'] < onset
            connection['notification_summary'] = {handle: {'count': len(times), 'first_time': times[0], 'last_time': times[-1]} for handle, times in streams.items()}
            connection['stream_onset_estimate'] = onset
            connection['events_before_stream'] = [i for i, e in enumerate(connection['events']) if onset is not None and e['completed_time'] < onset]
        return {'connections': self.connections, 'warnings': self.warnings + ([f'{len(self.buffers)} incomplete ACL messages at EOF'] if self.buffers else []),
                'limitations': ['Values omitted; 33-byte writes treated as sensitive.',
                                'Handle UUIDs require captured discovery; missing mappings remain unknown.',
                                'Stream onset is a notification-density heuristic, not proof of motion.',
                                'Only fixed ATT CID 0x0004; EATT and radio/link-layer captures unsupported.',
                                'H4 without direction cannot reliably separate simultaneous bidirectional fragments.',
                                'Connections are HCI-handle sessions, not confirmed sensor identities.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    parser.add_argument('--output', help='JSON report path (otherwise stdout)')
    parser.add_argument('--burst-count', type=int, default=5)
    parser.add_argument('--burst-window', type=float, default=1.0, help='seconds')
    args = parser.parse_args()
    if args.burst_count < 2 or args.burst_window <= 0:
        parser.error('burst count must be >=2 and window positive')
    analyzer = Analyzer(args.burst_count, args.burst_window)
    try:
        for timestamp, (interface, linktype), packet in pcapng_packets(args.capture):
            analyzer.feed(timestamp, interface, linktype, packet)
        report = json.dumps(analyzer.report(), indent=2)
        if args.output:
            with open(args.output, 'w') as stream:
                stream.write(report + '\n')
        else:
            print(report)
    except (OSError, ValueError, struct.error) as exc:
        parser.exit(2, f'error: {exc}\n')


if __name__ == '__main__':
    main()
