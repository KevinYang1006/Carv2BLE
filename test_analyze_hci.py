import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from analyze_hci import Analyzer, CaptureError, pcapng_packets


def acl(att, handle=1, direction=0, boundary=2, l2cap=True):
    payload = struct.pack('<HH', len(att), 4) + att if l2cap else att
    return struct.pack('>I', direction) + b'\x02' + struct.pack('<HH', handle | boundary << 12, len(payload)) + payload


def block(kind, body, endian='<'):
    body += bytes((-len(body)) % 4)
    size = len(body) + 12
    return struct.pack(endian + 'II', kind, size) + body + struct.pack(endian + 'I', size)


def capture(packet, endian='<'):
    return (block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
            + block(1, struct.pack(endian + 'HHI', 201, 0, 65535), endian)
            + block(6, struct.pack(endian + '5I', 0, 0, 1000000, len(packet), len(packet)) + packet, endian))


class AnalysisTests(unittest.TestCase):
    def test_fragmented_connections_discovery_redaction_and_onset(self):
        a = Analyzer(3, .5)
        # Characteristic declaration: handle 0x0f -> value 0x10 -> 128-bit notify UUID.
        wire_uuid = bytes.fromhex('2dfbfffe960d49098d28f353cb168e8a')[::-1]
        request = b'\x08\x01\x00\xff\xff\x03\x28'
        a.feed(0, 0, 201, acl(request))
        response = b'\x09\x15' + struct.pack('<HBH', 15, 16, 16) + wire_uuid
        pdu = struct.pack('<HH', len(response), 4) + response
        a.feed(.1, 0, 201, acl(pdu[:7], direction=1, l2cap=False))
        # A second connection's fragments must not contaminate the first.
        a.feed(.15, 0, 201, acl(b'\x1b\x0c\x00xyz', handle=2, direction=1))
        a.feed(.2, 0, 201, acl(pdu[7:], direction=1, boundary=1, l2cap=False))
        a.feed(.3, 0, 201, acl(b'\x05\x01\x11\x00\x02\x29', direction=1))
        a.feed(.4, 0, 201, acl(b'\x12\x11\x00\x01\x00'))
        secret = b'\x01' + b'\xab' * 32
        a.feed(.5, 0, 201, acl(b'\x12\x13\x00' + secret))
        for t in (1, 1.1, 1.2):
            a.feed(t, 0, 201, acl(b'\x1b\x10\x00' + bytes(33), direction=1))
        report = a.report()
        conn = report['connections'][0]
        self.assertEqual(len(report['connections']), 2)
        self.assertEqual(conn['characteristics']['0x0010']['uuid'], '2dfbfffe-960d-4909-8d28-f353cb168e8a')
        self.assertEqual(conn['events'][3]['cccd_bits'], 1)
        self.assertEqual(conn['events'][4]['value_length'], 33)
        self.assertIn('sensitive', conn['events'][4])
        self.assertEqual(conn['stream_onset_estimate'], 1)
        self.assertEqual(conn['events_before_stream'], list(range(5)))
        self.assertNotIn('abababab', json.dumps(report))
        self.assertEqual(conn['events'][-1]['characteristic_uuid'], conn['characteristics']['0x0010']['uuid'])

    def test_read_response_and_handle_reuse(self):
        a = Analyzer()
        a.feed(0, 0, 201, acl(b'\x0a\x0c\x00'))
        a.feed(1, 0, 201, acl(b'\x0bhello', direction=1))
        a.feed(2, 0, 201, struct.pack('>I', 1) + b'\x04\x05\x04\x00\x01\x00\x13')
        a.feed(3, 0, 201, acl(b'\x1b\x0c\x00x', direction=1))
        report = a.report()
        self.assertEqual(len(report['connections']), 2)
        event = report['connections'][0]['events'][1]
        self.assertEqual((event['handle'], event['value_length']), ('0x000c', 5))
        self.assertNotIn('hello', json.dumps(report))

    def test_orphan_and_truncated(self):
        a = Analyzer()
        a.feed(0, 0, 201, acl(b'x', boundary=1, l2cap=False))
        a.feed(1, 0, 201, acl(b'\x09', l2cap=False))
        self.assertEqual(len(a.report()['warnings']), 2)
        with self.assertRaises(CaptureError):
            a.feed(1, 0, 201, b'\x00')
        with self.assertRaises(CaptureError):
            a.feed(1, 0, 999, b'x')

    def test_pcapng_both_endians_and_truncation(self):
        packet = acl(b'\x1b\x10\x00abc', direction=1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcapng'
            for endian in ('<', '>'):
                path.write_bytes(capture(packet, endian))
                rows = list(pcapng_packets(path))
                self.assertEqual(rows, [(1., (0, 201), packet)])
            path.write_bytes(capture(packet)[:-1])
            with self.assertRaises(CaptureError):
                list(pcapng_packets(path))

    def test_cli_report_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'session.pcapng'
            output = Path(directory) / 'timeline.json'
            script = str(Path(__file__).with_name('analyze_hci.py'))
            path.write_bytes(capture(acl(b'\x12\x13\x00' + b'\x01' * 33)))
            run = subprocess.run([sys.executable, script, str(path), '--output', str(output)],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            event = json.loads(output.read_text())['connections'][0]['events'][0]
            self.assertEqual(event['value_length'], 33)
            self.assertIn('sensitive', event)
            self.assertNotIn('_value', event)
            path.write_bytes(b'broken')
            run = subprocess.run([sys.executable, script, str(path)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertIn('truncated block header', run.stderr)

    def test_service_discovery_and_unknown_mapping(self):
        a = Analyzer()
        a.feed(0, 0, 201, acl(b'\x10\x01\x00\xff\xff\x00\x28'))
        a.feed(1, 0, 201, acl(b'\x11\x06\x01\x00\x20\x00\x0f\x18', direction=1))
        a.feed(2, 0, 201, acl(b'\x1b\x10\x00x', direction=1))
        conn = a.report()['connections'][0]
        self.assertEqual(conn['services'][0], {'start': 1, 'end': 32, 'uuid': '180f'})
        self.assertNotIn('characteristic_uuid', conn['events'][-1])
        self.assertIsNone(conn['stream_onset_estimate'])


if __name__ == '__main__':
    unittest.main()
