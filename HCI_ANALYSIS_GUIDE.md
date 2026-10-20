# Offline Android Bluetooth HCI / ATT analysis

`analyze_hci.py` accepts a **pcapng** capture and writes a JSON report. It uses
only the Python standard library. It never connects to devices or produces
replay commands. All ATT value bytes are omitted, including read responses and
notifications. Every 33-byte outbound write is marked potentially sensitive;
this deliberately includes more than just payloads beginning with 01. No raw
session/authentication payload, hash, or peer Bluetooth address is emitted.
Keep the original capture private: it may contain sensitive information that
is absent from the report.

## Usage

Run from the repository root with Python 3 (tested on 3.12):

```sh
python analyze_hci.py session.pcapng --output timeline.json
python analyze_hci.py session.pcapng --burst-count 10 --burst-window 2 --output timeline.json
python -m unittest -v
```

The file must contain Enhanced Packet Blocks with Bluetooth H4 linktype 201
(direction prefix plus H4, common for exported Android captures) or 187 (H4).
This is not a parser for raw Android btsnoop files. If your original is btsnoop,
open it in Wireshark and save/export as pcapng, preserving the HCI encapsulation,
full packet contents and direction. Do not export decrypted traffic to public
services. Unsupported encapsulations and snaplen-truncated packets fail with an
explicit error; no package or external executable is required by this tool.

## What the report contains

- `connections`: separate sessions keyed internally by interface and HCI
  connection handle. Successful LE Connection Complete / Enhanced Connection
  Complete and Disconnection Complete events delimit handle reuse. A capture
  beginning mid-session creates a provisional session from ACL traffic. IDs
  identify connection sessions, not confirmed left/right sensor identities.
- `events`: capture-order ATT timeline, with first-fragment `time` and
  `completed_time` in capture-clock seconds. Direction, opcode, operation,
  handle (where applicable), ATT PDU length, and value length are included.
  ATT headers, prepare-write offsets and signed-write signatures are excluded
  from value lengths. Request-correlated read/read-blob responses get handles.
  Error responses include failed opcode, error code and handle.
- `characteristics`: value-handle → UUID, declaration handle and property bits,
  learned from Read By Type requests for UUID 2803 and responses. Both 16-bit
  and 128-bit UUIDs are supported. Discovery requests must be present to
  interpret Read By Type responses reliably.
- `services`: ranges and UUIDs learned from Read By Group Type discovery of
  primary/secondary services (2800/2801).
- `descriptors`: handle → attribute UUID from Find Information responses.
  These responses can describe any attribute, not only descriptors. A write to
  a discovered 2902 attribute gets decoded `cccd_bits` (1 = notifications,
  2 = indications); command payloads elsewhere remain omitted.
- Events receive `characteristic_uuid` or `attribute_uuid` when captured
  discovery supports the mapping, including discovery later in the same
  session. Missing mappings stay absent. Handles are session-local and are
  never assigned Carv UUIDs by convention.
- `notification_summary`: per-handle notification/indication counts and first/
  last times.
- `stream_onset_estimate`: start of the earliest same-handle burst meeting
  `--burst-count` events within `--burst-window` seconds (defaults: 5 in 1 s).
  `events_before_stream` contains zero-based event indices before that estimate;
  each event also gets `before_stream_estimate`. With no burst these are an
  empty list and null flags. This highlights setup activity for inspection.
- `warnings`: orphan continuations, replaced incomplete messages, size mismatch,
  or unfinished ACL messages at EOF. Do not treat a report with missing traffic
  as a complete handshake record.

## Applying this to the preliminary Carv observations

The preliminary sequence is evidence supplied by the user, not a trace already
processed by this tool:

1. Write 0100 at handle 0x0011.
2. Write a 33-byte value beginning with 01 at 0x0013.
3. Several shorter writes at 0x0013.
4. Enable additional notifications at 0x000D.
5. Notifications at 0x0010 and 0x000C.

Check discovery in **each connection** to establish whether 0x0011 and 0x000D
are CCCDs, and which characteristic value UUIDs correspond to 0x0010, 0x0013
and 0x000C. Numeric adjacency alone is not proof. Compare timelines and burst
onsets separately, including responses/errors, to identify operations preceding
sustained transmission. A write response acknowledges an ATT operation; it does
not prove application-level authentication succeeded.

The 33-byte host-to-sensor value is potentially session/authentication material.
Its size and first byte do not establish that it shares the sensor-to-host
motion layout. Do not feed it into the motion decoder as validated motion or
publish/replay its bytes. The tool marks it without revealing its value.

No actual capture was supplied when this implementation was written. Tests
use synthetic pcapng/ACL/ATT traffic, not a claim that this preliminary sequence
has been independently verified. Run the tool against the private capture and
inspect warnings before drawing conclusions.

## Limits and interpretation

ACL fragments are reassembled per session and direction, then parsed on fixed
L2CAP ATT CID 0x0004. Non-ATT channels are ignored. EATT, LE radio/link-layer
captures, ATT multi-notification PDUs, and some less common ATT procedures are
not decoded into individual value events. Unknown opcodes remain in the
timeline with their PDU length. H4 without a direction prefix cannot reliably
separate simultaneous opposite-direction fragments or correlate requests.
Do not combine multiple controllers into a single undifferentiated interface.

Stream onset is a density heuristic, **not proof of continuous motion data**.
It can detect status bursts or miss slower streams. Adjust thresholds, inspect
per-handle timing, and correlate with known recording/movement intervals. A
command preceding a burst is a correlation, not its proven cause. The report
cannot establish membership requirements, authenticate sensors, or identify
unknown commands. It contains no pairing, firmware, bypass or replay workflow.
