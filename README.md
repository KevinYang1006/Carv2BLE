# Carv 2 offline packet decoder

A standard-library-only Python 3 decoder for **exactly 33 bytes**, based on
[upstream Carv2Data.swift lines 78–103](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakei/Carv2/Carv2Data.swift#L78-L103).
See [CARV2_BLE_ANALYSIS.md](CARV2_BLE_ANALYSIS.md) for protocol evidence and limitations.
That report predates receipt of the full captures; the complete A/B frames are now
included as `CAPTURED_FRAMES` in `decode_carv.py`.

This program only processes bytes offline. It has no Bluetooth dependency, sensor
connection, device command, pairing, or firmware functionality.

## Run

From the repository root, with Python 3 (tested with 3.12):

```sh
# Decode the supplied A and B captures as labeled JSON:
python decode_carv.py

# Decode one or more hex packets (quote whitespace-separated hex):
python decode_carv.py 0195aac2263256d3eadf4f3909c27cab3d0804b6ef8b54cabf6b1ffc5f928020c7

# Run tests:
python -m unittest -v
```

No installation or network access is required. Invalid hex or any length other
than 33 bytes produces an error and exit code 2. Output goes to standard output;
redirect it to a file if desired.

For Python callers:

```python
from decode_carv import decode_hex, decode_packet
result = decode_packet(bytes(33))
# decode_hex accepts a hexadecimal string instead.
```

## Interpretation and output

Offsets are zero-based, inclusive. `struct` formats explicitly select little-endian
standard-width values, with no native alignment or padding:

| Bytes | Interpretation |
| --- | --- |
| 0 | Unknown prefix, returned without requiring `0x01` |
| 1–2 | Unused signed Int16, also returned divided by 32768 |
| 3–10 | Raw signed Int16 quaternion x,y,z,w; decoded components divided by 32768 |
| 11–16 | Raw signed Int16 acceleration x,y,z; decoded components scaled by 16/32768 |
| 17–28 | Three IEEE-754 binary32 values, labeled angular velocity x,y,z by upstream |
| 29–32 | Unused binary32 value, also preserved as raw hex |

The entire packet hex is preserved. Quaternion norm is computed **before any
normalization**; this decoder does not reproduce possible normalization inside
Swift's rotation library. Per-component finite checks cover quaternion,
acceleration, and angular velocity; separate checks cover the unused float and
norm, with `all_values` aggregating the checks. Integer fields are inherently
finite. Nonfinite values are retained by the Python API and flagged; the JSON
CLI represents them as strings `NaN`, `Infinity`, or `-Infinity` to keep valid JSON.

These are raw, source-derived interpretations, **not validated physical units**.
No g, m/s², rad/s, or deg/s conversion is asserted. Packet type, prefix meaning,
unknown fields, and compatibility of these captures with the upstream layout
remain unverified. Passing a finite check only excludes NaN/infinity; it does not
establish physical plausibility or prove that a packet contains motion.

## Captured results

The complete numeric output, including integer fields and unused bytes, is
reproducible with `python decode_carv.py`. Rounded highlights:

| Field | A | B |
| --- | --- | --- |
| Quaternion x,y,z,w | (0.302795, 0.673401, -0.165436, 0.623993) | (-0.187775, 0.324829, -0.518250, 0.457458) |
| Quaternion norm | 0.9807598937 | 0.7865266045 |
| Acceleration x,y,z | (1.152832, 15.594727, 7.708496) | (-10.112305, 3.984863, 14.687500) |
| Angular velocity x,y,z | (-1.126623e29, -1.580705, 3.633471e19) | (6.027007e-28, -1.584055e28, -1.470623e29) |
| Unused Int16 | -21867 | -13859 |
| Unused float | -41088.5703125 | -1.776969e31 |
| Prefix | 1 | 1 |
| All values finite | true | true |

The huge candidate angular velocities and B's non-unit raw quaternion warrant
further investigation. They do not establish encryption, authentication, a
particular alternate layout, or a sensor fault. Do not silently normalize or
change offsets to make the outputs appear plausible. The next useful evidence
is a normal official-app session trace and motion-correlated captures, as
described in the analysis report; no guessed BLE writes are needed.

## Tests

Tests exercise distinct signed boundary values and every field offset, scaling,
quaternion norm, unknown prefix preservation, the actual A/B integer and float
fields, all shorter packet lengths and representative oversized lengths, invalid
hex, NaN/infinity handling, and CLI success/error behavior. These validate the
offline implementation, not sensor behavior or physical units.
