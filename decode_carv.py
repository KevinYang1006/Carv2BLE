"""Offline interpretation of 33-byte values using upstream Carv2Data.swift offsets."""

import argparse
import json
import math
import struct

CAPTURED_FRAMES = {
    "A": "0195aac2263256d3eadf4f3909c27cab3d0804b6ef8b54cabf6b1ffc5f928020c7",
    "B": "01ddc9f7e79429aabd8e3a1aafe11f8075e3003f12fdbb4cee8897edeff54860f3",
}
PACKET_SIZE = 33


def decode_packet(packet: bytes) -> dict:
    """Decode exactly one packet; no claim about packet type or physical units.

    Quaternion components are returned before any rotation-library normalization.
    Unknown prefix values and nonfinite floats are preserved, not rejected.
    """
    if not isinstance(packet, bytes):
        raise TypeError("packet must be bytes")
    if len(packet) != PACKET_SIZE:
        raise ValueError(f"expected exactly {PACKET_SIZE} bytes, got {len(packet)}")
    words = struct.unpack_from("<8h", packet, 1)
    floats = struct.unpack_from("<4f", packet, 17)
    quaternion = [v / 32768 for v in words[1:5]]
    acceleration = [v / 32768 * 16 for v in words[5:8]]
    angular_velocity = list(floats[:3])
    norm = math.sqrt(sum(v * v for v in quaternion))
    finite = {
        "quaternion_xyzw": [math.isfinite(v) for v in quaternion],
        "acceleration_xyz": [math.isfinite(v) for v in acceleration],
        "angular_velocity_xyz": [math.isfinite(v) for v in angular_velocity],
        "unused_float": math.isfinite(floats[3]),
        "quaternion_norm": math.isfinite(norm),
    }
    finite["all_values"] = all(
        all(value) if isinstance(value, list) else value
        for value in finite.values()
    )
    return {
        "packet_hex": packet.hex(),
        "packet_length": len(packet),
        "interpretation": "upstream layout only; packet type and physical units unvalidated",
        "raw_quaternion_int16_xyzw": list(words[1:5]),
        "quaternion_xyzw": quaternion,
        "quaternion_norm": norm,
        "raw_acceleration_int16_xyz": list(words[5:8]),
        "acceleration_xyz": acceleration,
        "angular_velocity_xyz": angular_velocity,
        "unused": {
            "prefix_byte": packet[0],
            "int16_at_1": words[0],
            "normalized_int16_at_1": words[0] / 32768,
            "float_at_29": floats[3],
            "bytes_29_32_hex": packet[29:33].hex(),
        },
        "finite": finite,
    }


def decode_hex(value: str) -> dict:
    """Decode hex, allowing whitespace as bytes.fromhex does."""
    try:
        packet = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("invalid hexadecimal packet") from exc
    return decode_packet(packet)


def json_safe(value):
    """Represent nonfinite numbers as strings for standards-compliant JSON."""
    if isinstance(value, float) and not math.isfinite(value):
        return "NaN" if math.isnan(value) else ("Infinity" if value > 0 else "-Infinity")
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("frames", nargs="*", metavar="HEX", help="33-byte hex frames; defaults to captured A and B")
    args = parser.parse_args()
    frames = dict(enumerate(args.frames, 1)) if args.frames else CAPTURED_FRAMES
    try:
        results = {str(label): decode_hex(value) for label, value in frames.items()}
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(json_safe(results), indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
