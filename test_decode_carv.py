import json
import math
import struct
import subprocess
import sys
import unittest
from pathlib import Path

from decode_carv import CAPTURED_FRAMES, decode_hex, decode_packet, json_safe


class DecoderTests(unittest.TestCase):
    def test_offsets_endianness_and_scaling(self):
        # Deliberately distinct signed fields and floats expose offset/order errors.
        packet = struct.pack('<B8h4f', 0x7F, -1234, -32768, 16384, -8192,
                             4096, 2048, -4096, 8192, 1.25, -2.5, 3.75, 4.5)
        result = decode_packet(packet)
        self.assertEqual(result['quaternion_xyzw'], [-1, .5, -.25, .125])
        self.assertEqual(result['acceleration_xyz'], [1, -2, 4])
        self.assertEqual(result['angular_velocity_xyz'], [1.25, -2.5, 3.75])
        self.assertEqual(result['unused']['int16_at_1'], -1234)
        self.assertEqual(result['unused']['prefix_byte'], 0x7F)
        self.assertEqual(result['unused']['float_at_29'], 4.5)
        self.assertAlmostEqual(result['quaternion_norm'], math.sqrt(1.328125))
        self.assertTrue(result['finite']['all_values'])

    def test_captured_frame_integer_fields(self):
        expected = {
            'A': (-21867, [9922, 22066, -5421, 20447], [2361, 31938, 15787]),
            'B': (-13859, [-6153, 10644, -16982, 14990], [-20710, 8161, 30080]),
        }
        for label, (unused, quaternion, acceleration) in expected.items():
            with self.subTest(frame=label):
                result = decode_hex(CAPTURED_FRAMES[label])
                self.assertEqual(result['packet_length'], 33)
                self.assertEqual(result['unused']['prefix_byte'], 1)
                self.assertEqual(result['unused']['int16_at_1'], unused)
                self.assertEqual(result['raw_quaternion_int16_xyzw'], quaternion)
                self.assertEqual(result['raw_acceleration_int16_xyz'], acceleration)
                self.assertTrue(result['finite']['all_values'])

    def test_captured_float_fields(self):
        expected = {
            'A': ([-1.1266229053939025e29, -1.5807050466537476, 3.6334714139160084e19],
                  -41088.5703125, 0.9807598937482072),
            'B': ([6.027006612412874e-28, -1.5840551472635624e28, -1.4706227473652452e29],
                  -1.7769687510728154e31, 0.7865266044643878),
        }
        for label, (velocity, unused, norm) in expected.items():
            with self.subTest(frame=label):
                result = decode_hex(CAPTURED_FRAMES[label])
                self.assertEqual(result['angular_velocity_xyz'], velocity)
                self.assertEqual(result['unused']['float_at_29'], unused)
                self.assertAlmostEqual(result['quaternion_norm'], norm)

    def test_every_invalid_length(self):
        for length in list(range(33)) + [34, 66]:
            with self.subTest(length=length), self.assertRaises(ValueError):
                decode_packet(bytes(length))

    def test_invalid_hex_and_type(self):
        for value in ['zz', '0', '01gg']:
            with self.assertRaises(ValueError):
                decode_hex(value)
        with self.assertRaises(TypeError):
            decode_packet('0' * 33)

    def test_nonfinite_values_preserved_and_flagged(self):
        packet = struct.pack('<B8h4f', 1, *([0] * 8), math.nan, math.inf, -math.inf, math.nan)
        result = decode_packet(packet)
        self.assertEqual(result['finite']['angular_velocity_xyz'], [False] * 3)
        self.assertFalse(result['finite']['unused_float'])
        self.assertFalse(result['finite']['all_values'])
        self.assertTrue(math.isnan(result['angular_velocity_xyz'][0]))
        safe = json_safe(result)
        self.assertEqual(safe['angular_velocity_xyz'], ['NaN', 'Infinity', '-Infinity'])
        json.dumps(safe, allow_nan=False)

    def test_cli_defaults_and_invalid_input(self):
        script = str(Path(__file__).with_name('decode_carv.py'))
        run = subprocess.run([sys.executable, script], capture_output=True, text=True, check=True)
        self.assertEqual(set(json.loads(run.stdout)), {'A', 'B'})
        invalid = subprocess.run([sys.executable, script, '01'], capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 2)
        self.assertIn('expected exactly 33 bytes', invalid.stderr)


if __name__ == '__main__':
    unittest.main()
