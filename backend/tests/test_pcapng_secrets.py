import importlib
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def block(kind, body, endian='<'):
    size = len(body) + 12
    assert size % 4 == 0
    return struct.pack(endian + 'II', kind, size) + body + struct.pack(endian + 'I', size)


def section(endian='<'):
    return block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)


def secret(value=b'KEY\n', endian='<'):
    return block(10, struct.pack(endian + 'II', 0x544c534b, len(value)) + value + b'\0' * (-len(value) % 4), endian)


class PCAPNGSecretsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'input.pcapng'
        try:
            self.module = importlib.import_module('analyzers.pcapng_secrets')
        except ModuleNotFoundError:
            self.fail('PCAPNG section-local secret normalization is not implemented')

    def normalize(self, original, expected):
        self.path.write_bytes(original)
        with self.module.prepared_pcapng(str(self.path)) as prepared:
            self.assertEqual(Path(prepared).read_bytes(), expected)
            self.assertEqual(self.path.read_bytes(), original)
            if str(prepared) != str(self.path):
                self.assertEqual(os.stat(prepared).st_mode & 0o777, 0o600)
                parent = Path(prepared).parent
        if str(prepared) != str(self.path):
            self.assertFalse(Path(prepared).exists())
            self.assertFalse(parent.exists())

    def test_late_secrets_precede_packets_and_preserve_every_other_byte(self):
        shb = section()
        interface = block(1, struct.pack('<HHI', 1, 0, 65535))
        packet = block(6, struct.pack('<IIIII', 0, 0, 1, 4, 4) + b'data')
        dsb = secret()
        self.normalize(shb + interface + packet + dsb, shb + dsb + interface + packet)

    def test_secrets_remain_in_their_own_section_with_mixed_endianness(self):
        a, b = section(), section('>')
        one, two = secret(b'ONE\n'), secret(b'TWO\n', '>')
        other1, other2 = block(0xbad, b'ABCD'), block(0xbad, b'EFGH', '>')
        self.normalize(a + other1 + one + b + other2 + two, a + one + other1 + b + two + other2)

    def test_multiple_secret_blocks_preserve_order(self):
        a, one, two = section(), secret(), secret(b'END\n')
        unknown = block(0xbad, b'KEEP')
        self.normalize(a + one + unknown + two, a + one + two + unknown)

    def test_capture_without_secrets_uses_original_path(self):
        self.path.write_bytes(section() + block(0xbad, b'KEEP'))
        with self.module.prepared_pcapng(str(self.path)) as prepared:
            self.assertEqual(str(prepared), str(self.path))

    def test_classic_pcap_is_unchanged(self):
        self.normalize(b'\xd4\xc3\xb2\xa1' + b'\0' * 20, b'\xd4\xc3\xb2\xa1' + b'\0' * 20)

    def test_truncated_block_and_mismatched_trailer_are_rejected(self):
        for value in [section() + secret()[:-2], section() + secret()[:-4] + struct.pack('<I', 12), section() + struct.pack('<II', 10, 0), section() + b'\x01']:
            with self.subTest(value=value):
                self.path.write_bytes(value)
                with self.assertRaisesRegex(ValueError, 'PCAPNG'):
                    with self.module.prepared_pcapng(str(self.path)):
                        self.fail('malformed capture was accepted')

    def test_invalid_section_magic_and_secret_length_are_rejected(self):
        invalid = section()[:8] + b'BAD!' + section()[12:]
        oversized_secret = block(10, struct.pack('<II', 0x544c534b, 0xffffffff))
        for value in [invalid, section() + oversized_secret]:
            self.path.write_bytes(value)
            with self.assertRaisesRegex(ValueError, 'PCAPNG'):
                with self.module.prepared_pcapng(str(self.path)):
                    self.fail('invalid capture accepted')

    def test_cleanup_on_consumer_exception(self):
        self.path.write_bytes(section() + block(0xbad, b'KEEP') + secret())
        with self.assertRaisesRegex(RuntimeError, 'consumer'):
            with self.module.prepared_pcapng(str(self.path)) as prepared:
                temp = prepared
                raise RuntimeError('consumer')
        self.assertFalse(Path(temp).exists())

    def test_preparation_does_not_read_entire_capture_into_memory(self):
        from unittest.mock import patch
        original = section() + block(0xbad, b'data' * (1024 * 1024)) + secret()
        self.path.write_bytes(original)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('whole-file read')):
            with self.module.prepared_pcapng(str(self.path)) as prepared:
                with open(prepared, 'rb') as stream:
                    self.assertEqual(stream.read(len(section() + secret())), section() + secret())
                self.assertEqual(os.path.getsize(prepared), len(original))

    def test_parser_cancellation_removes_copy_and_stops_process(self):
        import io
        from unittest.mock import MagicMock, patch
        from analyzers.ecapture_parser import ECaptureParser
        self.path.write_bytes(section() + block(0xbad, b'KEEP') + secret())
        process = MagicMock()
        process.stdout = io.StringIO('')
        process.poll.return_value = None
        parser = ECaptureParser()
        used = []

        def start(command, **kwargs):
            used.append(command[command.index('-r') + 1])
            return process

        with patch.object(parser, '_check_tshark', return_value=True), patch('analyzers.ecapture_parser.subprocess.Popen', side_effect=start), patch.object(parser, 'parse_ek_packets', return_value=iter(['event'])):
            iterator = parser.parse_pcapng_stream(str(self.path))
            self.assertEqual(next(iterator), 'event')
            self.assertTrue(Path(used[0]).exists())
            iterator.close()
        self.assertFalse(Path(used[0]).exists())
        process.terminate.assert_called_once()
        process.wait.assert_called_once()

    def test_parser_uses_normalized_copy_and_cleans_it_on_tshark_failure(self):
        from analyzers.ecapture_parser import ECaptureParser
        from unittest.mock import patch
        self.path.write_bytes(section() + block(0xbad, b'KEEP') + secret())
        used = []

        def fail_start(command, **kwargs):
            used.append(command[command.index('-r') + 1])
            self.assertEqual(Path(used[-1]).read_bytes(), section() + secret() + block(0xbad, b'KEEP'))
            raise OSError('tshark startup failed')

        parser = ECaptureParser()
        with patch.object(parser, '_check_tshark', return_value=True), patch('analyzers.ecapture_parser.subprocess.Popen', side_effect=fail_start):
            with self.assertRaisesRegex(OSError, 'startup failed'):
                parser.parse_pcapng(str(self.path))
        self.assertEqual(len(used), 1)
        self.assertFalse(Path(used[0]).exists())


if __name__ == '__main__':
    unittest.main()
