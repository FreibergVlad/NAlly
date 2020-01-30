from unittest import TestCase

from port_scanner.layers.ip.ip_utils import IpUtils


class TestIpUtils(TestCase):

    def test_validate_fragment_offset(self):
        self.assertEqual(0, IpUtils.validate_fragment_offset(0))

        # max allowed value is 8191 - max 13 bit number
        max_offset_value = pow(2, 13) - 1
        self.assertEqual(max_offset_value, IpUtils.validate_fragment_offset(max_offset_value))

        # values longer than 13 bits length are not allowed
        self.assertRaises(ValueError, IpUtils.validate_fragment_offset, max_offset_value + 1)

    def test_validate_or_gen_packet_id(self):
        self.assertEqual(0, IpUtils.validate_or_gen_packet_id(0))
        self.assertIsInstance(IpUtils.validate_or_gen_packet_id(), int)

        # max allowed value is 65535 - max 16 bit number
        max_id_value = pow(2, 16) - 1
        self.assertEqual(max_id_value, IpUtils.validate_or_gen_packet_id(max_id_value))

        # values longer than 16 bits length are not allowed
        self.assertRaises(ValueError, IpUtils.validate_or_gen_packet_id, max_id_value + 1)

    def test_validate_packet_length(self):
        self.assertRaises(ValueError, IpUtils.validate_packet_length, 0)
        self.assertRaises(ValueError, IpUtils.validate_packet_length, 19)
        self.assertRaises(ValueError, IpUtils.validate_packet_length, 65536)

        self.assertEqual(65535, IpUtils.validate_packet_length(65535))



