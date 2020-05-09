import socket
from unittest import TestCase

from port_scanner.layers.inet.ip.ip_utils import IpUtils


class TestIpUtils(TestCase):

    HEADER_DUMPS_TO_CHECKSUM = {
        "450000347a6b0000fc060000d83ace0ec0a80108": 0xdc5e,
        "450000344f714000fc06000068517956c0a80108": 0x8bfa,
        "450000424655400040110000c0a80108c0a80101": 0x70fc,
        "45000034fe7a4000fc0600008ac951c7c0a80108": 0xe207
    }

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

    def test_calc_ip_checksum(self):
        for dump, checksum in self.HEADER_DUMPS_TO_CHECKSUM.items():
            header_bytes = bytearray.fromhex(dump)
            self.assertEqual(IpUtils.calc_ip_checksum(header_bytes), checksum)

    def test_validate_and_pack_ip4_addr(self):
        valid_ip = "224.103.1.23"
        valid_ip_bytes = socket.inet_aton(valid_ip)
        self.assertEqual(valid_ip_bytes, IpUtils.validate_and_pack_ip4_addr(valid_ip))
        self.assertEqual(valid_ip_bytes, IpUtils.validate_and_pack_ip4_addr(valid_ip_bytes))

        invalid_ips = ["qwe", "192.168aa", "192.168.", "421.12.0.1"]
        for ip in invalid_ips:
            self.assertRaises(ValueError, IpUtils.validate_and_pack_ip4_addr, ip)
