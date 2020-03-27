import socket
from unittest import TestCase

from port_scanner.layers.link.arp.arp_utils import ArpHardwareType
from port_scanner.layers.link.arp.arp_utils import ArpUtils
from port_scanner.layers.link.proto_type import EtherType


class TestArpUtils(TestCase):

    def test_validate_hw_addr(self):
        mac_str = "52 54 00 a9 40 62"
        mac_bytes = bytearray.fromhex(mac_str)
        self.assertEqual(mac_bytes, ArpUtils.validate_hw_addr(mac_str, ArpHardwareType.ETHERNET))

        invalid_mac_str = mac_str + " 01"
        invalid_mac_bytes = bytearray.fromhex(invalid_mac_str)
        self.assertRaises(ValueError, ArpUtils.validate_hw_addr, invalid_mac_str, ArpHardwareType.ETHERNET)
        self.assertRaises(ValueError, ArpUtils.validate_hw_addr, invalid_mac_bytes, ArpHardwareType.ETHERNET)

        # pass unsupported protocol type
        self.assertRaises(ValueError, ArpUtils.validate_hw_addr, mac_str, 2)
        self.assertRaises(ValueError, ArpUtils.validate_hw_addr, mac_bytes, 2)

    def test_validate_proto_addr(self):
        ip_str = "192.168.0.1"
        ip_bytes = socket.inet_aton(ip_str)

        self.assertEqual(ip_bytes, ArpUtils.validate_proto_addr(ip_str, EtherType.IPV4))
        self.assertEqual(ip_bytes, ArpUtils.validate_proto_addr(ip_bytes, EtherType.IPV4))
        self.assertRaises(ValueError, ArpUtils.validate_proto_addr, "192.1.1.257", EtherType.IPV4)

        # pass unsupported protocol type
        self.assertRaises(ValueError, ArpUtils.validate_proto_addr, ip_str, EtherType.ARP)

    def test_resolve_proto_len(self):
        self.assertEqual(4, ArpUtils.resolve_proto_len(EtherType.IPV4))
        self.assertRaises(ValueError, ArpUtils.resolve_proto_len, EtherType.ARP)

    def test_resolve_hw_len(self):
        self.assertEqual(6, ArpUtils.resolve_hw_len(ArpHardwareType.ETHERNET))
        self.assertRaises(ValueError, ArpUtils.resolve_hw_len, 2)
