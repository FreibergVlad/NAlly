from unittest import TestCase

from port_scanner.layers.link.ethernet.ethernet_utils import EthernetUtils


class TestEthernetUtils(TestCase):

    def test_validate_mac(self):
        hex_mac = "01 00 5e 67 01 11"
        bytes_mac = bytes.fromhex(hex_mac)
        self.assertEqual(bytes_mac, EthernetUtils.validate_mac(hex_mac))
        self.assertEqual(bytes_mac, EthernetUtils.validate_mac(bytes_mac))

        invalid_hex_mac = hex_mac + " 01"
        invalid_bytes_mac = bytes_mac.fromhex(invalid_hex_mac)

        self.assertRaises(ValueError, EthernetUtils.validate_mac, invalid_hex_mac)
        self.assertRaises(ValueError, EthernetUtils.validate_mac, invalid_bytes_mac)

    def test_validate_payload(self):
        invalid_payload = bytearray(15001)
        # should throw error if payload size is greater than max allowed one
        self.assertRaises(ValueError, EthernetUtils.validate_payload, invalid_payload)
