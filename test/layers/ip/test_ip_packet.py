from unittest import TestCase

from port_scanner.layers.ip.ip_diff_service_values import IpDiffServiceValues
from port_scanner.layers.ip.ip_ecn_values import IpEcnValues
from port_scanner.layers.ip.ip_fragmentation_flags import IpFragmentationFlags
from port_scanner.layers.ip.ip_packet import IpPacket

#
#  DSCP = 0
#  total length = 25 bytes (20 + 5)
#  identification = 39434
#  flags = 0 (no flags set)
#  ttl = 64
#  protocol = TCP (6)
#  source IP = 192.168.1.8
#  destination IP = 126.12.14.67
#  payload = 5 * 0x58 bytes
#

PACKET_DUMP_1 = "450000199a0a0000400692d5c0a801087e0c0e435858585858"

#
#  DSCP = 0xb8 (EF PHB + Non-ECN)
#  total length = 20 bytes
#  identification = 29320
#  flags = 0
#  ttl = 64
#  protocol = TCP (6)
#  source IP = 192.168.1.8
#  destination IP = 8.8.8.8
#
PACKET_DUMP_2 = "45b8001472880000400635e4c0a8010808080808"

#
#  DSCP = 0xbb (EF PHB + CE)
#  total length = 20 bytes
#  identification = 55463
#  flags = 0
#  ttl = 64
#  protocol = TCP (6)
#  source IP = 192.168.1.8
#  destination IP = 8.8.8.8
#
PACKET_DUMP_3 = "45bb0014d8a700004006cfc1c0a8010808080808"


class TestIpv4Packet(TestCase):

    def test_to_bytes(self):
        ip_packet_1 = IpPacket(
            source_addr_str="192.168.1.8",
            dest_addr_str="126.12.14.67",
            payload=bytearray([0x58] * 5),
            flags=IpFragmentationFlags(),
            identification=39434
        )
        hex_dump_1 = ip_packet_1.to_bytes().hex()
        self.assertEqual(PACKET_DUMP_1, hex_dump_1)
        self.assertEqual(ip_packet_1, IpPacket.from_bytes(ip_packet_1.to_bytes()))

        ip_packet_2 = IpPacket(
            source_addr_str="192.168.1.8",
            dest_addr_str="8.8.8.8",
            dscp=IpDiffServiceValues.EF,
            flags=IpFragmentationFlags(),
            payload=bytearray(0),
            identification=29320
        )
        hex_dump_2 = ip_packet_2.to_bytes().hex()
        self.assertEqual(PACKET_DUMP_2, hex_dump_2)
        self.assertEqual(ip_packet_2, IpPacket.from_bytes(ip_packet_2.to_bytes()))

        ip_packet_3 = IpPacket(
            source_addr_str="192.168.1.8",
            dest_addr_str="8.8.8.8",
            dscp=IpDiffServiceValues.EF,
            ecn=IpEcnValues.CE,
            flags=IpFragmentationFlags(),
            payload=bytearray(0),
            identification=55463
        )
        hex_dump_3 = ip_packet_3.to_bytes().hex()
        self.assertEqual(PACKET_DUMP_3, hex_dump_3)
        self.assertEqual(ip_packet_3, IpPacket.from_bytes(ip_packet_3.to_bytes()))

    def test_packet_creation_with_invalid_fields(self):
        # pass too long payload
        self.assertRaises(
            ValueError,
            IpPacket,
            source_addr_str="10.10.128.44",
            dest_addr_str="216.58.209.14",
            payload=bytearray(65535)
        )

        # pass to long Identification field
        self.assertRaises(
            ValueError,
            IpPacket,
            source_addr_str="10.10.128.44",
            dest_addr_str="216.58.209.14",
            payload=bytearray(0),
            identification=pow(2, 16)
        )

        # pass to long Identification field
        self.assertRaises(
            ValueError,
            IpPacket,
            source_addr_str="10.10.128.44",
            dest_addr_str="216.58.209.14",
            payload=bytearray(0),
            fragment_offset=pow(2, 13)
        )
