import socket
from unittest import TestCase

from port_scanner.layers.ip.ip_diff_service_values import IpDiffServiceValues
from port_scanner.layers.ip.ip_ecn_values import IpEcnValues
from port_scanner.layers.ip.ip_fragmentation_flags import IpFragmentationFlags
from port_scanner.layers.ip.ip_packet import IpPacket

#
#  DSCP = 0
#  total length = 393 bytes (20 + 373)
#  identification = 31205
#  flags = 0x4000 (DF set, fragment offset is 0)
#  ttl = 252
#  protocol = TCP (6)
#  source IP = 93.186.225.198
#  destination IP = 192.168.1.16
#
PACKET_DUMP_1 = "4500018979e54000fc0602505dbae1c6c0a80110"

#
#  DSCP = 0
#  total length = 68 bytes (20 + 48)
#  identification = 27536
#  flags = 0x4000 (DF set, fragment offset is 0)
#  ttl = 64
#  protocol = UDP (17)
#  source IP = 192.168.0.102
#  destination IP = 192.168.0.1
#
PACKET_DUMP_2 = "450000446b90400040114d61c0a80066c0a80001"

#
#  DSCP = 0
#  total length = 1500 bytes (20 + 1480)
#  identification = 57527
#  flags = 0x239d (MF set and fragment offset is 925)
#  ttl = 64
#  protocol = ICMP (1)
#  source IP = 10.10.128.44
#  destination IP = 216.58.209.14
#
PACKET_DUMP_3 = "450005dce0b7239d40013d4d0a0a802cd83ad10e"

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
PACKET_DUMP_4 = "45b8001472880000400635e4c0a8010808080808"

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
PACKET_DUMP_5 = "45bb0014d8a700004006cfc1c0a8010808080808"


class TestIpv4Packet(TestCase):

    def test_pack(self):
        ip_packet_1 = IpPacket(
            source_addr_str="93.186.225.198",
            dest_addr_str="192.168.1.16",
            payload=bytearray(373),
            ttl=252,
            identification=31205
        )
        hex_dump_1 = ip_packet_1.to_bytes().hex()
        self.assertEqual(PACKET_DUMP_1, hex_dump_1)

        ip_packet_2 = IpPacket(
            source_addr_str="192.168.0.102",
            dest_addr_str="192.168.0.1",
            payload=bytearray(48),
            ttl=64,
            identification=27536,
            protocol=socket.IPPROTO_UDP
        )
        hex_dump_2 = ip_packet_2.to_bytes().hex()
        self.assertEqual(PACKET_DUMP_2, hex_dump_2)

        ip_packet_3 = IpPacket(
            source_addr_str="10.10.128.44",
            dest_addr_str="216.58.209.14",
            payload=bytearray(1480),
            ttl=64,
            identification=57527,
            flags=IpFragmentationFlags(mf=True),
            fragment_offset=925,
            protocol=socket.IPPROTO_ICMP
        )
        hex_dump_3 = ip_packet_3.to_bytes().hex()
        self.assertEqual(PACKET_DUMP_3, hex_dump_3)

        ip_packet_4 = IpPacket(
            source_addr_str="192.168.1.8",
            dest_addr_str="8.8.8.8",
            dscp=IpDiffServiceValues.EF,
            flags=IpFragmentationFlags(),
            payload=bytearray(0),
            identification=29320
        )
        hex_dump_4 = ip_packet_4.to_bytes().hex()
        self.assertEqual(PACKET_DUMP_4, hex_dump_4)

        ip_packet_5 = IpPacket(
            source_addr_str="192.168.1.8",
            dest_addr_str="8.8.8.8",
            dscp=IpDiffServiceValues.EF,
            ecn=IpEcnValues.CE,
            flags=IpFragmentationFlags(),
            payload=bytearray(0),
            identification=55463
        )
        hex_dump_5 = ip_packet_5.to_bytes().hex()
        self.assertEqual(PACKET_DUMP_5, hex_dump_5)

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
