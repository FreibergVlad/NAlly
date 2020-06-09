import socket
from unittest import TestCase

#
# Source port: 55380
# Destination port: 53
# Length: 66
# Checksum: 0x1d81
#
# Underlying IP:
#   Src = 192.168.1.32
#   Dst = 192.168.1.1
#
from nally.core.layers.inet.ip.ip_packet import IpPacket
from nally.core.layers.transport.udp.udp_packet import UdpPacket

PACKET_DUMP_1_PAYLOAD = "fc3c010000010000000000001872332d2d2d7" \
                        "36e2d357561356f75757861786a2d686e39650" \
                        "b676f6f676c65766964656f03636f6d0000010001"
PACKET_DUMP_1 = "d854003500421d81" + PACKET_DUMP_1_PAYLOAD

#
# Source port: 53349
# Destination port: 1194
# Length: 121
# Checksum: 0x0000a351
#
# Underlying IP:
#   Src = 192.168.1.32
#   Dst = 217.38.170.114
#
PACKET_DUMP_2_PAYLOAD = "306357a78616b3f152c9385a8a8e4a34" \
                        "92ba5b274254d97ef246282d8935ecfc" \
                        "be0479a496ceee59520792b0085edfe0" \
                        "5edcbc585ffe8efed56489fd51dc2ba2" \
                        "49ff413a55906ba26bfb6109c27d7ea8" \
                        "cbc3cd218ad7d48340eea7964bfeb67b" \
                        "6dceb1fa74c3eea95936393f9b9489f09b"
PACKET_DUMP_2 = "d06504aa0079a351" + PACKET_DUMP_2_PAYLOAD


class TestUdpPacket(TestCase):

    def test_to_bytes(self):
        udp_packet1 = UdpPacket(
            source_port=55380,
            dest_port=53
        ) / bytes.fromhex(PACKET_DUMP_1_PAYLOAD)
        udp_packet1 = IpPacket(
            source_addr_str="192.168.1.32",
            dest_addr_str="192.168.1.1",
            protocol=socket.IPPROTO_UDP
        ) / udp_packet1
        self.__test_udp_packet(PACKET_DUMP_1, udp_packet1)

        udp_packet2 = UdpPacket(
            source_port=53349,
            dest_port=1194
        ) / bytes.fromhex(PACKET_DUMP_2_PAYLOAD)
        udp_packet2 = IpPacket(
            source_addr_str="192.168.1.32",
            dest_addr_str="217.38.170.114",
            protocol=socket.IPPROTO_UDP
        ) / udp_packet2
        self.__test_udp_packet(PACKET_DUMP_2, udp_packet2)

    def test_is_response(self):
        # ports are correct
        udp_packet1 = UdpPacket(
            source_port=55380,
            dest_port=53
        )
        udp_response1 = UdpPacket(
            source_port=53,
            dest_port=55380
        )
        self.assertTrue(udp_response1.is_response(udp_packet1))

        # ports mismatch
        udp_packet2 = UdpPacket(
            source_port=55380,
            dest_port=53
        )
        udp_response2 = UdpPacket(
            source_port=54,
            dest_port=55380
        )
        self.assertFalse(udp_response2.is_response(udp_packet2))

    def __test_udp_packet(self, expected_hex_dump: str, packet: IpPacket):
        self.assertTrue(isinstance(packet, IpPacket))
        udp_packet = packet.upper_layer
        self.assertTrue(isinstance(udp_packet, UdpPacket))
        packet_bytes = udp_packet.to_bytes()
        self.assertEqual(expected_hex_dump, packet_bytes.hex())
        parsed_packet = UdpPacket.from_bytes(packet_bytes)
        parsed_packet.under_layer = packet
        self.assertEqual(udp_packet, parsed_packet)
        self.assertEqual(expected_hex_dump, parsed_packet.to_bytes().hex())
