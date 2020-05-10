from unittest import TestCase

from port_scanner.layers.inet.ip.ip_packet import IpPacket
from port_scanner.layers.transport.tcp.tcp_packet import TcpPacket
from port_scanner.layers.transport.tcp.tcp_control_bits import TcpControlBits
from port_scanner.layers.transport.tcp.tcp_options import TcpOptions

#
# Source port = 59700
# Destination port = 443
# Sequence number = 1407506493
# Acknowledgment number = 3676709599
# Flags = 0x010 (ACK)
# Window size = 501
# Checksum = 0x9156
# Urgent pointer = 0
# Options:
#   NOP
#   NOP
#   Timestamps = 3252488245 and 365238493
#
# Underlying IP:
#   Src = 192.168.1.32
#   Dst = 35.160.240.60
#

PACKET_DUMP_1 = "e93401bb53e4d83ddb2622df801001f5915600000101080ac1dd083515c518dd"

#
# Source port = 44134
# Destination port = 443
# Sequence number = 2302261952
# Acknowledgment number = 1291093731
# Flags = 0x010 (ACK)
# Window size = 496
# Checksum = 0x00002264
# Urgent pointer = 0
#
# Underlying IP:
#   Src = 10.10.128.44
#   Dst = 40.101.18.242
#
PACKET_DUMP_2 = "ac6601bb8939bac04cf486e3501001f022640000"

#
# Source port = 43480
# Destination port = 2193
# Sequence number = 703011338
# Acknowledgment number = 2915529351
# Flags = 0x018 (PSH, ACK)
# Window size = 22461
# Checksum = 0x9f65
# Urgent pointer = 0
# Options:
#   NOP
#   NOP
#   Timestamps = 1314978149 and 3029537658
#
# Underlying IP:
#   Src = 10.10.128.44
#   Dst = 10.10.144.153
#
# Payload = "a9c23efadc549e4ab164aa1c29b3e2eecd8a5e27dfa02f7306705520326f79df2d40bd188c8f82a878b95c173c59b653e51d7fb5"
#
PACKET_DUMP_3_PAYLOAD = "a9c23efadc549e4ab164aa1c29b3e2eecd8a5e27dfa02f730670" \
                        "5520326f79df2d40bd188c8f82a878b95c173c59b653e51d7fb5"
PACKET_DUMP_3 = "a9d8089129e71a0aadc77287801857bd9f6500000101080a4e60f965b493137a" + PACKET_DUMP_3_PAYLOAD


class TestTcpPacket(TestCase):

    def test_to_bytes(self):
        tcp_packet1 = TcpPacket(
            source_port=59700,
            dest_port=443,
            sequence_number=1407506493,
            ack_number=3676709599,
            flags=TcpControlBits(ack=True),
            win_size=501,
            urg_pointer=0,
            options=TcpOptions([
                TcpOptions.NOP,
                TcpOptions.NOP,
                (TcpOptions.TIMESTAMPS, [3252488245, 365238493])
            ]),
            payload=bytearray(0)
        )
        tcp_packet1 = IpPacket(source_addr_str="192.168.1.32", dest_addr_str="35.160.240.60") / tcp_packet1
        self.__test_tcp_packet(PACKET_DUMP_1, tcp_packet1)

        tcp_packet2 = TcpPacket(
            source_port=44134,
            dest_port=443,
            sequence_number=2302261952,
            ack_number=1291093731,
            flags=TcpControlBits(ack=True),
            win_size=496
        )
        tcp_packet2 = IpPacket(source_addr_str="10.10.128.44", dest_addr_str="40.101.18.242") / tcp_packet2
        self.__test_tcp_packet(PACKET_DUMP_2, tcp_packet2)

        tcp_packet3 = TcpPacket(
            source_port=43480,
            dest_port=2193,
            sequence_number=703011338,
            ack_number=2915529351,
            flags=TcpControlBits(ack=True, psh=True),
            win_size=22461,
            options=TcpOptions([
                TcpOptions.NOP,
                TcpOptions.NOP,
                (TcpOptions.TIMESTAMPS, [1314978149, 3029537658])
            ]),
            payload=bytearray.fromhex(PACKET_DUMP_3_PAYLOAD)
        )
        tcp_packet3 = IpPacket(source_addr_str="10.10.128.44", dest_addr_str="10.10.144.153") / tcp_packet3
        self.__test_tcp_packet(PACKET_DUMP_3, tcp_packet3)

    def __test_tcp_packet(self, expected_hex_dump: str, packet: IpPacket):
        self.assertTrue(isinstance(packet, IpPacket))
        tcp_packet = packet.upper_layer
        self.assertTrue(isinstance(tcp_packet, TcpPacket))
        packet_bytes = tcp_packet.to_bytes()
        self.assertEqual(expected_hex_dump, packet_bytes.hex())
        parsed_packet = TcpPacket.from_bytes(packet_bytes)
        parsed_packet.under_layer = packet
        self.assertEqual(tcp_packet, parsed_packet)
        self.assertEqual(expected_hex_dump, parsed_packet.to_bytes().hex())
