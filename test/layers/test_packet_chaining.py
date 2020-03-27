from unittest import TestCase

from port_scanner.layers.inet.ip.ip_packet import IpPacket
from port_scanner.layers.tcp.tcp_control_bits import TcpControlBits
from port_scanner.layers.tcp.tcp_options import TcpOptions
from port_scanner.layers.tcp.tcp_packet import TcpPacket

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
#   DSCP = CS0
#   ECN = Not-ECT
#   id = 39522
#   flags = Don't fragment
#   fragment offset = 0
#   ttl = 64
#   protocol = TCP (6)
#   checksum = 0xcabc
#

PACKET_DUMP_1 = "450000349a6240004006cabcc0a8012023a0f03c" \
                "e93401bb53e4d83ddb2622df801001f5915600000101080ac1dd083515c518dd"


class TestPacketChaining(TestCase):

    def test_packet_chaining(self):
        tcp_options = TcpOptions([
            TcpOptions.NOP,
            TcpOptions.NOP,
            (TcpOptions.TIMESTAMPS, [3252488245, 365238493])
        ])

        tcp_packet = TcpPacket(
            source_port=59700,
            dest_port=443,
            sequence_number=1407506493,
            ack_number=3676709599,
            flags=TcpControlBits(ack=True),
            win_size=501,
            urg_pointer=0,
            options=tcp_options,
            payload=bytearray(0)
        )

        ip_packet = IpPacket(
            source_addr_str="192.168.1.32",
            dest_addr_str="35.160.240.60",
            identification=39522,
        )

        ip_with_tcp = ip_packet / tcp_packet

        self.assertEqual(ip_with_tcp.to_bytes().hex(), PACKET_DUMP_1)
        self.assertEqual(ip_with_tcp.payload, tcp_packet.to_bytes())
        self.assertEqual(tcp_packet.underlying_packet, ip_with_tcp)
