from unittest import TestCase

from port_scanner.layers.tcp.tcp_packet import TcpPacket
from port_scanner.layers.tcp.tcp_control_bits import TcpControlBits
from port_scanner.layers.tcp.tcp_options import TcpOptions

#
# Source port = 35654
# Destination port = 443
# Sequence number = 0
# Acknowledgment number = 0
# Flags = 0x002 (SYN)
# Window size = 64240
# Checksum = 0xc3c1
# Urgent pointer = 0
# Options:
#   MSS = 1460
#   SACK permitted
#   Timestamps = 3046248901 and 0
#   Nop
#   Window scale = 7
#

PACKET_DUMP_1 = "8b4601bb8d6e6dd100000000a002faf0c3c10000020405b40402080ab59211c50000000001030307"


class TestTcpPacket(TestCase):

    def test_to_bytes(self):
        tcp_options = TcpOptions()\
            .set_mss(1460)\
            .set_sack_permitted()\
            .set_timestamps(3046248901, 0)\
            .set_nop()\
            .set_window_scale(7)

        tcp_packet1 = TcpPacket(
            source_port=35654,
            dest_port=443,
            sequence_number=0,
            ack_number=0,
            flags=TcpControlBits(syn=True),
            win_size=64240,
            urg_pointer=0,
            options=tcp_options,
            payload=bytearray(0)
        )
