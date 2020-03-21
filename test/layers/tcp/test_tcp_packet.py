from unittest import TestCase

from port_scanner.layers.tcp.tcp_packet import TcpPacket
from port_scanner.layers.tcp.tcp_control_bits import TcpControlBits
from port_scanner.layers.tcp.tcp_options import TcpOptions

#
# Source port = 443
# Destination port = 50012
# Sequence number = 3102652131
# Acknowledgment number = 3461676770
# Flags = 0x010 (ACK)
# Window size = 356
# Checksum = 0xc4ee
# Urgent pointer = 0
# Options:
#   NOP
#   NOP
#   Timestamps = 3293157569 and 235644918
#

PACKET_DUMP_1 = "01bbc35cb8eeb6e3ce54fee280100164c4ee00000101080ac44998c10e0ba7f6"


class TestTcpPacket(TestCase):

    def test_to_bytes(self):
        tcp_options = TcpOptions([
            TcpOptions.NOP,
            TcpOptions.NOP,
            (TcpOptions.TIMESTAMPS, [3293157569, 235644918])
        ])

        tcp_packet = TcpPacket(
            source_port=443,
            dest_port=50012,
            sequence_number=3102652131,
            ack_number=3461676770,
            flags=TcpControlBits(ack=True),
            win_size=356,
            urg_pointer=0,
            options=tcp_options,
            payload=bytearray(0)
        )

        self.assertEqual(PACKET_DUMP_1, tcp_packet.to_bytes().hex())
