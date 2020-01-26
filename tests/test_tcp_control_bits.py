from unittest import TestCase

from port_scanner.layers.tcp.tcp_control_bits import TcpControlBits


class TestTcpControlBits(TestCase):

    """Only PSH and ACK flags set """
    FLAGS_PSH_ACK = 0b11000

    """ All flags set """
    FLAGS_ALL = 0b111111111

    """ Only SYN flag set """
    FLAGS_SYN = 0b000000010

    def test_flags_all_set(self):
        tcp_control_flags = TcpControlBits(
            ns=True, cwr=True, urg=True, ece=True,
            ack=True, psh=True, rst=True, syn=True, fin=True
        )
        self.assertEqual(self.FLAGS_ALL, tcp_control_flags.flags)

    def test_flags_some_set(self):
        tcp_control_flags = TcpControlBits(ack=True, psh=True)
        self.assertEqual(self.FLAGS_PSH_ACK, tcp_control_flags.flags)

        self.assertTrue(tcp_control_flags.is_flag_set(TcpControlBits.ACK))
        self.assertTrue(tcp_control_flags.is_flag_set(TcpControlBits.PSH))

    def test_flags_one_set(self):
        tcp_control_flags = TcpControlBits(syn=True)
        self.assertEqual(self.FLAGS_SYN, tcp_control_flags.flags)
        self.assertTrue(tcp_control_flags.is_flag_set(TcpControlBits.SYN))

    def test_flags_none_set(self):
        tcp_control_flags = TcpControlBits()
        self.assertEqual(0, tcp_control_flags.flags)
