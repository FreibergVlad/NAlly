from unittest import TestCase

from nally.core.layers.transport.tcp.tcp_control_bits import TcpControlBits


class TestTcpControlBits(TestCase):

    FLAGS_PSH_ACK = 0b11000  # only PSH and ACK flags set

    FLAGS_ALL = 0b111111111  # all flags set

    FLAGS_SYN = 0b000000010  # only SYN flag set

    def test_flags_all_set(self):
        tcp_control_flags = TcpControlBits(
            ns=True, cwr=True, urg=True, ece=True,
            ack=True, psh=True, rst=True, syn=True, fin=True
        )
        self.assertTrue(
            tcp_control_flags.ns and tcp_control_flags.cwr and tcp_control_flags.urg and
            tcp_control_flags.ece and tcp_control_flags.ack and tcp_control_flags.psh and
            tcp_control_flags.rst and tcp_control_flags.syn and tcp_control_flags.fin
        )
        self.assertEqual(self.FLAGS_ALL, tcp_control_flags.flags)

    def test_flags_some_set(self):
        tcp_control_flags = TcpControlBits(ack=True, psh=True)
        self.assertEqual(self.FLAGS_PSH_ACK, tcp_control_flags.flags)

        self.assertTrue(tcp_control_flags.is_flag_set(TcpControlBits.ACK))
        self.assertTrue(tcp_control_flags.is_flag_set(TcpControlBits.PSH))
        self.assertFalse(
            tcp_control_flags.ns or tcp_control_flags.cwr or tcp_control_flags.urg or
            tcp_control_flags.ece or tcp_control_flags.rst or tcp_control_flags.syn or
            tcp_control_flags.fin
        )
        self.assertTrue(tcp_control_flags.ack and tcp_control_flags.psh)

    def test_flags_one_set(self):
        tcp_control_flags = TcpControlBits(syn=True)
        self.assertEqual(self.FLAGS_SYN, tcp_control_flags.flags)
        self.assertTrue(tcp_control_flags.is_flag_set(TcpControlBits.SYN))
        self.assertTrue(tcp_control_flags.syn)

    def test_flags_none_set(self):
        tcp_control_flags = TcpControlBits()
        self.assertEqual(0, tcp_control_flags.flags)

    def test_from_int(self):
        flags_syn = TcpControlBits.from_int(self.FLAGS_SYN)
        self.assertEqual(self.FLAGS_SYN, flags_syn.flags)

        flags_psh_ack = TcpControlBits.from_int(self.FLAGS_PSH_ACK)
        self.assertEqual(self.FLAGS_PSH_ACK, flags_psh_ack.flags)

        flags_all = TcpControlBits.from_int(self.FLAGS_ALL)
        self.assertEqual(self.FLAGS_ALL, flags_all.flags)
