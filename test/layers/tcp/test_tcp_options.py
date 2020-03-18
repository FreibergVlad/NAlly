from unittest import TestCase

from port_scanner.layers.tcp.tcp_options import TcpOptions


class TestTcpOptions(TestCase):

    def test_to_bytes(self):
        tcp_options = TcpOptions([(TcpOptions.TIMESTAMPS, [770552664, 0])])
        options_bytes = tcp_options.to_bytes()
        self.assertEqual("080a2dedb358000000000000", options_bytes.hex())
        self.assertEqual(tcp_options, TcpOptions.from_bytes(options_bytes))

        tcp_options = TcpOptions([
            (TcpOptions.MAX_SEGMENT_SIZE, 1460),
            TcpOptions.SACK_PERMITTED,
            (TcpOptions.TIMESTAMPS, [770552664, 0]),
            TcpOptions.NOP,
            (TcpOptions.WINDOW_SCALE, 7)
        ])
        options_bytes = tcp_options.to_bytes()
        self.assertEqual("020405b40402080a2dedb3580000000001030307", options_bytes.hex())
        self.assertEqual(tcp_options, TcpOptions.from_bytes(options_bytes))

        tcp_options = TcpOptions([
            TcpOptions.NOP,
            TcpOptions.NOP,
            (TcpOptions.TIMESTAMPS, [51284612, 552681034]),
            TcpOptions.NOP,
            TcpOptions.NOP,
            (TcpOptions.SACK, [3875764423, 3875765791])
        ])
        options_bytes = tcp_options.to_bytes()
        self.assertEqual("0101080a030e8a8420f13e4a0101050ae70378c7e7037e1f", options_bytes.hex())
        self.assertEqual(tcp_options, TcpOptions.from_bytes(options_bytes))

        tcp_options = TcpOptions([
            TcpOptions.NOP,
            TcpOptions.NOP,
            (TcpOptions.TIMESTAMPS, [2841501127, 3147548165]),
            TcpOptions.NOP,
            TcpOptions.NOP,
            (TcpOptions.SACK, [7843280, 8170232, 7803608, 7839176])
        ])
        options_bytes = tcp_options.to_bytes()
        self.assertEqual("0101080aa95dddc7bb9bc605010105120077add0007caaf8007712d800779dc8", options_bytes.hex())
        self.assertEqual(tcp_options, TcpOptions.from_bytes(options_bytes))

        tcp_options = TcpOptions([
            TcpOptions.NOP,
            TcpOptions.NOP,
            (TcpOptions.TIMESTAMPS, [969039773, 3087503206])
        ])
        options_bytes = tcp_options.to_bytes()
        self.assertEqual("0101080a39c25f9db8078f66", options_bytes.hex())
        self.assertEqual(tcp_options, TcpOptions.from_bytes(options_bytes))

        # more that max allowed 40 bytes
        tcp_options = TcpOptions([(TcpOptions.SACK, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])])
        self.assertRaises(ValueError, tcp_options.to_bytes)

        tcp_options = TcpOptions(["UNKNOWN"])
        self.assertRaises(ValueError, tcp_options.to_bytes)

    def test_options_creation_with_invalid_data(self):
        self.assertRaises(ValueError, TcpOptions, [1])
        self.assertRaises(ValueError, TcpOptions, [(1, 2, 3)])
        self.assertRaises(ValueError, TcpOptions, [(1, 2)])
        self.assertRaises(ValueError, TcpOptions, [("OPTION", "invalid value")])
