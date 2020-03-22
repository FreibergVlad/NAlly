from port_scanner.utils.utils import Utils


class TcpUtils:
    """
    Stores constants related to TCP protocol and utility methods
    """

    PSEUDO_HEADER_LENGTH_BYTES = 12
    TCP_HEADER_LENGTH = 5
    TCP_HEADER_LENGTH_BYTES = TCP_HEADER_LENGTH * 4
    TCP_OPTIONS_MAX_LENGTH_BYTES = 40

    @staticmethod
    def validate_port_num(port):
        if port < 0 or port > 65535:
            raise ValueError("port number should be in [0;65535] range")
        return port

    @staticmethod
    def validate_options_length(options):
        length = len(options)
        if length > TcpUtils.TCP_OPTIONS_MAX_LENGTH_BYTES:
            raise ValueError(f"Max options length is ${TcpUtils.TCP_OPTIONS_MAX_LENGTH_BYTES} got ${length}")

    @staticmethod
    def calc_tcp_checksum(pseudo_header, header, payload):
        """
        Calculates TCP header checksum using the algorithm described in
        https://tools.ietf.org/html/rfc793#section-3.1

        Note: header passed as method param should have 16-th and 17-th bytes
        (counting from 0) set to 0

        :param pseudo_header: 12 bytes pseudo header constructed using the underlying protocol
        :param header: 20 TCP header bytes with 16-th and 17-th bytes (counting from 0) set to 0
        :param payload: payload, should include packet data and Options field if presents
        :return: calculated checksum (16 bits value)
        """
        if len(pseudo_header) != TcpUtils.PSEUDO_HEADER_LENGTH_BYTES:
            raise ValueError(f"Pseudo header length should be ${TcpUtils.PSEUDO_HEADER_LENGTH_BYTES} bytes")
        if len(header) != TcpUtils.TCP_HEADER_LENGTH_BYTES:
            raise ValueError(f"Header length should be ${TcpUtils.TCP_HEADER_LENGTH_BYTES} bytes")
        if header[16] != 0 or header[17] != 0:
            raise ValueError("16-th and 17-th bytes of header should be set to 0")
        return Utils.calc_checksum(pseudo_header + header + payload)
