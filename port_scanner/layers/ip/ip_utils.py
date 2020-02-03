import random
import socket


class IpUtils:
    """
    Stores constants related to IP protocol and methods for IP fields validation

    Note: constants and method in this class don't support IPv4 Options field
    """

    IP_V4_MAX_HEADER_LENGTH = 5
    """Max IP header length in 32-bit words"""

    IP_V4_MAX_PACKET_LENGTH_BYTES = 65535
    """Max IP packet size in bytes including header and payload"""
    IP_V4_MAX_HEADER_LENGTH_BYTES = IP_V4_MAX_HEADER_LENGTH * 4
    """Max IP header length in bytes"""

    IP_V4_MAX_FRAG_OFFSET_LENGTH_BITS = 13
    """Max allowed bit length of Fragment Offset field"""
    IP_V4_MAX_ID_LENGTH_BITS = 16
    """Max allowed bit length of Identification field"""

    IP_V4_VER_IHL = socket.IPPROTO_IPIP << 4 | IP_V4_MAX_HEADER_LENGTH
    """Concatenation of IP version (always 4 for IPv4) and header length"""

    @staticmethod
    def validate_fragment_offset(fragment_offset: int):
        """
        Validates Fragment Offset IPv4 header field. Fragment Offset should be
        integer value of 13 bits length

        :param int fragment_offset: value which need to be validated
        :return: validated fragment_offset value
        :raises: ValueError: if passed value doesn't satisfy bit length requirements
        """
        if fragment_offset.bit_length() > IpUtils.IP_V4_MAX_FRAG_OFFSET_LENGTH_BITS:
            raise ValueError(f"Fragmentation offset should be {IpUtils.IP_V4_MAX_FRAG_OFFSET_LENGTH_BITS} bit length")
        return fragment_offset

    @staticmethod
    def validate_or_gen_packet_id(packet_id: int = None):
        """
        Validates Identification IPv4 header field value or
        generates it of value wasn't passed into the method.
        Identification field should be 16 bits long

        :param int packet_id: value which need to be validated,
            or None, if value should be generated
        :return: validated or generated 16 bits integer
        :raises: ValueError: if passed value doesn't satisfy bit length requirements
        """
        if packet_id is None:
            return IpUtils.gen_fragment_id()
        if packet_id.bit_length() > IpUtils.IP_V4_MAX_ID_LENGTH_BITS:
            raise ValueError(f"Packet identification should be {IpUtils.IP_V4_MAX_ID_LENGTH_BITS} bit length")
        return packet_id

    @staticmethod
    def validate_packet_length(total_length: int):
        """
        Validates Total Length IPv4 header field. Value should be in range [20, 65535]

        :param int total_length: total length of IP packet including header and payload
        :return: validated total_length value
        :raises: ValueError: if passed value isn't in required range
        """
        if total_length < IpUtils.IP_V4_MAX_HEADER_LENGTH_BYTES or total_length > IpUtils.IP_V4_MAX_PACKET_LENGTH_BYTES:
            raise ValueError(f"Packet length should be <=  {IpUtils.IP_V4_MAX_PACKET_LENGTH_BYTES} bytes")
        return total_length

    @staticmethod
    def gen_fragment_id() -> int:
        """
        Generates random 16 bits value which can be used as Identification field of IPv4 header

        :return: random 16-bits integer
        """
        return random.getrandbits(IpUtils.IP_V4_MAX_ID_LENGTH_BITS)

    @staticmethod
    def calc_ip_checksum(header_bytes: bytearray) -> int:
        """
        Calculates IPv4 header checksum using the algorithm described in
        https://tools.ietf.org/html/rfc1624

        Note: header passed as method param should have 10-th and 11-th bytes
        (counting from 0) set to 0

        :param header_bytes: header fields in byte array representation
            with 10-th and 11-th bytes (counting from 0) set to 0
        :return: calculated checksum (16 bits number)
        :raises: ValueError: if 10-th or 11-th byte of header is not 0
        """
        if header_bytes[10] != 0 or header_bytes[11] != 0:
            raise ValueError("10-th and 11-th bytes of header should be set to 0")
        checksum = 0
        for i in range(0, len(header_bytes), 2):
            # pair two bytes into 16-bits value
            paired_bytes = (header_bytes[i] << 8) + header_bytes[i + 1]
            checksum += paired_bytes
        checksum += (checksum >> 16)
        checksum = ~checksum & 0xffff
        return checksum
