import struct

from nally.core.layers.packet import Packet


class TransportLayerUtils:
    """
    Defines common utility methods for TCP and UDP protocols
    """

    PSEUDO_HEADER_FORMAT = "!4s4sBBH"
    """
    Defines pseudo header format used for checksum computation (IPv4):
        * Source address : 4 bytes
        * Destination address : 4 bytes
        * Zero padding : 1 byte
        * Protocol : 1 byte
        * TCP packet length : 2 bytes
    """

    PACKET_MAX_LENGTH_BYTES = 65535
    """
    Max length of TCP or UDP packet in bytes
    """

    @staticmethod
    def validate_port_num(port):
        if port < 0 or port > 65535:
            raise ValueError("port number should be in [0;65535] range")
        return port

    @staticmethod
    def validate_packet_length(packet: bytes):
        if len(packet) > TransportLayerUtils.PACKET_MAX_LENGTH_BYTES:
            raise ValueError(f"packet size can't be larger than {TransportLayerUtils.PACKET_MAX_LENGTH_BYTES} bytes")
        return packet

    @staticmethod
    def get_pseudo_header(packet: Packet, segment_len: int) -> bytes:
        """
        Constructs pseudo header used to TCP and UDP checksum computation

        :param packet: TCP or UDP packet with IP underlying
        :param segment_len: length of the packet in bytes including payload length
        :return: 12 bytes pseudo header
        """
        from nally.core.layers.inet.ip.ip_packet import IpPacket
        if not isinstance(packet.under_layer, IpPacket):
            raise ValueError("Underlying packet should be IpPacket instance")
        ip_packet: IpPacket = packet.under_layer
        return struct.pack(
            TransportLayerUtils.PSEUDO_HEADER_FORMAT,
            ip_packet.source_addr_raw,
            ip_packet.dest_addr_raw,
            0,  # reserved 8 zero bits
            ip_packet.protocol,
            segment_len,
        )
