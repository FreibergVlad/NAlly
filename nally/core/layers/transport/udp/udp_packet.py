import struct

from nally.core.layers.packet import Packet
from nally.core.layers.transport.transport_layer_utils \
    import TransportLayerUtils
from nally.core.utils.utils import Utils


class UdpPacket(Packet):
    """
    Represents UDP (User Datagram Protocol) datagram
    """

    UDP_HEADER_FORMAT = "!HHHH"
    """
        Defines UDP header format:
            * Source port field : 2 bytes
            * Destination port field : 2 bytes
            * Length field : 2 bytes
            * Checksum field : 2 bytes
    """

    UDP_HEADER_LENGTH_BYTES = 8

    def __init__(
            self,
            dest_port: int,
            source_port: int = 0,
    ):
        """
        Initializes UDP packet instance

        :param dest_port: Destination port field value,
            integer in range [0; 65535]
        :param source_port: Source port field value,
            integer in range [0; 65535]. 0 by default
        """
        super().__init__()
        self.__dest_port = TransportLayerUtils.validate_port_num(dest_port)
        self.__source_port = TransportLayerUtils.validate_port_num(source_port)

    def to_bytes(self):
        payload = self.raw_payload
        length = self.UDP_HEADER_LENGTH_BYTES + len(payload)
        header_fields = [self.__source_port, self.__dest_port, length, 0]

        # allocate 20 bytes buffer to put header in
        header_buffer = bytearray(self.UDP_HEADER_LENGTH_BYTES)
        # pack header without checksum to the buffer
        struct.pack_into(
            self.UDP_HEADER_FORMAT,
            header_buffer,
            0,
            *header_fields
        )

        # generate pseudo header using underlying IP packet
        pseudo_header = TransportLayerUtils.get_pseudo_header(self, length)
        # calculate checksum
        checksum_bytes = Utils.calc_checksum(
            pseudo_header + header_buffer + payload
        )
        # checksum takes 6-th and 7-th bytes of the header (counting from 0)
        # see https://tools.ietf.org/html/rfc768 for more details
        header_buffer[6] = checksum_bytes[0]
        header_buffer[7] = checksum_bytes[1]

        return TransportLayerUtils.validate_packet_length(
            bytes(header_buffer) + payload
        )

    @staticmethod
    def from_bytes(packet_bytes: bytes):
        header_bytes = packet_bytes[:UdpPacket.UDP_HEADER_LENGTH_BYTES]
        payload = packet_bytes[UdpPacket.UDP_HEADER_LENGTH_BYTES:]
        header_fields = struct.unpack(
            UdpPacket.UDP_HEADER_FORMAT,
            header_bytes
        )

        source_port = header_fields[0]
        dest_port = header_fields[1]

        udp_header = UdpPacket(dest_port=dest_port, source_port=source_port)
        return udp_header / payload if len(payload) > 0 else udp_header

    @property
    def dest_port(self) -> int:
        return self.__dest_port

    @property
    def source_port(self) -> int:
        return self.__source_port

    @property
    def length(self) -> int:
        return self.UDP_HEADER_LENGTH_BYTES + len(self.raw_payload)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UdpPacket):
            return self.dest_port == other.dest_port and \
                   self.source_port == other.source_port and \
                   self.upper_layer == other.upper_layer

    def __str__(self) -> str:
        return f"UDP(dst_port={self.dest_port}, " \
               f"src_port={self.source_port}, " \
               f"length={self.length})"
