import struct
import socket

from port_scanner.layers.ip.ip_fragmentation_flags import IpFragmentationFlags
from port_scanner.layers.ip.ip_utils import IpUtils


class IpPacket:

    IP_V4_HEADER_FORMAT = "!BBHHHBBH4s4s"

    IP_V4_TYPE_OF_SERVICE = 0b000000
    IP_V4_FLAGS_DF = IpFragmentationFlags(df=True)
    IP_V4_DEFAULT_TTL = 64

    def __init__(
            self,
            source_addr_str: str,
            dest_addr_str: str,
            payload: bytes,
            type_of_service: int = IP_V4_TYPE_OF_SERVICE,
            identification: int = None,
            flags: IpFragmentationFlags = IP_V4_FLAGS_DF,
            fragment_offset: int = 0,
            ttl: int = IP_V4_DEFAULT_TTL,
            protocol: int = socket.IPPROTO_TCP
    ):
        self.__source_addr = socket.inet_aton(source_addr_str)
        self.__dest_addr = socket.inet_aton(dest_addr_str)
        self.__payload = payload
        self.__type_of_service = type_of_service
        self.__total_length = IpUtils.validate_packet_length(IpUtils.IP_V4_MAX_HEADER_LENGTH_BYTES + len(self.__payload))
        self.__identification = IpUtils.validate_or_gen_packet_id(identification)
        self.__flags = flags
        self.__fragment_offset = IpUtils.validate_fragment_offset(fragment_offset)
        self.__ttl = ttl
        self.__protocol = protocol

    def pack(self) -> bytes:

        # fragmentation flags should take first 3 bits, next 13 bits is fragment offset
        flags_fragment_offset = self.__flags.flags << 13 | self.__fragment_offset

        header_fields = [
            IpUtils.IP_V4_VER_IHL,
            self.__type_of_service,
            self.__total_length,
            self.__identification,
            flags_fragment_offset,
            self.__ttl,
            self.__protocol,
            0,  # placeholder for checksum
            self.__source_addr,
            self.__dest_addr
        ]

        # allocate 20 bytes buffer to put header in
        header_bytes = bytearray(IpUtils.IP_V4_MAX_HEADER_LENGTH_BYTES)
        # pack header without checksum to the buffer
        struct.pack_into(self.IP_V4_HEADER_FORMAT, header_bytes, 0, *header_fields)

        checksum = self.__gen_checksum(header_bytes)
        # split 16-bits checksum into two 8-bits values
        checksum_bytes = checksum.to_bytes(2, byteorder="big")
        # checksum takes 10-th and 11-th bytes of the header (counting from 0)
        # see https://tools.ietf.org/html/rfc791#section-3.1 for more details
        header_bytes[10] = checksum_bytes[0]
        header_bytes[11] = checksum_bytes[1]

        return bytes(header_bytes)

    @staticmethod
    def __gen_checksum(header_bytes: bytearray) -> int:
        checksum = 0
        for i in range(0, len(header_bytes), 2):
            # pair two bytes into 16-bits value
            paired_bytes = (header_bytes[i] << 8) + header_bytes[i + 1]
            checksum += paired_bytes
        checksum += (checksum >> 16)
        checksum = ~checksum & 0xffff
        return checksum
