import random
import struct
import socket


class IpPacket:

    IP_V4_HEADER_FORMAT = "!BBHHHBBH4s4s"

    IP_V4_MAX_PACKET_LENGTH = 65535
    IP_V4_HEADER_LENGTH = 5
    IP_V4_HEADER_LENGTH_BYTES = IP_V4_HEADER_LENGTH * 4
    IP_V4_VER_IHL = socket.IPPROTO_IPIP << 4 | IP_V4_HEADER_LENGTH
    IP_V4_TYPE_OF_SERVICE = 0b000000
    IP_V4_FLAGS = 0b0100000000000000
    IP_V4_TTL = 64
    IP_V4_ID_LENGTH = 16

    def __init__(
            self,
            source_addr_str: str,
            dest_addr_str: str,
            payload: bytes,
            type_of_service: int = IP_V4_TYPE_OF_SERVICE,
            identification: int = None,
            flags: int = IP_V4_FLAGS,
            ttl: int = IP_V4_TTL,
            protocol: int = socket.IPPROTO_TCP
    ):
        self.__source_addr = socket.inet_aton(source_addr_str)
        self.__dest_addr = socket.inet_aton(dest_addr_str)
        self.__payload = payload
        self.__type_of_service = type_of_service
        self.__total_length = self.IP_V4_HEADER_LENGTH_BYTES + len(self.__payload)
        assert self.__total_length <= self.IP_V4_MAX_PACKET_LENGTH, "Length of packet should be <= 65535 bytes"
        if identification is None:
            identification = self.__get_fragment_id()
        self.__identification = identification
        self.__flags = flags
        self.__ttl = ttl
        self.__protocol = protocol

    def pack(self) -> bytes:
        header_fields = [
            self.IP_V4_VER_IHL,
            self.__type_of_service,
            self.__total_length,
            self.__identification,
            self.__flags,
            self.__ttl,
            self.__protocol,
            0,  # placeholder for checksum
            self.__source_addr,
            self.__dest_addr
        ]

        # allocate 20 bytes buffer to put header in
        header_bytes = bytearray(self.IP_V4_HEADER_LENGTH_BYTES)
        # pack header without checksum to the buffer
        struct.pack_into(self.IP_V4_HEADER_FORMAT, header_bytes, 0, *header_fields)

        checksum = self.__get_checksum(header_bytes)
        # split 16-bits checksum into two 8-bits values
        checksum_bytes = checksum.to_bytes(2, byteorder="big")
        # checksum takes 10-th and 11-th bytes of the header (counting from 0)
        # see https://tools.ietf.org/html/rfc791#section-3.1 for more details
        header_bytes[10] = checksum_bytes[0]
        header_bytes[11] = checksum_bytes[1]

        return bytes(header_bytes)

    @staticmethod
    def __get_checksum(header_bytes: bytearray) -> int:
        checksum = 0
        for i in range(0, len(header_bytes), 2):
            # pair two bytes into 16-bits value
            paired_bytes = (header_bytes[i] << 8) + header_bytes[i + 1]
            checksum += paired_bytes
        checksum += (checksum >> 16)
        checksum = ~checksum & 0xffff
        return checksum

    @staticmethod
    def __get_fragment_id() -> int:
        return random.getrandbits(IpPacket.IP_V4_ID_LENGTH)
