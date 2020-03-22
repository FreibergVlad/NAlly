import struct

from port_scanner.layers.ip.ip_packet import IpPacket
from port_scanner.layers.packet import Packet
from port_scanner.layers.tcp.tcp_control_bits import TcpControlBits
from port_scanner.layers.tcp.tcp_utils import TcpUtils
from port_scanner.layers.tcp.tcp_options import TcpOptions


class TcpPacket(Packet):

    TCP_HEADER_FORMAT = "!HHIIHHHH"
    TCP_PSEUDO_HEADER_FORMAT = "!4s4sBBH"

    def __init__(
            self,
            source_port: int,
            dest_port: int,
            sequence_number: int,
            ack_number: int,
            flags: TcpControlBits,
            win_size: int,
            urg_pointer: int,
            options: TcpOptions,
            payload: bytearray
    ):
        super().__init__()
        self.__source_port = TcpUtils.validate_port_num(source_port)
        self.__dest_port = TcpUtils.validate_port_num(dest_port)
        self.__sequence_number = sequence_number
        self.__ack_number = ack_number
        self.__flags = flags
        self.__win_size = win_size
        self.__urg_pointer = urg_pointer
        self.__options = options
        self._payload = payload

    def to_bytes(self):
        options_bytes = self.__options.to_bytes()
        # make sure that options bit length is divisible by 32
        # should not fail here since all required padding already performed in TcpOptions class
        assert len(options_bytes) % 4 == 0
        # calculate data offset value in 32-bits words
        data_offset = 5 + len(options_bytes) // 4
        # concat 4 data offset bits + 3 reserved zero bits + 9 control bit flags
        data_offset_flags = data_offset << 12 | self.__flags.flags

        header_fields = [
            self.__source_port,
            self.__dest_port,
            self.__sequence_number,
            self.__ack_number,
            data_offset_flags,
            self.__win_size,
            0,
            self.__urg_pointer,
        ]

        # allocate 20 bytes buffer to put header in
        header_buffer = bytearray(TcpUtils.TCP_HEADER_LENGTH_BYTES)
        # pack header without checksum to the buffer
        struct.pack_into(self.TCP_HEADER_FORMAT, header_buffer, 0, *header_fields)

        # generate pseudo header using underlying IP packet
        pseudo_header = self.__get_pseudo_header(data_offset * 4 + len(self._payload))
        # calculate checksum
        checksum = TcpUtils.calc_tcp_checksum(pseudo_header, header_buffer, options_bytes + self._payload)
        # split 16-bits checksum into two 8-bits values
        checksum_bytes = checksum.to_bytes(2, byteorder="big")
        # checksum takes 16-th and 17-th bytes of the header (counting from 0)
        # see https://tools.ietf.org/html/rfc793#section-3.1 for more details
        header_buffer[16] = checksum_bytes[0]
        header_buffer[17] = checksum_bytes[1]

        return bytes(header_buffer) + options_bytes + self._payload

    def __get_pseudo_header(self, segment_len) -> bytes:
        if not isinstance(self.underlying_packet, IpPacket):
            raise ValueError("Underlying packet should be IpPacket instance")
        ip_packet: IpPacket = self.underlying_packet
        return struct.pack(
            self.TCP_PSEUDO_HEADER_FORMAT,
            ip_packet.source_addr_raw,
            ip_packet.dest_addr_raw,
            0,  # reserved 8 zero bits
            ip_packet.protocol,
            segment_len,
        )

    @staticmethod
    def from_bytes(bytes_packet: bytes):  # TODO implement from_bytes method
        pass

    @property
    def source_port(self) -> int:
        return self.__source_port

    @property
    def dest_port(self) -> int:
        return self.__dest_port

    @property
    def sequence_number(self) -> int:
        return self.__sequence_number

    @property
    def ack_number(self) -> int:
        return self.__ack_number

    @property
    def flags(self) -> TcpControlBits:
        return self.__flags

    @property
    def win_size(self) -> int:
        return self.__win_size

    @property
    def urg_pointer(self) -> int:
        return self.__urg_pointer

    @property
    def options(self) -> TcpOptions:
        return self.__options

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TcpPacket):
            return self.dest_port == other.dest_port and \
                   self.source_port == other.source_port and \
                   self.payload == other.payload and \
                   self.sequence_number == other.sequence_number and \
                   self.ack_number == other.ack_number and \
                   self.flags == other.flags and \
                   self.win_size == other.win_size and \
                   self.urg_pointer == other.urg_pointer and \
                   self.options == other.options and \
                   self.underlying_packet == other.underlying_packet
