import struct

from port_scanner.layers.tcp.tcp_control_bits import TcpControlBits
from port_scanner.layers.tcp.tcp_utils import TcpUtils
from port_scanner.layers.tcp.tcp_options import TcpOptions


class TcpPacket:

    TCP_HEADER_FORMAT = "!HHIIHHHHI"

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
        self.__source_port = TcpUtils.validate_port_num(source_port)
        self.__dest_port = TcpUtils.validate_port_num(dest_port)
        self.__sequence_number = sequence_number
        self.__ack_number = ack_number
        self.__flags = flags
        self.__win_size = win_size
        self.__urg_pointer = urg_pointer
        self.__options = options
        self.__payload = payload

    def to_bytes(self):
        options_bytes = self.__options.to_bytes()
        # calculate data offset value in 32-bits words
        data_offset = 5 + len(options_bytes) // 4  # TODO take care about options
        # concat 4 data offset bits + 3 reserved zero bits + 9 control bit flags
        data_offset_flags = data_offset << 12 | self.__flags.flags
        header = struct.pack(
            self.TCP_HEADER_FORMAT,
            self.__source_port,
            self.__dest_port,
            self.__sequence_number,
            self.__ack_number,
            data_offset_flags,
            self.__win_size,
            0,  # TODO calculate checksum
            self.__urg_pointer,
            options_bytes
        )
        return header + self.__payload

    @staticmethod
    def from_bytes():
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

    @property
    def payload(self) -> bytearray:
        return self.__payload
