import struct

from port_scanner.layers.tcp.tcp_control_bits import TcpControlBits


class TcpPacket:

    TCP_HEADER_FORMAT = "!HHIIHHHH"

    def __init__(
            self,
            source_port: int,
            dest_port: int,
            sequence_number: int,
            ack_number: int,
            data_offset: int,
            flags: TcpControlBits,
            win_size: int,
            urg_pointer: int,
            payload: bytearray

    ):
        self.__source_port = source_port
        self.__dest_port = dest_port
        self.__sequence_number = sequence_number
        self.__ack_number = ack_number
        self.__data_offset = data_offset
        self.__flags = flags
        self.__win_size = win_size
        self.__urg_pointer = urg_pointer
        self.__payload = payload

    def to_bytes(self):
        # concat 4 data offset bits + 3 reserved zero bits + 9 control bit flags
        data_offset_flags = self.__data_offset << 12 | self.__flags.flags
        header = struct.pack(
            self.TCP_HEADER_FORMAT,
            self.__source_port,
            self.__dest_port,
            self.__sequence_number,
            self.__ack_number,
            data_offset_flags,
            self.__win_size,
            0,
            self.__urg_pointer
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
    def data_offset(self) -> int:
        return self.__data_offset

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
    def payload(self) -> bytearray:
        return self.__payload
