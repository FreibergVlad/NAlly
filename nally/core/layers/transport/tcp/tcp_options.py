from typing import Dict
from typing import Tuple

import struct

from nally.core.layers.transport.tcp.tcp_utils import TcpUtils


class TcpOptions:
    """
    Represents TCP header's 'Options' field. Supported options:
        * End of options
        * No operation
        * Maximum segment size
        * Window scale
        * Selective Acknowledgement permitted
        * Selective Acknowledgement
        * Timestamps
    See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1 for mode details # noqa
    """

    END_OF_OPTIONS = "EOL"
    NOP = "NOP"
    MAX_SEGMENT_SIZE = "MSS"
    WINDOW_SCALE = "WS"
    SACK_PERMITTED = "SACK_OK"
    SACK = "SACK"
    TIMESTAMPS = "TIMESTAMPS"

    #
    # Storage of supported options definitions. Option definition is a
    # tuple with min size 1 and max 3 fields:
    #   * Option kind
    #   * Option length (includes 1 byte of 'kind' field and 1 byte of
    #       'length' field itself)
    #   * Format string (may be None for variable length fields)
    #
    SUPPORTED_OPTIONS: Dict[str, Tuple[int, int, str]] = {
        END_OF_OPTIONS: (0,),
        NOP: (1,),
        MAX_SEGMENT_SIZE: (2, 4, "!H"),
        WINDOW_SCALE: (3, 3, "!B"),
        SACK_PERMITTED: (4, 2, None),
        SACK: (5, None, None),
        TIMESTAMPS: (8, 10, "!II")
    }

    OPTION_KINDS = {
        0: END_OF_OPTIONS,
        1: NOP,
        2: MAX_SEGMENT_SIZE,
        3: WINDOW_SCALE,
        4: SACK_PERMITTED,
        5: SACK,
        8: TIMESTAMPS
    }

    def __init__(self, options: list = None):
        """
        Initialises TcpOptions instance
        :param list options: option list, list items can be in the
        following format:
            * String. For options that don't have 'length' and 'value'
                fields (like NOP)
            * Tuple[str, int]. For options with only one value
            * Tuple[str, list]. For options with multiple values
                (like TIMESTAMPS, SACK etc)
        """
        self.__options = []
        if options is None:
            options = []
        for option in options:
            if isinstance(option, tuple):
                if len(option) != 2:
                    raise ValueError(f"Invalid option "
                                     f"{option}. Should a tuple with 2 "
                                     f"elements (name, value)")
                option_name = option[0]
                if not isinstance(option_name, str):
                    raise ValueError(f"Invalid option name "
                                     f"{option_name}. Should be a string")
                option_value = option[1]
                if isinstance(option_value, list):
                    self.__options.append(option)
                elif isinstance(option_value, int):
                    self.__options.append((option_name, [option_value]))
                else:
                    raise ValueError(f"Invalid option value "
                                     f"{option_value}. Should either a "
                                     f"'int' or a 'list[int]'")
            elif isinstance(option, str):
                self.__options.append((option, None))
            else:
                raise ValueError(f"Invalid option "
                                 f"{option}. "
                                 f"Should be either a 'Tuple[str, list|int]' "
                                 f"or a 'str'")

    def to_bytes(self) -> bytes:
        """
        Converts options to the binary format ready to be sent over the
        network. Performs padding if necessary

        :return: byte array representation of options
        :raises: ValueError: if options length is more that max allowed value
            (40 bytes)
        """
        options_bytes = bytearray()
        for option in self.__options:
            opt_name: str = option[0]
            if opt_name not in self.SUPPORTED_OPTIONS:
                raise ValueError(f"Unknown option {opt_name}")
            if opt_name == self.END_OF_OPTIONS:
                options_bytes.append(0x00)
                continue
            if opt_name == self.NOP:
                options_bytes.append(0x01)
                continue
            opt_values: list = option[1]
            opt_kind: int = self.SUPPORTED_OPTIONS[opt_name][0]
            opt_length: int = self.SUPPORTED_OPTIONS[opt_name][1]
            opt_format: str = self.SUPPORTED_OPTIONS[opt_name][2]
            if opt_name == self.SACK:  # SACK option has variable length
                # calculating 'length' field, consider that each SACK block
                # is 4 bytes unsigned integer. Also include 1 byte of
                # 'option kind' field and 1 byte of 'length' field itself
                opt_length: int = len(opt_values) * 4 + 2
                opt_format: str = f"!{len(opt_values)}I"
            option_bytes = bytearray([opt_kind, opt_length])
            if opt_values:
                option_bytes += struct.pack(opt_format, *opt_values)
            options_bytes += option_bytes

        # pad with zeros to make the bit length divisible by 32
        options_bytes += b"\x00" * (3 - ((len(options_bytes) + 3) % 4))
        TcpUtils.validate_options_length(options_bytes)
        return options_bytes

    @staticmethod
    def from_bytes(options_bytes: bytes):
        """
        :param bytes options_bytes: byte array representation of options
        :return: TcpOptions instance
        :raises: ValueError: if options length is more that max allowed value
            (40 bytes) or options have incorrect format
        """
        TcpUtils.validate_options_length(options_bytes)
        index = 0
        options = []
        while index < len(options_bytes):
            option_kind = options_bytes[index]
            if option_kind not in TcpOptions.OPTION_KINDS:
                raise ValueError(f"Unknown option kind {option_kind}")
            option_name = TcpOptions.OPTION_KINDS[option_kind]
            if option_name == TcpOptions.END_OF_OPTIONS:
                break
            if option_name == TcpOptions.NOP:
                options.append(TcpOptions.NOP)
                index += 1
                continue
            option_length = options_bytes[index + 1]
            if option_length < 2:
                raise ValueError(f"Invalid option length {option_length}")
            # option length 2 means that no value is present
            if option_length == 2:
                index += 2
                options.append(option_name)
                continue
            option_value_bytes = options_bytes[index + 2:index + option_length]
            option_format: str = TcpOptions.SUPPORTED_OPTIONS[option_name][2]
            if option_name == TcpOptions.SACK:
                # calculate number of 4-bytes words
                option_format: str = f"!{len(option_value_bytes) // 4}I"
            option_value: tuple = struct.unpack_from(
                option_format,
                option_value_bytes
            )
            if len(option_value) == 0:
                raise ValueError(f"Option value is empty. Option name: "
                                 f"{option_name}")
            elif len(option_value) == 1:
                options.append((option_name, option_value[0]))
            else:
                options.append((option_name, list(option_value)))
            index += option_length
        return TcpOptions(options)

    @property
    def options(self):
        return self.__options

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TcpOptions):
            return self.__options == other.options
        return False

    def __str__(self) -> str:
        res = ""
        options_len = len(self.__options)
        for i in range(options_len):
            opt_name = self.__options[i][0]
            opt_value = self.__options[i][1]
            if opt_value is None:
                res += opt_name
            else:
                res += f"{opt_name}={opt_value}"
            if options_len - 1 != i:
                res += ", "
        return res
