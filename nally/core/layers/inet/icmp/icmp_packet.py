import struct

from nally.core.layers.inet.icmp.icmp_codes import IcmpType, ICMP_CODE,\
    ICMP_VARIABLE_HEADER_FIELDS, IcmpFormat
from nally.core.layers.packet import Packet
from nally.core.utils.utils import Utils


class IcmpPacket(Packet):
    """
    Represents ICMP packet
    """

    ICMP_HEADER_FORMAT = "!BBH"
    """
    Defines format of ICMP header fields:
       * ICMP type : 1 byte
       * ICMP code : 1 byte
       * Checksum : 2 bytes
    """

    def __init__(
            self,
            icmp_type: IcmpType,
            icmp_code: int,
            **kwargs
    ):
        super().__init__()
        self.__icmp_type = icmp_type
        if icmp_code not in ICMP_CODE.get(icmp_type):
            raise ValueError(f'Invalid or unsupported ICMP code:'
                             f'{icmp_type=}, {icmp_code=}')
        self.__icmp_code = icmp_code
        self.__rest_of_header = self._parse_rest_of_header(**kwargs)

    def to_bytes(self) -> bytes:
        header_info: IcmpFormat = self._get_header_format(
            self.icmp_type,
            self.icmp_code
        )
        rest_of_header = None
        # pack rest of the header fields if needed,
        # otherwize 4 zero bytes will be used
        if header_info.header_format is not None:
            rest_of_header = struct.pack(
                header_info.header_format,
                *self.rest_of_header.values()
            )
        else:
            rest_of_header = b'\0\0\0\0'

        header_fields = [
            self.icmp_type,
            self.icmp_code,
            0 # checksum, will be calculated later
        ]

        # allocate 4 bytes buffer to put header without variable fields in
        header_buffer = bytearray(4)
        # pack header without checksum and variable fields to the buffer
        struct.pack_into(
            self.ICMP_HEADER_FORMAT,
            header_buffer,
            0,
            *header_fields
        )
        # finally add variable header fields to the buffer
        header_buffer += rest_of_header

        payload = self.raw_payload
        checksum_bytes = Utils.calc_checksum(header_buffer + payload)
        # checksum takes 2-nd and 3-rd bytes of the header (counting from 0)
        # see https://tools.ietf.org/html/rfc792 for more details
        header_buffer[2] = checksum_bytes[0]
        header_buffer[3] = checksum_bytes[1]

        return bytes(header_buffer) + payload

    @staticmethod
    def from_bytes(packet_bytes: bytes):
        header_bytes = packet_bytes[:8]
        # unpack first 4 bytes firstly since we need to know ICMP type
        # and code to find out format of last 4 ones
        header_fields = struct.unpack(
            IcmpPacket.ICMP_HEADER_FORMAT,
            header_bytes[:4]
        )
        icmp_type = header_fields[0]
        icmp_code = header_fields[1]
        header_info = IcmpPacket._get_header_format(icmp_type, icmp_code)

        variable_header_fields = ()
        if header_info.header_format is not None:
            variable_header_fields = struct.unpack(
                header_info.header_format,
                header_bytes[4:8]
            )

        required_fields = header_info.required_header_fields
        assert len(variable_header_fields) == len(required_fields)

        rest_of_header = {
            field: variable_header_fields[index]
            for index, field in enumerate(required_fields)
        }

        payload = packet_bytes[8:]  # TODO specify data length

        return IcmpPacket(
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            **rest_of_header
        ) / payload

    def _parse_rest_of_header(self, **kwargs) -> dict:
        """
        Parses ICMP Rest of Header field from kwargs
        according to ICMP type and code
        """
        header_info: IcmpFormat = self._get_header_format(
            self.icmp_type,
            self.icmp_code
        )
        rest_of_header = {}
        for field in header_info.required_header_fields:
            field_value = kwargs.get(field)
            if field_value is None:
                raise ValueError(f'Required field {field} is missing,'
                                 '{self.icmp_type=}, {self.icmp_code=}')
            rest_of_header[field] = field_value
        return rest_of_header

    @staticmethod
    def _get_header_format(
            icmp_type: IcmpType,
            icmp_code: int
    ) -> IcmpFormat:
        """
        Returns IcmpFormat instance for this ICMP type and code,
        returned object defines list of required header fields and
        their memory format
        """
        header_info = ICMP_VARIABLE_HEADER_FIELDS[icmp_type]
        if isinstance(header_info, dict):
            header_info = header_info.get(icmp_code)
        return header_info

    def is_response(self, packet: Packet) -> bool:
        pass

    @property
    def icmp_type(self) -> IcmpType:
        return self.__icmp_type

    @property
    def icmp_code(self) -> int:
        return self.__icmp_code

    @property
    def rest_of_header(self) -> dict:
        return self.__rest_of_header

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IcmpPacket):
            return False
        return self.icmp_type == other.icmp_type and \
               self.icmp_type == other.icmp_type and \
               self.rest_of_header == other.rest_of_header and \
               self.upper_layer == other.upper_layer

    def __str__(self):
        return f'ICMP({self.icmp_type=},{self.icmp_code=},' \
                f'{self.rest_of_header=})'
