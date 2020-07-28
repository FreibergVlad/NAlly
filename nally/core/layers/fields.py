import struct

from enum import Enum


class Field:

    def __init__(
            self,
            name: str,
            field_format: str = None,
            default_value: int = 0
    ):
        """
        @param name: field name
        @param field_format: format string used to specify field layout, see
            https://docs.python.org/3/library/struct.html#format-strings
            for more details
        @param default_value: default field value
        """
        self.name = name
        self.default_value = default_value
        # if format string doesn't include byte order character,
        # then use network byte order
        if field_format and field_format[0] not in "@=<>!":
            field_format = "!" + field_format
        self.field_format = field_format

    def to_bytes(self, value: int = None) -> bytes:
        """
        Converts field value to the bytes representation
        ready to be sent over the network
        """
        if self.field_format is None:
            raise RuntimeError("If field format isn't specified,"
                               "method 'to_bytes' should be overridden")
        value = self._prepare_field_value(value)
        return struct.pack(self.field_format, value)

    def _validate(self, value: int):
        """
        Validates field value
        """

    def _prepare_field_value(self, value) -> int:
        """
        Applies defaults and handles None values
        """
        if value is not None:
            return value
        value = self.default_value or 0
        return value


class ShortField(Field):
    """
    Represents unsigned short 2 bytes field
    """

    def __init__(self, name: str, default_value: int = 0):
        super().__init__(name, "H", default_value)


class ByteField(Field):
    """
    Represents unsigned char 1 byte field
    """

    def __init__(self, name: str, default_value: int = 0):
        super().__init__(name, "B", default_value)


class BitField(Field):

    def __init__(self, name: str, bit_length: int, default_value: int = 0):
        super().__init__(name=name, default_value=default_value)
        self.bit_length = bit_length


class EnumBitField(BitField):

    def __init__(
            self,
            name: str,
            bit_length: int,
            enum: Enum,
            default_value: int = 0
    ):
        super().__init__(
            name=name,
            bit_length=bit_length,
            default_value=default_value
        )
        self.enum = enum
