from abc import ABC, abstractmethod

from port_scanner.utils.utils import Utils


class BitFlags(ABC):

    def __init__(self):
        self._flags = 0

    @staticmethod
    @abstractmethod
    def from_int(bits: int):
        raise NotImplementedError

    @property
    def flags(self) -> int:
        return self._flags

    def is_flag_set(self, flag_mask: int) -> bool:
        """
        Checks if flag is set using the bit mask

        :param int flag_mask: bit mask associated with flag
        :return: True if flag is set, False otherwise
        """
        return Utils.is_bit_set(self._flags, flag_mask)

    def set_flag(self, flag_mask: int, value: bool):
        """
        Sets flag using the bit mask to 1 or 0

        :param int flag_mask: bit mask associated with flag
        :param bool value: value which flag should be set to
        """
        self._flags = Utils.set_bit(self._flags, flag_mask, value)
