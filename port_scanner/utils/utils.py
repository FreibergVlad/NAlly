class Utils:

    @staticmethod
    def set_bit(num: int, bit_mask: int, value: bool) -> int:
        if value:  # bit is 1
            return num | bit_mask
        else:  # bit is 0
            return num & ~bit_mask

    @staticmethod
    def is_bit_set(bits: int, bit_mask: int) -> bool:
        return bits & bit_mask != 0