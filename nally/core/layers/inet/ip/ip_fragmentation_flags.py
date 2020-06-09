from nally.core.utils.bit_flags import BitFlags
from nally.core.utils.utils import Utils


class IpFragmentationFlags(BitFlags):
    """
    Represents 3-bits field which contains fragmentation flags for IP protocol
    """

    DF = 2
    """Bit mask used to check or set DF flag"""
    MF = 1
    """Bit mask used to check or set MF flag"""

    def __init__(self, mf=False, df=False):
        """
        Initialises IP fragmentation flags

        :param bool mf: when set, then indicates that the packet contains
            more fragments
        :param bool df: when set, then indicates that the packet cannot be
            fragmented for transmission
        """
        super().__init__()
        self.set_flag(self.MF, mf)
        self.set_flag(self.DF, df)

    @staticmethod
    def from_int(bits: int):
        """
        Creates IpFragmentationFlags instance from integer

        :param int bits: integer which represents bit flags
        :return: IpFragmentationFlags instance
        """
        df_flag = Utils.is_bit_set(bits, IpFragmentationFlags.DF)
        mf_flag = Utils.is_bit_set(bits, IpFragmentationFlags.MF)
        return IpFragmentationFlags(mf=mf_flag, df=df_flag)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, IpFragmentationFlags):
            return self.flags == other.flags

    def __str__(self) -> str:
        res = ""
        if self.is_flag_set(self.DF):
            res += "df "
        if self.is_flag_set(self.MF):
            res += "mf"
        if len(res) == 0:
            res = "none"
        return res.strip()
