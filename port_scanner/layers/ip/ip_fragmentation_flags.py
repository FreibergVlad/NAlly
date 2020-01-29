from port_scanner.utils.bit_flags import BitFlags
from port_scanner.utils.utils import Utils


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

        :param bool mf: when set, then indicates that the packet contains more fragments
        :param bool df: when set, then indicates that the packet cannot be fragmented for transmission
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
