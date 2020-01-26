class TcpControlBits:

    __flags = 0

    NS = 256
    CWR = 128
    ECE = 64
    URG = 32
    ACK = 16
    PSH = 8
    RST = 4
    SYN = 2
    FIN = 1

    def __init__(
            self,
            ns=False,
            cwr=False,
            ece=False,
            urg=False,
            ack=False,
            psh=False,
            rst=False,
            syn=False,
            fin=False
    ):
        self.__set_flag(self.NS, ns)
        self.__set_flag(self.CWR, cwr)
        self.__set_flag(self.ECE, ece)
        self.__set_flag(self.URG, urg)
        self.__set_flag(self.ACK, ack)
        self.__set_flag(self.PSH, psh)
        self.__set_flag(self.RST, rst)
        self.__set_flag(self.SYN, syn)
        self.__set_flag(self.FIN, fin)

    @property
    def flags(self):
        return self.__flags

    def is_flag_set(self, flag_mask) -> bool:
        return self.__flags & flag_mask != 0

    def __set_flag(self, flag_mask: int, value: bool):
        if value:  # bit is 1
            self.__flags = self.__flags | flag_mask
        else:  # bit is 0
            self.__flags = self.__flags & ~flag_mask

