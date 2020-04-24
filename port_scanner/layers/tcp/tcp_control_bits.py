from port_scanner.utils.bit_flags import BitFlags
from port_scanner.utils.utils import Utils


class TcpControlBits(BitFlags):
    """
    Represents 9 TCP control flags, can be used for storing, setting or retrieving flags
    """

    NS = 256
    """Bit mask used to check or set NS flag """
    CWR = 128
    """Bit mask used to check or set CWR flag """
    ECE = 64
    """Bit mask used to check or set ECE flag """
    URG = 32
    """Bit mask used to check or set URG flag """
    ACK = 16
    """Bit mask used to check or set ACK flag """
    PSH = 8
    """Bit mask used to check or set PSH flag """
    RST = 4
    """Bit mask used to check or set RST flag """
    SYN = 2
    """Bit mask used to check or set SYN flag """
    FIN = 1
    """Bit mask used to check or set FIN flag """

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
        """
        Initialises TCPControlBits instance

        :param bool ns: ECN-nonce - concealment protection
        :param bool cwr: Congestion window reduced (CWR) flag is set by the sending host to indicate that it received a
            TCP segment with the ECE flag set and had responded in congestion control mechanism
        :param bool ece: ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
            * If the SYN flag is set (1), that the TCP peer is ECN capable.
            * If the SYN flag is clear (0), that a packet with Congestion Experienced flag set (ECN=11) in the IP header
            was received during normal transmission. This serves as an indication of network congestion
            (or impending congestion) to the TCP sender.
        :param bool urg: indicates that the Urgent pointer field is significant
        :param bool ack: indicates that the Acknowledgment field is significant. All packets after the initial SYN
            packet sent by the client should have this flag set
        :param bool psh: push function. Asks to push the buffered data to the receiving application
        :param bool rst: reset the connection
        :param bool syn: synchronize sequence numbers. Only the first packet sent from each end should have this flag
            set. Some other flags and fields change meaning based on this flag, and some are only valid when it is set,
            and others when it is clear
        :param bool fin: means that current packet is the last packet from sender
        """
        super().__init__()
        self.set_flag(self.NS, ns)
        self.set_flag(self.CWR, cwr)
        self.set_flag(self.ECE, ece)
        self.set_flag(self.URG, urg)
        self.set_flag(self.ACK, ack)
        self.set_flag(self.PSH, psh)
        self.set_flag(self.RST, rst)
        self.set_flag(self.SYN, syn)
        self.set_flag(self.FIN, fin)

    @staticmethod
    def from_int(bits: int):
        """
        Creates TcpControlBits instance from integer

        :param int bits: integer which represents bit flags
        :return: TcpControlBits instance
        """
        is_flag_set: callable = Utils.is_bit_set
        return TcpControlBits(
            is_flag_set(bits, TcpControlBits.NS),
            is_flag_set(bits, TcpControlBits.CWR),
            is_flag_set(bits, TcpControlBits.ECE),
            is_flag_set(bits, TcpControlBits.URG),
            is_flag_set(bits, TcpControlBits.ACK),
            is_flag_set(bits, TcpControlBits.PSH),
            is_flag_set(bits, TcpControlBits.RST),
            is_flag_set(bits, TcpControlBits.SYN),
            is_flag_set(bits, TcpControlBits.FIN)
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TcpControlBits):
            return self.flags == other.flags

    def __str__(self) -> str:
        flags_str = ""
        is_flag_set: callable = Utils.is_bit_set
        if is_flag_set(self.flags, TcpControlBits.NS): flags_str += "ns "
        if is_flag_set(self.flags, TcpControlBits.CWR): flags_str += "cwr "
        if is_flag_set(self.flags, TcpControlBits.ECE): flags_str += "ece "
        if is_flag_set(self.flags, TcpControlBits.URG): flags_str += "urg "
        if is_flag_set(self.flags, TcpControlBits.ACK): flags_str += "ack "
        if is_flag_set(self.flags, TcpControlBits.PSH): flags_str += "psh "
        if is_flag_set(self.flags, TcpControlBits.RST): flags_str += "rst "
        if is_flag_set(self.flags, TcpControlBits.SYN): flags_str += "syn "
        if is_flag_set(self.flags, TcpControlBits.FIN): flags_str += "fin"
        return flags_str.strip()
