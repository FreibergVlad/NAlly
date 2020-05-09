from port_scanner.layers.packet import Packet


class RawPacket(Packet):
    """
    Raw implementation of Packet interface. Actually, just a holder of raw bytes
    """

    def __init__(self, raw_packet):
        super().__init__()
        self.__raw_packet = bytes(raw_packet)

    def to_bytes(self):
        return self.__raw_packet

    @staticmethod
    def from_bytes(bytes_packet: bytes):
        return RawPacket(bytes_packet)

    @property
    def raw_packet(self):
        return self.__raw_packet

    @Packet.upper_layer.setter
    def upper_layer(self, upper_layer):
        raise NotImplementedError("Raw packet doesn't support payload")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RawPacket):
            return self.raw_packet == other.raw_packet
        return False
