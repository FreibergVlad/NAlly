import copy
from abc import ABC, abstractmethod


class Packet(ABC):
    """
    Abstract class which defines the base interface for all network packets implementation
    """

    def __init__(self):
        self._under_layer = None
        self._upper_layer = None

    @abstractmethod
    def to_bytes(self):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def from_bytes(bytes_packet: bytes):
        raise NotImplementedError

    @property
    def raw_payload(self) -> bytes:
        return self.upper_layer.to_bytes() if self.upper_layer is not None else bytes()

    @property
    def upper_layer(self):
        return self._upper_layer

    @upper_layer.setter
    def upper_layer(self, packet):
        if isinstance(packet, Packet):
            self._upper_layer = packet
        else:
            raise ValueError("Upper layer packet should be Packet instance")

    @property
    def under_layer(self):
        return self._under_layer

    @under_layer.setter
    def under_layer(self, packet):
        if isinstance(packet, Packet):
            self._under_layer = packet
        else:
            raise ValueError("Under layer packet should be Packet instance")

    def clone(self):
        return copy.deepcopy(self)

    def add_payload(self, payload):
        if self.upper_layer is None:
            payload.under_layer = self
            self.upper_layer = payload
        else:
            self.upper_layer.add_payload(payload)

    def __truediv__(self, other):
        if isinstance(other, (bytes, bytearray)):
            from port_scanner.layers.raw_packet import RawPacket
            other = RawPacket(other)
        if not isinstance(other, Packet):
            raise ValueError("Underlying packet should be Packet instance")
        self_copy = self.clone()
        other_copy = other.clone()
        self_copy.add_payload(other_copy)
        return self_copy
