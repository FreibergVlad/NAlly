import copy
from abc import ABC, abstractmethod


class Packet(ABC):
    """
    Abstract class which defines the base interface for all network packets implementation
    """

    def __init__(self):
        self._payload = bytearray()
        self._underlying_packet = None

    @abstractmethod
    def to_bytes(self):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def from_bytes(bytes_packet: bytes):
        raise NotImplementedError

    @property
    def payload(self) -> bytearray:
        return self._payload

    @payload.setter
    def payload(self, payload: bytearray):
        self._payload = payload

    @property
    def underlying_packet(self):
        return self._underlying_packet

    @underlying_packet.setter
    def underlying_packet(self, packet):
        if isinstance(packet, Packet):
            self._underlying_packet = packet
        else:
            raise ValueError("Underlying packet should be Packet instance")

    def clone(self):
        return copy.deepcopy(self)

    def __truediv__(self, other):
        if not isinstance(other, Packet):
            raise ValueError("Underlying packet should be Packet instance")
        copied_packet = self.clone()
        other.underlying_packet = copied_packet
        copied_packet.payload = other.to_bytes()
        return copied_packet
