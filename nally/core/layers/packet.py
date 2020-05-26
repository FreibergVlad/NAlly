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
        """
        Converts 'Packet' instance to the 'bytes' representation ready to be sent over the network
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def from_bytes(bytes_packet: bytes):
        """
        Converts raw bytes to the Packet instance, also tries to parse upper protocols layers
        """
        raise NotImplementedError

    @property
    def raw_payload(self) -> bytes:
        """
        Returns 'bytes' representation of all upper protocols layers if present
        """
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

    def __getitem__(self, key):
        """
        Layers accessor, accepts layer class and recursively searches it in the payload
        """
        if isinstance(self, key):
            return self
        if self.upper_layer is None:
            return None
        return self.upper_layer[key]

    def __contains__(self, key):
        return self[key] is not None

    def __truediv__(self, other):
        """
        Performs layer stacking. Puts right packet to the payload of the left one.
        If right packet already has the upper layer packet, then checks all upper layers
        until packet without payload will be found

        :param other: either a Packet instance or raw bytes
        """
        if isinstance(other, (bytes, bytearray)):
            from nally.core.layers.raw_packet import RawPacket
            other = RawPacket(other)
        if not isinstance(other, Packet):
            raise ValueError("Underlying packet should be Packet instance")
        self_copy = self.clone()
        other_copy = other.clone()
        self_copy.add_payload(other_copy)
        return self_copy
