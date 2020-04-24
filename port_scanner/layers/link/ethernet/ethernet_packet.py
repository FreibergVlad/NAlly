import struct

from port_scanner.layers.link.proto_type import EtherType
from port_scanner.layers.link.ethernet.ethernet_utils import EthernetUtils
from port_scanner.layers.packet import Packet


class EthernetPacket(Packet):
    """
    Represents Ethernet II (DIX Ethernet) frame
    """

    ETHERNET_HEADER_LENGTH_BYTES = 14

    ETHERNET_PACKET_FORMAT = "!6s6sH"
    """
    Ethernet packet format, includes 12 bytes for source and 
    destination MAC addresses and also 2 bytes for EtherType/length field
    """

    def __init__(
            self,
            dest_mac,
            source_mac,
            ether_type: EtherType = EtherType.IPV4,
            payload: bytearray = bytearray(0)
    ):
        """
        Initializes Ethernet frame instance
        :param dest_mac: destination MAC address, could be either a byte array or hexadecimal string
        :param source_mac: source MAC address, could be either a byte array or hexadecimal string
        :param ether_type: indicates which protocol is encapsulated in the payload of the frame
        :param payload: byte array frame payload with length <= 1500 bytes
        """
        super().__init__()
        self.__dest_mac = EthernetUtils.validate_mac(dest_mac)
        self.__source_mac = EthernetUtils.validate_mac(source_mac)
        self.__ether_type = ether_type
        self._payload = EthernetUtils.validate_payload(payload)

    def to_bytes(self):
        header = struct.pack(
            self.ETHERNET_PACKET_FORMAT,
            self.__dest_mac,
            self.__source_mac,
            self.__ether_type,
        )
        return header + self._payload

    @staticmethod
    def from_bytes(bytes_packet: bytes):
        header_bytes = bytes_packet[:EthernetPacket.ETHERNET_HEADER_LENGTH_BYTES]
        payload_bytes = bytes_packet[EthernetPacket.ETHERNET_HEADER_LENGTH_BYTES:]
        packet_fields = struct.unpack(EthernetPacket.ETHERNET_PACKET_FORMAT, header_bytes)
        dest_mac = packet_fields[0]
        source_mac = packet_fields[1]
        ether_type = EtherType(packet_fields[2])
        return EthernetPacket(dest_mac, source_mac, ether_type, bytearray(payload_bytes))

    @Packet.payload.setter
    def payload(self, payload: bytearray):
        self._payload = EthernetUtils.validate_payload(payload)

    @property
    def dest_mac(self):
        return self.__dest_mac

    @property
    def source_mac(self):
        return self.__source_mac

    @property
    def ether_type(self):
        return self.__ether_type

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EthernetPacket):
            return self.source_mac == other.source_mac and \
                   self.dest_mac == other.dest_mac and \
                   self.ether_type == other.ether_type and \
                   self.payload == other.payload
        return False

    def __str__(self) -> str:
        dest_mac = self.dest_mac.hex()
        src_mac = self.source_mac.hex()
        ether_type = hex(self.ether_type)
        return f"Ethernet(dest_mac={dest_mac}, src_mac={src_mac}, " \
               f"ether_type={ether_type} ({self.ether_type.name})) "
