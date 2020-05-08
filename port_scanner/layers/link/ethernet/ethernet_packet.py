import logging
import struct

from port_scanner.layers.inet.ip.ip_packet import IpPacket
from port_scanner.layers.link.arp.arp_packet import ArpPacket
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

    INTERNET_LAYER_CONVERTERS = {
        EtherType.IPV4: IpPacket.from_bytes,
        EtherType.ARP: ArpPacket.from_bytes
    }
    """
    Defines converters to the Internet layer packets based on the value of EtherType field in Ethernet frame
    """

    LOG = logging.getLogger("EthernetPacket")

    def __init__(
            self,
            dest_mac,
            source_mac,
            ether_type=EtherType.IPV4,
    ):
        """
        Initializes Ethernet frame instance
        :param dest_mac: destination MAC address, could be either a byte array or hexadecimal string
        :param source_mac: source MAC address, could be either a byte array or hexadecimal string
        :param ether_type: can either be a 2 bytes number which specifies payload size in bytes or EtherType instance
            which indicates which protocol is encapsulated in the payload of the frame
        """
        super().__init__()
        self.__dest_mac = EthernetUtils.validate_mac(dest_mac)
        self.__source_mac = EthernetUtils.validate_mac(source_mac)
        self.__ether_type = EthernetUtils.validate_ether_type(ether_type)

    def to_bytes(self):
        header = struct.pack(
            self.ETHERNET_PACKET_FORMAT,
            self.__dest_mac,
            self.__source_mac,
            self.__ether_type,
        )
        return header + EthernetUtils.validate_payload(self.raw_payload)

    @staticmethod
    def from_bytes(bytes_packet: bytes):
        header_bytes = bytes_packet[:EthernetPacket.ETHERNET_HEADER_LENGTH_BYTES]
        payload_bytes = EthernetUtils.validate_payload(bytes_packet[EthernetPacket.ETHERNET_HEADER_LENGTH_BYTES:])
        packet_fields = struct.unpack(EthernetPacket.ETHERNET_PACKET_FORMAT, header_bytes)
        dest_mac = packet_fields[0]
        source_mac = packet_fields[1]
        ether_type = packet_fields[2]
        ethernet_packet = EthernetPacket(dest_mac, source_mac, ether_type)
        if len(payload_bytes) == 0:
            return ethernet_packet
        # try to find appropriate converter based on EtherType field
        internet_layer_converter = EthernetPacket.INTERNET_LAYER_CONVERTERS.get(ether_type)
        if internet_layer_converter is None:
            EthernetPacket.LOG.warning(
                f"Can't find converter to internet layer packet. "
                f"EtherType: {ether_type}. "
                f"Payload: {payload_bytes.hex()}"
            )
            return ethernet_packet
        internet_layer = internet_layer_converter(payload_bytes)
        return ethernet_packet / internet_layer

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
                   self.upper_layer == other.upper_layer
        return False

    def __str__(self) -> str:
        dest_mac = self.dest_mac.hex()
        src_mac = self.source_mac.hex()
        ether_type = hex(self.ether_type)
        ether_type_name = self.ether_type.name if isinstance(self.ether_type, EtherType) else "length"
        return f"Ethernet(dest_mac={dest_mac}, src_mac={src_mac}, " \
               f"ether_type={ether_type} ({ether_type_name})) "
