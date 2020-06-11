import struct

from nally.core.layers.link.arp.arp_utils import ArpUtils, ArpOperation
from nally.core.layers.link.proto_type import EtherType
from nally.core.layers.link.arp.arp_utils import ArpHardwareType
from nally.core.layers.packet import Packet


class ArpPacket(Packet):
    """
    Represents ARP (Address Resolution Protocol) packet
    """

    ARP_PACKET_FORMAT = "!HHBBH"
    """
    Defines format of ARP packet without hardware and protocol addresses
    (their sizes calculated dynamically based on HLEN, PLEN fields values):
        * HTYPE field : 2 bytes
        * PTYPE field : 2 bytes
        * HLEN field : 1 byte
        * PLEN field : 1 byte
        * Operation field : 1 byte
    """

    def __init__(
            self,
            operation: ArpOperation,
            sender_hw_address,
            sender_proto_address,
            target_hw_address,
            target_proto_address,
            hardware_type: ArpHardwareType = ArpHardwareType.ETHERNET,
            protocol_type: EtherType = EtherType.IPV4,
    ):
        """
        Initializes ARP packet instance

        :param operation: Operation field, instance of ArpOperation enum
        :param sender_hw_address: sender hardware address, format depends on
            HTYPE field
        :param sender_proto_address: sender protocol address, format depends on
            PTYPE field
        :param target_hw_address: target hardware address, format depends on
            HTYPE field
        :param target_proto_address: target protocol address, format depends on
            PTYPE field
        :param hardware_type: HTYPE field, instance of ArpHardwareType enum,
            Ethernet by default
        :param protocol_type: PTYPE field, instance of EtherType enum,
            IPv4 by default
        """
        super().__init__()
        self.__hardware_type = hardware_type
        self.__protocol_type = protocol_type
        self.__operation = operation
        self.__hw_len = ArpUtils.resolve_hw_len(hardware_type)
        self.__proto_len = ArpUtils.resolve_proto_len(protocol_type)
        self.__sender_hw_address = ArpUtils.validate_hw_addr(
            sender_hw_address,
            hardware_type
        )
        self.__sender_proto_address = ArpUtils.validate_proto_addr(
            sender_proto_address,
            protocol_type
        )
        self.__target_hw_address = ArpUtils.validate_hw_addr(
            target_hw_address,
            hardware_type
        )
        self.__target_proto_address = ArpUtils.validate_proto_addr(
            target_proto_address,
            protocol_type
        )

    def to_bytes(self):
        packet_without_addr = struct.pack(
            self.ARP_PACKET_FORMAT,
            self.__hardware_type,
            self.__protocol_type,
            self.__hw_len,
            self.__proto_len,
            self.__operation
        )
        sender_addr = self.__sender_hw_address + self.__sender_proto_address
        dest_addr = self.__target_hw_address + self.__target_proto_address
        return packet_without_addr + sender_addr + dest_addr

    @staticmethod
    def from_bytes(bytes_packet: bytes):
        packet_without_addr_len = struct.calcsize(ArpPacket.ARP_PACKET_FORMAT)
        packet_bytes_without_addr = bytes_packet[:packet_without_addr_len]
        packet_without_addr = struct.unpack_from(
            ArpPacket.ARP_PACKET_FORMAT,
            packet_bytes_without_addr
        )
        hw_type = ArpHardwareType(packet_without_addr[0])
        proto_type = EtherType(packet_without_addr[1])
        hw_len = packet_without_addr[2]
        proto_len = packet_without_addr[3]
        op_code = ArpOperation(packet_without_addr[4])

        cursor = packet_without_addr_len
        sender_hw_addr = bytes_packet[cursor: cursor + hw_len]
        cursor += hw_len
        sender_proto_addr = bytes_packet[cursor: cursor + proto_len]
        cursor += proto_len
        target_hw_addr = bytes_packet[cursor: cursor + hw_len]
        cursor += hw_len
        target_proto_addr = bytes_packet[cursor: cursor + proto_len]

        return ArpPacket(
            hardware_type=hw_type,
            protocol_type=proto_type,
            operation=op_code,
            sender_hw_address=sender_hw_addr,
            sender_proto_address=sender_proto_addr,
            target_hw_address=target_hw_addr,
            target_proto_address=target_proto_addr
        )

    def is_response(self, packet: Packet) -> bool:
        if ArpPacket not in packet:
            return False
        arp_layer: ArpPacket = packet[ArpPacket]
        if self.operation != ArpOperation.OP_REPLY \
                or arp_layer.operation != ArpOperation.OP_REQUEST:
            return False
        if self.proto_type != arp_layer.proto_type:
            return False
        if self.proto_len != arp_layer.proto_len:
            return False
        if self.sender_proto_addr != arp_layer.target_proto_addr:
            return False
        if self.target_proto_addr != arp_layer.sender_proto_addr:
            return False
        return True

    @property
    def hw_type(self) -> ArpHardwareType:
        return self.__hardware_type

    @property
    def proto_type(self) -> EtherType:
        return self.__protocol_type

    @property
    def operation(self) -> ArpOperation:
        return self.__operation

    @property
    def hw_len(self) -> int:
        return self.__hw_len

    @property
    def proto_len(self) -> int:
        return self.__proto_len

    @property
    def sender_hw_addr(self) -> bytes:
        return self.__sender_hw_address

    @property
    def sender_proto_addr(self) -> bytes:
        return self.__sender_proto_address

    @property
    def target_hw_addr(self) -> bytes:
        return self.__target_hw_address

    @property
    def target_proto_addr(self) -> bytes:
        return self.__target_proto_address

    @Packet.upper_layer.setter
    def upper_layer(self, packet):
        raise NotImplementedError("ARP packet doesn't support payload")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ArpPacket):
            return self.hw_type == other.hw_type and \
                   self.proto_type == other.proto_type and \
                   self.operation == other.operation and \
                   self.hw_len == other.hw_len and \
                   self.proto_len == other.proto_len and \
                   self.sender_hw_addr == other.sender_hw_addr and \
                   self.sender_proto_addr == other.sender_proto_addr and \
                   self.target_hw_addr == other.target_hw_addr and \
                   self.target_proto_addr == other.target_proto_addr
