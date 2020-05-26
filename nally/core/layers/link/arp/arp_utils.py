from enum import IntEnum

from nally.core.layers.inet.ip.ip_utils import IpUtils
from nally.core.layers.link.ethernet.ethernet_utils import EthernetUtils
from nally.core.layers.link.proto_type import EtherType


class ArpHardwareType(IntEnum):
    """
    Stores possible values for 'HTYPE' field in ARP frame, used to specify the network link protocol type
    List of possible values described at https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
    """

    # ====== New supported protocols should be added below ======
    ETHERNET = 1


class ArpOperation(IntEnum):

    OP_REQUEST = 0x0001
    OP_REPLY = 0x0002


class ArpUtils:
    """
    Defines useful utility methods related to ARP protocol
    """

    HARDWARE_LENGTH = {
        ArpHardwareType.ETHERNET: 6
    }
    """
    Defines possible values of HLEN field in accordance with HTYPE field values
    """

    PROTOCOL_LENGTH = {
        EtherType.IPV4: 4
    }
    """
    Defines possible values of PLEN field in accordance with PTYPE field values
    """

    HW_ADDR_VALIDATORS = {
        ArpHardwareType.ETHERNET: EthernetUtils.validate_mac
    }
    """
    Defines validators for SHA, THA fields in accordance with HTYPE field values
    """

    PROTO_ADDR_VALIDATORS = {
        EtherType.IPV4: IpUtils.validate_and_pack_ip4_addr
    }
    """
    Defines validators for SPA, TPA fields in accordance with PTYPE field values
    """

    @staticmethod
    def validate_hw_addr(hw_addr, hw_type: ArpHardwareType) -> bytes:
        """
        Validates hardware address in accordance with hardware type
        """
        addr_validator = ArpUtils.HW_ADDR_VALIDATORS.get(hw_type)
        if addr_validator is None:
            raise ValueError(f"Unsupported protocol type: {hw_type}")
        return addr_validator(hw_addr)

    @staticmethod
    def validate_proto_addr(proto_addr, proto_type: EtherType) -> bytes:
        """
        Validates protocol address in accordance with protocol type
        """
        addr_validator = ArpUtils.PROTO_ADDR_VALIDATORS.get(proto_type)
        if addr_validator is None:
            raise ValueError(f"Unsupported protocol type: {proto_type}")
        return addr_validator(proto_addr)

    @staticmethod
    def resolve_proto_len(proto_type: EtherType) -> int:
        """
        Resolves 'PLEN' field value in accordance to protocol type
        """
        proto_len = ArpUtils.PROTOCOL_LENGTH.get(proto_type)
        if proto_len is None:
            raise ValueError(f"Unsupported protocol type: {proto_type}")
        return proto_len

    @staticmethod
    def resolve_hw_len(hw_type: ArpHardwareType) -> int:
        """
        Resolves 'HLEN' field value in accordance to protocol type
        """
        hw_len = ArpUtils.HARDWARE_LENGTH.get(hw_type)
        if hw_len is None:
            raise ValueError(f"Unsupported link protocol type: {hw_type}")
        return hw_len
