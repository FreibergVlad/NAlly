from port_scanner.layers.link.proto_type import EtherType


class EthernetUtils:

    MAC_LENGTH_BYTES = 6
    MAX_PAYLOAD_LENGTH_BYTES = 1500
    MIN_PAYLOAD_LENGTH_BYTES = 46

    @staticmethod
    def validate_mac(mac) -> bytes:
        if isinstance(mac, bytes) or isinstance(mac, bytearray):
            return EthernetUtils.validate_mac_length(mac)
        if isinstance(mac, str):
            return EthernetUtils.hex_mac_to_bytes(mac)
        raise ValueError("MAC should be either a string value or byte array")

    @staticmethod
    def validate_mac_length(mac: bytes) -> bytes:
        if len(mac) != EthernetUtils.MAC_LENGTH_BYTES:
            raise ValueError(f"MAC address should be {EthernetUtils.MAC_LENGTH_BYTES} bytes length")
        return mac

    @staticmethod
    def hex_mac_to_bytes(hex_mac: str) -> bytes:
        return EthernetUtils.validate_mac_length(bytes.fromhex(hex_mac))

    @staticmethod
    def validate_payload(payload_bytes: bytearray):
        if len(payload_bytes) > EthernetUtils.MAX_PAYLOAD_LENGTH_BYTES:
            raise ValueError(f"Ethernet frame payload can't be greater than "
                             f"{EthernetUtils.MAX_PAYLOAD_LENGTH_BYTES} bytes")
        return payload_bytes

    @staticmethod
    def validate_ether_type(ether_type):
        """
        Validates and return EtherType Ethernet header field
        """
        if isinstance(ether_type, EtherType):
            return ether_type
        elif isinstance(ether_type, int):
            if ether_type <= 1500:
                return ether_type
            elif ether_type >= 1536:
                return EtherType(ether_type)
            else:
                raise ValueError(f"Invalid EtherType field value {ether_type}")
        else:
            raise ValueError(f"Invalid EtherType field value {ether_type}")
