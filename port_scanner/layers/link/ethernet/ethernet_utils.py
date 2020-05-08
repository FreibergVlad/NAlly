from port_scanner.layers.link.proto_type import EtherType


class EthernetUtils:

    MAC_LENGTH_BYTES = 6
    MAX_PAYLOAD_LENGTH_BYTES = 1500
    MIN_PAYLOAD_LENGTH_BYTES = 46

    @staticmethod
    def validate_mac(mac) -> bytes:
        """
        Validates and returns MAC address

        :param mac: either a string representation of MAC address (with or without ':' delimiter),
            or the bytes one
        :return: validated MAC address
        :raises: ValueError: if passed value isn't valid MAC address
        """
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
        """
        Converts string representation of MAC address to the bytes one

        :param hex_mac: hexadecimal MAC string (with or without ':' delimiter)
        :return: MAC bytes object
        """
        hex_mac_bytes = hex_mac.split(":")
        if len(hex_mac_bytes) == EthernetUtils.MAC_LENGTH_BYTES:
            hex_mac = "".join(hex_mac_bytes)
        return EthernetUtils.validate_mac_length(bytes.fromhex(hex_mac))

    @staticmethod
    def validate_payload(payload_bytes):
        """
        Validates payload length against to maximum Ethernet frame size

        :param payload_bytes:
        :return:
        """
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
