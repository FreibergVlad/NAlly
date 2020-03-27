from unittest import TestCase

from port_scanner.layers.link.proto_type import EtherType
from port_scanner.layers.link.ethernet.ethernet_packet import EthernetPacket

HEX_PAYLOAD = "4500006958c240000111a6120a0a9027e0670017b1fcb1fc00556bca54524942" \
              "45532d420100000000350000000005dd9e5d00000fa0ffffffffffffffff040a" \
              "0a9264000000000000000012c9473238ea48c28d117ab6664b9f94000000005452494245532d450100"
#
# Destination MAC = "01 00 5e 67 00 17"
# Source MAC = "52 54 00 33 fd 06"
# Type = IPV4
#
HEX_PACKET = "01005e67001752540033fd060800" + HEX_PAYLOAD


class TestEthernetPacket(TestCase):

    def test_to_bytes(self):
        packet = EthernetPacket(
            dest_mac="01 00 5e 67 00 17",
            source_mac="52 54 00 33 fd 06",
            ether_type=EtherType.IPV4,
            payload=bytearray.fromhex(HEX_PAYLOAD)
        )
        packet_bytes = packet.to_bytes()
        self.assertEqual(HEX_PACKET, packet_bytes.hex())
        self.assertEqual(packet, EthernetPacket.from_bytes(packet_bytes))
