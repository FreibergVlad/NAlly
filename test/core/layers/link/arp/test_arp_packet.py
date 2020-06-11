from unittest import TestCase

from nally.core.layers.link.arp.arp_utils import ArpHardwareType
from nally.core.layers.link.arp.arp_packet import ArpPacket
from nally.core.layers.link.arp.arp_utils import ArpOperation
from nally.core.layers.link.proto_type import EtherType

#
# Hardware type = Ethernet (1)
# Protocol type = IPv4 (0x08)
# Hardware length = 6
# Protocol length = 4
# Operation code: request (1)
# Sender HW address = b0:6e:bf:c7:e6:ba
# Sender protocol address = 10.10.128.161
# Target HW address = 00:00:00:00:00:00
# Target protocol address = 10.10.128.43
#
PACKET_DUMP_1 = "0001080006040001b06ebfc7e6ba0a0a80a10000000000000a0a802b"

#
# Hardware type = Ethernet (1)
# Protocol type = IPv4 (0x08)
# Hardware length = 6
# Protocol length = 4
# Operation code: reply (2)
# Sender HW address = 00:7e:95:02:61:42
# Sender protocol address = 10.10.128.2
# Target HW address = e0:d5:5e:21:b0:cb
# Target protocol address = 10.10.128.44
#
PACKET_DUMP_2 = "0001080006040002007e950261420a0a8002e0d55e21b0cb0a0a802c"


class TestArpPacket(TestCase):

    def test_to_bytes(self):
        arp_packet = ArpPacket(
            hardware_type=ArpHardwareType.ETHERNET,
            protocol_type=EtherType.IPV4,
            operation=ArpOperation.OP_REQUEST,
            sender_hw_address="b0 6e bf c7 e6 ba",
            sender_proto_address="10.10.128.161",
            target_hw_address="00 00 00 00 00 00",
            target_proto_address="10.10.128.43"
        )
        arp_bytes = arp_packet.to_bytes()
        self.assertEqual(PACKET_DUMP_1, arp_bytes.hex())
        self.assertEqual(arp_packet, ArpPacket.from_bytes(arp_bytes))

        arp_packet = ArpPacket(
            hardware_type=ArpHardwareType.ETHERNET,
            protocol_type=EtherType.IPV4,
            operation=ArpOperation.OP_REPLY,
            sender_hw_address="00 7e 95 02 61 42",
            sender_proto_address="10.10.128.2",
            target_hw_address="e0 d5 5e 21 b0 cb",
            target_proto_address="10.10.128.44"
        )
        arp_bytes = arp_packet.to_bytes()
        self.assertEqual(PACKET_DUMP_2, arp_bytes.hex())
        self.assertEqual(arp_packet, ArpPacket.from_bytes(arp_bytes))

    def test_is_response(self):
        arp_request = ArpPacket(
            hardware_type=ArpHardwareType.ETHERNET,
            protocol_type=EtherType.IPV4,
            operation=ArpOperation.OP_REQUEST,
            sender_hw_address="b0 6e bf c7 e6 ba",
            sender_proto_address="10.10.128.39",
            target_hw_address="ff ff ff ff ff ff",
            target_proto_address="10.10.128.44"
        )
        arp_response = ArpPacket(
            hardware_type=ArpHardwareType.ETHERNET,
            protocol_type=EtherType.IPV4,
            operation=ArpOperation.OP_REPLY,
            sender_hw_address="00 7e 95 02 61 42",
            sender_proto_address="10.10.128.44",
            target_hw_address="e0 d5 5e 21 b0 cb",
            target_proto_address="10.10.128.39"
        )
        self.assertTrue(arp_response.is_response(arp_request))
