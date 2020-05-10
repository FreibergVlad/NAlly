import socket
from unittest import TestCase

from port_scanner.layers.inet.ip.ip_fragmentation_flags import IpFragmentationFlags
from port_scanner.layers.inet.ip.ip_packet import IpPacket
from port_scanner.layers.link.arp.arp_packet import ArpPacket
from port_scanner.layers.link.arp.arp_utils import ArpHardwareType, ArpOperation
from port_scanner.layers.link.ethernet.ethernet_packet import EthernetPacket
from port_scanner.layers.link.proto_type import EtherType
from port_scanner.layers.transport.tcp.tcp_control_bits import TcpControlBits
from port_scanner.layers.transport.tcp.tcp_options import TcpOptions
from port_scanner.layers.transport.tcp.tcp_packet import TcpPacket

ARP_PAYLOAD_TEST_CONTEXT = {
    #
    # Hardware type = Ethernet (1)
    # Protocol type = IPv4 (0x08)
    # Hardware length = 6
    # Protocol length = 4
    # Operation code: request (1)
    # Sender HW address = 52:54:00:eb:a2:58
    # Sender protocol address = 10.10.144.73
    # Target HW address = 00:00:00:00:00:00
    # Target protocol address = 10.10.152.144
    #
    "ARP_PAYLOAD": "0001080006040001525400eba2580a0a90490000000000000a0a9890",
    #
    # Destination MAC = "ff:ff:ff:ff:ff:ff"
    # Source MAC = "52:54:00:eb:a2:58"
    # Type = ARP
    #
    "ETHERNET_HEADER": "ffffffffffff525400eba2580806",
}

NO_PAYLOAD_TEST_CONTEXT = {
    #
    # Destination MAC = "01:00:5e:67:00:0a"
    # Source MAC = "52:54:00:46:cd:26"
    # Type = IPv4
    #
    "ETHERNET_HEADER": "01005e67000a52540046cd260800"
}

IP_PAYLOAD_TEST_CONTEXT = {
    #
    #  DSCP = 0x00
    #  total length = 20 bytes
    #  identification = 49101
    #  flags = 0
    #  ttl = 255
    #  protocol = 0
    #  checksum = 0x6d0c
    #  source IP = 127.0.0.1
    #  destination IP = 8.8.8.7
    #
    "IP_PAYLOAD": "45000014bfcd0000ff006d0c7f00000108080807",
    #
    # Destination MAC = "00:7e:95:02:61:42"
    # Source MAC = "e0:d5:5e:21:b0:cb"
    # Type = IPv4
    #
    "ETHERNET_HEADER": "007e95026142e0d55e21b0cb0800",
}

TCP_IP_PAYLOAD_TEST_CONTEXT = {
    #
    # Destination MAC = "e0:d5:5e:21:b0:cb"
    # Source MAC = "00:7e:95:02:61:42"
    # Type = IPv4
    #
    "ETHERNET_HEADER": "e0d55e21b0cb007e950261420800",
    #
    #  DSCP = 0x00
    #  total length = 52 bytes
    #  identification = 11150
    #  flags = 0x4000 (DF)
    #  ttl = 47
    #  protocol = TCP (6)
    #  checksum = 0xb8b4
    #  source IP = 3.123.217.208
    #  destination IP = 10.10.128.44
    #
    "IP_PAYLOAD": "450000342b8e40002f06b8b4037bd9d00a0a802c",
    #
    # Source port = 443
    # Destination port = 55978
    # Sequence number = 2555500760
    # Acknowledgment number = 1254966751
    # Flags = 0x010 (ACK)
    # Window size = 10
    # Checksum = 0x07c2
    # Urgent pointer = 0
    # Options:
    #   NOP
    #   NOP
    #   Timestamps = 654701382 and 3921945890
    #
    "TCP_PAYLOAD": "01bbdaaa9851d8d84acd45df8010000a07c200000101080a2705f346e9c42522"
}


class TestEthernetPacket(TestCase):

    def test_arp_payload(self):
        ethernet_header_hex = ARP_PAYLOAD_TEST_CONTEXT["ETHERNET_HEADER"]
        arp_payload_hex = ARP_PAYLOAD_TEST_CONTEXT["ARP_PAYLOAD"]
        packet_hex = ethernet_header_hex + arp_payload_hex

        packet = EthernetPacket(
            dest_mac="ff:ff:ff:ff:ff:ff",
            source_mac="52:54:00:eb:a2:58",
            ether_type=EtherType.ARP
        )
        packet_bytes = packet.to_bytes()
        self.assertEqual(ethernet_header_hex, packet_bytes.hex())

        arp_payload = ArpPacket(
            hardware_type=ArpHardwareType.ETHERNET,
            protocol_type=EtherType.IPV4,
            operation=ArpOperation.OP_REQUEST,
            sender_hw_address="52:54:00:eb:a2:58",
            sender_proto_address="10.10.144.73",
            target_hw_address="00:00:00:00:00:00",
            target_proto_address="10.10.152.144"
        )
        self.assertEqual(arp_payload_hex, arp_payload.to_bytes().hex())

        ethernet_arp = packet / arp_payload
        self.assertEqual(packet_hex, ethernet_arp.to_bytes().hex())
        self.assertEqual(ethernet_arp, EthernetPacket.from_bytes(bytes.fromhex(packet_hex)))

    def test_ip_payload(self):
        ethernet_header_hex = IP_PAYLOAD_TEST_CONTEXT["ETHERNET_HEADER"]
        ip_payload_hex = IP_PAYLOAD_TEST_CONTEXT["IP_PAYLOAD"]
        packet_hex = ethernet_header_hex + ip_payload_hex

        packet = EthernetPacket(
            dest_mac="00:7e:95:02:61:42",
            source_mac="e0:d5:5e:21:b0:cb"
        )
        packet_bytes = packet.to_bytes()
        self.assertEqual(ethernet_header_hex, packet_bytes.hex())

        ip_packet = IpPacket(
            source_addr_str="127.0.0.1",
            dest_addr_str="8.8.8.7",
            identification=49101,
            flags=IpFragmentationFlags.from_int(0),
            ttl=255,
            protocol=0
        )
        self.assertEqual(ip_payload_hex, ip_packet.to_bytes().hex())

        ethernet_ip = packet / ip_packet
        self.assertEqual(packet_hex, ethernet_ip.to_bytes().hex())
        self.assertEqual(ethernet_ip, EthernetPacket.from_bytes(bytes.fromhex(packet_hex)))

    def test_tcp_ip_payload(self):
        ethernet_header_hex = TCP_IP_PAYLOAD_TEST_CONTEXT["ETHERNET_HEADER"]
        ip_payload_hex = TCP_IP_PAYLOAD_TEST_CONTEXT["IP_PAYLOAD"]
        tcp_payload_hex = TCP_IP_PAYLOAD_TEST_CONTEXT["TCP_PAYLOAD"]
        packet_hex = ethernet_header_hex + ip_payload_hex + tcp_payload_hex

        ethernet_packet = EthernetPacket(dest_mac="e0:d5:5e:21:b0:cb", source_mac="00:7e:95:02:61:42")
        self.assertEqual(ethernet_header_hex, ethernet_packet.to_bytes().hex())

        ip_packet = IpPacket(
            source_addr_str="3.123.217.208",
            dest_addr_str="10.10.128.44",
            identification=11150,
            flags=IpFragmentationFlags(df=True),
            ttl=47,
            protocol=socket.IPPROTO_TCP
        )
        tcp_packet = TcpPacket(
            source_port=443,
            dest_port=55978,
            sequence_number=2555500760,
            ack_number=1254966751,
            flags=TcpControlBits(ack=True),
            win_size=10,
            options=TcpOptions([
                TcpOptions.NOP,
                TcpOptions.NOP,
                (TcpOptions.TIMESTAMPS, [654701382, 3921945890])
            ]),
        )

        packet = ethernet_packet / ip_packet / tcp_packet
        self.assertEqual(packet_hex, packet.to_bytes().hex())
        self.assertEqual(packet, EthernetPacket.from_bytes(bytes.fromhex(packet_hex)))

    def test_no_payload(self):
        ethernet_header_hex = NO_PAYLOAD_TEST_CONTEXT["ETHERNET_HEADER"]

        packet = EthernetPacket(
            dest_mac="01:00:5e:67:00:0a",
            source_mac="52:54:00:46:cd:26"
        )
        self.assertEqual(ethernet_header_hex, packet.to_bytes().hex())
        self.assertEqual(packet, EthernetPacket.from_bytes(bytes.fromhex(ethernet_header_hex)))
