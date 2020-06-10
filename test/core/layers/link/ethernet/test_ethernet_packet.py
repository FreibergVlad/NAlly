import socket
from unittest import TestCase

from nally.core.layers.inet.ip.ip_diff_service_values \
    import IpDiffServiceValues
from nally.core.layers.inet.ip.ip_fragmentation_flags \
    import IpFragmentationFlags
from nally.core.layers.inet.ip.ip_packet import IpPacket
from nally.core.layers.link.arp.arp_packet import ArpPacket
from nally.core.layers.link.arp.arp_utils import ArpHardwareType, ArpOperation
from nally.core.layers.link.ethernet.ethernet_packet import EthernetPacket
from nally.core.layers.link.proto_type import EtherType
from nally.core.layers.transport.tcp.tcp_control_bits import TcpControlBits
from nally.core.layers.transport.tcp.tcp_options import TcpOptions
from nally.core.layers.transport.tcp.tcp_packet import TcpPacket
from nally.core.layers.transport.udp.udp_packet import UdpPacket

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
    "TCP_PAYLOAD": "01bbdaaa9851d8d84acd45df8010000a07"
                   "c200000101080a2705f346e9c42522"
}

UDP_IP_PAYLOAD_TEST_CONTEXT = {
    #
    # Destination MAC = "0c:84:dc:a6:bf:c1"
    # Source MAC = "34:da:b7:87:d5:34"
    # Type = IPv4
    #
    "ETHERNET_HEADER": "0c84dca6bfc134dab787d5340800",
    #
    #  DSCP = 0x40 (CS2, Not-ECN)
    #  total length = 217 bytes
    #  identification = 53262
    #  flags = 0
    #  ttl = 252
    #  protocol = UDP (17)
    #  checksum = 0x4e02
    #  source IP = 86.57.135.193
    #  destination IP = 192.168.1.32
    #
    "IP_PAYLOAD": "454000d9d00e0000fc114e02563987c1c0a80120",
    #
    # Source port = 443
    # Destination port = 39237
    # Length: 197
    # Checksum: 0x0000e1b1
    #
    "UDP_PAYLOAD": "01bb994500c5e1b1",
    "APP_LAYER_PAYLOAD": "170100000100000000002000b0538ec1"
                         "a3bce5c2121d0fd7c95afe68bbe62530"
                         "4588271c633c5cba1e0c2fe95addb53b"
                         "cca024908174139935f56e9f6d2b34a6"
                         "026b5d1109da0ec7017a6de7409a4152"
                         "543dd0df67d1e490edf207980bef0310"
                         "a5a16e05a831141b0892a9a05d51e274"
                         "86bae8e3603d9ee35feff001a90cb5ef"
                         "061b1b25890c2346ffae43a00e311205"
                         "40086a6361209eb283549c0e7c645537"
                         "2a3e7cd40428ac213a39daf9ca9c89ac"
                         "522b75c58fef3fcd6efd9f52cd"

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
        self.assertEqual(
            ethernet_arp,
            EthernetPacket.from_bytes(bytes.fromhex(packet_hex))
        )
        self.assertTrue(EthernetPacket in ethernet_arp)
        self.assertTrue(ArpPacket in ethernet_arp)
        self.assertEqual(arp_payload, ethernet_arp[ArpPacket])

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
        self.assertEqual(
            ethernet_ip,
            EthernetPacket.from_bytes(bytes.fromhex(packet_hex))
        )
        self.assertTrue(EthernetPacket in ethernet_ip)
        self.assertTrue(IpPacket in ethernet_ip)
        self.assertEqual(ip_packet, ethernet_ip[IpPacket])

    def test_tcp_ip_payload(self):
        ethernet_header_hex = TCP_IP_PAYLOAD_TEST_CONTEXT["ETHERNET_HEADER"]
        ip_payload_hex = TCP_IP_PAYLOAD_TEST_CONTEXT["IP_PAYLOAD"]
        tcp_payload_hex = TCP_IP_PAYLOAD_TEST_CONTEXT["TCP_PAYLOAD"]
        packet_hex = ethernet_header_hex + ip_payload_hex + tcp_payload_hex

        ethernet_packet = EthernetPacket(
            dest_mac="e0:d5:5e:21:b0:cb",
            source_mac="00:7e:95:02:61:42"
        )
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
        self.assertEqual(
            packet,
            EthernetPacket.from_bytes(bytes.fromhex(packet_hex))
        )
        self.assertTrue(EthernetPacket in packet)
        self.assertTrue(IpPacket in packet)
        self.assertTrue(TcpPacket in packet)

    def test_udp_ip_payload(self):
        ethernet_header_hex = UDP_IP_PAYLOAD_TEST_CONTEXT["ETHERNET_HEADER"]
        ip_payload_hex = UDP_IP_PAYLOAD_TEST_CONTEXT["IP_PAYLOAD"]
        udp_payload_hex = UDP_IP_PAYLOAD_TEST_CONTEXT["UDP_PAYLOAD"]
        app_payer_payload = UDP_IP_PAYLOAD_TEST_CONTEXT["APP_LAYER_PAYLOAD"]
        packet_hex = (ethernet_header_hex + ip_payload_hex
                      + udp_payload_hex + app_payer_payload)

        ethernet_packet = EthernetPacket(
            dest_mac="0c:84:dc:a6:bf:c1",
            source_mac="34:da:b7:87:d5:34"
        )
        self.assertEqual(ethernet_header_hex, ethernet_packet.to_bytes().hex())

        ip_packet = IpPacket(
            source_addr_str="86.57.135.193",
            dest_addr_str="192.168.1.32",
            dscp=IpDiffServiceValues.CS2,
            identification=53262,
            flags=IpFragmentationFlags(),
            ttl=252,
            protocol=socket.IPPROTO_UDP
        )

        udp_packet = UdpPacket(
            dest_port=39237,
            source_port=443
        ) / bytes.fromhex(app_payer_payload)

        packet = ethernet_packet / ip_packet / udp_packet
        self.assertEqual(packet_hex, packet.to_bytes().hex())
        self.assertEqual(
            packet,
            EthernetPacket.from_bytes(bytes.fromhex(packet_hex))
        )
        self.assertTrue(EthernetPacket in packet)
        self.assertTrue(IpPacket in packet)
        self.assertTrue(UdpPacket in packet)
        self.assertFalse(TcpPacket in packet)

    def test_no_payload(self):
        ethernet_header_hex = NO_PAYLOAD_TEST_CONTEXT["ETHERNET_HEADER"]

        packet = EthernetPacket(
            dest_mac="01:00:5e:67:00:0a",
            source_mac="52:54:00:46:cd:26"
        )
        self.assertEqual(ethernet_header_hex, packet.to_bytes().hex())
        self.assertEqual(
            packet,
            EthernetPacket.from_bytes(bytes.fromhex(ethernet_header_hex))
        )

    def test_is_response(self):
        packet1 = EthernetPacket(
            dest_mac="01:00:5e:67:00:0a",
            source_mac="52:54:00:46:cd:26"
        )
        response1 = EthernetPacket(
            dest_mac="52:54:00:46:cd:26",
            source_mac="01:00:5e:67:00:0a"
        )
        self.assertTrue(response1.is_response(packet1))

        # EtherType mismatch
        packet2 = EthernetPacket(
            dest_mac="01:00:5e:67:00:0a",
            source_mac="52:54:00:46:cd:26",
            ether_type=EtherType.IPV4
        )
        response2 = EthernetPacket(
            dest_mac="52:54:00:46:cd:26",
            source_mac="01:00:5e:67:00:0a",
            ether_type=EtherType.IPV6
        )
        self.assertFalse(response2.is_response(packet2))
