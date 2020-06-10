from nally.core.layers.inet.ip.ip_packet import IpPacket
from nally.core.layers.link.ethernet.ethernet_packet import EthernetPacket
from nally.core.layers.transport.tcp.tcp_control_bits import TcpControlBits
from nally.core.layers.transport.tcp.tcp_packet import TcpPacket
from nally.core.sender.packet_sender import PacketSender


tcp_syn = EthernetPacket(dest_mac="00:7e:95:02:61:42") / \
          IpPacket(dest_addr_str="8.8.8.8") / \
          TcpPacket(source_port=12346, dest_port=443, flags=TcpControlBits(syn=True))

print(PacketSender.send_and_get_response(tcp_syn, timeout=5)[IpPacket])
