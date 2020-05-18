import logging
import socket
import struct
import port_scanner.layers.transport.tcp.tcp_packet as tcp_packet
import port_scanner.layers.transport.udp.udp_packet as udp_packet

from port_scanner.layers.inet.ip.ip_diff_service_values import IpDiffServiceValues
from port_scanner.layers.inet.ip.ip_ecn_values import IpEcnValues
from port_scanner.layers.inet.ip.ip_fragmentation_flags import IpFragmentationFlags
from port_scanner.layers.inet.ip.ip_utils import IpUtils
from port_scanner.layers.packet import Packet
from port_scanner.utils.utils import Utils


class IpPacket(Packet):
    """
    Represents IPv4 packet

    Note: implementation doesn't support 'Options' field
    """

    IP_V4_HEADER_FORMAT = "!BBHHHBBH4s4s"
    """
    Defines format of IPv4 header fields:
        * Version + IHL : 1 byte
        * DSCP + ECN : 1 byte
        * Total Length : 2 bytes
        * Identification : 2 bytes
        * Flags + Fragment Offset : 2 bytes
        * TTL : 1 byte
        * Protocol : 1 byte
        * Header checksum : 2 bytes
        * Source IP : 4 bytes
        * Destination IP : 4 bytes
    """

    IP_V4_DEFAULT_TTL = 64

    TRANSPORT_LAYER_CONVERTERS = {
        socket.IPPROTO_TCP: tcp_packet.TcpPacket.from_bytes,
        socket.IPPROTO_UDP: udp_packet.UdpPacket.from_bytes,
    }
    """
    Defines converters to the Transport layer packets based on the value
    of Protocol field in IP packet
    """

    LOG = logging.getLogger("IpPacket")

    def __init__(
            self,
            source_addr_str: str,
            dest_addr_str: str,
            dscp: IpDiffServiceValues = IpDiffServiceValues.DEFAULT,
            ecn: IpEcnValues = IpEcnValues.NON_ECT,
            identification: int = None,
            flags: IpFragmentationFlags = IpFragmentationFlags(df=True),
            fragment_offset: int = 0,
            ttl: int = IP_V4_DEFAULT_TTL,
            protocol: int = socket.IPPROTO_TCP
    ):
        """
        Initializes IPv4 packet instance

        :param source_addr_str: string representation of source IP address
        :param dest_addr_str: string representation of destination IP address
        :param dscp: DSCP field, instance of IpDiffServiceValues enum
        :param ecn: ECN field, instance of IpEcnValues enum
        :param identification: unique identifier of the fragment in a single IP datagram.
            Should be a 16 bits integer. If None, then randomly generated value will be used
        :param flags: fragmentation flags, instance of IpFragmentationFlags, DF by default
        :param fragment_offset: Fragment Offset field, 13 bits integer, 0 by default
        :param ttl: TTL field, defines packet lifetime, 64 by default
        :param protocol: Protocol field, defines the protocol used in the data
            portion of the IP datagram. Full list of protocols available
            at https://tools.ietf.org/html/rfc790
        """
        super().__init__()
        self.__source_addr = socket.inet_aton(source_addr_str)
        self.__dest_addr = socket.inet_aton(dest_addr_str)
        self.__dscp = dscp
        self.__ecn = ecn
        self.__identification = IpUtils.validate_or_gen_packet_id(identification)
        self.__flags = flags
        self.__fragment_offset = IpUtils.validate_fragment_offset(fragment_offset)
        self.__ttl = ttl
        self.__protocol = protocol

    def to_bytes(self) -> bytes:
        # fragmentation flags takes first 3 bits, next 13 bits is fragment offset
        flags_fragment_offset = self.__flags.flags << 13 | self.__fragment_offset

        # DSCP value takes first 6 bits, the next 2 ones is ECN
        dscp_ecn = self.__dscp << 2 | self.__ecn

        header_fields = [
            IpUtils.IP_V4_VER_IHL,
            dscp_ecn,
            self.total_length,
            self.__identification,
            flags_fragment_offset,
            self.__ttl,
            self.__protocol,
            0,  # placeholder for checksum
            self.__source_addr,
            self.__dest_addr
        ]

        # allocate 20 bytes buffer to put header in
        header_bytes = bytearray(IpUtils.IP_V4_MAX_HEADER_LENGTH_BYTES)
        # pack header without checksum to the buffer
        struct.pack_into(self.IP_V4_HEADER_FORMAT, header_bytes, 0, *header_fields)

        # calculate checksum
        checksum_bytes = Utils.calc_checksum(header_bytes)
        # checksum takes 10-th and 11-th bytes of the header (counting from 0)
        # see https://tools.ietf.org/html/rfc791#section-3.1 for more details
        header_bytes[10] = checksum_bytes[0]
        header_bytes[11] = checksum_bytes[1]

        return bytes(header_bytes) + self.raw_payload

    @staticmethod
    def from_bytes(packet_bytes: bytes):
        header_bytes = packet_bytes[:IpUtils.IP_V4_MAX_HEADER_LENGTH_BYTES]
        payload_bytes = packet_bytes[IpUtils.IP_V4_MAX_HEADER_LENGTH_BYTES:]
        header_fields = struct.unpack(IpPacket.IP_V4_HEADER_FORMAT, header_bytes)

        # we don't extract ver_ihl, total_length, checksum fields (0, 2, 7 indices)
        # since they will be calculated after IpPacket instantiating
        dscp_ecn = header_fields[1]
        identification = header_fields[3]
        flags_fragment_offset = header_fields[4]
        ttl = header_fields[5]
        protocol = header_fields[6]
        source_addr = socket.inet_ntoa(header_fields[8])
        dest_addr = socket.inet_ntoa(header_fields[9])

        dscp = IpDiffServiceValues(dscp_ecn >> 2)  # take first 6 bits dropping last 2 bits
        ecn = IpEcnValues(dscp_ecn & 3)  # take last 2 bits

        # take first 3 bits dropping last 13 bits
        flags = IpFragmentationFlags.from_int(flags_fragment_offset >> 13)
        # take last 13 bits
        fragment_offset = flags_fragment_offset & 0x1fff

        ip_packet = IpPacket(
            source_addr_str=source_addr,
            dest_addr_str=dest_addr,
            dscp=dscp,
            ecn=ecn,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol
        )

        if len(payload_bytes) == 0:
            return ip_packet
        # try to find appropriate converter based on protocol field
        transport_layer_converter = IpPacket.TRANSPORT_LAYER_CONVERTERS.get(protocol)
        if transport_layer_converter is None:
            IpPacket.LOG.warning(
                f"Can't find converter to transport layer packet. "
                f"Protocol: {protocol}. "
                f"Payload: {payload_bytes.hex()}"
            )
            return ip_packet / payload_bytes
        transport_layer = transport_layer_converter(payload_bytes)
        return ip_packet / transport_layer

    @property
    def source_addr(self) -> str:
        return socket.inet_ntoa(self.__source_addr)

    @property
    def dest_addr(self) -> str:
        return socket.inet_ntoa(self.__dest_addr)

    @property
    def source_addr_raw(self) -> bytes:
        return self.__source_addr

    @property
    def dest_addr_raw(self) -> bytes:
        return self.__dest_addr

    @property
    def dscp(self) -> IpDiffServiceValues:
        return self.__dscp

    @property
    def ecn(self) -> IpEcnValues:
        return self.__ecn

    @property
    def total_length(self) -> int:
        return IpUtils.validate_packet_length(
            IpUtils.IP_V4_MAX_HEADER_LENGTH_BYTES + len(self.raw_payload))

    @property
    def id(self) -> int:
        return self.__identification

    @property
    def flags(self) -> IpFragmentationFlags:
        return self.__flags

    @property
    def frag_offset(self) -> int:
        return self.__fragment_offset

    @property
    def ttl(self) -> int:
        return self.__ttl

    @property
    def protocol(self) -> int:
        return self.__protocol

    def __eq__(self, other: object) -> bool:
        if isinstance(other, IpPacket):
            return self.source_addr == other.source_addr and \
                   self.dest_addr == other.dest_addr and \
                   self.upper_layer == other.upper_layer and \
                   self.dscp == other.dscp and \
                   self.ecn == other.ecn and \
                   self.total_length == other.total_length and \
                   self.id == other.id and \
                   self.flags == other.flags and \
                   self.frag_offset == other.frag_offset and \
                   self.ttl == other.ttl and \
                   self.protocol == other.protocol
        return False

    def __str__(self) -> str:
        return f"IP(dest_addr={self.dest_addr}, src_addr={self.source_addr}, " \
               f"dscp={self.dscp}, ecn={self.ecn}, " \
               f"length={self.total_length}, id={self.id}, flags=({self.flags}), " \
               f"frag_offset={self.frag_offset}, ttl={self.ttl}, protocol={self.protocol})"
