import struct
import socket

from port_scanner.layers.ip.ip_diff_service_values import IpDiffServiceValues
from port_scanner.layers.ip.ip_ecn_values import IpEcnValues
from port_scanner.layers.ip.ip_fragmentation_flags import IpFragmentationFlags
from port_scanner.layers.ip.ip_utils import IpUtils


class IpPacket:

    IP_V4_HEADER_FORMAT = "!BBHHHBBH4s4s"

    IP_V4_DEFAULT_TTL = 64

    def __init__(
            self,
            source_addr_str: str,
            dest_addr_str: str,
            payload: bytes,
            dscp: IpDiffServiceValues = IpDiffServiceValues.DEFAULT,
            ecn: IpEcnValues = IpEcnValues.NON_ECT,
            identification: int = None,
            flags: IpFragmentationFlags = IpFragmentationFlags(df=True),
            fragment_offset: int = 0,
            ttl: int = IP_V4_DEFAULT_TTL,
            protocol: int = socket.IPPROTO_TCP
    ):
        self.__source_addr = socket.inet_aton(source_addr_str)
        self.__dest_addr = socket.inet_aton(dest_addr_str)
        self.__payload = payload
        self.__dscp = dscp
        self.__ecn = ecn
        self.__total_length = IpUtils.validate_packet_length(
            IpUtils.IP_V4_MAX_HEADER_LENGTH_BYTES + len(self.__payload))
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
            self.__total_length,
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
        checksum = IpUtils.calc_ip_checksum(header_bytes)
        # split 16-bits checksum into two 8-bits values
        checksum_bytes = checksum.to_bytes(2, byteorder="big")
        # checksum takes 10-th and 11-th bytes of the header (counting from 0)
        # see https://tools.ietf.org/html/rfc791#section-3.1 for more details
        header_bytes[10] = checksum_bytes[0]
        header_bytes[11] = checksum_bytes[1]

        return bytes(header_bytes) + self.payload

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

        flags = IpFragmentationFlags.from_int(flags_fragment_offset >> 13)  # take first 3 bits dropping last 13 bits
        fragment_offset = flags_fragment_offset & 0x1fff  # take last 13 bits

        return IpPacket(
            source_addr_str=source_addr,
            dest_addr_str=dest_addr,
            payload=payload_bytes,
            dscp=dscp,
            ecn=ecn,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol
        )

    @property
    def source_adr(self) -> str:
        return socket.inet_ntoa(self.__source_addr)

    @property
    def dest_addr(self) -> str:
        return socket.inet_ntoa(self.__dest_addr)

    @property
    def payload(self) -> bytes:
        return self.__payload

    @property
    def dscp(self) -> IpDiffServiceValues:
        return self.__dscp

    @property
    def ecn(self) -> IpEcnValues:
        return self.__ecn

    @property
    def total_length(self) -> int:
        return self.__total_length

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
            return self.source_adr == other.source_adr and \
                   self.dest_addr == other.dest_addr and \
                   self.payload == other.payload and \
                   self.dscp == other.dscp and \
                   self.ecn == other.ecn and \
                   self.total_length == other.total_length and \
                   self.id == other.id and \
                   self.flags == other.flags and \
                   self.frag_offset == other.frag_offset and \
                   self.ttl == other.ttl and \
                   self.protocol == other.protocol
        return False
