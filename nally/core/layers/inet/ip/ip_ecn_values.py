from enum import IntEnum


class IpEcnValues(IntEnum):
    """
    Explicit Congestion Notification (ECN) is an extension to the IP protocol and defined in RFC 3168.
    ECN allows end-to-end notification of network congestion without dropping packets. ECN uses the two
    least significant (right-most) bits of the DiffService field in the IPv4 header.

    When both endpoints support ECN they mark their packets with ECT_0 or ECT_1. Routers treat the ECT_0
    and ECT_1 code points as equivalent. If the packet traverses a network that is experiencing congestion
    and the corresponding router supports ECN, it may change the code point to CE instead of dropping the packet.
    This act is referred to as “marking” and its purpose is to inform the receiving endpoint of impending congestion.
    At the receiving endpoint, this congestion indication is handled by the upper layer protocol
    (transport layer protocol) and needs to be echoed back to the transmitting node in order to signal it to
    reduce its transmission rate.

    Because the CE indication can only be handled effectively by an upper layer protocol that supports it,
    ECN is only used in conjunction with upper layer protocols, such as TCP, that support congestion control
    and have a method for echoing the CE indication to the transmitting endpoint.

    See https://tools.ietf.org/html/rfc3168 for more details
    """

    NON_ECT = 0
    """Non ECN-Capable Transport"""
    ECT_0 = 2
    """ECN Capable Transport"""
    ECT_1 = 1
    """ECN Capable Transport"""
    CE = 3
    """Congestion Encountered"""
