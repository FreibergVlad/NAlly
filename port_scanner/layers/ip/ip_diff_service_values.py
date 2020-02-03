from enum import IntEnum


class IpDiffServiceValues(IntEnum):
    """
    Differentiated services is an extension of IP protocol that specifies a simple and scalable mechanism for
    classifying and managing network traffic and providing quality of service (QoS) on modern IP networks.
    It can, for example, be used to provide low-latency to critical network traffic such as voice or streaming media
    while providing simple best-effort service to non-critical services such as web traffic or file transfers.

    DiffService uses a 6-bit differentiated services code point (DSCP) in the 8-bit differentiated services
    field (DS field) in the IP header for packet classification purposes. The DS field replaces the outdated
    IPv4 TOS field.
    """

    DEFAULT = 0

    EF = 46

    AF11 = 10
    AF12 = 12
    AF13 = 14

    AF21 = 18
    AF22 = 20
    AF23 = 22

    AF31 = 26
    AF32 = 28
    AF33 = 30

    AF41 = 34
    AF42 = 36
    AF43 = 38

    CS1 = 8
    CS2 = 16
    CS3 = 24
    CS4 = 32
    CS5 = 40
    CS6 = 48
    CS7 = 56
