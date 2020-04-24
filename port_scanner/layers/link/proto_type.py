from enum import IntEnum


class EtherType(IntEnum):
    """
    Stores possible values for 'EtherType' field in Ethernet frame and for 'PTYPE' field in ARP frame.
    For Ethernet, it is used to indicate which protocol is encapsulated in the payload of the frame
    For ARP - to specify the protocol for which the ARP request is intended
    """

    # ====== New supported protocols should be added below ======
    IPV4 = 0x0800
    IPV6 = 0x86dd
    ARP = 0x0806
