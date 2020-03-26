from enum import IntEnum


class EtherType(IntEnum):
    """
    Stores possible values for 'EtherType' field in Ethernet frame.
    It is used to indicate which protocol is encapsulated in the payload of the frame
    """

    # ====== New supported protocols should be added below ======
    IPV4 = 0x0800
    ARP = 0x0806
