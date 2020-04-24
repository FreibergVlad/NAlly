import ctypes
from socket import socket

from port_scanner.utils.platform_specific.abstract_platform_specific_utils import AbstractPlatformSpecificUtils


class LinuxUtils(AbstractPlatformSpecificUtils):

    # linux/if.h
    IFF_PROMISC = 0x100
    """
    Enables promiscuous mode for network card
    """

    # linux/sockios.h
    SIOCGIFFLAGS = 0x8913
    """
    Gets the active flag word of the device
    """
    SIOCSIFFLAGS = 0x8914
    """
    Sets or set the active flag word of the device
    """

    # noinspection PyTypeChecker
    @staticmethod
    def toggle_promiscuous_mode(if_name: str, socket_obj: socket, enable: bool):
        import fcntl
        request = LinuxUtils.FcntlRequest()
        request.if_name = if_name.encode()
        fcntl.ioctl(socket_obj, LinuxUtils.SIOCGIFFLAGS, request)
        if enable:
            request.if_flags |= LinuxUtils.IFF_PROMISC  # add the promiscuous flag
        else:
            request.if_flags ^= LinuxUtils.IFF_PROMISC  # remove the promiscuous flag
        fcntl.ioctl(socket_obj, LinuxUtils.SIOCSIFFLAGS, request)  # update

    class FcntlRequest(ctypes.Structure):
        _fields_ = [
            ("if_name", ctypes.c_char * 16),
            ("if_flags", ctypes.c_short)
        ]
