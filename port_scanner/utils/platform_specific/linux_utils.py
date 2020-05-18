import ctypes
import struct
from socket import socket, AF_INET, SOCK_DGRAM, inet_ntoa

from port_scanner.utils.platform_specific.abstract_platform_specific_utils import AbstractPlatformSpecificUtils


class LinuxUtils(AbstractPlatformSpecificUtils):
    """
    Linux implementation of OS specific utils
    """

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
    Sets the active flag word of the device
    """
    SIOCGIFADDR = 0x8915
    """
    Gets the IP address of the device
    """

    # linux/route.h
    RTF_GATEWAY = 0x0002
    """
    If set, then route points to an intermediate destination
    and not the ultimate recipient
    """

    IF_NAME_SIZE_BYTES = 16
    """
    Network interface name size in bytes in 'ifreq' structure
    """

    IF_REQ_FORMAT = '!256s'
    """
    Defines format of 'ifreq' structure
    """

    @staticmethod
    def get_default_interface() -> str:
        """
        Returns default network interface name parsing '/proc/net/route' file
        """
        with open('/proc/net/route') as routes_file:
            for line in routes_file:
                fields = line.strip().split()
                destination = fields[1]
                flags = fields[3]
                # check default gateway and RTF_GATEWAY flag
                if destination == '00000000' and int(flags, 16) & LinuxUtils.RTF_GATEWAY:
                    return fields[0]
        raise RuntimeError("Can't find default network interface in /proc/net/route")

    # noinspection PyTypeChecker
    @staticmethod
    def get_net_interface_ip(if_name: str) -> str:
        """
        Returns string representation of IP address for this network interface
        Uses Fcntl system call, hence available only for Linux
        """
        with socket(AF_INET, SOCK_DGRAM) as socket_obj:
            import fcntl
            if_name: bytes = if_name.encode()
            # according to 'if.h', interface name takes first 16 bytes
            if_req = struct.pack(LinuxUtils.IF_REQ_FORMAT, if_name[:LinuxUtils.IF_NAME_SIZE_BYTES - 1])
            if_resp = fcntl.ioctl(socket_obj, LinuxUtils.SIOCGIFADDR, if_req)
            # take 4 IP bytes
            raw_ip = if_resp[20:24]
            return inet_ntoa(raw_ip)

    # noinspection PyTypeChecker
    @staticmethod
    def toggle_promiscuous_mode(if_name: str, enable: bool):
        """
        Toggles promiscuous mode on network card using Fcntl system calls. Available
        only for Linux

        :param if_name: network interface name
        :param enable: if True, promiscuous mode will be enabled, disabled otherwise
        """
        with socket(AF_INET, SOCK_DGRAM) as socket_obj:

            class IfFlagsRequest(ctypes.Structure):
                # according to 'if.h'
                _fields_ = [
                    ("if_name", ctypes.c_char * 16),
                    ("if_flags", ctypes.c_short)
                ]

            import fcntl
            request = IfFlagsRequest()
            request.if_name = if_name.encode()
            fcntl.ioctl(socket_obj, LinuxUtils.SIOCGIFFLAGS, request)
            if enable:
                request.if_flags |= LinuxUtils.IFF_PROMISC  # add the promiscuous flag
            else:
                request.if_flags ^= LinuxUtils.IFF_PROMISC  # remove the promiscuous flag
            fcntl.ioctl(socket_obj, LinuxUtils.SIOCSIFFLAGS, request)  # update
