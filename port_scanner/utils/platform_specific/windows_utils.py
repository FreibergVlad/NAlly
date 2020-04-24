from socket import socket

from port_scanner.utils.platform_specific.abstract_platform_specific_utils import AbstractPlatformSpecificUtils


class WindowsUtils(AbstractPlatformSpecificUtils):

    @staticmethod
    def toggle_promiscuous_mode(if_name: str, socket_obj: socket, enable: bool):
        raise NotImplementedError
