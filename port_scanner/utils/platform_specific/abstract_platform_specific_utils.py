from abc import abstractmethod, ABC
from socket import socket


class AbstractPlatformSpecificUtils(ABC):
    """
    Defines abstract interface for OS specific utils implementations
    """

    @staticmethod
    @abstractmethod
    def toggle_promiscuous_mode(if_name: str, socket_obj: socket, enable: bool):
        """
        Toggles promiscuous mode on network card

        :param if_name: network interface name
        :param socket_obj: socket object
        :param enable: if True, promiscuous mode will be enabled, disabled otherwise
        """
        raise NotImplementedError
