from abc import abstractmethod, ABC
from socket import socket


class AbstractPlatformSpecificUtils(ABC):

    @staticmethod
    @abstractmethod
    def toggle_promiscuous_mode(if_name: str, socket_obj: socket, enable: bool):
        raise NotImplementedError
