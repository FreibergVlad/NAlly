from abc import abstractmethod, ABC


class AbstractPlatformSpecificUtils(ABC):
    """
    Defines abstract interface for OS specific utils implementations
    """

    @staticmethod
    @abstractmethod
    def get_default_interface() -> str:
        """
        Returns name of the default network interface
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def get_net_interface_mac(if_name: str) -> str:
        """
        Returns MAC address associated with this network interface.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def get_net_interface_ip(if_name: str) -> str:
        """
        Returns IP address associated with this network interface.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def toggle_promiscuous_mode(if_name: str, enable: bool):
        """
        Toggles promiscuous mode on network card

        :param if_name: network interface name
        :param enable: if True, promiscuous mode will be enabled,
            disabled otherwise
        """
        raise NotImplementedError
