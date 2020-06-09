from nally.core.utils.platform_specific.abstract_platform_specific_utils \
    import AbstractPlatformSpecificUtils


class WindowsUtils(AbstractPlatformSpecificUtils):

    @staticmethod
    def get_default_interface() -> str:
        raise NotImplementedError

    @staticmethod
    def get_net_interface_mac(if_name: str) -> str:
        raise NotImplementedError

    @staticmethod
    def get_net_interface_ip(if_name: str) -> str:
        raise NotImplementedError

    @staticmethod
    def toggle_promiscuous_mode(if_name: str, enable: bool):
        raise NotImplementedError
