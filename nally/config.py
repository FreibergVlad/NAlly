from nally.core.utils.platform_specific.platform_specific_utils import PlatformSpecificUtils


class Config:

    def __init__(self, **kwargs) -> None:
        self.interface_name: str = kwargs.get('interface_name') or PlatformSpecificUtils.get_default_interface()
        self.interface_ip: str = PlatformSpecificUtils.get_net_interface_ip(self.interface_name)
        self.interface_mac: str = PlatformSpecificUtils.get_net_interface_mac(self.interface_name)


config = Config()
