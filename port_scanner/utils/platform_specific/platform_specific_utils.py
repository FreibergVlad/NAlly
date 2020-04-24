import platform

from port_scanner.utils.platform_specific.linux_utils import LinuxUtils
from port_scanner.utils.platform_specific.windows_utils import WindowsUtils

PlatformSpecificUtils = None
os_name = platform.system()
if os_name == 'Linux' or os_name == 'Darwin':
    PlatformSpecificUtils = LinuxUtils
elif os_name == 'Windows':
    PlatformSpecificUtils = WindowsUtils
else:
    raise RuntimeError(f"Unsupported OS: {os_name}")
