class TcpUtils:
    """
    Stores constants related to TCP protocol and utility methods
    """

    TCP_HEADER_LENGTH = 5
    TCP_HEADER_LENGTH_BYTES = TCP_HEADER_LENGTH * 4
    TCP_OPTIONS_MAX_LENGTH_BYTES = 40

    @staticmethod
    def validate_options_length(options):
        length = len(options)
        if length > TcpUtils.TCP_OPTIONS_MAX_LENGTH_BYTES:
            raise ValueError(f"Max options length is "
                             f"{TcpUtils.TCP_OPTIONS_MAX_LENGTH_BYTES} "
                             f"got {length}")
