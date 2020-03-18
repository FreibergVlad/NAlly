class TcpUtils:

    @staticmethod
    def validate_port_num(port):
        if port < 0 or port > 65535:
            raise ValueError("port number should be in [0;65535] range")
        return port
