from abc import ABC, abstractmethod


class ScanningStrategy(ABC):

    SYN_STRATEGY = "SYN"

    @abstractmethod
    def scan_port(self, host: str, port: int) -> bool:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def get_strategy_name():
        raise NotImplementedError
