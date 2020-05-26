from nally.port_scanner.scanning_strategies.scanning_strategy import ScanningStrategy


class SynScanningStrategy(ScanningStrategy):

    def scan_port(self, host: str, port: int) -> bool:
        return False

    @staticmethod
    def get_strategy_name() -> str:
        return ScanningStrategy.SYN_STRATEGY
