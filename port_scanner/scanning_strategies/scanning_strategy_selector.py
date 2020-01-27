from port_scanner.scanning_strategies.scanning_strategy import ScanningStrategy
from port_scanner.scanning_strategies.syn_scanning_strategy import SynScanningStrategy


class ScanningStrategySelector:

    AVAILABLE_STRATEGIES = {
        ScanningStrategy.SYN_STRATEGY: SynScanningStrategy(),
    }

    @staticmethod
    def get_scanning_strategy(scanning_type: str) -> ScanningStrategy:
        scan_strategy = ScanningStrategySelector.AVAILABLE_STRATEGIES.get(scanning_type)
        if scan_strategy is not None:
            return scan_strategy
        else:
            raise ValueError("Port scanning strategy [" + scanning_type + "] not found")
