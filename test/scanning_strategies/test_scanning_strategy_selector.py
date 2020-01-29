from unittest import TestCase

from port_scanner.scanning_strategies.scanning_strategy import ScanningStrategy
from port_scanner.scanning_strategies.scanning_strategy_selector import ScanningStrategySelector


class TestScanningStrategySelector(TestCase):

    def test_get_scanning_strategy(self):
        syn_strategy = ScanningStrategySelector.get_scanning_strategy(ScanningStrategy.SYN_STRATEGY)
        self.assertEqual(ScanningStrategy.SYN_STRATEGY, syn_strategy.get_strategy_name())

    def test_get_scanning_strategy_with_invalid_params(self):
        self.assertRaises(ValueError, ScanningStrategySelector.get_scanning_strategy, "invalid_value")
