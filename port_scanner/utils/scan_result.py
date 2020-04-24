from enum import IntEnum


class ScanResult(IntEnum):

    OPEN = 0
    CLOSED = 1
    FILTERED = 2
    UNFILTERED = 3
    OPEN_FILTERED = 4
    CLOSED_FILTERED = 5
