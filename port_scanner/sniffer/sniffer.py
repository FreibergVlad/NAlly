import socket
import selectors
import time

from pcapy import BPFProgram

from port_scanner.layers.link.ethernet.ethernet_utils import EthernetUtils
from port_scanner.utils.platform_specific.platform_specific_utils import PlatformSpecificUtils


class Sniffer:
    """
    Provides interface for packet capturing
    """

    ETH_P_ALL = 3  # TODO move to commons utils?
    # FIXME should buffer size be equal to maximum Ethernet frame size?
    BUFFER_SIZE_BYTES = EthernetUtils.MAX_PAYLOAD_LENGTH_BYTES

    def __init__(
            self,
            if_name: str,
            callback: callable,
            packet_count: int = None,
            promiscuous_mode: bool = True,
            bpf_filter: str = "",
            timeout: int = None
    ):
        """
        :param if_name: network interface for capturing
        :param callback: function which will be called when the new packet caught
        :param packet_count: number of packets that should be caught
        :param promiscuous_mode: indicates if sniffer should receive all packets on the LAN, including packets sent to
            a network address that the network adapter isn't configured to recognize.
        :param bpf_filter: packet filter in BPF format
        :param timeout: specifies timeout in seconds after which sniffer will be terminated
        """
        self._if_name = if_name
        self._packet_count = packet_count
        self._callback = callback
        self._promiscuous_mode = promiscuous_mode
        self._bpf_filter = bpf_filter
        self._timeout = timeout
        self._sniff_socket = None
        self._compiled_filter = None

    def sniff(self) -> int:
        if self._sniff_socket is None:
            raise RuntimeError('Sniffer should be used inside context manager')
        processed_count = 0
        termination_date_seconds = None
        if self._timeout is not None:
            termination_date_seconds = time.time() + self._timeout
        remaining_time_seconds = None
        while True:
            if self._timeout is not None:
                remaining_time_seconds = termination_date_seconds - time.time()
                if remaining_time_seconds <= 0:
                    break
            # blocking call, waits until data in socket will be available,
            # or until timeout expires
            if not self._selector.select(remaining_time_seconds):
                # no data in socket available yet
                continue
            # data is available
            packet_addr: tuple = self._sniff_socket.recvfrom(self.BUFFER_SIZE_BYTES)
            packet: bytes = packet_addr[0]
            if self._process_packet(packet):
                processed_count += 1
            if processed_count == self._packet_count:
                break
        return processed_count

    def _process_packet(self, raw_packet: bytes) -> bool:
        """
        Processes arrived raw packet, applies necessary filters and passes
        it to the user-defined callback

        :param raw_packet: raw network packet
        :return: True, if packet was processed successfully, False otherwise
        """
        if self._filter_packet(raw_packet):
            self._callback(raw_packet)
            return True
        return False

    def _compile_filter(self):
        """
        If BPF filter was specified, then compiles it using 'libpcap'
        """
        if self._bpf_filter is not None:
            self._compiled_filter = BPFProgram(self._bpf_filter)

    def _filter_packet(self, raw_packet: bytes):
        """
        Filters packet using the BPF filter, if specified

        :param raw_packet: raw network packet
        :return: True, if packet satisfies the filter conditions, False otherwise
        """
        if self._compiled_filter is not None:
            return self._compiled_filter.filter(raw_packet) != 0
        return True

    def __enter__(self):
        self._sniff_socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(self.ETH_P_ALL)
        )
        PlatformSpecificUtils.toggle_promiscuous_mode(self._if_name, self._sniff_socket, True)
        self._sniff_socket.setblocking(False)
        self._sniff_socket.bind((self._if_name, 0))
        self._compile_filter()
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._sniff_socket, selectors.EVENT_READ)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        PlatformSpecificUtils.toggle_promiscuous_mode(self._if_name, self._sniff_socket, False)
        self._sniff_socket.close()
        self._sniff_socket = None
        self._selector.close()
        self._selector = None
