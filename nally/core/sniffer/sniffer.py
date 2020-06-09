import logging
import socket
import selectors
import time
from typing import Generator

from pcapy import BPFProgram

from nally.config import config
from nally.core.layers.link.ethernet.ethernet_packet import EthernetPacket
from nally.core.layers.link.ethernet.ethernet_utils import EthernetUtils
from nally.core.layers.packet import Packet
from nally.core.utils.platform_specific.platform_specific_utils import PlatformSpecificUtils


class Sniffer:
    """
    Provides interface for packet capturing
    """

    ETH_P_ALL = 3
    BUFFER_SIZE_BYTES = EthernetUtils.MAX_PAYLOAD_LENGTH_BYTES

    LOG = logging.getLogger("Sniffer")

    def __init__(
            self,
            if_name: str = None,
            started_callback: callable = None,
            packet_count: int = None,
            promiscuous_mode: bool = True,
            bpf_filter: str = "",
            timeout: int = None
    ):
        """
        :param if_name: network interface for capturing, if not specified,
            then sniffer will try to pick up the default one
        :param started_callback: function which will be called after the sniffer initialization
        :param packet_count: number of packets that should be caught
        :param promiscuous_mode: indicates if sniffer should receive all packets on the LAN, including packets sent to
            a network address that the network adapter isn't configured to recognize.
        :param bpf_filter: packet filter in BPF format
        :param timeout: specifies timeout in seconds after which sniffer will be terminated
        """
        self._if_name = if_name if if_name is not None else config.interface_name
        self._started_callback = started_callback
        self._packet_count = packet_count
        self._promiscuous_mode = promiscuous_mode
        self._bpf_filter = bpf_filter
        self._timeout = timeout
        self._stopped = False
        self._sniff_socket = None
        self._compiled_filter = None

    def sniff(self) -> Generator[Packet, None, int]:
        processed_count = 0
        try:
            if self._sniff_socket is None:
                raise RuntimeError('Sniffer should be used inside context manager')
            termination_date_seconds = None
            if self._started_callback is not None:
                self._started_callback()
            if self._timeout is not None:
                termination_date_seconds = time.time() + self._timeout
            remaining_time_seconds = None
            while not self._stopped:
                if processed_count == self._packet_count:
                    break
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
                raw_packet: bytes = packet_addr[0]
                if self._filter_packet(raw_packet):
                    # parse Ethernet header and all upper layers if present
                    ethernet_packet = EthernetPacket.from_bytes(raw_packet)
                    processed_count += 1
                    yield ethernet_packet
            return processed_count
        except KeyboardInterrupt:
            self.LOG.debug("Keyboard interruption received. Exiting...")
            return processed_count

    def stop(self):
        """
        Provides ability to gracefully terminate the sniffer (makes sense if sniffer is running in
        the separate thread)
        """
        if self._stopped:
            raise RuntimeError("Illegal state: sniffer already terminated")
        self._stopped = True

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

    def _toggle_promiscuous_mode(self, enable: bool):
        """
        Toggles promiscuous mode on network card if
        corresponding sniffer option enabled
        """
        if self._promiscuous_mode:
            PlatformSpecificUtils.toggle_promiscuous_mode(self._if_name, enable)

    def __enter__(self):
        self._sniff_socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(self.ETH_P_ALL)
        )
        self._toggle_promiscuous_mode(True)
        self._sniff_socket.setblocking(False)
        self._sniff_socket.bind((self._if_name, 0))
        self._compile_filter()
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._sniff_socket, selectors.EVENT_READ)
        self.LOG.debug(
            "Sniffer had been initialized with the following options: "
            f"promiscuous_mode={self._promiscuous_mode}, "
            f"bpf_filter='{self._bpf_filter}', "
            f"timeout={self._timeout}, "
            f"if_name={self._if_name}, "
            f"packet_count={self._packet_count}"
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.LOG.debug("Exiting from sniffer, cleaning up resources...")
        self._toggle_promiscuous_mode(False)
        self._sniff_socket.close()
        self._sniff_socket = None
        self._selector.close()
        self._selector = None
