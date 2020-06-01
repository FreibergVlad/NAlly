from concurrent.futures.thread import ThreadPoolExecutor

from nally.core.sniffer.sniffer import Sniffer


class AsyncSniffer:
    """
    Provides interface for asynchronous packet capturing

    Note: caller classes are fully responsible for external exceptions handling
    (e.g. KeyboardInterrupt) and calling 'stop()' method to avoid unreleased resources
    """

    def __init__(
            self,
            packet_callback: callable,
            started_callback: callable = None,
            if_name: str = None,
            packet_count: int = None,
            promiscuous_mode: bool = True,
            bpf_filter: str = "",
            timeout: int = None
    ):
        """
        Initializes AsyncSniffer instance

        :param packet_callback: function which will be called when the new packet caught
        :param started_callback: function which will be called when the sniffer is initialized
        :param if_name: network interface for capturing, if not specified,
            then sniffer will try to pick up the default one
        :param packet_count: number of packets that should be caught
        :param promiscuous_mode: indicates if sniffer should receive all packets on the LAN, including packets sent to
            a network address that the network adapter isn't configured to recognize.
        :param bpf_filter: packet filter in BPF format
        :param timeout: specifies timeout in seconds after which sniffer will be terminated
        """
        self._packet_callback = packet_callback
        self._started_callback = started_callback
        self._if_name = if_name
        self._packet_count = packet_count
        self._promiscuous_mode = promiscuous_mode
        self._bpf_filter = bpf_filter
        self._timeout = timeout
        self._sniffer = Sniffer(
                callback=self._packet_callback,
                if_name=self._if_name,
                packet_count=self._packet_count,
                promiscuous_mode=self._promiscuous_mode,
                bpf_filter=self._bpf_filter,
                timeout=self._timeout,
        )

    def sniff_async(self):
        """
        Starts sniffing thread
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(self._sniff)

    def stop(self):
        """
        Gracefully shutdowns sniffer
        """
        self._sniffer.stop()

    def _sniff(self):
        with self._sniffer as sniffer:
            if self._started_callback is not None:
                self._started_callback()
            return sniffer.sniff()
