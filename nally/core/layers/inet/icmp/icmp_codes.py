from enum import IntEnum
from typing import NamedTuple


class IcmpType(IntEnum):
    """
    Enum of ICMP types, doesn't include deprecated, unassigned, reserved
    and experimental types
    """
    ECHO_REPLY = 0
    DEST_UNREACHABLE = 3
    REDIRECT = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    BAD_IP_HEADER = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14
    EXT_ECHO_REQUEST = 42
    EXT_ECHO_REPLY = 43


ICMP_CODE = {
    IcmpType.ECHO_REPLY: {
        0: "echo_reply"
    },
    IcmpType.DEST_UNREACHABLE: {
        0: "dest_network_unreachable",
        1: "dest_host_unreachable",
        2: "dest_proto_unreachable",
        3: "dest_port_unreachable",
        4: "frag_required",
        5: "source_route_failed",
        6: "dest_network_unknown",
        7: "dest_host_unknown",
        8: "source_host_isolated",
        9: "network_prohibited",
        10: "host_prohibited",
        11: "network_unreachable_tos",
        12: "host_unreachable_tos",
        13: "communication_prohibited",
        14: "host_precedence_validation",
        15: "precedence_cutoff_in_effect"
    },
    IcmpType.REDIRECT: {
        0: "redirect_for_network",
        1: "redirect_for_host",
        2: "redirect_for_tos_network",
        3: "redirect_for_tos_host"
    },
    IcmpType.ECHO_REQUEST: {
        0: "echo_request"
    },
    IcmpType.ROUTER_ADVERTISEMENT: {
        0: "router_advertisement"
    },
    IcmpType.ROUTER_SOLICITATION: {
        0: "router_solicitation"
    },
    IcmpType.TIME_EXCEEDED: {
        0: "ttl_expired",
        1: "frag_reassembly_time_exceeded"
    },
    IcmpType.BAD_IP_HEADER: {
        0: "pointer_indicates_error",
        1: "missing_required_option",
        2: "bad_length"
    },
    IcmpType.TIMESTAMP: {
        0: "timestamp_request"
    },
    IcmpType.TIMESTAMP_REPLY: {
        0: "timestamp_reply"
    },
    IcmpType.EXT_ECHO_REQUEST: {
        0: "ext_echo_request"
    },
    IcmpType.EXT_ECHO_REPLY: {
        0: "ext_echo_reply"
    }
}


class IcmpFormat(NamedTuple):
    """
    Describes format of ICMP packet depending
    on ICMP type and code
    """
    required_header_fields: list = []
    header_format: str = None


ICMP_VARIABLE_HEADER_FIELDS = {
    IcmpType.ECHO_REPLY: IcmpFormat(
        required_header_fields=['identifier', 'seq_number'],
        header_format='!HH'
    ),
    IcmpType.DEST_UNREACHABLE: IcmpFormat(),
    IcmpType.REDIRECT: IcmpFormat(
        required_header_fields=['gateway_ip'],
        header_format='!4s'
    ),
    IcmpType.ECHO_REQUEST: IcmpFormat(
        required_header_fields=['identifier', 'seq_number'],
        header_format='!HH'
    ),
    IcmpType.ROUTER_ADVERTISEMENT: IcmpFormat(),
    IcmpType.ROUTER_SOLICITATION: IcmpFormat(),
    IcmpType.TIME_EXCEEDED: IcmpFormat(),
    IcmpType.BAD_IP_HEADER: {
        0: IcmpFormat(
            required_header_fields=['pointer'],
            header_format='B0I'
        ),
        1: IcmpFormat(),
        2: IcmpFormat()
    },
    IcmpType.TIMESTAMP: {
    },
    IcmpType.TIMESTAMP_REPLY: {
    },
    IcmpType.EXT_ECHO_REQUEST: {
    },
    IcmpType.EXT_ECHO_REPLY: {
    }
}
