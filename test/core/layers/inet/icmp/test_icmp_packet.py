from unittest import TestCase

from nally.core.layers.inet.icmp.icmp_packet import IcmpPacket, ICMP_CODE
from nally.core.layers.inet.icmp.icmp_codes import IcmpType


#
# ICMP echo request:
# Type: 8
# Code: 0
# Checksum: 0xd2c7
# Identifier: 1
# Sequence number: 1
#
ECHO_REQUEST_DUMP = '0800d2c700010001'
ECHO_REQUEST_PAYLOAD = '33e91e5f00000000131b0100000000001011121314151617' \
              '18191a1b1c1d1e1f2021222324252627' \
              '28292a2b2c2d2e2f3031323334353637'


#
# ICMP echo reply
# Type: 0
# Code: 0
# Checksum: 0x3483
# Identifier: 1
# Sequence number: 11
#
ECHO_REPLY_DUMP = '000034830001000b'
ECHO_REPLY_PAYLOAD = '3de91e5f00000000af550100000000001011121314151617' \
              '18191a1b1c1d1e1f2021222324252627' \
              '28292a2b2c2d2e2f3031323334353637'

class TestIcmpPacket(TestCase):

    def test_icmp_echo(self):
        icmp_request = IcmpPacket(
            icmp_type=IcmpType.ECHO_REQUEST,
            icmp_code=0,
            identifier=1,
            seq_number=1
        ) / bytes.fromhex(ECHO_REQUEST_PAYLOAD)
        packet_dump_1 = icmp_request.to_bytes()
        self.assertEqual(
            packet_dump_1.hex(),
            ECHO_REQUEST_DUMP + ECHO_REQUEST_PAYLOAD
        )
        parsed_packet = IcmpPacket.from_bytes(packet_dump_1)
        self.assertEqual(icmp_request, parsed_packet)

        icmp_reply = IcmpPacket(
            icmp_type=IcmpType.ECHO_REPLY,
            icmp_code=0,
            identifier=1,
            seq_number=11
        ) / bytes.fromhex(ECHO_REPLY_PAYLOAD)
        icmp_reply_dump = icmp_reply.to_bytes()
        self.assertEqual(
            icmp_reply_dump.hex(),
            ECHO_REPLY_DUMP + ECHO_REPLY_PAYLOAD
        )
        parsed_icmp_reply = IcmpPacket.from_bytes(icmp_reply_dump)
        self.assertEqual(icmp_reply, parsed_icmp_reply)

        with self.assertRaisesRegex(ValueError, 'unsupported ICMP code'):
            # should fail if ICMP code is invalid
            IcmpPacket(
                icmp_type=IcmpType.ECHO_REQUEST,
                icmp_code=2
            )

        with self.assertRaisesRegex(ValueError, 'unsupported ICMP code'):
            # should fail if ICMP code is invalid
            IcmpPacket(
                icmp_type=IcmpType.ECHO_REPLY,
                icmp_code=2
            )

        with self.assertRaisesRegex(ValueError, 'Required field'):
            # should fail if required params missed
            IcmpPacket(
                icmp_type=IcmpType.ECHO_REQUEST,
                icmp_code=0
            )

        with self.assertRaisesRegex(ValueError, 'Required field'):
            # should fail if required params missed
            IcmpPacket(
                icmp_type=IcmpType.ECHO_REPLY,
                icmp_code=0
            )
