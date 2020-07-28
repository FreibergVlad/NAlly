from unittest import TestCase

from nally.core.layers.fields import ShortField, ByteField


class TestField(TestCase):

    def test_short_field_to_bytes(self):
        field = ShortField("field")
        self.assertRaises(Exception, field.to_bytes, 65536)
        self.assertEqual(bytes(b"\xff\xff"), field.to_bytes(65535))
        self.assertEqual(bytes(b"\x00\x00"), field.to_bytes())

        field2 = ShortField("field2", 1)
        self.assertEqual(bytes(b"\xff\xff"), field2.to_bytes(65535))
        self.assertEqual(bytes(b"\x00\x01"), field2.to_bytes())

    def test_byte_field_to_bytes(self):
        field = ByteField("field")
        self.assertRaises(Exception, field.to_bytes, 256)
        self.assertEqual(bytes(b"\xff"), field.to_bytes(255))
        self.assertEqual(bytes(b"\x00"), field.to_bytes())

        field2 = ByteField("field2", 1)
        self.assertEqual(bytes(b"\xff"), field2.to_bytes(255))
        self.assertEqual(bytes(b"\x01"), field2.to_bytes())
