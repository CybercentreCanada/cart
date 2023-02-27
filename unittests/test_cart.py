#!/usr/bin/env python

import cart
import struct
import tempfile
import unittest

from io import BytesIO


class TestCart(unittest.TestCase):
    def setUp(self):
        self.MANDATORY_HEADER_SIZE = struct.calcsize(cart.MANDATORY_HEADER_FMT)

    def tearDown(self):
        pass

    def assert_valid_mandatory_header(self, packed):
        if not len(packed) >= self.MANDATORY_HEADER_SIZE:
            raise AssertionError("Not enough bytes for mandatory header.")

        # unpack the header
        (magic, version, reserved, arc4_key, opt_hlen) = struct.unpack(
            cart.MANDATORY_HEADER_FMT, packed[: self.MANDATORY_HEADER_SIZE]
        )

        self.assertEqual(magic, b"CART")
        self.assertEqual(version, 1)
        self.assertEqual(reserved, 0)
        self.assertEqual(arc4_key, cart.DEFAULT_ARC4_KEY)
        # self.assertGreaterEqual(opt_hlen, 0)

    def test_empty(self):
        """
        Empty input stream, empty opt header, empty opt footer, no digests.
        """
        empty_stream = BytesIO()
        output_stream = BytesIO()
        header = footer = {}

        # Pack with empty everything
        cart.pack_stream(empty_stream, output_stream, header, footer, auto_digests=())
        packed_text = output_stream.getvalue()
        self.assert_valid_mandatory_header(packed_text)

        # Now test unpacking the result.
        packed_stream = BytesIO(packed_text)
        plain_stream = BytesIO()
        (opt_header, opt_footer) = cart.unpack_stream(packed_stream, plain_stream)
        plain_text = plain_stream.getvalue()
        self.assertEqual(opt_header, {})
        self.assertEqual(opt_footer, {})
        self.assertEqual(len(plain_text), 0)

    def test_small(self):
        """
        1 byte stream, 1 element opt header, 1 element opt footer, default digests.
        """
        test_text = b"a"
        in_stream = BytesIO(test_text)
        output_stream = BytesIO()
        test_header = {"testkey": "testvalue"}
        test_footer = {"complete": "yes"}

        # Pack with empty everything
        cart.pack_stream(in_stream, output_stream, test_header, test_footer)
        packed_text = output_stream.getvalue()
        self.assert_valid_mandatory_header(packed_text)

        # Now test unpacking the result.
        packed_stream = BytesIO(packed_text)
        plain_stream = BytesIO()
        (opt_header, opt_footer) = cart.unpack_stream(packed_stream, plain_stream)
        plain_text = plain_stream.getvalue()
        self.assertEqual(test_header, opt_header)
        self.assertEqual(test_footer, opt_footer)
        self.assertEqual(test_text, plain_text)

    def test_large(self):
        """
        128MB stream, large opt header, large opt footer, default digests + testdigester.
        """
        test_text = b"0" * 1024 * 1024 * 128
        in_stream = BytesIO(test_text)
        output_stream = BytesIO()
        test_header = {}
        test_footer = {}

        # Pack with empty everything
        cart.pack_stream(in_stream, output_stream, test_header, test_footer)
        packed_text = output_stream.getvalue()
        self.assert_valid_mandatory_header(packed_text)

        # Now test unpacking the result.
        packed_stream = BytesIO(packed_text)
        plain_stream = BytesIO()
        (opt_header, opt_footer) = cart.unpack_stream(packed_stream, plain_stream)
        plain_text = plain_stream.getvalue()
        self.assertEqual(test_header, opt_header)
        self.assertEqual(test_footer, opt_footer)
        self.assertEqual(test_text, plain_text)

    def test_simple(self):
        plaintext = b"0123456789" * 10000000

        pt_stream = BytesIO(plaintext)

        ct_stream = BytesIO()

        cart.pack_stream(
            pt_stream, ct_stream, {"name": "hello.txt"}, {"digest": "done"}
        )

        crypt_text = ct_stream.getvalue()
        ct_stream = BytesIO(crypt_text)
        pt_stream = BytesIO()

        temp_file = tempfile.mkstemp()[1]
        with open(temp_file, "wb") as f:
            f.write(ct_stream.getvalue())

        (header, footer) = cart.unpack_stream(ct_stream, pt_stream)
        inline_metadata = {}
        if header:
            inline_metadata.update(header)

        if footer:
            inline_metadata.update(footer)

        plaintext_prime = pt_stream.getvalue()
        self.assertEqual(plaintext_prime, plaintext)

        metadata = cart.get_metadata_only(temp_file)
        self.assertEqual(metadata, inline_metadata)
        self.assertTrue(cart.is_cart(crypt_text))

    def test_rc4_override(self):
        rc4_key = b"Test Da Key !"
        tmp_header = {"name": "hello.txt"}
        tmp_footer = {"rc4_key": rc4_key.decode()}
        plaintext = b"0123456789" * 100
        pt_stream = BytesIO(plaintext)
        ct_stream = BytesIO()

        cart.pack_stream(
            pt_stream,
            ct_stream,
            optional_header=tmp_header,
            optional_footer=tmp_footer,
            arc4_key_override=rc4_key,
        )

        crypt_text = ct_stream.getvalue()
        ct_stream = BytesIO(crypt_text)
        pt_stream = BytesIO()

        with self.assertRaises(cart.InvalidARC4KeyException):
            cart.unpack_stream(ct_stream, pt_stream)

        ct_stream = BytesIO(crypt_text)
        pt_stream = BytesIO()

        (header, footer) = cart.unpack_stream(
            ct_stream, pt_stream, arc4_key_override=rc4_key
        )
        self.assertEqual(header, tmp_header)
        self.assertEqual(footer, tmp_footer)

    def test_not_a_cart(self):
        fake_cart = b"0123456789" * 1000
        ct_stream = BytesIO(fake_cart)

        ot_stream = BytesIO()

        with self.assertRaises(cart.InvalidCARTException):
            cart.unpack_stream(ct_stream, ot_stream)


if __name__ == "__main__":
    unittest.main()
