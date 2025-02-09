#!/usr/bin/env python

import asyncio
import struct
import tempfile
import unittest
from io import BytesIO
from typing import AsyncGenerator, AsyncIterable

import cart

try:
    # Handle python 3.8+
    from unittest import IsolatedAsyncioTestCase

    async def async_test(f):
        """Do nothing if IsolatedAsyncioTestCase is an option."""

        async def wrapper(*args, **kwargs):
            f(*args, **kwargs)

        return wrapper

except ImportError:
    # Handle older versions of Python 3.6 and 3.7

    class IsolatedAsyncioTestCase(unittest.TestCase):
        pass

    def async_test(f):
        """Handle async test cases for python 3.6 and 3.7"""

        def wrapper(*args, **kwargs):
            coro = asyncio.coroutine(f)
            future = coro(*args, **kwargs)
            loop = asyncio.get_event_loop()
            loop.run_until_complete(future)

        return wrapper


class BaseTest(IsolatedAsyncioTestCase):
    def setUp(self):
        self.MANDATORY_HEADER_SIZE = struct.calcsize(cart.MANDATORY_HEADER_FMT)

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


class TestCart(BaseTest):
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


class TestAsyncCart(BaseTest):
    """Test cases for the asynchronous functionalities of cart."""

    async def _convert_stream_to_async_iterable(
        self, stream: BytesIO
    ) -> AsyncGenerator[bytes, bytes]:
        chunk_size = 100
        while True:
            data = stream.read(chunk_size)
            if data:
                yield data
            else:
                return

    async def _read_all_async_iterable(
        self, async_iterable: AsyncIterable[bytes]
    ) -> bytes:
        data = []
        async for b in async_iterable:
            data.append(b)
        return b"".join(data)

    async def _base_async_test(
        self,
        test_data: bytes,
        test_header: dict,
        test_footer: dict,
    ):
        # Setup Async pack cart
        output_async_iterable = cart.async_pack_iterable(
            self._convert_stream_to_async_iterable(BytesIO(test_data)),
            test_header,
            test_footer,
            auto_digests=(),
        )
        # Test unpacking the result. async
        (outstream, opt_header) = await cart.async_unpack_iterable(
            output_async_iterable
        )
        plain_text = await self._read_all_async_iterable(outstream)
        self.assertEqual(test_header, opt_header)
        self.assertEqual(len(plain_text), len(test_data))

        # Setup Async pack cart for synchronous checks
        output_async_iterable = cart.async_pack_iterable(
            self._convert_stream_to_async_iterable(BytesIO(test_data)),
            test_header,
            test_footer,
            auto_digests=(),
        )
        packed_text = await self._read_all_async_iterable(output_async_iterable)

        # Now test unpacking the result. synchronously
        packed_stream = BytesIO(packed_text)
        plain_stream = BytesIO()
        (opt_header, opt_footer) = cart.unpack_stream(packed_stream, plain_stream)
        plain_text = plain_stream.getvalue()
        self.assertEqual(test_header, opt_header)
        self.assertEqual(test_footer, opt_footer)
        self.assertEqual(len(plain_text), len(test_data))

    @async_test
    async def test_empty(self):
        """
        Empty input stream, empty opt header, empty opt footer, no digests.
        """
        header = footer = {}
        await self._base_async_test(b"", header, footer)

    @async_test
    async def test_small(self):
        """
        1 byte stream, 1 element opt header, 1 element opt footer, default digests.
        """
        test_text = b"a"
        test_header = {"testkey": "testvalue"}
        test_footer = {"complete": "yes"}
        await self._base_async_test(test_text, test_header, test_footer)

    @async_test
    async def test_large(self):
        """
        128MB stream, large opt header, large opt footer, default digests + testdigester.
        """
        test_text = b"0" * 1024 * 1024 * 128
        test_header = {}
        test_footer = {}
        await self._base_async_test(test_text, test_header, test_footer)

    @async_test
    async def test_rc4_override(self):
        rc4_key = b"Test Da Key !"
        test_header = {"name": "hello.txt"}
        test_footer = {"rc4_key": rc4_key.decode()}
        test_text = b"0123456789" * 100

        output_async_iterable = cart.async_pack_iterable(
            self._convert_stream_to_async_iterable(BytesIO(test_text)),
            test_header,
            test_footer,
            auto_digests=(),
            arc4_key_override=rc4_key,
        )

        crypt_text = await self._read_all_async_iterable(output_async_iterable)
        ct_stream = BytesIO(crypt_text)
        pt_stream = BytesIO()

        with self.assertRaises(cart.InvalidARC4KeyException):
            cart.unpack_stream(ct_stream, pt_stream)

        ct_stream = BytesIO(crypt_text)
        pt_stream = BytesIO()

        (header, footer) = cart.unpack_stream(
            ct_stream, pt_stream, arc4_key_override=rc4_key
        )
        self.assertEqual(header, test_header)
        self.assertEqual(footer, test_footer)

    @async_test
    async def test_not_a_cart(self):
        fake_cart = b"0123456789" * 1000
        ct_stream = BytesIO(fake_cart)
        with self.assertRaises(cart.InvalidCARTException):
            await cart.async_unpack_iterable(
                self._convert_stream_to_async_iterable(ct_stream)
            )


if __name__ == "__main__":
    unittest.main()
