# Unix SMB/CIFS implementation.
# Copyright © Catalyst
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from unittest import TestSuite
import os
import random

from samba.tests import TestCase
from samba import compression


TEST_DIR = "testdata/compression"


class BaseCompressionTest(TestCase):
    def round_trip(self, data, size_delta=0):
        """Compress, decompress, assert equality with original.

        If size_delta is None, no size is given to decompress. This
        should fail with the Huffman variant and succeed with plain.
        Otherwise size_delta is added to the gven size; if negative,
        we'd expect a failure, with plain compression a positive delta
        will succeed.
        """

        compressed = self.compress(data)
        if size_delta is None:
            decompressed = self.decompress(compressed)
        else:
            decomp_size = len(data) + size_delta
            decompressed = self.decompress(compressed, decomp_size)

        if isinstance(data, str):
            data = data.encode()

        self.assertEqual(data, decompressed)
        return compressed

    def decompress_file(self, fn):
        decomp_fn = os.path.join(TEST_DIR,
                                 "decompressed",
                                 fn + ".decomp")
        comp_fn = os.path.join(TEST_DIR,
                               self.compressed_dir,
                               fn + self.compressed_suffix)

        with open(decomp_fn, 'rb') as f:
            decomp_expected = f.read()
        with open(comp_fn, 'rb') as f:
            comp = f.read()

        decompressed = self.decompress(comp, len(decomp_expected))

        self.assertEqual(decomp_expected, decompressed)


class LzxpressPlainCompressionTest(BaseCompressionTest):
    compress = compression.plain_compress
    decompress = compression.plain_decompress
    compressed_dir = "compressed-plain"
    compressed_suffix = ".lzplain"

    def test_round_trip_aaa_str(self):
        s = 'a' * 150000
        self.round_trip(s)

    def test_round_trip_aaa_bytes(self):
        s = b'a' * 150000
        self.round_trip(s)

    def test_round_trip_aaa_short(self):
        s = b'a' * 150000

        # this'll fail because the match for 'aaa...' will run
        # past the end of the buffer
        self.assertRaises(compression.CompressionError,
                          self.round_trip, s, -1)

    def test_round_trip_aaa_long(self):
        s = b'a' * 150000
        # this *won't* fail because although the data will run out
        # before the buffer is full, LZXpress plain does not care
        # about that.
        try:
            self.round_trip(s, 1)
        except compression.CompressionError as e:
            self.fail(f"failed to decompress with {e}")

    def test_round_trip_aaab_short(self):
        s = b'a' * 150000 + b'b'

        # this will *partially* succeed, because the buffer will fill
        # up vat a break in the decompression (not mid-match), and
        # lzxpress plain does not mind that. However self.round_trip
        # also makes an assertion that the original data equals the
        # decompressed result, and it won't because the decompressed
        # result is one byte shorter.
        self.assertRaises(AssertionError,
                          self.round_trip, s, -1)

    def test_round_trip_aaab_unstated(self):
        s = b'a' * 150000 + b'b'

        # this will succeed, because with no target size given, we
        # guess a large buffer in the python bindings.
        try:
            self.round_trip(s)
        except compression.CompressionError as e:
            self.fail(f"failed to decompress with {e}")

    def test_round_trip_30mb(self):
        s = b'abc' * 10000000
        # This will decompress into a string bigger than the python
        # bindings are willing to speculatively allocate, so will fail
        # to decompress.
        with self.assertRaises(compression.CompressionError):
            self.round_trip(s, None)

        # but it will be fine if we use the length
        try:
            self.round_trip(s, 0)
        except compression.CompressionError as e:
            self.fail(f"failed to decompress with {e}")

    def test_files(self):
        # We don't go through the whole set, which are already tested
        # by lib/compression/tests/test_lzxpress_plain.c
        for fn in ("slow-33d90a24e70515b14cd0",
                   "midsummer-nights-dream.txt"):
            self.decompress_file(fn)

    def test_empty_round_trip(self):
        # not symmetrical with Huffman, this doesn't fail
        self.round_trip('')


class LzxpressHuffmanCompressionTest(BaseCompressionTest):
    compress = compression.huffman_compress
    decompress = compression.huffman_decompress
    compressed_dir = "compressed-huffman"
    compressed_suffix = ".lzhuff"

    def test_round_trip_aaa_str(self):
        s = 'a' * 150000
        self.round_trip(s)

    def test_round_trip_aaa_bytes(self):
        s = b'a' * 150000
        self.round_trip(s)

    def test_round_trip_aaa_short(self):
        s = b'a' * 150000

        # this'll fail because the match for 'aaa...' will run
        # past the end of the buffer
        self.assertRaises(compression.CompressionError,
                          self.round_trip, s, -1)

    def test_round_trip_aaa_long(self):
        s = b'a' * 150000

        # this'll fail because the data will run out before the buffer
        # is full.
        self.assertRaises(compression.CompressionError,
                          self.round_trip, s, 1)

    def test_round_trip_aaab_short(self):
        s = b'a' * 150000 + b'b'

        # this *could* be allowed to succeed, because even though we
        # give it the wrong size, we know the decompression will not
        # flow over the end of the buffer, The behaviour here appears
        # to be implementation dependent -- the decompressor has the
        # option of saying 'whatever' and continuing. We are probably
        # stricter than Windows.
        self.assertRaises(compression.CompressionError,
                          self.round_trip, s, -1)

    def test_round_trip_aaab_unstated(self):
        s = b'a' * 150000 + b'b'

        # For the Huffman algorithm, the length is really an essential
        # part of the compression data, and the bindings will reject a
        # call with out it. This happens at the argument parsing stage,
        # so is a TypeError (i.e. wrong type of function), not a
        # CompressionError.
        self.assertRaises(TypeError,
                          self.round_trip, s, None)

    def test_files(self):
        # We don't go through the whole set, which are already tested
        # by lib/compression/tests/test_lzx_huffman.c
        for fn in ("slow-33d90a24e70515b14cd0",
                   "midsummer-nights-dream.txt"):
            self.decompress_file(fn)

    def test_empty_round_trip(self):
        with self.assertRaises(compression.CompressionError):
            self.round_trip('')
