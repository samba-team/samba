/*
 * Samba compression library - LGPLv3
 *
 * Copyright © Catalyst IT 2022
 *
 * Written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
 *
 *  ** NOTE! The following LGPL license applies to this file.
 *  ** It does NOT imply that all of Samba is released under the LGPL
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 3 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include "replace.h"
#include <talloc.h>
#include "lzxpress_huffman.h"
#include "lib/util/stable_sort.h"
#include "lib/util/data_blob.h"

/* set LZXHUFF_DEBUG_FILES to true to save round-trip files in /tmp. */
#define LZXHUFF_DEBUG_FILES false

/* set LZXHUFF_DEBUG_VERBOSE to true to print more. */
#define LZXHUFF_DEBUG_VERBOSE false


#if LZXHUFF_DEBUG_VERBOSE
#define debug_message(...) print_message(__VA_ARGS__)
#else
#define debug_message(...) /* debug_message */
#endif


struct lzx_pair {
	const char *name;
	DATA_BLOB compressed;
	DATA_BLOB decompressed;
};

struct lzx_file_pair {
	const char *name;
	const char *compressed_file;
	const char *decompressed_file;
};


#define DECOMP_DIR "testdata/compression/lzxpress-huffman/decompressed"
#define COMP_DIR "testdata/compression/lzxpress-huffman/compressed"
#define MORE_COMP_DIR "testdata/compression/lzxpress-huffman/more-compressed"


#define VARRGH(...) __VA_ARGS__

#define BLOB_FROM_ARRAY(...)                             \
	{                                                \
		.data = (uint8_t[]){__VA_ARGS__},          \
		.length = sizeof((uint8_t[]){__VA_ARGS__}) \
	}

#define BLOB_FROM_STRING(s)                                      \
	{                                                            \
		.data = discard_const_p(uint8_t, s),		     \
		.length = (sizeof(s) - 1)		     \
	}


const char * file_names[] = {
	"27826-8.txt",
	"5d049b4cb1bd933f5e8ex19",
	"638e61e96d54279981c3x5",
	"64k-minus-one-zeros",
	"64k-plus-one-zeros",
	"64k-zeros",
	"96f696a4e5ce56c61a3dx10",
	"9e0b6a12febf38e98f13",
	"abc-times-101",
	"abc-times-105",
	"abc-times-200",
	"and_rand",
	"and_rand-128k+",
	"b63289ccc7f218c0d56b",
	"beta-variate1-128k+",
	"beta-variate2-128k+",
	"beta-variate3-128k+",
	"decayed_alphabet_128k+",
	"decayed_alphabet_64k",
	"exp_shuffle",
	"exp_shuffle-128k+",
	"f00842317dc6d5695b02",
	"fib_shuffle",
	"fib_shuffle-128k+",
	"fuzzing-0fc2d461b56cd8103c91",
	"fuzzing-17c961778538cc10ab7c",
	"fuzzing-3591f9dc02bb00a54b60",
	"fuzzing-3ec3bca27bb9eb40c128",
	"fuzzing-80b4fa18ff5f8dd04862",
	"fuzzing-a3115a81d1ac500318f9",
	"generate-windows-test-vectors.c",
	"midsummer-nights-dream.txt",
	"notes-on-the-underground.txt",
	"pg22009.txt",
	"repeating",
	"repeating-exactly-64k",
	"setup.log",
	"skewed_choices",
	"skewed_choices-128k+",
	/* These ones were deathly slow in fuzzing at one point */
	"slow-015ddc36a71412ccc50d",
	"slow-100e9f966a7feb9ca40a",
	"slow-2a671c3cff4f1574cbab",
	"slow-33d90a24e70515b14cd0",
	"slow-49d8c05261e3f412fc72",
	"slow-50a249d2fe56873e56a0",
	"slow-63e9f0b52235fb0129fa",
	"slow-73b7f971d65908ac0095",
	"slow-8b61e3dd267908544531",
	"slow-9d1c5a079b0462986f1f",
	"slow-aa7262a821dabdcf04a6",
	"slow-b8a91d142b0d2af7f5ca",
	"slow-c79142457734bbc8d575",
	"slow-d736544545b90d83fe75",
	"slow-e3b9bdfaed7d1a606fdb",
	"slow-f3f1c02a9d006e5e1703",
	"square_series",
	"square_series-128k+",
	"trigram_128k+",
	"trigram_64k",
	"trigram_sum_128k+",
	"trigram_sum_64k",
	NULL
};

struct lzx_pair bidirectional_pairs[] = {

	{.name = "abc__100_repeats", /* [MS-XCA] 3.2 example 2. */
	 .decompressed = BLOB_FROM_STRING(
		 "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc"
		 "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc"
		 "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc"
		 "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc"
		 "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc"
		 ),
	 .compressed = BLOB_FROM_ARRAY(
		 /*
		  * The 'a', 'b', and 'c' bytes are 0x61, 0x62, 0x63. No other
		  * symbols occur. That means we need 48 0x00 bytes for the
		  * first 96 symbol-nybbles, then some short codes, then zeros
		  * again for the rest of the literals.
		  */
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,
		 0x30, 0x23, /* a_ cb */
		 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, /* 100 bytes */
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0, /* here end the 0-255 literals (128 bytes) */
		 0x02, /* 'EOF' symbol 256 (byte 128 low) */
		 0,0,0,0,0, 0,0,0,0,0, 0,                    /* 140 bytes */
	         0,0,0,
		 0x20, /* codepoint 287 (byte 143 high) */
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,         /* 160 bytes */
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, /* 240 bytes */
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,
		 /*
		  * So that's the tree.
		  *
		  * length 2 codes for 'c', EOF, 287
		  * length 3 for 'a', 'b'.
		  *
		  * c:   00
		  * EOF: 01
		  * 287: 10
		  * a:   110
		  * b:   111
		  *
		  * thus the literal string "abc" is 110-111-00.
		  *
		  * Now for the lz77 match definitions for EOF and 287.
		  *
		  * Why 287? It encodes the match distance and offset.
		  *
		  * 287 - 256 = 31
		  *
		  * _length = 31 % 16 = 15
		  * _distance = 31 / 16 = 1
		  *
		  * (it's easier to look at the hex, 0x11f:
		  * 1xx means a match; x1x is _distance; xxf is _length)
		  *
		  * _distance 1 means a two bit distance (10 or 11; 2 or 3).
		  * That means the next bit will be the least significant bit
		  * of distance (1 in this case, meaning distance 3).
		  *
		  * if _length is 15, real length is included inline.
		  *
		  * 'EOF' == 256 means _length = 0, _distance = 0.
		  *
		  * _distance 0 means 1, so no further bits needed.
		  * _length 0 means length 3.
		  *
		  * but when used as EOF, this doesn't matter.
		  */
		 0xa8, 0xdc, 0x00, 0x00, 0xff, 0x26, 0x01
		  /* These remaining bytes are:
		  *
		  * 10101000 11011100 00000000 00000000 11111111
		  * 00100110 00000001
		  *
		  * and we read them as 16 chunks (i.e. flipping odd/even order)
		  *
		  * 110-111-00  10-1-01-000
		  *   a  b   c 287 | EOF
		  *                |
		  *                this is the 287 distance low bit.
		  *
		  * The last 3 bits are not used. The 287 length is sort of
		  * out of band, coming up soon (because 287 encodes length
		  * 15; most codes do not do this).
		  *
		  * 00000000 00000000
		  *
		  * This padding is there because the first 32 bits are read
		  * at the beginning of decoding. If there were more things to
		  * be encoded, they would be in here.
		  *
		  * 11111111
		  *
		  * This byte is pulled as the length for the 287 match.
		  * Because it is 0xff, we pull a further 2 bytes for the
		  * actual length, i.e. a 16 bit number greater than 270.
		  *
		  * 00000001 00100110
		  *
		  * that is 0x126 = 294 = the match length - 3 (because we're
		  * encoding ["abc", <copy from 3 back, 297 chars>, EOF]).
		  *
		  */
		 )
	},
	{.name = "abcdefghijklmnopqrstuvwxyz", /* [MS-XCA] 3.2 example 1. */
	 .decompressed = BLOB_FROM_STRING("abcdefghijklmnopqrstuvwxyz"),
	 .compressed = BLOB_FROM_ARRAY(
		 /*
		  * In this case there are no matches encoded as there are no
		  * repeated symbols. Including the EOF, there are 27 symbols
		  * all occuring exactly as frequently as each other (once).
		  * From that we would expect the codes to be mostly 5 bits
		  * long, because 27 < 2^5 (32), but greater than 2^4. And
		  * that's what we see.
		  */
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,
		 /* 14 non-zero bytes for 26 letters/nibbles */
		 0x50, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
		 0x55, 0x55, 0x55, 0x45, 0x44, 0x04,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,   /* 80 */
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,
		 0x04,                                 /* 0x100 EOF */
		 /* no matches */
		 0,0,0,0,0, 0,0,0,0,0, 0,                    /* 140 */
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, /* 240 */
		 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,

		 0xd8, 0x52, 0x3e, 0xd7, 0x94, 0x11, 0x5b, 0xe9,
		 0x19, 0x5f, 0xf9, 0xd6, 0x7c, 0xdf, 0x8d, 0x04,
		 0x00, 0x00, 0x00, 0x00)
	},
	{0}
};


static void test_lzxpress_huffman_decompress(void **state)
{
	size_t i;
	ssize_t written;
	uint8_t *dest = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	for (i = 0; bidirectional_pairs[i].name != NULL; i++) {
		struct lzx_pair p = bidirectional_pairs[i];
		dest = talloc_array(mem_ctx, uint8_t, p.decompressed.length);

		debug_message("%s compressed %zu decomp %zu\n", p.name,
			      p.compressed.length,
			      p.decompressed.length);

		written = lzxpress_huffman_decompress(p.compressed.data,
						      p.compressed.length,
						      dest,
						      p.decompressed.length);
		assert_int_equal(written, p.decompressed.length);

		assert_memory_equal(dest, p.decompressed.data, p.decompressed.length);
		talloc_free(dest);
	}
}


static DATA_BLOB datablob_from_file(TALLOC_CTX *mem_ctx,
				    const char *filename)
{
	DATA_BLOB b = {0};
	FILE *fh = fopen(filename, "rb");
	int ret;
	struct stat s;
	size_t len;
	if (fh == NULL) {
		debug_message("could not open '%s'\n", filename);
		return b;
	}
	ret = fstat(fileno(fh), &s);
	if (ret != 0) {
		fclose(fh);
		return b;
	}
	b.data = talloc_array(mem_ctx, uint8_t, s.st_size);
	if (b.data == NULL) {
		fclose(fh);
		return b;
	}
	len = fread(b.data, 1, s.st_size, fh);
	if (ferror(fh) || len != s.st_size) {
		TALLOC_FREE(b.data);
	} else {
		b.length = len;
	}
	fclose(fh);
	return b;
}


static void test_lzxpress_huffman_decompress_files(void **state)
{
	size_t i;
	int score = 0;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	for (i = 0; file_names[i] != NULL; i++) {
		char filename[200];
		uint8_t *dest = NULL;
		ssize_t written;
		TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
		struct lzx_pair p = {
			.name = file_names[i]
		};

		debug_message("%s\n", p.name);

		snprintf(filename, sizeof(filename),
			 "%s/%s.decomp", DECOMP_DIR, p.name);

		p.decompressed = datablob_from_file(tmp_ctx, filename);
		assert_non_null(p.decompressed.data);

		snprintf(filename, sizeof(filename),
			 "%s/%s.lzhuff", COMP_DIR, p.name);

		p.compressed = datablob_from_file(tmp_ctx, filename);
		assert_non_null(p.compressed.data);

		dest = talloc_array(tmp_ctx, uint8_t, p.decompressed.length);

		written = lzxpress_huffman_decompress(p.compressed.data,
						      p.compressed.length,
						      dest,
						      p.decompressed.length);
		if (written == p.decompressed.length &&
		    memcmp(dest, p.decompressed.data, p.decompressed.length) == 0) {
			debug_message("\033[1;32mdecompressed %s!\033[0m\n", p.name);
			score++;
		} else {
			debug_message("\033[1;31mfailed to decompress %s!\033[0m\n",
				      p.name);
			debug_message("size %zd vs reference %zu\n",
				      written, p.decompressed.length);
		}
		talloc_free(tmp_ctx);
	}
	debug_message("%d/%zu correct\n", score, i);
	assert_int_equal(score, i);
}


static void test_lzxpress_huffman_decompress_more_compressed_files(void **state)
{
	/*
	 * This tests the decompression of files that have been compressed on
	 * Windows with the level turned up (to 1, default for MS-XCA is 0).
	 *
	 * The format is identical, but it will have tried harder to find
	 * matches.
	 */
	size_t i;
	int score = 0;
	int found = 0;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	for (i = 0; file_names[i] != NULL; i++) {
		char filename[200];
		uint8_t *dest = NULL;
		ssize_t written;
		TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
		struct lzx_pair p = {
			.name = file_names[i]
		};

		debug_message("%s\n", p.name);

		snprintf(filename, sizeof(filename),
			 "%s/%s.decomp", DECOMP_DIR, p.name);

		p.decompressed = datablob_from_file(tmp_ctx, filename);
		assert_non_null(p.decompressed.data);

		snprintf(filename, sizeof(filename),
			 "%s/%s.lzhuff", MORE_COMP_DIR, p.name);

		p.compressed = datablob_from_file(tmp_ctx, filename);
		if (p.compressed.data == NULL) {
			/*
			 * We don't have all the vectors in the
			 * more-compressed directory, which is OK, we skip
			 * them.
			 */
			continue;
		}
		found++;
		dest = talloc_array(tmp_ctx, uint8_t, p.decompressed.length);

		written = lzxpress_huffman_decompress(p.compressed.data,
						      p.compressed.length,
						      dest,
						      p.decompressed.length);
		if (written == p.decompressed.length &&
		    memcmp(dest, p.decompressed.data, p.decompressed.length) == 0) {
			debug_message("\033[1;32mdecompressed %s!\033[0m\n", p.name);
			score++;
		} else {
			debug_message("\033[1;31mfailed to decompress %s!\033[0m\n",
				      p.name);
			debug_message("size %zd vs reference %zu\n",
				      written, p.decompressed.length);
		}
		talloc_free(tmp_ctx);
	}
	debug_message("%d/%d correct\n", score, found);
	assert_int_equal(score, found);
}


static void test_lzxpress_huffman_decompress_empty_or_null(void **state)
{
	/*
	 * We expect these to fail with a -1, except the last one.
	 */
	ssize_t ret;
	const uint8_t *input = bidirectional_pairs[0].compressed.data;
	size_t ilen = bidirectional_pairs[0].compressed.length;
	size_t olen = bidirectional_pairs[0].decompressed.length;
	uint8_t output[olen];

	ret = lzxpress_huffman_decompress(input, 0, output, olen);
	assert_int_equal(ret, -1LL);
	ret = lzxpress_huffman_decompress(input, ilen, output, 0);
	assert_int_equal(ret, -1LL);

	ret = lzxpress_huffman_decompress(NULL, ilen, output, olen);
	assert_int_equal(ret, -1LL);
	ret = lzxpress_huffman_decompress(input, ilen, NULL, olen);
	assert_int_equal(ret, -1LL);

	ret = lzxpress_huffman_decompress(input, ilen, output, olen);
	assert_int_equal(ret, olen);
}


int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_lzxpress_huffman_decompress_files),
		cmocka_unit_test(test_lzxpress_huffman_decompress_more_compressed_files),
		cmocka_unit_test(test_lzxpress_huffman_decompress),
		cmocka_unit_test(test_lzxpress_huffman_decompress_empty_or_null),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}

	return cmocka_run_group_tests(tests, NULL, NULL);
}
