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
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <sys/stat.h>
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

#include <time.h>

struct timespec start = {0};
struct timespec end = {0};
static void debug_start_timer(void)
{
	clock_gettime(CLOCK_MONOTONIC, &start);
}

static void debug_end_timer(const char *name, size_t len)
{
	uint64_t ns;
	double secs;
	double rate;
	clock_gettime(CLOCK_MONOTONIC, &end);
	ns = end.tv_nsec;
	ns += end.tv_sec * 1000 * 1000 * 1000;
	ns -= start.tv_nsec;
	ns -= start.tv_sec * 1000 * 1000 * 1000;
	secs = ns / 1e9;
	rate = len / (secs * 1024 * 1024);
	debug_message("%s %zu bytes in %.2g: \033[1;35m%.2f\033[0m MB per second\n",
		      name, len, secs, rate);
}

#else
#define debug_message(...) /* debug_message */
#define debug_start_timer(...) /* debug_start_timer */
#define debug_end_timer(...) /* debug_end_timer */
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


#define DECOMP_DIR "testdata/compression/decompressed"
#define COMP_DIR "testdata/compression/compressed-huffman"
#define MORE_COMP_DIR "testdata/compression/compressed-more-huffman"


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
		  * all occurring exactly as frequently as each other (once).
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
		assert_int_not_equal(written, -1);
		assert_int_equal(written, p.decompressed.length);

		assert_memory_equal(dest, p.decompressed.data, p.decompressed.length);
		talloc_free(dest);
	}
}

static void test_lzxpress_huffman_compress(void **state)
{
	size_t i;
	ssize_t written;
	uint8_t *dest = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	for (i = 0; bidirectional_pairs[i].name != NULL; i++) {
		struct lzx_pair p = bidirectional_pairs[i];
		debug_message("%s compressed %zu decomp %zu\n", p.name,
			      p.compressed.length,
			      p.decompressed.length);

		written = lzxpress_huffman_compress_talloc(mem_ctx,
							   p.decompressed.data,
							   p.decompressed.length,
							   &dest);

		assert_int_not_equal(written, -1);
		assert_int_equal(written, p.compressed.length);
		assert_memory_equal(dest, p.compressed.data, p.compressed.length);
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
		debug_start_timer();
		written = lzxpress_huffman_decompress(p.compressed.data,
						      p.compressed.length,
						      dest,
						      p.decompressed.length);
		debug_end_timer("decompress", p.decompressed.length);
		if (written != -1 &&
		    written == p.decompressed.length &&
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
		debug_start_timer();
		written = lzxpress_huffman_decompress(p.compressed.data,
						      p.compressed.length,
						      dest,
						      p.decompressed.length);
		debug_end_timer("decompress", p.decompressed.length);
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


/*
 * attempt_round_trip() tests whether a data blob can survive a compression
 * and decompression cycle. If save_name is not NULL and LZXHUFF_DEBUG_FILES
 * evals to true, the various stages are saved in files with that name and the
 * '-original', '-compressed', and '-decompressed' suffixes. If ref_compressed
 * has data, it'll print a message saying whether the compressed data matches
 * that.
 */

static ssize_t attempt_round_trip(TALLOC_CTX *mem_ctx,
				  DATA_BLOB original,
				  const char *save_name,
				  DATA_BLOB ref_compressed)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	DATA_BLOB compressed = data_blob_talloc(tmp_ctx, NULL,
						original.length * 4 / 3 + 260);
	DATA_BLOB decompressed = data_blob_talloc(tmp_ctx, NULL,
						original.length);
	ssize_t comp_written, decomp_written;
	debug_start_timer();
	comp_written = lzxpress_huffman_compress_talloc(tmp_ctx,
							original.data,
							original.length,
							&compressed.data);
	debug_end_timer("compress", original.length);
	if (comp_written <= 0) {
		talloc_free(tmp_ctx);
		return -1;
	}

	if (ref_compressed.data != NULL) {
		/*
		 * This is informational, not an assertion; there are
		 * ~infinite legitimate ways to compress the data, many as
		 * good as each other (think of compression as a language, not
		 * a format).
		 */
		debug_message("compressed size %zd vs reference %zu\n",
			      comp_written, ref_compressed.length);

		if (comp_written == compressed.length &&
		    memcmp(compressed.data, ref_compressed.data, comp_written) == 0) {
			debug_message("\033[1;32mbyte identical!\033[0m\n");
		}
	}
	debug_start_timer();
	decomp_written = lzxpress_huffman_decompress(compressed.data,
						     comp_written,
						     decompressed.data,
						     original.length);
	debug_end_timer("decompress", original.length);
	if (save_name != NULL && LZXHUFF_DEBUG_FILES) {
		char s[300];
		FILE *fh = NULL;

		snprintf(s, sizeof(s), "%s-original", save_name);
		fprintf(stderr, "Saving %zu bytes to %s\n", original.length, s);
		fh = fopen(s, "w");
		fwrite(original.data, 1, original.length, fh);
		fclose(fh);

		snprintf(s, sizeof(s), "%s-compressed", save_name);
		fprintf(stderr, "Saving %zu bytes to %s\n", comp_written, s);
		fh = fopen(s, "w");
		fwrite(compressed.data, 1, comp_written, fh);
		fclose(fh);
		/*
		 * We save the decompressed file using original.length, not
		 * the returned size. If these differ, the returned size will
		 * be -1. By saving the whole buffer we can see at what point
		 * it went haywire.
		 */
		snprintf(s, sizeof(s), "%s-decompressed", save_name);
		fprintf(stderr, "Saving %zu bytes to %s\n", original.length, s);
		fh = fopen(s, "w");
		fwrite(decompressed.data, 1, original.length, fh);
		fclose(fh);
	}

	if (original.length != decomp_written ||
	    memcmp(decompressed.data,
		   original.data,
		   original.length) != 0) {
		debug_message("\033[1;31mgot %zd, expected %zu\033[0m\n",
			      decomp_written,
			      original.length);
		talloc_free(tmp_ctx);
		return -1;
	}
	talloc_free(tmp_ctx);
	return comp_written;
}


static void test_lzxpress_huffman_round_trip(void **state)
{
	size_t i;
	int score = 0;
	ssize_t compressed_total = 0;
	ssize_t reference_total = 0;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	for (i = 0; file_names[i] != NULL; i++) {
		char filename[200];
		char *debug_files = NULL;
		TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
		ssize_t comp_size;
		struct lzx_pair p = {
			.name = file_names[i]
		};
		debug_message("-------------------\n");
		debug_message("%s\n", p.name);

		snprintf(filename, sizeof(filename),
			 "%s/%s.decomp", DECOMP_DIR, p.name);

		p.decompressed = datablob_from_file(tmp_ctx, filename);
		assert_non_null(p.decompressed.data);

		snprintf(filename, sizeof(filename),
			 "%s/%s.lzhuff", COMP_DIR, p.name);

		p.compressed = datablob_from_file(tmp_ctx, filename);
		if (p.compressed.data == NULL) {
			debug_message(
				"Could not load %s reference file %s\n",
				p.name, filename);
			debug_message("%s decompressed %zu\n", p.name,
				      p.decompressed.length);
		} else {
			debug_message("%s: reference compressed %zu decomp %zu\n",
				      p.name,
				      p.compressed.length,
				      p.decompressed.length);
		}
		if (1) {
			/*
			 * We're going to save copies in /tmp.
			 */
			snprintf(filename, sizeof(filename),
				 "/tmp/lzxhuffman-%s", p.name);
			debug_files = filename;
		}

		comp_size = attempt_round_trip(mem_ctx, p.decompressed,
					       debug_files,
					       p.compressed);
		if (comp_size > 0) {
			debug_message("\033[1;32mround trip!\033[0m\n");
			score++;
			if (p.compressed.length) {
				compressed_total += comp_size;
				reference_total += p.compressed.length;
			}
		}
		talloc_free(tmp_ctx);
	}
	debug_message("%d/%zu correct\n", score, i);
	print_message("\033[1;34mtotal compressed size: %zu\033[0m\n",
		      compressed_total);
	print_message("total reference size:  %zd \n", reference_total);
	print_message("diff:                  %7zd \n",
		      reference_total - compressed_total);
	assert_true(reference_total != 0);
	print_message("ratio: \033[1;3%dm%.2f\033[0m \n",
		      2 + (compressed_total >= reference_total),
		      ((double)compressed_total) / reference_total);
	/*
	 * Assert that the compression is *about* as good as Windows. Of course
	 * it doesn't matter if we do better, but mysteriously getting better
	 * is usually a sign that something is wrong.
	 *
	 * At the time of writing, compressed_total is 2674004, or 10686 more
	 * than the Windows reference total. That's < 0.5% difference, we're
	 * asserting at 2%.
	 */
	assert_true(labs(compressed_total - reference_total) <
		    compressed_total / 50);

	assert_int_equal(score, i);
	talloc_free(mem_ctx);
}

/*
 * Bob Jenkins' Small Fast RNG.
 *
 * We don't need it to be this good, but we do need it to be reproduceable
 * across platforms, which rand() etc aren't.
 *
 * http://burtleburtle.net/bob/rand/smallprng.html
 */

struct jsf_rng {
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
};

#define ROTATE32(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

static uint32_t jsf32(struct jsf_rng *x) {
	uint32_t e = x->a - ROTATE32(x->b, 27);
	x->a = x->b ^ ROTATE32(x->c, 17);
	x->b = x->c + x->d;
	x->c = x->d + e;
	x->d = e + x->a;
	return x->d;
}

static void jsf32_init(struct jsf_rng *x, uint32_t seed) {
	size_t i;
	x->a = 0xf1ea5eed;
	x->b = x->c = x->d = seed;
	for (i = 0; i < 20; ++i) {
		jsf32(x);
	}
}


static void test_lzxpress_huffman_long_gpl_round_trip(void **state)
{
	/*
	 * We use a kind of model-free Markov model to generate a massively
	 * extended pastiche of the GPLv3 (chosen because it is right there in
	 * "COPYING" and won't change often).
	 *
	 * The point is to check a round trip of a very long message with
	 * multiple repetitions on many scales, without having to add a very
	 * large file.
	 */
	size_t i, j, k;
	uint8_t c;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB gpl = datablob_from_file(mem_ctx, "COPYING");
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, 5 * 1024 * 1024);
	DATA_BLOB ref = {0};
	ssize_t comp_size;
	struct jsf_rng rng;

	if (gpl.data == NULL) {
		print_message("could not read COPYING\n");
		fail();
	}

	jsf32_init(&rng, 1);

	j = 1;
	original.data[0] = gpl.data[0];
	for (i = 1; i < original.length; i++) {
		size_t m;
		char p = original.data[i - 1];
		c = gpl.data[j];
		original.data[i] = c;
		j++;
		m = (j + jsf32(&rng)) % (gpl.length - 50);
		for (k = m; k < m + 30; k++) {
			if (p == gpl.data[k] &&
			    c == gpl.data[k + 1]) {
				j = k + 2;
				break;
			}
		}
		if (j == gpl.length) {
			j = 1;
		}
	}

	comp_size = attempt_round_trip(mem_ctx, original, "/tmp/gpl", ref);
	assert_true(comp_size > 0);
	assert_true(comp_size < original.length);

	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_long_random_graph_round_trip(void **state)
{
	size_t i;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, 5 * 1024 * 1024);
	DATA_BLOB ref = {0};
	/*
	 * There's a random trigram graph, with each pair of sequential bytes
	 * pointing to a successor. This would probably fall into a fairly
	 * simple loop, but we introduce damage into the system, randomly
	 * flipping about 1 bit in 64.
	 *
	 * The result is semi-structured and compressible.
	 */
	uint8_t *d = original.data;
	uint8_t *table = talloc_array(mem_ctx, uint8_t, 65536);
	uint32_t *table32 = (void*)table;
	ssize_t comp_size;
	struct jsf_rng rng;

	jsf32_init(&rng, 1);
	for (i = 0; i < (65536 / 4); i++) {
		table32[i] = jsf32(&rng);
	}

	d[0] = 'a';
	d[1] = 'b';

	for (i = 2; i < original.length; i++) {
		uint16_t k = (d[i - 2] << 8) | d[i - 1];
		uint32_t damage = jsf32(&rng) & jsf32(&rng) & jsf32(&rng);
		damage &= (damage >> 16);
		k ^= damage & 0xffff;
		d[i] = table[k];
	}

	comp_size = attempt_round_trip(mem_ctx, original, "/tmp/random-graph", ref);
	assert_true(comp_size > 0);
	assert_true(comp_size < original.length);

	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_chaos_graph_round_trip(void **state)
{
	size_t i;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, 5 * 1024 * 1024);
	DATA_BLOB ref = {0};
	/*
	 * There's a random trigram graph, with each pair of sequential bytes
	 * pointing to a successor. This would probably fall into a fairly
	 * simple loop, but we keep changing the graph. The result is long
	 * periods of stability separatd by bursts of noise.
	 */
	uint8_t *d = original.data;
	uint8_t *table = talloc_array(mem_ctx, uint8_t, 65536);
	uint32_t *table32 = (void*)table;
	ssize_t comp_size;
	struct jsf_rng rng;

	jsf32_init(&rng, 1);
	for (i = 0; i < (65536 / 4); i++) {
		table32[i] = jsf32(&rng);
	}

	d[0] = 'a';
	d[1] = 'b';

	for (i = 2; i < original.length; i++) {
		uint16_t k = (d[i - 2] << 8) | d[i - 1];
		uint32_t damage = jsf32(&rng);
		d[i] = table[k];
		if ((damage >> 29) == 0) {
			uint16_t index = damage & 0xffff;
			uint8_t value = (damage >> 16) & 0xff;
			table[index] = value;
		}
	}

	comp_size = attempt_round_trip(mem_ctx, original, "/tmp/chaos-graph", ref);
	assert_true(comp_size > 0);
	assert_true(comp_size < original.length);

	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_sparse_random_graph_round_trip(void **state)
{
	size_t i;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, 5 * 1024 * 1024);
	DATA_BLOB ref = {0};
	/*
	 * There's a random trigram graph, with each pair of sequential bytes
	 * pointing to a successor. This will fall into a fairly simple loops,
	 * but we introduce damage into the system, randomly mangling about 1
	 * byte in 65536.
	 *
	 * The result has very long repetitive runs, which should lead to
	 * oversized blocks.
	 */
	uint8_t *d = original.data;
	uint8_t *table = talloc_array(mem_ctx, uint8_t, 65536);
	uint32_t *table32 = (void*)table;
	ssize_t comp_size;
	struct jsf_rng rng;

	jsf32_init(&rng, 3);
	for (i = 0; i < (65536 / 4); i++) {
		table32[i] = jsf32(&rng);
	}

	d[0] = 'a';
	d[1] = 'b';

	for (i = 2; i < original.length; i++) {
		uint16_t k = (d[i - 2] << 8) | d[i - 1];
		uint32_t damage = jsf32(&rng);
		if ((damage & 0xffff0000) == 0) {
			k ^= damage & 0xffff;
		}
		d[i] = table[k];
	}

	comp_size = attempt_round_trip(mem_ctx, original, "/tmp/sparse-random-graph", ref);
	assert_true(comp_size > 0);
	assert_true(comp_size < original.length);

	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_random_noise_round_trip(void **state)
{
	size_t i;
	size_t len = 1024 * 1024;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, len);
	DATA_BLOB ref = {0};
	ssize_t comp_size;
	/*
	 * We are filling this up with incompressible noise, but we can assert
	 * quite tight bounds on how badly it will fail to compress.
	 *
	 * Specifically, with randomly distributed codes, the Huffman table
	 * should come out as roughly even, averaging 8 bit codes. Then there
	 * will be a 256 byte table every 64k, which is a 1/256 overhead (i.e.
	 * the compressed length will be 257/256 the original *on average*).
	 * We assert it is less than 1 in 200 but more than 1 in 300.
	 */
	uint32_t *d32 = (uint32_t*)((void*)original.data);
	struct jsf_rng rng;
	jsf32_init(&rng, 2);

	for (i = 0; i < (len / 4); i++) {
		d32[i] = jsf32(&rng);
	}

	comp_size = attempt_round_trip(mem_ctx, original, "/tmp/random-noise", ref);
	assert_true(comp_size > 0);
	assert_true(comp_size > original.length + original.length / 300);
	assert_true(comp_size < original.length + original.length / 200);
	debug_message("original size %zu; compressed size %zd; ratio %.3f\n",
		      len, comp_size, ((double)comp_size) / len);

	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_overlong_matches(void **state)
{
	size_t i, j = 0;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, 1024 * 1024);
	DATA_BLOB ref = {0};
	uint8_t *d = original.data;
	char filename[300];
	/*
	 * We are testing with something like "aaaaaaaaaaaaaaaaaaaaaaabbbbb"
	 * where typically the number of "a"s is > 65536, and the number of
	 * "b"s is < 42.
	 */
	ssize_t na[] = {65535, 65536, 65537, 65559, 65575, 200000, -1};
	ssize_t nb[] = {1, 2, 20, 39, 40, 41, 42, -1};
	int score = 0;
	ssize_t comp_size;

	for (i = 0; na[i] >= 0; i++) {
		ssize_t a = na[i];
		memset(d, 'a', a);
		for (j = 0; nb[j] >= 0; j++) {
			ssize_t b = nb[j];
			memset(d + a, 'b', b);
			original.length = a + b;
			snprintf(filename, sizeof(filename),
				 "/tmp/overlong-%zd-%zd", a, b);
			comp_size = attempt_round_trip(mem_ctx,
						       original,
						       filename, ref);
			if (comp_size > 0) {
				score++;
			}
		}
	}
	debug_message("%d/%zu correct\n", score, i * j);
	assert_int_equal(score, i * j);
	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_overlong_matches_abc(void **state)
{
	size_t i, j = 0, k = 0;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, 1024 * 1024);
	DATA_BLOB ref = {0};
	uint8_t *d = original.data;
	char filename[300];
	/*
	 * We are testing with something like "aaaabbbbcc" where typically
	 * the number of "a"s + "b"s is around 65536, and the number of "c"s
	 * is < 43.
	 */
	ssize_t nab[] = {1, 21, 32767, 32768, 32769, -1};
	ssize_t nc[] = {1, 2, 20, 39, 40, 41, 42, -1};
	int score = 0;
	ssize_t comp_size;

	for (i = 0; nab[i] >= 0; i++) {
		ssize_t a = nab[i];
		memset(d, 'a', a);
		for (j = 0; nab[j] >= 0; j++) {
			ssize_t b = nab[j];
			memset(d + a, 'b', b);
			for (k = 0; nc[k] >= 0; k++) {
				ssize_t c = nc[k];
				memset(d + a + b, 'c', c);
				original.length = a + b + c;
				snprintf(filename, sizeof(filename),
					 "/tmp/overlong-abc-%zd-%zd-%zd",
					 a, b, c);
				comp_size = attempt_round_trip(mem_ctx,
							       original,
							       filename, ref);
				if (comp_size > 0) {
					score++;
				}
			}
		}
	}
	debug_message("%d/%zu correct\n", score, i * j * k);
	assert_int_equal(score, i * j * k);
	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_extremely_compressible_middle(void **state)
{
	size_t len = 192 * 1024;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, len);
	DATA_BLOB ref = {0};
	ssize_t comp_size;
	/*
	 * When a middle block (i.e. not the first and not the last of >= 3),
	 * can be entirely expressed as a match starting in the previous
	 * block, the Huffman tree would end up with 1 element, which does not
	 * work for the code construction. It really wants to use both bits.
	 * So we need to ensure we have some way of dealing with this.
	 */
	memset(original.data, 'a', 0x10000 - 1);
	memset(original.data + 0x10000 - 1, 'b', 0x10000 + 1);
	memset(original.data + 0x20000, 'a', 0x10000);
	comp_size = attempt_round_trip(mem_ctx, original, "/tmp/compressible-middle", ref);
	assert_true(comp_size > 0);
	assert_true(comp_size < 1024);
	debug_message("original size %zu; compressed size %zd; ratio %.3f\n",
		      len, comp_size, ((double)comp_size) / len);

	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_max_length_limit(void **state)
{
	size_t len = 65 * 1024 * 1024;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc_zero(mem_ctx, len);
	DATA_BLOB ref = {0};
	ssize_t comp_size;
	/*
	 * Reputedly Windows has a 64MB limit in the maximum match length it
	 * will encode. We follow this, and test that here with nearly 65 MB
	 * of zeros between two letters; this should be encoded in three
	 * blocks:
	 *
	 * 1. 'a', 64M × '\0'
	 * 2. (1M - 2) × '\0' -- finishing off what would have been the same match
	 * 3. 'b' EOF
	 *
	 * Which we can assert by saying the length is > 768, < 1024.
	 */
	original.data[0] = 'a';
	original.data[len - 1] = 'b';
	comp_size = attempt_round_trip(mem_ctx, original, "/tmp/max-length-limit", ref);
	assert_true(comp_size > 0x300);
	assert_true(comp_size < 0x400);
	debug_message("original size %zu; compressed size %zd; ratio %.3f\n",
		      len, comp_size, ((double)comp_size) / len);

	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_short_boring_strings(void **state)
{
	size_t len = 64 * 1024;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, len);
	DATA_BLOB ref = {0};
	ssize_t comp_size;
	ssize_t lengths[] = {
		1, 2, 20, 39, 40, 41, 42, 256, 270, 273, 274, 1000, 64000, -1};
	char filename[300];
	size_t i;
	/*
	 * How do short repetitive strings work? We're poking at the limit
	 * around which LZ77 compression is turned on.
	 *
	 * For this test we don't change the blob memory between runs, just
	 * the declared length.
	 */
	memset(original.data, 'a', len);
	for (i = 0; lengths[i] >= 0; i++) {
		original.length = lengths[i];
		snprintf(filename, sizeof(filename),
			 "/tmp/short-boring-%zu",
			 original.length);
		comp_size = attempt_round_trip(mem_ctx, original, filename, ref);
		if (original.length < 41) {
			assert_true(comp_size > 256 + original.length / 8);
		} else if (original.length < 274) {
			assert_true(comp_size == 261);
		} else {
			assert_true(comp_size == 263);
		}
		assert_true(comp_size < 261 + original.length / 8);
	}
	/* let's just show we didn't change the original */
	for (i = 0; i < len; i++) {
		if (original.data[i] != 'a') {
			fail_msg("input data[%zu] was changed! (%2x, expected %2x)\n",
				 i, original.data[i], 'a');
		}
	}

	talloc_free(mem_ctx);
}


static void test_lzxpress_huffman_compress_empty_or_null(void **state)
{
	/*
	 * We expect these to fail with a -1, except the last one, which does
	 * the real thing.
	 */
	ssize_t ret;
	const uint8_t *input = bidirectional_pairs[0].decompressed.data;
	size_t ilen = bidirectional_pairs[0].decompressed.length;
	size_t olen = bidirectional_pairs[0].compressed.length;
	uint8_t output[olen];
	struct lzxhuff_compressor_mem cmp_mem;

	ret = lzxpress_huffman_compress(&cmp_mem, input, 0, output, olen);
	assert_int_equal(ret, -1LL);
	ret = lzxpress_huffman_compress(&cmp_mem, input, ilen, output, 0);
	assert_int_equal(ret, -1LL);

	ret = lzxpress_huffman_compress(&cmp_mem, NULL, ilen, output, olen);
	assert_int_equal(ret, -1LL);
	ret = lzxpress_huffman_compress(&cmp_mem, input, ilen, NULL, olen);
	assert_int_equal(ret, -1LL);
	ret = lzxpress_huffman_compress(NULL, input, ilen, output, olen);
	assert_int_equal(ret, -1LL);

	ret = lzxpress_huffman_compress(&cmp_mem, input, ilen, output, olen);
	assert_int_equal(ret, olen);
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
		cmocka_unit_test(test_lzxpress_huffman_short_boring_strings),
		cmocka_unit_test(test_lzxpress_huffman_max_length_limit),
		cmocka_unit_test(test_lzxpress_huffman_extremely_compressible_middle),
		cmocka_unit_test(test_lzxpress_huffman_long_random_graph_round_trip),
		cmocka_unit_test(test_lzxpress_huffman_chaos_graph_round_trip),
		cmocka_unit_test(test_lzxpress_huffman_sparse_random_graph_round_trip),
		cmocka_unit_test(test_lzxpress_huffman_round_trip),
		cmocka_unit_test(test_lzxpress_huffman_decompress_files),
		cmocka_unit_test(test_lzxpress_huffman_decompress_more_compressed_files),
		cmocka_unit_test(test_lzxpress_huffman_compress),
		cmocka_unit_test(test_lzxpress_huffman_decompress),
		cmocka_unit_test(test_lzxpress_huffman_long_gpl_round_trip),
		cmocka_unit_test(test_lzxpress_huffman_long_random_graph_round_trip),
		cmocka_unit_test(test_lzxpress_huffman_random_noise_round_trip),
		cmocka_unit_test(test_lzxpress_huffman_overlong_matches_abc),
		cmocka_unit_test(test_lzxpress_huffman_overlong_matches),
		cmocka_unit_test(test_lzxpress_huffman_decompress_empty_or_null),
		cmocka_unit_test(test_lzxpress_huffman_compress_empty_or_null),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}

	return cmocka_run_group_tests(tests, NULL, NULL);
}
