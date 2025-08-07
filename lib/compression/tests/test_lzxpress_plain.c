/*
   Unix SMB/CIFS implementation.
   test suite for the compression functions

   Copyright (C) Jelmer Vernooij 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <cmocka.h>
#include "includes.h"
#include "talloc.h"
#include "lzxpress.h"
#include "lib/util/base64.h"


/* set LZX_DEBUG_FILES to true to save round-trip files in /tmp. */
#define LZX_DEBUG_FILES false

/* set LZX_DEBUG_VERBOSE to true to print more. */
#define LZX_DEBUG_VERBOSE false


#if LZX_DEBUG_VERBOSE
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
#define COMP_DIR "testdata/compression/compressed-plain"
#define MORE_COMP_DIR "testdata/compression/compressed-more-plain"


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
	"generate-windows-test-vectors.c",
	"fib_shuffle-128k+",
	"fuzzing-0fc2d461b56cd8103c91",
	"fuzzing-3ec3bca27bb9eb40c128",
	"fuzzing-a3115a81d1ac500318f9",
	"fuzzing-3591f9dc02bb00a54b60",
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
	"b63289ccc7f218c0d56b",
	"beta-variate1-128k+",
	"beta-variate3-128k+",
	"decayed_alphabet_128k+",
	"decayed_alphabet_64k",
	"f00842317dc6d5695b02",
	"fib_shuffle",
	"midsummer-nights-dream.txt",
	"notes-on-the-underground.txt",
	"pg22009.txt",
	"repeating",
	"repeating-exactly-64k",
	"setup.log",
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
	"trigram_128k+",
	"trigram_64k",
	"trigram_sum_128k+",
	"trigram_sum_64k",
	NULL
};



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



static void test_lzxpress_plain_decompress_files(void **state)
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
			 "%s/%s.lzplain", COMP_DIR, p.name);

		p.compressed = datablob_from_file(tmp_ctx, filename);
		assert_non_null(p.compressed.data);

		dest = talloc_array(tmp_ctx, uint8_t, p.decompressed.length);
		debug_start_timer();
		written = lzxpress_decompress(p.compressed.data,
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
	debug_message("%d/%zu correct\n", score, i);
	assert_int_equal(score, i);
}


static void test_lzxpress_plain_decompress_more_compressed_files(void **state)
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
			 "%s/%s.lzplain", MORE_COMP_DIR, p.name);

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
		written = lzxpress_decompress(p.compressed.data,
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
	debug_message("%d/%d correct\n", score, found);
	assert_int_equal(score, found);
}


/*
 * attempt_round_trip() tests whether a data blob can survive a compression
 * and decompression cycle. If save_name is not NULL and LZX_DEBUG_FILES
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
						original.length * 8 / 7 + 8);
	DATA_BLOB decompressed = data_blob_talloc(tmp_ctx, NULL,
						  original.length);
	ssize_t comp_written, decomp_written;
	debug_start_timer();
	comp_written = lzxpress_compress(original.data,
					 original.length,
					 compressed.data,
					 compressed.length);
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
	decomp_written = lzxpress_decompress(compressed.data,
					     comp_written,
					     decompressed.data,
					     decompressed.length);
	if (decomp_written <= 0) {
		talloc_free(tmp_ctx);
		return -1;
	}

	debug_end_timer("decompress", original.length);
	if (save_name != NULL && LZX_DEBUG_FILES) {
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


static void test_lzxpress_plain_round_trip_files(void **state)
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
			 "%s/%s.lzplain", COMP_DIR, p.name);

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
				 "/tmp/lzxplain-%s", p.name);
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
	 * Assert that the compression is better than Windows. Unlike the
	 * Huffman variant, where things are very even, here we do much better
	 * than Windows without especially trying.
	 */
	assert_true(compressed_total <= reference_total);

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


static void test_lzxpress_plain_long_gpl_round_trip(void **state)
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


static void test_lzxpress_plain_long_random_graph_round_trip(void **state)
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


static void test_lzxpress_plain_chaos_graph_round_trip(void **state)
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


static void test_lzxpress_plain_sparse_random_graph_round_trip(void **state)
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


static void test_lzxpress_plain_random_noise_round_trip(void **state)
{
	size_t i;
	size_t len = 10 * 1024 * 1024;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	DATA_BLOB original = data_blob_talloc(mem_ctx, NULL, len);
	DATA_BLOB ref = {0};
	ssize_t comp_size;
	/*
	 * We are filling this up with incompressible noise, but we can assert
	 * quite tight bounds on how badly it will fail to compress.
	 *
	 * There is one additional bit for each code, which says whether the
	 * code is a literal byte or a match. If *all* codes are literal
	 * bytes, the length should be 9/8 the original (with rounding
	 * issues regarding the indicator bit blocks).
	 *
	 * If some matches are found the length will be a bit less. We would
	 * expect one 3 byte match per 1 << 24 tries, but we try 8192 times
	 * per position. That means there'll a match 1/2048 of the time at
	 * best. 255 times out of 256 this will be exactly a 3 byte match,
	 * encoded as two bytes, so we could get a 1 / 2048 saving on top of
	 * the 1/8 cost. There'll be a smattering of longer matches too, and
	 * the potential for complicated maths to account for those, but we'll
	 * skimp on that by allowing for a 1/1500 saving.
	 *
	 * With the hash table, we take a shortcut in the "8192 tries", and
	 * the size of the table makes a difference in how we perform, with 13
	 * bits (8192 slots) naturally being luckier than 12. Ultimately,
	 * either way, the compressed file is still 12.5% bigger than the
	 * original.
	 */
	size_t limit = len * 9 / 8 + 4;

	uint32_t *d32 = (uint32_t*)((void*)original.data);
	struct jsf_rng rng;
	jsf32_init(&rng, 2);

	for (i = 0; i < (len / 4); i++) {
		d32[i] = jsf32(&rng);
	}

	comp_size = attempt_round_trip(mem_ctx, original, "/tmp/random-noise", ref);
	debug_message("original size %zu; compressed size %zd; ratio %.5f\n",
		      len, comp_size, ((double)comp_size) / len);
	debug_message("expected range %zu - %zu\n",
		      limit - limit / 1500, limit);

	assert_true(comp_size > 0);
	assert_true(comp_size < limit);
	assert_true(comp_size >= limit - limit / 1500);
	talloc_free(mem_ctx);
}


/* Tests based on [MS-XCA] 3.1 Examples */
static void test_msft_data1(void **state)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	const char *fixed_data = "abcdefghijklmnopqrstuvwxyz";
	const uint8_t fixed_out[] = {
		0x3f, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64,
		0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
		0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
		0x75, 0x76, 0x77, 0x78, 0x79, 0x7a };

	ssize_t c_size;
	uint8_t *out, *out2;

	out  = talloc_size(tmp_ctx, 2048);
	memset(out, 0x42, talloc_get_size(out));

	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));
	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, sizeof(fixed_out));
	assert_memory_equal(out, fixed_out, c_size);
	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));
	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, strlen(fixed_data));
	assert_memory_equal(out2, fixed_data, c_size);

	talloc_free(tmp_ctx);
}


static void test_msft_data2(void **state)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	const char *fixed_data =
		"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc"
		"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc"
		"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc"
		"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc"
		"abcabcabcabcabcabcabcabc";
	const uint8_t fixed_out[] = {
		0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17,
		0x00, 0x0f, 0xff, 0x26, 0x01};

	ssize_t c_size;
	uint8_t *out, *out2;

	out  = talloc_size(tmp_ctx, 2048);
	memset(out, 0x42, talloc_get_size(out));

	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));
	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, sizeof(fixed_out));
	assert_memory_equal(out, fixed_out, c_size);

	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, strlen(fixed_data));
	assert_memory_equal(out2, fixed_data, c_size);

	talloc_free(tmp_ctx);
}

/*
  test lzxpress
 */
static void test_lzxpress(void **state)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	const char *fixed_data = "this is a test. and this is a test too";
	const uint8_t fixed_out[] = {
		0xff, 0x21, 0x00, 0x04, 0x74, 0x68, 0x69, 0x73,
		0x20, 0x10, 0x00, 0x61, 0x20, 0x74, 0x65, 0x73,
		0x74, 0x2E, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x9F,
		0x00, 0x04, 0x20, 0x74, 0x6F, 0x6F };

	const uint8_t fixed_out_old_version[] = {
		0x00, 0x20, 0x00, 0x04, 0x74, 0x68, 0x69, 0x73,
		0x20, 0x10, 0x00, 0x61, 0x20, 0x74, 0x65, 0x73,
		0x74, 0x2E, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x9F,
		0x00, 0x04, 0x20, 0x74, 0x6F, 0x6F, 0x00, 0x00,
		0x00, 0x00 };

	ssize_t c_size;
	uint8_t *out, *out2, *out3;

	out  = talloc_size(tmp_ctx, 2048);
	memset(out, 0x42, talloc_get_size(out));

	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, sizeof(fixed_out));
	assert_memory_equal(out, fixed_out, c_size);

	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, strlen(fixed_data));
	assert_memory_equal(out2, fixed_data, c_size);

	out3  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(fixed_out_old_version,
				     sizeof(fixed_out_old_version),
				     out3,
				     talloc_get_size(out3));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, strlen(fixed_data));
	assert_memory_equal(out3, fixed_data, c_size);

	talloc_free(tmp_ctx);
}

static void test_lzxpress2(void **state)
{
	/*
	 * Use two matches, separated by a literal, and each with a length
	 * greater than 10, to test the use of nibble_index. Both length values
	 * (less ten) should be stored as adjacent nibbles to form the 0x21
	 * byte.
	 */

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	const char *fixed_data = "aaaaaaaaaaaabaaaaaaaaaaaa";
	const uint8_t fixed_out[] = {
		0xff, 0xff, 0xff, 0x5f, 0x61, 0x07, 0x00, 0x21,
		0x62, 0x67, 0x00};

	ssize_t c_size;
	uint8_t *out, *out2;

	out  = talloc_size(tmp_ctx, 2048);
	memset(out, 0x42, talloc_get_size(out));

	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, sizeof(fixed_out));
	assert_memory_equal(out, fixed_out, c_size);

	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, strlen(fixed_data));
	assert_memory_equal(out2, fixed_data, c_size);

	talloc_free(tmp_ctx);
}

static void test_lzxpress3(void **state)
{
	/*
	 * Use a series of 31 literals, followed by a single minimum-length
	 * match (and a terminating literal), to test setting indic_pos when the
	 * 32-bit flags value overflows after a match.
	 */

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	const char *fixed_data = "abcdefghijklmnopqrstuvwxyz01234abca";
	const uint8_t fixed_out[] = {
		0x01, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64,
		0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
		0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
		0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31,
		0x32, 0x33, 0x34, 0xf0, 0x00, 0xff, 0xff, 0xff,
		0x7f, 0x61};

	ssize_t c_size;
	uint8_t *out, *out2;

	out  = talloc_size(tmp_ctx, 2048);
	memset(out, 0x42, talloc_get_size(out));

	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, sizeof(fixed_out));
	assert_memory_equal(out, fixed_out, c_size);

	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, strlen(fixed_data));
	assert_memory_equal(out2, fixed_data, c_size);

	talloc_free(tmp_ctx);
}

static void test_lzxpress4(void **state)
{
	/*
	 * Use a series of 31 literals, followed by a single minimum-length
	 * match, to test that the final set of 32-bit flags is written
	 * correctly when it is empty.
	 */

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	const char *fixed_data = "abcdefghijklmnopqrstuvwxyz01234abc";
	const uint8_t fixed_out[] = {
		0x01, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64,
		0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
		0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
		0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31,
		0x32, 0x33, 0x34, 0xf0, 0x00, 0xff, 0xff, 0xff,
		0xff};

	ssize_t c_size;
	uint8_t *out, *out2;

	out  = talloc_size(tmp_ctx, 2048);
	memset(out, 0x42, talloc_get_size(out));

	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, sizeof(fixed_out));
	assert_memory_equal(out, fixed_out, c_size);

	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	assert_int_not_equal(c_size, -1);
	assert_int_equal(c_size, strlen(fixed_data));
	assert_memory_equal(out2, fixed_data, c_size);

	talloc_free(tmp_ctx);
}


static void test_lzxpress_many_zeros(void **state)
{
	/*
	 * Repeated values (zero is convenient but not special) will lead to
	 * very long substring searches in compression, which can be very slow
	 * if we're not careful.
	 *
	 * This test makes a very loose assertion about how long it should
	 * take to compress a million zeros.
	 *
	 * Wall clock time *should* be < 0.1 seconds with the fix and around a
	 * minute without it. We try for CLOCK_THREAD_CPUTIME_ID which should
	 * filter out some noise on the machine, and set the threshold at 5
	 * seconds.
	 */

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	const size_t N_ZEROS = 1000000;
	const uint8_t *zeros = talloc_zero_size(tmp_ctx, N_ZEROS);
	const ssize_t expected_c_size_max = 120;
	const ssize_t expected_c_size_min = 93;
	ssize_t c_size;
	uint8_t *comp, *decomp;
	static struct timespec t_start, t_end;
	uint64_t elapsed_ns;

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t_start) != 0) {
		if (clock_gettime(CUSTOM_CLOCK_MONOTONIC, &t_start) != 0) {
			clock_gettime(CLOCK_REALTIME, &t_start);
		}
	}

	comp = talloc_zero_size(tmp_ctx, 2048);

	c_size = lzxpress_compress(zeros,
				   N_ZEROS,
				   comp,
				   talloc_get_size(comp));
	/*
	 * Because our compression depends on heuristics, we don't insist on
	 * an exact size in this case.
	 */

	assert_true(c_size <= expected_c_size_max);
	assert_true(c_size >= expected_c_size_min);

	decomp = talloc_size(tmp_ctx, N_ZEROS * 2);
	c_size = lzxpress_decompress(comp,
				     c_size,
				     decomp,
				     N_ZEROS * 2);

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t_end) != 0) {
		if (clock_gettime(CUSTOM_CLOCK_MONOTONIC, &t_end) != 0) {
			clock_gettime(CLOCK_REALTIME, &t_end);
		}
	}
	elapsed_ns = (
		(t_end.tv_sec - t_start.tv_sec) * 1000U * 1000U * 1000U) +
		(t_end.tv_nsec - t_start.tv_nsec);
	print_message("round-trip time: %"PRIu64" ns\n", elapsed_ns);
	assert_true(elapsed_ns < 3 * 1000U * 1000U * 1000U);
	assert_memory_equal(decomp, zeros, N_ZEROS);

	talloc_free(tmp_ctx);
}


static void test_lzxpress_round_trip(void **state)
{
	/*
	 * Examples found using via fuzzing.
	 */
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	size_t i;
	struct b64_pair {
		const char *uncompressed;
		const char *compressed;
	} pairs[] = {
		{   /* this results in a trailing flags block */
			"AAICAmq/EKdP785YU2Ddh7d4vUtdlQyLeHV09LHpUBw=",
			"AAAAAAACAgJqvxCnT+/OWFNg3Ye3eL1LXZUMi3h1dPSx6VAc/////w==",
		},
		{    /* empty string compresses to empty string */
			"",  ""
		},
	};
	const size_t alloc_size = 1000;
	uint8_t *data = talloc_array(tmp_ctx, uint8_t, alloc_size);

	for (i = 0; i < ARRAY_SIZE(pairs); i++) {
		ssize_t len;
		DATA_BLOB uncomp = base64_decode_data_blob_talloc(
			tmp_ctx,
			pairs[i].uncompressed);
		DATA_BLOB comp = base64_decode_data_blob_talloc(
			tmp_ctx,
			pairs[i].compressed);

		len = lzxpress_compress(uncomp.data,
					uncomp.length,
					data,
					alloc_size);

		assert_int_not_equal(len, -1);
		assert_int_equal(len, comp.length);

		assert_memory_equal(comp.data, data, len);

		len = lzxpress_decompress(comp.data,
					  comp.length,
					  data,
					  alloc_size);

		assert_int_not_equal(len, -1);
		assert_int_equal(len, uncomp.length);

		assert_memory_equal(uncomp.data, data, len);
	}
	talloc_free(tmp_ctx);
}


int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_lzxpress_plain_decompress_files),
		cmocka_unit_test(test_lzxpress_plain_decompress_more_compressed_files),
		cmocka_unit_test(test_lzxpress_plain_round_trip_files),
		cmocka_unit_test(test_lzxpress_plain_long_gpl_round_trip),
		cmocka_unit_test(test_lzxpress_plain_long_random_graph_round_trip),
		cmocka_unit_test(test_lzxpress_plain_chaos_graph_round_trip),
		cmocka_unit_test(test_lzxpress_plain_sparse_random_graph_round_trip),
		cmocka_unit_test(test_lzxpress_plain_long_random_graph_round_trip),
		cmocka_unit_test(test_lzxpress_plain_random_noise_round_trip),
		cmocka_unit_test(test_lzxpress),
		cmocka_unit_test(test_msft_data1),
		cmocka_unit_test(test_msft_data2),
		cmocka_unit_test(test_lzxpress2),
		cmocka_unit_test(test_lzxpress3),
		cmocka_unit_test(test_lzxpress4),
		cmocka_unit_test(test_lzxpress_many_zeros),
		cmocka_unit_test(test_lzxpress_round_trip),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}
