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

#include "includes.h"
#include "torture/torture.h"
#include "torture/local/proto.h"
#include "talloc.h"
#include "lzxpress.h"
#include "lib/util/base64.h"

/* Tests based on [MS-XCA] 3.1 Examples */
static bool test_msft_data1(
	struct torture_context *test
)
{
	TALLOC_CTX *tmp_ctx = talloc_new(test);

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

	torture_comment(test, "lzxpress fixed compression\n");
	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	torture_assert_int_equal(test, c_size, sizeof(fixed_out),
				 "fixed lzxpress_compress size");
	torture_assert_mem_equal(test, out, fixed_out, c_size,
				 "fixed lzxpress_compress data");

	torture_comment(test, "lzxpress fixed decompression\n");
	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	torture_assert_int_equal(test, c_size, strlen(fixed_data),
				 "fixed lzxpress_decompress size");
	torture_assert_mem_equal(test, out2, fixed_data, c_size,
				 "fixed lzxpress_decompress data");

	talloc_free(tmp_ctx);
	return true;
}


static bool test_msft_data2(
	struct torture_context *test
)
{
	TALLOC_CTX *tmp_ctx = talloc_new(test);

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

	torture_comment(test, "lzxpress fixed compression\n");
	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	torture_assert_int_equal(test, c_size, sizeof(fixed_out),
				 "fixed lzxpress_compress size");
	torture_assert_mem_equal(test, out, fixed_out, c_size,
				 "fixed lzxpress_compress data");

	torture_comment(test, "lzxpress fixed decompression\n");
	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	torture_comment(test, "out2: %.*s\n", (int)c_size, (char *)out2);

	torture_assert_int_equal(test, c_size, strlen(fixed_data),
				 "fixed lzxpress_decompress size");
	torture_assert_mem_equal(test, out2, fixed_data, c_size,
				 "fixed lzxpress_decompress data");

	talloc_free(tmp_ctx);
	return true;
}

/*
  test lzxpress
 */
static bool test_lzxpress(struct torture_context *test)
{
	TALLOC_CTX *tmp_ctx = talloc_new(test);
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

	torture_comment(test, "lzxpress fixed compression\n");
	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	torture_assert_int_equal(test, c_size, sizeof(fixed_out),
				 "fixed lzxpress_compress size");
	torture_assert_mem_equal(test, out, fixed_out, c_size,
				 "fixed lzxpress_compress data");

	torture_comment(test, "lzxpress fixed decompression\n");
	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	torture_assert_int_equal(test, c_size, strlen(fixed_data),
				 "fixed lzxpress_decompress size");
	torture_assert_mem_equal(test, out2, fixed_data, c_size,
				 "fixed lzxpress_decompress data");


	torture_comment(test, "lzxpress fixed decompression (old data)\n");
	out3  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(fixed_out_old_version,
				     sizeof(fixed_out_old_version),
				     out3,
				     talloc_get_size(out3));

	torture_assert_int_equal(test, c_size, strlen(fixed_data),
				 "fixed lzxpress_decompress size");
	torture_assert_mem_equal(test, out3, fixed_data, c_size,
				 "fixed lzxpress_decompress data");

	talloc_free(tmp_ctx);
	return true;
}

static bool test_lzxpress2(struct torture_context *test)
{
	/*
	 * Use two matches, separated by a literal, and each with a length
	 * greater than 10, to test the use of nibble_index. Both length values
	 * (less ten) should be stored as adjacent nibbles to form the 0x21
	 * byte.
	 */

	TALLOC_CTX *tmp_ctx = talloc_new(test);
	const char *fixed_data = "aaaaaaaaaaaabaaaaaaaaaaaa";
	const uint8_t fixed_out[] = {
		0xff, 0xff, 0xff, 0x5f, 0x61, 0x07, 0x00, 0x21,
		0x62, 0x67, 0x00};

	ssize_t c_size;
	uint8_t *out, *out2;

	out  = talloc_size(tmp_ctx, 2048);
	memset(out, 0x42, talloc_get_size(out));

	torture_comment(test, "lzxpress fixed compression\n");
	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	torture_assert_int_equal(test, c_size, sizeof(fixed_out),
				 "fixed lzxpress_compress size");
	torture_assert_mem_equal(test, out, fixed_out, c_size,
				 "fixed lzxpress_compress data");

	torture_comment(test, "lzxpress fixed decompression\n");
	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	torture_assert_int_equal(test, c_size, strlen(fixed_data),
				 "fixed lzxpress_decompress size");
	torture_assert_mem_equal(test, out2, fixed_data, c_size,
				 "fixed lzxpress_decompress data");

	talloc_free(tmp_ctx);
	return true;
}

static bool test_lzxpress3(struct torture_context *test)
{
	/*
	 * Use a series of 31 literals, followed by a single minimum-length
	 * match (and a terminating literal), to test setting indic_pos when the
	 * 32-bit flags value overflows after a match.
	 */

	TALLOC_CTX *tmp_ctx = talloc_new(test);
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

	torture_comment(test, "lzxpress fixed compression\n");
	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	torture_assert_int_equal(test, c_size, sizeof(fixed_out),
				 "fixed lzxpress_compress size");
	torture_assert_mem_equal(test, out, fixed_out, c_size,
				 "fixed lzxpress_compress data");

	torture_comment(test, "lzxpress fixed decompression\n");
	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	torture_assert_int_equal(test, c_size, strlen(fixed_data),
				 "fixed lzxpress_decompress size");
	torture_assert_mem_equal(test, out2, fixed_data, c_size,
				 "fixed lzxpress_decompress data");

	talloc_free(tmp_ctx);
	return true;
}

static bool test_lzxpress4(struct torture_context *test)
{
	/*
	 * Use a series of 31 literals, followed by a single minimum-length
	 * match, to test that the final set of 32-bit flags is written
	 * correctly when it is empty.
	 */

	TALLOC_CTX *tmp_ctx = talloc_new(test);
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

	torture_comment(test, "lzxpress fixed compression\n");
	c_size = lzxpress_compress((const uint8_t *)fixed_data,
				   strlen(fixed_data),
				   out,
				   talloc_get_size(out));

	torture_assert_int_equal(test, c_size, sizeof(fixed_out),
				 "fixed lzxpress_compress size");
	torture_assert_mem_equal(test, out, fixed_out, c_size,
				 "fixed lzxpress_compress data");

	torture_comment(test, "lzxpress fixed decompression\n");
	out2  = talloc_size(tmp_ctx, strlen(fixed_data));
	c_size = lzxpress_decompress(out,
				     sizeof(fixed_out),
				     out2,
				     talloc_get_size(out2));

	torture_assert_int_equal(test, c_size, strlen(fixed_data),
				 "fixed lzxpress_decompress size");
	torture_assert_mem_equal(test, out2, fixed_data, c_size,
				 "fixed lzxpress_decompress data");

	talloc_free(tmp_ctx);
	return true;
}


static bool test_lzxpress_many_zeros(struct torture_context *test)
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

	TALLOC_CTX *tmp_ctx = talloc_new(test);
	const size_t N_ZEROS = 1000000;
	const uint8_t *zeros = talloc_zero_size(tmp_ctx, N_ZEROS);
	const ssize_t expected_c_size = 93;
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

	torture_assert_int_equal(test, c_size, expected_c_size,
				 "fixed lzxpress_compress size");

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
	torture_comment(test, "round-trip time: %"PRIu64" ns\n", elapsed_ns);
	torture_assert(test, elapsed_ns < 3 * 1000U * 1000U * 1000U,
		       "million zeros round trip tool > 3 seconds");
	torture_assert_mem_equal(test, decomp, zeros, N_ZEROS,
				 "fixed lzxpress_decompress data");

	talloc_free(tmp_ctx);
	return true;
}


static bool test_lzxpress_round_trip(struct torture_context *test)
{
	/*
	 * Examples found using via fuzzing.
	 */
	TALLOC_CTX *tmp_ctx = talloc_new(test);
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

		torture_assert_int_equal(test, len, comp.length,
					 "lzexpress compression size");

		torture_assert_mem_equal(test, comp.data, data, len,
					 "lzxpress compression data");

		len = lzxpress_decompress(comp.data,
					  comp.length,
					  data,
					  alloc_size);

		torture_assert_int_equal(test, len, uncomp.length,
					 "lzexpress decompression size");

		torture_assert_mem_equal(test, uncomp.data, data, len,
					 "lzxpress decompression data");
	}
	talloc_free(tmp_ctx);
	return true;
}


struct torture_suite *torture_local_compression(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "compression");

	torture_suite_add_simple_test(suite, "lzxpress", test_lzxpress);
	torture_suite_add_simple_test(suite, "lzxpress_msft_data1", test_msft_data1);
	torture_suite_add_simple_test(suite, "lzxpress_msft_data2", test_msft_data2);
	torture_suite_add_simple_test(suite, "lzxpress2", test_lzxpress2);
	torture_suite_add_simple_test(suite, "lzxpress3", test_lzxpress3);
	torture_suite_add_simple_test(suite, "lzxpress4", test_lzxpress4);
	torture_suite_add_simple_test(suite, "lzxpress_many_zeros",
				      test_lzxpress_many_zeros);
	torture_suite_add_simple_test(suite, "lzxpress_round_trip",
				      test_lzxpress_round_trip);
	return suite;
}
