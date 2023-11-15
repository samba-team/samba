/*
 * Unit tests for GMSA NDR structures.
 *
 *  Copyright (C) Catalyst.NET Ltd 2023
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include "cmocka.h"

#include "lib/replace/replace.h"

#include "lib/util/attr.h"
#include "librpc/gen_ndr/ndr_gmsa.h"
#include "librpc/gen_ndr/gmsa.h"

static void assert_utf16_equal(const uint16_t *s1, const uint16_t *s2)
{
	uint16_t c1;
	uint16_t c2;

	assert_non_null(s1);
	assert_non_null(s2);

	do {
		c1 = *s1++;
		c2 = *s2++;
		assert_int_equal(c1, c2);
	} while (c1);
}

static void test_managed_password_blob(void **state)
{
	TALLOC_CTX *mem_ctx = NULL;

	enum ndr_err_code err;
	struct MANAGEDPASSWORD_BLOB managed_password = {};

	/* A sample blob produced by Windows. */
	uint8_t data[] = {
		1,   0,	  0,   0,   34,	 1,   0,   0,	16,  0,	  0,   0,   18,
		1,   26,  1,   141, 65,	 237, 151, 152, 15,  173, 200, 51,  62,
		252, 30,  45,  180, 254, 9,   148, 134, 82,  118, 93,  131, 207,
		203, 229, 43,  238, 154, 85,  94,  21,	146, 124, 43,  133, 75,
		168, 15,  221, 241, 54,	 38,  127, 134, 4,   232, 180, 54,  112,
		224, 35,  18,  178, 140, 241, 53,  177, 75,  47,  178, 148, 17,
		178, 163, 78,  51,  82,	 15,  197, 117, 2,   57,  115, 243, 251,
		146, 75,  249, 21,  55,	 226, 125, 85,	112, 156, 85,  42,  39,
		131, 17,  41,  198, 233, 163, 44,  171, 134, 145, 93,  134, 90,
		95,  244, 70,  252, 137, 76,  200, 15,	20,  5,	  86,  125, 235,
		2,   3,	  161, 249, 4,	 26,  245, 205, 138, 17,  249, 33,  139,
		150, 129, 142, 35,  23,	 123, 190, 217, 88,  83,  128, 187, 24,
		3,   69,  250, 56,  137, 86,  158, 197, 158, 122, 138, 101, 20,
		252, 105, 105, 118, 28,	 235, 24,  220, 251, 58,  44,  52,  231,
		66,  74,  250, 215, 207, 96,  217, 57,	153, 25,  11,  5,   10,
		81,  198, 198, 242, 245, 83,  91,  122, 175, 74,  30,  254, 26,
		218, 113, 193, 249, 189, 95,  125, 151, 249, 235, 132, 66,  69,
		170, 235, 143, 107, 155, 26,  34,  160, 27,  166, 79,  32,  104,
		246, 100, 58,  76,  146, 102, 241, 105, 8,   151, 163, 20,  26,
		232, 33,  138, 159, 184, 129, 187, 30,	123, 181, 17,  149, 84,
		183, 248, 210, 254, 46,	 98,  225, 12,	49,  196, 192, 149, 0,
		0,   169, 191, 68,  132, 110, 23,  0,	0,   169, 97,  116, 209,
		109, 23,  0,   0,
	};

	const DATA_BLOB blob = {data, sizeof data};

	/* The UTF‐16 password contained in the blob. */
	const uint16_t current_password[] = {
		16781, 38893, 3992,  51373, 15923, 7932,  46125, 2558,	34452,
		30290, 33629, 52175, 11237, 39662, 24149, 37397, 11132, 19333,
		4008,  61917, 9782,  34431, 59396, 14004, 57456, 4643,	36018,
		13809, 19377, 45615, 4500,  41906, 13134, 3922,	 30149, 14594,
		62323, 37627, 63819, 14101, 32226, 28757, 21916, 10026, 4483,
		50729, 41961, 43820, 37254, 34397, 24410, 18164, 35324, 51276,
		5135,  22021, 60285, 770,   63905, 6660,  52725, 4490,	8697,
		38539, 36481, 5923,  48763, 22745, 32851, 6331,	 17667, 14586,
		22153, 50590, 31390, 25994, 64532, 26985, 7286,	 6379,	64476,
		11322, 59188, 19010, 55290, 24783, 14809, 6553,	 1291,	20746,
		50886, 62962, 23379, 44922, 7754,  6910,  29146, 63937, 24509,
		38781, 60409, 17028, 43589, 36843, 39787, 8730,	 7072,	20390,
		26656, 25846, 19514, 26258, 27121, 38664, 5283,	 59418, 35361,
		47263, 48001, 31518, 4533,  21653, 63671, 65234, 25134, 3297,
		50225, 38336, 0,
	};

	DATA_BLOB packed_blob = data_blob_null;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	/* Pull the Managed Password structure. */
	err = ndr_pull_struct_blob(&blob,
				   mem_ctx,
				   &managed_password,
				   (ndr_pull_flags_fn_t)
					   ndr_pull_MANAGEDPASSWORD_BLOB);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* Check the header. */
	assert_int_equal(1, managed_password.version);
	assert_int_equal(0, managed_password.reserved);
	assert_int_equal(sizeof data, managed_password.length);

	/* Check the password fields. */
	assert_utf16_equal(managed_password.passwords.current,
			   current_password);
	assert_null(managed_password.passwords.previous);

	/* Check the password query intervals.*/
	assert_int_equal(0x176e8444bfa9,
			 *managed_password.passwords.query_interval);
	assert_int_equal(0x176dd17461a9,
			 *managed_password.passwords.unchanged_interval);

	/* Repack the Managed Password structure. */
	managed_password.length = 0;
	err = ndr_push_struct_blob(&packed_blob,
				   mem_ctx,
				   &managed_password,
				   (ndr_push_flags_fn_t)
					   ndr_push_MANAGEDPASSWORD_BLOB);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/*
	 * Check that the result is identical to the blob produced by Windows.
	 */
	assert_int_equal(blob.length, packed_blob.length);
	assert_memory_equal(blob.data, packed_blob.data, blob.length);

	talloc_free(mem_ctx);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_managed_password_blob),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}
