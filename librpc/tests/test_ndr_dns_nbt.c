/*
 * Tests for librpc ndr functions
 *
 * Copyright (C) Catalyst.NET Ltd 2020
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

#include "replace.h"
#include <setjmp.h>
#include <cmocka.h>

#include "includes.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "lib/util/time.h"

#define NBT_NAME "EOGFGLGPCACACACACACACACACACACACA" /* "neko" */


static DATA_BLOB generate_obnoxious_dns_name(TALLOC_CTX *mem_ctx,
					     size_t n_labels,
					     size_t dot_every,
					     bool is_nbt)
{
	size_t i, j;
	char *s;
	DATA_BLOB name = data_blob_talloc(mem_ctx, NULL, 64 * n_labels + 1);
	assert_non_null(name.data);

	s = (char*)name.data;
	if (is_nbt) {
		size_t len = strlen(NBT_NAME);
		*s = len;
		s++;
		memcpy(s, NBT_NAME, len);
		s += len;
		n_labels--;
	}

	for (i = 0; i < n_labels; i++) {
		*s = 63;
		s++;
		for (j = 0; j < 63; j++) {
			if (j % dot_every == (dot_every - 1)) {
				*s = '.';
			} else {
				*s = 'x';
			}
			s++;
		}
	}
	*s = 0;
	s++;
	name.length = s - (char*)name.data;
	return name;
}


static char *_test_ndr_pull_dns_string_list(TALLOC_CTX *mem_ctx,
					    size_t n_labels,
					    size_t dot_every,
					    bool is_nbt)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob = generate_obnoxious_dns_name(mem_ctx,
						     n_labels,
						     dot_every,
						     is_nbt);

	char *name;
	ndr_pull_flags_fn_t fn;

	if (is_nbt) {
		fn = (ndr_pull_flags_fn_t)ndr_pull_nbt_string;
	} else {
		fn = (ndr_pull_flags_fn_t)ndr_pull_dns_string;
	}

	ndr_err = ndr_pull_struct_blob(&blob,
				       mem_ctx,
				       &name,
				       fn);
	/* Success here is not expected, but we let it go to measure timing. */
	if (ndr_err == NDR_ERR_SUCCESS) {
		printf("pull succeed\n");
	} else {
		assert_int_equal(ndr_err, NDR_ERR_STRING);
	}

	TALLOC_FREE(blob.data);
	return name;
}


static void _test_ndr_push_dns_string_list(TALLOC_CTX *mem_ctx,
					   char *name,
					   bool is_nbt)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	ndr_push_flags_fn_t fn;

	if (is_nbt) {
		fn = (ndr_push_flags_fn_t)ndr_push_nbt_string;
	} else {
		fn = (ndr_push_flags_fn_t)ndr_push_dns_string;
	}

	ndr_err = ndr_push_struct_blob(&blob,
				       mem_ctx,
				       name,
				       fn);

	/* Success here is not expected, but we let it go to measure timing. */
	if (ndr_err == NDR_ERR_SUCCESS) {
		printf("push succeed\n");
	} else {
		assert_int_equal(ndr_err, NDR_ERR_STRING);
	}
}


static uint64_t elapsed_time(struct timespec start, const char *print)
{
	struct timespec end;
	unsigned long long microsecs;
	clock_gettime_mono(&end);
	end.tv_sec -= start.tv_sec;
	if (end.tv_nsec < start.tv_nsec) {
		/* we need to borrow */
		end.tv_nsec += 1000 * 1000 * 1000;
		end.tv_sec -= 1;
	}
	end.tv_nsec -= start.tv_nsec;
	microsecs = end.tv_sec * 1000000;
	microsecs += end.tv_nsec / 1000;

	if (print != NULL) {
		printf(" %s: %llu microseconds\n", print, microsecs);
	}
	return microsecs;
}


static void test_ndr_dns_string_half_dots(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	char *name;
	struct timespec start;
	uint64_t elapsed;

	clock_gettime_mono(&start);
	name =_test_ndr_pull_dns_string_list(mem_ctx, 127, 2, false);
	elapsed_time(start, "pull");
	_test_ndr_push_dns_string_list(mem_ctx, name, false);
	elapsed = elapsed_time(start, "total");
	assert_in_range(elapsed, 0, 200000);
	talloc_free(mem_ctx);
}

static void test_ndr_nbt_string_half_dots(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	char *name;
	struct timespec start;
	uint64_t elapsed;

	clock_gettime_mono(&start);
	name =_test_ndr_pull_dns_string_list(mem_ctx, 127, 2, true);
	elapsed_time(start, "pull");
	_test_ndr_push_dns_string_list(mem_ctx, name, true);
	elapsed = elapsed_time(start, "total");
	assert_in_range(elapsed, 0, 200000);
	talloc_free(mem_ctx);
}

static void test_ndr_dns_string_all_dots(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	char *name;
	struct timespec start;
	uint64_t elapsed;

	clock_gettime_mono(&start);
	name =_test_ndr_pull_dns_string_list(mem_ctx, 127, 1, false);
	elapsed_time(start, "pull");
	_test_ndr_push_dns_string_list(mem_ctx, name, false);
	elapsed = elapsed_time(start, "total");
	assert_in_range(elapsed, 0, 200000);
	talloc_free(mem_ctx);
}

static void test_ndr_nbt_string_all_dots(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	char *name;
	struct timespec start;
	uint64_t elapsed;

	clock_gettime_mono(&start);
	name =_test_ndr_pull_dns_string_list(mem_ctx, 127, 1, true);
	elapsed_time(start, "pull");
	_test_ndr_push_dns_string_list(mem_ctx, name, true);
	elapsed = elapsed_time(start, "total");
	assert_in_range(elapsed, 0, 200000);
	talloc_free(mem_ctx);
}



int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ndr_nbt_string_half_dots),
		cmocka_unit_test(test_ndr_dns_string_half_dots),
		cmocka_unit_test(test_ndr_nbt_string_all_dots),
		cmocka_unit_test(test_ndr_dns_string_all_dots),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
