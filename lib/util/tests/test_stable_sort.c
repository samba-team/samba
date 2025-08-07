/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2018      Andreas Schneider <asn@samba.org>
 * Copyright (C) 2022      Douglas Bagnall   <dbagnall@samba.org>
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
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdbool.h>
#include "replace.h"
#include <talloc.h>

#include "../stable_sort.h"


static int cmp_integer(int *a, int *b)
{
	if (a == NULL || b == NULL) {
		return 0;
	}

	if (*a > *b) {
		return 1;
	}

	if (*a < *b) {
		return -1;
	}

	return 0;
}

static void test_stable_sort(void **state)
{
	int a[6] = { 6, 3, 2, 7, 9, 4 };
	int tmp[6];
	bool ok;
	ok = stable_sort(a, tmp,
			 6, sizeof(int), (samba_compare_fn_t)cmp_integer);

	assert_true(ok);
	assert_int_equal(a[0], 2);
	assert_int_equal(a[1], 3);
	assert_int_equal(a[2], 4);
	assert_int_equal(a[3], 6);
	assert_int_equal(a[4], 7);
	assert_int_equal(a[5], 9);
}

static void test_stable_sort_talloc_short(void **state)
{
	int a[6] = { 6, 3, 2, 7, 9, 4 };
	int ret;
	ret = stable_sort_talloc(NULL, a, 6, sizeof(int),
				 (samba_compare_fn_t)cmp_integer);
	assert_true(ret);

	assert_int_equal(a[0], 2);
	assert_int_equal(a[1], 3);
	assert_int_equal(a[2], 4);
	assert_int_equal(a[3], 6);
	assert_int_equal(a[4], 7);
	assert_int_equal(a[5], 9);
}

static void test_stable_sort_talloc_long(void **state)
{
	int i, ret;
	size_t n = 1500;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	int *a = talloc_array(mem_ctx, int, n);
	for (i = 0; i < n; i++) {
		a[i] = n - i;
	}

	ret = stable_sort_talloc(mem_ctx, a, n, sizeof(int),
				     (samba_compare_fn_t)cmp_integer);
	assert_true(ret);

	for (i = 0; i < n; i++) {
		assert_int_equal(a[i], 1 + i);
	}
}


/*
 * Sort an array of structs with:
 * - unwieldy uneven size
 * - sort key not at the start
 * - comparison depends on context
 *
 * which are things we sometimes do.
 */

struct contrived_struct {
	char padding_1[13];
	int key[3];
	char padding_2[18];
	size_t *index;
};


static int cmp_contrived_struct(struct contrived_struct *as,
				struct contrived_struct *bs)
{
	int i = *as->index;
	int a = as->key[i];
	int b = bs->key[i];
	return a - b;
}

static int cmp_contrived_struct_rev(struct contrived_struct *as,
				    struct contrived_struct *bs)
{
	/* will sort in reverseo order */
	int i = *as->index;
	int a = as->key[i];
	int b = bs->key[i];
	return b - a;
}


static void test_stable_sort_talloc_contrived_struct(void **state)
{
	int i, ret, prev;
	size_t n = 800000;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	size_t key_index = 0;

	struct contrived_struct *a = talloc_zero_array(mem_ctx,
						       struct contrived_struct,
						       n);

	/* we don't really want a good RNG, we want mess and repeated values. */
	uint32_t x = 89, y = (uint32_t)-6, z = 11;
	for (i = 0; i < n; i++) {
		a[i].index = &key_index;
		a[i].key[0] = (x & 0xffff) - 0x8000;
		a[i].key[1] = z & 255;
		/* key[2] is original order, useful for checking stability */
		a[i].key[2] = i;
		x += z ^ y;
		y *= z + (x + 0x5555);
		z -= x ^ i;
	}

	/* 1. sort by key[0] */
	ret = stable_sort_talloc(mem_ctx, a, n,
				 sizeof(struct contrived_struct),
				 (samba_compare_fn_t)cmp_contrived_struct);
	assert_true(ret);
	prev = a[0].key[0];
	for (i = 1; i < n; i++) {
		int value = a[i].key[0];
		assert_true(value >= prev);
		if (value == prev) {
			/* we can test the stability by comparing key[2] */
			assert_true(a[i].key[2] >= a[i - 1].key[2]);
		}
		prev = value;
	}

	/* 2. sort by key[1]. key[0] now indicates stability. */
	key_index = 1;
	ret = stable_sort_talloc(mem_ctx, a, n,
				 sizeof(struct contrived_struct),
				 (samba_compare_fn_t)cmp_contrived_struct);
	assert_true(ret);
	prev = a[0].key[1];
	for (i = 1; i < n; i++) {
		int value = a[i].key[1];
		assert_true(value >= prev);
		if (value == prev) {
			assert_true(a[i].key[0] >= a[i - 1].key[0]);
		}
		prev = value;
	}

	/*
	 * 3. sort by key[2]. key[1] would now indicate stability, but we know
	 * that key[2] has no duplicates, so stability is moot.
	 */
	key_index = 2;
	ret = stable_sort_talloc(mem_ctx, a, n,
				 sizeof(struct contrived_struct),
				 (samba_compare_fn_t)cmp_contrived_struct);
	assert_true(ret);
	prev = a[0].key[2];
	for (i = 1; i < n; i++) {
		int value = a[i].key[2];
		assert_true(value > prev);
		prev = value;
	}

	/*
	 * 4. sort by key[0] again, using descending sort order. key[2] should
	 * still be in ascending order where there are duplicate key[0] values.
	 */
	key_index = 0;
	ret = stable_sort_talloc(mem_ctx, a, n,
				 sizeof(struct contrived_struct),
				 (samba_compare_fn_t)cmp_contrived_struct_rev);
	assert_true(ret);
	prev = a[0].key[0];
	for (i = 1; i < n; i++) {
		int value = a[i].key[0];
		assert_true(value <= prev);
		if (value == prev) {
			assert_true(a[i].key[2] >= a[i - 1].key[2]);
		}
		prev = value;
	}
}



static int cmp_integer_xor_blob(int *_a, int *_b, int *opaque)
{
	int a = *_a ^ *opaque;
	int b = *_b ^ *opaque;

	if (a > b) {
		return 1;
	}

	if (a < b) {
		return -1;
	}

	return 0;
}

static void test_stable_sort_talloc_r(void **state)
{
	int i;
	size_t n = 1500;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	int opaque = 42;
	bool ok;
	int *a = talloc_array(mem_ctx, int, n);
	for (i = 0; i < n; i++) {
		a[i] = (i * 7) & 255;
	}

	ok = stable_sort_talloc_r(mem_ctx, a, n, sizeof(int),
				  (samba_compare_with_context_fn_t)cmp_integer_xor_blob,
				  &opaque);
	assert_true(ok);

	for (i = 1; i < n; i++) {
		assert_true((a[i - 1] ^ opaque) <= (a[i] ^ opaque));
	}
}


static void test_stable_sort_silly_size(void **state)
{
	bool ok;
	int a[33] = {0};
	int b[33] = {0};

	ok = stable_sort(a,
			 b,
			 (SIZE_MAX / 2) + 2,
			 (SIZE_MAX / 2) + 2,
			 (samba_compare_fn_t)cmp_integer);
	assert_false(ok);
}

static void test_stable_sort_null_array(void **state)
{
	bool ok;
	int a[33] = {0};

	ok = stable_sort(a,
			 NULL,
			 33,
			 sizeof(int),
			 (samba_compare_fn_t)cmp_integer);
	assert_false(ok);
}





int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_stable_sort),
		cmocka_unit_test(test_stable_sort_talloc_short),
		cmocka_unit_test(test_stable_sort_talloc_long),
		cmocka_unit_test(test_stable_sort_talloc_contrived_struct),
		cmocka_unit_test(test_stable_sort_talloc_r),
		cmocka_unit_test(test_stable_sort_silly_size),
		cmocka_unit_test(test_stable_sort_null_array),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}
