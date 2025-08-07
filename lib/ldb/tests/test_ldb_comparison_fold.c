/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2018      Andreas Schneider <asn@samba.org>
 * Copyright (C) 2024      Douglas Bagnall   <dbagnall@samba.org>
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
#include "ldb.h"
#include "ldb_private.h"
#include "ldb_handlers.h"
#include "util/tsort.h"
#include "ldb-samba/ldb_wrap.h"


#define debug_message(...)  do {			\
		if (isatty(1)) {			\
			print_message(__VA_ARGS__);	\
				}			\
	} while(0)

/*
 * We use sets of string values paired with integer rankings and make every
 * pair-wise comparison (both ways: cmp(a,b) and cmp(b,a)). The strings should
 * be consistently ordered in the same way as the integers.
 *
 * There are separate sets for the default ldb ASCII comparison, and for
 * Samba's utf-8 aware comparisons, and a common set that both of them should
 * pass.
 */

struct ranked_value {
	struct ldb_val val;
	int rank;
};

#define STR_VAL(s, r) { { discard_const(s), sizeof(s) - 1 }, r}

static const struct ranked_value values_common[] = {
	STR_VAL("", 0),
	STR_VAL("    ", 0),
	STR_VAL("a", 10),
	STR_VAL(" A\0 ignored-post-zero", 10),
	STR_VAL("a   b", 15),
	STR_VAL("a     B ", 15),
	STR_VAL("    A b", 15),

	STR_VAL("a\xc2\xfe", 30),
	STR_VAL("a\xc2\xfe  a", 32),
	STR_VAL("a\xc2\xfe A", 32),
	STR_VAL("a\xc2\xfe Ā", 35),
	STR_VAL("A\xc2\xfe       Ā", 35),
	STR_VAL("a\xc2\xfe ā", 37),
	STR_VAL("a\xff\xfe ā", 40),

	STR_VAL("b", 50),

	STR_VAL("\xff\xfe", 1000),
};

static const struct ranked_value values_default_ascii[] = {
	STR_VAL(" a", 1),

	STR_VAL("b", 50),
	STR_VAL("Ā", 256),
	STR_VAL("  Ā", 256),
	STR_VAL("ā", 257),
	STR_VAL("ā  ", 257),

	STR_VAL("Ʊ", 433),
	STR_VAL("\xc8\xfe", 500),
	STR_VAL("ʊ", 650),

	STR_VAL("\xff\xfe", 1000),
};

static const struct ranked_value values_utf8[] = {
	STR_VAL(" a", 1),

	STR_VAL("b", 50),
	STR_VAL("Ā", 256),
	STR_VAL("  Ā", 256),
	STR_VAL("ā", 256),
	STR_VAL("ā  ", 256),

	STR_VAL("Ʊ", 433),
	STR_VAL("ʊ", 433),
	STR_VAL("\xc8\xfe", 900),

	STR_VAL("\xff\xfe", 1000),
};



#undef STR_VAL


static void _test_ldb_comparison_fold_set(struct ldb_context *ldb,
					  const struct ranked_value *values,
					  size_t n)
{
	size_t i, j;
	size_t n_errors = 0;

	for (i = 0; i < n; i++) {
		struct ranked_value a = values[i];
		for (j = 0; j < n; j++) {
			struct ranked_value b = values[j];
			int ret = ldb_comparison_fold(ldb, NULL, &a.val, &b.val);
			if ((ret < 0 && a.rank < b.rank) ||
			    (ret == 0 && a.rank == b.rank) ||
			    (ret > 0 && a.rank > b.rank)) {
				continue;
			}
			debug_message("A {'%s', %zu} vs B {'%s', %zu} returned %d,"
				      "should be %d (%d - %d)\n",
				      a.val.data, a.val.length, b.val.data, b.val.length, ret,
				      NUMERIC_CMP(a.rank, b.rank), a.rank, b.rank);

			n_errors++;
		}
	}
	debug_message("%zu errors out of %zu\n", n_errors, n * n);

	assert_int_equal(n_errors, 0);
}


/*
 * These tests are for the specific behaviour of the default ASCII-only
 * casefold.
 */
static void test_ldb_comparison_fold_default_ascii(void **state)
{
	struct ldb_context *ldb = ldb_init(NULL, NULL);
	_test_ldb_comparison_fold_set(ldb,
				      values_default_ascii,
				      ARRAY_SIZE(values_default_ascii));
}


/*
 * These tests are for behaviour with the default comparison, that should work
 * the same with the Samba utf-8 comparison.
 */
static void test_ldb_comparison_fold_default_common(void **state)
{
	struct ldb_context *ldb = ldb_init(NULL, NULL);
	_test_ldb_comparison_fold_set(ldb,
				      values_common,
				      ARRAY_SIZE(values_common));
}


/*
 * These tests are for behaviour with the Samba utf-8 comparison, that should
 * work the same with the default ASCII comparison.
 */
static void test_ldb_comparison_fold_utf8_common(void **state)
{
	struct ldb_context *ldb = ldb_init(NULL, NULL);
	ldb_set_utf8_functions(ldb, NULL, wrap_casefold, ldb_comparison_fold_utf8);
	_test_ldb_comparison_fold_set(ldb,
				      values_common,
				      ARRAY_SIZE(values_common));
}

/*
 * These tests are for the specific behaviour of the default ASCII-only
 * casefold.
 */
static void test_ldb_comparison_fold_utf8(void **state)
{
	struct ldb_context *ldb = ldb_init(NULL, NULL);
	ldb_set_utf8_functions(ldb, NULL, wrap_casefold, ldb_comparison_fold_utf8);
	_test_ldb_comparison_fold_set(ldb,
				      values_utf8,
				      ARRAY_SIZE(values_utf8));
}




int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ldb_comparison_fold_default_common),
		cmocka_unit_test(test_ldb_comparison_fold_default_ascii),
		cmocka_unit_test(test_ldb_comparison_fold_utf8_common),
		cmocka_unit_test(test_ldb_comparison_fold_utf8),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}
