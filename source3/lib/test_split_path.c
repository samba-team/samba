/*
 * Unix SMB/CIFS implementation.
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
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "split_path_below.c"

static void test_split_path_simple_below(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/export", "data", &base));

	assert_true(split_path_below(&base, "/export/data", "file.txt", true));
}

static void test_split_path_sibling_not_below(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/export", "data", &base));

	assert_false(split_path_below(&base, "/export", "other", true));
}

static void test_split_path_equal_not_below(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/export", "data", &base));

	/*
	 * The exact same path is not a *strict* descendant of itself.
	 */
	assert_false(split_path_below(&base, "/export", "data", true));
}

static void test_split_path_prefix_without_boundary(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/export", "dat", &base));

	/*
	 * "/export/data" is not below "/export/dat": the byte
	 * following the "dat" prefix is 'a', not '/'.
	 */
	assert_false(split_path_below(&base, "/export", "data", true));
}

static void test_split_path_shorter_full_not_below(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/export/data/sub", "file", &base));

	assert_false(split_path_below(&base, "/export", "data", true));
}

static void test_split_path_differing_dirlen_below(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/export/data", "sub", &base));

	/*
	 * dirpath  = "/export/data/sub"        (built from dir1+name1)
	 * fullpath = "/export/data/sub/file"   (built from dir2+name2,
	 *                                       split at a different
	 *                                       point than dirpath)
	 */
	assert_true(split_path_below(&base, "/export", "data/sub/file", true));
}

static void test_split_path_differing_dirlen_false_prefix(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/export/data", "sub", &base));

	/*
	 * "data" is a textual prefix of "database", but the two
	 * paths diverge right at the path-component boundary, so
	 * this must not be reported as "below".
	 */
	assert_false(
		split_path_below(&base, "/export", "database/sub/file", true));
}

static void test_split_path_embedded_slash_in_dir(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/export/data", "sub", &base));

	/*
	 * Same scenario as above, but with dir2 longer than dir1
	 * instead of the other way round.
	 */
	assert_true(split_path_below(&base, "/export/data/sub", "file", true));
}

static void test_split_path_case_insensitive_match(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/Export", "DATA", &base));

	/*
	 * case_insensitive=true matches file_find_subpath()'s
	 * traditional comparator.
	 */
	assert_true(
		split_path_below(&base, "/export/data", "FILE.txt", false));
}

static void test_split_path_case_sensitive_rejects_mismatch(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/Export", "DATA", &base));

	/*
	 * The same inputs, but with a byte-exact comparator: the
	 * differing case must now be reported as "not below".
	 */
	assert_false(
		split_path_below(&base, "/export/data", "FILE.txt", true));
}

static void test_split_path_accepts_sep_only(void **state)
{
	struct split_path base = {};

	assert_true(split_path_init("/export", "data", &base));

	/*
	 * fullpath is exactly "dirpath/", with nothing following the
	 * separator: the bare separator is sufficient.
	 */
	assert_true(split_path_below(&base, "/export/data", "", true));
}

static void test_split_path_multibyte(void **state)
{
	struct split_path base = {};

	/* base = "/ä/d" */
	assert_true(split_path_init("/\xc3\xa4", "d", &base));

	/*
	 * Multibyte characters in the path compare correctly with
	 * both comparators.
	 */
	assert_true(split_path_below(&base, "/\xc3\xa4/d", "f", true));
	assert_true(split_path_below(&base, "/\xc3\xa4/d", "f", false));

	/* base = "/a/b" */
	assert_true(split_path_init("/a", "b", &base));

	/*
	 * "/äz/d" has the separator at the right place, but the first
	 * chunk is "/a" vs "/\xc3", cutting the multibyte character in
	 * half.
	 */
	assert_false(split_path_below(&base, "/\xc3\xa4z", "d", true));
	assert_false(split_path_below(&base, "/\xc3\xa4z", "d", false));
}
/*
 * Reference implementation that materializes the two full paths and
 * compares them the way the original (pre-optimization) code did.
 * Used to cross-check split_path_below() over many combinations of
 * inputs, including differing directory lengths and embedded path
 * separators, without hand-picking every expected result.
 */
static bool naive_is_below(const char *dir1,
			   const char *name1,
			   const char *dir2,
			   const char *name2)
{
	char full1[1024], full2[1024];
	size_t l1, l2;

	snprintf(full1, sizeof(full1), "%s/%s", dir1, name1);
	snprintf(full2, sizeof(full2), "%s/%s", dir2, name2);

	l1 = strlen(full1);
	l2 = strlen(full2);

	if (l1 >= l2) {
		return false;
	}
	if (full2[l1] != '/') {
		return false;
	}
	return (memcmp(full1, full2, l1) == 0);
}

static void test_split_path_matches_naive_reference(void **state)
{
	static const char *pool[] = {
		"",
		"a",
		"ab",
		"abc",
		"abcd",
		"/a",
		"/ab",
		"/abc",
		"a/b",
		"ab/cd",
		"data",
		"data/exports",
		"export",
		"export/data",
		"export/data/sub",
		"exp",
		"x",
		"xy",
		"xyz",
		"/export/data",
		"/export/data/sub",
		"/export",
	};
	size_t n = ARRAY_SIZE(pool);
	size_t i, j, k, l;

	for (i = 0; i < n; i++) {
		for (j = 0; j < n; j++) {
			struct split_path base = {};

			assert_true(split_path_init(pool[i], pool[j], &base));

			for (k = 0; k < n; k++) {
				for (l = 0; l < n; l++) {
					bool got = split_path_below(&base,
								    pool[k],
								    pool[l],
								    true);
					bool want = naive_is_below(pool[i],
								   pool[j],
								   pool[k],
								   pool[l]);

					if (got != want) {
						fail_msg("mismatch for "
							 "dir1=\"%s\" "
							 "name1=\"%s\" "
							 "dir2=\"%s\" "
							 "name2=\"%s\": "
							 "got=%d "
							 "want=%d",
							 pool[i],
							 pool[j],
							 pool[k],
							 pool[l],
							 (int)got,
							 (int)want);
					}
				}
			}
		}
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_split_path_simple_below),
		cmocka_unit_test(test_split_path_sibling_not_below),
		cmocka_unit_test(test_split_path_equal_not_below),
		cmocka_unit_test(test_split_path_prefix_without_boundary),
		cmocka_unit_test(test_split_path_shorter_full_not_below),
		cmocka_unit_test(test_split_path_differing_dirlen_below),
		cmocka_unit_test(
			test_split_path_differing_dirlen_false_prefix),
		cmocka_unit_test(test_split_path_embedded_slash_in_dir),
		cmocka_unit_test(test_split_path_case_insensitive_match),
		cmocka_unit_test(
			test_split_path_case_sensitive_rejects_mismatch),
		cmocka_unit_test(test_split_path_accepts_sep_only),
		cmocka_unit_test(test_split_path_multibyte),
		cmocka_unit_test(test_split_path_matches_naive_reference),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
