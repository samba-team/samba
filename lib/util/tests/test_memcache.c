/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2021      Andreas Schneider <asn@samba.org>
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

#include "lib/replace/replace.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/memcache.h"

static int setup_talloc_context(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();

	*state = frame;
	return 0;
}

static int teardown_talloc_context(void **state)
{
	TALLOC_CTX *frame = *state;
	TALLOC_FREE(frame);
	return 0;
}

static void torture_memcache_init(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct memcache *cache = NULL;

	cache = memcache_init(mem_ctx, 0);
	assert_non_null(cache);

	TALLOC_FREE(cache);

	cache = memcache_init(mem_ctx, 10);
	assert_non_null(cache);

	TALLOC_FREE(cache);
}

static void torture_memcache_add_lookup_delete(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct memcache *cache = NULL;
	DATA_BLOB key1, key2;
	char *path1 = NULL, *path2 = NULL;

	cache = memcache_init(mem_ctx, 0);
	assert_non_null(cache);

	key1 = data_blob_const("key1", 4);
	path1 = talloc_strdup(mem_ctx, "/tmp/one");
	assert_non_null(path1);

	key2 = data_blob_const("key2", 4);
	path2 = talloc_strdup(mem_ctx, "/tmp/two");
	assert_non_null(path1);

	memcache_add_talloc(cache, GETWD_CACHE, key1, &path1);
	assert_null(path1);

	memcache_add_talloc(cache, GETWD_CACHE, key2, &path2);
	assert_null(path2);

	path1 = memcache_lookup_talloc(cache, GETWD_CACHE, key1);
	assert_non_null(path1);
	assert_string_equal(path1, "/tmp/one");

	path2 = memcache_lookup_talloc(cache, GETWD_CACHE, key2);
	assert_non_null(path2);
	assert_string_equal(path2, "/tmp/two");

	memcache_delete(cache, GETWD_CACHE, key1);
	path1 = memcache_lookup_talloc(cache, GETWD_CACHE, key1);
	assert_null(path1);

	memcache_flush(cache, GETWD_CACHE);
	path2 = memcache_lookup_talloc(cache, GETWD_CACHE, key2);
	assert_null(path2);

	TALLOC_FREE(path1);
	TALLOC_FREE(path2);
	TALLOC_FREE(cache);
}

static void torture_memcache_add_oversize(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct memcache *cache = NULL;
	DATA_BLOB key1, key2;
	char *path1 = NULL, *path2 = NULL;

	cache = memcache_init(mem_ctx, 10);
	assert_non_null(cache);

	key1 = data_blob_const("key1", 4);
	path1 = talloc_strdup(mem_ctx, "/tmp/one");
	assert_non_null(path1);

	key2 = data_blob_const("key2", 4);
	path2 = talloc_strdup(mem_ctx, "/tmp/two");
	assert_non_null(path1);

	memcache_add_talloc(cache, GETWD_CACHE, key1, &path1);
	assert_null(path1);

	memcache_add_talloc(cache, GETWD_CACHE, key2, &path2);
	assert_null(path2);

	path1 = memcache_lookup_talloc(cache, GETWD_CACHE, key1);
	assert_null(path1);

	path2 = memcache_lookup_talloc(cache, GETWD_CACHE, key2);
	assert_non_null(path2);
	assert_string_equal(path2, "/tmp/two");

	TALLOC_FREE(path1);
	TALLOC_FREE(path2);
	TALLOC_FREE(cache);
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_memcache_init),
		cmocka_unit_test(torture_memcache_add_lookup_delete),
		cmocka_unit_test(torture_memcache_add_oversize),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests,
				    setup_talloc_context,
				    teardown_talloc_context);

	return rc;
}
