/*
 * Tests exercising the ldb key value operations.
 *
 *  Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 *
 */

/*
 * A KV module is expected to have the following behaviour
 *
 * - A transaction must be open to perform any read, write or delete operation
 * - Writes and Deletes should not be visible until a transaction is commited
 * - Nested transactions are not permitted
 * - transactions can be rolled back and commited.
 * - supports iteration over all records in the database
 * - supports the update_in_iterate operation allowing entries to be
 *   re-keyed.
 * - has a get_size implementation that returns an estimate of the number of
 *   records in the database.  Note that this can be an estimate rather than
 *   an accurate size.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <unistd.h>
#include <talloc.h>
#include <tevent.h>
#include <ldb.h>
#include <ldb_module.h>
#include <ldb_private.h>
#include <string.h>
#include <ctype.h>

#include <sys/wait.h>

#include "ldb_tdb/ldb_tdb.h"
#include "ldb_key_value/ldb_kv.h"


#define DEFAULT_BE  "tdb"

#ifndef TEST_BE
#define TEST_BE DEFAULT_BE
#endif /* TEST_BE */

#define NUM_RECS 1024


struct test_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;

	const char *dbfile;
	const char *lockfile;   /* lockfile is separate */

	const char *dbpath;
};

static void unlink_old_db(struct test_ctx *test_ctx)
{
	int ret;

	errno = 0;
	ret = unlink(test_ctx->lockfile);
	if (ret == -1 && errno != ENOENT) {
		fail();
	}

	errno = 0;
	ret = unlink(test_ctx->dbfile);
	if (ret == -1 && errno != ENOENT) {
		fail();
	}
}

static int noconn_setup(void **state)
{
	struct test_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	test_ctx->dbfile = talloc_strdup(test_ctx, "kvopstest.ldb");
	assert_non_null(test_ctx->dbfile);

	test_ctx->lockfile = talloc_asprintf(test_ctx, "%s-lock",
					     test_ctx->dbfile);
	assert_non_null(test_ctx->lockfile);

	test_ctx->dbpath = talloc_asprintf(test_ctx,
			TEST_BE"://%s", test_ctx->dbfile);
	assert_non_null(test_ctx->dbpath);

	unlink_old_db(test_ctx);
	*state = test_ctx;
	return 0;
}

static int noconn_teardown(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);

	unlink_old_db(test_ctx);
	talloc_free(test_ctx);
	return 0;
}

static int setup(void **state)
{
	struct test_ctx *test_ctx;
	int ret;
	struct ldb_ldif *ldif;
	const char *index_ldif =		\
		"dn: @INDEXLIST\n"
		"@IDXGUID: objectUUID\n"
		"@IDX_DN_GUID: GUID\n"
		"\n";

	noconn_setup((void **) &test_ctx);

	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(ret, 0);

	while ((ldif = ldb_ldif_read_string(test_ctx->ldb, &index_ldif))) {
		ret = ldb_add(test_ctx->ldb, ldif->msg);
		assert_int_equal(ret, LDB_SUCCESS);
	}
	*state = test_ctx;
	return 0;
}

static int teardown(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	noconn_teardown((void **) &test_ctx);
	return 0;
}

static struct ldb_kv_private *get_ldb_kv(struct ldb_context *ldb)
{
	void *data = NULL;
	struct ldb_kv_private *ldb_kv = NULL;

	data = ldb_module_get_private(ldb->modules);
	assert_non_null(data);

	ldb_kv = talloc_get_type(data, struct ldb_kv_private);
	assert_non_null(ldb_kv);

	return ldb_kv;
}

static int parse(struct ldb_val key,
		 struct ldb_val data,
		 void *private_data)
{
	struct ldb_val* read = private_data;

	/* Yes, we leak this.  That is OK */
	read->data = talloc_size(NULL,
				 data.length);
	assert_non_null(read->data);

	memcpy(read->data, data.data, data.length);
	read->length = data.length;
	return LDB_SUCCESS;
}

/*
 * Parse function that just returns the int we pass it.
 */
static int parse_return(struct ldb_val key,
		        struct ldb_val data,
		        void *private_data)
{
	int *rcode = private_data;
	return *rcode;
}

/*
 * Test that data can be written to the kv store and be read back.
 */
static void test_add_get(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	uint8_t key_val[] = "TheKey";
	struct ldb_val key = {
		.data   = key_val,
		.length = sizeof(key_val)
	};

	uint8_t value[] = "The record contents";
	struct ldb_val data = {
		.data    = value,
		.length = sizeof(value)
	};

	struct ldb_val read;
	int rcode;

	int flags = 0;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the record
	 */
	ret = ldb_kv->kv_ops->store(ldb_kv, key, data, flags);
	assert_int_equal(ret, 0);

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * And now read it back
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, 0);

	assert_int_equal(sizeof(value), read.length);
	assert_memory_equal(value, read.data, sizeof(value));

	/*
	 * Now check that the error code we return in the
	 * parse function is returned by fetch_and_parse.
	 */
	for (rcode=0; rcode<50; rcode++) {
		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key,
						      parse_return,
						      &rcode);
		assert_int_equal(ret, rcode);
	}

	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	talloc_free(tmp_ctx);
}

/*
 * Test that attempts to read data without a read transaction fail.
 */
static void test_read_outside_transaction(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	uint8_t key_val[] = "TheKey";
	struct ldb_val key = {
		.data   = key_val,
		.length = sizeof(key_val)
	};

	uint8_t value[] = "The record contents";
	struct ldb_val data = {
		.data    = value,
		.length = sizeof(value)
	};

	struct ldb_val read;

	int flags = 0;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the record
	 */
	ret = ldb_kv->kv_ops->store(ldb_kv, key, data, flags);
	assert_int_equal(ret, 0);

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * And now read it back
	 * Note there is no read transaction active
	 */
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, LDB_ERR_PROTOCOL_ERROR);

	talloc_free(tmp_ctx);
}

/*
 * Test that data can be deleted from the kv store
 */
static void test_delete(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	uint8_t key_val[] = "TheKey";
	struct ldb_val key = {
		.data   = key_val,
		.length = sizeof(key_val)
	};

	uint8_t value[] = "The record contents";
	struct ldb_val data = {
		.data    = value,
		.length = sizeof(value)
	};

	struct ldb_val read;

	int flags = 0;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the record
	 */
	ret = ldb_kv->kv_ops->store(ldb_kv, key, data, flags);
	assert_int_equal(ret, 0);

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * And now read it back
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, 0);
	assert_int_equal(sizeof(value), read.length);
	assert_memory_equal(value, read.data, sizeof(value));
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Now delete it.
	 */
	ret = ldb_kv->kv_ops->delete (ldb_kv, key);
	assert_int_equal(ret, 0);

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * And now try to read it back
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, LDB_ERR_NO_SUCH_OBJECT);
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	talloc_free(tmp_ctx);
}

/*
 * Check that writes are correctly rolled back when a transaction
 * is rolled back.
 */
static void test_transaction_abort_write(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	uint8_t key_val[] = "TheKey";
	struct ldb_val key = {
		.data   = key_val,
		.length = sizeof(key_val)
	};

	uint8_t value[] = "The record contents";
	struct ldb_val data = {
		.data    = value,
		.length = sizeof(value)
	};

	struct ldb_val read;

	int flags = 0;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the record
	 */
	ret = ldb_kv->kv_ops->store(ldb_kv, key, data, flags);
	assert_int_equal(ret, 0);

	/*
	 * And now read it back
	 */
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, 0);
	assert_int_equal(sizeof(value), read.length);
	assert_memory_equal(value, read.data, sizeof(value));


	/*
	 * Now abort the transaction
	 */
	ret = ldb_kv->kv_ops->abort_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * And now read it back, should not be there
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, LDB_ERR_NO_SUCH_OBJECT);
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	talloc_free(tmp_ctx);
}

/*
 * Check that deletes are correctly rolled back when a transaction is
 * aborted.
 */
static void test_transaction_abort_delete(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	uint8_t key_val[] = "TheKey";
	struct ldb_val key = {
		.data   = key_val,
		.length = sizeof(key_val)
	};

	uint8_t value[] = "The record contents";
	struct ldb_val data = {
		.data    = value,
		.length = sizeof(value)
	};

	struct ldb_val read;

	int flags = 0;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the record
	 */
	ret = ldb_kv->kv_ops->store(ldb_kv, key, data, flags);
	assert_int_equal(ret, 0);

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * And now read it back
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, 0);
	assert_int_equal(sizeof(value), read.length);
	assert_memory_equal(value, read.data, sizeof(value));
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Now delete it.
	 */
	ret = ldb_kv->kv_ops->delete (ldb_kv, key);
	assert_int_equal(ret, 0);

	/*
	 * And now read it back
	 */
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, LDB_ERR_NO_SUCH_OBJECT);

	/*
	 * Abort the transaction
	 */
	ret = ldb_kv->kv_ops->abort_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * And now try to read it back
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, 0);
	assert_int_equal(sizeof(value), read.length);
	assert_memory_equal(value, read.data, sizeof(value));
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	talloc_free(tmp_ctx);
}

/*
 * Test that writes outside a transaction fail
 */
static void test_write_outside_transaction(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	uint8_t key_val[] = "TheKey";
	struct ldb_val key = {
		.data   = key_val,
		.length = sizeof(key_val)
	};

	uint8_t value[] = "The record contents";
	struct ldb_val data = {
		.data    = value,
		.length = sizeof(value)
	};


	int flags = 0;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	/*
	 * Attempt to write the record
	 */
	ret = ldb_kv->kv_ops->store(ldb_kv, key, data, flags);
	assert_int_equal(ret, LDB_ERR_PROTOCOL_ERROR);

	talloc_free(tmp_ctx);
}

/*
 * Test data can not be deleted outside a transaction
 */
static void test_delete_outside_transaction(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	uint8_t key_val[] = "TheKey";
	struct ldb_val key = {
		.data   = key_val,
		.length = sizeof(key_val)
	};

	uint8_t value[] = "The record contents";
	struct ldb_val data = {
		.data    = value,
		.length = sizeof(value)
	};

	struct ldb_val read;

	int flags = 0;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the record
	 */
	ret = ldb_kv->kv_ops->store(ldb_kv, key, data, flags);
	assert_int_equal(ret, 0);

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * And now read it back
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, 0);
	assert_int_equal(sizeof(value), read.length);
	assert_memory_equal(value, read.data, sizeof(value));
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	/*
	 * Now attempt to delete a record
	 */
	ret = ldb_kv->kv_ops->delete (ldb_kv, key);
	assert_int_equal(ret, LDB_ERR_PROTOCOL_ERROR);

	/*
	 * And now read it back
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &read);
	assert_int_equal(ret, 0);
	assert_int_equal(sizeof(value), read.length);
	assert_memory_equal(value, read.data, sizeof(value));
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	talloc_free(tmp_ctx);
}

static int traverse_fn(struct ldb_kv_private *ldb_kv,
		       struct ldb_val key,
		       struct ldb_val data,
		       void *ctx)
{

	int *visits = ctx;
	int i;

	if (strncmp("key ", (char *) key.data, 4) == 0) {
		i = strtol((char *) &key.data[4], NULL, 10);
		visits[i]++;
	}
	return LDB_SUCCESS;
}

/*
 * Test that iterate visits all the records.
 */
static void test_iterate(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	int i;
	int num_recs = 1024;
	int visits[num_recs];

	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the records
	 */
	for (i = 0; i < num_recs; i++) {
		struct ldb_val key;
		struct ldb_val rec;
		int flags = 0;

		visits[i] = 0;
		key.data   = (uint8_t *)talloc_asprintf(tmp_ctx, "key %04d", i);
		key.length = strlen((char *)key.data) + 1;

		rec.data = (uint8_t *) talloc_asprintf(tmp_ctx,
						       "data for record (%04d)",
						       i);
		rec.length = strlen((char *)rec.data) + 1;

		ret = ldb_kv->kv_ops->store(ldb_kv, key, rec, flags);
		assert_int_equal(ret, 0);

		TALLOC_FREE(key.data);
		TALLOC_FREE(rec.data);
	}

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Now iterate over the kv store and ensure that all the
	 * records are visited.
	 */
	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	ret = ldb_kv->kv_ops->iterate(ldb_kv, traverse_fn, visits);
	for (i = 0; i <num_recs; i++) {
		assert_int_equal(1, visits[i]);
	}
	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	TALLOC_FREE(tmp_ctx);
}

static void do_iterate_range_test(void **state, int range_start,
				  int range_end, bool fail)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = NULL;
	int i;
	int num_recs = 1024;
	int skip_recs = 10;
	int visits[num_recs];
	struct ldb_val sk, ek;

	TALLOC_CTX *tmp_ctx;

	ldb_kv = get_ldb_kv(test_ctx->ldb);
	assert_non_null(ldb_kv);

	for (i = 0; i < num_recs; i++){
		visits[i] = 0;
	}

	/*
	 * No iterate_range on tdb
	 */
	if (strcmp(TEST_BE, "tdb") == 0) {
		return;
	}

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the records
	 */
	for (i = skip_recs; i <= num_recs - skip_recs; i++) {
		struct ldb_val key;
		struct ldb_val rec;
		int flags = 0;

		key.data   = (uint8_t *)talloc_asprintf(tmp_ctx,
							"key %04d",
							i);
		key.length = strlen((char *)key.data);

		rec.data = (uint8_t *)talloc_asprintf(tmp_ctx,
						      "data for record (%04d)",
						      i);
		rec.length = strlen((char *)rec.data) + 1;

		ret = ldb_kv->kv_ops->store(ldb_kv, key, rec, flags);
		assert_int_equal(ret, 0);

		TALLOC_FREE(key.data);
		TALLOC_FREE(rec.data);
	}

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	sk.data = (uint8_t *)talloc_asprintf(tmp_ctx, "key %04d", range_start);
	sk.length = strlen((char *)sk.data);

	ek.data = (uint8_t *)talloc_asprintf(tmp_ctx, "key %04d", range_end);
	ek.length = strlen((char *)ek.data) + 1;

	ret = ldb_kv->kv_ops->lock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);
	ret = ldb_kv->kv_ops->iterate_range(ldb_kv, sk, ek,
					    traverse_fn, visits);
	if (fail){
		assert_int_equal(ret, LDB_ERR_PROTOCOL_ERROR);
		TALLOC_FREE(tmp_ctx);
		return;
	} else{
		assert_int_equal(ret, 0);
	}
	for (i = 0; i < num_recs; i++) {
		if (i >= skip_recs && i <= num_recs - skip_recs &&
		    i >= range_start && i <= range_end){
			assert_int_equal(1, visits[i]);
		} else {
			assert_int_equal(0, visits[i]);
		}
	}

	ret = ldb_kv->kv_ops->unlock_read(test_ctx->ldb->modules);
	assert_int_equal(ret, 0);

	TALLOC_FREE(tmp_ctx);
}

/*
 * Test that iterate_range visits all the records between two keys.
 */
static void test_iterate_range(void **state)
{
	do_iterate_range_test(state, 300, 900, false);

	/*
	 * test start_key = end_key
	 */
	do_iterate_range_test(state, 20, 20, false);

	/*
	 * test reverse range fails
	 */
	do_iterate_range_test(state, 50, 40, true);

	/*
	 * keys are between 10-1014 so test with keys outside that range
	 */
	do_iterate_range_test(state, 0, 20, false);
	do_iterate_range_test(state, 1010, 1030, false);
	do_iterate_range_test(state, 0, 1030, false);
}

struct update_context {
	struct ldb_context* ldb;
	int visits[NUM_RECS];
};

static int update_fn(struct ldb_kv_private *ldb_kv,
		     struct ldb_val key,
		     struct ldb_val data,
		     void *ctx)
{

	struct ldb_val new_key;
	struct ldb_module *module = NULL;
	struct update_context *context =NULL;
	int ret = LDB_SUCCESS;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(ldb_kv);
	assert_non_null(tmp_ctx);

	context = talloc_get_type_abort(ctx, struct update_context);

	module = talloc_zero(tmp_ctx, struct ldb_module);
	module->ldb = context->ldb;

	if (strncmp("key ", (char *) key.data, 4) == 0) {
		int i = strtol((char *) &key.data[4], NULL, 10);
		context->visits[i]++;
		new_key.data = talloc_memdup(tmp_ctx, key.data, key.length);
		new_key.length  = key.length;
		new_key.data[0] = 'K';

		ret = ldb_kv->kv_ops->update_in_iterate(
		    ldb_kv, key, new_key, data, &module);
	}
	TALLOC_FREE(tmp_ctx);
	return ret;
}

/*
 * Test that update_in_iterate behaves as expected.
 */
static void test_update_in_iterate(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	int i;
	struct update_context *context = NULL;


	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	context = talloc_zero(tmp_ctx, struct update_context);
	assert_non_null(context);
	context->ldb = test_ctx->ldb;
	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the records
	 */
	for (i = 0; i < NUM_RECS; i++) {
		struct ldb_val key;
		struct ldb_val rec;
		int flags = 0;

		key.data   = (uint8_t *)talloc_asprintf(tmp_ctx, "key %04d", i);
		key.length = strlen((char *)key.data) + 1;

		rec.data   = (uint8_t *) talloc_asprintf(tmp_ctx,
							 "data for record (%04d)",
							 i);
		rec.length = strlen((char *)rec.data) + 1;

		ret = ldb_kv->kv_ops->store(ldb_kv, key, rec, flags);
		assert_int_equal(ret, 0);

		TALLOC_FREE(key.data);
		TALLOC_FREE(rec.data);
	}

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Now iterate over the kv store and ensure that all the
	 * records are visited.
	 */

	/*
	 * Needs to be done inside a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	ret = ldb_kv->kv_ops->iterate(ldb_kv, update_fn, context);
	for (i = 0; i < NUM_RECS; i++) {
		assert_int_equal(1, context->visits[i]);
	}

	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	TALLOC_FREE(tmp_ctx);
}

/*
 * Ensure that writes are not visible until the transaction has been
 * committed.
 */
static void test_write_transaction_isolation(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	struct ldb_val key;
	struct ldb_val val;

	const char *KEY1 = "KEY01";
	const char *VAL1 = "VALUE01";

	const char *KEY2 = "KEY02";
	const char *VAL2 = "VALUE02";

	/*
	 * Pipes etc to co-ordinate the processes
	 */
	int to_child[2];
	int to_parent[2];
	char buf[2];
	pid_t pid, w_pid;
	int wstatus;

	TALLOC_CTX *tmp_ctx;
	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);


	/*
	 * Add a record to the database
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
	key.length = strlen(KEY1) + 1;

	val.data = (uint8_t *)talloc_strdup(tmp_ctx, VAL1);
	val.length = strlen(VAL1) + 1;

	ret = ldb_kv->kv_ops->store(ldb_kv, key, val, 0);
	assert_int_equal(ret, 0);

	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);


	ret = pipe(to_child);
	assert_int_equal(ret, 0);
	ret = pipe(to_parent);
	assert_int_equal(ret, 0);
	/*
	 * Now fork a new process
	 */

	pid = fork();
	if (pid == 0) {

		struct ldb_context *ldb = NULL;
		close(to_child[1]);
		close(to_parent[0]);

		/*
		 * Wait for the transaction to start
		 */
		ret = read(to_child[0], buf, 2);
		if (ret != 2) {
			print_error(__location__": read returned (%d)\n",
				    ret);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		ldb = ldb_init(test_ctx, test_ctx->ev);
		ret = ldb_connect(ldb, test_ctx->dbpath, 0, NULL);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": ldb_connect returned (%d)\n",
				    ret);
			exit(ret);
		}

		ldb_kv = get_ldb_kv(ldb);

		ret = ldb_kv->kv_ops->lock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": lock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		/*
		 * Check that KEY1 is there
		 */
		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
		key.length = strlen(KEY1) + 1;

		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": fetch_and_parse returned "
				    "(%d)\n",
				    ret);
			exit(ret);
		}

		if ((strlen(VAL1) + 1) != val.length) {
			print_error(__location__": KEY1 value lengths different"
				    ", expected (%d) actual(%d)\n",
				    (int)(strlen(VAL1) + 1), (int)val.length);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		if (memcmp(VAL1, val.data, strlen(VAL1)) != 0) {
			print_error(__location__": KEY1 values different, "
				    "expected (%s) actual(%s)\n",
				    VAL1,
				    val.data);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		ret = ldb_kv->kv_ops->unlock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		/*
		 * Check that KEY2 is not there
		 */
		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY2);
		key.length = strlen(KEY2 + 1);

		ret = ldb_kv->kv_ops->lock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": lock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
		if (ret != LDB_ERR_NO_SUCH_OBJECT) {
			print_error(__location__": fetch_and_parse returned "
				    "(%d)\n",
				    ret);
			exit(ret);
		}

		ret = ldb_kv->kv_ops->unlock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		/*
		 * Signal the other process to commit the transaction
		 */
		ret = write(to_parent[1], "GO", 2);
		if (ret != 2) {
			print_error(__location__": write returned (%d)\n",
				    ret);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		/*
		 * Wait for the transaction to be commited
		 */
		ret = read(to_child[0], buf, 2);
		if (ret != 2) {
			print_error(__location__": read returned (%d)\n",
				    ret);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		/*
		 * Check that KEY1 is there
		 */
		ret = ldb_kv->kv_ops->lock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}
		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
		key.length = strlen(KEY1) + 1;

		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": fetch_and_parse returned "
				    "(%d)\n",
				    ret);
			exit(ret);
		}

		if ((strlen(VAL1) + 1) != val.length) {
			print_error(__location__": KEY1 value lengths different"
				    ", expected (%d) actual(%d)\n",
				    (int)(strlen(VAL1) + 1), (int)val.length);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		if (memcmp(VAL1, val.data, strlen(VAL1)) != 0) {
			print_error(__location__": KEY1 values different, "
				    "expected (%s) actual(%s)\n",
				    VAL1,
				    val.data);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		ret = ldb_kv->kv_ops->unlock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}


		/*
		 * Check that KEY2 is there
		 */
		ret = ldb_kv->kv_ops->lock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY2);
		key.length = strlen(KEY2) + 1;

		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": fetch_and_parse returned "
				    "(%d)\n",
				    ret);
			exit(ret);
		}

		if ((strlen(VAL2) + 1) != val.length) {
			print_error(__location__": KEY2 value lengths different"
				    ", expected (%d) actual(%d)\n",
				    (int)(strlen(VAL2) + 1), (int)val.length);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		if (memcmp(VAL2, val.data, strlen(VAL2)) != 0) {
			print_error(__location__": KEY2 values different, "
				    "expected (%s) actual(%s)\n",
				    VAL2,
				    val.data);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		ret = ldb_kv->kv_ops->unlock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		exit(0);
	}
	close(to_child[0]);
	close(to_parent[1]);

	/*
	 * Begin a transaction and add a record to the database
	 * but leave the transaction open
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY2);
	key.length = strlen(KEY2) + 1;

	val.data = (uint8_t *)talloc_strdup(tmp_ctx, VAL2);
	val.length = strlen(VAL2) + 1;

	ret = ldb_kv->kv_ops->store(ldb_kv, key, val, 0);
	assert_int_equal(ret, 0);

	/*
	 * Signal the child process
	 */
	ret = write(to_child[1], "GO", 2);
	assert_int_equal(2, ret);

	/*
	 * Wait for the child process to check the DB state while the
	 * transaction is active
	 */
	ret = read(to_parent[0], buf, 2);
	assert_int_equal(2, ret);

	/*
	 * commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(0, ret);

	/*
	 * Signal the child process
	 */
	ret = write(to_child[1], "GO", 2);
	assert_int_equal(2, ret);

	w_pid = waitpid(pid, &wstatus, 0);
	assert_int_equal(pid, w_pid);

	assert_true(WIFEXITED(wstatus));

	assert_int_equal(WEXITSTATUS(wstatus), 0);


	TALLOC_FREE(tmp_ctx);
}

/*
 * Ensure that deletes are not visible until the transaction has been
 * committed.
 */
static void test_delete_transaction_isolation(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	struct ldb_val key;
	struct ldb_val val;

	const char *KEY1 = "KEY01";
	const char *VAL1 = "VALUE01";

	const char *KEY2 = "KEY02";
	const char *VAL2 = "VALUE02";

	/*
	 * Pipes etc to co-ordinate the processes
	 */
	int to_child[2];
	int to_parent[2];
	char buf[2];
	pid_t pid, w_pid;
	int wstatus;

	TALLOC_CTX *tmp_ctx;
	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);


	/*
	 * Add records to the database
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
	key.length = strlen(KEY1) + 1;

	val.data = (uint8_t *)talloc_strdup(tmp_ctx, VAL1);
	val.length = strlen(VAL1) + 1;

	ret = ldb_kv->kv_ops->store(ldb_kv, key, val, 0);
	assert_int_equal(ret, 0);

	key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY2);
	key.length = strlen(KEY2) + 1;

	val.data = (uint8_t *)talloc_strdup(tmp_ctx, VAL2);
	val.length = strlen(VAL2) + 1;

	ret = ldb_kv->kv_ops->store(ldb_kv, key, val, 0);
	assert_int_equal(ret, 0);

	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);


	ret = pipe(to_child);
	assert_int_equal(ret, 0);
	ret = pipe(to_parent);
	assert_int_equal(ret, 0);
	/*
	 * Now fork a new process
	 */

	pid = fork();
	if (pid == 0) {

		struct ldb_context *ldb = NULL;
		close(to_child[1]);
		close(to_parent[0]);

		/*
		 * Wait for the transaction to be started
		 */
		ret = read(to_child[0], buf, 2);
		if (ret != 2) {
			print_error(__location__": read returned (%d)\n",
				    ret);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		ldb = ldb_init(test_ctx, test_ctx->ev);
		ret = ldb_connect(ldb, test_ctx->dbpath, 0, NULL);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": ldb_connect returned (%d)\n",
				    ret);
			exit(ret);
		}

		ldb_kv = get_ldb_kv(ldb);

		ret = ldb_kv->kv_ops->lock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": lock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		/*
		 * Check that KEY1 is there
		 */
		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
		key.length = strlen(KEY1) + 1;

		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": fetch_and_parse returned "
				    "(%d)\n",
				    ret);
			exit(ret);
		}

		if ((strlen(VAL1) + 1) != val.length) {
			print_error(__location__": KEY1 value lengths different"
				    ", expected (%d) actual(%d)\n",
				    (int)(strlen(VAL1) + 1), (int)val.length);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		if (memcmp(VAL1, val.data, strlen(VAL1)) != 0) {
			print_error(__location__": KEY1 values different, "
				    "expected (%s) actual(%s)\n",
				    VAL1,
				    val.data);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		/*
		 * Check that KEY2 is there
		 */

		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY2);
		key.length = strlen(KEY2) + 1;

		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": fetch_and_parse returned "
				    "(%d)\n",
				    ret);
			exit(ret);
		}

		if ((strlen(VAL2) + 1) != val.length) {
			print_error(__location__": KEY2 value lengths different"
				    ", expected (%d) actual(%d)\n",
				    (int)(strlen(VAL2) + 1), (int)val.length);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		if (memcmp(VAL2, val.data, strlen(VAL2)) != 0) {
			print_error(__location__": KEY2 values different, "
				    "expected (%s) actual(%s)\n",
				    VAL2,
				    val.data);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		ret = ldb_kv->kv_ops->unlock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		/*
		 * Signal the other process to commit the transaction
		 */
		ret = write(to_parent[1], "GO", 2);
		if (ret != 2) {
			print_error(__location__": write returned (%d)\n",
				    ret);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		/*
		 * Wait for the transaction to be commited
		 */
		ret = read(to_child[0], buf, 2);
		if (ret != 2) {
			print_error(__location__": read returned (%d)\n",
				    ret);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}

		/*
		 * Check that KEY1 is there
		 */
		ret = ldb_kv->kv_ops->lock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}
		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY1);
		key.length = strlen(KEY1) + 1;

		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": fetch_and_parse returned "
				    "(%d)\n",
				    ret);
			exit(ret);
		}

		if ((strlen(VAL1) + 1) != val.length) {
			print_error(__location__": KEY1 value lengths different"
				    ", expected (%d) actual(%d)\n",
				    (int)(strlen(VAL1) + 1), (int)val.length);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		if (memcmp(VAL1, val.data, strlen(VAL1)) != 0) {
			print_error(__location__": KEY1 values different, "
				    "expected (%s) actual(%s)\n",
				    VAL1,
				    val.data);
			exit(LDB_ERR_OPERATIONS_ERROR);
		}
		ret = ldb_kv->kv_ops->unlock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		/*
		 * Check that KEY2 is not there
		 */
		key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY2);
		key.length = strlen(KEY2 + 1);

		ret = ldb_kv->kv_ops->lock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": lock_read returned (%d)\n",
				    ret);
			exit(ret);
		}

		ret = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key, parse, &val);
		if (ret != LDB_ERR_NO_SUCH_OBJECT) {
			print_error(__location__": fetch_and_parse returned "
				    "(%d)\n",
				    ret);
			exit(ret);
		}

		ret = ldb_kv->kv_ops->unlock_read(ldb->modules);
		if (ret != LDB_SUCCESS) {
			print_error(__location__": unlock_read returned (%d)\n",
				    ret);
			exit(ret);
		}
		TALLOC_FREE(tmp_ctx);
		exit(0);
	}
	close(to_child[0]);
	close(to_parent[1]);

	/*
	 * Begin a transaction and delete a record from the database
	 * but leave the transaction open
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	key.data = (uint8_t *)talloc_strdup(tmp_ctx, KEY2);
	key.length = strlen(KEY2) + 1;

	ret = ldb_kv->kv_ops->delete (ldb_kv, key);
	assert_int_equal(ret, 0);
	/*
	 * Signal the child process
	 */
	ret = write(to_child[1], "GO", 2);
	assert_int_equal(2, ret);

	/*
	 * Wait for the child process to check the DB state while the
	 * transaction is active
	 */
	ret = read(to_parent[0], buf, 2);
	assert_int_equal(2, ret);

	/*
	 * commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(0, ret);

	/*
	 * Signal the child process
	 */
	ret = write(to_child[1], "GO", 2);
	assert_int_equal(2, ret);

	w_pid = waitpid(pid, &wstatus, 0);
	assert_int_equal(pid, w_pid);

	assert_true(WIFEXITED(wstatus));

	assert_int_equal(WEXITSTATUS(wstatus), 0);


	TALLOC_FREE(tmp_ctx);
}


/*
 * Test that get_size returns a sensible estimate of the number of records
 * in the database.
 */
static void test_get_size(void **state)
{
	int ret;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_kv_private *ldb_kv = get_ldb_kv(test_ctx->ldb);
	uint8_t key_val[] = "TheKey";
	struct ldb_val key = {
		.data   = key_val,
		.length = sizeof(key_val)
	};

	uint8_t value[] = "The record contents";
	struct ldb_val data = {
		.data    = value,
		.length = sizeof(value)
	};
	size_t size = 0;

	int flags = 0;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	size = ldb_kv->kv_ops->get_size(ldb_kv);
#if defined(TEST_LMDB)
	assert_int_equal(2, size);
#else
	/*
	 * The tdb implementation of get_size over estimates for sparse files
	 * which is perfectly acceptable for it's intended use.
	 */
	assert_in_range(size, 2500, 5000);
#endif

	/*
	 * Begin a transaction
	 */
	ret = ldb_kv->kv_ops->begin_write(ldb_kv);
	assert_int_equal(ret, 0);

	/*
	 * Write the record
	 */
	ret = ldb_kv->kv_ops->store(ldb_kv, key, data, flags);
	assert_int_equal(ret, 0);

	/*
	 * Commit the transaction
	 */
	ret = ldb_kv->kv_ops->finish_write(ldb_kv);
	assert_int_equal(ret, 0);

	size = ldb_kv->kv_ops->get_size(ldb_kv);
#ifdef TEST_LMDB
	assert_int_equal(3, size);
#else
	/*
	 * The tdb implementation of get_size over estimates for sparse files
	 * which is perfectly acceptable for it's intended use.
	 */
	assert_in_range(size, 2500, 5000);
#endif
	talloc_free(tmp_ctx);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_add_get,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_delete,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_transaction_abort_write,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_transaction_abort_delete,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_read_outside_transaction,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_write_outside_transaction,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_delete_outside_transaction,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_iterate,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_iterate_range,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_update_in_iterate,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_write_transaction_isolation,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_delete_transaction_isolation,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_get_size,
			setup,
			teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
