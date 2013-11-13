#include "../common/tdb_private.h"
#include "../common/io.c"
#include "../common/tdb.c"
#include "../common/lock.c"
#include "../common/freelist.c"
#include "../common/traverse.c"
#include "../common/transaction.c"
#include "../common/error.c"
#include "../common/open.c"
#include "../common/check.c"
#include "../common/hash.c"
#include "../common/rescue.c"
#include "tap-interface.h"
#include <stdlib.h>
#include "logging.h"

struct walk_data {
	TDB_DATA key;
	TDB_DATA data;
	bool fail;
	unsigned count;
};

static inline bool tdb_deq(TDB_DATA a, TDB_DATA b)
{
	return a.dsize == b.dsize && memcmp(a.dptr, b.dptr, a.dsize) == 0;
}

static inline TDB_DATA tdb_mkdata(const void *p, size_t len)
{
	TDB_DATA d;
	d.dptr = (void *)p;
	d.dsize = len;
	return d;
}

static void walk(TDB_DATA key, TDB_DATA data, void *_wd)
{
	struct walk_data *wd = _wd;

	if (!tdb_deq(key, wd->key)) {
		wd->fail = true;
	}

	if (!tdb_deq(data, wd->data)) {
		wd->fail = true;
	}
	wd->count++;
}

static void count_records(TDB_DATA key, TDB_DATA data, void *_wd)
{
	struct walk_data *wd = _wd;

	if (!tdb_deq(key, wd->key) || !tdb_deq(data, wd->data))
		diag("%.*s::%.*s\n",
		     (int)key.dsize, key.dptr, (int)data.dsize, data.dptr);
	wd->count++;
}

static void log_fn(struct tdb_context *tdb, enum tdb_debug_level level, const char *fmt, ...)
{
	unsigned int *count = tdb_get_logging_private(tdb);
	(*count)++;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	struct walk_data wd;
	unsigned int i, size, log_count = 0;
	struct tdb_logging_context log_ctx = { log_fn, &log_count };

	plan_tests(8);
	tdb = tdb_open_ex("run-rescue.tdb", 1, TDB_CLEAR_IF_FIRST,
			  O_CREAT|O_TRUNC|O_RDWR, 0600, &log_ctx, NULL);

	wd.key.dsize = strlen("hi");
	wd.key.dptr = (void *)"hi";
	wd.data.dsize = strlen("world");
	wd.data.dptr = (void *)"world";
	wd.count = 0;
	wd.fail = false;

	ok1(tdb_store(tdb, wd.key, wd.data, TDB_INSERT) == 0);

	ok1(tdb_rescue(tdb, walk, &wd) == 0);
	ok1(!wd.fail);
	ok1(wd.count == 1);

	/* Corrupt the database, walk should either get it or not. */
	size = tdb->map_size;
	for (i = sizeof(struct tdb_header); i < size; i++) {
		char c;
		if (tdb->methods->tdb_read(tdb, i, &c, 1, false) != 0)
			fail("Reading offset %i", i);
		if (tdb->methods->tdb_write(tdb, i, "X", 1) != 0)
			fail("Writing X at offset %i", i);

		wd.count = 0;
		if (tdb_rescue(tdb, count_records, &wd) != 0) {
			wd.fail = true;
			break;
		}
		/* Could be 0 or 1. */
		if (wd.count > 1) {
			wd.fail = true;
			break;
		}
		if (tdb->methods->tdb_write(tdb, i, &c, 1) != 0)
			fail("Restoring offset %i", i);
	}
	ok1(log_count == 0);
	ok1(!wd.fail);
	tdb_close(tdb);

	/* Now try our known-corrupt db. */
	tdb = tdb_open_ex("test/tdb.corrupt", 1024, 0, O_RDWR, 0,
			  &taplogctx, NULL);
	wd.count = 0;
	ok1(tdb_rescue(tdb, count_records, &wd) == 0);
	ok1(wd.count == 1627);
	tdb_close(tdb);

	return exit_status();
}
