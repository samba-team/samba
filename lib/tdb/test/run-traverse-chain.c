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
#include "../common/mutex.c"
#include "tap-interface.h"
#include <stdlib.h>
#include "logging.h"

static char keystr0[] = "x";
static TDB_DATA key0 = { .dptr = (uint8_t *)keystr0,
			 .dsize = sizeof(keystr0) };
static char valuestr0[] = "y";
static TDB_DATA value0 = { .dptr = (uint8_t *)valuestr0,
			   .dsize = sizeof(valuestr0) };

static char keystr1[] = "aaa";
static TDB_DATA key1 = { .dptr = (uint8_t *)keystr1,
			 .dsize = sizeof(keystr1) };
static char valuestr1[] = "bbbbb";
static TDB_DATA value1 = { .dptr = (uint8_t *)valuestr1,
			   .dsize = sizeof(valuestr1) };

static TDB_DATA *keys[] = { &key0, &key1 };
static TDB_DATA *values[] = { &value0, &value1 };

static bool tdb_data_same(TDB_DATA d1, TDB_DATA d2)
{
	if (d1.dsize != d2.dsize) {
		return false;
	}
	return (memcmp(d1.dptr, d2.dptr, d1.dsize) == 0);
}

struct traverse_chain_state {
	size_t idx;
	bool ok;
};

static int traverse_chain_fn(struct tdb_context *tdb,
			     TDB_DATA key,
			     TDB_DATA data,
			     void *private_data)
{
	struct traverse_chain_state *state = private_data;

	state->ok &= tdb_data_same(key, *keys[state->idx]);
	state->ok &= tdb_data_same(data, *values[state->idx]);
	state->idx += 1;

	return 0;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	struct traverse_chain_state state = { .ok = true };
	int ret;

	plan_tests(4);

	tdb = tdb_open_ex(
		"traverse_chain.tdb",
		1,
		TDB_CLEAR_IF_FIRST,
		O_RDWR|O_CREAT,
		0600,
		&taplogctx,
		NULL);
	ok1(tdb);

	/* add in reverse order, tdb_store adds to the front of the list */
	ret = tdb_store(tdb, key1, value1, TDB_INSERT);
	ok1(ret == 0);
	ret = tdb_store(tdb, key0, value0, TDB_INSERT);
	ok1(ret == 0);

	ret = tdb_traverse_key_chain(tdb, key0, traverse_chain_fn, &state);
	ok1(ret == 2);
	ok1(state.ok);

	unlink(tdb_name(tdb));

	tdb_close(tdb);

	return exit_status();
}
