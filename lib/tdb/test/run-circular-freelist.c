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

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	TDB_DATA key, data;

	plan_tests(3);
	tdb = tdb_open_ex(
		"test/circular_freelist.tdb",
		0,
		TDB_DEFAULT,
		O_RDWR,
		0600,
		&taplogctx,
		NULL);

	ok1(tdb);

	/*
	 * All freelist records are just 1 byte key and value. Insert
	 * something that will walk the whole freelist and hit the
	 * circle.
	 */
	key.dsize = strlen("x");
	key.dptr = discard_const_p(uint8_t, "x");
	data.dsize = strlen("too long");
	data.dptr = discard_const_p(uint8_t, "too long");

	ok1(tdb_store(tdb, key, data, TDB_INSERT) == -1);
	ok1(tdb_error(tdb) == TDB_ERR_CORRUPT);

	tdb_close(tdb);

	return exit_status();
}
