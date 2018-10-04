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
	TDB_DATA key;

	plan_tests(3);
	tdb = tdb_open_ex(
		"test/circular_chain.tdb",
		0,
		TDB_DEFAULT,
		O_RDONLY,
		0600,
		&taplogctx,
		NULL);

	ok1(tdb);
	key.dsize = strlen("x");
	key.dptr = discard_const_p(uint8_t, "x");

	ok1(tdb_exists(tdb, key) == 0);
	ok1(tdb_error(tdb) == TDB_ERR_CORRUPT);

	tdb_close(tdb);

	return exit_status();
}
