/* We should be able to tdb_check a O_RDONLY tdb, and we were previously allowed
 * to tdb_check() inside a transaction (though that's paranoia!). */
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

	plan_tests(11);
	tdb = tdb_open_ex("run-readonly-check.tdb", 1024,
			  TDB_DEFAULT,
			  O_CREAT|O_TRUNC|O_RDWR, 0600, &taplogctx, NULL);

	ok1(tdb);
	key.dsize = strlen("hi");
	key.dptr = discard_const_p(uint8_t, "hi");
	data.dsize = strlen("world");
	data.dptr = discard_const_p(uint8_t, "world");

	ok1(tdb_store(tdb, key, data, TDB_INSERT) == 0);
	ok1(tdb_check(tdb, NULL, NULL) == 0);

	/* We are also allowed to do a check inside a transaction. */
	ok1(tdb_transaction_start(tdb) == 0);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	ok1(tdb_close(tdb) == 0);

	tdb = tdb_open_ex("run-readonly-check.tdb", 1024,
			  TDB_DEFAULT, O_RDONLY, 0, &taplogctx, NULL);

	ok1(tdb);
	ok1(tdb_store(tdb, key, data, TDB_MODIFY) == -1);
	ok1(tdb_error(tdb) == TDB_ERR_RDONLY);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	ok1(tdb_close(tdb) == 0);

	return exit_status();
}
