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

	plan_tests(4);
	tdb = tdb_open_ex(NULL, 1024, TDB_INTERNAL, O_CREAT|O_TRUNC|O_RDWR,
			  0600, &taplogctx, NULL);
	ok1(tdb);

	/* Tickle bug on appending zero length buffer to zero length buffer. */
	key.dsize = strlen("hi");
	key.dptr = discard_const_p(uint8_t, "hi");
	data.dptr = discard_const_p(uint8_t, "world");
	data.dsize = 0;

	ok1(tdb_append(tdb, key, data) == 0);
	ok1(tdb_append(tdb, key, data) == 0);
	data = tdb_fetch(tdb, key);
	ok1(data.dsize == 0);
	tdb_close(tdb);
	free(data.dptr);

	return exit_status();
}
