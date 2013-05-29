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
#include "tap-interface.h"
#include <stdlib.h>
#include "logging.h"

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;

	plan_tests(8);

	/* Old format (with zeroes in the hash magic fields) should
	 * open with any hash (since we don't know what hash they used). */
	tdb = tdb_open_ex("test/old-nohash-le.tdb", 0, 0, O_RDWR, 0,
			  &taplogctx, NULL);
	ok1(tdb);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	tdb = tdb_open_ex("test/old-nohash-be.tdb", 0, 0, O_RDWR, 0,
			  &taplogctx, NULL);
	ok1(tdb);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	tdb = tdb_open_ex("test/old-nohash-le.tdb", 0, 0, O_RDWR, 0,
			  &taplogctx, tdb_jenkins_hash);
	ok1(tdb);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	tdb = tdb_open_ex("test/old-nohash-be.tdb", 0, 0, O_RDWR, 0,
			  &taplogctx, tdb_jenkins_hash);
	ok1(tdb);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	return exit_status();
}
