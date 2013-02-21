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

static void log_fn(struct tdb_context *tdb, enum tdb_debug_level level, const char *fmt, ...)
{
	unsigned int *count = tdb_get_logging_private(tdb);
	if (strstr(fmt, "spinlocks"))
		(*count)++;
}

/* The code should barf on TDBs created with rwlocks. */
int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	unsigned int log_count;
	struct tdb_logging_context log_ctx = { log_fn, &log_count };

	plan_tests(4);

	/* We should fail to open rwlock-using tdbs of either endian. */
	log_count = 0;
	tdb = tdb_open_ex("test/rwlock-le.tdb", 0, 0, O_RDWR, 0,
			  &log_ctx, NULL);
	ok1(!tdb);
	ok1(log_count == 1);

	log_count = 0;
	tdb = tdb_open_ex("test/rwlock-be.tdb", 0, 0, O_RDWR, 0,
			  &log_ctx, NULL);
	ok1(!tdb);
	ok1(log_count == 1);

	return exit_status();
}
