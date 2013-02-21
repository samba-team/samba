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
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>

static TDB_DATA key, data;

static void log_fn(struct tdb_context *tdb, enum tdb_debug_level level,
		   const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static double timeval_elapsed2(const struct timeval *tv1, const struct timeval *tv2)
{
	return (tv2->tv_sec - tv1->tv_sec) +
	       (tv2->tv_usec - tv1->tv_usec)*1.0e-6;
}

static double timeval_elapsed(const struct timeval *tv)
{
	struct timeval tv2;
	gettimeofday(&tv2, NULL);
	return timeval_elapsed2(tv, &tv2);
}

/* The code should barf on TDBs created with rwlocks. */
int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	unsigned int log_count;
	struct tdb_logging_context log_ctx = { log_fn, &log_count };
	int ret;
	struct timeval start;
	double elapsed;
	bool runtime_support;

	runtime_support = tdb_runtime_check_for_robust_mutexes();

	if (!runtime_support) {
		skip(1, "No robust mutex support");
		return exit_status();
	}

	key.dsize = strlen("hi");
	key.dptr = discard_const_p(uint8_t, "hi");
	data.dsize = strlen("world");
	data.dptr = discard_const_p(uint8_t, "world");

	tdb = tdb_open_ex("mutex-allrecord-bench.tdb", 1000000,
			  TDB_INCOMPATIBLE_HASH|
			  TDB_MUTEX_LOCKING|
			  TDB_CLEAR_IF_FIRST,
			  O_RDWR|O_CREAT, 0755, &log_ctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	gettimeofday(&start, NULL);
	ret = tdb_allrecord_lock(tdb, F_WRLCK, TDB_LOCK_WAIT, false);
	elapsed = timeval_elapsed(&start);

	ok(ret == 0, "tdb_allrecord_lock should succeed");

	diag("allrecord_lock took %f seconds", elapsed);

	return exit_status();
}
