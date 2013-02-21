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

static int do_child(int tdb_flags, int to, int from)
{
	struct tdb_context *tdb;
	unsigned int log_count;
	struct tdb_logging_context log_ctx = { log_fn, &log_count };
	int ret;
	char c = 0;

	tdb = tdb_open_ex("mutex-allrecord-block.tdb", 3, tdb_flags,
			  O_RDWR|O_CREAT, 0755, &log_ctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	ret = tdb_allrecord_lock(tdb, F_WRLCK, TDB_LOCK_WAIT, false);
	ok(ret == 0, "tdb_allrecord_lock should succeed");

	write(to, &c, sizeof(c));

	read(from, &c, sizeof(c));

	ret = tdb_allrecord_unlock(tdb, F_WRLCK, false);
	ok(ret == 0, "tdb_allrecord_unlock should succeed");

	return 0;
}

/* The code should barf on TDBs created with rwlocks. */
int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	unsigned int log_count;
	struct tdb_logging_context log_ctx = { log_fn, &log_count };
	int ret, status;
	pid_t child, wait_ret;
	int fromchild[2];
	int tochild[2];
	char c;
	int tdb_flags;
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

	pipe(fromchild);
	pipe(tochild);

	tdb_flags = TDB_INCOMPATIBLE_HASH|
		TDB_MUTEX_LOCKING|
		TDB_CLEAR_IF_FIRST;

	child = fork();
	if (child == 0) {
		close(fromchild[0]);
		close(tochild[1]);
		return do_child(tdb_flags, fromchild[1], tochild[0]);
	}
	close(fromchild[1]);
	close(tochild[0]);

	read(fromchild[0], &c, sizeof(c));

	tdb = tdb_open_ex("mutex-allrecord-block.tdb", 0,
			  tdb_flags, O_RDWR|O_CREAT, 0755,
			  &log_ctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	ret = tdb_chainlock_nonblock(tdb, key);
	ok(ret == -1, "tdb_chainlock_nonblock should not succeed");

	write(tochild[1], &c, sizeof(c));

	ret = tdb_chainlock(tdb, key);
	ok(ret == 0, "tdb_chainlock should not succeed");

	ret = tdb_chainunlock(tdb, key);
	ok(ret == 0, "tdb_chainunlock should succeed");

	wait_ret = wait(&status);
	ok(wait_ret == child, "child should have exited correctly");

	diag("done");
	return exit_status();
}
