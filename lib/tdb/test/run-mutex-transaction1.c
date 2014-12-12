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

	tdb = tdb_open_ex("mutex-transaction1.tdb", 3, tdb_flags,
			  O_RDWR|O_CREAT, 0755, &log_ctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	ret = tdb_transaction_start(tdb);
	ok(ret == 0, "tdb_transaction_start should succeed");

	ret = tdb_store(tdb, key, data, TDB_INSERT);
	ok(ret == 0, "tdb_store(tdb, key, data, TDB_INSERT) should succeed");

	write(to, &c, sizeof(c));
	read(from, &c, sizeof(c));

	ret = tdb_transaction_cancel(tdb);
	ok(ret == 0, "tdb_transaction_cancel should succeed");

	write(to, &c, sizeof(c));
	read(from, &c, sizeof(c));

	ret = tdb_transaction_start(tdb);
	ok(ret == 0, "tdb_transaction_start should succeed");

	ret = tdb_store(tdb, key, data, TDB_INSERT);
	ok(ret == 0, "tdb_store(tdb, key, data, TDB_INSERT) should succeed");

	write(to, &c, sizeof(c));
	read(from, &c, sizeof(c));

	ret = tdb_transaction_commit(tdb);
	ok(ret == 0, "tdb_transaction_commit should succeed");

	write(to, &c, sizeof(c));
	read(from, &c, sizeof(c));

	ret = tdb_transaction_start(tdb);
	ok(ret == 0, "tdb_transaction_start should succeed");

	ret = tdb_store(tdb, key, key, TDB_REPLACE);
	ok(ret == 0, "tdb_store(tdb, key, data, TDB_REPLACE) should succeed");

	write(to, &c, sizeof(c));
	read(from, &c, sizeof(c));

	ret = tdb_transaction_commit(tdb);
	ok(ret == 0, "tdb_transaction_commit should succeed");

	write(to, &c, sizeof(c));
	read(from, &c, sizeof(c));

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
	TDB_DATA val;
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

	tdb = tdb_open_ex("mutex-transaction1.tdb", 0,
			  tdb_flags, O_RDWR|O_CREAT, 0755,
			  &log_ctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	/*
	 * The child has the transaction running
	 */
	ret = tdb_transaction_start_nonblock(tdb);
	ok(ret == -1, "tdb_transaction_start_nonblock not succeed");

	ret = tdb_chainlock_nonblock(tdb, key);
	ok(ret == -1, "tdb_chainlock_nonblock should not succeed");

	/*
	 * We can still read
	 */
	ret = tdb_exists(tdb, key);
	ok(ret == 0, "tdb_exists(tdb, key) should return 0");

	val = tdb_fetch(tdb, key);
	ok(val.dsize == 0, "tdb_fetch(tdb, key) should return an empty value");

	write(tochild[1], &c, sizeof(c));

	/*
	 * When the child canceled we can start...
	 */
	ret = tdb_transaction_start(tdb);
	ok(ret == 0, "tdb_transaction_start should succeed");

	read(fromchild[0], &c, sizeof(c));
	write(tochild[1], &c, sizeof(c));

	ret = tdb_transaction_cancel(tdb);
	ok(ret == 0, "tdb_transaction_cancel should succeed");

	/*
	 * When we canceled the child can start and store...
	 */
	read(fromchild[0], &c, sizeof(c));

	/*
	 * We still see the old values before the child commits...
	 */
	ret = tdb_exists(tdb, key);
	ok(ret == 0, "tdb_exists(tdb, key) should return 0");

	val = tdb_fetch(tdb, key);
	ok(val.dsize == 0, "tdb_fetch(tdb, key) should return an empty value");

	write(tochild[1], &c, sizeof(c));
	read(fromchild[0], &c, sizeof(c));

	/*
	 * We see the new values after the commit...
	 */
	ret = tdb_exists(tdb, key);
	ok(ret == 1, "tdb_exists(tdb, key) should return 1");

	val = tdb_fetch(tdb, key);
	ok(val.dsize != 0, "tdb_fetch(tdb, key) should return a value");
	ok(val.dsize == data.dsize, "tdb_fetch(tdb, key) should return a value");
	ok(memcmp(val.dptr, data.dptr, data.dsize) == 0, "tdb_fetch(tdb, key) should return a value");

	write(tochild[1], &c, sizeof(c));
	read(fromchild[0], &c, sizeof(c));

	/*
	 * The child started a new transaction and replaces the value,
	 * but we still see the old values before the child commits...
	 */
	ret = tdb_exists(tdb, key);
	ok(ret == 1, "tdb_exists(tdb, key) should return 1");

	val = tdb_fetch(tdb, key);
	ok(val.dsize != 0, "tdb_fetch(tdb, key) should return a value");
	ok(val.dsize == data.dsize, "tdb_fetch(tdb, key) should return a value");
	ok(memcmp(val.dptr, data.dptr, data.dsize) == 0, "tdb_fetch(tdb, key) should return a value");

	write(tochild[1], &c, sizeof(c));
	read(fromchild[0], &c, sizeof(c));

	/*
	 * We see the new values after the commit...
	 */
	ret = tdb_exists(tdb, key);
	ok(ret == 1, "tdb_exists(tdb, key) should return 1");

	val = tdb_fetch(tdb, key);
	ok(val.dsize != 0, "tdb_fetch(tdb, key) should return a value");
	ok(val.dsize == key.dsize, "tdb_fetch(tdb, key) should return a value");
	ok(memcmp(val.dptr, key.dptr, key.dsize) == 0, "tdb_fetch(tdb, key) should return a value");

	write(tochild[1], &c, sizeof(c));

	wait_ret = wait(&status);
	ok(wait_ret == child, "child should have exited correctly");

	diag("done");
	return exit_status();
}
