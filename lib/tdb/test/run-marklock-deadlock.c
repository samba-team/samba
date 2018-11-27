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
#include "logging.h"

static TDB_DATA key, data;

static void do_chainlock(const char *name, int tdb_flags, int up, int down)
{
	struct tdb_context *tdb;
	int ret;
	ssize_t nread, nwritten;
	char c = 0;

	tdb = tdb_open_ex(name, 3, tdb_flags,
			  O_RDWR|O_CREAT, 0755, &taplogctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	ret = tdb_chainlock(tdb, key);
	ok(ret == 0, "tdb_chainlock should succeed");

	nwritten = write(up, &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(down, &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	exit(0);
}

static void do_allrecord_lock(const char *name, int tdb_flags, int up, int down)
{
	struct tdb_context *tdb;
	int ret;
	ssize_t nread, nwritten;
	char c = 0;

	tdb = tdb_open_ex(name, 3, tdb_flags,
			  O_RDWR|O_CREAT, 0755, &taplogctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	ret = tdb_allrecord_lock(tdb, F_WRLCK, TDB_LOCK_WAIT, false);
	ok(ret == 0, "tdb_allrecord_lock should succeed");

	nwritten = write(up, &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(down, &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	exit(0);
}

/* The code should barf on TDBs created with rwlocks. */
static int do_tests(const char *name, int tdb_flags)
{
	struct tdb_context *tdb;
	int ret;
	pid_t chainlock_child, allrecord_child;
	int chainlock_down[2];
	int chainlock_up[2];
	int allrecord_down[2];
	int allrecord_up[2];
	char c;
	ssize_t nread, nwritten;

	key.dsize = strlen("hi");
	key.dptr = discard_const_p(uint8_t, "hi");
	data.dsize = strlen("world");
	data.dptr = discard_const_p(uint8_t, "world");

	ret = pipe(chainlock_down);
	ok(ret == 0, "pipe should succeed");

	ret = pipe(chainlock_up);
	ok(ret == 0, "pipe should succeed");

	ret = pipe(allrecord_down);
	ok(ret == 0, "pipe should succeed");

	ret = pipe(allrecord_up);
	ok(ret == 0, "pipe should succeed");

	chainlock_child = fork();
	ok(chainlock_child != -1, "fork should succeed");

	if (chainlock_child == 0) {
		close(chainlock_up[0]);
		close(chainlock_down[1]);
		close(allrecord_up[0]);
		close(allrecord_up[1]);
		close(allrecord_down[0]);
		close(allrecord_down[1]);
		do_chainlock(name, tdb_flags,
			     chainlock_up[1], chainlock_down[0]);
		exit(0);
	}
	close(chainlock_up[1]);
	close(chainlock_down[0]);

	nread = read(chainlock_up[0], &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	/*
	 * Now we have a process holding a chainlock. Start another process
	 * trying the allrecord lock. This will block.
	 */

	allrecord_child = fork();
	ok(allrecord_child != -1, "fork should succeed");

	if (allrecord_child == 0) {
		close(chainlock_up[0]);
		close(chainlock_up[1]);
		close(chainlock_down[0]);
		close(chainlock_down[1]);
		close(allrecord_up[0]);
		close(allrecord_down[1]);
		do_allrecord_lock(name, tdb_flags,
				  allrecord_up[1], allrecord_down[0]);
		exit(0);
	}
	close(allrecord_up[1]);
	close(allrecord_down[0]);

	poll(NULL, 0, 500);

	tdb = tdb_open_ex(name, 3, tdb_flags,
			  O_RDWR|O_CREAT, 0755, &taplogctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	/*
	 * Someone already holds a chainlock, but we're able to get the
	 * freelist lock.
	 *
	 * The freelist lock/mutex is independent from the allrecord lock/mutex.
	 */

	ret = tdb_chainlock_nonblock(tdb, key);
	ok(ret == -1, "tdb_chainlock_nonblock should not succeed");

	ret = tdb_lock_nonblock(tdb, -1, F_WRLCK);
	ok(ret == 0, "tdb_lock_nonblock should succeed");

	ret = tdb_unlock(tdb, -1, F_WRLCK);
	ok(ret == 0, "tdb_unlock should succeed");

	/*
	 * We have someone else having done the lock for us. Just mark it.
	 */

	ret = tdb_chainlock_mark(tdb, key);
	ok(ret == 0, "tdb_chainlock_mark should succeed");

	/*
	 * The tdb_store below will block the freelist. In one version of the
	 * mutex patches, the freelist was already blocked here by the
	 * allrecord child, which was waiting for the chainlock child to give
	 * up its chainlock. Make sure that we don't run into this
	 * deadlock. To exercise the deadlock, just comment out the "ok"
	 * line.
	 *
	 * The freelist lock/mutex is independent from the allrecord lock/mutex.
	 */

	ret = tdb_lock_nonblock(tdb, -1, F_WRLCK);
	ok(ret == 0, "tdb_lock_nonblock should succeed");

	ret = tdb_unlock(tdb, -1, F_WRLCK);
	ok(ret == 0, "tdb_unlock should succeed");

	ret = tdb_store(tdb, key, data, TDB_INSERT);
	ok(ret == 0, "tdb_store should succeed");

	ret = tdb_chainlock_unmark(tdb, key);
	ok(ret == 0, "tdb_chainlock_unmark should succeed");

	nwritten = write(chainlock_down[1], &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(chainlock_up[0], &c, sizeof(c));
	ok(nread == 0, "read should succeed");

	nread = read(allrecord_up[0], &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	/*
	 * Someone already holds the allrecord lock, but we're able to get the
	 * freelist lock.
	 *
	 * The freelist lock/mutex is independent from the allrecord lock/mutex.
	 */

	ret = tdb_chainlock_nonblock(tdb, key);
	ok(ret == -1, "tdb_chainlock_nonblock should not succeed");

	ret = tdb_lockall_nonblock(tdb);
	ok(ret == -1, "tdb_lockall_nonblock should not succeed");

	ret = tdb_lock_nonblock(tdb, -1, F_WRLCK);
	ok(ret == 0, "tdb_lock_nonblock should succeed");

	ret = tdb_unlock(tdb, -1, F_WRLCK);
	ok(ret == 0, "tdb_unlock should succeed");

	/*
	 * We have someone else having done the lock for us. Just mark it.
	 */

	ret = tdb_lockall_mark(tdb);
	ok(ret == 0, "tdb_lockall_mark should succeed");

	ret = tdb_lock_nonblock(tdb, -1, F_WRLCK);
	ok(ret == 0, "tdb_lock_nonblock should succeed");

	ret = tdb_unlock(tdb, -1, F_WRLCK);
	ok(ret == 0, "tdb_unlock should succeed");

	ret = tdb_store(tdb, key, data, TDB_REPLACE);
	ok(ret == 0, "tdb_store should succeed");

	ret = tdb_lockall_unmark(tdb);
	ok(ret == 0, "tdb_lockall_unmark should succeed");

	nwritten = write(allrecord_down[1], &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(allrecord_up[0], &c, sizeof(c));
	ok(nread == 0, "read should succeed");

	close(chainlock_up[0]);
	close(chainlock_down[1]);
	close(allrecord_up[0]);
	close(allrecord_down[1]);
	diag("%s tests done", name);
	return exit_status();
}

int main(int argc, char *argv[])
{
	int ret;
	bool mutex_support;

	mutex_support = tdb_runtime_check_for_robust_mutexes();

	ret = do_tests("marklock-deadlock-fcntl.tdb",
		       TDB_CLEAR_IF_FIRST |
		       TDB_INCOMPATIBLE_HASH);
	ok(ret == 0, "marklock-deadlock-fcntl.tdb tests should succeed");

	if (!mutex_support) {
		skip(1, "No robust mutex support, "
			"skipping marklock-deadlock-mutex.tdb tests");
		return exit_status();
	}

	ret = do_tests("marklock-deadlock-mutex.tdb",
		       TDB_CLEAR_IF_FIRST |
		       TDB_MUTEX_LOCKING |
		       TDB_INCOMPATIBLE_HASH);
	ok(ret == 0, "marklock-deadlock-mutex.tdb tests should succeed");

	return exit_status();
}
