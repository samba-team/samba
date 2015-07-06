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

static void do_allrecord_lock(const char *name, int tdb_flags, int up,
			      int down)
{
	struct tdb_context *tdb;
	int ret;
	ssize_t nread, nwritten;
	char c = 0;

	tdb = tdb_open_ex(name, 3, tdb_flags,
			  O_RDWR|O_CREAT, 0755, &taplogctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	ret = tdb_lockall(tdb);
	ok(ret == 0, "tdb_lockall should succeed");

	nwritten = write(up, &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(down, &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	ret = tdb_traverse(tdb, NULL, NULL);
	ok(ret == -1, "do_allrecord_lock: traverse should fail");

	nwritten = write(up, &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	exit(0);
}

static void do_traverse(const char *name, int tdb_flags, int up, int down)
{
	struct tdb_context *tdb;
	int ret;
	ssize_t nread, nwritten;
	char c = 0;

	tdb = tdb_open_ex(name, 3, tdb_flags,
			  O_RDWR|O_CREAT, 0755, &taplogctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	ret = tdb_traverse(tdb, NULL, NULL);
	ok(ret == 1, "do_traverse: tdb_traverse should return 1 record");

	nwritten = write(up, &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(down, &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	exit(0);
}

/*
 * Process 1: get the allrecord_lock on a tdb.
 * Process 2: start a traverse, this will stall waiting for the
 *            first chainlock: That is taken by the allrecord_lock
 * Process 1: start a traverse: This will get EDEADLK in trying to
 *            get the TRANSACTION_LOCK. It will deadlock for mutexes,
 *            which don't have built-in deadlock detection.
 */

static int do_tests(const char *name, int tdb_flags)
{
	struct tdb_context *tdb;
	int ret;
	pid_t traverse_child, allrecord_child;
	int traverse_down[2];
	int traverse_up[2];
	int allrecord_down[2];
	int allrecord_up[2];
	char c;
	ssize_t nread, nwritten;
	TDB_DATA key, data;

	key.dsize = strlen("hi");
	key.dptr = discard_const_p(uint8_t, "hi");
	data.dsize = strlen("world");
	data.dptr = discard_const_p(uint8_t, "world");

	tdb = tdb_open_ex(name, 3, tdb_flags,
			  O_RDWR|O_CREAT, 0755, &taplogctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	ret = tdb_store(tdb, key, data, TDB_INSERT);
	ok(ret == 0, "tdb_store should succeed");

	ret = pipe(traverse_down);
	ok(ret == 0, "pipe should succeed");

	ret = pipe(traverse_up);
	ok(ret == 0, "pipe should succeed");

	ret = pipe(allrecord_down);
	ok(ret == 0, "pipe should succeed");

	ret = pipe(allrecord_up);
	ok(ret == 0, "pipe should succeed");

	allrecord_child = fork();
	ok(allrecord_child != -1, "fork should succeed");

	if (allrecord_child == 0) {
		tdb_close(tdb);
		close(traverse_up[0]);
		close(traverse_up[1]);
		close(traverse_down[0]);
		close(traverse_down[1]);
		close(allrecord_up[0]);
		close(allrecord_down[1]);
		do_allrecord_lock(name, tdb_flags,
				  allrecord_up[1], allrecord_down[0]);
		exit(0);
	}
	close(allrecord_up[1]);
	close(allrecord_down[0]);

	nread = read(allrecord_up[0], &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	traverse_child = fork();
	ok(traverse_child != -1, "fork should succeed");

	if (traverse_child == 0) {
		tdb_close(tdb);
		close(traverse_up[0]);
		close(traverse_down[1]);
		close(allrecord_up[0]);
		close(allrecord_down[1]);
		do_traverse(name, tdb_flags,
			    traverse_up[1], traverse_down[0]);
		exit(0);
	}
	close(traverse_up[1]);
	close(traverse_down[0]);

	poll(NULL, 0, 1000);

	nwritten = write(allrecord_down[1], &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(traverse_up[0], &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	nwritten = write(traverse_down[1], &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(allrecord_up[0], &c, sizeof(c));
	ok(nread == sizeof(c), "ret should succeed");

	close(traverse_up[0]);
	close(traverse_down[1]);
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
