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

	ret = tdb_chainlock_read(tdb, key);
	ok(ret == 0, "tdb_chainlock_read should succeed");

	nwritten = write(up, &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(down, &c, sizeof(c));
	ok(nread == 0, "read should succeed");

	exit(0);
}

static void do_trylock(const char *name, int tdb_flags, int up, int down)
{
	struct tdb_context *tdb;
	int ret;
	ssize_t nread, nwritten;
	char c = 0;

	tdb = tdb_open_ex(name, 3, tdb_flags,
			  O_RDWR|O_CREAT, 0755, &taplogctx, NULL);
	ok(tdb, "tdb_open_ex should succeed");

	/*
	 * tdb used to have a bug where with fcntl locks an upgrade
	 * from a readlock to writelock did not check for the
	 * underlying fcntl lock. Mutexes don't distinguish between
	 * readlocks and writelocks, so that bug does not apply here.
	 */

	ret = tdb_chainlock_read(tdb, key);
	ok(ret == 0, "tdb_chainlock_read should succeed");

	ret = tdb_chainlock_nonblock(tdb, key);
	ok(ret == -1, "tdb_chainlock_nonblock should fail");

	nwritten = write(up, &c, sizeof(c));
	ok(nwritten == sizeof(c), "write should succeed");

	nread = read(down, &c, sizeof(c));
	ok(nread == 0, "read should succeed");

	exit(0);
}

static int do_tests(const char *name, int tdb_flags)
{
	int ret;
	pid_t chainlock_child, store_child;
	int chainlock_down[2];
	int chainlock_up[2];
	int store_down[2];
	int store_up[2];
	char c;
	ssize_t nread;

	key.dsize = strlen("hi");
	key.dptr = discard_const_p(uint8_t, "hi");
	data.dsize = strlen("world");
	data.dptr = discard_const_p(uint8_t, "world");

	ret = pipe(chainlock_down);
	ok(ret == 0, "pipe should succeed");

	ret = pipe(chainlock_up);
	ok(ret == 0, "pipe should succeed");

	ret = pipe(store_down);
	ok(ret == 0, "pipe should succeed");

	ret = pipe(store_up);
	ok(ret == 0, "pipe should succeed");

	chainlock_child = fork();
	ok(chainlock_child != -1, "fork should succeed");

	if (chainlock_child == 0) {
		close(chainlock_up[0]);
		close(chainlock_down[1]);
		close(store_up[0]);
		close(store_up[1]);
		close(store_down[0]);
		close(store_down[1]);
		do_chainlock(name, tdb_flags,
			     chainlock_up[1], chainlock_down[0]);
		exit(0);
	}
	close(chainlock_up[1]);
	close(chainlock_down[0]);

	nread = read(chainlock_up[0], &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	/*
	 * Now we have a process holding a chain read lock. Start
	 * another process trying to write lock. This should fail.
	 */

	store_child = fork();
	ok(store_child != -1, "fork should succeed");

	if (store_child == 0) {
		close(chainlock_up[0]);
		close(chainlock_down[1]);
		close(store_up[0]);
		close(store_down[1]);
		do_trylock(name, tdb_flags,
			   store_up[1], store_down[0]);
		exit(0);
	}
	close(store_up[1]);
	close(store_down[0]);

	nread = read(store_up[0], &c, sizeof(c));
	ok(nread == sizeof(c), "read should succeed");

	close(chainlock_up[0]);
	close(chainlock_down[1]);
	close(store_up[0]);
	close(store_down[1]);
	diag("%s tests done", name);
	return exit_status();
}

int main(int argc, char *argv[])
{
	int ret;

	ret = do_tests("rdlock-upgrade.tdb",
		       TDB_CLEAR_IF_FIRST |
		       TDB_INCOMPATIBLE_HASH);
	ok(ret == 0, "rdlock-upgrade.tdb tests should succeed");

	return exit_status();
}
