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
#include <poll.h>
#include <stdarg.h>

static TDB_DATA key, data;

static void log_void(struct tdb_context *tdb, enum tdb_debug_level level,
		     const char *fmt, ...)
{
}

static void log_fn(struct tdb_context *tdb, enum tdb_debug_level level,
		   const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static int do_child(int fd)
{
	struct tdb_context *tdb;
	unsigned int log_count;
	struct tdb_logging_context log_ctx = { log_fn, &log_count };
	struct tdb_logging_context nolog_ctx = { log_void, NULL };
	char c;

	read(fd, &c, 1);

	tdb = tdb_open_ex("mutex-openflags2.tdb", 0,
			  TDB_DEFAULT,
			  O_RDWR|O_CREAT, 0755, &nolog_ctx, NULL);
	ok((tdb == NULL) && (errno == EINVAL), "TDB_DEFAULT without "
	   "TDB_MUTEX_LOCKING should fail with EINVAL - %d", errno);

	tdb = tdb_open_ex("mutex-openflags2.tdb", 0,
			  TDB_CLEAR_IF_FIRST,
			  O_RDWR|O_CREAT, 0755, &nolog_ctx, NULL);
	ok((tdb == NULL) && (errno == EINVAL), "TDB_CLEAR_IF_FIRST without "
	   "TDB_MUTEX_LOCKING should fail with EINVAL - %d", errno);

	tdb = tdb_open_ex("mutex-openflags2.tdb", 0,
			  TDB_CLEAR_IF_FIRST |
			  TDB_MUTEX_LOCKING |
			  TDB_INTERNAL,
			  O_RDWR|O_CREAT, 0755, &nolog_ctx, NULL);
	ok((tdb == NULL) && (errno == EINVAL), "TDB_MUTEX_LOCKING with "
	   "TDB_INTERNAL should fail with EINVAL - %d", errno);

	tdb = tdb_open_ex("mutex-openflags2.tdb", 0,
			  TDB_CLEAR_IF_FIRST |
			  TDB_MUTEX_LOCKING |
			  TDB_NOMMAP,
			  O_RDWR|O_CREAT, 0755, &nolog_ctx, NULL);
	ok((tdb == NULL) && (errno == EINVAL), "TDB_MUTEX_LOCKING with "
	   "TDB_NOMMAP should fail with EINVAL - %d", errno);

	tdb = tdb_open_ex("mutex-openflags2.tdb", 0,
			  TDB_CLEAR_IF_FIRST |
			  TDB_MUTEX_LOCKING,
			  O_RDONLY, 0755, &nolog_ctx, NULL);
	ok((tdb != NULL), "TDB_MUTEX_LOCKING with "
	   "O_RDONLY should work - %d", errno);
	tdb_close(tdb);

	tdb = tdb_open_ex("mutex-openflags2.tdb", 0,
			  TDB_CLEAR_IF_FIRST |
			  TDB_MUTEX_LOCKING,
			  O_RDWR|O_CREAT, 0755, &log_ctx, NULL);
	ok((tdb != NULL), "TDB_MUTEX_LOCKING with TDB_CLEAR_IF_FIRST"
	   "TDB_NOMMAP should work - %d", errno);

	return 0;
}

/* The code should barf on TDBs created with rwlocks. */
int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	unsigned int log_count;
	struct tdb_logging_context log_ctx = { log_fn, &log_count };
	struct tdb_logging_context nolog_ctx = { log_void, NULL };
	int ret, status;
	pid_t child, wait_ret;
	int pipefd[2];
	char c = 0;
	bool runtime_support;

	runtime_support = tdb_runtime_check_for_robust_mutexes();

	ret = pipe(pipefd);
	ok1(ret == 0);

	key.dsize = strlen("hi");
	key.dptr = discard_const_p(uint8_t, "hi");
	data.dsize = strlen("world");
	data.dptr = discard_const_p(uint8_t, "world");

	if (!runtime_support) {
		tdb = tdb_open_ex("mutex-openflags2.tdb", 0,
				  TDB_CLEAR_IF_FIRST|
				  TDB_MUTEX_LOCKING,
				  O_RDWR|O_CREAT, 0755, &nolog_ctx, NULL);
		ok((tdb == NULL) && (errno == ENOSYS), "TDB_MUTEX_LOCKING without "
		   "runtime support should fail with ENOSYS - %d", errno);

		skip(1, "No robust mutex support");
		return exit_status();
	}

	child = fork();
	if (child == 0) {
		return do_child(pipefd[0]);
	}

	tdb = tdb_open_ex("mutex-openflags2.tdb", 0,
			  TDB_CLEAR_IF_FIRST|
			  TDB_MUTEX_LOCKING,
			  O_RDWR|O_CREAT, 0755, &log_ctx, NULL);
	ok((tdb != NULL), "tdb_open_ex with mutexes should succeed");

	write(pipefd[1], &c, 1);

	wait_ret = wait(&status);
	ok((wait_ret == child) && (status == 0),
	   "child should have exited correctly");

	diag("done");
	return exit_status();
}
