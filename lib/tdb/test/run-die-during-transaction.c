#include "../common/tdb_private.h"
#include "lock-tracking.h"
static ssize_t pwrite_check(int fd, const void *buf, size_t count, off_t offset);
static ssize_t write_check(int fd, const void *buf, size_t count);
static int ftruncate_check(int fd, off_t length);

#define pwrite pwrite_check
#define write write_check
#define fcntl fcntl_with_lockcheck
#define ftruncate ftruncate_check

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
#include <stdbool.h>
#include <stdarg.h>
#include <setjmp.h>
#include "external-agent.h"
#include "logging.h"

#undef write
#undef pwrite
#undef fcntl
#undef ftruncate

static bool in_transaction;
static int target, current;
static jmp_buf jmpbuf;
#define TEST_DBNAME "run-die-during-transaction.tdb"
#define KEY_STRING "helloworld"

static void maybe_die(int fd)
{
	if (in_transaction && current++ == target) {
		longjmp(jmpbuf, 1);
	}
}

static ssize_t pwrite_check(int fd,
			    const void *buf, size_t count, off_t offset)
{
	ssize_t ret;

	maybe_die(fd);

	ret = pwrite(fd, buf, count, offset);
	if (ret != count)
		return ret;

	maybe_die(fd);
	return ret;
}

static ssize_t write_check(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	maybe_die(fd);

	ret = write(fd, buf, count);
	if (ret != count)
		return ret;

	maybe_die(fd);
	return ret;
}

static int ftruncate_check(int fd, off_t length)
{
	int ret;

	maybe_die(fd);

	ret = ftruncate(fd, length);

	maybe_die(fd);
	return ret;
}

static bool test_death(enum operation op, struct agent *agent)
{
	struct tdb_context *tdb = NULL;
	TDB_DATA key;
	enum agent_return ret;
	int needed_recovery = 0;

	current = target = 0;
reset:
	unlink(TEST_DBNAME);
	tdb = tdb_open_ex(TEST_DBNAME, 1024, TDB_NOMMAP,
			  O_CREAT|O_TRUNC|O_RDWR, 0600, &taplogctx, NULL);

	if (setjmp(jmpbuf) != 0) {
		/* We're partway through.  Simulate our death. */
		close(tdb->fd);
		forget_locking();
		in_transaction = false;

		ret = external_agent_operation(agent, NEEDS_RECOVERY, "");
		if (ret == SUCCESS)
			needed_recovery++;
		else if (ret != FAILED) {
			diag("Step %u agent NEEDS_RECOVERY = %s", current,
			     agent_return_name(ret));
			return false;
		}

		ret = external_agent_operation(agent, op, KEY_STRING);
		if (ret != SUCCESS) {
			diag("Step %u op %s failed = %s", current,
			     operation_name(op),
			     agent_return_name(ret));
			return false;
		}

		ret = external_agent_operation(agent, NEEDS_RECOVERY, "");
		if (ret != FAILED) {
			diag("Still needs recovery after step %u = %s",
			     current, agent_return_name(ret));
			return false;
		}

		ret = external_agent_operation(agent, CHECK, "");
		if (ret != SUCCESS) {
			diag("Step %u check failed = %s", current,
			     agent_return_name(ret));
			return false;
		}

		ret = external_agent_operation(agent, CLOSE, "");
		if (ret != SUCCESS) {
			diag("Step %u close failed = %s", current,
			     agent_return_name(ret));
			return false;
		}

		/* Suppress logging as this tries to use closed fd. */
		suppress_logging = true;
		suppress_lockcheck = true;
		tdb_close(tdb);
		suppress_logging = false;
		suppress_lockcheck = false;
		target++;
		current = 0;
		goto reset;
	}

	/* Put key for agent to fetch. */
	key.dsize = strlen(KEY_STRING);
	key.dptr = discard_const_p(uint8_t, KEY_STRING);
	if (tdb_store(tdb, key, key, TDB_INSERT) != 0)
		return false;

	/* This is the key we insert in transaction. */
	key.dsize--;

	ret = external_agent_operation(agent, OPEN, TEST_DBNAME);
	if (ret != SUCCESS) {
		fprintf(stderr, "Agent failed to open: %s\n",
			agent_return_name(ret));
		exit(1);
	}

	ret = external_agent_operation(agent, FETCH, KEY_STRING);
	if (ret != SUCCESS) {
		fprintf(stderr, "Agent failed find key: %s\n",
			agent_return_name(ret));
		exit(1);
	}

	in_transaction = true;
	if (tdb_transaction_start(tdb) != 0)
		return false;

	if (tdb_store(tdb, key, key, TDB_INSERT) != 0)
		return false;

	if (tdb_transaction_commit(tdb) != 0)
		return false;

	in_transaction = false;

	/* We made it! */
	diag("Completed %u runs", current);
	tdb_close(tdb);
	ret = external_agent_operation(agent, CLOSE, "");
	if (ret != SUCCESS) {
		diag("Step %u close failed = %s", current,
		     agent_return_name(ret));
		return false;
	}

#ifdef HAVE_INCOHERENT_MMAP
	/* This means we always mmap, which makes this test a noop. */
	ok1(1);
#else
	ok1(needed_recovery);
#endif
	ok1(locking_errors == 0);
	ok1(forget_locking() == 0);
	locking_errors = 0;
	return true;
}

int main(int argc, char *argv[])
{
	enum operation ops[] = { FETCH, STORE, TRANSACTION_START };
	struct agent *agent;
	int i;

	plan_tests(12);
	unlock_callback = maybe_die;

	agent = prepare_external_agent();

	for (i = 0; i < sizeof(ops)/sizeof(ops[0]); i++) {
		diag("Testing %s after death", operation_name(ops[i]));
		ok1(test_death(ops[i], agent));
	}

	return exit_status();
}
