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
#include "external-agent.h"
#include "logging.h"

#undef write
#undef pwrite
#undef fcntl
#undef ftruncate

static int target, current;
#define TEST_DBNAME "run-mutex-die.tdb"
#define KEY_STRING "helloworld"

static void maybe_die(int fd)
{
	if (target == 0) {
		return;
	}
	current += 1;
	if (current == target) {
		_exit(1);
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

static enum agent_return flakey_ops(struct agent *a)
{
	enum agent_return ret;

	/*
	 * Run in the external agent child
	 */

	ret = external_agent_operation(a, OPEN_WITH_CLEAR_IF_FIRST, TEST_DBNAME);
	if (ret != SUCCESS) {
		fprintf(stderr, "Agent failed to open: %s\n",
			agent_return_name(ret));
		return ret;
	}
	ret = external_agent_operation(a, UNMAP, "");
	if (ret != SUCCESS) {
		fprintf(stderr, "Agent failed to unmap: %s\n",
			agent_return_name(ret));
		return ret;
	}
	ret = external_agent_operation(a, STORE, "xyz");
	if (ret != SUCCESS) {
		fprintf(stderr, "Agent failed to store: %s\n",
			agent_return_name(ret));
		return ret;
	}
	ret = external_agent_operation(a, STORE, KEY_STRING);
	if (ret != SUCCESS) {
		fprintf(stderr, "Agent failed store: %s\n",
			agent_return_name(ret));
		return ret;
	}
	ret = external_agent_operation(a, FETCH, KEY_STRING);
	if (ret != SUCCESS) {
		fprintf(stderr, "Agent failed find key: %s\n",
			agent_return_name(ret));
		return ret;
	}
	ret = external_agent_operation(a, PING, "");
	if (ret != SUCCESS) {
		fprintf(stderr, "Agent failed ping: %s\n",
			agent_return_name(ret));
		return ret;
	}
	return ret;
}

static bool prep_db(void) {
	struct tdb_context *tdb;
	TDB_DATA key;
	TDB_DATA data;

	key.dptr = discard_const_p(uint8_t, KEY_STRING);
	key.dsize = strlen((char *)key.dptr);
	data.dptr = discard_const_p(uint8_t, "foo");
	data.dsize = strlen((char *)data.dptr);

	unlink(TEST_DBNAME);

	tdb = tdb_open_ex(
		TEST_DBNAME, 2,
		TDB_INCOMPATIBLE_HASH|TDB_MUTEX_LOCKING|TDB_CLEAR_IF_FIRST,
		O_CREAT|O_TRUNC|O_RDWR, 0600, &taplogctx, NULL);
	if (tdb == NULL) {
		return false;
	}

	if (tdb_store(tdb, key, data, TDB_INSERT) != 0) {
		return false;
	}

	tdb_close(tdb);
	tdb = NULL;

	forget_locking();

	return true;
}

static bool test_db(void) {
	struct tdb_context *tdb;
	int ret;

	tdb = tdb_open_ex(
		TEST_DBNAME, 1024, TDB_INCOMPATIBLE_HASH,
		O_RDWR, 0600, &taplogctx, NULL);

	if (tdb == NULL) {
		perror("tdb_open_ex failed");
		return false;
	}

	ret = tdb_traverse(tdb, NULL, NULL);
	if (ret == -1) {
		perror("traverse failed");
		goto fail;
	}

	tdb_close(tdb);

	forget_locking();

	return true;

fail:
	tdb_close(tdb);
	return false;
}

static bool test_one(void)
{
	enum agent_return ret;

	ret = AGENT_DIED;
	target = 19;

	while (ret != SUCCESS) {
		struct agent *agent;

		{
			int child_target = target;
			bool pret;
			target = 0;
			pret = prep_db();
			ok1(pret);
			target = child_target;
		}

		agent = prepare_external_agent();

		ret = flakey_ops(agent);

		diag("Agent (target=%d) returns %s",
		     target, agent_return_name(ret));

		if (ret == SUCCESS) {
			ok((target > 19), "At least one AGENT_DIED expected");
		} else {
			ok(ret == AGENT_DIED, "AGENT_DIED expected");
		}

		shutdown_agent(agent);

		{
			int child_target = target;
			bool tret;
			target = 0;
			tret = test_db();
			ok1(tret);
			target = child_target;
		}

		target += 1;
	}

	return true;
}

int main(int argc, char *argv[])
{
	bool ret;
	bool runtime_support;

	runtime_support = tdb_runtime_check_for_robust_mutexes();

	if (!runtime_support) {
		skip(1, "No robust mutex support");
		return exit_status();
	}

	plan_tests(12);
	unlock_callback = maybe_die;

	ret = test_one();
	ok1(ret);

	diag("done");
	return exit_status();
}
