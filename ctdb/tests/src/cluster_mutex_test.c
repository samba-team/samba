/*
   CTDB cluster mutex test

   Copyright (C) Martin Schwenke  2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "system/wait.h"

#include <assert.h>

#include <talloc.h>
#include <tevent.h>

#include "lib/util/util.h"

/*
 * ctdb_cluster_mutex.c is included below.  This requires a few hacks...
 */

/* Avoid inclusion of ctdb_private.h */
#define _CTDB_PRIVATE_H

/* Fake ctdb_context */
struct ctdb_context {
	struct tevent_context *ev;
};

/*
 * ctdb_fork() and ctdb_kill() are used in ctdb_cluster_mutex.c for
 * safer tracking of PIDs.  Fake them here to avoid dragging in the
 * world.
 */

static pid_t ctdb_fork(struct ctdb_context *ctdb)
{
	return fork();
}

static int ctdb_kill(struct ctdb_context *ctdb, pid_t pid, int signum)
{
	/*
	 * Tests need to wait for the child to exit to ensure that the
	 * lock really has been released.  The PID is only accessible
	 * in ctdb_cluster_mutex.c, so make a best attempt to ensure
	 * that the child process is waited for after it is killed.
	 * Avoid waiting if the process is already gone.
	 */
	int ret;

	if (signum == 0) {
		return kill(pid, signum);
	}

	ret = kill(pid, signum);
	waitpid(pid, NULL, 0);

	return ret;
}

#include "server/ctdb_cluster_mutex.c"

/*
 * Mutex testing support
 */

struct mutex_handle {
	bool done;
	bool locked;
	struct ctdb_cluster_mutex_handle *h;
};

struct do_lock_context {
	struct mutex_handle *mh;
	struct ctdb_context *ctdb;
};

static void do_lock_handler(char status, double latency, void *private_data)
{
	struct do_lock_context *dl = talloc_get_type_abort(
		private_data, struct do_lock_context);
	struct mutex_handle *mh;

	assert(dl->mh != NULL);
	mh = dl->mh;

	mh->locked = (status == '0') ;

	/*
	 * If unsuccessful then ensure the process has exited and that
	 * the file descriptor event handler has been cancelled
	 */
	if (! mh->locked) {
		TALLOC_FREE(mh->h);
	}

	switch (status) {
	case '0':
		printf("LOCK\n");
		break;

	case '1':
		printf("CONTENTION\n");
		break;

	case '2':
		printf("TIMEOUT\n");
		break;

	default:
		printf("ERROR\n");
	}

	fflush(stdout);
	mh->done = true;
}

static void do_lock_lost_handler(void *private_data)
{
	struct do_lock_context *dl = talloc_get_type_abort(
		private_data, struct do_lock_context);

	printf("LOST\n");
	fflush(stdout);
	TALLOC_FREE(dl->mh);
}

static void do_lock_take(struct do_lock_context *dl,
			 const char *mutex_string)
{
	struct ctdb_cluster_mutex_handle *h;

	dl->mh = talloc_zero(dl, struct mutex_handle);
	assert(dl->mh != NULL);

	h = ctdb_cluster_mutex(dl->mh,
			       dl->ctdb,
			       mutex_string,
			       120,
			       do_lock_handler,
			       dl,
			       do_lock_lost_handler,
			       dl);
	assert(h != NULL);

	dl->mh->h = h;
}

static void do_lock_wait_done(struct do_lock_context *dl)
{
	assert(dl->mh != NULL);

	while (! dl->mh->done) {
		tevent_loop_once(dl->ctdb->ev);
	}
}

static void do_lock_check(struct do_lock_context *dl)
{
	assert(dl->mh != NULL);

	if (! dl->mh->locked) {
		printf("NOLOCK\n");
		fflush(stdout);
		TALLOC_FREE(dl->mh);
	}
}

static void do_lock(struct do_lock_context *dl,
		    const char *mutex_string)
{
	do_lock_take(dl, mutex_string);

	do_lock_wait_done(dl);

	do_lock_check(dl);
}

static void do_unlock(struct do_lock_context *dl)
{
	if (dl->mh == NULL) {
		return;
	}

	if (! dl->mh->done) {
		/*
		 * Taking of lock still in progress.  Free the cluster
		 * mutex handle to release it but leave the lock
		 * handle in place to allow taking of the lock to
		 * fail.
		 */
		printf("CANCEL\n");
		fflush(stdout);
		TALLOC_FREE(dl->mh->h);
		dl->mh->done = true;
		dl->mh->locked = false;
		return;
	}

	printf("UNLOCK\n");
	fflush(stdout);
	TALLOC_FREE(dl->mh);
}

static void wait_handler(struct tevent_context *ev,
			 struct tevent_timer *te,
			 struct timeval t,
			 void *private_data)
{
	bool *done = (bool *)private_data;

	*done = true;
}

static void do_lock_wait_time(struct do_lock_context *dl,
			      unsigned long wait_time)
{
	struct tevent_timer *tt;
	bool done = false;

	tt = tevent_add_timer(dl->ctdb->ev,
			      dl,
			      tevent_timeval_current_ofs(wait_time, 0),
			      wait_handler,
			      &done);
	assert(tt != NULL);

	while (! done) {
		tevent_loop_once(dl->ctdb->ev);
	}
}

/*
 * Testcases
 */

static void test_lock_unlock(TALLOC_CTX *mem_ctx,
			     struct ctdb_context *ctdb,
			     const char *mutex_string)
{
	struct do_lock_context *dl;

	dl = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl != NULL);
	dl->ctdb = ctdb;

	/* LOCK */
	do_lock(dl, mutex_string);
	assert(dl->mh != NULL);

	/* UNLOCK */
	do_unlock(dl);
	assert(dl->mh == NULL);
}

static void test_lock_lock_unlock(TALLOC_CTX *mem_ctx,
				  struct ctdb_context *ctdb,
				  const char *mutex_string)
{
	struct do_lock_context *dl1;
	struct do_lock_context *dl2;

	dl1 = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl1 != NULL);
	dl1->ctdb = ctdb;

	dl2 = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl2 != NULL);
	dl2->ctdb = ctdb;

	/* LOCK */
	do_lock(dl1, mutex_string);
	assert(dl1->mh != NULL);

	/* CONTENTION */
	do_lock(dl2, mutex_string);
	assert(dl2->mh == NULL);

	/* UNLOCK */
	do_unlock(dl1);
	assert(dl1->mh == NULL);
}

static void test_lock_unlock_lock_unlock(TALLOC_CTX *mem_ctx,
					 struct ctdb_context *ctdb,
					 const char *mutex_string)
{
	struct do_lock_context *dl1;
	struct do_lock_context *dl2;

	dl1 = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl1 != NULL);
	dl1->ctdb = ctdb;

	dl2 = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl2 != NULL);
	dl2->ctdb = ctdb;

	/* LOCK */
	do_lock(dl1, mutex_string);
	assert(dl1->mh != NULL);

	/* UNLOCK */
	do_unlock(dl1);
	assert(dl1->mh == NULL);

	/* LOCK */
	do_lock(dl2, mutex_string);
	assert(dl2->mh != NULL);

	/* UNLOCK */
	do_unlock(dl2);
	assert(dl2->mh == NULL);
}

static void test_lock_cancel_check(TALLOC_CTX *mem_ctx,
				   struct ctdb_context *ctdb,
				   const char *mutex_string)
{
	struct do_lock_context *dl;

	dl = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl != NULL);
	dl->ctdb = ctdb;

	do_lock_take(dl, mutex_string);
	assert(dl->mh != NULL);

	/* CANCEL */
	do_unlock(dl);
	assert(dl->mh != NULL);

	do_lock_wait_done(dl);

	/* NOLOCK */
	do_lock_check(dl);
	assert(dl->mh == NULL);
}

static void test_lock_cancel_unlock(TALLOC_CTX *mem_ctx,
				    struct ctdb_context *ctdb,
				    const char *mutex_string)
{
	struct do_lock_context *dl;

	dl = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl != NULL);
	dl->ctdb = ctdb;

	do_lock_take(dl, mutex_string);
	assert(dl->mh != NULL);

	/* CANCEL */
	do_unlock(dl);
	assert(dl->mh != NULL);

	do_lock_wait_done(dl);

	/* UNLOCK */
	do_unlock(dl);
	assert(dl->mh == NULL);
}

static void test_lock_wait_unlock(TALLOC_CTX *mem_ctx,
				  struct ctdb_context *ctdb,
				  const char *mutex_string)
{
	struct do_lock_context *dl;

	dl = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl != NULL);
	dl->ctdb = ctdb;

	/* LOCK */
	do_lock(dl, mutex_string);
	assert(dl->mh != NULL);

	/* Wait for twice as long as the PPID timeout */
	do_lock_wait_time(dl, 2 * 5);
	assert(dl->mh != NULL);

	/* UNLOCK */
	do_unlock(dl);
	assert(dl->mh == NULL);
}

static void fd_done_handler(struct tevent_context *ev,
			    struct tevent_fd *fde,
			    uint16_t flags,
			    void *private_data)
{
	bool *done = (bool *)private_data;

	*done = true;
}

static void test_lock_ppid_gone_lock_unlock(TALLOC_CTX *mem_ctx,
					    struct ctdb_context *ctdb,
					    const char *mutex_string)
{
	struct do_lock_context *dl;
	struct tevent_fd *fde;
	int pipefd[2];
	int ret;
	pid_t pid, pid2;
	ssize_t nread;
	bool done;

	/*
	 * Do this in the parent - debugging aborts of the child is
	 * trickier
	 */
	dl = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl != NULL);
	dl->ctdb = ctdb;

	ret = pipe(pipefd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		ssize_t nwritten;

		close(pipefd[0]);

		/* LOCK */
		do_lock(dl, mutex_string);
		assert(dl->mh != NULL);

		/*
		 * Note that we never see corresponding LOST.  That
		 * would come from this process, but it is killed
		 * below.
		 */

		nwritten = write(pipefd[1], &ret, sizeof(ret));
		assert(nwritten == sizeof(ret));

		sleep(999);
		exit(1);
	}

	close(pipefd[1]);

	nread = read(pipefd[0], &ret, sizeof(ret));
	assert(nread == sizeof(ret));
	assert(ret == 0);

	/*
	 * pipefd[1] is leaked into the helper, so there will be an
	 * event generated when the helper exits
	 */
	done = false;
	fde = tevent_add_fd(ctdb->ev,
			    ctdb,
			    pipefd[0],
			    TEVENT_FD_READ,
			    fd_done_handler,
			    &done);
	assert(fde != NULL);

	ret = kill(pid, SIGKILL);
	assert(ret == 0);
	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);

	while (! done) {
		tevent_loop_once(ctdb->ev);
	}

	/* LOCK */
	do_lock(dl, mutex_string);
	assert(dl->mh != NULL);

	/* UNLOCK */
	do_unlock(dl);
	assert(dl->mh == NULL);
}

static void test_lock_file_removed_no_recheck(TALLOC_CTX *mem_ctx,
					      struct ctdb_context *ctdb,
					      const char *mutex_string,
					      const char *lock_file)
{
	struct do_lock_context *dl1;
	struct do_lock_context *dl2;
	int ret;

	dl1 = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl1 != NULL);
	dl1->ctdb = ctdb;

	dl2 = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl2 != NULL);
	dl2->ctdb = ctdb;

	/* LOCK */
	do_lock(dl1, mutex_string);
	assert(dl1->mh != NULL);

	ret = unlink(lock_file);
	assert(ret == 0);

	/* LOCK */
	do_lock(dl2, mutex_string);
	assert(dl2->mh != NULL);

	/* UNLOCK */
	do_unlock(dl2);
	assert(dl2->mh == NULL);

	/* UNLOCK */
	do_unlock(dl1);
	assert(dl1->mh == NULL);
}

static void test_lock_file_wait_recheck_unlock(TALLOC_CTX *mem_ctx,
					       struct ctdb_context *ctdb,
					       const char *mutex_string,
					       unsigned long wait_time)
{
	struct do_lock_context *dl;

	dl = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl != NULL);
	dl->ctdb = ctdb;

	/* LOCK */
	do_lock(dl, mutex_string);
	assert(dl->mh != NULL);

	do_lock_wait_time(dl, wait_time);
	assert(dl->mh != NULL);

	/* UNLOCK */
	do_unlock(dl);
	assert(dl->mh == NULL);
}

static void test_lock_file_removed(TALLOC_CTX *mem_ctx,
				   struct ctdb_context *ctdb,
				   const char *mutex_string,
				   const char *lock_file)
{
	struct do_lock_context *dl;
	int ret;

	dl = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl != NULL);
	dl->ctdb = ctdb;

	/* LOCK */
	do_lock(dl, mutex_string);
	assert(dl->mh != NULL);

	ret = unlink(lock_file);
	assert(ret == 0);

	while (dl->mh != NULL) {
		/* LOST */
		tevent_loop_once(ctdb->ev);
	}
}

static void test_lock_file_changed(TALLOC_CTX *mem_ctx,
				   struct ctdb_context *ctdb,
				   const char *mutex_string,
				   const char *lock_file)
{
	struct do_lock_context *dl;
	char *t;
	int fd;
	int ret;

	dl = talloc_zero(mem_ctx, struct do_lock_context);
	assert(dl != NULL);
	dl->ctdb = ctdb;

	/* LOCK */
	do_lock(dl, mutex_string);
	assert(dl->mh != NULL);

	t = talloc_asprintf(ctdb, "%s.new", lock_file);
	assert(t != NULL);

	fd = open(t, O_RDWR|O_CREAT, 0600);
	assert(fd != -1);
	close(fd);

	ret = rename(t, lock_file);
	assert(ret == 0);

	while (dl->mh != NULL) {
		/* LOST */
		tevent_loop_once(ctdb->ev);
	}
}

/*
 * Main
 */

static const char *prog;

static void usage(void)
{
	fprintf(stderr, "usage: %s <test> <mutex-string> [<arg>...]\n", prog);
	exit(1);
}

static void alarm_handler(int sig)
{
	abort();
}

int main(int argc, const char *argv[])
{
	TALLOC_CTX *mem_ctx;
	struct ctdb_context *ctdb;
	const char *mutex_string;
	const char *test;
	struct sigaction sa = { .sa_handler = NULL, };
	int ret;
	const char *lock_file;
	unsigned int wait_time;

	prog = argv[0];

	if (argc < 3) {
		usage();
	}

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb = talloc_zero(mem_ctx, struct ctdb_context);
	assert(ctdb != NULL);

	ctdb->ev = tevent_context_init(ctdb);
	assert(ctdb->ev != NULL);

	/* Add a 60s timeout for the whole test */
	sa.sa_handler = alarm_handler;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGALRM, &sa, NULL);
	assert(ret == 0);
	alarm(60);

	test = argv[1];
	mutex_string = argv[2];

	if (strcmp(test, "lock-unlock") == 0) {
		test_lock_unlock(mem_ctx, ctdb, mutex_string);
	} else if (strcmp(test, "lock-lock-unlock") == 0) {
		test_lock_lock_unlock(mem_ctx, ctdb, mutex_string);
	} else if (strcmp(test, "lock-unlock-lock-unlock") == 0) {
		test_lock_unlock_lock_unlock(mem_ctx, ctdb, mutex_string);
	} else if (strcmp(test, "lock-cancel-check") == 0) {
		test_lock_cancel_check(mem_ctx, ctdb, mutex_string);
	} else if (strcmp(test, "lock-cancel-unlock") == 0) {
		test_lock_cancel_unlock(mem_ctx, ctdb, mutex_string);
	} else if (strcmp(test, "lock-wait-unlock") == 0) {
		test_lock_wait_unlock(mem_ctx, ctdb, mutex_string);
	} else if (strcmp(test, "lock-ppid-gone-lock-unlock") == 0) {
		test_lock_ppid_gone_lock_unlock(mem_ctx, ctdb, mutex_string);
	} else if (strcmp(test, "lock-file-removed-no-recheck") == 0) {
		if (argc != 4) {
			usage();
		}

		lock_file = argv[3];

		test_lock_file_removed_no_recheck(mem_ctx,
						  ctdb,
						  mutex_string,
						  lock_file);
	} else if (strcmp(test, "lock-file-wait-recheck-unlock") == 0) {
		if (argc != 4) {
			usage();
		}

		wait_time = smb_strtoul(argv[3],
					NULL,
					10,
					&ret,
					SMB_STR_STANDARD);
		if (ret != 0) {
			usage();
		}

		test_lock_file_wait_recheck_unlock(mem_ctx,
						   ctdb,
						   mutex_string,
						   wait_time);
	} else if (strcmp(test, "lock-file-removed") == 0) {
		if (argc != 4) {
			usage();
		}

		lock_file = argv[3];

		test_lock_file_removed(mem_ctx,
				       ctdb,
				       mutex_string,
				       lock_file);
	} else if (strcmp(test, "lock-file-changed") == 0) {
		if (argc != 4) {
			usage();
		}

		lock_file = argv[3];

		test_lock_file_changed(mem_ctx,
				       ctdb,
				       mutex_string,
				       lock_file);
	} else {
		fprintf(stderr, "Unknown test\n");
		exit(1);
	}

	talloc_free(mem_ctx);

	return 0;
}
