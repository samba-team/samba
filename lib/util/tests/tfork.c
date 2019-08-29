/*
 * Tests for tfork
 *
 * Copyright Ralph Boehme <slow@samba.org> 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include <talloc.h>
#include <tevent.h>
#include "system/filesys.h"
#include "system/wait.h"
#include "system/select.h"
#include "libcli/util/ntstatus.h"
#include "torture/torture.h"
#include "lib/util/data_blob.h"
#include "torture/local/proto.h"
#include "lib/util/tfork.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

static bool test_tfork_simple(struct torture_context *tctx)
{
        pid_t parent = getpid();
        struct tfork *t = NULL;
        pid_t child;
        int ret;

        t = tfork_create();
        if (t == NULL) {
                torture_fail(tctx, "tfork failed\n");
                return false;
        }
        child = tfork_child_pid(t);
        if (child == 0) {
                torture_comment(tctx, "my parent pid is %d\n", parent);
                torture_assert(tctx, getpid() != parent, "tfork failed\n");
                _exit(0);
        }

        ret = tfork_destroy(&t);
        torture_assert(tctx, ret == 0, "tfork_destroy failed\n");

        return true;
}

static bool test_tfork_status(struct torture_context *tctx)
{
	struct tfork *t = NULL;
	int status;
	pid_t child;
	bool ok = true;

	t = tfork_create();
	if (t == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}
	child = tfork_child_pid(t);
	if (child == 0) {
		_exit(123);
	}

	status = tfork_status(&t, true);
	if (status == -1) {
		torture_fail(tctx, "tfork_status failed\n");
	}

	torture_assert_goto(tctx, WIFEXITED(status) == true, ok, done,
			    "tfork failed\n");
	torture_assert_goto(tctx, WEXITSTATUS(status) == 123, ok, done,
			    "tfork failed\n");

	torture_comment(tctx, "exit status [%d]\n", WEXITSTATUS(status));

done:
	return ok;
}

static bool test_tfork_sigign(struct torture_context *tctx)
{
	struct tfork *t = NULL;
	struct sigaction act;
	pid_t child;
	int status;
	bool ok = true;
	int ret;

	act = (struct sigaction) {
		.sa_flags = SA_NOCLDWAIT,
		.sa_handler = SIG_IGN,
	};

	ret = sigaction(SIGCHLD, &act, NULL);
	torture_assert_goto(tctx, ret == 0, ok, done, "sigaction failed\n");

	t = tfork_create();
	if (t == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}
	child = tfork_child_pid(t);
	if (child == 0) {
		sleep(1);
		_exit(123);
	}

	child = fork();
	if (child == -1) {
		torture_fail(tctx, "fork failed\n");
		return false;
	}
	if (child == 0) {
		_exit(0);
	}

	status = tfork_status(&t, true);
	if (status == -1) {
		torture_fail(tctx, "tfork_status failed\n");
	}

	torture_assert_goto(tctx, WIFEXITED(status) == true, ok, done,
			    "tfork failed\n");
	torture_assert_goto(tctx, WEXITSTATUS(status) == 123, ok, done,
			    "tfork failed\n");
	torture_comment(tctx, "exit status [%d]\n", WEXITSTATUS(status));

done:
	return ok;
}

static void sigchld_handler1(int signum, siginfo_t *si, void *u)
{
	pid_t pid;
	int status;

	if (signum != SIGCHLD) {
		abort();
	}

	pid = waitpid(si->si_pid, &status, 0);
	if (pid != si->si_pid) {
		abort();
	}
}

static bool test_tfork_sighandler(struct torture_context *tctx)
{
	struct tfork *t = NULL;
	struct sigaction act;
	struct sigaction oldact;
	pid_t child;
	int status;
	bool ok = true;
	int ret;

	act = (struct sigaction) {
		.sa_flags = SA_SIGINFO,
		.sa_sigaction = sigchld_handler1,
	};

	ret = sigaction(SIGCHLD, &act, &oldact);
	torture_assert_goto(tctx, ret == 0, ok, done, "sigaction failed\n");

	t = tfork_create();
	if (t == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}
	child = tfork_child_pid(t);
	if (child == 0) {
		sleep(1);
		_exit(123);
	}

	child = fork();
	if (child == -1) {
		torture_fail(tctx, "fork failed\n");
		return false;
	}
	if (child == 0) {
		_exit(0);
	}

	status = tfork_status(&t, true);
	if (status == -1) {
		torture_fail(tctx, "tfork_status failed\n");
	}

	torture_assert_goto(tctx, WIFEXITED(status) == true, ok, done,
			    "tfork failed\n");
	torture_assert_goto(tctx, WEXITSTATUS(status) == 123, ok, done,
			    "tfork failed\n");
	torture_comment(tctx, "exit status [%d]\n", WEXITSTATUS(status));

done:
	sigaction(SIGCHLD, &oldact, NULL);

	return ok;
}

static bool test_tfork_process_hierarchy(struct torture_context *tctx)
{
	struct tfork *t = NULL;
	pid_t pid = getpid();
	pid_t child;
	pid_t pgid = getpgid(0);
	pid_t sid = getsid(0);
	char *procpath = NULL;
	int status;
	struct stat st;
	int ret;
	bool ok = true;

	procpath = talloc_asprintf(tctx, "/proc/%d/status", getpid());
	torture_assert_not_null(tctx, procpath, "talloc_asprintf failed\n");

	ret = stat(procpath, &st);
	TALLOC_FREE(procpath);
	if (ret != 0) {
		if (errno == ENOENT) {
			torture_skip(tctx, "/proc missing\n");
		}
		torture_fail(tctx, "stat failed\n");
	}

	t = tfork_create();
	if (t == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}
	child = tfork_child_pid(t);
	if (child == 0) {
		char *cmd = NULL;
		FILE *fp = NULL;
		char line[64];
		char *p;
		pid_t ppid;

		torture_assert_goto(tctx, pgid == getpgid(0), ok, child_fail, "tfork failed\n");
		torture_assert_goto(tctx, sid == getsid(0), ok, child_fail, "tfork failed\n");

		cmd = talloc_asprintf(tctx, "cat /proc/%d/status | awk '/^PPid:/ {print $2}'", getppid());
		torture_assert_goto(tctx, cmd != NULL, ok, child_fail, "talloc_asprintf failed\n");

		fp = popen(cmd, "r");
		torture_assert_goto(tctx, fp != NULL, ok, child_fail, "popen failed\n");

		p = fgets(line, sizeof(line) - 1, fp);
		pclose(fp);
		torture_assert_goto(tctx, p != NULL, ok, child_fail, "popen failed\n");

		ret = sscanf(line, "%d", &ppid);
		torture_assert_goto(tctx, ret == 1, ok, child_fail, "sscanf failed\n");
		torture_assert_goto(tctx, ppid == pid, ok, child_fail, "process hierarchy not rooted at caller\n");

		_exit(0);

	child_fail:
		_exit(1);
	}

	status = tfork_status(&t, true);
	if (status == -1) {
		torture_fail(tctx, "tfork_status failed\n");
	}

	torture_assert_goto(tctx, WIFEXITED(status) == true, ok, done,
			    "tfork failed\n");
	torture_assert_goto(tctx, WEXITSTATUS(status) == 0, ok, done,
			    "tfork failed\n");
	torture_comment(tctx, "exit status [%d]\n", WEXITSTATUS(status));

done:
	return ok;
}

static bool test_tfork_pipe(struct torture_context *tctx)
{
	struct tfork *t = NULL;
	int status;
	pid_t child;
	int up[2];
	int down[2];
	char c;
	int ret;
	bool ok = true;

	ret = pipe(&up[0]);
	torture_assert(tctx, ret == 0, "pipe failed\n");

	ret = pipe(&down[0]);
	torture_assert(tctx, ret == 0, "pipe failed\n");

	t = tfork_create();
	if (t == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}
	child = tfork_child_pid(t);
	if (child == 0) {
		close(up[0]);
		close(down[1]);

		ret = read(down[0], &c, 1);
		torture_assert_goto(tctx, ret == 1, ok, child_fail, "read failed\n");
		torture_assert_goto(tctx, c == 1, ok, child_fail, "read failed\n");

		ret = write(up[1], &(char){2}, 1);
		torture_assert_goto(tctx, ret == 1, ok, child_fail, "write failed\n");

		_exit(0);

	child_fail:
		_exit(1);
	}

	close(up[1]);
	close(down[0]);

	ret = write(down[1], &(char){1}, 1);
	torture_assert(tctx, ret == 1, "read failed\n");

	ret = read(up[0], &c, 1);
	torture_assert(tctx, ret == 1, "read failed\n");
	torture_assert(tctx, c == 2, "read failed\n");

	status = tfork_status(&t, true);
	if (status == -1) {
		torture_fail(tctx, "tfork_status failed\n");
	}

	torture_assert_goto(tctx, WIFEXITED(status) == true, ok, done,
			    "tfork failed\n");
	torture_assert_goto(tctx, WEXITSTATUS(status) == 0, ok, done,
			    "tfork failed\n");
done:
	return ok;
}

static bool test_tfork_twice(struct torture_context *tctx)
{
	struct tfork *t = NULL;
	int status;
	pid_t child;
	pid_t pid;
	int up[2];
	int ret;
	bool ok = true;

	ret = pipe(&up[0]);
	torture_assert(tctx, ret == 0, "pipe failed\n");

	t = tfork_create();
	if (t == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}
	child = tfork_child_pid(t);
	if (child == 0) {
		close(up[0]);

		t = tfork_create();
		if (t == NULL) {
			torture_fail(tctx, "tfork failed\n");
			return false;
		}
		child = tfork_child_pid(t);
		if (child == 0) {
			sleep(1);
			pid = getpid();
			ret = write(up[1], &pid, sizeof(pid_t));
			torture_assert_goto(tctx, ret == sizeof(pid_t), ok, child_fail, "write failed\n");

			_exit(0);

		child_fail:
			_exit(1);
		}

		_exit(0);
	}

	close(up[1]);

	ret = read(up[0], &pid, sizeof(pid_t));
	torture_assert(tctx, ret == sizeof(pid_t), "read failed\n");

	status = tfork_status(&t, true);
	torture_assert_goto(tctx, status != -1, ok, done, "tfork_status failed\n");

	torture_assert_goto(tctx, WIFEXITED(status) == true, ok, done,
			    "tfork failed\n");
	torture_assert_goto(tctx, WEXITSTATUS(status) == 0, ok, done,
			    "tfork failed\n");
done:
	return ok;
}

static void *tfork_thread(void *p)
{
	struct tfork *t = NULL;
	int status;
	pid_t child;
	uint64_t tid = (uint64_t)pthread_self();
	uint64_t *result = NULL;
	int up[2];
	ssize_t nread;
	int ret;

	ret = pipe(up);
	if (ret != 0) {
		pthread_exit(NULL);
	}

	t = tfork_create();
	if (t == NULL) {
		pthread_exit(NULL);
	}
	child = tfork_child_pid(t);
	if (child == 0) {
		ssize_t nwritten;

		close(up[0]);
		tid++;
		nwritten = sys_write(up[1], &tid, sizeof(uint64_t));
		if (nwritten != sizeof(uint64_t)) {
			_exit(1);
		}
		_exit(0);
	}
	close(up[1]);

	result = malloc(sizeof(uint64_t));
	if (result == NULL) {
		pthread_exit(NULL);
	}

	nread = sys_read(up[0], result, sizeof(uint64_t));
	if (nread != sizeof(uint64_t)) {
		pthread_exit(NULL);
	}

	status = tfork_status(&t, true);
	if (status == -1) {
		pthread_exit(NULL);
	}

	pthread_exit(result);
}

static bool test_tfork_threads(struct torture_context *tctx)
{
	int ret;
	bool ok = true;
	const int num_threads = 64;
	pthread_t threads[num_threads];
	sigset_t set;
	int i;

#ifndef HAVE_PTHREAD
	torture_skip(tctx, "no pthread support\n");
#endif

	/*
	 * Be nasty and taste for the worst case: ensure all threads start with
	 * SIGCHLD unblocked so we have the most fun with SIGCHLD being
	 * delivered to a random thread. :)
	 */
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
#ifdef HAVE_PTHREAD
	ret = pthread_sigmask(SIG_UNBLOCK, &set, NULL);
#else
	ret = sigprocmask(SIG_UNBLOCK, &set, NULL);
#endif
	if (ret != 0) {
		return false;
	}

	for (i = 0; i < num_threads; i++) {
		ret = pthread_create(&threads[i], NULL, tfork_thread, NULL);
		torture_assert_goto(tctx, ret == 0, ok, done,
				    "pthread_create failed\n");
	}

	for (i = 0; i < num_threads; i++) {
		void *p;
		uint64_t *result;

		ret = pthread_join(threads[i], &p);
		torture_assert_goto(tctx, ret == 0, ok, done,
				    "pthread_join failed\n");
		result = (uint64_t *)p;
		torture_assert_goto(tctx, *result == (uint64_t)threads[i] + 1,
				    ok, done, "thread failed\n");
		free(p);
	}

done:
	return ok;
}

static bool test_tfork_cmd_send(struct torture_context *tctx)
{
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	const char *cmd[2] = { NULL, NULL };
	bool ok = true;

	ev = tevent_context_init(tctx);
	torture_assert_goto(tctx, ev != NULL, ok, done,
			    "tevent_context_init failed\n");

	cmd[0] = talloc_asprintf(tctx, "%s/testprogs/blackbox/tfork.sh", SRCDIR);
	torture_assert_goto(tctx, cmd[0] != NULL, ok, done,
			    "talloc_asprintf failed\n");

	req = samba_runcmd_send(tctx, ev, timeval_zero(), 0, 0,
				cmd, "foo", NULL);
	torture_assert_goto(tctx, req != NULL, ok, done,
			    "samba_runcmd_send failed\n");

	ok = tevent_req_poll(req, ev);
	torture_assert_goto(tctx, ok, ok, done, "tevent_req_poll failed\n");

	torture_comment(tctx, "samba_runcmd_send test finished\n");

done:
	TALLOC_FREE(ev);

	return ok;
}

/*
 * Test to ensure that the event_fd becomes readable after
 * a tfork_process terminates.
 */
static bool test_tfork_event_file_handle(struct torture_context *tctx)
{
	bool ok = true;

	struct tfork *t1 = NULL;
	pid_t child1;
	struct pollfd poll1[] = {
		{
			.fd = -1,
			.events = POLLIN,
		},
	};

	struct tfork *t2 = NULL;
	pid_t child2;
	struct pollfd poll2[] = {
		{
			.fd = -1,
			.events = POLLIN,
		},
	};


	t1 = tfork_create();
	if (t1 == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}

	child1 = tfork_child_pid(t1);
	if (child1 == 0) {
		/*
		 * Parent process will kill this with a SIGTERM
		 * so 10 seconds should be plenty
		 */
		sleep(10);
		exit(1);
	}
	poll1[0].fd = tfork_event_fd(t1);

	t2 = tfork_create();
	if (t2 == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}
	child2 = tfork_child_pid(t2);
	if (child2 == 0) {
		/*
		 * Parent process will kill this with a SIGTERM
		 * so 10 seconds should be plenty
		 */
		sleep(10);
		exit(2);
	}
	poll2[0].fd = tfork_event_fd(t2);

	/*
	 * Have forked two process and are in the master process
	 * Expect that both event_fds are unreadable
	 */
	poll(poll1, 1, 0);
	ok = !(poll1[0].revents & POLLIN);
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 1 event fd readable\n");
	poll(poll2, 1, 0);
	ok = !(poll2[0].revents & POLLIN);
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 1 event fd readable\n");

	/* Kill the first child process */
	kill(child1, SIGKILL);
	sleep(1);

	/*
	 * Have killed the first child, so expect it's event_fd to have gone
	 * readable.
	 *
	 */
	poll(poll1, 1, 0);
	ok = (poll1[0].revents & POLLIN);
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 1 event fd not readable\n");
	poll(poll2, 1, 0);
	ok = !(poll2[0].revents & POLLIN);
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 2 event fd readable\n");

	/* Kill the secind child process */
	kill(child2, SIGKILL);
	sleep(1);
	/*
	 * Have killed the children, so expect their event_fd's to have gone
	 * readable.
	 *
	 */
	poll(poll1, 1, 0);
	ok = (poll1[0].revents & POLLIN);
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 1 event fd not readable\n");
	poll(poll2, 1, 0);
	ok = (poll2[0].revents & POLLIN);
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 2 event fd not readable\n");

done:
	free(t1);
	free(t2);

	return ok;
}

/*
 * Test to ensure that the status calls behave as expected after a process
 * terminates.
 *
 * As the parent process owns the status fd's they get passed to all
 * subsequent children after a tfork.  So it's possible for another
 * child process to hold the status pipe open.
 *
 * The event fd needs to be left open by tfork, as a close in the status
 * code can cause issues in tevent code.
 *
 */
static bool test_tfork_status_handle(struct torture_context *tctx)
{
	bool ok = true;

	struct tfork *t1 = NULL;
	pid_t child1;

	struct tfork *t2 = NULL;
	pid_t child2;

	int status;
	int fd;
	int ev1_fd;
	int ev2_fd;


	t1 = tfork_create();
	if (t1 == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}

	child1 = tfork_child_pid(t1);
	if (child1 == 0) {
		/*
		 * Parent process will kill this with a SIGTERM
		 * so 10 seconds should be plenty
		 */
		sleep(10);
		exit(1);
	}
	ev1_fd = tfork_event_fd(t1);

	t2 = tfork_create();
	if (t2 == NULL) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}
	child2 = tfork_child_pid(t2);
	if (child2 == 0) {
		/*
		 * Parent process will kill this with a SIGTERM
		 * so 10 seconds should be plenty
		 */
		sleep(10);
		exit(2);
	}
	ev2_fd = tfork_event_fd(t2);

	/*
	 * Have forked two process and are in the master process
	 * expect that the status call will block, and hence return -1
	 * as the processes are still running
	 * The event fd's should be open.
	 */
	status = tfork_status(&t1, false);
	ok = status == -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork status available for non terminated "
			    "process 1\n");
	/* Is the event fd open? */
	fd = dup(ev1_fd);
	ok = fd != -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 1 event fd is not open");

	status = tfork_status(&t2, false);
	ok = status == -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork status available for non terminated "
			    "process 2\n");
	/* Is the event fd open? */
	fd = dup(ev2_fd);
	ok = fd != -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 2 event fd is not open");

	/*
	 * Kill the first process, it's status should be readable
	 * and it's event_fd should be open
	 * The second process's status should be unreadable.
	 */
	kill(child1, SIGTERM);
	sleep(1);
	status = tfork_status(&t1, false);
	ok = status != -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork status for child 1 not available after "
			    "termination\n");
	/* Is the event fd open? */
	fd = dup(ev2_fd);
	ok = fd != -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 1 event fd is not open");

	status = tfork_status(&t2, false);
	ok = status == -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork status available for child 2 after "
			    "termination of child 1\n");

	/*
	 * Kill the second process, it's status should be readable
	 */
	kill(child2, SIGTERM);
	sleep(1);
	status = tfork_status(&t2, false);
	ok = status != -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork status for child 2 not available after "
			    "termination\n");

	/* Check that the event fd's are still open */
	/* Is the event fd open? */
	fd = dup(ev1_fd);
	ok = fd != -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 1 event fd is not open");
	/* Is the event fd open? */
	fd = dup(ev2_fd);
	ok = fd != -1;
	torture_assert_goto(tctx, ok, ok, done,
			    "tfork process 2 event fd is not open");

done:
	return ok;
}

struct torture_suite *torture_local_tfork(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite =
		torture_suite_create(mem_ctx, "tfork");

	torture_suite_add_simple_test(suite,
				      "tfork_simple",
				      test_tfork_simple);

	torture_suite_add_simple_test(suite,
				      "tfork_status",
				      test_tfork_status);

	torture_suite_add_simple_test(suite,
				      "tfork_sigign",
				      test_tfork_sigign);

	torture_suite_add_simple_test(suite,
				      "tfork_sighandler",
				      test_tfork_sighandler);

	torture_suite_add_simple_test(suite,
				      "tfork_process_hierarchy",
				      test_tfork_process_hierarchy);

	torture_suite_add_simple_test(suite,
				      "tfork_pipe",
				      test_tfork_pipe);

	torture_suite_add_simple_test(suite,
				      "tfork_twice",
				      test_tfork_twice);

	torture_suite_add_simple_test(suite,
				      "tfork_threads",
				      test_tfork_threads);

	torture_suite_add_simple_test(suite,
				      "tfork_cmd_send",
				      test_tfork_cmd_send);

	torture_suite_add_simple_test(suite,
				      "tfork_event_file_handle",
				      test_tfork_event_file_handle);

	torture_suite_add_simple_test(suite,
				      "tfork_status_handle",
				      test_tfork_status_handle);

	return suite;
}
