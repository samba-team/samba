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
#include "libcli/util/ntstatus.h"
#include "torture/torture.h"
#include "lib/util/data_blob.h"
#include "torture/local/proto.h"
#include "lib/util/tfork.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"

static bool test_tfork_simple(struct torture_context *tctx)
{
	pid_t pid;
	pid_t parent = getpid();
	pid_t parent_arg;

	pid = tfork(NULL, &parent_arg);
	if (pid == 0) {
		torture_comment(tctx, "my parent pid is %d\n", parent);
		torture_assert(tctx, parent == parent_arg, "tfork failed\n");
		_exit(0);
	}
	if (pid == -1) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}

	return true;
}

static bool test_tfork_status(struct torture_context *tctx)
{
	pid_t child;
	int status;
	ssize_t nread;
	int status_fd = -1;
	bool ok = true;

	child = tfork(&status_fd, NULL);
	if (child == 0) {
		_exit(123);
	}
	if (child == -1) {
		torture_fail(tctx, "tfork failed\n");
		return false;
	}

	nread = sys_read(status_fd, &status, sizeof(status));
	if (nread != sizeof(status)) {
		torture_fail(tctx, "sys_read failed\n");
	}

	torture_assert_goto(tctx, WIFEXITED(status) == true, ok, done,
			    "tfork failed\n");
	torture_assert_goto(tctx, WEXITSTATUS(status) == 123, ok, done,
			    "tfork failed\n");

	torture_comment(tctx, "exit status [%d]\n", WEXITSTATUS(status));

done:
	if (status_fd != -1) {
		close(status_fd);
	}

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

	req = samba_runcmd_send(tctx, ev, timeval_zero(), 1, 0,
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
				      "tfork_cmd_send",
				      test_tfork_cmd_send);

	return suite;
}
