/*
   Unix SMB/CIFS implementation.

   Test some misc Samba3 code paths

   Copyright (C) Volker Lendecke 2006
   Copyright (C) Stefan Metzmacher 2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/time.h"
#include "system/filesys.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "../libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "torture/util.h"
#include "lib/events/events.h"
#include "param/param.h"

#define CHECK_STATUS(status, correct) do { \
	const char *_cmt = "(" __location__ ")"; \
	torture_assert_ntstatus_equal_goto(tctx,status,correct, \
					   ret,done,_cmt); \
	} while (0)

#define BASEDIR "samba3misc.smb2"

#define WAIT_FOR_ASYNC_RESPONSE(req) \
	while (!req->cancel.can_cancel && req->state <= SMB2_REQUEST_RECV) { \
		if (tevent_loop_once(tctx->ev) != 0) { \
			break; \
		} \
	}

static void torture_smb2_tree_disconnect_timer(struct tevent_context *ev,
					       struct tevent_timer *te,
					       struct timeval now,
					       void *private_data)
{
	struct smb2_tree *tree =
		talloc_get_type_abort(private_data,
		struct smb2_tree);

	smbXcli_conn_disconnect(tree->session->transport->conn,
				NT_STATUS_CTX_CLIENT_QUERY_TIMEOUT);
}

/*
 * Check that Samba3 correctly deals with conflicting local posix byte range
 * locks on an underlying file via "normal" SMB2 (without posix extentions).
 *
 * Note: This test depends on "posix locking = yes".
 * Note: To run this test, use "--option=torture:localdir=<LOCALDIR>"
 */
static bool torture_samba3_localposixlock1(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	int rc;
	const char *fname = "posixtimedlock.dat";
	const char *fpath;
	const char *localdir;
	const char *localname;
	struct smb2_handle h = {{0}};
	struct smb2_lock lck = {0};
	struct smb2_lock_element el[1] = {{0}};
	struct smb2_request *req = NULL;
	int fd = -1;
	struct flock posix_lock;
	struct tevent_timer *te;

	status = torture_smb2_testdir(tree, BASEDIR, &h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, h);

	status = torture_smb2_testfile(tree, fname, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	fpath = talloc_asprintf(tctx, "%s\\%s", BASEDIR, fname);
	torture_assert(tctx, fpath != NULL, "fpath\n");

	status = torture_smb2_testfile(tree, fpath, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	localdir = torture_setting_string(tctx, "localdir", NULL);
	torture_assert(tctx, localdir != NULL,
		       "--option=torture:localdir=<LOCALDIR> required\n");

	localname = talloc_asprintf(tctx, "%s/%s/%s",
				    localdir, BASEDIR, fname);
	torture_assert(tctx, localname != NULL, "localname\n");

	/*
	 * Lock a byte range from posix
	 */

	torture_comment(tctx, "  local open(%s)\n", localname);
	fd = open(localname, O_RDWR);
	if (fd == -1) {
		torture_warning(tctx, "open(%s) failed: %s\n",
				localname, strerror(errno));
		torture_assert(tctx, fd != -1, "open localname\n");
	}

	posix_lock.l_type = F_WRLCK;
	posix_lock.l_whence = SEEK_SET;
	posix_lock.l_start = 0;
	posix_lock.l_len = 1;

	torture_comment(tctx, "  local fcntl\n");
	rc = fcntl(fd, F_SETLK, &posix_lock);
	if (rc == -1) {
		torture_warning(tctx, "fcntl failed: %s\n", strerror(errno));
		torture_assert_goto(tctx, rc != -1, ret, done,
				    "fcntl lock\n");
	}

	el[0].offset		= 0;
	el[0].length		= 1;
	el[0].reserved		= 0x00000000;
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE |
				  SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
	lck.in.locks		= el;
	lck.in.lock_count	= 0x0001;
	lck.in.lock_sequence	= 0x00000000;
	lck.in.file.handle	= h;

	torture_comment(tctx, "  remote non-blocking lock\n");
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	torture_comment(tctx, "  remote async blocking lock\n");
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE;
	req = smb2_lock_send(tree, &lck);
	torture_assert_goto(tctx, req != NULL, ret, done, "smb2_lock_send()\n");

	te = tevent_add_timer(tctx->ev,
			      tctx, timeval_current_ofs(5, 0),
			      torture_smb2_tree_disconnect_timer,
			      tree);
	torture_assert_goto(tctx, te != NULL, ret, done, "tevent_add_timer\n");

	torture_comment(tctx, "  remote wait for STATUS_PENDING\n");
	WAIT_FOR_ASYNC_RESPONSE(req);

	torture_comment(tctx, "  local close file\n");
	close(fd);
	fd = -1;

	torture_comment(tctx, "  remote lock should now succeed\n");
	status = smb2_lock_recv(req, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	if (fd != -1) {
		close(fd);
	}
	smb2_util_close(tree, h);
	smb2_deltree(tree, BASEDIR);
	return ret;
}

struct torture_suite *torture_smb2_samba3misc_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "samba3misc");

	torture_suite_add_1smb2_test(suite, "localposixlock1",
				     torture_samba3_localposixlock1);

	suite->description = talloc_strdup(suite, "SMB2 Samba3 MISC");

	return suite;
}
