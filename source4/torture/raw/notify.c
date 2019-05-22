/* 
   Unix SMB/CIFS implementation.
   basic raw test suite for change notify
   Copyright (C) Andrew Tridgell 2003
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/libcli.h"
#include "system/filesys.h"
#include "torture/util.h"
#include "torture/raw/proto.h"
#include "lib/events/events.h"

#define BASEDIR "\\test_notify"

#define CHECK_WSTR(tctx, field, value, flags) \
do { \
	torture_assert_str_equal(tctx, field.s, value, "values don't match"); \
	torture_assert(tctx, \
		       !wire_bad_flags(&field, STR_UNICODE, cli->transport), \
		       "wire_bad_flags"); \
} while (0)

#define BASEDIR_CN1_DIR BASEDIR "_CN1_DIR"

/* 
   basic testing of change notify on directories
*/
static bool test_notify_dir(struct torture_context *tctx,
			    struct smbcli_state *cli,
			    struct smbcli_state *cli2)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	union smb_close cl;
	int i, count, fnum, fnum2;
	struct smbcli_request *req, *req2;
	extern int torture_numops;

	torture_comment(tctx, "TESTING CHANGE NOTIFY ON DIRECTORIES\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_DIR),
		       "Failed to setup up test directory: " BASEDIR_CN1_DIR);

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_DIR;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum2 = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = true;

	torture_comment(tctx, "Testing notify cancel\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smb_raw_ntcancel(req);
	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_CANCELLED,
					   ret, done,
					   "smb_raw_changenotify_recv");

	torture_comment(tctx, "Testing notify mkdir\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_mkdir(cli2->tree, BASEDIR_CN1_DIR "\\subdir-name");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "more than one change");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "wrong action (exp: ADDED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);

	torture_comment(tctx, "Testing notify rmdir\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_rmdir(cli2->tree, BASEDIR_CN1_DIR "\\subdir-name");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "more than one change");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);

	torture_comment(tctx, "Testing notify mkdir - rmdir - mkdir - rmdir\n");

	smbcli_mkdir(cli2->tree, BASEDIR_CN1_DIR "\\subdir-name");
	smbcli_rmdir(cli2->tree, BASEDIR_CN1_DIR "\\subdir-name");
	smbcli_mkdir(cli2->tree, BASEDIR_CN1_DIR "\\subdir-name");
	smbcli_rmdir(cli2->tree, BASEDIR_CN1_DIR "\\subdir-name");
	smb_msleep(200);
	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      4, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "wrong action (exp: ADDED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[1].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[1].name, "subdir-name",
		   STR_UNICODE);
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[2].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "wrong action (exp: ADDED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[2].name, "subdir-name",
		   STR_UNICODE);
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[3].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[3].name, "subdir-name",
		   STR_UNICODE);

	count = torture_numops;
	torture_comment(tctx, "Testing buffered notify on create of %d files\n", count);
	for (i=0;i<count;i++) {
		char *fname = talloc_asprintf(cli,
				BASEDIR_CN1_DIR "\\test%d.txt",
				i);
		int fnum3 = smbcli_open(cli->tree, fname, O_CREAT|O_RDWR, DENY_NONE);
		torture_assert_int_not_equal_goto(tctx, fnum3, -1, ret, done,
			talloc_asprintf(tctx, "Failed to create %s - %s",
					fname, smbcli_errstr(cli->tree)));
		talloc_free(fname);
		smbcli_close(cli->tree, fnum3);
	}

	/* (1st notify) setup a new notify on a different directory handle.
	   This new notify won't see the events above. */
	notify.nttrans.in.file.fnum = fnum2;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	/* (2nd notify) whereas this notify will see the above buffered events,
	   and it directly returns the buffered events */
	notify.nttrans.in.file.fnum = fnum;
	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smbcli_unlink(cli->tree, BASEDIR_CN1_DIR "\\nonexistent.txt");
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "smbcli_unlink");

	/* (1st unlink) as the 2nd notify directly returns,
	   this unlink is only seen by the 1st notify and 
	   the 3rd notify (later) */
	torture_comment(tctx, "Testing notify on unlink for the first file\n");
	status = smbcli_unlink(cli2->tree, BASEDIR_CN1_DIR "\\test0.txt");
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smbcli_unlink");

	/* receive the reply from the 2nd notify */
	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      count, ret, done,
				      "wrong number of changes");
	for (i=1;i<count;i++) {
		torture_assert_int_equal_goto(tctx,
					notify.nttrans.out.changes[i].action,
					NOTIFY_ACTION_ADDED, ret, done,
					"wrong action (exp: ADDED)");
	}
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "test0.txt",
		   STR_UNICODE);

	torture_comment(tctx, "and now from the 1st notify\n");
	status = smb_raw_changenotify_recv(req2, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "test0.txt",
		   STR_UNICODE);

	torture_comment(tctx, "(3rd notify) this notify will only see the 1st unlink\n");
	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smbcli_unlink(cli->tree, BASEDIR_CN1_DIR "\\nonexistent.txt");
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "smbcli_unlink");

	torture_comment(tctx, "Testing notify on wildcard unlink for %d files\n", count-1);
	/* (2nd unlink) do a wildcard unlink */
	status = smbcli_unlink(cli2->tree, BASEDIR_CN1_DIR "\\test*.txt");
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	/* receive the 3rd notify */
	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "test0.txt",
		   STR_UNICODE);

	/* and we now see the rest of the unlink calls on both directory handles */
	notify.nttrans.in.file.fnum = fnum;
	sleep(3);
	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      count - 1, ret, done,
				      "wrong number of changes");
	for (i=0;i<notify.nttrans.out.num_changes;i++) {
		torture_assert_int_equal_goto(tctx,
					notify.nttrans.out.changes[i].action,
					NOTIFY_ACTION_REMOVED, ret, done,
					"wrong action (exp: REMOVED)");
	}
	notify.nttrans.in.file.fnum = fnum2;
	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      count - 1, ret, done,
				      "wrong number of changes");
	for (i=0;i<notify.nttrans.out.num_changes;i++) {
		torture_assert_int_equal_goto(tctx,
					notify.nttrans.out.changes[i].action,
					NOTIFY_ACTION_REMOVED, ret, done,
					"wrong action (exp: REMOVED)");
	}

	torture_comment(tctx, "Testing if a close() on the dir handle triggers the notify reply\n");

	notify.nttrans.in.file.fnum = fnum;
	req = smb_raw_changenotify_send(cli->tree, &notify);

	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_close");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      0, ret, done, "no changes expected");

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_DIR);
	return ret;
}

/*
 * Check notify reply for a rename action. Not sure if this is a valid thing
 * to do, but depending on timing between inotify and messaging we get the
 * add/remove/modify in any order. This routines tries to find the action/name
 * pair in any of the three following notify_changes.
 */

static bool check_rename_reply(struct torture_context *tctx,
			       struct smbcli_state *cli,
			       int line,
			       struct notify_changes *actions,
			       uint32_t action, const char *name)
{
	int i;

	for (i=0; i<3; i++) {
		if (actions[i].action == action) {
			CHECK_WSTR(tctx, actions[i].name, name, STR_UNICODE);
			return true;
		}
	}

	torture_result(tctx, TORTURE_FAIL,
		       __location__": (%d) expected action %d, not found\n",
		       line, action);
	return false;
}

/* 
   testing of recursive change notify
*/

#define BASEDIR_CN1_RECUR BASEDIR "_CN1_RECUR"

static bool test_notify_recursive(struct torture_context *tctx,
				  struct smbcli_state *cli,
				  struct smbcli_state *cli2)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req1, *req2;

	torture_comment(tctx, "TESTING CHANGE NOTIFY WITH RECURSION\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_RECUR),
		       "Failed to setup up test directory: " BASEDIR_CN1_RECUR);

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_RECUR;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify, on file or directory name
	   changes. Setup both with and without recursion */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_CREATION;
	notify.nttrans.in.file.fnum = fnum;

	notify.nttrans.in.recursive = true;
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	notify.nttrans.in.recursive = false;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	/* cancel initial requests so the buffer is setup */
	smb_raw_ntcancel(req1);
	status = smb_raw_changenotify_recv(req1, tctx, &notify);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_CANCELLED,
					   ret, done,
					   "smb_raw_changenotify_recv");

	smb_raw_ntcancel(req2);
	status = smb_raw_changenotify_recv(req2, tctx, &notify);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_CANCELLED,
					   ret, done,
					   "smb_raw_changenotify_recv");

	/*
	 * Make notifies a bit more interesting in a cluster by doing
	 * the changes against different nodes with --unclist
	 */
	smbcli_mkdir(cli->tree, BASEDIR_CN1_RECUR "\\subdir-name");
	smbcli_mkdir(cli2->tree, BASEDIR_CN1_RECUR "\\subdir-name\\subname1");
	smbcli_close(cli->tree, 
		     smbcli_open(cli->tree,
				BASEDIR_CN1_RECUR "\\subdir-name\\subname2",
				O_CREAT, 0));
	smbcli_rename(cli2->tree, BASEDIR_CN1_RECUR "\\subdir-name\\subname1",
		      BASEDIR_CN1_RECUR "\\subdir-name\\subname1-r");
	smbcli_rename(cli->tree,
		BASEDIR_CN1_RECUR "\\subdir-name\\subname2",
		BASEDIR_CN1_RECUR "\\subname2-r");
	smbcli_rename(cli2->tree, BASEDIR_CN1_RECUR "\\subname2-r",
		      BASEDIR_CN1_RECUR "\\subname3-r");

	notify.nttrans.in.completion_filter = 0;
	notify.nttrans.in.recursive = true;
	smb_msleep(200);
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	smbcli_rmdir(cli->tree, BASEDIR_CN1_RECUR "\\subdir-name\\subname1-r");
	smbcli_rmdir(cli2->tree, BASEDIR_CN1_RECUR "\\subdir-name");
	smbcli_unlink(cli->tree, BASEDIR_CN1_RECUR "\\subname3-r");

	smb_msleep(200);
	notify.nttrans.in.recursive = false;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	status = smb_raw_changenotify_recv(req1, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      11, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "wrong action (exp: ADDED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[1].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "wrong action (exp: ADDED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[1].name,
		   "subdir-name\\subname1", STR_UNICODE);
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[2].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "wrong action (exp: ADDED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[2].name,
		   "subdir-name\\subname2", STR_UNICODE);
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[3].action,
				      NOTIFY_ACTION_OLD_NAME, ret, done,
				      "wrong action (exp: OLD_NAME)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[3].name,
		   "subdir-name\\subname1", STR_UNICODE);
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[4].action,
				      NOTIFY_ACTION_NEW_NAME, ret, done,
				      "wrong action (exp: NEW_NAME)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[4].name,
		   "subdir-name\\subname1-r", STR_UNICODE);

	ret &= check_rename_reply(tctx,
		cli, __LINE__, &notify.nttrans.out.changes[5],
		NOTIFY_ACTION_ADDED, "subname2-r");
	ret &= check_rename_reply(tctx,
		cli, __LINE__, &notify.nttrans.out.changes[5],
		NOTIFY_ACTION_REMOVED, "subdir-name\\subname2");
	ret &= check_rename_reply(tctx,
		cli, __LINE__, &notify.nttrans.out.changes[5],
		NOTIFY_ACTION_MODIFIED, "subname2-r");
		
	ret &= check_rename_reply(tctx,
		cli, __LINE__, &notify.nttrans.out.changes[8],
		NOTIFY_ACTION_OLD_NAME, "subname2-r");
	ret &= check_rename_reply(tctx,
		cli, __LINE__, &notify.nttrans.out.changes[8],
		NOTIFY_ACTION_NEW_NAME, "subname3-r");
	ret &= check_rename_reply(tctx,
		cli, __LINE__, &notify.nttrans.out.changes[8],
		NOTIFY_ACTION_MODIFIED, "subname3-r");

	if (!ret) {
		goto done;
	}

	status = smb_raw_changenotify_recv(req2, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      3, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name,
		   "subdir-name\\subname1-r", STR_UNICODE);
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[1].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[1].name, "subdir-name",
		   STR_UNICODE);
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[2].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[2].name, "subname3-r",
		   STR_UNICODE);

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_RECUR);
	return ret;
}

/* 
   testing of change notify mask change
*/

#define BASEDIR_CN1_CNMC BASEDIR "_CN1_CNMC"

static bool test_notify_mask_change(struct torture_context *tctx,
				    struct smbcli_state *cli)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req1, *req2;

	torture_comment(tctx, "TESTING CHANGE NOTIFY WITH MASK CHANGE\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_CNMC),
		       "Failed to setup up test directory: " BASEDIR_CN1_CNMC);

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_CNMC;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify, on file or directory name
	   changes. Setup both with and without recursion */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_ATTRIBUTES;
	notify.nttrans.in.file.fnum = fnum;

	notify.nttrans.in.recursive = true;
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	notify.nttrans.in.recursive = false;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	/* cancel initial requests so the buffer is setup */
	smb_raw_ntcancel(req1);
	status = smb_raw_changenotify_recv(req1, tctx, &notify);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_CANCELLED,
					   ret, done,
					   "smb_raw_changenotify_recv");

	smb_raw_ntcancel(req2);
	status = smb_raw_changenotify_recv(req2, tctx, &notify);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_CANCELLED,
					   ret, done,
					   "smb_raw_changenotify_recv");

	notify.nttrans.in.recursive = true;
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	/* Set to hidden then back again. */
	smbcli_close(cli->tree,
		smbcli_open(cli->tree,BASEDIR_CN1_CNMC "\\tname1", O_CREAT, 0));
	smbcli_setatr(cli->tree, BASEDIR_CN1_CNMC "\\tname1",
		FILE_ATTRIBUTE_HIDDEN, 0);
	smbcli_unlink(cli->tree, BASEDIR_CN1_CNMC "\\tname1");

	status = smb_raw_changenotify_recv(req1, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_MODIFIED, ret, done,
				      "wrong action (exp: MODIFIED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "tname1",
		   STR_UNICODE);

	/* Now try and change the mask to include other events.
	 * This should not work - once the mask is set on a directory
	 * fnum it seems to be fixed until the fnum is closed. */

	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_CREATION;
	notify.nttrans.in.recursive = true;
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	notify.nttrans.in.recursive = false;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	smbcli_mkdir(cli->tree, BASEDIR_CN1_CNMC "\\subdir-name");
	smbcli_mkdir(cli->tree, BASEDIR_CN1_CNMC "\\subdir-name\\subname1");
	smbcli_close(cli->tree, 
		     smbcli_open(cli->tree,
			BASEDIR_CN1_CNMC "\\subdir-name\\subname2",
			O_CREAT, 0));
	smbcli_rename(cli->tree,
			BASEDIR_CN1_CNMC "\\subdir-name\\subname1",
			BASEDIR_CN1_CNMC "\\subdir-name\\subname1-r");
	smbcli_rename(cli->tree,
			BASEDIR_CN1_CNMC "\\subdir-name\\subname2",
			BASEDIR_CN1_CNMC "\\subname2-r");
	smbcli_rename(cli->tree,
			BASEDIR_CN1_CNMC "\\subname2-r",
			BASEDIR_CN1_CNMC "\\subname3-r");

	smbcli_rmdir(cli->tree, BASEDIR_CN1_CNMC "\\subdir-name\\subname1-r");
	smbcli_rmdir(cli->tree, BASEDIR_CN1_CNMC "\\subdir-name");
	smbcli_unlink(cli->tree, BASEDIR_CN1_CNMC "\\subname3-r");

	status = smb_raw_changenotify_recv(req1, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_MODIFIED, ret, done,
				      "wrong action (exp: MODIFIED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subname2-r",
		   STR_UNICODE);

	status = smb_raw_changenotify_recv(req2, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_MODIFIED, ret, done,
				      "wrong action (exp: MODIFIED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subname3-r",
		   STR_UNICODE);

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_CNMC);
	return ret;
}


/* 
   testing of mask bits for change notify
*/

#define BASEDIR_CN1_NOTM BASEDIR "_CN1_NOTM"

static bool test_notify_mask(struct torture_context *tctx,
			     struct smbcli_state *cli,
			     struct smbcli_state *cli2)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	union smb_chkpath chkpath;
	int fnum, fnum2;
	uint32_t mask;
	int i;
	char c = 1;
	struct timeval tv;
	NTTIME t;

	torture_comment(tctx, "TESTING CHANGE NOTIFY COMPLETION FILTERS\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_NOTM),
		       "Failed to setup up test directory: " BASEDIR_CN1_NOTM);

	tv = timeval_current_ofs(1000, 0);
	t = timeval_to_nttime(&tv);

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_NOTM;

	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.recursive = true;

	chkpath.chkpath.in.path = "\\";

#define NOTIFY_MASK_TEST(test_name, setup, op, cleanup, Action, expected, nchanges) \
	do { \
	smbcli_getatr(cli->tree, test_name, NULL, NULL, NULL); \
	for (mask=i=0;i<32;i++) { \
		struct smbcli_request *req; \
		status = smb_raw_open(cli->tree, tctx, &io); \
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done, \
						"smb_raw_open"); \
		fnum = io.ntcreatex.out.file.fnum; \
		setup \
		notify.nttrans.in.file.fnum = fnum;	\
		notify.nttrans.in.completion_filter = ((uint32_t)1<<i); \
		req = smb_raw_changenotify_send(cli->tree, &notify); \
		smb_raw_chkpath(cli->tree, &chkpath); \
		op \
		smb_msleep(200); smb_raw_ntcancel(req); \
		status = smb_raw_changenotify_recv(req, tctx, &notify); \
		cleanup \
		smbcli_close(cli->tree, fnum); \
		if (NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED)) continue; \
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done, \
						"smbcli_close"); \
		/* special case to cope with file rename behaviour */ \
		if (nchanges == 2 && notify.nttrans.out.num_changes == 1 && \
		    notify.nttrans.out.changes[0].action == NOTIFY_ACTION_MODIFIED && \
		    ((expected) & FILE_NOTIFY_CHANGE_ATTRIBUTES) && \
		    Action == NOTIFY_ACTION_OLD_NAME) { \
			torture_comment(tctx, "(rename file special handling OK)\n"); \
		} else { \
			torture_assert_int_equal_goto(tctx, \
				notify.nttrans.out.num_changes,\
				nchanges, ret, done, \
				talloc_asprintf(tctx, \
					"nchanges=%d expected=%d action=%d " \
					"filter=0x%08x\n", \
					notify.nttrans.out.num_changes, \
					nchanges, \
					notify.nttrans.out.changes[0].action, \
					notify.nttrans.in.completion_filter)); \
			torture_assert_int_equal_goto(tctx, \
				notify.nttrans.out.changes[0].action, \
				Action, ret, done, \
				talloc_asprintf(tctx, \
					"nchanges=%d action=%d " \
					"expectedAction=%d filter=0x%08x\n", \
					notify.nttrans.out.num_changes, \
					notify.nttrans.out.changes[0].action, \
					Action, \
					notify.nttrans.in.completion_filter)); \
			torture_assert_str_equal_goto(tctx, \
				notify.nttrans.out.changes[0].name.s, \
				"tname1", ret, done, \
				talloc_asprintf(tctx, \
					"nchanges=%d action=%d filter=0x%08x " \
					"name=%s expected_name=tname1\n", \
					notify.nttrans.out.num_changes, \
					notify.nttrans.out.changes[0].action, \
					notify.nttrans.in.completion_filter, \
					notify.nttrans.out.changes[0].name.s));\
		} \
		mask |= ((uint32_t)1<<i); \
	} \
	if ((expected) != mask) { \
		torture_assert_int_not_equal_goto(tctx, ((expected) & ~mask), \
				0, ret, done, "Too few bits"); \
		torture_comment(tctx, "WARNING: trigger on too many bits. mask=0x%08x expected=0x%08x\n", \
		       mask, expected); \
	} \
	} while (0);

	torture_comment(tctx, "Testing mkdir\n");
	NOTIFY_MASK_TEST("Testing mkdir",;,
			 smbcli_mkdir(cli->tree, BASEDIR_CN1_NOTM "\\tname1");,
			 smbcli_rmdir(cli2->tree, BASEDIR_CN1_NOTM "\\tname1");,
			 NOTIFY_ACTION_ADDED,
			 FILE_NOTIFY_CHANGE_DIR_NAME, 1);

	torture_comment(tctx, "Testing create file\n");
	NOTIFY_MASK_TEST("Testing create file",;,
			 smbcli_close(cli->tree,
				smbcli_open(cli->tree,
					BASEDIR_CN1_NOTM "\\tname1",
					O_CREAT, 0));,
			 smbcli_unlink(cli2->tree,
				BASEDIR_CN1_NOTM "\\tname1");,
			 NOTIFY_ACTION_ADDED,
			 FILE_NOTIFY_CHANGE_FILE_NAME, 1);

	torture_comment(tctx, "Testing unlink\n");
	NOTIFY_MASK_TEST("Testing unlink",
			 smbcli_close(cli->tree,
				smbcli_open(cli->tree,
					BASEDIR_CN1_NOTM "\\tname1",
					O_CREAT, 0));,
			 smbcli_unlink(cli2->tree,
				BASEDIR_CN1_NOTM "\\tname1");,
			 ;,
			 NOTIFY_ACTION_REMOVED,
			 FILE_NOTIFY_CHANGE_FILE_NAME, 1);

	torture_comment(tctx, "Testing rmdir\n");
	NOTIFY_MASK_TEST("Testing rmdir",
			 smbcli_mkdir(cli->tree, BASEDIR_CN1_NOTM "\\tname1");,
			 smbcli_rmdir(cli2->tree, BASEDIR_CN1_NOTM "\\tname1");,
			 ;,
			 NOTIFY_ACTION_REMOVED,
			 FILE_NOTIFY_CHANGE_DIR_NAME, 1);

	torture_comment(tctx, "Testing rename file\n");
	NOTIFY_MASK_TEST("Testing rename file",
			 smbcli_close(cli->tree,
				smbcli_open(cli->tree,
					BASEDIR_CN1_NOTM "\\tname1",
					O_CREAT, 0));,
			 smbcli_rename(cli2->tree,
				BASEDIR_CN1_NOTM "\\tname1",
				BASEDIR_CN1_NOTM "\\tname2");,
			 smbcli_unlink(cli->tree, BASEDIR_CN1_NOTM "\\tname2");,
			 NOTIFY_ACTION_OLD_NAME,
			 FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_ATTRIBUTES|FILE_NOTIFY_CHANGE_CREATION, 2);

	torture_comment(tctx, "Testing rename dir\n");
	NOTIFY_MASK_TEST("Testing rename dir",
		smbcli_mkdir(cli->tree, BASEDIR_CN1_NOTM "\\tname1");,
		smbcli_rename(cli2->tree,
			BASEDIR_CN1_NOTM "\\tname1",
			BASEDIR_CN1_NOTM "\\tname2");,
		smbcli_rmdir(cli->tree, BASEDIR_CN1_NOTM "\\tname2");,
		NOTIFY_ACTION_OLD_NAME,
		FILE_NOTIFY_CHANGE_DIR_NAME, 2);

	torture_comment(tctx, "Testing set path attribute\n");
	NOTIFY_MASK_TEST("Testing set path attribute",
		smbcli_close(cli->tree,
			smbcli_open(cli->tree,
				BASEDIR_CN1_NOTM "\\tname1", O_CREAT, 0));,
		smbcli_setatr(cli2->tree,
			BASEDIR_CN1_NOTM "\\tname1", FILE_ATTRIBUTE_HIDDEN, 0);,
		smbcli_unlink(cli->tree, BASEDIR_CN1_NOTM "\\tname1");,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_ATTRIBUTES, 1);

	torture_comment(tctx, "Testing set path write time\n");
	NOTIFY_MASK_TEST("Testing set path write time",
		smbcli_close(cli->tree, smbcli_open(cli->tree,
			BASEDIR_CN1_NOTM "\\tname1", O_CREAT, 0));,
		smbcli_setatr(cli2->tree,
			BASEDIR_CN1_NOTM "\\tname1",
			FILE_ATTRIBUTE_NORMAL, 1000);,
		smbcli_unlink(cli->tree, BASEDIR_CN1_NOTM "\\tname1");,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_LAST_WRITE, 1);

	torture_comment(tctx, "Testing set file attribute\n");
	NOTIFY_MASK_TEST("Testing set file attribute",
		fnum2 = create_complex_file(cli2, tctx,
			BASEDIR_CN1_NOTM "\\tname1");,
		smbcli_fsetatr(cli2->tree, fnum2, FILE_ATTRIBUTE_HIDDEN, 0, 0, 0, 0);,
		(smbcli_close(cli2->tree, fnum2),
		smbcli_unlink(cli2->tree, BASEDIR_CN1_NOTM "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_ATTRIBUTES, 1);

	if (torture_setting_bool(tctx, "samba3", false)) {
		torture_comment(tctx, "Samba3 does not yet support create times "
		       "everywhere\n");
	}
	else {
		torture_comment(tctx, "Testing set file create time\n");
		NOTIFY_MASK_TEST("Testing set file create time",
			fnum2 = create_complex_file(cli, tctx,
					    BASEDIR_CN1_NOTM "\\tname1");,
			smbcli_fsetatr(cli->tree, fnum2, 0, t, 0, 0, 0);,
			(smbcli_close(cli->tree, fnum2),
			 smbcli_unlink(cli->tree,
					BASEDIR_CN1_NOTM "\\tname1"));,
			NOTIFY_ACTION_MODIFIED,
			FILE_NOTIFY_CHANGE_CREATION, 1);
	}

	torture_comment(tctx, "Testing set file access time\n");
	NOTIFY_MASK_TEST("Testing set file access time",
		fnum2 = create_complex_file(cli, tctx,
				BASEDIR_CN1_NOTM "\\tname1");,
		smbcli_fsetatr(cli->tree, fnum2, 0, 0, t, 0, 0);,
		(smbcli_close(cli->tree, fnum2),
			smbcli_unlink(cli->tree, BASEDIR_CN1_NOTM "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_LAST_ACCESS, 1);

	torture_comment(tctx, "Testing set file write time\n");
	NOTIFY_MASK_TEST("Testing set file write time",
		fnum2 = create_complex_file(cli, tctx,
			BASEDIR_CN1_NOTM "\\tname1");,
		smbcli_fsetatr(cli->tree, fnum2, 0, 0, 0, t, 0);,
		(smbcli_close(cli->tree, fnum2),
		smbcli_unlink(cli->tree, BASEDIR_CN1_NOTM "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_LAST_WRITE, 1);

	torture_comment(tctx, "Testing set file change time\n");
	NOTIFY_MASK_TEST("Testing set file change time",
		fnum2 = create_complex_file(cli, tctx,
			BASEDIR_CN1_NOTM "\\tname1");,
		smbcli_fsetatr(cli->tree, fnum2, 0, 0, 0, 0, t);,
		(smbcli_close(cli->tree, fnum2),
		smbcli_unlink(cli->tree, BASEDIR_CN1_NOTM "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		0, 1);


	torture_comment(tctx, "Testing write\n");
	NOTIFY_MASK_TEST("Testing write",
		fnum2 = create_complex_file(cli2, tctx,
			BASEDIR_CN1_NOTM "\\tname1");,
		smbcli_write(cli2->tree, fnum2, 1, &c, 10000, 1);,
		(smbcli_close(cli2->tree, fnum2),
			smbcli_unlink(cli->tree, BASEDIR_CN1_NOTM "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		0, 1);

	torture_comment(tctx, "Testing truncate\n");
	NOTIFY_MASK_TEST("Testing truncate",
		fnum2 = create_complex_file(cli2, tctx,
			BASEDIR_CN1_NOTM "\\tname1");,
		smbcli_ftruncate(cli2->tree, fnum2, 10000);,
		(smbcli_close(cli2->tree, fnum2),
		smbcli_unlink(cli2->tree, BASEDIR_CN1_NOTM "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_ATTRIBUTES, 1);

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_NOTM);
	return ret;
}

/*
  basic testing of change notify on files
*/

#define BASEDIR_CN1_FILE BASEDIR "_CN1_FILE"

static bool test_notify_file(struct torture_context *tctx,
			     struct smbcli_state *cli)
{
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_close cl;
	union smb_notify notify;
	struct smbcli_request *req;
	int fnum;
	const char *fname = BASEDIR_CN1_FILE "\\file.txt";

	torture_comment(tctx, "TESTING CHANGE NOTIFY ON FILES\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_FILE),
		       "Failed to setup up test directory: " BASEDIR_CN1_FILE);

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_STREAM_NAME;
	notify.nttrans.in.recursive = false;

	torture_comment(tctx, "Testing if notifies on file handles are invalid (should be)\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_INVALID_PARAMETER,
					   ret, done,
					   "smb_raw_changenotify_recv");

	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_close");

	status = smbcli_unlink(cli->tree, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smbcli_unlink");

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_FILE);
	return ret;
}

/*
  basic testing of change notifies followed by a tdis
*/
#define BASEDIR_CN1_TDIS BASEDIR "_CN1_TDIS"

static bool test_notify_tdis(struct torture_context *tctx,
			     struct smbcli_state *cli1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	torture_comment(tctx, "TESTING CHANGE NOTIFY FOLLOWED BY TDIS\n");

	torture_assert(tctx, torture_setup_dir(cli1, BASEDIR_CN1_TDIS),
		       "Failed to setup up test directory: " BASEDIR_CN1_TDIS);

	torture_assert(tctx, torture_open_connection(&cli, tctx, 0),
		       "Failed to open connection.");

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_TDIS;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = true;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smbcli_tdis(cli);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smbcli_tdis");
	cli->tree = NULL;

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      0, ret, done, "no changes expected");

done:
	torture_close_connection(cli);
	smbcli_deltree(cli1->tree, BASEDIR_CN1_TDIS);
	return ret;
}

/*
  basic testing of change notifies followed by a exit
*/

#define BASEDIR_CN1_EX BASEDIR "_CN1_EX"

static bool test_notify_exit(struct torture_context *tctx,
			     struct smbcli_state *cli1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	torture_comment(tctx, "TESTING CHANGE NOTIFY FOLLOWED BY EXIT\n");

	torture_assert(tctx, torture_setup_dir(cli1, BASEDIR_CN1_EX),
		       "Failed to setup up test directory: " BASEDIR_CN1_EX);

	torture_assert(tctx, torture_open_connection(&cli, tctx, 0),
		       "Failed to open connection.");

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_EX;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = true;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smb_raw_exit(cli->session);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_exit");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      0, ret, done, "no changes expected");

done:
	torture_close_connection(cli);
	smbcli_deltree(cli1->tree, BASEDIR_CN1_EX);
	return ret;
}

/*
  basic testing of change notifies followed by a ulogoff
*/

#define BASEDIR_CN1_UL BASEDIR "_CN1_UL"

static bool test_notify_ulogoff(struct torture_context *tctx,
				struct smbcli_state *cli1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	torture_comment(tctx, "TESTING CHANGE NOTIFY FOLLOWED BY ULOGOFF\n");

	torture_assert(tctx, torture_setup_dir(cli1, BASEDIR_CN1_UL),
		       "Failed to setup up test directory: " BASEDIR_CN1_UL);

	torture_assert(tctx, torture_open_connection(&cli, tctx, 0),
		       "Failed to open connection.");

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_UL;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = true;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smb_raw_ulogoff(cli->session);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_ulogoff");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      0, ret, done, "no changes expected");

done:
	torture_close_connection(cli);
	smbcli_deltree(cli1->tree, BASEDIR_CN1_UL);
	return ret;
}

static void tcp_dis_handler(struct smbcli_transport *t, void *p)
{
	struct smbcli_state *cli = (struct smbcli_state *)p;
	smbcli_transport_dead(cli->transport, NT_STATUS_LOCAL_DISCONNECT);
	cli->transport = NULL;
	cli->tree = NULL;
}
/*
  basic testing of change notifies followed by tcp disconnect
*/

#define BASEDIR_CN1_TCPDIS BASEDIR "_CN1_TCPDIS"

static bool test_notify_tcp_dis(struct torture_context *tctx,
				struct smbcli_state *cli1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	torture_comment(tctx, "TESTING CHANGE NOTIFY FOLLOWED BY TCP DISCONNECT\n");

	torture_assert(tctx, torture_setup_dir(cli1, BASEDIR_CN1_TCPDIS),
		       "Failed to setup up test directory: "
			BASEDIR_CN1_TCPDIS);

	torture_assert(tctx, torture_open_connection(&cli, tctx, 0),
		       "Failed to open connection.");

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_TCPDIS;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = true;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	smbcli_transport_idle_handler(cli->transport, tcp_dis_handler, 250000, cli);

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_LOCAL_DISCONNECT,
					   ret, done,
					   "smb_raw_changenotify_recv");

done:
	torture_close_connection(cli);
	smbcli_deltree(cli1->tree, BASEDIR_CN1_TCPDIS);
	return ret;
}

/* 
   test setting up two change notify requests on one handle
*/

#define BASEDIR_CN1_DBL BASEDIR "_CN1_DBL"

static bool test_notify_double(struct torture_context *tctx,
			       struct smbcli_state *cli)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req1, *req2;

	torture_comment(tctx, "TESTING CHANGE NOTIFY TWICE ON ONE DIRECTORY\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_DBL),
		       "Failed to setup up test directory: " BASEDIR_CN1_DBL);

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_DBL;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = true;

	req1 = smb_raw_changenotify_send(cli->tree, &notify);
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	smbcli_mkdir(cli->tree, BASEDIR_CN1_DBL "\\subdir-name");

	status = smb_raw_changenotify_recv(req1, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);

	smbcli_mkdir(cli->tree, BASEDIR_CN1_DBL "\\subdir-name2");

	status = smb_raw_changenotify_recv(req2, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name2",
		   STR_UNICODE);

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_DBL);
	return ret;
}


/* 
   test multiple change notifies at different depths and with/without recursion
*/

#define BASEDIR_CN1_TNT BASEDIR "_CN1_TNT"

static bool test_notify_tree(struct torture_context *tctx,
			     struct smbcli_state *cli,
			     struct smbcli_state *cli2)
{
	bool ret = true;
	union smb_notify notify;
	union smb_open io;
	struct smbcli_request *req;
	struct timeval tv;
	struct {
		const char *path;
		bool recursive;
		uint32_t filter;
		int expected;
		int fnum;
		int counted;
	} dirs[] = {
		{
			.path      = BASEDIR_CN1_TNT "\\abc",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 30,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\zqy",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 8,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\atsy",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 4,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc\\foo",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 2,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc\\blah",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 13,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc\\blah",
			.recursive = false,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 7,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc\\blah\\a",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 2,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc\\blah\\b",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 2,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc\\blah\\c",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 2,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc\\fooblah",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 2,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\zqy\\xx",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 2,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\zqy\\yyy",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 2,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\zqy\\..",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 40,
		},
		{
			.path      = BASEDIR_CN1_TNT,
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 40,
		},
		{
			.path      = BASEDIR_CN1_TNT,
			.recursive = false,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 6,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\atsy",
			.recursive = false,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 4,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 24,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc",
			.recursive = false,
			.filter    = FILE_NOTIFY_CHANGE_FILE_NAME,
			.expected  = 0,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_FILE_NAME,
			.expected  = 0,
		},
		{
			.path      = BASEDIR_CN1_TNT "\\abc",
			.recursive = true,
			.filter    = FILE_NOTIFY_CHANGE_NAME,
			.expected  = 24,
		},
	};
	int i;
	NTSTATUS status;
	bool all_done = false;

	torture_comment(tctx, "TESTING CHANGE NOTIFY FOR DIFFERENT DEPTHS\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_TNT),
		       "Failed to setup up test directory: " BASEDIR_CN1_TNT);

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;

	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 20000;

	/*
	  setup the directory tree, and the notify buffer on each directory
	*/
	for (i=0;i<ARRAY_SIZE(dirs);i++) {
		io.ntcreatex.in.fname = dirs[i].path;
		status = smb_raw_open(cli->tree, tctx, &io);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb_raw_open");
		dirs[i].fnum = io.ntcreatex.out.file.fnum;

		notify.nttrans.in.completion_filter = dirs[i].filter;
		notify.nttrans.in.file.fnum = dirs[i].fnum;
		notify.nttrans.in.recursive = dirs[i].recursive;
		req = smb_raw_changenotify_send(cli->tree, &notify);
		smb_raw_ntcancel(req);
		status = smb_raw_changenotify_recv(req, tctx, &notify);
		torture_assert_ntstatus_equal_goto(tctx, status,
						   NT_STATUS_CANCELLED,
						   ret, done,
						   "smb_raw_changenotify_recv");
	}

	/* trigger 2 events in each dir */
	for (i=0;i<ARRAY_SIZE(dirs);i++) {
		char *path = talloc_asprintf(tctx, "%s\\test.dir", dirs[i].path);
		/*
		 * Make notifies a bit more interesting in a cluster
		 * by doing the changes against different nodes with
		 * --unclist
		 */
		smbcli_mkdir(cli->tree, path);
		smbcli_rmdir(cli2->tree, path);
		talloc_free(path);
	}

	/* give a bit of time for the events to propagate */
	tv = timeval_current();

	do {
		/* count events that have happened in each dir */
		for (i=0;i<ARRAY_SIZE(dirs);i++) {
			notify.nttrans.in.file.fnum = dirs[i].fnum;
			req = smb_raw_changenotify_send(cli->tree, &notify);
			smb_raw_ntcancel(req);
			notify.nttrans.out.num_changes = 0;
			status = smb_raw_changenotify_recv(req, tctx, &notify);
			dirs[i].counted += notify.nttrans.out.num_changes;
		}
		
		all_done = true;

		for (i=0;i<ARRAY_SIZE(dirs);i++) {
			if (dirs[i].counted != dirs[i].expected) {
				all_done = false;
			}
		}
	} while (!all_done && timeval_elapsed(&tv) < 20);

	torture_comment(tctx, "took %.4f seconds to propagate all events\n", timeval_elapsed(&tv));

	for (i=0;i<ARRAY_SIZE(dirs);i++) {
		torture_assert_int_equal_goto(tctx,
			dirs[i].counted, dirs[i].expected, ret, done,
			talloc_asprintf(tctx,
					"unexpected number of events for '%s'",
					dirs[i].path));
	}

	/*
	  run from the back, closing and deleting
	*/
	for (i=ARRAY_SIZE(dirs)-1;i>=0;i--) {
		smbcli_close(cli->tree, dirs[i].fnum);
		smbcli_rmdir(cli->tree, dirs[i].path);
	}

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_TNT);
	return ret;
}

/*
   Test response when cached server events exceed single NT NOTFIY response
   packet size.
*/

#define BASEDIR_CN1_NO BASEDIR "_CN1_NO"

static bool test_notify_overflow(struct torture_context *tctx,
				 struct smbcli_state *cli)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	int count = 100;
	struct smbcli_request *req1;
	int i;

	torture_comment(tctx, "TESTING CHANGE NOTIFY EVENT OVERFLOW\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_NO),
		       "Failed to setup up test directory: " BASEDIR_CN1_NO);

	/* get a handle on the directory */
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
	    NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_NO;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify, on name changes. */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;

	notify.nttrans.in.recursive = true;
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	/* cancel initial requests so the buffer is setup */
	smb_raw_ntcancel(req1);
	status = smb_raw_changenotify_recv(req1, tctx, &notify);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_CANCELLED,
					   ret, done,
					   "smb_raw_changenotify_recv");

	/* open a lot of files, filling up the server side notify buffer */
	torture_comment(tctx, "Testing overflowed buffer notify on create of %d files\n",
	       count);
	for (i=0;i<count;i++) {
		char *fname = talloc_asprintf(cli,
				BASEDIR_CN1_NO "\\test%d.txt", i);
		int fnum2 = smbcli_open(cli->tree, fname, O_CREAT|O_RDWR,
					DENY_NONE);
		torture_assert_int_not_equal_goto(tctx, fnum2, -1, ret, done,
			talloc_asprintf(tctx, "Failed to create %s - %s",
					fname, smbcli_errstr(cli->tree)));
		talloc_free(fname);
		smbcli_close(cli->tree, fnum2);
	}

	/* expect that 0 events will be returned with NT_STATUS_OK */
	req1 = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req1, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      0, ret, done, "no changes expected");

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_NO);
	return ret;
}

/*
   Test if notifications are returned for changes to the base directory.
   They shouldn't be.
*/

#define BASEDIR_CN1_NBASE BASEDIR "_CN1_NBASE"

static bool test_notify_basedir(struct torture_context *tctx,
				struct smbcli_state *cli)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req1;

	torture_comment(tctx, "TESTING CHANGE NOTIFY BASEDIR EVENTS\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_NBASE),
		       "Failed to setup up test directory: " BASEDIR_CN1_NBASE);

	/* get a handle on the directory */
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
	    NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_NBASE;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* create a test file that will also be modified */
	smbcli_close(cli->tree, smbcli_open(cli->tree,
				BASEDIR_CN1_NBASE "\\tname1",
					    O_CREAT, 0));

	/* ask for a change notify, on attribute changes. */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_ATTRIBUTES;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = true;

	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	/* set attribute on the base dir */
	smbcli_setatr(cli->tree, BASEDIR_CN1_NBASE, FILE_ATTRIBUTE_HIDDEN, 0);

	/* set attribute on a file to assure we receive a notification */
	smbcli_setatr(cli->tree, BASEDIR_CN1_NBASE "\\tname1",
			FILE_ATTRIBUTE_HIDDEN, 0);
	smb_msleep(200);

	/* check how many responses were given, expect only 1 for the file */
	status = smb_raw_changenotify_recv(req1, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of  changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_MODIFIED, ret, done,
				      "wrong action (exp: MODIFIED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "tname1",
		   STR_UNICODE);

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_NBASE);
	return ret;
}


/*
  create a secondary tree connect - used to test for a bug in Samba3 messaging
  with change notify
*/

static struct smbcli_tree *secondary_tcon(struct smbcli_state *cli, 
					  struct torture_context *tctx)
{
	NTSTATUS status;
	const char *share, *host;
	struct smbcli_tree *tree;
	union smb_tcon tcon;

	share = torture_setting_string(tctx, "share", NULL);
	host  = torture_setting_string(tctx, "host", NULL);
	
	torture_comment(tctx, "create a second tree context on the same session\n");
	tree = smbcli_tree_init(cli->session, tctx, false);

	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = TCONX_FLAG_EXTENDED_RESPONSE;
	tcon.tconx.in.password = data_blob(NULL, 0);
	tcon.tconx.in.path = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	tcon.tconx.in.device = "A:";	
	status = smb_raw_tcon(tree, tctx, &tcon);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tree);
		torture_comment(tctx, "Failed to create secondary tree\n");
		return NULL;
	}

	tree->tid = tcon.tconx.out.tid;
	torture_comment(tctx, "tid1=%d tid2=%d\n", cli->tree->tid, tree->tid);

	return tree;
}


/* 
   very simple change notify test
*/

#define BASEDIR_CN1_NTCON BASEDIR "_CN1_NTCON"

static bool test_notify_tcon(struct torture_context *tctx,
			     struct smbcli_state *cli)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	extern int torture_numops;
	struct smbcli_tree *tree = NULL;
		
	torture_comment(tctx, "TESTING SIMPLE CHANGE NOTIFY\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_NTCON),
		       "Failed to setup up test directory: " BASEDIR_CN1_NTCON);

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_NTCON;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_open");

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = true;

	torture_comment(tctx, "Testing notify mkdir\n");
	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_mkdir(cli->tree, BASEDIR_CN1_NTCON "\\subdir-name");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "wrong action (exp: ADDED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);

	torture_comment(tctx, "Testing notify rmdir\n");
	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_rmdir(cli->tree, BASEDIR_CN1_NTCON "\\subdir-name");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);

	torture_comment(tctx, "SIMPLE CHANGE NOTIFY OK\n");

	torture_comment(tctx, "TESTING WITH SECONDARY TCON\n");
	tree = secondary_tcon(cli, tctx);
	torture_assert_not_null_goto(tctx, tree, ret, done,
				     "failed to create secondary tcon");

	torture_comment(tctx, "Testing notify mkdir\n");
	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_mkdir(cli->tree, BASEDIR_CN1_NTCON "\\subdir-name");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "wrong action (exp: ADDED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);

	torture_comment(tctx, "Testing notify rmdir\n");
	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_rmdir(cli->tree, BASEDIR_CN1_NTCON "\\subdir-name");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);

	torture_comment(tctx, "CHANGE NOTIFY WITH TCON OK\n");

	torture_comment(tctx, "Disconnecting secondary tree\n");
	status = smb_tree_disconnect(tree);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_tree_disconnect");
	talloc_free(tree);

	torture_comment(tctx, "Testing notify mkdir\n");
	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_mkdir(cli->tree, BASEDIR_CN1_NTCON "\\subdir-name");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");

	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "wrong action (exp: ADDED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);

	torture_comment(tctx, "Testing notify rmdir\n");
	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_rmdir(cli->tree, BASEDIR_CN1_NTCON "\\subdir-name");

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb_raw_changenotify_recv");
	torture_assert_int_equal_goto(tctx, notify.nttrans.out.num_changes,
				      1, ret, done, "wrong number of changes");
	torture_assert_int_equal_goto(tctx,
				      notify.nttrans.out.changes[0].action,
				      NOTIFY_ACTION_REMOVED, ret, done,
				      "wrong action (exp: REMOVED)");
	CHECK_WSTR(tctx, notify.nttrans.out.changes[0].name, "subdir-name",
		   STR_UNICODE);

	torture_comment(tctx, "CHANGE NOTIFY WITH TDIS OK\n");
done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_NTCON);
	return ret;
}

struct cb_data {
	struct smbcli_request *req;
	bool timed_out;
};

static void timeout_cb(struct tevent_context *ev,
			struct tevent_timer *te,
			struct timeval current_time,
			void *private_data)
{
	struct cb_data *cbp = (struct cb_data *)private_data;
	cbp->req->state = SMBCLI_REQUEST_ERROR;
	cbp->timed_out = true;
}

/*
   testing alignment of multiple change notify infos
*/

#define BASEDIR_CN1_NALIGN BASEDIR "_CN1_NALIGN"

static bool test_notify_alignment(struct torture_context *tctx,
				  struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum, fnum2;
	struct smbcli_request *req;
	const char *fname = BASEDIR_CN1_NALIGN "\\starter";
	const char *fnames[] = { "a",
				 "ab",
				 "abc",
				 "abcd" };
	bool fnames_received[] = {false,
				  false,
				  false,
				  false};
	size_t total_names_received = 0;
	size_t num_names = ARRAY_SIZE(fnames);
	size_t i;
	char *fpath = NULL;

	torture_comment(tctx, "TESTING CHANGE NOTIFY REPLY ALIGNMENT\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR_CN1_NALIGN),
		"Failed to setup up test directory: " BASEDIR_CN1_NALIGN);

	/* get a handle on the directory */
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				       NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR_CN1_NALIGN;

	status = smb_raw_open(cli->tree, tctx, &io);
	torture_assert_ntstatus_ok(tctx, status, "smb_raw_open");
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify, on file creation */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_FILE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = false;

	/* start change tracking */
	req = smb_raw_changenotify_send(cli->tree, &notify);

	fnum2 = smbcli_open(cli->tree, fname, O_CREAT|O_RDWR, DENY_NONE);
	torture_assert(tctx, fnum2 != -1, smbcli_errstr(cli->tree));
	smbcli_close(cli->tree, fnum2);

	status = smb_raw_changenotify_recv(req, tctx, &notify);
	torture_assert_ntstatus_ok(tctx, status, "smb_raw_changenotify_recv");

	/* create 4 files that will cause CHANGE_NOTIFY_INFO structures
	 * to be returned in the same packet with all possible 4-byte padding
	 * permutations.  As per MS-CIFS 2.2.7.4.2 these structures should be
	 * 4-byte aligned. */

	for (i = 0; i < num_names; i++) {
		fpath = talloc_asprintf(tctx, "%s\\%s",
				BASEDIR_CN1_NALIGN, fnames[i]);
		fnum2 = smbcli_open(cli->tree, fpath,
		    O_CREAT|O_RDWR, DENY_NONE);
		torture_assert(tctx, fnum2 != -1, smbcli_errstr(cli->tree));
		smbcli_close(cli->tree, fnum2);
		talloc_free(fpath);
	}

	/*
	 * Slow cloud filesystems mean we might
	 * not get everything in one go. Keep going
	 * until we get them all.
	 */
	while (total_names_received < num_names) {
		struct tevent_timer *te = NULL;
		struct cb_data to_data = {0};

		/*
		 * We send a notify packet, and let
		 * smb_raw_changenotify_recv() do
		 * the alignment checking for us.
		 */
		req = smb_raw_changenotify_send(cli->tree, &notify);
		torture_assert(tctx,
			req != NULL,
			"smb_raw_changenotify_send failed\n");

		/* Ensure we don't wait more than 30 seconds. */
		to_data.req = req;
		to_data.timed_out = false;

		te = tevent_add_timer(tctx->ev,
				req,
				tevent_timeval_current_ofs(30, 0),
				timeout_cb,
				&to_data);
		if (te == NULL) {
			torture_fail(tctx, "tevent_add_timer fail\n");
		}

		status = smb_raw_changenotify_recv(req, tctx, &notify);
		if (!NT_STATUS_IS_OK(status)) {
			if (to_data.timed_out == true) {
				torture_fail(tctx, "smb_raw_changenotify_recv "
					"timed out\n");
			}
		}

		torture_assert_ntstatus_ok(tctx, status,
			"smb_raw_changenotify_recv");

		for (i = 0; i < notify.nttrans.out.num_changes; i++) {
			size_t j;

			/* Ensure it was an 'add'. */
			torture_assert(tctx,
				notify.nttrans.out.changes[i].action ==
					NOTIFY_ACTION_ADDED,
				"");

			for (j = 0; j < num_names; j++) {
				if (strcmp(notify.nttrans.out.changes[i].name.s,
						fnames[j]) == 0) {
					if (fnames_received[j] == true) {
						const char *err =
							talloc_asprintf(tctx,
								"Duplicate "
								"name %s\n",
								fnames[j]);
						if (err == NULL) {
							torture_fail(tctx,
								"talloc "
								"fail\n");
						}
						/* already got this. */
						torture_fail(tctx, err);
					}
					fnames_received[j] = true;
					break;
				}
			}
			if (j == num_names) {
				/* No name match. */
				const char *err = talloc_asprintf(tctx,
					"Unexpected name %s\n",
					notify.nttrans.out.changes[i].name.s);
				if (err == NULL) {
					torture_fail(tctx, "talloc fail\n");
				}
				torture_fail(tctx, err);
			}
			total_names_received++;
		}
	}

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR_CN1_NALIGN);
	return true;
}

struct torture_suite *torture_raw_notify(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "notify");

	torture_suite_add_1smb_test(suite, "tcon", test_notify_tcon);
	torture_suite_add_2smb_test(suite, "dir", test_notify_dir);
	torture_suite_add_2smb_test(suite, "mask", test_notify_mask);
	torture_suite_add_2smb_test(suite, "recursive", test_notify_recursive);
	torture_suite_add_1smb_test(suite, "mask_change",
				    test_notify_mask_change);
	torture_suite_add_1smb_test(suite, "file", test_notify_file);
	torture_suite_add_1smb_test(suite, "tdis", test_notify_tdis);
	torture_suite_add_1smb_test(suite, "exit", test_notify_exit);
	torture_suite_add_1smb_test(suite, "ulogoff", test_notify_ulogoff);
	torture_suite_add_1smb_test(suite, "tcp_dis", test_notify_tcp_dis);
	torture_suite_add_1smb_test(suite, "double", test_notify_double);
	torture_suite_add_2smb_test(suite, "tree", test_notify_tree);
	torture_suite_add_1smb_test(suite, "overflow", test_notify_overflow);
	torture_suite_add_1smb_test(suite, "basedir", test_notify_basedir);
	torture_suite_add_1smb_test(suite, "alignment", test_notify_alignment);

	return suite;
}
