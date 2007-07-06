/* 
   Unix SMB/CIFS implementation.
   basic raw test suite for change notify
   Copyright (C) Andrew Tridgell 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "system/filesys.h"
#include "torture/util.h"

#define BASEDIR "\\test_notify"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%d) wrong value for %s  0x%x should be 0x%x\n", \
		       __LINE__, #v, (int)v, (int)correct); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_WSTR(field, value, flags) do { \
	if (!field.s || strcmp(field.s, value) || wire_bad_flags(&field, flags, cli->transport)) { \
		printf("(%d) %s [%s] != %s\n",  __LINE__, #field, field.s, value); \
			ret = False; \
		goto done; \
	}} while (0)


/* 
   basic testing of change notify on directories
*/
static BOOL test_notify_dir(struct smbcli_state *cli, struct smbcli_state *cli2, 
			    TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	union smb_close cl;
	int i, count, fnum, fnum2;
	struct smbcli_request *req, *req2;
	extern int torture_numops;

	printf("TESTING CHANGE NOTIFY ON DIRECTRIES\n");
		
	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = True;

	printf("testing notify cancel\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smb_raw_ntcancel(req);
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_CANCELLED);

	printf("testing notify mkdir\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_mkdir(cli2->tree, BASEDIR "\\subdir-name");

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(notify.nttrans.out.num_changes, 1);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_ADDED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "subdir-name", STR_UNICODE);

	printf("testing notify rmdir\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_rmdir(cli2->tree, BASEDIR "\\subdir-name");

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 1);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "subdir-name", STR_UNICODE);

	printf("testing notify mkdir - rmdir - mkdir - rmdir\n");

	smbcli_mkdir(cli2->tree, BASEDIR "\\subdir-name");
	smbcli_rmdir(cli2->tree, BASEDIR "\\subdir-name");
	smbcli_mkdir(cli2->tree, BASEDIR "\\subdir-name");
	smbcli_rmdir(cli2->tree, BASEDIR "\\subdir-name");
	msleep(200);
	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 4);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_ADDED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "subdir-name", STR_UNICODE);
	CHECK_VAL(notify.nttrans.out.changes[1].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.nttrans.out.changes[1].name, "subdir-name", STR_UNICODE);
	CHECK_VAL(notify.nttrans.out.changes[2].action, NOTIFY_ACTION_ADDED);
	CHECK_WSTR(notify.nttrans.out.changes[2].name, "subdir-name", STR_UNICODE);
	CHECK_VAL(notify.nttrans.out.changes[3].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.nttrans.out.changes[3].name, "subdir-name", STR_UNICODE);

	count = torture_numops;
	printf("testing buffered notify on create of %d files\n", count);
	for (i=0;i<count;i++) {
		char *fname = talloc_asprintf(cli, BASEDIR "\\test%d.txt", i);
		int fnum3 = smbcli_open(cli->tree, fname, O_CREAT|O_RDWR, DENY_NONE);
		if (fnum3 == -1) {
			printf("Failed to create %s - %s\n", 
			       fname, smbcli_errstr(cli->tree));
			ret = False;
			goto done;
		}
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

	status = smbcli_unlink(cli->tree, BASEDIR "\\nonexistant.txt");
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/* (1st unlink) as the 2nd notify directly returns,
	   this unlink is only seen by the 1st notify and 
	   the 3rd notify (later) */
	printf("testing notify on unlink for the first file\n");
	status = smbcli_unlink(cli2->tree, BASEDIR "\\test0.txt");
	CHECK_STATUS(status, NT_STATUS_OK);

	/* receive the reply from the 2nd notify */
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(notify.nttrans.out.num_changes, count);
	for (i=1;i<count;i++) {
		CHECK_VAL(notify.nttrans.out.changes[i].action, NOTIFY_ACTION_ADDED);
	}
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "test0.txt", STR_UNICODE);

	printf("and now from the 1st notify\n");
	status = smb_raw_changenotify_recv(req2, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 1);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "test0.txt", STR_UNICODE);

	printf("(3rd notify) this notify will only see the 1st unlink\n");
	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smbcli_unlink(cli->tree, BASEDIR "\\nonexistant.txt");
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	printf("testing notify on wildcard unlink for %d files\n", count-1);
	/* (2nd unlink) do a wildcard unlink */
	status = smbcli_unlink(cli2->tree, BASEDIR "\\test*.txt");
	CHECK_STATUS(status, NT_STATUS_OK);

	/* receive the 3rd notify */
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 1);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "test0.txt", STR_UNICODE);

	/* and we now see the rest of the unlink calls on both directory handles */
	notify.nttrans.in.file.fnum = fnum;
	sleep(3);
	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, count-1);
	for (i=0;i<notify.nttrans.out.num_changes;i++) {
		CHECK_VAL(notify.nttrans.out.changes[i].action, NOTIFY_ACTION_REMOVED);
	}
	notify.nttrans.in.file.fnum = fnum2;
	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, count-1);
	for (i=0;i<notify.nttrans.out.num_changes;i++) {
		CHECK_VAL(notify.nttrans.out.changes[i].action, NOTIFY_ACTION_REMOVED);
	}

	printf("testing if a close() on the dir handle triggers the notify reply\n");

	notify.nttrans.in.file.fnum = fnum;
	req = smb_raw_changenotify_send(cli->tree, &notify);

	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 0);

done:
	smb_raw_exit(cli->session);
	return ret;
}

/*
 * Check notify reply for a rename action. Not sure if this is a valid thing
 * to do, but depending on timing between inotify and messaging we get the
 * add/remove/modify in any order. This routines tries to find the action/name
 * pair in any of the three following notify_changes.
 */

static BOOL check_rename_reply(struct smbcli_state *cli,
			       int line,
			       struct notify_changes *actions,
			       uint32_t action, const char *name)
{
	int i;

	for (i=0; i<3; i++) {
		if (actions[i].action == action) {
			if ((actions[i].name.s == NULL)
			    || (strcmp(actions[i].name.s, name) != 0)
			    || (wire_bad_flags(&actions[i].name, STR_UNICODE,
					       cli->transport))) {
				printf("(%d) name [%s] != %s\n", line,
				       actions[i].name.s, name);
				return False;
			}
			return True;
		}
	}

	printf("(%d) expected action %d, not found\n", line, action);
	return False;
}

/* 
   testing of recursive change notify
*/
static BOOL test_notify_recursive(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req1, *req2;

	printf("TESTING CHANGE NOTIFY WITH RECURSION\n");
		
	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify, on file or directory name
	   changes. Setup both with and without recursion */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_CREATION;
	notify.nttrans.in.file.fnum = fnum;

	notify.nttrans.in.recursive = True;
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	notify.nttrans.in.recursive = False;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	/* cancel initial requests so the buffer is setup */
	smb_raw_ntcancel(req1);
	status = smb_raw_changenotify_recv(req1, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_CANCELLED);

	smb_raw_ntcancel(req2);
	status = smb_raw_changenotify_recv(req2, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_CANCELLED);

	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name");
	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name\\subname1");
	smbcli_close(cli->tree, 
		     smbcli_open(cli->tree, BASEDIR "\\subdir-name\\subname2", O_CREAT, 0));
	smbcli_rename(cli->tree, BASEDIR "\\subdir-name\\subname1", BASEDIR "\\subdir-name\\subname1-r");
	smbcli_rename(cli->tree, BASEDIR "\\subdir-name\\subname2", BASEDIR "\\subname2-r");
	smbcli_rename(cli->tree, BASEDIR "\\subname2-r", BASEDIR "\\subname3-r");

	notify.nttrans.in.completion_filter = 0;
	notify.nttrans.in.recursive = True;
	msleep(200);
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	smbcli_rmdir(cli->tree, BASEDIR "\\subdir-name\\subname1-r");
	smbcli_rmdir(cli->tree, BASEDIR "\\subdir-name");
	smbcli_unlink(cli->tree, BASEDIR "\\subname3-r");

	notify.nttrans.in.recursive = False;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	status = smb_raw_changenotify_recv(req1, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(notify.nttrans.out.num_changes, 11);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_ADDED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "subdir-name", STR_UNICODE);
	CHECK_VAL(notify.nttrans.out.changes[1].action, NOTIFY_ACTION_ADDED);
	CHECK_WSTR(notify.nttrans.out.changes[1].name, "subdir-name\\subname1", STR_UNICODE);
	CHECK_VAL(notify.nttrans.out.changes[2].action, NOTIFY_ACTION_ADDED);
	CHECK_WSTR(notify.nttrans.out.changes[2].name, "subdir-name\\subname2", STR_UNICODE);
	CHECK_VAL(notify.nttrans.out.changes[3].action, NOTIFY_ACTION_OLD_NAME);
	CHECK_WSTR(notify.nttrans.out.changes[3].name, "subdir-name\\subname1", STR_UNICODE);
	CHECK_VAL(notify.nttrans.out.changes[4].action, NOTIFY_ACTION_NEW_NAME);
	CHECK_WSTR(notify.nttrans.out.changes[4].name, "subdir-name\\subname1-r", STR_UNICODE);

	ret &= check_rename_reply(
		cli, __LINE__, &notify.nttrans.out.changes[5],
		NOTIFY_ACTION_ADDED, "subname2-r");
	ret &= check_rename_reply(
		cli, __LINE__, &notify.nttrans.out.changes[5],
		NOTIFY_ACTION_REMOVED, "subdir-name\\subname2");
	ret &= check_rename_reply(
		cli, __LINE__, &notify.nttrans.out.changes[5],
		NOTIFY_ACTION_MODIFIED, "subname2-r");
		
	ret &= check_rename_reply(
		cli, __LINE__, &notify.nttrans.out.changes[8],
		NOTIFY_ACTION_OLD_NAME, "subname2-r");
	ret &= check_rename_reply(
		cli, __LINE__, &notify.nttrans.out.changes[8],
		NOTIFY_ACTION_NEW_NAME, "subname3-r");
	ret &= check_rename_reply(
		cli, __LINE__, &notify.nttrans.out.changes[8],
		NOTIFY_ACTION_MODIFIED, "subname3-r");

	if (!ret) {
		goto done;
	}

	status = smb_raw_changenotify_recv(req2, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(notify.nttrans.out.num_changes, 3);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "subdir-name\\subname1-r", STR_UNICODE);
	CHECK_VAL(notify.nttrans.out.changes[1].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.nttrans.out.changes[1].name, "subdir-name", STR_UNICODE);
	CHECK_VAL(notify.nttrans.out.changes[2].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.nttrans.out.changes[2].name, "subname3-r", STR_UNICODE);

done:
	smb_raw_exit(cli->session);
	return ret;
}

/* 
   testing of change notify mask change
*/
static BOOL test_notify_mask_change(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req1, *req2;
	union smb_setfileinfo sfinfo;

	printf("TESTING CHANGE NOTIFY WITH MASK CHANGE\n");

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify, on file or directory name
	   changes. Setup both with and without recursion */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_ATTRIBUTES;
	notify.nttrans.in.file.fnum = fnum;

	notify.nttrans.in.recursive = True;
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	notify.nttrans.in.recursive = False;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	/* cancel initial requests so the buffer is setup */
	smb_raw_ntcancel(req1);
	status = smb_raw_changenotify_recv(req1, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_CANCELLED);

	smb_raw_ntcancel(req2);
	status = smb_raw_changenotify_recv(req2, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_CANCELLED);

	notify.nttrans.in.recursive = True;
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	/* Set to hidden then back again. */
	smbcli_close(cli->tree, smbcli_open(cli->tree, BASEDIR "\\tname1", O_CREAT, 0));
	smbcli_setatr(cli->tree, BASEDIR "\\tname1", FILE_ATTRIBUTE_HIDDEN, 0);
	smbcli_unlink(cli->tree, BASEDIR "\\tname1");

	status = smb_raw_changenotify_recv(req1, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(notify.nttrans.out.num_changes, 1);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_MODIFIED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "tname1", STR_UNICODE);

	/* Now try and change the mask to include other events.
	 * This should not work - once the mask is set on a directory
	 * fnum it seems to be fixed until the fnum is closed. */

	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_CREATION;
	notify.nttrans.in.recursive = True;
	req1 = smb_raw_changenotify_send(cli->tree, &notify);

	notify.nttrans.in.recursive = False;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name");
	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name\\subname1");
	smbcli_close(cli->tree, 
		     smbcli_open(cli->tree, BASEDIR "\\subdir-name\\subname2", O_CREAT, 0));
	smbcli_rename(cli->tree, BASEDIR "\\subdir-name\\subname1", BASEDIR "\\subdir-name\\subname1-r");
	smbcli_rename(cli->tree, BASEDIR "\\subdir-name\\subname2", BASEDIR "\\subname2-r");
	smbcli_rename(cli->tree, BASEDIR "\\subname2-r", BASEDIR "\\subname3-r");

	smbcli_rmdir(cli->tree, BASEDIR "\\subdir-name\\subname1-r");
	smbcli_rmdir(cli->tree, BASEDIR "\\subdir-name");
	smbcli_unlink(cli->tree, BASEDIR "\\subname3-r");

	status = smb_raw_changenotify_recv(req1, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(notify.nttrans.out.num_changes, 1);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_MODIFIED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "subname2-r", STR_UNICODE);

	status = smb_raw_changenotify_recv(req2, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(notify.nttrans.out.num_changes, 1);
	CHECK_VAL(notify.nttrans.out.changes[0].action, NOTIFY_ACTION_MODIFIED);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "subname3-r", STR_UNICODE);

	if (!ret) {
		goto done;
	}

done:
	smb_raw_exit(cli->session);
	return ret;
}


/* 
   testing of mask bits for change notify
*/
static BOOL test_notify_mask(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum, fnum2;
	uint32_t mask;
	int i;
	char c = 1;
	struct timeval tv;
	NTTIME t;

	printf("TESTING CHANGE NOTIFY COMPLETION FILTERS\n");

	tv = timeval_current_ofs(1000, 0);
	t = timeval_to_nttime(&tv);
		
	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.recursive = True;

#define NOTIFY_MASK_TEST(setup, op, cleanup, Action, expected, nchanges) \
	do { for (mask=i=0;i<32;i++) { \
		struct smbcli_request *req; \
		status = smb_raw_open(cli->tree, mem_ctx, &io); \
		CHECK_STATUS(status, NT_STATUS_OK); \
		fnum = io.ntcreatex.out.file.fnum; \
		setup \
		notify.nttrans.in.file.fnum = fnum;	\
		notify.nttrans.in.completion_filter = (1<<i); \
		req = smb_raw_changenotify_send(cli->tree, &notify); \
		op \
		msleep(200); smb_raw_ntcancel(req); \
		status = smb_raw_changenotify_recv(req, mem_ctx, &notify); \
		cleanup \
		smbcli_close(cli->tree, fnum); \
		if (NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED)) continue; \
		CHECK_STATUS(status, NT_STATUS_OK); \
		/* special case to cope with file rename behaviour */ \
		if (nchanges == 2 && notify.nttrans.out.num_changes == 1 && \
		    notify.nttrans.out.changes[0].action == NOTIFY_ACTION_MODIFIED && \
		    ((expected) & FILE_NOTIFY_CHANGE_ATTRIBUTES) && \
		    Action == NOTIFY_ACTION_OLD_NAME) { \
			printf("(rename file special handling OK)\n"); \
		} else if (nchanges != notify.nttrans.out.num_changes) { \
			printf("ERROR: nchanges=%d expected=%d action=%d filter=0x%08x\n", \
			       notify.nttrans.out.num_changes, \
			       nchanges, \
			       notify.nttrans.out.changes[0].action, \
			       notify.nttrans.in.completion_filter); \
			ret = False; \
		} else if (notify.nttrans.out.changes[0].action != Action) { \
			printf("ERROR: nchanges=%d action=%d expectedAction=%d filter=0x%08x\n", \
			       notify.nttrans.out.num_changes, \
			       notify.nttrans.out.changes[0].action, \
			       Action, \
			       notify.nttrans.in.completion_filter); \
			ret = False; \
		} else if (strcmp(notify.nttrans.out.changes[0].name.s, "tname1") != 0) { \
			printf("ERROR: nchanges=%d action=%d filter=0x%08x name=%s\n", \
			       notify.nttrans.out.num_changes, \
			       notify.nttrans.out.changes[0].action, \
			       notify.nttrans.in.completion_filter, \
			       notify.nttrans.out.changes[0].name.s);	\
			ret = False; \
		} \
		mask |= (1<<i); \
	} \
	if ((expected) != mask) { \
		if (((expected) & ~mask) != 0) { \
			printf("ERROR: trigger on too few bits. mask=0x%08x expected=0x%08x\n", \
			       mask, expected); \
			ret = False; \
		} else { \
			printf("WARNING: trigger on too many bits. mask=0x%08x expected=0x%08x\n", \
			       mask, expected); \
		} \
	} \
	} while (0)

	printf("testing mkdir\n");
	NOTIFY_MASK_TEST(;,
			 smbcli_mkdir(cli->tree, BASEDIR "\\tname1");,
			 smbcli_rmdir(cli->tree, BASEDIR "\\tname1");,
			 NOTIFY_ACTION_ADDED,
			 FILE_NOTIFY_CHANGE_DIR_NAME, 1);

	printf("testing create file\n");
	NOTIFY_MASK_TEST(;,
			 smbcli_close(cli->tree, smbcli_open(cli->tree, BASEDIR "\\tname1", O_CREAT, 0));,
			 smbcli_unlink(cli->tree, BASEDIR "\\tname1");,
			 NOTIFY_ACTION_ADDED,
			 FILE_NOTIFY_CHANGE_FILE_NAME, 1);

	printf("testing unlink\n");
	NOTIFY_MASK_TEST(
			 smbcli_close(cli->tree, smbcli_open(cli->tree, BASEDIR "\\tname1", O_CREAT, 0));,
			 smbcli_unlink(cli->tree, BASEDIR "\\tname1");,
			 ;,
			 NOTIFY_ACTION_REMOVED,
			 FILE_NOTIFY_CHANGE_FILE_NAME, 1);

	printf("testing rmdir\n");
	NOTIFY_MASK_TEST(
			 smbcli_mkdir(cli->tree, BASEDIR "\\tname1");,
			 smbcli_rmdir(cli->tree, BASEDIR "\\tname1");,
			 ;,
			 NOTIFY_ACTION_REMOVED,
			 FILE_NOTIFY_CHANGE_DIR_NAME, 1);

	printf("testing rename file\n");
	NOTIFY_MASK_TEST(
			 smbcli_close(cli->tree, smbcli_open(cli->tree, BASEDIR "\\tname1", O_CREAT, 0));,
			 smbcli_rename(cli->tree, BASEDIR "\\tname1", BASEDIR "\\tname2");,
			 smbcli_unlink(cli->tree, BASEDIR "\\tname2");,
			 NOTIFY_ACTION_OLD_NAME,
			 FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_ATTRIBUTES|FILE_NOTIFY_CHANGE_CREATION, 2);

	printf("testing rename dir\n");
	NOTIFY_MASK_TEST(
		smbcli_mkdir(cli->tree, BASEDIR "\\tname1");,
		smbcli_rename(cli->tree, BASEDIR "\\tname1", BASEDIR "\\tname2");,
		smbcli_rmdir(cli->tree, BASEDIR "\\tname2");,
		NOTIFY_ACTION_OLD_NAME,
		FILE_NOTIFY_CHANGE_DIR_NAME, 2);

	printf("testing set path attribute\n");
	NOTIFY_MASK_TEST(
		smbcli_close(cli->tree, smbcli_open(cli->tree, BASEDIR "\\tname1", O_CREAT, 0));,
		smbcli_setatr(cli->tree, BASEDIR "\\tname1", FILE_ATTRIBUTE_HIDDEN, 0);,
		smbcli_unlink(cli->tree, BASEDIR "\\tname1");,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_ATTRIBUTES, 1);

	printf("testing set path write time\n");
	NOTIFY_MASK_TEST(
		smbcli_close(cli->tree, smbcli_open(cli->tree, BASEDIR "\\tname1", O_CREAT, 0));,
		smbcli_setatr(cli->tree, BASEDIR "\\tname1", FILE_ATTRIBUTE_NORMAL, 1000);,
		smbcli_unlink(cli->tree, BASEDIR "\\tname1");,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_LAST_WRITE, 1);

	printf("testing set file attribute\n");
	NOTIFY_MASK_TEST(
		fnum2 = create_complex_file(cli, mem_ctx, BASEDIR "\\tname1");,
		smbcli_fsetatr(cli->tree, fnum2, FILE_ATTRIBUTE_HIDDEN, 0, 0, 0, 0);,
		(smbcli_close(cli->tree, fnum2), smbcli_unlink(cli->tree, BASEDIR "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_ATTRIBUTES, 1);

	if (lp_parm_bool(-1, "torture", "samba3", False)) {
		printf("Samba3 does not yet support create times "
		       "everywhere\n");
	}
	else {
		printf("testing set file create time\n");
		NOTIFY_MASK_TEST(
			fnum2 = create_complex_file(cli, mem_ctx,
						    BASEDIR "\\tname1");,
			smbcli_fsetatr(cli->tree, fnum2, 0, t, 0, 0, 0);,
			(smbcli_close(cli->tree, fnum2),
			 smbcli_unlink(cli->tree, BASEDIR "\\tname1"));,
			NOTIFY_ACTION_MODIFIED,
			FILE_NOTIFY_CHANGE_CREATION, 1);
	}

	printf("testing set file access time\n");
	NOTIFY_MASK_TEST(
		fnum2 = create_complex_file(cli, mem_ctx, BASEDIR "\\tname1");,
		smbcli_fsetatr(cli->tree, fnum2, 0, 0, t, 0, 0);,
		(smbcli_close(cli->tree, fnum2), smbcli_unlink(cli->tree, BASEDIR "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_LAST_ACCESS, 1);

	printf("testing set file write time\n");
	NOTIFY_MASK_TEST(
		fnum2 = create_complex_file(cli, mem_ctx, BASEDIR "\\tname1");,
		smbcli_fsetatr(cli->tree, fnum2, 0, 0, 0, t, 0);,
		(smbcli_close(cli->tree, fnum2), smbcli_unlink(cli->tree, BASEDIR "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_LAST_WRITE, 1);

	printf("testing set file change time\n");
	NOTIFY_MASK_TEST(
		fnum2 = create_complex_file(cli, mem_ctx, BASEDIR "\\tname1");,
		smbcli_fsetatr(cli->tree, fnum2, 0, 0, 0, 0, t);,
		(smbcli_close(cli->tree, fnum2), smbcli_unlink(cli->tree, BASEDIR "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		0, 1);


	printf("testing write\n");
	NOTIFY_MASK_TEST(
		fnum2 = create_complex_file(cli, mem_ctx, BASEDIR "\\tname1");,
		smbcli_write(cli->tree, fnum2, 1, &c, 10000, 1);,
		(smbcli_close(cli->tree, fnum2), smbcli_unlink(cli->tree, BASEDIR "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		0, 1);

	printf("testing truncate\n");
	NOTIFY_MASK_TEST(
		fnum2 = create_complex_file(cli, mem_ctx, BASEDIR "\\tname1");,
		smbcli_ftruncate(cli->tree, fnum2, 10000);,
		(smbcli_close(cli->tree, fnum2), smbcli_unlink(cli->tree, BASEDIR "\\tname1"));,
		NOTIFY_ACTION_MODIFIED,
		FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_ATTRIBUTES, 1);

done:
	smb_raw_exit(cli->session);
	return ret;
}

/*
  basic testing of change notify on files
*/
static BOOL test_notify_file(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	BOOL ret = True;
	union smb_open io;
	union smb_close cl;
	union smb_notify notify;
	struct smbcli_request *req;
	int fnum;
	const char *fname = BASEDIR "\\file.txt";

	printf("TESTING CHANGE NOTIFY ON FILES\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
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
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_STREAM_NAME;
	notify.nttrans.in.recursive = False;

	printf("testing if notifies on file handles are invalid (should be)\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smbcli_unlink(cli->tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smb_raw_exit(cli->session);
	return ret;
}

/*
  basic testing of change notifies followed by a tdis
*/
static BOOL test_notify_tdis(TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	printf("TESTING CHANGE NOTIFY FOLLOWED BY TDIS\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = True;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smbcli_tdis(cli);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->tree = NULL;

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 0);

done:
	torture_close_connection(cli);
	return ret;
}

/*
  basic testing of change notifies followed by a exit
*/
static BOOL test_notify_exit(TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	printf("TESTING CHANGE NOTIFY FOLLOWED BY EXIT\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = True;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 0);

done:
	torture_close_connection(cli);
	return ret;
}

/*
  basic testing of change notifies followed by a ulogoff
*/
static BOOL test_notify_ulogoff(TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	printf("TESTING CHANGE NOTIFY FOLLOWED BY ULOGOFF\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = True;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smb_raw_ulogoff(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 0);

done:
	torture_close_connection(cli);
	return ret;
}

static void tcp_dis_handler(struct smbcli_transport *t, void *p)
{
	struct smbcli_state *cli = p;
	smbcli_transport_dead(cli->transport, NT_STATUS_LOCAL_DISCONNECT);
	cli->transport = NULL;
	cli->tree = NULL;
}
/*
  basic testing of change notifies followed by tcp disconnect
*/
static BOOL test_notify_tcp_dis(TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	printf("TESTING CHANGE NOTIFY FOLLOWED BY TCP DISCONNECT\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = True;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	smbcli_transport_idle_handler(cli->transport, tcp_dis_handler, 250, cli);

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_LOCAL_DISCONNECT);

done:
	torture_close_connection(cli);
	return ret;
}

/* 
   test setting up two change notify requests on one handle
*/
static BOOL test_notify_double(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req1, *req2;

	printf("TESTING CHANGE NOTIFY TWICE ON ONE DIRECTORY\n");
		
	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_ALL;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	/* ask for a change notify,
	   on file or directory name changes */
	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	notify.nttrans.in.buffer_size = 1000;
	notify.nttrans.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.nttrans.in.file.fnum = fnum;
	notify.nttrans.in.recursive = True;

	req1 = smb_raw_changenotify_send(cli->tree, &notify);
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name");

	status = smb_raw_changenotify_recv(req1, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 1);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "subdir-name", STR_UNICODE);

	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name2");

	status = smb_raw_changenotify_recv(req2, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.nttrans.out.num_changes, 1);
	CHECK_WSTR(notify.nttrans.out.changes[0].name, "subdir-name2", STR_UNICODE);

done:
	smb_raw_exit(cli->session);
	return ret;
}


/* 
   test multiple change notifies at different depths and with/without recursion
*/
static BOOL test_notify_tree(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	union smb_notify notify;
	union smb_open io;
	struct smbcli_request *req;
	struct timeval tv;
	struct {
		const char *path;
		BOOL recursive;
		uint32_t filter;
		int expected;
		int fnum;
		int counted;
	} dirs[] = {
		{BASEDIR "\\abc",               True, FILE_NOTIFY_CHANGE_NAME, 30 },
		{BASEDIR "\\zqy",               True, FILE_NOTIFY_CHANGE_NAME, 8 },
		{BASEDIR "\\atsy",              True, FILE_NOTIFY_CHANGE_NAME, 4 },
		{BASEDIR "\\abc\\foo",          True,  FILE_NOTIFY_CHANGE_NAME, 2 },
		{BASEDIR "\\abc\\blah",         True,  FILE_NOTIFY_CHANGE_NAME, 13 },
		{BASEDIR "\\abc\\blah",         False, FILE_NOTIFY_CHANGE_NAME, 7 },
		{BASEDIR "\\abc\\blah\\a",      True, FILE_NOTIFY_CHANGE_NAME, 2 },
		{BASEDIR "\\abc\\blah\\b",      True, FILE_NOTIFY_CHANGE_NAME, 2 },
		{BASEDIR "\\abc\\blah\\c",      True, FILE_NOTIFY_CHANGE_NAME, 2 },
		{BASEDIR "\\abc\\fooblah",      True, FILE_NOTIFY_CHANGE_NAME, 2 },
		{BASEDIR "\\zqy\\xx",           True, FILE_NOTIFY_CHANGE_NAME, 2 },
		{BASEDIR "\\zqy\\yyy",          True, FILE_NOTIFY_CHANGE_NAME, 2 },
		{BASEDIR "\\zqy\\..",           True, FILE_NOTIFY_CHANGE_NAME, 40 },
		{BASEDIR,                       True, FILE_NOTIFY_CHANGE_NAME, 40 },
		{BASEDIR,                       False,FILE_NOTIFY_CHANGE_NAME, 6 },
		{BASEDIR "\\atsy",              False,FILE_NOTIFY_CHANGE_NAME, 4 },
		{BASEDIR "\\abc",               True, FILE_NOTIFY_CHANGE_NAME, 24 },
		{BASEDIR "\\abc",               False,FILE_NOTIFY_CHANGE_FILE_NAME, 0 },
		{BASEDIR "\\abc",               True, FILE_NOTIFY_CHANGE_FILE_NAME, 0 },
		{BASEDIR "\\abc",               True, FILE_NOTIFY_CHANGE_NAME, 24 },
	};
	int i;
	NTSTATUS status;
	BOOL all_done = False;

	printf("TESTING CHANGE NOTIFY FOR DIFFERENT DEPTHS\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
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
		status = smb_raw_open(cli->tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		dirs[i].fnum = io.ntcreatex.out.file.fnum;

		notify.nttrans.in.completion_filter = dirs[i].filter;
		notify.nttrans.in.file.fnum = dirs[i].fnum;
		notify.nttrans.in.recursive = dirs[i].recursive;
		req = smb_raw_changenotify_send(cli->tree, &notify);
		smb_raw_ntcancel(req);
		status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
		CHECK_STATUS(status, NT_STATUS_CANCELLED);
	}

	/* trigger 2 events in each dir */
	for (i=0;i<ARRAY_SIZE(dirs);i++) {
		char *path = talloc_asprintf(mem_ctx, "%s\\test.dir", dirs[i].path);
		smbcli_mkdir(cli->tree, path);
		smbcli_rmdir(cli->tree, path);
		talloc_free(path);
	}

	/* give a bit of time for the events to propogate */
	tv = timeval_current();

	do {
		/* count events that have happened in each dir */
		for (i=0;i<ARRAY_SIZE(dirs);i++) {
			notify.nttrans.in.file.fnum = dirs[i].fnum;
			req = smb_raw_changenotify_send(cli->tree, &notify);
			smb_raw_ntcancel(req);
			notify.nttrans.out.num_changes = 0;
			status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
			dirs[i].counted += notify.nttrans.out.num_changes;
		}
		
		all_done = True;

		for (i=0;i<ARRAY_SIZE(dirs);i++) {
			if (dirs[i].counted != dirs[i].expected) {
				all_done = False;
			}
		}
	} while (!all_done && timeval_elapsed(&tv) < 20);

	printf("took %.4f seconds to propogate all events\n", timeval_elapsed(&tv));

	for (i=0;i<ARRAY_SIZE(dirs);i++) {
		if (dirs[i].counted != dirs[i].expected) {
			printf("ERROR: i=%d expected %d got %d for '%s'\n",
			       i, dirs[i].expected, dirs[i].counted, dirs[i].path);
			ret = False;
		}
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
	return ret;
}

/* 
   basic testing of change notify
*/
BOOL torture_raw_notify(struct torture_context *torture)
{
	struct smbcli_state *cli, *cli2;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
		
	if (!torture_open_connection(&cli, 0)) {
		return False;
	}
	if (!torture_open_connection(&cli2, 0)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_notify");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	ret &= test_notify_dir(cli, cli2, mem_ctx);
	ret &= test_notify_mask(cli, mem_ctx);
	ret &= test_notify_recursive(cli, mem_ctx);
	ret &= test_notify_mask_change(cli, mem_ctx);
	ret &= test_notify_file(cli, mem_ctx);
	ret &= test_notify_tdis(mem_ctx);
	ret &= test_notify_exit(mem_ctx);
	ret &= test_notify_ulogoff(mem_ctx);
	ret &= test_notify_tcp_dis(mem_ctx);
	ret &= test_notify_double(cli, mem_ctx);
	ret &= test_notify_tree(cli, mem_ctx);

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	torture_close_connection(cli);
	torture_close_connection(cli2);
	talloc_free(mem_ctx);
	return ret;
}
