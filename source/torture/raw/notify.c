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
	if (!field.s || strcmp(field.s, value) || wire_bad_flags(&field, flags, cli)) { \
		printf("(%d) %s [%s] != %s\n",  __LINE__, #field, field.s, value); \
			ret = False; \
		goto done; \
	}} while (0)


/* 
   basic testing of change notify on directories
*/
static BOOL test_notify_dir(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	struct smb_notify notify;
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
	notify.in.buffer_size = 1000;
	notify.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.in.file.fnum = fnum;
	notify.in.recursive = True;

	printf("testing notify cancel\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smb_raw_ntcancel(req);
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_CANCELLED);

	printf("testing notify mkdir\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name");

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(notify.out.num_changes, 1);
	CHECK_VAL(notify.out.changes[0].action, NOTIFY_ACTION_ADDED);
	CHECK_WSTR(notify.out.changes[0].name, "subdir-name", STR_UNICODE);

	printf("testing notify rmdir\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smbcli_rmdir(cli->tree, BASEDIR "\\subdir-name");

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 1);
	CHECK_VAL(notify.out.changes[0].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.out.changes[0].name, "subdir-name", STR_UNICODE);

	printf("testing notify mkdir - rmdir - mkdir - rmdir\n");

	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name");
	smbcli_rmdir(cli->tree, BASEDIR "\\subdir-name");
	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name");
	smbcli_rmdir(cli->tree, BASEDIR "\\subdir-name");
	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 4);
	CHECK_VAL(notify.out.changes[0].action, NOTIFY_ACTION_ADDED);
	CHECK_WSTR(notify.out.changes[0].name, "subdir-name", STR_UNICODE);
	CHECK_VAL(notify.out.changes[1].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.out.changes[1].name, "subdir-name", STR_UNICODE);
	CHECK_VAL(notify.out.changes[2].action, NOTIFY_ACTION_ADDED);
	CHECK_WSTR(notify.out.changes[2].name, "subdir-name", STR_UNICODE);
	CHECK_VAL(notify.out.changes[3].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.out.changes[3].name, "subdir-name", STR_UNICODE);

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
	notify.in.file.fnum = fnum2;
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	/* (2nd notify) whereas this notify will see the above buffered events,
	   and it directly returns the buffered events */
	notify.in.file.fnum = fnum;
	req = smb_raw_changenotify_send(cli->tree, &notify);

	/* (1st unlink) as the 2nd notify directly returns,
	   this unlink is only seen by the 1st notify and 
	   the 3rd notify (later) */
	printf("testing notify on unlink for the first file\n");
	status = smbcli_unlink(cli->tree, BASEDIR "\\test0.txt");
	CHECK_STATUS(status, NT_STATUS_OK);

	/* receive the reply from the 2nd notify */
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(notify.out.num_changes, count);
	for (i=1;i<notify.out.num_changes;i++) {
		CHECK_VAL(notify.out.changes[i].action, NOTIFY_ACTION_ADDED);
	}
	CHECK_WSTR(notify.out.changes[0].name, "test0.txt", STR_UNICODE);

	/* and now from the 1st notify */
	status = smb_raw_changenotify_recv(req2, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 1);
	CHECK_VAL(notify.out.changes[0].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.out.changes[0].name, "test0.txt", STR_UNICODE);

	/* (3rd notify) this notify will only see the 1st unlink */
	req = smb_raw_changenotify_send(cli->tree, &notify);

	printf("testing notify on wildcard unlink for %d files\n", count-1);
	/* (2nd unlink) do a wildcard unlink */
	status = smbcli_unlink(cli->tree, BASEDIR "\\test*.txt");
	CHECK_STATUS(status, NT_STATUS_OK);

	/* recev the 3rd notify */
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 1);
	CHECK_VAL(notify.out.changes[0].action, NOTIFY_ACTION_REMOVED);
	CHECK_WSTR(notify.out.changes[0].name, "test0.txt", STR_UNICODE);

	/* and we now see the rest of the unlink calls on both directory handles */
	notify.in.file.fnum = fnum;
	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, count-1);
	for (i=0;i<notify.out.num_changes;i++) {
		CHECK_VAL(notify.out.changes[i].action, NOTIFY_ACTION_REMOVED);
	}
	notify.in.file.fnum = fnum2;
	req = smb_raw_changenotify_send(cli->tree, &notify);
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, count-1);
	for (i=0;i<notify.out.num_changes;i++) {
		CHECK_VAL(notify.out.changes[i].action, NOTIFY_ACTION_REMOVED);
	}

	printf("testing if a close() on the dir handle triggers the notify reply\n");

	notify.in.file.fnum = fnum;
	req = smb_raw_changenotify_send(cli->tree, &notify);

	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 0);

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
	struct smb_notify notify;
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
	notify.in.file.fnum = fnum;
	notify.in.buffer_size = 1000;
	notify.in.completion_filter = FILE_NOTIFY_CHANGE_STREAM_NAME;
	notify.in.recursive = False;

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
	struct smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	printf("TESTING CHANGE NOTIFY FOLLOWED BY TDIS\n");

	if (!torture_open_connection(&cli)) {
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
	notify.in.buffer_size = 1000;
	notify.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.in.file.fnum = fnum;
	notify.in.recursive = True;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smbcli_tdis(cli);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 0);

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
	struct smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	printf("TESTING CHANGE NOTIFY FOLLOWED BY EXIT\n");

	if (!torture_open_connection(&cli)) {
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
	notify.in.buffer_size = 1000;
	notify.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.in.file.fnum = fnum;
	notify.in.recursive = True;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 0);

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
	struct smb_notify notify;
	union smb_open io;
	int fnum;
	struct smbcli_request *req;
	struct smbcli_state *cli = NULL;

	printf("TESTING CHANGE NOTIFY FOLLOWED BY ULOGOFF\n");

	if (!torture_open_connection(&cli)) {
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
	notify.in.buffer_size = 1000;
	notify.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.in.file.fnum = fnum;
	notify.in.recursive = True;

	req = smb_raw_changenotify_send(cli->tree, &notify);

	status = smb_raw_ulogoff(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 0);

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
	struct smb_notify notify;
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
	notify.in.buffer_size = 1000;
	notify.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.in.file.fnum = fnum;
	notify.in.recursive = True;

	req1 = smb_raw_changenotify_send(cli->tree, &notify);
	req2 = smb_raw_changenotify_send(cli->tree, &notify);

	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name");

	status = smb_raw_changenotify_recv(req1, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 1);
	CHECK_WSTR(notify.out.changes[0].name, "subdir-name", STR_UNICODE);

	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name2");

	status = smb_raw_changenotify_recv(req2, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(notify.out.num_changes, 1);
	CHECK_WSTR(notify.out.changes[0].name, "subdir-name2", STR_UNICODE);


done:
	smb_raw_exit(cli->session);
	return ret;
}

/* 
   basic testing of change notify
*/
BOOL torture_raw_notify(struct torture_context *torture)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
		
	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_notify");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	ret &= test_notify_dir(cli, mem_ctx);
	ret &= test_notify_file(cli, mem_ctx);
	ret &= test_notify_tdis(mem_ctx);
	ret &= test_notify_exit(mem_ctx);
	ret &= test_notify_ulogoff(mem_ctx);
	ret &= test_notify_double(cli, mem_ctx);

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	torture_close_connection(cli);
	talloc_free(mem_ctx);
	return ret;
}
