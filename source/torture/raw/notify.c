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
		printf("(%d) wrong value for %s  0x%x - 0x%x\n", \
		       __LINE__, #v, (int)v, (int)correct); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_WSTR(field, value, flags) do { \
	if (!field.s || strcmp(field.s, value) || wire_bad_flags(&field, flags)) { \
		printf("(%d) %s [%s] != %s\n",  __LINE__, #field, field.s, value); \
			ret = False; \
		goto done; \
	}} while (0)


/* 
   basic testing of change notify
*/
BOOL torture_raw_notify(int dummy)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	struct smb_notify notify;
	union smb_open io;
	int fnum = -1;
	struct smbcli_request *req;
		
	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_notify");

	/* cleanup */
	if (smbcli_deltree(cli->tree, BASEDIR) == -1) {
		printf("Failed to cleanup " BASEDIR "\n");
		ret = False;
		goto done;
	}

	/*
	  get a handle on the directory
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SA_RIGHT_FILE_ALL_ACCESS;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;

	/* ask for a change notify */
	notify.in.buffer_size = 4096;
	notify.in.completion_filter = 0xFF;
	notify.in.fnum = fnum;
	notify.in.recursive = True;

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

	printf("testing notify cancel\n");

	req = smb_raw_changenotify_send(cli->tree, &notify);
	smb_raw_ntcancel(req);
	smbcli_mkdir(cli->tree, BASEDIR "\\subdir-name");
	status = smb_raw_changenotify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_CANCELLED);

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
