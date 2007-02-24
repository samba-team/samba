/* 
   Unix SMB/CIFS implementation.

   SMB2 opcode scanner

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"
#include "torture/torture.h"

#include "torture/smb2/proto.h"

#define FNAME "scan-getinfo.dat"
#define DNAME "scan-getinfo.dir"


/* 
   scan for valid SMB2 getinfo levels
*/
BOOL torture_smb2_getinfo_scan(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	NTSTATUS status;
	struct smb2_getinfo io;
	struct smb2_handle fhandle, dhandle;
	int c, i;

	if (!torture_smb2_connection(mem_ctx, &tree)) {
		return False;
	}

	status = torture_setup_complex_file(tree, FNAME);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to setup complex file '%s'\n", FNAME);
		return False;
	}
	torture_setup_complex_file(tree, FNAME ":2ndstream");

	status = torture_setup_complex_dir(tree, DNAME);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to setup complex dir  '%s'\n", DNAME);
		return False;
	}
	torture_setup_complex_file(tree, DNAME ":2ndstream");

	torture_smb2_testfile(tree, FNAME, &fhandle);
	torture_smb2_testdir(tree, DNAME, &dhandle);


	ZERO_STRUCT(io);
	io.in.max_response_size = 0xFFFF;

	for (c=1;c<5;c++) {
		for (i=0;i<0x100;i++) {
			io.in.level = (i<<8) | c;

			io.in.file.handle = fhandle;
			status = smb2_getinfo(tree, mem_ctx, &io);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS) &&
			    !NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER) &&
			    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
				printf("file level 0x%04x is %ld bytes - %s\n", 
				       io.in.level, (long)io.out.blob.length, nt_errstr(status));
				dump_data(1, io.out.blob.data, io.out.blob.length);
			}

			io.in.file.handle = dhandle;
			status = smb2_getinfo(tree, mem_ctx, &io);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS) &&
			    !NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER) &&
			    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
				printf("dir  level 0x%04x is %ld bytes - %s\n", 
				       io.in.level, (long)io.out.blob.length, nt_errstr(status));
				dump_data(1, io.out.blob.data, io.out.blob.length);
			}
		}
	}

	talloc_free(mem_ctx);

	return True;
}

/* 
   scan for valid SMB2 setinfo levels
*/
BOOL torture_smb2_setinfo_scan(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	NTSTATUS status;
	struct smb2_setinfo io;
	struct smb2_handle handle;
	int c, i;

	if (!torture_smb2_connection(mem_ctx, &tree)) {
		return False;
	}

	status = torture_setup_complex_file(tree, FNAME);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to setup complex file '%s'\n", FNAME);
		return False;
	}
	torture_setup_complex_file(tree, FNAME ":2ndstream");

	torture_smb2_testfile(tree, FNAME, &handle);

	ZERO_STRUCT(io);
	io.in.blob = data_blob_talloc_zero(mem_ctx, 1024);

	for (c=1;c<5;c++) {
		for (i=0;i<0x100;i++) {
			io.in.level = (i<<8) | c;
			io.in.file.handle = handle;
			status = smb2_setinfo(tree, &io);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS) &&
			    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
				printf("file level 0x%04x - %s\n", 
				       io.in.level, nt_errstr(status));
			}
		}
	}

	talloc_free(mem_ctx);

	return True;
}


/* 
   scan for valid SMB2 scan levels
*/
BOOL torture_smb2_find_scan(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	NTSTATUS status;
	struct smb2_find io;
	struct smb2_handle handle;
	int i;

	if (!torture_smb2_connection(mem_ctx, &tree)) {
		return False;
	}

	status = smb2_util_roothandle(tree, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open roothandle - %s\n", nt_errstr(status));
		return False;
	}

	ZERO_STRUCT(io);
	io.in.file.handle	= handle;
	io.in.pattern		= "*";
	io.in.continue_flags	= SMB2_CONTINUE_FLAG_RESTART;
	io.in.max_response_size	= 0x10000;

	for (i=1;i<0x100;i++) {
		io.in.level = i;

		io.in.file.handle = handle;
		status = smb2_find(tree, mem_ctx, &io);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			printf("find level 0x%04x is %ld bytes - %s\n", 
			       io.in.level, (long)io.out.blob.length, nt_errstr(status));
			dump_data(1, io.out.blob.data, io.out.blob.length);
		}
	}

	talloc_free(mem_ctx);

	return True;
}

/* 
   scan for valid SMB2 opcodes
*/
BOOL torture_smb2_scan(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	const char *host = torture_setting_string(torture, "host", NULL);
	const char *share = torture_setting_string(torture, "share", NULL);
	struct cli_credentials *credentials = cmdline_credentials;
	NTSTATUS status;
	int opcode;
	struct smb2_request *req;

	status = smb2_connect(mem_ctx, host, share, credentials, &tree, 
			      event_context_find(mem_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connection failed - %s\n", nt_errstr(status));
		return False;
	}

	tree->session->transport->options.timeout = 3;

	for (opcode=0;opcode<1000;opcode++) {
		req = smb2_request_init_tree(tree, opcode, 2, False, 0);
		SSVAL(req->out.body, 0, 0);
		smb2_transport_send(req);
		if (!smb2_request_receive(req)) {
			talloc_free(tree);
			status = smb2_connect(mem_ctx, host, share, credentials, &tree, 
					      event_context_find(mem_ctx));
			if (!NT_STATUS_IS_OK(status)) {
				printf("Connection failed - %s\n", nt_errstr(status));
				return False;
			}
			tree->session->transport->options.timeout = 3;
		} else {
			status = smb2_request_destroy(req);
			printf("active opcode %4d gave status %s\n", opcode, nt_errstr(status));
		}
	}

	talloc_free(mem_ctx);

	return True;
}
