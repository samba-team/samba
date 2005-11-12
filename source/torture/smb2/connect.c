/* 
   Unix SMB/CIFS implementation.

   test suite for SMB2 connection operations

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
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"

#define BASEDIR "\\testsmb2"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


/*
  send a close
*/
static NTSTATUS torture_smb2_close(struct smb2_tree *tree, struct smb2_handle handle)
{
	struct smb2_close io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(io);
	io.in.buffer_code = 0x18;
	io.in.flags       = SMB2_CLOSE_FLAGS_FULL_INFORMATION;
	io.in.handle   = handle;
	status = smb2_close(tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed - %s\n", nt_errstr(status));
		return status;
	}

	printf("Close gave:\n");
	printf("create_time     = %s\n", nt_time_string(tmp_ctx, io.out.create_time));
	printf("access_time     = %s\n", nt_time_string(tmp_ctx, io.out.access_time));
	printf("write_time      = %s\n", nt_time_string(tmp_ctx, io.out.write_time));
	printf("change_time     = %s\n", nt_time_string(tmp_ctx, io.out.change_time));
	printf("alloc_size      = %lld\n", io.out.alloc_size);
	printf("size            = %lld\n", io.out.size);
	printf("file_attr       = 0x%x\n", io.out.file_attr);

	talloc_free(tmp_ctx);
	
	return status;
}


/*
  send a create
*/
static struct smb2_handle torture_smb2_create(struct smb2_tree *tree, 
					      const char *fname)
{
	struct smb2_create io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(io);
	io.in.buffer_code = 0x39;
	io.in.oplock_flags = 0;
	io.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.in.file_attr   = FILE_ATTRIBUTE_NORMAL;
	io.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = NTCREATEX_OPTIONS_WRITE_THROUGH;
	io.in.fname = fname;

	status = smb2_create(tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("create1 failed - %s\n", nt_errstr(status));
		return io.out.handle;
	}

	printf("Open gave:\n");
	printf("oplock_flags    = 0x%x\n", io.out.oplock_flags);
	printf("create_action   = 0x%x\n", io.out.create_action);
	printf("create_time     = %s\n", nt_time_string(tmp_ctx, io.out.create_time));
	printf("access_time     = %s\n", nt_time_string(tmp_ctx, io.out.access_time));
	printf("write_time      = %s\n", nt_time_string(tmp_ctx, io.out.write_time));
	printf("change_time     = %s\n", nt_time_string(tmp_ctx, io.out.change_time));
	printf("alloc_size      = %lld\n", io.out.alloc_size);
	printf("size            = %lld\n", io.out.size);
	printf("file_attr       = 0x%x\n", io.out.file_attr);
	printf("handle          = %016llx%016llx\n", 
	       io.out.handle.data[0], 
	       io.out.handle.data[1]);

	talloc_free(tmp_ctx);
	
	return io.out.handle;
}

/* 
   basic testing of SMB2 connection calls
*/
BOOL torture_smb2_connect(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");
	struct cli_credentials *credentials = cmdline_credentials;
	struct smb2_handle h1, h2;
	NTSTATUS status;

	status = smb2_connect(mem_ctx, host, share, credentials, &tree, 
			      event_context_find(mem_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connection failed - %s\n", nt_errstr(status));
		return False;
	}

	h1        = torture_smb2_create(tree, "test9.dat");
	h2        = torture_smb2_create(tree, "test9.dat");
	torture_smb2_close(tree, h1);
	torture_smb2_close(tree, h2);

	talloc_free(mem_ctx);

	return True;
}
