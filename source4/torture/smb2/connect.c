/* 
   Unix SMB/CIFS implementation.

   test suite for SMB2 connection operations

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"

/*
  send a close
*/
static NTSTATUS torture_smb2_close(struct smb2_tree *tree, struct smb2_handle handle)
{
	struct smb2_close io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(io);
	io.in.file.handle	= handle;
	io.in.flags		= SMB2_CLOSE_FLAGS_FULL_INFORMATION;
	status = smb2_close(tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed - %s\n", nt_errstr(status));
		return status;
	}

	if (DEBUGLVL(1)) {
		printf("Close gave:\n");
		printf("create_time     = %s\n", nt_time_string(tmp_ctx, io.out.create_time));
		printf("access_time     = %s\n", nt_time_string(tmp_ctx, io.out.access_time));
		printf("write_time      = %s\n", nt_time_string(tmp_ctx, io.out.write_time));
		printf("change_time     = %s\n", nt_time_string(tmp_ctx, io.out.change_time));
		printf("alloc_size      = %lld\n", (long long)io.out.alloc_size);
		printf("size            = %lld\n", (long long)io.out.size);
		printf("file_attr       = 0x%x\n", io.out.file_attr);
	}

	talloc_free(tmp_ctx);
	
	return status;
}


/*
  test writing
*/
static NTSTATUS torture_smb2_write(struct torture_context *tctx, struct smb2_tree *tree, struct smb2_handle handle)
{
	struct smb2_write w;
	struct smb2_read r;
	struct smb2_flush f;
	NTSTATUS status;
	DATA_BLOB data;
	int i;
	uint32_t size = torture_setting_int(tctx, "smb2maxwrite", 64*1024);
	
	data = data_blob_talloc(tree, NULL, size);
	if (size != data.length) {
		printf("data_blob_talloc(%u) failed\n", (unsigned int)size);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<data.length;i++) {
		data.data[i] = i;
	}

	ZERO_STRUCT(w);
	w.in.file.handle = handle;
	w.in.offset      = 0;
	w.in.data        = data;

	status = smb2_write(tree, &w);
	if (!NT_STATUS_IS_OK(status)) {
		printf("write 1 failed - %s\n", nt_errstr(status));
		return status;
	}

	torture_smb2_all_info(tree, handle);

	status = smb2_write(tree, &w);
	if (!NT_STATUS_IS_OK(status)) {
		printf("write 2 failed - %s\n", nt_errstr(status));
		return status;
	}

	torture_smb2_all_info(tree, handle);

	ZERO_STRUCT(f);
	f.in.file.handle = handle;

	status = smb2_flush(tree, &f);
	if (!NT_STATUS_IS_OK(status)) {
		printf("flush failed - %s\n", nt_errstr(status));
		return status;
	}

	ZERO_STRUCT(r);
	r.in.file.handle = handle;
	r.in.length      = data.length;
	r.in.offset      = 0;

	status = smb2_read(tree, tree, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("read failed - %s\n", nt_errstr(status));
		return status;
	}

	if (data.length != r.out.data.length ||
	    memcmp(data.data, r.out.data.data, data.length) != 0) {
		printf("read data mismatch\n");
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return status;
}


/*
  send a create
*/
static NTSTATUS torture_smb2_createfile(struct smb2_tree *tree,
					const char *fname,
					struct smb2_handle *handle)
{
	struct smb2_create io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(io);
	io.in.oplock_level = 0;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = NTCREATEX_OPTIONS_WRITE_THROUGH;
	io.in.fname = fname;

	status = smb2_create(tree, tmp_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	if (DEBUGLVL(1)) {
		printf("Open gave:\n");
		printf("oplock_flags    = 0x%x\n", io.out.oplock_level);
		printf("create_action   = 0x%x\n", io.out.create_action);
		printf("create_time     = %s\n", nt_time_string(tmp_ctx, io.out.create_time));
		printf("access_time     = %s\n", nt_time_string(tmp_ctx, io.out.access_time));
		printf("write_time      = %s\n", nt_time_string(tmp_ctx, io.out.write_time));
		printf("change_time     = %s\n", nt_time_string(tmp_ctx, io.out.change_time));
		printf("alloc_size      = %lld\n", (long long)io.out.alloc_size);
		printf("size            = %lld\n", (long long)io.out.size);
		printf("file_attr       = 0x%x\n", io.out.file_attr);
		printf("handle          = %016llx%016llx\n", 
		       (long long)io.out.file.handle.data[0], 
		       (long long)io.out.file.handle.data[1]);
	}

	talloc_free(tmp_ctx);

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}


/* 
   basic testing of SMB2 connection calls
*/
bool torture_smb2_connect(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	struct smb2_request *req;
	struct smb2_handle h1, h2;
	NTSTATUS status;
	bool ok;

	ok = torture_smb2_connection(torture, &tree);
	torture_assert(torture, ok, "torture_smb2_connection failed");

	smb2_util_unlink(tree, "test9.dat");

	status = torture_smb2_createfile(tree, "test9.dat", &h1);
	torture_assert_ntstatus_ok(torture, status, "create failed");

	status = torture_smb2_createfile(tree, "test9.dat", &h2);
	torture_assert_ntstatus_ok(torture, status, "create failed");

	status = torture_smb2_write(torture, tree, h1);
	torture_assert_ntstatus_ok(torture, status, "write failed");

	status = torture_smb2_close(tree, h1);
	torture_assert_ntstatus_ok(torture, status, "close failed");

	status = torture_smb2_close(tree, h2);
	torture_assert_ntstatus_ok(torture, status, "close failed");

	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_equal(torture, status, NT_STATUS_FILE_CLOSED,
				      "close should have closed the handle");

	status = smb2_tdis(tree);
	torture_assert_ntstatus_ok(torture, status, "tdis failed");

	status = smb2_tdis(tree);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_NETWORK_NAME_DELETED,
				      "tdis should have closed the tcon");

 	status = smb2_logoff(tree->session);
	torture_assert_ntstatus_ok(torture, status, "logoff failed");

	req = smb2_logoff_send(tree->session);
	torture_assert_not_null(torture, req, "smb2_logoff_send failed");

	req->session = NULL;

	status = smb2_logoff_recv(req);
	torture_assert_ntstatus_equal(torture, status, NT_STATUS_USER_SESSION_DELETED,
				      "logoff should have disabled session");

	status = smb2_keepalive(tree->session->transport);
	torture_assert_ntstatus_ok(torture, status, "keepalive failed");

	talloc_free(mem_ctx);

	return true;
}
