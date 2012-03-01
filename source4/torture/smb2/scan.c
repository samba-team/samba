/* 
   Unix SMB/CIFS implementation.

   SMB2 opcode scanner

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
#include "lib/cmdline/popt_common.h"
#include "torture/torture.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"

#include "torture/smb2/proto.h"

/* 
   scan for valid SMB2 getinfo levels
*/
static bool torture_smb2_getinfo_scan(struct torture_context *torture)
{
	struct smb2_tree *tree;
	NTSTATUS status;
	struct smb2_getinfo io;
	struct smb2_handle fhandle, dhandle;
	int c, i;

	static const char *FNAME  = "scan-getinfo.dat";
	static const char *FNAME2 = "scan-getinfo.dat:2ndstream";
	static const char *DNAME  = "scan-getinfo.dir";
	static const char *DNAME2 = "scan-getinfo.dir:2ndstream";

	if (!torture_smb2_connection(torture, &tree)) {
		return false;
	}

	status = torture_setup_complex_file(tree, FNAME);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to setup complex file '%s': %s\n",
		       FNAME, nt_errstr(status));
		return false;
	}
	torture_setup_complex_file(tree, FNAME2);

	status = torture_setup_complex_dir(tree, DNAME);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to setup complex dir '%s': %s\n",
		       DNAME, nt_errstr(status));
		smb2_util_unlink(tree, FNAME);
		return false;
	}
	torture_setup_complex_file(tree, DNAME2);

	torture_smb2_testfile(tree, FNAME, &fhandle);
	torture_smb2_testdir(tree, DNAME, &dhandle);


	ZERO_STRUCT(io);
	io.in.output_buffer_length = 0xFFFF;

	for (c=1;c<5;c++) {
		for (i=0;i<0x100;i++) {
			io.in.info_type = c;
			io.in.info_class = i;

			io.in.file.handle = fhandle;
			status = smb2_getinfo(tree, torture, &io);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS)) {
				printf("file level 0x%02x:%02x %u is %ld bytes - %s\n", 
				       io.in.info_type, io.in.info_class, 
				       (unsigned)io.in.info_class, 
				       (long)io.out.blob.length, nt_errstr(status));
				dump_data(1, io.out.blob.data, io.out.blob.length);
			}

			io.in.file.handle = dhandle;
			status = smb2_getinfo(tree, torture, &io);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS)) {
				printf("dir  level 0x%02x:%02x %u is %ld bytes - %s\n", 
				       io.in.info_type, io.in.info_class,
				       (unsigned)io.in.info_class, 
				       (long)io.out.blob.length, nt_errstr(status));
				dump_data(1, io.out.blob.data, io.out.blob.length);
			}
		}
	}

	smb2_util_unlink(tree, FNAME);
	smb2_util_rmdir(tree, DNAME);
	return true;
}

/* 
   scan for valid SMB2 setinfo levels
*/
static bool torture_smb2_setinfo_scan(struct torture_context *torture)
{
	static const char *FNAME  = "scan-setinfo.dat";
	static const char *FNAME2 = "scan-setinfo.dat:2ndstream";

	struct smb2_tree *tree;
	NTSTATUS status;
	struct smb2_setinfo io;
	struct smb2_handle handle;
	int c, i;

	if (!torture_smb2_connection(torture, &tree)) {
		return false;
	}

	status = torture_setup_complex_file(tree, FNAME);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to setup complex file '%s': %s\n",
		       FNAME, nt_errstr(status));
		return false;
	}
	torture_setup_complex_file(tree, FNAME2);

	torture_smb2_testfile(tree, FNAME, &handle);

	ZERO_STRUCT(io);
	io.in.blob = data_blob_talloc_zero(torture, 1024);

	for (c=1;c<5;c++) {
		for (i=0;i<0x100;i++) {
			io.in.level = (i<<8) | c;
			io.in.file.handle = handle;
			status = smb2_setinfo(tree, &io);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS)) {
				printf("file level 0x%04x - %s\n", 
				       io.in.level, nt_errstr(status));
			}
		}
	}

	smb2_util_unlink(tree, FNAME);
	return true;
}


/* 
   scan for valid SMB2 scan levels
*/
static bool torture_smb2_find_scan(struct torture_context *torture)
{
	struct smb2_tree *tree;
	NTSTATUS status;
	struct smb2_find io;
	struct smb2_handle handle;
	int i;

	if (!torture_smb2_connection(torture, &tree)) {
		return false;
	}

	status = smb2_util_roothandle(tree, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open roothandle - %s\n", nt_errstr(status));
		return false;
	}

	ZERO_STRUCT(io);
	io.in.file.handle	= handle;
	io.in.pattern		= "*";
	io.in.continue_flags	= SMB2_CONTINUE_FLAG_RESTART;
	io.in.max_response_size	= 0x10000;

	for (i=1;i<0x100;i++) {
		io.in.level = i;

		io.in.file.handle = handle;
		status = smb2_find(tree, torture, &io);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			printf("find level 0x%04x is %ld bytes - %s\n", 
			       io.in.level, (long)io.out.blob.length, nt_errstr(status));
			dump_data(1, io.out.blob.data, io.out.blob.length);
		}
	}

	return true;
}

/* 
   scan for valid SMB2 opcodes
*/
static bool torture_smb2_scan(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	const char *host = torture_setting_string(torture, "host", NULL);
	const char *share = torture_setting_string(torture, "share", NULL);
	struct cli_credentials *credentials = cmdline_credentials;
	NTSTATUS status;
	int opcode;
	struct smb2_request *req;
	struct smbcli_options options;

	lpcfg_smbcli_options(torture->lp_ctx, &options);

	status = smb2_connect(mem_ctx, host, 
						  lpcfg_smb_ports(torture->lp_ctx),
						  share, 
						  lpcfg_resolve_context(torture->lp_ctx),
						  credentials, &tree, torture->ev, &options,
						  lpcfg_socket_options(torture->lp_ctx),
						  lpcfg_gensec_settings(torture, torture->lp_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connection failed - %s\n", nt_errstr(status));
		return false;
	}

	tree->session->transport->options.request_timeout = 3;

	for (opcode=0;opcode<1000;opcode++) {
		req = smb2_request_init_tree(tree, opcode, 2, false, 0);
		SSVAL(req->out.body, 0, 0);
		smb2_transport_send(req);
		if (!smb2_request_receive(req)) {
			talloc_free(tree);
			status = smb2_connect(mem_ctx, host, 
								  lpcfg_smb_ports(torture->lp_ctx),
								  share, 
								  lpcfg_resolve_context(torture->lp_ctx),
								  credentials, &tree, torture->ev, &options,
								  lpcfg_socket_options(torture->lp_ctx),
								  lpcfg_gensec_settings(mem_ctx, torture->lp_ctx));
			if (!NT_STATUS_IS_OK(status)) {
				printf("Connection failed - %s\n", nt_errstr(status));
				return false;
			}
			tree->session->transport->options.request_timeout = 3;
		} else {
			status = smb2_request_destroy(req);
			printf("active opcode %4d gave status %s\n", opcode, nt_errstr(status));
		}
	}

	talloc_free(mem_ctx);

	return true;
}

struct torture_suite *torture_smb2_scan_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "scan");

	torture_suite_add_simple_test(suite, "scan", torture_smb2_scan);
	torture_suite_add_simple_test(suite, "getinfo", torture_smb2_getinfo_scan);
	torture_suite_add_simple_test(suite, "setinfo", torture_smb2_setinfo_scan);
	torture_suite_add_simple_test(suite, "find", torture_smb2_find_scan);

	suite->description = talloc_strdup(suite, "scan target (not a test)");

	return suite;
}
