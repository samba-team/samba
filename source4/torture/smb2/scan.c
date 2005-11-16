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
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"


/* 
   scan for valid SMB2 getinfo levels
*/
BOOL torture_smb2_getinfo_scan(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	NTSTATUS status;
	struct smb2_getinfo io;
	struct smb2_create cr;
	struct smb2_handle handle;
	int c, i;
	const char *fname = "scan-getinfo.dat";

	if (!torture_smb2_connection(mem_ctx, &tree)) {
		return False;
	}

	if (!torture_setup_complex_file(fname)) {
		printf("Failed to setup complex file '%s'\n", fname);
	}

	ZERO_STRUCT(cr);
	cr.in.oplock_flags = 0;
	cr.in.access_mask = SEC_RIGHTS_FILE_ALL;
	cr.in.file_attr   = FILE_ATTRIBUTE_NORMAL;
	cr.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_options = NTCREATEX_OPTIONS_WRITE_THROUGH;
	cr.in.fname = fname;
	cr.in.blob  = data_blob(NULL, 0);

	status = smb2_create(tree, mem_ctx, &cr);
	if (!NT_STATUS_IS_OK(status)) {
		printf("create of '%s' failed - %s\n", fname, nt_errstr(status));
		return False;
	}

	handle = cr.out.handle;


	ZERO_STRUCT(io);
	io.in.max_response_size = 0xFFFF;
	io.in.handle            = handle;

	io.in.max_response_size = 128;
	io.in.unknown1 = 0;
	io.in.level = SMB2_GETINFO_FILE_ALL_INFO;
	status = smb2_getinfo(tree, mem_ctx, &io);

	io.in.max_response_size = 128;
	io.in.unknown1 = 64;
	io.in.flags = 64;
	io.in.unknown3 = 64;
	io.in.unknown4 = 64;
	io.in.level = SMB2_GETINFO_FILE_ALL_INFO;
	status = smb2_getinfo(tree, mem_ctx, &io);

	if (!NT_STATUS_IS_OK(status)) {
		printf("level 0x%04x is %d bytes - %s\n", 
		       io.in.level, io.out.blob.length, nt_errstr(status));
		dump_data(1, io.out.blob.data, io.out.blob.length);
	}

	return True;

	for (c=0;c<5;c++) {
		for (i=0;i<0x100;i++) {
			io.in.level = (i<<8) | c;
			status = smb2_getinfo(tree, mem_ctx, &io);
			if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER) ||
			    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS) ||
			    NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
				continue;
			}
			printf("level 0x%04x is %d bytes - %s\n", 
			       io.in.level, io.out.blob.length, nt_errstr(status));
			dump_data(1, io.out.blob.data, io.out.blob.length);
		}
	}

	talloc_free(mem_ctx);

	return True;
}

/* 
   scan for valid SMB2 opcodes
*/
BOOL torture_smb2_scan(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");
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
		req = smb2_request_init_tree(tree, opcode, 2, 0);
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
