/* 
   Unix SMB/CIFS implementation.

   helper functions for SMB2 test suite

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
  show lots of information about a file
*/
void torture_smb2_all_info(struct smb2_tree *tree, struct smb2_handle handle)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	union smb2_fileinfo io;

	status = smb2_getinfo_level(tree, tmp_ctx, handle, SMB2_GETINFO_FILE_ALL_INFO, &io);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("getinfo failed - %s\n", nt_errstr(status)));
		talloc_free(tmp_ctx);
		return;
	}

	d_printf("\tcreate_time:    %s\n", nt_time_string(tmp_ctx, io.all_info.create_time));
	d_printf("\taccess_time:    %s\n", nt_time_string(tmp_ctx, io.all_info.access_time));
	d_printf("\twrite_time:     %s\n", nt_time_string(tmp_ctx, io.all_info.write_time));
	d_printf("\tchange_time:    %s\n", nt_time_string(tmp_ctx, io.all_info.change_time));
	d_printf("\tattrib:         0x%x\n", io.all_info.file_attr);
	d_printf("\talloc_size:     %llu\n", (uint64_t)io.all_info.alloc_size);
	d_printf("\tsize:           %llu\n", (uint64_t)io.all_info.size);
	d_printf("\tnlink:          %u\n", io.all_info.nlink);
	d_printf("\tdelete_pending: %u\n", io.all_info.delete_pending);
	d_printf("\tdirectory:      %u\n", io.all_info.directory);
	d_printf("\tfile_id:        %llu\n", io.all_info.file_id);
	d_printf("\tea_size:        %u\n", io.all_info.ea_size);
	d_printf("\taccess_mask:    0x%08x\n", io.all_info.access_mask);
	d_printf("\tunknown5:       0x%llx\n", io.all_info.unknown5);
	d_printf("\tunknown6:       0x%llx\n", io.all_info.unknown6);
	d_printf("\tfname:          '%s'\n", io.all_info.fname);

	/* the EAs, if any */
	status = smb2_getinfo_level(tree, tmp_ctx, handle, 
				    SMB2_GETINFO_FILE_ALL_EAS, &io);
	if (NT_STATUS_IS_OK(status)) {
		int i;
		for (i=0;i<io.all_eas.num_eas;i++) {
			d_printf("\tEA[%d] flags=%d len=%d '%s'\n", i,
				 io.all_eas.eas[i].flags,
				 (int)io.all_eas.eas[i].value.length,
				 io.all_eas.eas[i].name.s);
		}
	}

	/* streams, if available */
	status = smb2_getinfo_level(tree, tmp_ctx, handle, 
				    SMB2_GETINFO_FILE_STREAM_INFO, &io);
	if (NT_STATUS_IS_OK(status)) {
		int i;
		for (i=0;i<io.stream_info.num_streams;i++) {
			d_printf("\tstream %d:\n", i);
			d_printf("\t\tsize       %ld\n", 
				 (long)io.stream_info.streams[i].size);
			d_printf("\t\talloc size %ld\n", 
				 (long)io.stream_info.streams[i].alloc_size);
			d_printf("\t\tname       %s\n", io.stream_info.streams[i].stream_name.s);
		}
	}	

	talloc_free(tmp_ctx);	
}


/*
  open a smb2 connection
*/
BOOL torture_smb2_connection(TALLOC_CTX *mem_ctx, struct smb2_tree **tree)
{
	NTSTATUS status;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");
	struct cli_credentials *credentials = cmdline_credentials;

	status = smb2_connect(mem_ctx, host, share, credentials, tree, 
			      event_context_find(mem_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect to SMB2 share \\\\%s\\%s - %s\n",
		       host, share, nt_errstr(status));
		return False;
	}
	return True;
}


/*
  create and return a handle to a test file
*/
NTSTATUS torture_smb2_testfile(struct smb2_tree *tree, const char *fname, 
			       struct smb2_handle *handle)
{
	struct smb2_create io;
	struct smb2_read r;
	NTSTATUS status;

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
	io.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	io.in.fname = fname;

	status = smb2_create(tree, &io);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.handle;

	ZERO_STRUCT(r);
	r.in.buffer_code = 0x31;
	r.in.length      = 5;
	r.in.offset      = 0;
	r.in.handle      = *handle;

	smb2_read(tree, tree, &r);

	return NT_STATUS_OK;
}

/*
  create and return a handle to a test directory
*/
NTSTATUS torture_smb2_testdir(struct smb2_tree *tree, const char *fname, 
			      struct smb2_handle *handle)
{
	struct smb2_create io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.in.buffer_code = 0x39;
	io.in.oplock_flags = 0;
	io.in.access_mask = SEC_RIGHTS_DIR_ALL;
	io.in.file_attr   = FILE_ATTRIBUTE_DIRECTORY;
	io.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.fname = fname;

	status = smb2_create(tree, &io);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.handle;

	return NT_STATUS_OK;
}


/*
  create a complex file using the old SMB protocol, to make it easier to 
  find fields in SMB2 getinfo levels
*/
BOOL torture_setup_complex_file(const char *fname)
{
	struct smbcli_state *cli;
	int fnum;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	fnum = create_complex_file(cli, cli, fname);

	if (DEBUGLVL(1)) {
		torture_all_info(cli->tree, fname);
	}
	
	talloc_free(cli);
	return fnum != -1;
}

/*
  create a complex directory using the old SMB protocol, to make it easier to 
  find fields in SMB2 getinfo levels
*/
BOOL torture_setup_complex_dir(const char *dname)
{
	struct smbcli_state *cli;
	int fnum;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	fnum = create_complex_dir(cli, cli, dname);

	if (DEBUGLVL(1)) {
		torture_all_info(cli->tree, dname);
	}
	
	talloc_free(cli);
	return fnum != -1;
}
