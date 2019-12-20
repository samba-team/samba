/* 
   Unix SMB/CIFS implementation.

   helper functions for SMB2 test suite

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
#include "libcli/security/security_descriptor.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/cmdline/popt_common.h"
#include "system/time.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "lib/util/tevent_ntstatus.h"

#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "source4/torture/util.h"
#include "libcli/security/dom_sid.h"
#include "librpc/gen_ndr/lsa.h"
#include "libcli/util/clilsa.h"


/*
  write to a file on SMB2
*/
NTSTATUS smb2_util_write(struct smb2_tree *tree,
			 struct smb2_handle handle, 
			 const void *buf, off_t offset, size_t size)
{
	struct smb2_write w;

	ZERO_STRUCT(w);
	w.in.file.handle = handle;
	w.in.offset      = offset;
	w.in.data        = data_blob_const(buf, size);

	return smb2_write(tree, &w);
}

/*
  create a complex file/dir using the SMB2 protocol
*/
static NTSTATUS smb2_create_complex(struct torture_context *tctx,
				    struct smb2_tree *tree,
				    const char *fname,
				    struct smb2_handle *handle,
				    bool dir)
{
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	char buf[7] = "abc";
	struct smb2_create io;
	union smb_setfileinfo setfile;
	union smb_fileinfo fileinfo;
	time_t t = (time(NULL) & ~1);
	NTSTATUS status;

	smb2_util_unlink(tree, fname);
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = fname;
	if (dir) {
		io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		io.in.share_access &= ~NTCREATEX_SHARE_ACCESS_DELETE;
		io.in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
		io.in.create_disposition = NTCREATEX_DISP_CREATE;
	}

	/* it seems vista is now fussier about alignment? */
	if (strchr(fname, ':') == NULL) {
		/* setup some EAs */
		io.in.eas.num_eas = 2;
		io.in.eas.eas = talloc_array(tmp_ctx, struct ea_struct, 2);
		io.in.eas.eas[0].flags = 0;
		io.in.eas.eas[0].name.s = "EAONE";
		io.in.eas.eas[0].value = data_blob_talloc(tmp_ctx, "VALUE1", 6);
		io.in.eas.eas[1].flags = 0;
		io.in.eas.eas[1].name.s = "SECONDEA";
		io.in.eas.eas[1].value = data_blob_talloc(tmp_ctx, "ValueTwo", 8);
	}

	status = smb2_create(tree, tmp_ctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_EAS_NOT_SUPPORTED)) {
		torture_comment(
			tctx, "EAs not supported, creating: %s\n", fname);
		io.in.eas.num_eas = 0;
		status = smb2_create(tree, tmp_ctx, &io);
	}

	talloc_free(tmp_ctx);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.file.handle;

	if (!dir) {
		status = smb2_util_write(tree, *handle, buf, 0, sizeof(buf));
		NT_STATUS_NOT_OK_RETURN(status);
	}

	/* make sure all the timestamps aren't the same, and are also 
	   in different DST zones*/
	setfile.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	setfile.generic.in.file.handle = *handle;

	unix_to_nt_time(&setfile.basic_info.in.create_time, t + 9*30*24*60*60);
	unix_to_nt_time(&setfile.basic_info.in.access_time, t + 6*30*24*60*60);
	unix_to_nt_time(&setfile.basic_info.in.write_time,  t + 3*30*24*60*60);
	unix_to_nt_time(&setfile.basic_info.in.change_time, t + 1*30*24*60*60);
	setfile.basic_info.in.attrib      = FILE_ATTRIBUTE_NORMAL;

	status = smb2_setinfo_file(tree, &setfile);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to setup file times - %s\n", nt_errstr(status));
		return status;
	}

	/* make sure all the timestamps aren't the same */
	fileinfo.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	fileinfo.generic.in.file.handle = *handle;

	status = smb2_getinfo_file(tree, tree, &fileinfo);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to query file times - %s\n", nt_errstr(status));
		return status;
		
	}

#define CHECK_TIME(field) do {\
	if (setfile.basic_info.in.field != fileinfo.all_info2.out.field) { \
		torture_comment(tctx, "(%s) " #field " not setup correctly: %s(%llu) => %s(%llu)\n", \
			__location__, \
			nt_time_string(tree, setfile.basic_info.in.field), \
			(unsigned long long)setfile.basic_info.in.field, \
			nt_time_string(tree, fileinfo.basic_info.out.field), \
			(unsigned long long)fileinfo.basic_info.out.field); \
		status = NT_STATUS_INVALID_PARAMETER; \
	} \
} while (0)

	CHECK_TIME(create_time);
	CHECK_TIME(access_time);
	CHECK_TIME(write_time);
	CHECK_TIME(change_time);

	return status;
}

/*
  create a complex file using the SMB2 protocol
*/
NTSTATUS smb2_create_complex_file(struct torture_context *tctx,
				  struct smb2_tree *tree, const char *fname,
				  struct smb2_handle *handle)
{
	return smb2_create_complex(tctx, tree, fname, handle, false);
}

/*
  create a complex dir using the SMB2 protocol
*/
NTSTATUS smb2_create_complex_dir(struct torture_context *tctx,
				 struct smb2_tree *tree, const char *fname,
				 struct smb2_handle *handle)
{
	return smb2_create_complex(tctx, tree, fname, handle, true);
}

/*
  show lots of information about a file
*/
void torture_smb2_all_info(struct torture_context *tctx,
			   struct smb2_tree *tree, struct smb2_handle handle)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	union smb_fileinfo io;

	io.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	io.generic.in.file.handle = handle;

	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("getinfo failed - %s\n", nt_errstr(status)));
		talloc_free(tmp_ctx);
		return;
	}

	torture_comment(tctx, "all_info for '%s'\n", io.all_info2.out.fname.s);
	torture_comment(tctx, "\tcreate_time:    %s\n", nt_time_string(tmp_ctx, io.all_info2.out.create_time));
	torture_comment(tctx, "\taccess_time:    %s\n", nt_time_string(tmp_ctx, io.all_info2.out.access_time));
	torture_comment(tctx, "\twrite_time:     %s\n", nt_time_string(tmp_ctx, io.all_info2.out.write_time));
	torture_comment(tctx, "\tchange_time:    %s\n", nt_time_string(tmp_ctx, io.all_info2.out.change_time));
	torture_comment(tctx, "\tattrib:         0x%x\n", io.all_info2.out.attrib);
	torture_comment(tctx, "\tunknown1:       0x%x\n", io.all_info2.out.unknown1);
	torture_comment(tctx, "\talloc_size:     %llu\n", (long long)io.all_info2.out.alloc_size);
	torture_comment(tctx, "\tsize:           %llu\n", (long long)io.all_info2.out.size);
	torture_comment(tctx, "\tnlink:          %u\n", io.all_info2.out.nlink);
	torture_comment(tctx, "\tdelete_pending: %u\n", io.all_info2.out.delete_pending);
	torture_comment(tctx, "\tdirectory:      %u\n", io.all_info2.out.directory);
	torture_comment(tctx, "\tfile_id:        %llu\n", (long long)io.all_info2.out.file_id);
	torture_comment(tctx, "\tea_size:        %u\n", io.all_info2.out.ea_size);
	torture_comment(tctx, "\taccess_mask:    0x%08x\n", io.all_info2.out.access_mask);
	torture_comment(tctx, "\tposition:       0x%llx\n", (long long)io.all_info2.out.position);
	torture_comment(tctx, "\tmode:           0x%llx\n", (long long)io.all_info2.out.mode);

	/* short name, if any */
	io.generic.level = RAW_FILEINFO_ALT_NAME_INFORMATION;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "\tshort name:     '%s'\n", io.alt_name_info.out.fname.s);
	}

	/* the EAs, if any */
	io.generic.level = RAW_FILEINFO_SMB2_ALL_EAS;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (NT_STATUS_IS_OK(status)) {
		int i;
		for (i=0;i<io.all_eas.out.num_eas;i++) {
			torture_comment(tctx, "\tEA[%d] flags=%d len=%d '%s'\n", i,
				 io.all_eas.out.eas[i].flags,
				 (int)io.all_eas.out.eas[i].value.length,
				 io.all_eas.out.eas[i].name.s);
		}
	}

	/* streams, if available */
	io.generic.level = RAW_FILEINFO_STREAM_INFORMATION;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (NT_STATUS_IS_OK(status)) {
		int i;
		for (i=0;i<io.stream_info.out.num_streams;i++) {
			torture_comment(tctx, "\tstream %d:\n", i);
			torture_comment(tctx, "\t\tsize       %ld\n",
				 (long)io.stream_info.out.streams[i].size);
			torture_comment(tctx, "\t\talloc size %ld\n",
				 (long)io.stream_info.out.streams[i].alloc_size);
			torture_comment(tctx, "\t\tname       %s\n", io.stream_info.out.streams[i].stream_name.s);
		}
	}	

	if (DEBUGLVL(1)) {
		/* the security descriptor */
		io.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
		io.query_secdesc.in.secinfo_flags = 
			SECINFO_OWNER|SECINFO_GROUP|
			SECINFO_DACL;
		status = smb2_getinfo_file(tree, tmp_ctx, &io);
		if (NT_STATUS_IS_OK(status)) {
			NDR_PRINT_DEBUG(security_descriptor, io.query_secdesc.out.sd);
		}
	}

	talloc_free(tmp_ctx);	
}

/*
  get granted access of a file handle
*/
NTSTATUS torture_smb2_get_allinfo_access(struct smb2_tree *tree,
					 struct smb2_handle handle,
					 uint32_t *granted_access)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	union smb_fileinfo io;

	io.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	io.generic.in.file.handle = handle;

	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("getinfo failed - %s\n", nt_errstr(status)));
		goto out;
	}

	*granted_access = io.all_info2.out.access_mask;

out:
	talloc_free(tmp_ctx);
	return status;
}

/**
 * open a smb2 tree connect
 */
bool torture_smb2_tree_connect(struct torture_context *tctx,
			       struct smb2_session *session,
			       TALLOC_CTX *mem_ctx,
			       struct smb2_tree **_tree)
{
	NTSTATUS status;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	const char *unc;
	struct smb2_tree *tree;
	struct tevent_req *subreq;
	uint32_t timeout_msec;

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	torture_assert(tctx, unc != NULL, "talloc_asprintf");

	tree = smb2_tree_init(session, mem_ctx, false);
	torture_assert(tctx, tree != NULL, "smb2_tree_init");

	timeout_msec = session->transport->options.request_timeout * 1000;

	subreq = smb2cli_tcon_send(tree, tctx->ev,
				   session->transport->conn,
				   timeout_msec,
				   session->smbXcli,
				   tree->smbXcli,
				   0, /* flags */
				   unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");

	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");

	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_ok(tctx, status, "smb2cli_tcon_recv");

	*_tree = tree;

	return true;
}

/**
 * do a smb2 session setup (without a tree connect)
 */
bool torture_smb2_session_setup(struct torture_context *tctx,
				struct smb2_transport *transport,
				uint64_t previous_session_id,
				TALLOC_CTX *mem_ctx,
				struct smb2_session **_session)
{
	NTSTATUS status;
	struct smb2_session *session;

	session = smb2_session_init(transport,
				    lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				    mem_ctx);

	if (session == NULL) {
		return false;
	}

	status = smb2_session_setup_spnego(session,
					   popt_get_cmdline_credentials(),
					   previous_session_id);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "session setup failed: %s\n", nt_errstr(status));
		talloc_free(session);
		return false;
	}

	*_session = session;

	return true;
}

/*
  open a smb2 connection
*/
bool torture_smb2_connection_ext(struct torture_context *tctx,
				 uint64_t previous_session_id,
				 const struct smbcli_options *options,
				 struct smb2_tree **tree)
{
	NTSTATUS status;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	const char *p = torture_setting_string(tctx, "unclist", NULL);
	TALLOC_CTX *mem_ctx = NULL;
	bool ok;

	if (p != NULL) {
		char *host2 = NULL;
		char *share2 = NULL;

		mem_ctx = talloc_new(tctx);
		if (mem_ctx == NULL) {
			return false;
		}

		ok = torture_get_conn_index(tctx->conn_index++, mem_ctx, tctx,
					    &host2, &share2);
		if (!ok) {
			TALLOC_FREE(mem_ctx);
			return false;
		}

		host = host2;
		share = share2;
	}

	status = smb2_connect_ext(tctx,
				  host,
				  lpcfg_smb_ports(tctx->lp_ctx),
				  share,
				  lpcfg_resolve_context(tctx->lp_ctx),
				  popt_get_cmdline_credentials(),
				  previous_session_id,
				  tree,
				  tctx->ev,
				  options,
				  lpcfg_socket_options(tctx->lp_ctx),
				  lpcfg_gensec_settings(tctx, tctx->lp_ctx)
				  );
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to connect to SMB2 share \\\\%s\\%s - %s\n",
		       host, share, nt_errstr(status));
		TALLOC_FREE(mem_ctx);
		return false;
	}

	TALLOC_FREE(mem_ctx);
	return true;
}

bool torture_smb2_connection(struct torture_context *tctx, struct smb2_tree **tree)
{
	bool ret;
	struct smbcli_options options;

	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	ret = torture_smb2_connection_ext(tctx, 0, &options, tree);

	return ret;
}

/**
 * SMB2 connect with share from soption
 **/
bool torture_smb2_con_sopt(struct torture_context *tctx,
			   const char *soption,
			   struct smb2_tree **tree)
{
	struct smbcli_options options;
	NTSTATUS status;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, soption, NULL);

	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	if (share == NULL) {
		torture_comment(tctx, "No share for option %s\n", soption);
		return false;
	}

	status = smb2_connect_ext(tctx,
				  host,
				  lpcfg_smb_ports(tctx->lp_ctx),
				  share,
				  lpcfg_resolve_context(tctx->lp_ctx),
				  popt_get_cmdline_credentials(),
				  0,
				  tree,
				  tctx->ev,
				  &options,
				  lpcfg_socket_options(tctx->lp_ctx),
				  lpcfg_gensec_settings(tctx, tctx->lp_ctx)
				  );
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to connect to SMB2 share \\\\%s\\%s - %s\n",
		       host, share, nt_errstr(status));
		return false;
	}
	return true;
}

/*
  create and return a handle to a test file
  with a specific access mask
*/
NTSTATUS torture_smb2_testfile_access(struct smb2_tree *tree, const char *fname,
				      struct smb2_handle *handle,
				      uint32_t desired_access)
{
	struct smb2_create io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.in.oplock_level = 0;
	io.in.desired_access = desired_access;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = fname;

	status = smb2_create(tree, tree, &io);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}

/*
  create and return a handle to a test file
*/
NTSTATUS torture_smb2_testfile(struct smb2_tree *tree, const char *fname,
			       struct smb2_handle *handle)
{
	return torture_smb2_testfile_access(tree, fname, handle,
					    SEC_RIGHTS_FILE_ALL);
}

/*
  create and return a handle to a test file
  with a specific access mask
*/
NTSTATUS torture_smb2_open(struct smb2_tree *tree,
			   const char *fname,
			   uint32_t desired_access,
			   struct smb2_handle *handle)
{
	struct smb2_create io;
	NTSTATUS status;

	io = (struct smb2_create) {
		.in.fname = fname,
		.in.desired_access = desired_access,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
	};

	status = smb2_create(tree, tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}

/*
  create and return a handle to a test directory
  with specific desired access
*/
NTSTATUS torture_smb2_testdir_access(struct smb2_tree *tree, const char *fname,
				     struct smb2_handle *handle,
				     uint32_t desired_access)
{
	struct smb2_create io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.in.oplock_level = 0;
	io.in.desired_access = desired_access;
	io.in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.fname = fname;

	status = smb2_create(tree, tree, &io);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}

/*
  create and return a handle to a test directory
*/
NTSTATUS torture_smb2_testdir(struct smb2_tree *tree, const char *fname,
			      struct smb2_handle *handle)
{
	return torture_smb2_testdir_access(tree, fname, handle,
					   SEC_RIGHTS_DIR_ALL);
}

/*
  create a simple file using the SMB2 protocol
*/
NTSTATUS smb2_create_simple_file(struct torture_context *tctx,
				 struct smb2_tree *tree, const char *fname,
				 struct smb2_handle *handle)
{
	char buf[7] = "abc";
	NTSTATUS status;

	smb2_util_unlink(tree, fname);
	status = torture_smb2_testfile_access(tree,
					      fname, handle,
					      SEC_FLAG_MAXIMUM_ALLOWED);
	NT_STATUS_NOT_OK_RETURN(status);

	status = smb2_util_write(tree, *handle, buf, 0, sizeof(buf));
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

/*
  create a simple file using SMB2.
*/
NTSTATUS torture_setup_simple_file(struct torture_context *tctx,
				   struct smb2_tree *tree, const char *fname)
{
	struct smb2_handle handle;
	NTSTATUS status = smb2_create_simple_file(tctx, tree, fname, &handle);
	NT_STATUS_NOT_OK_RETURN(status);
	return smb2_util_close(tree, handle);
}

/*
  create a complex file using SMB2, to make it easier to
  find fields in SMB2 getinfo levels
*/
NTSTATUS torture_setup_complex_file(struct torture_context *tctx,
				    struct smb2_tree *tree, const char *fname)
{
	struct smb2_handle handle;
	NTSTATUS status = smb2_create_complex_file(tctx, tree, fname, &handle);
	NT_STATUS_NOT_OK_RETURN(status);
	return smb2_util_close(tree, handle);
}


/*
  create a complex dir using SMB2, to make it easier to
  find fields in SMB2 getinfo levels
*/
NTSTATUS torture_setup_complex_dir(struct torture_context *tctx,
				   struct smb2_tree *tree, const char *fname)
{
	struct smb2_handle handle;
	NTSTATUS status = smb2_create_complex_dir(tctx, tree, fname, &handle);
	NT_STATUS_NOT_OK_RETURN(status);
	return smb2_util_close(tree, handle);
}


/*
  return a handle to the root of the share
*/
NTSTATUS smb2_util_roothandle(struct smb2_tree *tree, struct smb2_handle *handle)
{
	struct smb2_create io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.in.oplock_level = 0;
	io.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_DIR_READ_ATTRIBUTE | SEC_DIR_LIST;
	io.in.file_attributes   = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options = NTCREATEX_OPTIONS_ASYNC_ALERT;
	io.in.fname = "";

	status = smb2_create(tree, tree, &io);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}

/* Comparable to torture_setup_dir, but for SMB2. */
bool smb2_util_setup_dir(struct torture_context *tctx, struct smb2_tree *tree,
    const char *dname)
{
	NTSTATUS status;

	/* XXX: smb_raw_exit equivalent?
	smb_raw_exit(cli->session); */
	if (smb2_deltree(tree, dname) == -1) {
		torture_result(tctx, TORTURE_ERROR, "Unable to deltree when setting up %s.\n", dname);
		return false;
	}

	status = smb2_util_mkdir(tree, dname);
	if (NT_STATUS_IS_ERR(status)) {
		torture_result(tctx, TORTURE_ERROR, "Unable to mkdir when setting up %s - %s\n", dname,
		    nt_errstr(status));
		return false;
	}

	return true;
}

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

/*
 * Helper function to verify a security descriptor, by querying
 * and comparing against the passed in sd.
 */
bool smb2_util_verify_sd(TALLOC_CTX *tctx, struct smb2_tree *tree,
    struct smb2_handle handle, struct security_descriptor *sd)
{
	NTSTATUS status;
	bool ret = true;
	union smb_fileinfo q = {};

	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags =
	    SECINFO_OWNER |
	    SECINFO_GROUP |
	    SECINFO_DACL;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (!security_acl_equal(
	    q.query_secdesc.out.sd->dacl, sd->dacl)) {
		torture_warning(tctx, "%s: security descriptors don't match!\n",
		    __location__);
		torture_warning(tctx, "got:\n");
		NDR_PRINT_DEBUG(security_descriptor,
		    q.query_secdesc.out.sd);
		torture_warning(tctx, "expected:\n");
		NDR_PRINT_DEBUG(security_descriptor, sd);
		ret = false;
	}

 done:
	return ret;
}

/*
 * Helper function to verify attributes, by querying
 * and comparing against the passed in attrib.
 */
bool smb2_util_verify_attrib(TALLOC_CTX *tctx, struct smb2_tree *tree,
    struct smb2_handle handle, uint32_t attrib)
{
	NTSTATUS status;
	bool ret = true;
	union smb_fileinfo q = {};

	q.standard.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	q.standard.in.file.handle = handle;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	q.all_info2.out.attrib &= ~(FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NONINDEXED);

	if (q.all_info2.out.attrib != attrib) {
		torture_warning(tctx, "%s: attributes don't match! "
		    "got %x, expected %x\n", __location__,
		    (uint32_t)q.standard.out.attrib,
		    (uint32_t)attrib);
		ret = false;
	}

 done:
	return ret;
}


uint32_t smb2_util_lease_state(const char *ls)
{
	uint32_t val = 0;
	int i;

	for (i = 0; i < strlen(ls); i++) {
		switch (ls[i]) {
		case 'R':
			val |= SMB2_LEASE_READ;
			break;
		case 'H':
			val |= SMB2_LEASE_HANDLE;
			break;
		case 'W':
			val |= SMB2_LEASE_WRITE;
			break;
		}
	}

	return val;
}


uint32_t smb2_util_share_access(const char *sharemode)
{
	uint32_t val = NTCREATEX_SHARE_ACCESS_NONE; /* 0 */
	int i;

	for (i = 0; i < strlen(sharemode); i++) {
		switch(sharemode[i]) {
		case 'R':
			val |= NTCREATEX_SHARE_ACCESS_READ;
			break;
		case 'W':
			val |= NTCREATEX_SHARE_ACCESS_WRITE;
			break;
		case 'D':
			val |= NTCREATEX_SHARE_ACCESS_DELETE;
			break;
		}
	}

	return val;
}

uint8_t smb2_util_oplock_level(const char *op)
{
	uint8_t val = SMB2_OPLOCK_LEVEL_NONE;
	int i;

	for (i = 0; i < strlen(op); i++) {
		switch (op[i]) {
		case 's':
			return SMB2_OPLOCK_LEVEL_II;
		case 'x':
			return SMB2_OPLOCK_LEVEL_EXCLUSIVE;
		case 'b':
			return SMB2_OPLOCK_LEVEL_BATCH;
		default:
			continue;
		}
	}

	return val;
}

/**
 * Helper functions to fill a smb2_create struct for several
 * open scenarios.
 */
void smb2_generic_create_share(struct smb2_create *io, struct smb2_lease *ls,
			       bool dir, const char *name, uint32_t disposition,
			       uint32_t share_access,
			       uint8_t oplock, uint64_t leasekey,
			       uint32_t leasestate)
{
	ZERO_STRUCT(*io);
	io->in.security_flags		= 0x00;
	io->in.oplock_level		= oplock;
	io->in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	io->in.create_flags		= 0x00000000;
	io->in.reserved			= 0x00000000;
	io->in.desired_access		= SEC_RIGHTS_FILE_ALL;
	io->in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	io->in.share_access		= share_access;
	io->in.create_disposition	= disposition;
	io->in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	io->in.fname			= name;

	if (dir) {
		io->in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		io->in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
		io->in.create_disposition = NTCREATEX_DISP_CREATE;
	}

	if (ls) {
		ZERO_STRUCTPN(ls);
		ls->lease_key.data[0] = leasekey;
		ls->lease_key.data[1] = ~leasekey;
		ls->lease_state = leasestate;
		io->in.lease_request = ls;
	}
}

void smb2_generic_create(struct smb2_create *io, struct smb2_lease *ls,
			 bool dir, const char *name, uint32_t disposition,
			 uint8_t oplock, uint64_t leasekey,
			 uint32_t leasestate)
{
	smb2_generic_create_share(io, ls, dir, name, disposition,
				  smb2_util_share_access("RWD"),
				  oplock,
				  leasekey, leasestate);
}

void smb2_lease_create_share(struct smb2_create *io, struct smb2_lease *ls,
			     bool dir, const char *name, uint32_t share_access,
			     uint64_t leasekey, uint32_t leasestate)
{
	smb2_generic_create_share(io, ls, dir, name, NTCREATEX_DISP_OPEN_IF,
				  share_access, SMB2_OPLOCK_LEVEL_LEASE,
				  leasekey, leasestate);
}

void smb2_lease_create(struct smb2_create *io, struct smb2_lease *ls,
		       bool dir, const char *name, uint64_t leasekey,
		       uint32_t leasestate)
{
	smb2_lease_create_share(io, ls, dir, name,
				smb2_util_share_access("RWD"),
				leasekey, leasestate);
}

void smb2_lease_v2_create_share(struct smb2_create *io,
				struct smb2_lease *ls,
				bool dir,
				const char *name,
				uint32_t share_access,
				uint64_t leasekey,
				const uint64_t *parentleasekey,
				uint32_t leasestate,
				uint16_t lease_epoch)
{
	smb2_generic_create_share(io, NULL, dir, name, NTCREATEX_DISP_OPEN_IF,
				  share_access, SMB2_OPLOCK_LEVEL_LEASE, 0, 0);

	if (ls) {
		ZERO_STRUCT(*ls);
		ls->lease_key.data[0] = leasekey;
		ls->lease_key.data[1] = ~leasekey;
		ls->lease_state = leasestate;
		if (parentleasekey != NULL) {
			ls->lease_flags |= SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET;
			ls->parent_lease_key.data[0] = *parentleasekey;
			ls->parent_lease_key.data[1] = ~(*parentleasekey);
		}
		ls->lease_epoch = lease_epoch;
		io->in.lease_request_v2 = ls;
	}
}

void smb2_lease_v2_create(struct smb2_create *io,
			  struct smb2_lease *ls,
			  bool dir,
			  const char *name,
			  uint64_t leasekey,
			  const uint64_t *parentleasekey,
			  uint32_t leasestate,
			  uint16_t lease_epoch)
{
	smb2_lease_v2_create_share(io, ls, dir, name,
				   smb2_util_share_access("RWD"),
				   leasekey, parentleasekey,
				   leasestate, lease_epoch);
}


void smb2_oplock_create_share(struct smb2_create *io, const char *name,
			      uint32_t share_access, uint8_t oplock)
{
	smb2_generic_create_share(io, NULL, false, name, NTCREATEX_DISP_OPEN_IF,
				  share_access, oplock, 0, 0);
}
void smb2_oplock_create(struct smb2_create *io, const char *name, uint8_t oplock)
{
	smb2_oplock_create_share(io, name, smb2_util_share_access("RWD"),
				 oplock);
}

/*
   a wrapper around smblsa_sid_check_privilege, that tries to take
   account of the fact that the lsa privileges calls don't expand
   group memberships, using an explicit check for administrator. There
   must be a better way ...
 */
NTSTATUS torture_smb2_check_privilege(struct smb2_tree *tree,
				     const char *sid_str,
				     const char *privilege)
{
	struct dom_sid *sid = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	uint32_t rid;
	NTSTATUS status;

	tmp_ctx = talloc_new(tree);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sid = dom_sid_parse_talloc(tmp_ctx, sid_str);
	if (sid == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_SID;
	}

	status = dom_sid_split_rid(tmp_ctx, sid, NULL, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	if (rid == DOMAIN_RID_ADMINISTRATOR) {
		/* assume the administrator has them all */
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_OK;
	}

	talloc_free(tmp_ctx);

	return smb2lsa_sid_check_privilege(tree, sid_str, privilege);
}
