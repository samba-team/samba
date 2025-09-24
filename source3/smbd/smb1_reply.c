/*
   Unix SMB/CIFS implementation.
   Main SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett      2001
   Copyright (C) Jeremy Allison 1992-2007.
   Copyright (C) Volker Lendecke 2007

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
/*
   This file handles most of the reply_ calls that the server
   makes to handle specific protocols
*/

#include "includes.h"
#include "libsmb/namequery.h"
#include "system/filesys.h"
#include "printing.h"
#include "locking/share_mode_lock.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "source3/smbd/smbXsrv_session.h"
#include "smbd/smbXsrv_open.h"
#include "fake_file.h"
#include "rpc_client/rpc_client.h"
#include "../librpc/gen_ndr/ndr_spoolss_c.h"
#include "rpc_client/cli_spoolss.h"
#include "rpc_client/init_spoolss.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "libcli/security/security.h"
#include "libsmb/nmblib.h"
#include "auth.h"
#include "smbprofile.h"
#include "../lib/tsocket/tsocket.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/smb/smb_signing.h"
#include "lib/util/sys_rw_data.h"
#include "librpc/gen_ndr/open_files.h"
#include "libcli/smb/smb2_posix.h"
#include "lib/util/string_wrappers.h"
#include "source3/printing/rap_jobid.h"
#include "source3/lib/substitute.h"
#include "source3/smbd/dir.h"

/****************************************************************************
 Check if we have a correct fsp pointing to a file. Basic check for open fsp.
****************************************************************************/

bool check_fsp_open(connection_struct *conn, struct smb_request *req,
                    files_struct *fsp)
{
	if ((fsp == NULL) || (conn == NULL)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return false;
	}
	if ((conn != fsp->conn) || (req->vuid != fsp->vuid)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return false;
	}
	return true;
}

/****************************************************************************
 SMB1 version of smb2_strip_dfs_path()
 Differs from SMB2 in that all Windows path separator '\' characters
 have already been converted to '/' by check_path_syntax().
****************************************************************************/

NTSTATUS smb1_strip_dfs_path(TALLOC_CTX *mem_ctx,
			     uint32_t *_ucf_flags,
			     char **in_path)
{
	uint32_t ucf_flags = *_ucf_flags;
	char *path = *in_path;
	char *return_path = NULL;

	if (!(ucf_flags & UCF_DFS_PATHNAME)) {
		return NT_STATUS_OK;
	}

	/* Strip any leading '/' characters - MacOSX client behavior. */
	while (*path == '/') {
		path++;
	}

	/* We should now be pointing at the server name. Go past it. */
	for (;;) {
		if (*path == '\0') {
			/* End of complete path. Exit OK. */
			goto done;
		}
		if (*path == '/') {
			/* End of server name. Go past and break. */
			path++;
			break;
		}
		path++; /* Continue looking for end of server name or string. */
	}

	/* We should now be pointing at the share name. Go past it. */
	for (;;) {
		if (*path == '\0') {
			/* End of complete path. Exit OK. */
			goto done;
                }
		if (*path == '/') {
			/* End of share name. Go past and break. */
			path++;
			break;
		}
		if (*path == ':') {
			/* Only invalid character in sharename. */
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
		path++; /* Continue looking for end of share name or string. */
	}

  done:
	/* path now points at the start of the real filename (if any). */
	/* Duplicate it first. */
	return_path = talloc_strdup(mem_ctx, path);
	if (return_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Now we can free the original (path points to part of this). */
	TALLOC_FREE(*in_path);

	*in_path = return_path;
	ucf_flags &= ~UCF_DFS_PATHNAME;
	*_ucf_flags = ucf_flags;
	return NT_STATUS_OK;
}

/****************************************************************************
 Check if we have a correct fsp pointing to a file.
****************************************************************************/

bool check_fsp(connection_struct *conn, struct smb_request *req,
               files_struct *fsp)
{
	if (!check_fsp_open(conn, req, fsp)) {
		return false;
	}
	if (fsp->fsp_flags.is_directory) {
		reply_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		return false;
	}
	if (fsp_get_pathref_fd(fsp) == -1) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		return false;
	}
	fsp->num_smb_operations++;
	return true;
}

/****************************************************************************
 Reply to a tcon.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_tcon(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	const char *service;
	char *service_buf = NULL;
	char *password = NULL;
	char *dev = NULL;
	int pwlen=0;
	NTSTATUS nt_status;
	const uint8_t *p;
	const char *p2;
	TALLOC_CTX *ctx = talloc_tos();
	struct smbXsrv_connection *xconn = req->xconn;
	NTTIME now = timeval_to_nttime(&req->request_time);

	START_PROFILE(SMBtcon);

	if (req->buflen < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtcon);
		return;
	}

	p = req->buf + 1;
	p += srvstr_pull_req_talloc(ctx, req, &service_buf, p, STR_TERMINATE);
	p += 1;
	pwlen = srvstr_pull_req_talloc(ctx, req, &password, p, STR_TERMINATE);
	p += pwlen+1;
	p += srvstr_pull_req_talloc(ctx, req, &dev, p, STR_TERMINATE);
	p += 1;

	if (service_buf == NULL || password == NULL || dev == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtcon);
		return;
	}
	p2 = strrchr_m(service_buf,'\\');
	if (p2) {
		service = p2+1;
	} else {
		service = service_buf;
	}

	conn = make_connection(req, now, service, dev,
			       req->vuid,&nt_status);
	req->conn = conn;

	if (!conn) {
		reply_nterror(req, nt_status);
		END_PROFILE(SMBtcon);
		return;
	}

	reply_smb1_outbuf(req, 2, 0);
	SSVAL(req->outbuf,smb_vwv0,xconn->smb1.negprot.max_recv);
	SSVAL(req->outbuf,smb_vwv1,conn->cnum);
	SSVAL(req->outbuf,smb_tid,conn->cnum);

	DEBUG(3,("tcon service=%s cnum=%d\n",
		 service, conn->cnum));

	END_PROFILE(SMBtcon);
	return;
}

/****************************************************************************
 Reply to a tcon and X.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_tcon_and_X(struct smb_request *req)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	connection_struct *conn = req->conn;
	const char *service = NULL;
	TALLOC_CTX *ctx = talloc_tos();
	/* what the client thinks the device is */
	char *client_devicetype = NULL;
	/* what the server tells the client the share represents */
	const char *server_devicetype;
	NTSTATUS nt_status;
	int passlen;
	char *path = NULL;
	const uint8_t *p;
	const char *q;
	uint16_t tcon_flags;
	struct smbXsrv_session *session = NULL;
	NTTIME now = timeval_to_nttime(&req->request_time);
	bool session_key_updated = false;
	uint16_t optional_support = 0;
	struct smbXsrv_connection *xconn = req->xconn;

	START_PROFILE(SMBtconX);

	if (req->wct < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtconX);
		return;
	}

	passlen = SVAL(req->vwv+3, 0);
	tcon_flags = SVAL(req->vwv+2, 0);

	/* we might have to close an old one */
	if ((tcon_flags & TCONX_FLAG_DISCONNECT_TID) && conn) {
		struct smbXsrv_tcon *tcon;
		NTSTATUS status;

		tcon = conn->tcon;
		req->conn = NULL;
		conn = NULL;

		/*
		 * TODO: cancel all outstanding requests on the tcon
		 */
		status = smbXsrv_tcon_disconnect(tcon, req->vuid);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("reply_tcon_and_X: "
				  "smbXsrv_tcon_disconnect() failed: %s\n",
				  nt_errstr(status)));
			/*
			 * If we hit this case, there is something completely
			 * wrong, so we better disconnect the transport connection.
			 */
			END_PROFILE(SMBtconX);
			exit_server(__location__ ": smbXsrv_tcon_disconnect failed");
			return;
		}

		TALLOC_FREE(tcon);
		/*
		 * This tree id is gone. Make sure we can't re-use it
		 * by accident.
		 */
		req->tid = 0;
	}

	if ((passlen > MAX_PASS_LEN) || (passlen >= req->buflen)) {
		reply_force_doserror(req, ERRDOS, ERRbuftoosmall);
		END_PROFILE(SMBtconX);
		return;
	}

	if (xconn->smb1.negprot.encrypted_passwords) {
		p = req->buf + passlen;
	} else {
		p = req->buf + passlen + 1;
	}

	p += srvstr_pull_req_talloc(ctx, req, &path, p, STR_TERMINATE);

	if (path == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtconX);
		return;
	}

	/*
	 * the service name can be either: \\server\share
	 * or share directly like on the DELL PowerVault 705
	 */
	if (*path=='\\') {
		q = strchr_m(path+2,'\\');
		if (!q) {
			reply_nterror(req, NT_STATUS_BAD_NETWORK_NAME);
			END_PROFILE(SMBtconX);
			return;
		}
		service = q+1;
	} else {
		service = path;
	}

	p += srvstr_pull_talloc(ctx, req->inbuf, req->flags2,
				&client_devicetype, p,
				MIN(6, smbreq_bufrem(req, p)), STR_ASCII);

	if (client_devicetype == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtconX);
		return;
	}

	DEBUG(4,("Client requested device type [%s] for share [%s]\n", client_devicetype, service));

	nt_status = smb1srv_session_lookup(xconn,
					   req->vuid, now, &session);
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_USER_SESSION_DELETED)) {
		reply_force_doserror(req, ERRSRV, ERRbaduid);
		END_PROFILE(SMBtconX);
		return;
	}
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		reply_nterror(req, nt_status);
		END_PROFILE(SMBtconX);
		return;
	}
	if (!NT_STATUS_IS_OK(nt_status)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		END_PROFILE(SMBtconX);
		return;
	}

	if (session->global->auth_session_info == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		END_PROFILE(SMBtconX);
		return;
	}

	/*
	 * If there is no application key defined yet
	 * we create one.
	 *
	 * This means we setup the application key on the
	 * first tcon that happens via the given session.
	 *
	 * Once the application key is defined, it does not
	 * change any more.
	 */
	if (session->global->application_key_blob.length == 0 &&
	    smb2_signing_key_valid(session->global->signing_key))
	{
		struct smbXsrv_session *x = session;
		struct auth_session_info *session_info =
			session->global->auth_session_info;
		uint8_t session_key[16];

		ZERO_STRUCT(session_key);
		memcpy(session_key, x->global->signing_key->blob.data,
		       MIN(x->global->signing_key->blob.length, sizeof(session_key)));

		/*
		 * The application key is truncated/padded to 16 bytes
		 */
		x->global->application_key_blob = data_blob_talloc(x->global,
							     session_key,
							     sizeof(session_key));
		ZERO_STRUCT(session_key);
		if (x->global->application_key_blob.data == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}
		talloc_keep_secret(x->global->application_key_blob.data);

		if (tcon_flags & TCONX_FLAG_EXTENDED_SIGNATURES) {
			NTSTATUS status;

			status = smb1_key_derivation(x->global->application_key_blob.data,
						    x->global->application_key_blob.length,
						    x->global->application_key_blob.data);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("smb1_key_derivation failed: %s\n",
					nt_errstr(status));
				END_PROFILE(SMBtconX);
				return;
			}
			optional_support |= SMB_EXTENDED_SIGNATURES;
		}

		/*
		 * Place the application key into the session_info
		 */
		data_blob_clear_free(&session_info->session_key);
		session_info->session_key = data_blob_dup_talloc(session_info,
						x->global->application_key_blob);
		if (session_info->session_key.data == NULL) {
			data_blob_clear_free(&x->global->application_key_blob);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}
		talloc_keep_secret(session_info->session_key.data);
		session_key_updated = true;
	}

	conn = make_connection(req, now, service, client_devicetype,
			       req->vuid, &nt_status);
	req->conn =conn;

	if (!conn) {
		if (session_key_updated) {
			struct smbXsrv_session *x = session;
			struct auth_session_info *session_info =
				session->global->auth_session_info;
			data_blob_clear_free(&x->global->application_key_blob);
			data_blob_clear_free(&session_info->session_key);
		}
		reply_nterror(req, nt_status);
		END_PROFILE(SMBtconX);
		return;
	}

	if ( IS_IPC(conn) )
		server_devicetype = "IPC";
	else if ( IS_PRINT(conn) )
		server_devicetype = "LPT1:";
	else
		server_devicetype = "A:";

	if (xconn->protocol < PROTOCOL_NT1) {
		reply_smb1_outbuf(req, 2, 0);
		if (message_push_string(&req->outbuf, server_devicetype,
					STR_TERMINATE|STR_ASCII) == -1) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}
	} else {
		/* NT sets the fstype of IPC$ to the null string */
		const char *fstype = IS_IPC(conn) ? "" : lp_fstype(SNUM(conn));

		if (tcon_flags & TCONX_FLAG_EXTENDED_RESPONSE) {
			/* Return permissions. */
			uint32_t perm1 = 0;
			uint32_t perm2 = 0;

			reply_smb1_outbuf(req, 7, 0);

			if (IS_IPC(conn)) {
				perm1 = FILE_ALL_ACCESS;
				perm2 = FILE_ALL_ACCESS;
			} else {
				perm1 = conn->share_access;
			}

			SIVAL(req->outbuf, smb_vwv3, perm1);
			SIVAL(req->outbuf, smb_vwv5, perm2);
		} else {
			reply_smb1_outbuf(req, 3, 0);
		}

		if ((message_push_string(&req->outbuf, server_devicetype,
					 STR_TERMINATE|STR_ASCII) == -1)
		    || (message_push_string(&req->outbuf, fstype,
					    STR_TERMINATE) == -1)) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtconX);
			return;
		}

		/* what does setting this bit do? It is set by NT4 and
		   may affect the ability to autorun mounted cdroms */
		optional_support |= SMB_SUPPORT_SEARCH_BITS;
		optional_support |=
			(lp_csc_policy(SNUM(conn)) << SMB_CSC_POLICY_SHIFT);

		if (lp_msdfs_root(SNUM(conn)) && lp_host_msdfs()) {
			DEBUG(2,("Serving %s as a Dfs root\n",
				 lp_servicename(ctx, lp_sub, SNUM(conn)) ));
			optional_support |= SMB_SHARE_IN_DFS;
		}

		SSVAL(req->outbuf, smb_vwv2, optional_support);
	}

	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	DEBUG(3,("tconX service=%s \n",
		 service));

	/* set the incoming and outgoing tid to the just created one */
	SSVAL(discard_const_p(uint8_t, req->inbuf),smb_tid,conn->cnum);
	SSVAL(req->outbuf,smb_tid,conn->cnum);

	END_PROFILE(SMBtconX);

	req->tid = conn->cnum;
}

/****************************************************************************
 Reply to an unknown type.
****************************************************************************/

void reply_unknown_new(struct smb_request *req, uint8_t type)
{
	DEBUG(0, ("unknown command type (%s): type=%d (0x%X)\n",
		  smb_fn_name(type), type, type));
	reply_force_doserror(req, ERRSRV, ERRunknownsmb);
	return;
}

/****************************************************************************
 Reply to an ioctl.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_ioctl(struct smb_request *req)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	connection_struct *conn = req->conn;
	uint16_t device;
	uint16_t function;
	uint32_t ioctl_code;
	int replysize;
	char *p;

	START_PROFILE(SMBioctl);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBioctl);
		return;
	}

	device     = SVAL(req->vwv+1, 0);
	function   = SVAL(req->vwv+2, 0);
	ioctl_code = (device << 16) + function;

	DEBUG(4, ("Received IOCTL (code 0x%x)\n", ioctl_code));

	switch (ioctl_code) {
	    case IOCTL_QUERY_JOB_INFO:
		    replysize = 32;
		    break;
	    default:
		    reply_force_doserror(req, ERRSRV, ERRnosupport);
		    END_PROFILE(SMBioctl);
		    return;
	}

	reply_smb1_outbuf(req, 8, replysize+1);
	SSVAL(req->outbuf,smb_vwv1,replysize); /* Total data bytes returned */
	SSVAL(req->outbuf,smb_vwv5,replysize); /* Data bytes this buffer */
	SSVAL(req->outbuf,smb_vwv6,52);        /* Offset to data */
	p = smb_buf(req->outbuf);
	memset(p, '\0', replysize+1); /* valgrind-safe. */
	p += 1;          /* Allow for alignment */

	switch (ioctl_code) {
		case IOCTL_QUERY_JOB_INFO:
		{
			NTSTATUS status;
			size_t len = 0;
			files_struct *fsp = file_fsp(
				req, SVAL(req->vwv+0, 0));
			if (!fsp) {
				reply_nterror(req, NT_STATUS_INVALID_HANDLE);
				END_PROFILE(SMBioctl);
				return;
			}
			/* Job number */
			SSVAL(p, 0, print_spool_rap_jobid(fsp->print_file));

			status = srvstr_push((char *)req->outbuf, req->flags2, p+2,
				    lp_netbios_name(), 15,
				    STR_TERMINATE|STR_ASCII, &len);
			if (!NT_STATUS_IS_OK(status)) {
				reply_nterror(req, status);
				END_PROFILE(SMBioctl);
				return;
			}
			if (conn) {
				status = srvstr_push((char *)req->outbuf, req->flags2,
					    p+18,
					    lp_servicename(talloc_tos(),
							   lp_sub,
							   SNUM(conn)),
					    13, STR_TERMINATE|STR_ASCII, &len);
				if (!NT_STATUS_IS_OK(status)) {
					reply_nterror(req, status);
					END_PROFILE(SMBioctl);
					return;
				}
			} else {
				memset(p+18, 0, 13);
			}
			break;
		}
	}

	END_PROFILE(SMBioctl);
	return;
}

/****************************************************************************
 Strange checkpath NTSTATUS mapping.
****************************************************************************/

static NTSTATUS map_checkpath_error(uint16_t flags2, NTSTATUS status)
{
	/* Strange DOS error code semantics only for checkpath... */
	if (!(flags2 & FLAGS2_32_BIT_ERROR_CODES)) {
		if (NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_INVALID,status)) {
			/* We need to map to ERRbadpath */
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
	}
	return status;
}

/****************************************************************************
 Reply to a checkpath.
****************************************************************************/

void reply_checkpath(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *name = NULL;
	NTSTATUS status;
	struct files_struct *dirfsp = NULL;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBcheckpath);

	srvstr_get_path_req(ctx, req, &name, (const char *)req->buf + 1,
			    STR_TERMINATE, &status);

	if (!NT_STATUS_IS_OK(status)) {
		status = map_checkpath_error(req->flags2, status);
		reply_nterror(req, status);
		END_PROFILE(SMBcheckpath);
		return;
	}

	DEBUG(3,("reply_checkpath %s mode=%d\n", name, (int)SVAL(req->vwv+0, 0)));

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(name, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &name);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert_dirfsp(ctx,
					 conn,
					 name,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			END_PROFILE(SMBcheckpath);
			return;
		}
		goto path_err;
	}

	if (!VALID_STAT(smb_fname->st)) {
		DBG_NOTICE("%s not found\n", smb_fname_str_dbg(smb_fname));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto path_err;
	}

	if (!S_ISDIR(smb_fname->st.st_ex_mode)) {
		reply_botherror(req, NT_STATUS_NOT_A_DIRECTORY,
				ERRDOS, ERRbadpath);
		goto out;
	}

	reply_smb1_outbuf(req, 0, 0);

 path_err:
	/* We special case this - as when a Windows machine
		is parsing a path is steps through the components
		one at a time - if a component fails it expects
		ERRbadpath, not ERRbadfile.
	*/
	status = map_checkpath_error(req->flags2, status);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * Windows returns different error codes if
		 * the parent directory is valid but not the
		 * last component - it returns NT_STATUS_OBJECT_NAME_NOT_FOUND
		 * for that case and NT_STATUS_OBJECT_PATH_NOT_FOUND
		 * if the path is invalid.
		 */
		reply_botherror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				ERRDOS, ERRbadpath);
		goto out;
	}

	reply_nterror(req, status);

 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBcheckpath);
	return;
}

/****************************************************************************
 Reply to a getatr.
****************************************************************************/

void reply_getatr(struct smb_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	int mode=0;
	off_t size=0;
	time_t mtime=0;
	const char *p;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBgetatr);

	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req(ctx, req, &fname, p, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	/*
	 * dos sometimes asks for a stat of "" - it returns a "hidden
	 * directory" under WfWg - weird!
	 */
	if (*fname == '\0') {
		mode = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY;
		if (!CAN_WRITE(conn)) {
			mode |= FILE_ATTRIBUTE_READONLY;
		}
		size = 0;
		mtime = 0;
	} else {
		struct files_struct *dirfsp = NULL;
		uint32_t ucf_flags = ucf_flags_from_smb_request(req);
		NTTIME twrp = 0;

		if (ucf_flags & UCF_GMT_PATHNAME) {
			extract_snapshot_token(fname, &twrp);
		}
		status = smb1_strip_dfs_path(ctx, &ucf_flags, &fname);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}
		status = filename_convert_dirfsp(ctx,
						 conn,
						 fname,
						 ucf_flags,
						 twrp,
						 &dirfsp,
						 &smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
				reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
						ERRSRV, ERRbadpath);
				goto out;
			}
			reply_nterror(req, status);
			goto out;
		}
		if (!VALID_STAT(smb_fname->st)) {
			DBG_NOTICE("File %s not found\n",
				   smb_fname_str_dbg(smb_fname));
			reply_nterror(req,  map_nt_error_from_unix(errno));
			goto out;
		}

		mode = fdos_mode(smb_fname->fsp);
		size = smb_fname->st.st_ex_size;

		mtime = convert_timespec_to_time_t(smb_fname->st.st_ex_mtime);
		if (mode & FILE_ATTRIBUTE_DIRECTORY) {
			size = 0;
		}
	}

	reply_smb1_outbuf(req, 10, 0);

	SSVAL(req->outbuf,smb_vwv0,mode);
	if(lp_dos_filetime_resolution(SNUM(conn)) ) {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv1,mtime & ~1);
	} else {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv1,mtime);
	}
	SIVAL(req->outbuf,smb_vwv3,(uint32_t)size);

	if (xconn->protocol >= PROTOCOL_NT1) {
		SSVAL(req->outbuf, smb_flg2,
		      SVAL(req->outbuf, smb_flg2) | FLAGS2_IS_LONG_NAME);
	}

	DEBUG(3,("reply_getatr: name=%s mode=%d size=%u\n",
		 smb_fname_str_dbg(smb_fname), mode, (unsigned int)size));

 out:
	TALLOC_FREE(smb_fname);
	TALLOC_FREE(fname);
	END_PROFILE(SMBgetatr);
	return;
}

/****************************************************************************
 Reply to a setatr.
****************************************************************************/

void reply_setatr(struct smb_request *req)
{
	struct smb_file_time ft;
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	struct files_struct *dirfsp = NULL;
	char *fname = NULL;
	int mode;
	time_t mtime;
	const char *p;
	NTSTATUS status;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBsetatr);
	init_smb_file_time(&ft);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req(ctx, req, &fname, p, STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(fname, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}
	status = filename_convert_dirfsp(ctx,
					 conn,
					 fname,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	if (ISDOT(smb_fname->base_name)) {
		/*
		 * Not sure here is the right place to catch this
		 * condition. Might be moved to somewhere else later -- vl
		 */
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	if (smb_fname->fsp == NULL) {
		/*
		 * filename_convert_dirfsp only returns a NULL fsp for
		 * new files.
		 */
		reply_nterror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		goto out;
	}

	mode = SVAL(req->vwv+0, 0);
	mtime = srv_make_unix_date3(req->vwv+1);

	if (mode != FILE_ATTRIBUTE_NORMAL) {
		if (VALID_STAT_OF_DIR(smb_fname->st))
			mode |= FILE_ATTRIBUTE_DIRECTORY;
		else
			mode &= ~FILE_ATTRIBUTE_DIRECTORY;

		status = smbd_check_access_rights_fsp(conn->cwd_fsp,
					smb_fname->fsp,
					false,
					FILE_WRITE_ATTRIBUTES);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}

		if (file_set_dosmode(conn, smb_fname, mode, NULL,
				     false) != 0) {
			reply_nterror(req, map_nt_error_from_unix(errno));
			goto out;
		}
	}

	ft.mtime = time_t_to_full_timespec(mtime);

	status = smb_set_file_time(conn, smb_fname->fsp, smb_fname, &ft, true);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	reply_smb1_outbuf(req, 0, 0);

	DEBUG(3, ("setatr name=%s mode=%d\n", smb_fname_str_dbg(smb_fname),
		 mode));
 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBsetatr);
	return;
}

/****************************************************************************
 Reply to a dskattr.
****************************************************************************/

void reply_dskattr(struct smb_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	connection_struct *conn = req->conn;
	uint64_t ret;
	uint64_t dfree,dsize,bsize;
	struct smb_filename smb_fname;
	START_PROFILE(SMBdskattr);

	ZERO_STRUCT(smb_fname);
	smb_fname.base_name = discard_const_p(char, ".");

	if (SMB_VFS_STAT(conn, &smb_fname) != 0) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		DBG_WARNING("stat of . failed (%s)\n", strerror(errno));
		END_PROFILE(SMBdskattr);
		return;
	}

	ret = get_dfree_info(conn, &smb_fname, &bsize, &dfree, &dsize);
	if (ret == (uint64_t)-1) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		END_PROFILE(SMBdskattr);
		return;
	}

	/*
	 * Force max to fit in 16 bit fields.
	 */
	while (dfree > WORDMAX || dsize > WORDMAX || bsize < 512) {
		dfree /= 2;
		dsize /= 2;
		bsize *= 2;
		if (bsize > (WORDMAX*512)) {
			bsize = (WORDMAX*512);
			if (dsize > WORDMAX)
				dsize = WORDMAX;
			if (dfree >  WORDMAX)
				dfree = WORDMAX;
			break;
		}
	}

	reply_smb1_outbuf(req, 5, 0);

	if (xconn->protocol <= PROTOCOL_LANMAN2) {
		double total_space, free_space;
		/* we need to scale this to a number that DOS6 can handle. We
		   use floating point so we can handle large drives on systems
		   that don't have 64 bit integers

		   we end up displaying a maximum of 2G to DOS systems
		*/
		total_space = dsize * (double)bsize;
		free_space = dfree * (double)bsize;

		dsize = (uint64_t)((total_space+63*512) / (64*512));
		dfree = (uint64_t)((free_space+63*512) / (64*512));

		if (dsize > 0xFFFF) dsize = 0xFFFF;
		if (dfree > 0xFFFF) dfree = 0xFFFF;

		SSVAL(req->outbuf,smb_vwv0,dsize);
		SSVAL(req->outbuf,smb_vwv1,64); /* this must be 64 for dos systems */
		SSVAL(req->outbuf,smb_vwv2,512); /* and this must be 512 */
		SSVAL(req->outbuf,smb_vwv3,dfree);
	} else {
		SSVAL(req->outbuf,smb_vwv0,dsize);
		SSVAL(req->outbuf,smb_vwv1,bsize/512);
		SSVAL(req->outbuf,smb_vwv2,512);
		SSVAL(req->outbuf,smb_vwv3,dfree);
	}

	DEBUG(3,("dskattr dfree=%d\n", (unsigned int)dfree));

	END_PROFILE(SMBdskattr);
	return;
}

/****************************************************************************
 Make a dir struct.
****************************************************************************/

static void make_dir_struct(char *buf,
			    const char *mask,
			    const char *fname,
			    off_t size,
			    uint32_t mode,
			    time_t date,
			    bool uc)
{
	char *p;

	if ((mode & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		size = 0;
	}

	memset(buf+1,' ',11);
	if ((p = strchr_m(mask, '.')) != NULL) {
		char name[p - mask + 1];
		strlcpy(name, mask, sizeof(name));
		push_ascii(buf + 1, name, 8, 0);
		push_ascii(buf+9,p+1,3, 0);
	} else {
		push_ascii(buf + 1, mask, 11, 0);
	}

	memset(buf+21,'\0',DIR_STRUCT_SIZE-21);
	SCVAL(buf,21,mode);
	srv_put_dos_date(buf,22,date);
	SSVAL(buf,26,size & 0xFFFF);
	SSVAL(buf,28,(size >> 16)&0xFFFF);
	/* We only uppercase if FLAGS2_LONG_PATH_COMPONENTS is zero in the input buf.
	   Strange, but verified on W2K3. Needed for OS/2. JRA. */
	push_ascii(buf+30,fname,12, uc ? STR_UPPER : 0);
	DEBUG(8,("put name [%s] from [%s] into dir struct\n",buf+30, fname));
}

/*******************************************************************
 A wrapper that handles case sensitivity and the special handling
 of the ".." name.
*******************************************************************/

static bool mask_match_search(const char *string,
			      const char *pattern,
			      bool is_case_sensitive)
{
	if (ISDOTDOT(string)) {
		string = ".";
	}
	if (ISDOT(pattern)) {
		return False;
	}

	return ms_fnmatch(pattern, string, True, is_case_sensitive) == 0;
}

static bool mangle_mask_match(connection_struct *conn,
			      const char *filename,
			      const char *mask)
{
	char mname[13];

	if (!name_to_8_3(filename, mname, False, conn->params)) {
		return False;
	}
	return mask_match_search(mname, mask, False);
}

/****************************************************************************
 Get an 8.3 directory entry.
****************************************************************************/

static bool smbd_dirptr_8_3_match_fn(TALLOC_CTX *ctx,
				     void *private_data,
				     const char *dname,
				     const char *mask,
				     char **_fname)
{
	connection_struct *conn = (connection_struct *)private_data;

	if ((strcmp(mask, "*.*") == 0) ||
	    mask_match_search(dname, mask, false) ||
	    mangle_mask_match(conn, dname, mask)) {
		char mname[13];
		const char *fname;
		/*
		 * Ensure we can push the original name as UCS2. If
		 * not, then just don't return this name.
		 */
		NTSTATUS status;
		size_t ret_len = 0;
		size_t len = (strlen(dname) + 2) * 4; /* Allow enough space. */
		uint8_t *tmp = talloc_array(talloc_tos(), uint8_t, len);

		status = srvstr_push(NULL,
				     FLAGS2_UNICODE_STRINGS,
				     tmp,
				     dname,
				     len,
				     STR_TERMINATE,
				     &ret_len);

		TALLOC_FREE(tmp);

		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		if (!mangle_is_8_3(dname, false, conn->params)) {
			bool ok =
				name_to_8_3(dname, mname, false, conn->params);
			if (!ok) {
				return false;
			}
			fname = mname;
		} else {
			fname = dname;
		}

		*_fname = talloc_strdup(ctx, fname);
		if (*_fname == NULL) {
			return false;
		}

		return true;
	}

	return false;
}

static bool get_dir_entry(TALLOC_CTX *ctx,
			  connection_struct *conn,
			  struct dptr_struct *dirptr,
			  const char *mask,
			  uint32_t dirtype,
			  char **_fname,
			  off_t *_size,
			  uint32_t *_mode,
			  struct timespec *_date,
			  bool check_descend)
{
	char *fname = NULL;
	struct smb_filename *smb_fname = NULL;
	uint32_t mode = 0;
	bool ok;

again:
	ok = smbd_dirptr_get_entry(ctx,
				   dirptr,
				   mask,
				   dirtype,
				   check_descend,
				   true,
				   smbd_dirptr_8_3_match_fn,
				   conn,
				   &fname,
				   &smb_fname,
				   &mode);
	if (!ok) {
		return false;
	}
	if (mode & FILE_ATTRIBUTE_REPARSE_POINT) {
		/* hide reparse points from ancient clients */
		TALLOC_FREE(fname);
		TALLOC_FREE(smb_fname);
		goto again;
	}

	*_fname = talloc_move(ctx, &fname);
	*_size = smb_fname->st.st_ex_size;
	*_mode = mode;
	*_date = smb_fname->st.st_ex_mtime;
	TALLOC_FREE(smb_fname);
	return true;
}

/****************************************************************************
 Reply to a search.
 Can be called from SMBsearch, SMBffirst or SMBfunique.
****************************************************************************/

void reply_search(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *path = NULL;
	char *mask = NULL;
	char *directory = NULL;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	off_t size;
	uint32_t mode;
	struct timespec date;
	uint32_t dirtype;
	unsigned int numentries = 0;
	unsigned int maxentries = 0;
	bool finished = False;
	const char *p;
	int status_len;
	char status[21];
	int dptr_num= -1;
	bool check_descend = False;
	bool expect_close = False;
	NTSTATUS nt_status;
	bool mask_contains_wcard = False;
	bool allow_long_path_components = (req->flags2 & FLAGS2_LONG_PATH_COMPONENTS) ? True : False;
	TALLOC_CTX *ctx = talloc_tos();
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_server_connection *sconn = req->sconn;
	files_struct *fsp = NULL;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	START_PROFILE(SMBsearch);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	if (req->posix_pathnames) {
		reply_unknown_new(req, req->cmd);
		goto out;
	}

	/* If we were called as SMBffirst then we must expect close. */
	if(req->cmd == SMBffirst) {
		expect_close = True;
	}

	reply_smb1_outbuf(req, 1, 3);
	maxentries = SVAL(req->vwv+0, 0);
	dirtype = SVAL(req->vwv+1, 0);
	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req(ctx, req, &path, p, STR_TERMINATE,
				       &nt_status);
	if (!NT_STATUS_IS_OK(nt_status)) {
		reply_nterror(req, nt_status);
		goto out;
	}

	if (smbreq_bufrem(req, p) < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	p++;
	status_len = SVAL(p, 0);
	p += 2;

	/* dirtype &= ~FILE_ATTRIBUTE_DIRECTORY; */

	if (status_len == 0) {
		const char *dirpath;
		struct files_struct *dirfsp = NULL;
		struct smb_filename *smb_dname = NULL;
		uint32_t ucf_flags = ucf_flags_from_smb_request(req);

		nt_status = smb1_strip_dfs_path(ctx, &ucf_flags, &path);
		if (!NT_STATUS_IS_OK(nt_status)) {
			reply_nterror(req, nt_status);
			goto out;
		}

		nt_status = filename_convert_smb1_search_path(ctx,
					conn,
					path,
					ucf_flags,
					&dirfsp,
					&smb_dname,
					&mask);

		if (!NT_STATUS_IS_OK(nt_status)) {
			if (NT_STATUS_EQUAL(nt_status,NT_STATUS_PATH_NOT_COVERED)) {
				reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
						ERRSRV, ERRbadpath);
				goto out;
			}
			reply_nterror(req, nt_status);
			goto out;
		}

		memset((char *)status,'\0',21);
		SCVAL(status,0,(dirtype & 0x1F));

		/*
		 * Open an fsp on this directory for the dptr.
		 */
		nt_status = SMB_VFS_CREATE_FILE(
				conn, /* conn */
				req, /* req */
				dirfsp, /* dirfsp */
				smb_dname, /* dname */
				FILE_LIST_DIRECTORY, /* access_mask */
				FILE_SHARE_READ|
				FILE_SHARE_WRITE, /* share_access */
				FILE_OPEN, /* create_disposition*/
				FILE_DIRECTORY_FILE, /* create_options */
				FILE_ATTRIBUTE_DIRECTORY,/* file_attributes */
				NO_OPLOCK, /* oplock_request */
				NULL, /* lease */
				0, /* allocation_size */
				0, /* private_flags */
				NULL, /* sd */
				NULL, /* ea_list */
				&fsp, /* result */
				NULL, /* pinfo */
				NULL, /* in_context */
				NULL);/* out_context */

		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("failed to open directory %s\n",
				smb_fname_str_dbg(smb_dname));
			reply_nterror(req, nt_status);
			goto out;
		}

		nt_status = dptr_create(conn,
					NULL, /* req */
					fsp, /* fsp */
					True,
					mask,
					dirtype,
					&fsp->dptr);

		TALLOC_FREE(smb_dname);

		if (!NT_STATUS_IS_OK(nt_status)) {
			/*
			 * Use NULL here for the first parameter (req)
			 * as this is not a client visible handle so
			 * can't be part of an SMB1 chain.
			 */
			close_file_free(NULL, &fsp, NORMAL_CLOSE);
			reply_nterror(req, nt_status);
			goto out;
		}

		dptr_num = dptr_dnum(fsp->dptr);
		dirpath = dptr_path(sconn, dptr_num);
		directory = talloc_strdup(ctx, dirpath);
		if (!directory) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

	} else {
		int status_dirtype;
		const char *dirpath;
		unsigned int dptr_filenum;
		uint32_t resume_key_index;

		if (smbreq_bufrem(req, p) < 21) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		memcpy(status,p,21);
		status_dirtype = CVAL(status,0) & 0x1F;
		if (status_dirtype != (dirtype & 0x1F)) {
			dirtype = status_dirtype;
		}

		dptr_num = CVAL(status, 12);
		fsp = dptr_fetch_lanman2_fsp(sconn, dptr_num);
		if (fsp == NULL) {
			goto SearchEmpty;
		}

		resume_key_index = PULL_LE_U32(status, 13);
		dptr_filenum = dptr_FileNumber(fsp->dptr);

		if (resume_key_index > dptr_filenum) {
			/*
			 * Haven't seen this resume key yet. Just stop
			 * the search.
			 */
			goto SearchEmpty;
		}

		if (resume_key_index < dptr_filenum) {
			/*
			 * The resume key was not the last one we
			 * sent, rewind and skip to what the client
			 * sent.
			 */
			dptr_RewindDir(fsp->dptr);

			dptr_filenum = dptr_FileNumber(fsp->dptr);
			SMB_ASSERT(dptr_filenum == 0);

			while (dptr_filenum < resume_key_index) {
				bool ok = get_dir_entry(
					ctx,
					conn,
					fsp->dptr,
					dptr_wcard(sconn, dptr_num),
					dirtype,
					&fname,
					&size,
					&mode,
					&date,
					check_descend);
				TALLOC_FREE(fname);
				if (!ok) {
					goto SearchEmpty;
				}

				dptr_filenum = dptr_FileNumber(fsp->dptr);
			}
		}

		dirpath = dptr_path(sconn, dptr_num);
		directory = talloc_strdup(ctx, dirpath);
		if (!directory) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

		mask = talloc_strdup(ctx, dptr_wcard(sconn, dptr_num));
		if (!mask) {
			goto SearchEmpty;
		}
		dirtype = dptr_attr(sconn, dptr_num);
	}

	mask_contains_wcard = dptr_has_wild(fsp->dptr);

	DEBUG(4,("dptr_num is %d\n",dptr_num));

	if ((dirtype&0x1F) == FILE_ATTRIBUTE_VOLUME) {
		char buf[DIR_STRUCT_SIZE];
		memcpy(buf,status,21);
		make_dir_struct(buf,
				"???????????",
				volume_label(ctx, SNUM(conn)),
				0,
				FILE_ATTRIBUTE_VOLUME,
				0,
				!allow_long_path_components);
		SCVAL(buf, 12, dptr_num);
		numentries = 1;
		if (message_push_blob(&req->outbuf,
				      data_blob_const(buf, sizeof(buf)))
		    == -1) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}
	} else {
		unsigned int i;
		size_t hdr_size = ((uint8_t *)smb_buf(req->outbuf) + 3 - req->outbuf);
		size_t available_space = xconn->smb1.sessions.max_send - hdr_size;

		maxentries = MIN(maxentries, available_space/DIR_STRUCT_SIZE);

		DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",
			 directory,lp_dont_descend(ctx, lp_sub, SNUM(conn))));
		if (in_list(directory, lp_dont_descend(ctx, lp_sub, SNUM(conn)),True)) {
			check_descend = True;
		}

		for (i=numentries;(i<maxentries) && !finished;i++) {
			finished = !get_dir_entry(ctx,
						  conn,
						  fsp->dptr,
						  mask,
						  dirtype,
						  &fname,
						  &size,
						  &mode,
						  &date,
						  check_descend);
			if (!finished) {
				char buf[DIR_STRUCT_SIZE];
				memcpy(buf,status,21);
				make_dir_struct(buf,
						mask,
						fname,
						size,
						mode,
						convert_timespec_to_time_t(
							date),
						!allow_long_path_components);
				SCVAL(buf, 12, dptr_num);
				PUSH_LE_U32(buf,
					    13,
					    dptr_FileNumber(fsp->dptr));
				if (message_push_blob(&req->outbuf,
						      data_blob_const(buf, sizeof(buf)))
				    == -1) {
					reply_nterror(req, NT_STATUS_NO_MEMORY);
					goto out;
				}
				numentries++;
			}
			TALLOC_FREE(fname);
		}
	}

  SearchEmpty:

	/* If we were called as SMBffirst with smb_search_id == NULL
		and no entries were found then return error and close fsp->dptr
		(X/Open spec) */

	if (numentries == 0) {
		dptr_num = -1;
		if (fsp != NULL) {
			close_file_free(NULL, &fsp, NORMAL_CLOSE);
		}
	} else if(expect_close && status_len == 0) {
		/* Close the dptr - we know it's gone */
		dptr_num = -1;
		if (fsp != NULL) {
			close_file_free(NULL, &fsp, NORMAL_CLOSE);
		}
	}

	/* If we were called as SMBfunique, then we can close the fsp->dptr now ! */
	if(dptr_num >= 0 && req->cmd == SMBfunique) {
		dptr_num = -1;
		/* fsp may have been closed above. */
		if (fsp != NULL) {
			close_file_free(NULL, &fsp, NORMAL_CLOSE);
		}
	}

	if ((numentries == 0) && !mask_contains_wcard) {
		reply_botherror(req, STATUS_NO_MORE_FILES, ERRDOS, ERRnofiles);
		goto out;
	}

	SSVAL(req->outbuf,smb_vwv0,numentries);
	SSVAL(req->outbuf,smb_vwv1,3 + numentries * DIR_STRUCT_SIZE);
	SCVAL(smb_buf(req->outbuf),0,5);
	SSVAL(smb_buf(req->outbuf),1,numentries*DIR_STRUCT_SIZE);

	/* The replies here are never long name. */
	SSVAL(req->outbuf, smb_flg2,
	      SVAL(req->outbuf, smb_flg2) & (~FLAGS2_IS_LONG_NAME));
	if (!allow_long_path_components) {
		SSVAL(req->outbuf, smb_flg2,
		      SVAL(req->outbuf, smb_flg2)
		      & (~FLAGS2_LONG_PATH_COMPONENTS));
	}

	/* This SMB *always* returns ASCII names. Remove the unicode bit in flags2. */
	SSVAL(req->outbuf, smb_flg2,
	      (SVAL(req->outbuf, smb_flg2) & (~FLAGS2_UNICODE_STRINGS)));

	DEBUG(4,("%s mask=%s path=%s dtype=%d nument=%u of %u\n",
		smb_fn_name(req->cmd),
		mask,
		directory,
		dirtype,
		numentries,
		maxentries ));
 out:
	TALLOC_FREE(directory);
	TALLOC_FREE(mask);
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBsearch);
	return;
}

/****************************************************************************
 Reply to a fclose (stop directory search).
****************************************************************************/

void reply_fclose(struct smb_request *req)
{
	int status_len;
	int dptr_num= -2;
	const char *p;
	char *path = NULL;
	NTSTATUS err;
	TALLOC_CTX *ctx = talloc_tos();
	struct smbd_server_connection *sconn = req->sconn;
	files_struct *fsp = NULL;

	START_PROFILE(SMBfclose);

	if (req->posix_pathnames) {
		reply_unknown_new(req, req->cmd);
		END_PROFILE(SMBfclose);
		return;
	}

	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req(ctx, req, &path, p, STR_TERMINATE,
				       &err);
	if (!NT_STATUS_IS_OK(err)) {
		reply_nterror(req, err);
		END_PROFILE(SMBfclose);
		return;
	}

	if (smbreq_bufrem(req, p) < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBfclose);
		return;
	}

	p++;
	status_len = SVAL(p,0);
	p += 2;

	if (status_len == 0) {
		reply_force_doserror(req, ERRSRV, ERRsrverror);
		END_PROFILE(SMBfclose);
		return;
	}

	if (smbreq_bufrem(req, p) < 21) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBfclose);
		return;
	}

	dptr_num = CVAL(p, 12);

	fsp = dptr_fetch_lanman2_fsp(sconn, dptr_num);
	if(fsp != NULL) {
		/*  Close the file - we know it's gone */
		close_file_free(NULL, &fsp, NORMAL_CLOSE);
		dptr_num = -1;
	}

	reply_smb1_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,0);

	DEBUG(3,("search close\n"));

	END_PROFILE(SMBfclose);
	return;
}

/****************************************************************************
 Reply to an open.
****************************************************************************/

void reply_open(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	uint32_t fattr=0;
	off_t size = 0;
	time_t mtime=0;
	int info;
	struct files_struct *dirfsp = NULL;
	files_struct *fsp;
	int oplock_request;
	int deny_mode;
	uint32_t dos_attr;
	uint32_t access_mask;
	uint32_t share_mode;
	uint32_t create_disposition;
	uint32_t create_options = 0;
	uint32_t private_flags = 0;
	NTSTATUS status;
	uint32_t ucf_flags;
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBopen);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);
	deny_mode = SVAL(req->vwv+0, 0);
	dos_attr = SVAL(req->vwv+1, 0);

	srvstr_get_path_req(ctx, req, &fname, (const char *)req->buf+1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (!map_open_params_to_ntcreate(fname, deny_mode,
					 OPENX_FILE_EXISTS_OPEN, &access_mask,
					 &share_mode, &create_disposition,
					 &create_options, &private_flags)) {
		reply_force_doserror(req, ERRDOS, ERRbadaccess);
		goto out;
	}

	ucf_flags = filename_create_ucf_flags(req,
					      create_disposition,
					      create_options);

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(fname, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}
	status = filename_convert_dirfsp(ctx,
					 conn,
					 fname,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
					NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_mode,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		dos_attr,				/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		private_flags,
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		&info,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}

		if (!NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			reply_openerror(req, status);
			goto out;
		}

		fsp = fcb_or_dos_open(
			req,
			smb_fname,
			access_mask,
			create_options,
			private_flags);
		if (fsp == NULL) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				goto out;
			}
			reply_openerror(req, status);
			goto out;
		}
	}

	/* Ensure we're pointing at the correct stat struct. */
	TALLOC_FREE(smb_fname);
	smb_fname = fsp->fsp_name;

	size = smb_fname->st.st_ex_size;
	fattr = fdos_mode(fsp);

	mtime = convert_timespec_to_time_t(smb_fname->st.st_ex_mtime);

	if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
		DEBUG(3,("attempt to open a directory %s\n",
			 fsp_str_dbg(fsp)));
		close_file_free(req, &fsp, ERROR_CLOSE);
		reply_botherror(req, NT_STATUS_ACCESS_DENIED,
			ERRDOS, ERRnoaccess);
		goto out;
	}

	reply_smb1_outbuf(req, 7, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);
	SSVAL(req->outbuf,smb_vwv1,fattr);
	if(lp_dos_filetime_resolution(SNUM(conn)) ) {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv2,mtime & ~1);
	} else {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv2,mtime);
	}
	SIVAL(req->outbuf,smb_vwv4,(uint32_t)size);
	SSVAL(req->outbuf,smb_vwv6,deny_mode);

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf,smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf,smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}
 out:
	END_PROFILE(SMBopen);
	return;
}

/****************************************************************************
 Reply to an open and X.
****************************************************************************/

void reply_open_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	uint16_t open_flags;
	int deny_mode;
	uint32_t smb_attr;
	/* Breakout the oplock request bits so we can set the
		reply bits separately. */
	int ex_oplock_request;
	int core_oplock_request;
	int oplock_request;
#if 0
	int smb_sattr = SVAL(req->vwv+4, 0);
	uint32_t smb_time = make_unix_date3(req->vwv+6);
#endif
	int smb_ofun;
	uint32_t fattr=0;
	time_t mtime=0;
	int smb_action = 0;
	struct files_struct *dirfsp = NULL;
	files_struct *fsp;
	NTSTATUS status;
	uint64_t allocation_size;
	ssize_t retval = -1;
	uint32_t access_mask;
	uint32_t share_mode;
	uint32_t create_disposition;
	uint32_t create_options = 0;
	uint32_t private_flags = 0;
	uint32_t ucf_flags;
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBopenX);

	if (req->wct < 15) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	open_flags = SVAL(req->vwv+2, 0);
	deny_mode = SVAL(req->vwv+3, 0);
	smb_attr = SVAL(req->vwv+5, 0);
	ex_oplock_request = EXTENDED_OPLOCK_REQUEST(req->inbuf);
	core_oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);
	oplock_request = ex_oplock_request | core_oplock_request;
	smb_ofun = SVAL(req->vwv+8, 0);
	allocation_size = (uint64_t)IVAL(req->vwv+9, 0);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		if (lp_nt_pipe_support()) {
			reply_open_pipe_and_X(conn, req);
		} else {
			reply_nterror(req, NT_STATUS_NETWORK_ACCESS_DENIED);
		}
		goto out;
	}

	/* XXXX we need to handle passed times, sattr and flags */
	srvstr_get_path_req(ctx, req, &fname, (const char *)req->buf,
			STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (!map_open_params_to_ntcreate(fname, deny_mode,
					 smb_ofun,
					 &access_mask, &share_mode,
					 &create_disposition,
					 &create_options,
					 &private_flags)) {
		reply_force_doserror(req, ERRDOS, ERRbadaccess);
		goto out;
	}

	ucf_flags = filename_create_ucf_flags(req,
					      create_disposition,
					      create_options);

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(fname, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert_dirfsp(ctx,
					 conn,
					 fname,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
					NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_mode,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		smb_attr,				/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		private_flags,
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		&smb_action,				/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}

		if (!NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			reply_openerror(req, status);
			goto out;
		}

		fsp = fcb_or_dos_open(
			req,
			smb_fname,
			access_mask,
			create_options,
			private_flags);
		if (fsp == NULL) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				goto out;
			}
			reply_openerror(req, status);
			goto out;
		}


		smb_action = FILE_WAS_OPENED;
	}

	/* Setting the "size" field in vwv9 and vwv10 causes the file to be set to this size,
	   if the file is truncated or created. */
	if (((smb_action == FILE_WAS_CREATED) || (smb_action == FILE_WAS_OVERWRITTEN)) && allocation_size) {
		fsp->initial_allocation_size = smb_roundup(fsp->conn, allocation_size);
		if (vfs_allocate_file_space(fsp, fsp->initial_allocation_size) == -1) {
			close_file_free(req, &fsp, ERROR_CLOSE);
			reply_nterror(req, NT_STATUS_DISK_FULL);
			goto out;
		}
		retval = vfs_set_filelen(fsp, (off_t)allocation_size);
		if (retval < 0) {
			close_file_free(req, &fsp, ERROR_CLOSE);
			reply_nterror(req, NT_STATUS_DISK_FULL);
			goto out;
		}
		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			close_file_free(req, &fsp, ERROR_CLOSE);
			reply_nterror(req, status);
			goto out;
		}
	}

	fattr = fdos_mode(fsp);
	if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
		close_file_free(req, &fsp, ERROR_CLOSE);
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}
	mtime = convert_timespec_to_time_t(fsp->fsp_name->st.st_ex_mtime);

	/* If the caller set the extended oplock request bit
		and we granted one (by whatever means) - set the
		correct bit for extended oplock reply.
	*/

	if (ex_oplock_request && lp_fake_oplocks(SNUM(conn))) {
		smb_action |= EXTENDED_OPLOCK_GRANTED;
	}

	if(ex_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		smb_action |= EXTENDED_OPLOCK_GRANTED;
	}

	/* If the caller set the core oplock request bit
		and we granted one (by whatever means) - set the
		correct bit for core oplock reply.
	*/

	if (open_flags & EXTENDED_RESPONSE_REQUIRED) {
		reply_smb1_outbuf(req, 19, 0);
	} else {
		reply_smb1_outbuf(req, 15, 0);
	}

	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	if (core_oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if(core_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	SSVAL(req->outbuf,smb_vwv2,fsp->fnum);
	SSVAL(req->outbuf,smb_vwv3,fattr);
	if(lp_dos_filetime_resolution(SNUM(conn)) ) {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv4,mtime & ~1);
	} else {
		srv_put_dos_date3((char *)req->outbuf,smb_vwv4,mtime);
	}
	SIVAL(req->outbuf,smb_vwv6,(uint32_t)fsp->fsp_name->st.st_ex_size);
	SSVAL(req->outbuf,smb_vwv8,GET_OPENX_MODE(deny_mode));
	SSVAL(req->outbuf,smb_vwv11,smb_action);

	if (open_flags & EXTENDED_RESPONSE_REQUIRED) {
		SIVAL(req->outbuf, smb_vwv15, SEC_STD_ALL);
	}

 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBopenX);
	return;
}

/****************************************************************************
 Reply to a SMBulogoffX.
****************************************************************************/

static struct tevent_req *reply_ulogoffX_send(struct smb_request *smb1req,
				struct smbXsrv_session *session);
static void reply_ulogoffX_done(struct tevent_req *req);

void reply_ulogoffX(struct smb_request *smb1req)
{
	struct timeval now = timeval_current();
	struct smbXsrv_session *session = NULL;
	struct tevent_req *req;
	NTSTATUS status;

	/*
	 * Don't setup the profile charge here, take
	 * it in reply_ulogoffX_done(). Not strictly correct
	 * but better than the other SMB1 async
	 * code that double-charges at the moment.
	 */

	status = smb1srv_session_lookup(smb1req->xconn,
					smb1req->vuid,
					timeval_to_nttime(&now),
					&session);
	if (!NT_STATUS_IS_OK(status)) {
		/* Not going async, profile here. */
		START_PROFILE(SMBulogoffX);
		DBG_WARNING("ulogoff, vuser id %llu does not map to user.\n",
			 (unsigned long long)smb1req->vuid);

		smb1req->vuid = UID_FIELD_INVALID;
		reply_force_doserror(smb1req, ERRSRV, ERRbaduid);
		END_PROFILE(SMBulogoffX);
		return;
	}

	req = reply_ulogoffX_send(smb1req, session);
	if (req == NULL) {
		/* Not going async, profile here. */
		START_PROFILE(SMBulogoffX);
		reply_force_doserror(smb1req, ERRDOS, ERRnomem);
		END_PROFILE(SMBulogoffX);
		return;
	}

	/* We're async. This will complete later. */
	tevent_req_set_callback(req, reply_ulogoffX_done, smb1req);
	return;
}

struct reply_ulogoffX_state {
	struct tevent_queue *wait_queue;
	struct smbXsrv_session *session;
};

static void reply_ulogoffX_wait_done(struct tevent_req *subreq);

/****************************************************************************
 Async SMB1 ulogoffX.
 Note, on failure here we deallocate and return NULL to allow the caller to
 SMB1 return an error of ERRnomem immediately.
****************************************************************************/

static struct tevent_req *reply_ulogoffX_send(struct smb_request *smb1req,
					struct smbXsrv_session *session)
{
	struct tevent_req *req;
	struct reply_ulogoffX_state *state;
	struct tevent_req *subreq;
	files_struct *fsp;
	struct smbd_server_connection *sconn = session->client->sconn;
	uint64_t vuid = session->global->session_wire_id;

	req = tevent_req_create(smb1req, &state,
			struct reply_ulogoffX_state);
	if (req == NULL) {
		return NULL;
	}
	state->wait_queue = tevent_queue_create(state,
				"reply_ulogoffX_wait_queue");
	if (tevent_req_nomem(state->wait_queue, req)) {
		TALLOC_FREE(req);
		return NULL;
	}
	state->session = session;

	/*
	 * Make sure that no new request will be able to use this session.
	 * This ensures that once all outstanding fsp->aio_requests
	 * on this session are done, we are safe to close it.
	 */
	session->status = NT_STATUS_USER_SESSION_DELETED;

	for (fsp = sconn->files; fsp; fsp = fsp->next) {
		if (fsp->vuid != vuid) {
			continue;
		}
		/*
		 * Flag the file as close in progress.
		 * This will prevent any more IO being
		 * done on it.
		 */
		fsp->fsp_flags.closing = true;

		if (fsp->num_aio_requests > 0) {
			/*
			 * Now wait until all aio requests on this fsp are
			 * finished.
			 *
			 * We don't set a callback, as we just want to block the
			 * wait queue and the talloc_free() of fsp->aio_request
			 * will remove the item from the wait queue.
			 */
			subreq = tevent_queue_wait_send(fsp->aio_requests,
						sconn->ev_ctx,
						state->wait_queue);
			if (tevent_req_nomem(subreq, req)) {
				TALLOC_FREE(req);
				return NULL;
			}
		}
	}

	/*
	 * Now we add our own waiter to the end of the queue,
	 * this way we get notified when all pending requests are finished
	 * and reply to the outstanding SMB1 request.
	 */
	subreq = tevent_queue_wait_send(state,
				sconn->ev_ctx,
				state->wait_queue);
	if (tevent_req_nomem(subreq, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	/*
	 * We're really going async - move the SMB1 request from
	 * a talloc stackframe above us to the sconn talloc-context.
	 * We need this to stick around until the wait_done
	 * callback is invoked.
	 */
	smb1req = talloc_move(sconn, &smb1req);

	tevent_req_set_callback(subreq, reply_ulogoffX_wait_done, req);

	return req;
}

static void reply_ulogoffX_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);

	tevent_queue_wait_recv(subreq);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static NTSTATUS reply_ulogoffX_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static void reply_ulogoffX_done(struct tevent_req *req)
{
	struct smb_request *smb1req = tevent_req_callback_data(
		req, struct smb_request);
	struct reply_ulogoffX_state *state = tevent_req_data(req,
						struct reply_ulogoffX_state);
	struct smbXsrv_session *session = state->session;
	NTSTATUS status;

	/*
	 * Take the profile charge here. Not strictly
	 * correct but better than the other SMB1 async
	 * code that double-charges at the moment.
	 */
	START_PROFILE(SMBulogoffX);

	status = reply_ulogoffX_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb1req);
		END_PROFILE(SMBulogoffX);
		exit_server(__location__ ": reply_ulogoffX_recv failed");
		return;
	}

	status = smbXsrv_session_logoff(session);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb1req);
		END_PROFILE(SMBulogoffX);
		exit_server(__location__ ": smbXsrv_session_logoff failed");
		return;
	}

	TALLOC_FREE(session);

	reply_smb1_outbuf(smb1req, 2, 0);
	SSVAL(smb1req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(smb1req->outbuf, smb_vwv1, 0);    /* no andx offset */

	DBG_NOTICE("ulogoffX vuid=%llu\n",
		  (unsigned long long)smb1req->vuid);

	smb1req->vuid = UID_FIELD_INVALID;
	/*
	 * The following call is needed to push the
	 * reply data back out the socket after async
	 * return. Plus it frees smb1req.
	 */
	smb_request_done(smb1req);
	END_PROFILE(SMBulogoffX);
}

/****************************************************************************
 Reply to a mknew or a create.
****************************************************************************/

void reply_mknew(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	uint32_t fattr = 0;
	struct smb_file_time ft;
	struct files_struct *dirfsp = NULL;
	files_struct *fsp;
	int oplock_request = 0;
	NTSTATUS status;
	uint32_t access_mask = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
	uint32_t share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;
	uint32_t create_disposition;
	uint32_t create_options = 0;
	uint32_t ucf_flags;
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBcreate);
	init_smb_file_time(&ft);

        if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	fattr = SVAL(req->vwv+0, 0);
	oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);

	if (req->cmd == SMBmknew) {
		/* We should fail if file exists. */
		create_disposition = FILE_CREATE;
	} else {
		/* Create if file doesn't exist, truncate if it does. */
		create_disposition = FILE_OVERWRITE_IF;
	}

	/* mtime. */
	ft.mtime = time_t_to_full_timespec(srv_make_unix_date3(req->vwv+1));

	srvstr_get_path_req(ctx, req, &fname, (const char *)req->buf + 1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	ucf_flags = filename_create_ucf_flags(req,
					      create_disposition,
					      create_options);
	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(fname, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert_dirfsp(ctx,
					 conn,
					 fname,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
					NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	if (fattr & FILE_ATTRIBUTE_VOLUME) {
		DEBUG(0,("Attempt to create file (%s) with volid set - "
			 "please report this\n",
			 smb_fname_str_dbg(smb_fname)));
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_mode,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		fattr,					/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				goto out;
			}
		}
		reply_openerror(req, status);
		goto out;
	}

	ft.atime = smb_fname->st.st_ex_atime; /* atime. */
	status = smb_set_file_time(conn, fsp, smb_fname, &ft, true);
	if (!NT_STATUS_IS_OK(status)) {
		END_PROFILE(SMBcreate);
		goto out;
	}

	reply_smb1_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf,smb_flg,
				CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf,smb_flg,
				CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	DEBUG(2, ("reply_mknew: file %s\n", smb_fname_str_dbg(smb_fname)));
	DEBUG(3, ("reply_mknew %s fd=%d dmode=0x%x\n",
		  smb_fname_str_dbg(smb_fname), fsp_get_io_fd(fsp),
		  (unsigned int)fattr));

 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBcreate);
	return;
}

/****************************************************************************
 Reply to a create temporary file.
****************************************************************************/

void reply_ctemp(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_fname = NULL;
	char *wire_name = NULL;
	char *fname = NULL;
	uint32_t fattr;
	struct files_struct *dirfsp = NULL;
	files_struct *fsp;
	int oplock_request;
	char *s;
	NTSTATUS status;
	int i;
	uint32_t ucf_flags;
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBctemp);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	fattr = SVAL(req->vwv+0, 0);
	oplock_request = CORE_OPLOCK_REQUEST(req->inbuf);

	srvstr_get_path_req(ctx, req, &wire_name, (const char *)req->buf+1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	for (i = 0; i < 10; i++) {
		char rand_str[6];

		generate_random_str_list_buf(rand_str,
					     sizeof(rand_str),
					     "0123456789");

		if (*wire_name) {
			fname = talloc_asprintf(ctx,
						"%s/TMP%s",
						wire_name,
						rand_str);
		} else {
			fname = talloc_asprintf(ctx, "TMP%s", rand_str);
		}

		if (!fname) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

		ucf_flags = filename_create_ucf_flags(req, FILE_CREATE, 0);
		if (ucf_flags & UCF_GMT_PATHNAME) {
			extract_snapshot_token(fname, &twrp);
		}
		status = smb1_strip_dfs_path(ctx, &ucf_flags, &fname);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}

		status = filename_convert_dirfsp(ctx,
						 conn,
						 fname,
						 ucf_flags,
						 twrp,
						 &dirfsp,
						 &smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
				reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
				goto out;
			}
			reply_nterror(req, status);
			goto out;
		}

		/* Create the file. */
		status = SMB_VFS_CREATE_FILE(
			conn,					/* conn */
			req,					/* req */
			dirfsp,					/* dirfsp */
			smb_fname,				/* fname */
			FILE_GENERIC_READ | FILE_GENERIC_WRITE, /* access_mask */
			FILE_SHARE_READ | FILE_SHARE_WRITE,	/* share_access */
			FILE_CREATE,				/* create_disposition*/
			0,					/* create_options */
			fattr,					/* file_attributes */
			oplock_request,				/* oplock_request */
			NULL,					/* lease */
			0,					/* allocation_size */
			0,					/* private_flags */
			NULL,					/* sd */
			NULL,					/* ea_list */
			&fsp,					/* result */
			NULL,					/* pinfo */
			NULL, NULL);				/* create context */

		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			TALLOC_FREE(fname);
			TALLOC_FREE(dirfsp);
			TALLOC_FREE(smb_fname);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			if (open_was_deferred(req->xconn, req->mid)) {
				/* We have re-scheduled this call. */
				goto out;
			}
			if (NT_STATUS_EQUAL(
				    status, NT_STATUS_SHARING_VIOLATION)) {
				bool ok = defer_smb1_sharing_violation(req);
				if (ok) {
					goto out;
				}
			}
			reply_openerror(req, status);
			goto out;
		}

		break;
	}

	if (i == 10) {
		/* Collision after 10 times... */
		reply_nterror(req, status);
		goto out;
	}

	reply_smb1_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);

	/* the returned filename is relative to the directory */
	s = strrchr_m(fsp->fsp_name->base_name, '/');
	if (!s) {
		s = fsp->fsp_name->base_name;
	} else {
		s++;
	}

#if 0
	/* Tested vs W2K3 - this doesn't seem to be here - null terminated filename is the only
	   thing in the byte section. JRA */
	SSVALS(p, 0, -1); /* what is this? not in spec */
#endif
	if (message_push_string(&req->outbuf, s, STR_ASCII|STR_TERMINATE)
	    == -1) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		goto out;
	}

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	if (EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		SCVAL(req->outbuf, smb_flg,
		      CVAL(req->outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}

	DEBUG(2, ("reply_ctemp: created temp file %s\n", fsp_str_dbg(fsp)));
	DEBUG(3, ("reply_ctemp %s fd=%d umode=0%o\n", fsp_str_dbg(fsp),
		    fsp_get_io_fd(fsp), (unsigned int)smb_fname->st.st_ex_mode));
 out:
	TALLOC_FREE(smb_fname);
	TALLOC_FREE(wire_name);
	END_PROFILE(SMBctemp);
	return;
}

/****************************************************************************
 Reply to a unlink
****************************************************************************/

void reply_unlink(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *name = NULL;
	struct files_struct *dirfsp = NULL;
	struct smb_filename *smb_fname = NULL;
	uint32_t dirtype;
	NTSTATUS status;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBunlink);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	dirtype = SVAL(req->vwv+0, 0);

	srvstr_get_path_req(ctx, req, &name, (const char *)req->buf + 1,
				  STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(name, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &name);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}
	status = filename_convert_dirfsp(ctx,
					 conn,
					 name,
					 ucf_flags | UCF_LCOMP_LNK_OK,
					 twrp,
					 &dirfsp,
					 &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	DEBUG(3,("reply_unlink : %s\n", smb_fname_str_dbg(smb_fname)));

	status = unlink_internals(conn, req, dirtype, dirfsp, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				goto out;
			}
		}
		reply_nterror(req, status);
		goto out;
	}

	reply_smb1_outbuf(req, 0, 0);
 out:
	TALLOC_FREE(smb_fname);
	END_PROFILE(SMBunlink);
	return;
}

/****************************************************************************
 Fail for readbraw.
****************************************************************************/

static void fail_readraw(void)
{
	const char *errstr = talloc_asprintf(talloc_tos(),
			"FAIL ! reply_readbraw: socket write fail (%s)",
			strerror(errno));
	if (!errstr) {
		errstr = "";
	}
	exit_server_cleanly(errstr);
}

/****************************************************************************
 Return a readbraw error (4 bytes of zero).
****************************************************************************/

static void reply_readbraw_error(struct smbXsrv_connection *xconn)
{
	char header[4];

	SIVAL(header,0,0);

	smbd_lock_socket(xconn);
	if (write_data(xconn->transport.sock,header,4) != 4) {
		int saved_errno = errno;
		/*
		 * Try and give an error message saying what
		 * client failed.
		 */
		DEBUG(0, ("write_data failed for client %s. "
			  "Error %s\n",
			  smbXsrv_connection_dbg(xconn),
			  strerror(saved_errno)));
		errno = saved_errno;

		fail_readraw();
	}
	smbd_unlock_socket(xconn);
}

/*******************************************************************
 Ensure we don't use sendfile if server smb signing is active.
********************************************************************/

static bool lp_use_sendfile(struct smbXsrv_connection *xconn,
			    int snum,
			    struct smb1_signing_state *signing_state)
{
	bool sign_active = false;

	/* Using sendfile blows the brains out of any DOS or Win9x TCP stack... JRA. */
	if (xconn->protocol < PROTOCOL_NT1) {
		return false;
	}
	if (signing_state) {
		sign_active = smb1_signing_is_active(signing_state);
	}
	return (lp__use_sendfile(snum) &&
			(get_remote_arch() != RA_WIN95) &&
			!sign_active);
}
/****************************************************************************
 Use sendfile in readbraw.
****************************************************************************/

static void send_file_readbraw(connection_struct *conn,
			       struct smb_request *req,
			       files_struct *fsp,
			       off_t startpos,
			       size_t nread,
			       ssize_t mincount)
{
	struct smbXsrv_connection *xconn = req->xconn;
	char *outbuf = NULL;
	ssize_t ret=0;

	/*
	 * We can only use sendfile on a non-chained packet
	 * but we can use on a non-oplocked file. tridge proved this
	 * on a train in Germany :-). JRA.
	 * reply_readbraw has already checked the length.
	 */

	if ( !req_is_in_chain(req) &&
	     (nread > 0) &&
	     !fsp_is_alternate_stream(fsp) &&
	     lp_use_sendfile(xconn, SNUM(conn), xconn->smb1.signing_state) ) {
		ssize_t sendfile_read = -1;
		char header[4];
		DATA_BLOB header_blob;

		_smb_setlen(header,nread);
		header_blob = data_blob_const(header, 4);

		sendfile_read = SMB_VFS_SENDFILE(xconn->transport.sock, fsp,
						 &header_blob, startpos,
						 nread);
		if (sendfile_read == -1) {
			/* Returning ENOSYS means no data at all was sent.
			 * Do this as a normal read. */
			if (errno == ENOSYS) {
				goto normal_readbraw;
			}

			/*
			 * Special hack for broken Linux with no working sendfile. If we
			 * return EINTR we sent the header but not the rest of the data.
			 * Fake this up by doing read/write calls.
			 */
			if (errno == EINTR) {
				/* Ensure we don't do this again. */
				set_use_sendfile(SNUM(conn), False);
				DEBUG(0,("send_file_readbraw: sendfile not available. Faking..\n"));

				if (fake_sendfile(xconn, fsp, startpos, nread) == -1) {
					DEBUG(0,("send_file_readbraw: "
						 "fake_sendfile failed for "
						 "file %s (%s).\n",
						 fsp_str_dbg(fsp),
						 strerror(errno)));
					exit_server_cleanly("send_file_readbraw fake_sendfile failed");
				}
				return;
			}

			DEBUG(0,("send_file_readbraw: sendfile failed for "
				 "file %s (%s). Terminating\n",
				 fsp_str_dbg(fsp), strerror(errno)));
			exit_server_cleanly("send_file_readbraw sendfile failed");
		} else if (sendfile_read == 0) {
			/*
			 * Some sendfile implementations return 0 to indicate
			 * that there was a short read, but nothing was
			 * actually written to the socket.  In this case,
			 * fallback to the normal read path so the header gets
			 * the correct byte count.
			 */
			DEBUG(3, ("send_file_readbraw: sendfile sent zero "
				  "bytes falling back to the normal read: "
				  "%s\n", fsp_str_dbg(fsp)));
			goto normal_readbraw;
		}

		/* Deal with possible short send. */
		if (sendfile_read != 4+nread) {
			ret = sendfile_short_send(xconn, fsp,
						  sendfile_read, 4, nread);
			if (ret == -1) {
				fail_readraw();
			}
		}
		return;
	}

normal_readbraw:

	outbuf = talloc_array(NULL, char, nread+4);
	if (!outbuf) {
		DEBUG(0,("send_file_readbraw: talloc_array failed for size %u.\n",
			(unsigned)(nread+4)));
		reply_readbraw_error(xconn);
		return;
	}

	if (nread > 0) {
		ret = read_file(fsp,outbuf+4,startpos,nread);
#if 0 /* mincount appears to be ignored in a W2K server. JRA. */
		if (ret < mincount)
			ret = 0;
#else
		if (ret < nread)
			ret = 0;
#endif
	}

	_smb_setlen(outbuf,ret);
	if (write_data(xconn->transport.sock, outbuf, 4+ret) != 4+ret) {
		int saved_errno = errno;
		/*
		 * Try and give an error message saying what
		 * client failed.
		 */
		DEBUG(0, ("write_data failed for client %s. Error %s\n",
			  smbXsrv_connection_dbg(xconn),
			  strerror(saved_errno)));
		errno = saved_errno;

		fail_readraw();
	}

	TALLOC_FREE(outbuf);
}

/****************************************************************************
 Reply to a readbraw (core+ protocol).
****************************************************************************/

void reply_readbraw(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smbXsrv_connection *xconn = req->xconn;
	ssize_t maxcount,mincount;
	size_t nread = 0;
	off_t startpos;
	files_struct *fsp;
	struct lock_struct lock;
	off_t size = 0;
	NTSTATUS status;

	START_PROFILE(SMBreadbraw);

	if (smb1_srv_is_signing_active(xconn) || req->encrypted) {
		exit_server_cleanly("reply_readbraw: SMB signing/sealing is active - "
			"raw reads/writes are disallowed.");
	}

	if (req->wct < 8) {
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	if (xconn->smb1.echo_handler.trusted_fde) {
		DEBUG(2,("SMBreadbraw rejected with NOT_SUPPORTED because of "
			 "'async smb echo handler = yes'\n"));
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	/*
	 * Special check if an oplock break has been issued
	 * and the readraw request croses on the wire, we must
	 * return a zero length response here.
	 */

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	/*
	 * We have to do a check_fsp by hand here, as
	 * we must always return 4 zero bytes on error,
	 * not a NTSTATUS.
	 */

	if (fsp == NULL ||
	    conn == NULL ||
	    conn != fsp->conn ||
	    req->vuid != fsp->vuid ||
	    fsp->fsp_flags.is_directory ||
	    fsp_get_io_fd(fsp) == -1)
	{
		/*
		 * fsp could be NULL here so use the value from the packet. JRA.
		 */
		DEBUG(3,("reply_readbraw: fnum %d not valid "
			"- cache prime?\n",
			(int)SVAL(req->vwv+0, 0)));
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	/* Do a "by hand" version of CHECK_READ. */
	if (!(fsp->fsp_flags.can_read ||
			((req->flags2 & FLAGS2_READ_PERMIT_EXECUTE) &&
				(fsp->access_mask & FILE_EXECUTE)))) {
		DEBUG(3,("reply_readbraw: fnum %d not readable.\n",
				(int)SVAL(req->vwv+0, 0)));
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	startpos = IVAL_TO_SMB_OFF_T(req->vwv+1, 0);
	if(req->wct == 10) {
		/*
		 * This is a large offset (64 bit) read.
		 */

		startpos |= (((off_t)IVAL(req->vwv+8, 0)) << 32);

		if(startpos < 0) {
			DEBUG(0,("reply_readbraw: negative 64 bit "
				"readraw offset (%.0f) !\n",
				(double)startpos ));
			reply_readbraw_error(xconn);
			END_PROFILE(SMBreadbraw);
			return;
		}
	}

	maxcount = (SVAL(req->vwv+3, 0) & 0xFFFF);
	mincount = (SVAL(req->vwv+4, 0) & 0xFFFF);

	/* ensure we don't overrun the packet size */
	maxcount = MIN(65535,maxcount);

	init_strict_lock_struct(fsp,
			(uint64_t)req->smbpid,
			(uint64_t)startpos,
			(uint64_t)maxcount,
			READ_LOCK,
			&lock);

	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &lock)) {
		reply_readbraw_error(xconn);
		END_PROFILE(SMBreadbraw);
		return;
	}

	status = vfs_stat_fsp(fsp);
	if (NT_STATUS_IS_OK(status)) {
		size = fsp->fsp_name->st.st_ex_size;
	}

	if (startpos >= size) {
		nread = 0;
	} else {
		nread = MIN(maxcount,(size - startpos));
	}

#if 0 /* mincount appears to be ignored in a W2K server. JRA. */
	if (nread < mincount)
		nread = 0;
#endif

	DEBUG( 3, ( "reply_readbraw: %s start=%.0f max=%lu "
		"min=%lu nread=%lu\n",
		fsp_fnum_dbg(fsp), (double)startpos,
		(unsigned long)maxcount,
		(unsigned long)mincount,
		(unsigned long)nread ) );

	send_file_readbraw(conn, req, fsp, startpos, nread, mincount);

	DEBUG(5,("reply_readbraw finished\n"));

	END_PROFILE(SMBreadbraw);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Reply to a lockread (core+ protocol).
****************************************************************************/

static void reply_lockread_locked(struct tevent_req *subreq);

void reply_lockread(struct smb_request *req)
{
	struct tevent_req *subreq = NULL;
	connection_struct *conn = req->conn;
	files_struct *fsp;
	struct smbd_lock_element *lck = NULL;

	START_PROFILE(SMBlockread);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlockread);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBlockread);
		return;
	}

	if (!CHECK_READ(fsp,req)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBlockread);
		return;
	}

	lck = talloc(req, struct smbd_lock_element);
	if (lck == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBlockread);
		return;
	}

	/*
	 * NB. Discovered by Menny Hamburger at Mainsoft. This is a core+
	 * protocol request that predates the read/write lock concept.
	 * Thus instead of asking for a read lock here we need to ask
	 * for a write lock. JRA.
	 * Note that the requested lock size is unaffected by max_send.
	 */

	*lck = (struct smbd_lock_element) {
		.req_guid = smbd_request_guid(req, 0),
		.smblctx = req->smbpid,
		.brltype = WRITE_LOCK,
		.lock_flav = WINDOWS_LOCK,
		.count = SVAL(req->vwv+1, 0),
		.offset = IVAL_TO_SMB_OFF_T(req->vwv+2, 0),
	};

	subreq = smbd_smb1_do_locks_send(
		fsp,
		req->sconn->ev_ctx,
		&req,
		fsp,
		0,
		false,		/* large_offset */
		1,
		lck);
	if (subreq == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBlockread);
		return;
	}
	tevent_req_set_callback(subreq, reply_lockread_locked, NULL);
	END_PROFILE(SMBlockread);
}

static void reply_lockread_locked(struct tevent_req *subreq)
{
	struct smb_request *req = NULL;
	ssize_t nread = -1;
	char *data = NULL;
	NTSTATUS status;
	bool ok;
	off_t startpos;
	size_t numtoread, maxtoread;
	struct files_struct *fsp = NULL;
	char *p = NULL;

	START_PROFILE(SMBlockread);

	ok = smbd_smb1_do_locks_extract_smbreq(subreq, talloc_tos(), &req);
	SMB_ASSERT(ok);

	status = smbd_smb1_do_locks_recv(subreq);
	TALLOC_FREE(subreq);

	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto send;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));
	if (fsp == NULL) {
		reply_nterror(req, NT_STATUS_INTERNAL_ERROR);
		goto send;
	}

	numtoread = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);

	/*
	 * However the requested READ size IS affected by max_send. Insanity.... JRA.
	 */
	maxtoread = req->xconn->smb1.sessions.max_send - (MIN_SMB_SIZE + 5*2 + 3);

	if (numtoread > maxtoread) {
		DBG_WARNING("requested read size (%zu) is greater than "
			    "maximum allowed (%zu/%d). "
			    "Returning short read of maximum allowed for "
			    "compatibility with Windows 2000.\n",
			    numtoread,
			    maxtoread,
			    req->xconn->smb1.sessions.max_send);
		numtoread = maxtoread;
	}

	reply_smb1_outbuf(req, 5, numtoread + 3);

	data = smb_buf(req->outbuf) + 3;

	nread = read_file(fsp,data,startpos,numtoread);

	if (nread < 0) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		goto send;
	}

	srv_smb1_set_message((char *)req->outbuf, 5, nread+3, False);

	SSVAL(req->outbuf,smb_vwv0,nread);
	SSVAL(req->outbuf,smb_vwv5,nread+3);
	p = smb_buf(req->outbuf);
	SCVAL(p,0,0); /* pad byte. */
	SSVAL(p,1,nread);

	DEBUG(3,("lockread %s num=%d nread=%d\n",
		 fsp_fnum_dbg(fsp), (int)numtoread, (int)nread));

send:
	ok = smb1_srv_send(req->xconn,
			   (char *)req->outbuf,
			   true,
			   req->seqnum + 1,
			   IS_CONN_ENCRYPTED(req->conn));
	if (!ok) {
		exit_server_cleanly("reply_lock_done: smb1_srv_send failed.");
	}
	TALLOC_FREE(req);
	END_PROFILE(SMBlockread);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a read.
****************************************************************************/

void reply_read(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	size_t numtoread;
	size_t maxtoread;
	ssize_t nread = 0;
	char *data;
	off_t startpos;
	files_struct *fsp;
	struct lock_struct lock;
	struct smbXsrv_connection *xconn = req->xconn;

	START_PROFILE(SMBread);

	if (req->wct < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBread);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBread);
		return;
	}

	if (!CHECK_READ(fsp,req)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBread);
		return;
	}

	numtoread = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);

	/*
	 * The requested read size cannot be greater than max_send. JRA.
	 */
	maxtoread = xconn->smb1.sessions.max_send - (MIN_SMB_SIZE + 5*2 + 3);

	if (numtoread > maxtoread) {
		DEBUG(0,("reply_read: requested read size (%u) is greater than maximum allowed (%u/%u). \
Returning short read of maximum allowed for compatibility with Windows 2000.\n",
			(unsigned int)numtoread, (unsigned int)maxtoread,
			(unsigned int)xconn->smb1.sessions.max_send));
		numtoread = maxtoread;
	}

	reply_smb1_outbuf(req, 5, numtoread+3);

	data = smb_buf(req->outbuf) + 3;

	init_strict_lock_struct(fsp,
			(uint64_t)req->smbpid,
			(uint64_t)startpos,
			(uint64_t)numtoread,
			READ_LOCK,
			&lock);

	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &lock)) {
		reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
		END_PROFILE(SMBread);
		return;
	}

	if (numtoread > 0)
		nread = read_file(fsp,data,startpos,numtoread);

	if (nread < 0) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		goto out;
	}

	srv_smb1_set_message((char *)req->outbuf, 5, nread+3, False);

	SSVAL(req->outbuf,smb_vwv0,nread);
	SSVAL(req->outbuf,smb_vwv5,nread+3);
	SCVAL(smb_buf(req->outbuf),0,1);
	SSVAL(smb_buf(req->outbuf),1,nread);

	DEBUG(3, ("read %s num=%d nread=%d\n",
		  fsp_fnum_dbg(fsp), (int)numtoread, (int)nread));

out:
	END_PROFILE(SMBread);
	return;
}

/****************************************************************************
 Setup readX header.
****************************************************************************/

size_t setup_readX_header(char *outbuf, size_t smb_maxcnt)
{
	size_t outsize;

	outsize = srv_smb1_set_message(outbuf,12,smb_maxcnt + 1 /* padding byte */,
				  False);

	memset(outbuf+smb_vwv0,'\0',24); /* valgrind init. */

	SCVAL(outbuf,smb_vwv0,0xFF);
	SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be -1. */
	SSVAL(outbuf,smb_vwv5,smb_maxcnt);
	SSVAL(outbuf,smb_vwv6,
	      (smb_wct - 4)	/* offset from smb header to wct */
	      + 1 		/* the wct field */
	      + 12 * sizeof(uint16_t) /* vwv */
	      + 2		/* the buflen field */
	      + 1);		/* padding byte */
	SSVAL(outbuf,smb_vwv7,(smb_maxcnt >> 16));
	SCVAL(smb_buf(outbuf), 0, 0); /* padding byte */
	/* Reset the outgoing length, set_message truncates at 0x1FFFF. */
	_smb_setlen_large(outbuf,
			  smb_size + 12*2 + smb_maxcnt - 4 + 1 /* pad */);
	return outsize;
}

/****************************************************************************
 Reply to a read and X - possibly using sendfile.
****************************************************************************/

static void send_file_readX(connection_struct *conn, struct smb_request *req,
			    files_struct *fsp, off_t startpos,
			    size_t smb_maxcnt)
{
	struct smbXsrv_connection *xconn = req->xconn;
	ssize_t nread = -1;
	struct lock_struct lock;
	int saved_errno = 0;
	NTSTATUS status;

	init_strict_lock_struct(fsp,
			(uint64_t)req->smbpid,
			(uint64_t)startpos,
			(uint64_t)smb_maxcnt,
			READ_LOCK,
			&lock);

	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &lock)) {
		reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
		return;
	}

	/*
	 * We can only use sendfile on a non-chained packet
	 * but we can use on a non-oplocked file. tridge proved this
	 * on a train in Germany :-). JRA.
	 */

	if (!req_is_in_chain(req) &&
	    !req->encrypted &&
	    !fsp_is_alternate_stream(fsp) &&
	    lp_use_sendfile(xconn, SNUM(conn), xconn->smb1.signing_state) ) {
		uint8_t headerbuf[smb_size + 12 * 2 + 1 /* padding byte */];
		DATA_BLOB header;

		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}

		if (!S_ISREG(fsp->fsp_name->st.st_ex_mode) ||
		    (startpos > fsp->fsp_name->st.st_ex_size) ||
		    (smb_maxcnt > (fsp->fsp_name->st.st_ex_size - startpos))) {
			/*
			 * We already know that we would do a short read, so don't
			 * try the sendfile() path.
			 */
			goto nosendfile_read;
		}

		/*
		 * Set up the packet header before send. We
		 * assume here the sendfile will work (get the
		 * correct amount of data).
		 */

		header = data_blob_const(headerbuf, sizeof(headerbuf));

		construct_smb1_reply_common_req(req, (char *)headerbuf);
		setup_readX_header((char *)headerbuf, smb_maxcnt);

		nread = SMB_VFS_SENDFILE(xconn->transport.sock, fsp, &header,
					 startpos, smb_maxcnt);
		if (nread == -1) {
			saved_errno = errno;

			/* Returning ENOSYS means no data at all was sent.
			   Do this as a normal read. */
			if (errno == ENOSYS) {
				goto normal_read;
			}

			/*
			 * Special hack for broken Linux with no working sendfile. If we
			 * return EINTR we sent the header but not the rest of the data.
			 * Fake this up by doing read/write calls.
			 */

			if (errno == EINTR) {
				/* Ensure we don't do this again. */
				set_use_sendfile(SNUM(conn), False);
				DEBUG(0,("send_file_readX: sendfile not available. Faking..\n"));
				nread = fake_sendfile(xconn, fsp, startpos,
						      smb_maxcnt);
				if (nread == -1) {
					saved_errno = errno;
					DEBUG(0,("send_file_readX: "
						 "fake_sendfile failed for "
						 "file %s (%s) for client %s. "
						 "Terminating\n",
						 fsp_str_dbg(fsp),
						 smbXsrv_connection_dbg(xconn),
						 strerror(saved_errno)));
					errno = saved_errno;
					exit_server_cleanly("send_file_readX: fake_sendfile failed");
				}
				DEBUG(3, ("send_file_readX: fake_sendfile %s max=%d nread=%d\n",
					  fsp_fnum_dbg(fsp), (int)smb_maxcnt, (int)nread));
				/* No outbuf here means successful sendfile. */
				goto out;
			}

			DEBUG(0,("send_file_readX: sendfile failed for file "
				 "%s (%s). Terminating\n", fsp_str_dbg(fsp),
				 strerror(errno)));
			exit_server_cleanly("send_file_readX sendfile failed");
		} else if (nread == 0) {
			/*
			 * Some sendfile implementations return 0 to indicate
			 * that there was a short read, but nothing was
			 * actually written to the socket.  In this case,
			 * fallback to the normal read path so the header gets
			 * the correct byte count.
			 */
			DEBUG(3, ("send_file_readX: sendfile sent zero bytes "
				  "falling back to the normal read: %s\n",
				  fsp_str_dbg(fsp)));
			goto normal_read;
		}

		DEBUG(3, ("send_file_readX: sendfile %s max=%d nread=%d\n",
			  fsp_fnum_dbg(fsp), (int)smb_maxcnt, (int)nread));

		/* Deal with possible short send. */
		if (nread != smb_maxcnt + sizeof(headerbuf)) {
			ssize_t ret;

			ret = sendfile_short_send(xconn, fsp, nread,
						  sizeof(headerbuf), smb_maxcnt);
			if (ret == -1) {
				const char *r;
				r = "send_file_readX: sendfile_short_send failed";
				DEBUG(0,("%s for file %s (%s).\n",
					 r, fsp_str_dbg(fsp), strerror(errno)));
				exit_server_cleanly(r);
			}
		}
		/* No outbuf here means successful sendfile. */
		goto out;
	}

normal_read:

	if ((smb_maxcnt & 0xFF0000) > 0x10000) {
		uint8_t headerbuf[smb_size + 2*12 + 1 /* padding byte */];
		ssize_t ret;

		if (!S_ISREG(fsp->fsp_name->st.st_ex_mode) ||
		    (startpos > fsp->fsp_name->st.st_ex_size) ||
		    (smb_maxcnt > (fsp->fsp_name->st.st_ex_size - startpos))) {
			/*
			 * We already know that we would do a short
			 * read, so don't try the sendfile() path.
			 */
			goto nosendfile_read;
		}

		construct_smb1_reply_common_req(req, (char *)headerbuf);
		setup_readX_header((char *)headerbuf, smb_maxcnt);

		/* Send out the header. */
		ret = write_data(xconn->transport.sock, (char *)headerbuf,
				 sizeof(headerbuf));
		if (ret != sizeof(headerbuf)) {
			saved_errno = errno;
			/*
			 * Try and give an error message saying what
			 * client failed.
			 */
			DEBUG(0,("send_file_readX: write_data failed for file "
				 "%s (%s) for client %s. Terminating\n",
				 fsp_str_dbg(fsp),
				 smbXsrv_connection_dbg(xconn),
				 strerror(saved_errno)));
			errno = saved_errno;
			exit_server_cleanly("send_file_readX sendfile failed");
		}
		nread = fake_sendfile(xconn, fsp, startpos, smb_maxcnt);
		if (nread == -1) {
			saved_errno = errno;
			DEBUG(0,("send_file_readX: fake_sendfile failed for file "
				 "%s (%s) for client %s. Terminating\n",
				 fsp_str_dbg(fsp),
				 smbXsrv_connection_dbg(xconn),
				 strerror(saved_errno)));
			errno = saved_errno;
			exit_server_cleanly("send_file_readX: fake_sendfile failed");
		}
		goto out;
	}

nosendfile_read:

	reply_smb1_outbuf(req, 12, smb_maxcnt + 1 /* padding byte */);
	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	nread = read_file(fsp, smb_buf(req->outbuf) + 1 /* padding byte */,
			  startpos, smb_maxcnt);
	saved_errno = errno;

	if (nread < 0) {
		reply_nterror(req, map_nt_error_from_unix(saved_errno));
		return;
	}

	setup_readX_header((char *)req->outbuf, nread);

	DEBUG(3, ("send_file_readX %s max=%d nread=%d\n",
		  fsp_fnum_dbg(fsp), (int)smb_maxcnt, (int)nread));
	return;

out:
	TALLOC_FREE(req->outbuf);
	return;
}

/****************************************************************************
 Work out how much space we have for a read return.
****************************************************************************/

static size_t calc_max_read_pdu(const struct smb_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;

	if (xconn->protocol < PROTOCOL_NT1) {
		return xconn->smb1.sessions.max_send;
	}

	if (!lp_large_readwrite()) {
		return xconn->smb1.sessions.max_send;
	}

	if (req_is_in_chain(req)) {
		return xconn->smb1.sessions.max_send;
	}

	if (req->encrypted) {
		/*
		 * Don't take encrypted traffic up to the
		 * limit. There are padding considerations
		 * that make that tricky.
		 */
		return xconn->smb1.sessions.max_send;
	}

	if (smb1_srv_is_signing_active(xconn)) {
		return 0x1FFFF;
	}

	if (!lp_smb1_unix_extensions()) {
		return 0x1FFFF;
	}

	/*
	 * We can do ultra-large POSIX reads.
	 */
	return 0xFFFFFF;
}

/****************************************************************************
 Calculate how big a read can be. Copes with all clients. It's always
 safe to return a short read - Windows does this.
****************************************************************************/

static size_t calc_read_size(const struct smb_request *req,
			     size_t upper_size,
			     size_t lower_size)
{
	struct smbXsrv_connection *xconn = req->xconn;
	size_t max_pdu = calc_max_read_pdu(req);
	size_t total_size = 0;
	size_t hdr_len = MIN_SMB_SIZE + VWV(12);
	size_t max_len = max_pdu - hdr_len - 1 /* padding byte */;

	/*
	 * Windows explicitly ignores upper size of 0xFFFF.
	 * See [MS-SMB].pdf <26> Section 2.2.4.2.1:
	 * We must do the same as these will never fit even in
	 * an extended size NetBIOS packet.
	 */
	if (upper_size == 0xFFFF) {
		upper_size = 0;
	}

	if (xconn->protocol < PROTOCOL_NT1) {
		upper_size = 0;
	}

	total_size = ((upper_size<<16) | lower_size);

	/*
	 * LARGE_READX test shows it's always safe to return
	 * a short read. Windows does so.
	 */
	return MIN(total_size, max_len);
}

/****************************************************************************
 Reply to a read and X.
****************************************************************************/

void reply_read_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	off_t startpos;
	size_t smb_maxcnt;
	size_t upper_size;
	bool big_readX = False;
#if 0
	size_t smb_mincnt = SVAL(req->vwv+6, 0);
#endif

	START_PROFILE(SMBreadX);

	if ((req->wct != 10) && (req->wct != 12)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+2, 0));
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+3, 0);
	smb_maxcnt = SVAL(req->vwv+5, 0);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		reply_pipe_read_and_X(req);
		END_PROFILE(SMBreadX);
		return;
	}

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBreadX);
		return;
	}

	if (!CHECK_READ(fsp,req)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBreadX);
		return;
	}

	upper_size = SVAL(req->vwv+7, 0);
	smb_maxcnt = calc_read_size(req, upper_size, smb_maxcnt);
	if (smb_maxcnt > (0x1FFFF - (MIN_SMB_SIZE + VWV(12)))) {
		/*
		 * This is a heuristic to avoid keeping large
		 * outgoing buffers around over long-lived aio
		 * requests.
		 */
		big_readX = True;
	}

	if (req->wct == 12) {
		/*
		 * This is a large offset (64 bit) read.
		 */
		startpos |= (((off_t)IVAL(req->vwv+10, 0)) << 32);

	}

	if (!big_readX) {
		NTSTATUS status = schedule_aio_read_and_X(conn,
					req,
					fsp,
					startpos,
					smb_maxcnt);
		if (NT_STATUS_IS_OK(status)) {
			/* Read scheduled - we're done. */
			goto out;
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
			/* Real error - report to client. */
			END_PROFILE(SMBreadX);
			reply_nterror(req, status);
			return;
		}
		/* NT_STATUS_RETRY - fall back to sync read. */
	}

	smbd_lock_socket(req->xconn);
	send_file_readX(conn, req, fsp,	startpos, smb_maxcnt);
	smbd_unlock_socket(req->xconn);

 out:
	END_PROFILE(SMBreadX);
	return;
}

/****************************************************************************
 Error replies to writebraw must have smb_wct == 1. Fix this up.
****************************************************************************/

void error_to_writebrawerr(struct smb_request *req)
{
	uint8_t *old_outbuf = req->outbuf;

	reply_smb1_outbuf(req, 1, 0);

	memmove(req->outbuf, old_outbuf, smb_size);
	TALLOC_FREE(old_outbuf);
}

/****************************************************************************
 Read 4 bytes of a smb packet and return the smb length of the packet.
 Store the result in the buffer. This version of the function will
 never return a session keepalive (length of zero).
 Timeout is in milliseconds.
****************************************************************************/

static NTSTATUS read_smb_length(int fd, char *inbuf, unsigned int timeout,
				size_t *len)
{
	uint8_t msgtype = NBSSkeepalive;

	while (msgtype == NBSSkeepalive) {
		NTSTATUS status;

		status = read_smb_length_return_keepalive(fd, inbuf, timeout,
							  len);
		if (!NT_STATUS_IS_OK(status)) {
			char addr[INET6_ADDRSTRLEN];
			/* Try and give an error message
			 * saying what client failed. */
			DEBUG(0, ("read_smb_length_return_keepalive failed for "
				  "client %s read error = %s.\n",
				  get_peer_addr(fd,addr,sizeof(addr)),
				  nt_errstr(status)));
			return status;
		}

		msgtype = CVAL(inbuf, 0);
	}

	DEBUG(10,("read_smb_length: got smb length of %lu\n",
		  (unsigned long)len));

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a writebraw (core+ or LANMAN1.0 protocol).
****************************************************************************/

void reply_writebraw(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smbXsrv_connection *xconn = req->xconn;
	char *buf = NULL;
	ssize_t nwritten=0;
	ssize_t total_written=0;
	size_t numtowrite=0;
	size_t tcount;
	off_t startpos;
	const char *data=NULL;
	bool write_through;
	files_struct *fsp;
	struct lock_struct lock;
	NTSTATUS status;

	START_PROFILE(SMBwritebraw);

	/*
	 * If we ever reply with an error, it must have the SMB command
	 * type of SMBwritec, not SMBwriteBraw, as this tells the client
	 * we're finished.
	 */
	SCVAL(discard_const_p(uint8_t, req->inbuf),smb_com,SMBwritec);

	if (smb1_srv_is_signing_active(xconn)) {
		END_PROFILE(SMBwritebraw);
		exit_server_cleanly("reply_writebraw: SMB signing is active - "
				"raw reads/writes are disallowed.");
	}

	if (req->wct < 12) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	if (xconn->smb1.echo_handler.trusted_fde) {
		DEBUG(2,("SMBwritebraw rejected with NOT_SUPPORTED because of "
			 "'async smb echo handler = yes'\n"));
		reply_nterror(req, NT_STATUS_NOT_SUPPORTED);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));
	if (!check_fsp(conn, req, fsp)) {
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	status = check_any_access_fsp(fsp, FILE_WRITE_DATA|FILE_APPEND_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	tcount = IVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+3, 0);
	write_through = BITSETW(req->vwv+7,0);

	/* We have to deal with slightly different formats depending
		on whether we are using the core+ or lanman1.0 protocol */

	if(xconn->protocol <= PROTOCOL_COREPLUS) {
		numtowrite = SVAL(smb_buf_const(req->inbuf),-2);
		data = smb_buf_const(req->inbuf);
	} else {
		numtowrite = SVAL(req->vwv+10, 0);
		data = smb_base(req->inbuf) + SVAL(req->vwv+11, 0);
	}

	/* Ensure we don't write bytes past the end of this packet. */
	/*
	 * This already protects us against CVE-2017-12163.
	 */
	if (data + numtowrite > smb_base(req->inbuf) + smb_len(req->inbuf)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		error_to_writebrawerr(req);
		END_PROFILE(SMBwritebraw);
		return;
	}

	if (!fsp->print_file) {
		init_strict_lock_struct(fsp,
				(uint64_t)req->smbpid,
				(uint64_t)startpos,
				(uint64_t)tcount,
				WRITE_LOCK,
				&lock);

		if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			error_to_writebrawerr(req);
			END_PROFILE(SMBwritebraw);
			return;
		}
	}

	if (numtowrite>0) {
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
	}

	DEBUG(3, ("reply_writebraw: initial write %s start=%.0f num=%d "
			"wrote=%d sync=%d\n",
		fsp_fnum_dbg(fsp), (double)startpos, (int)numtowrite,
		(int)nwritten, (int)write_through));

	if (nwritten < (ssize_t)numtowrite)  {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		error_to_writebrawerr(req);
		goto out;
	}

	total_written = nwritten;

	/* Allocate a buffer of 64k + length. */
	buf = talloc_array(NULL, char, 65540);
	if (!buf) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		error_to_writebrawerr(req);
		goto out;
	}

	/* Return a SMBwritebraw message to the redirector to tell
	 * it to send more bytes */

	memcpy(buf, req->inbuf, smb_size);
	srv_smb1_set_message(buf,xconn->protocol>PROTOCOL_COREPLUS?1:0,0,True);
	SCVAL(buf,smb_com,SMBwritebraw);
	SSVALS(buf,smb_vwv0,0xFFFF);
	show_msg(buf);
	if (!smb1_srv_send(req->xconn,
			   buf,
			   false,
			   0, /* no signing */
			   IS_CONN_ENCRYPTED(conn))) {
		exit_server_cleanly("reply_writebraw: smb1_srv_send "
			"failed.");
	}

	/* Now read the raw data into the buffer and write it */
	status = read_smb_length(xconn->transport.sock, buf, SMB_SECONDARY_WAIT,
				 &numtowrite);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server_cleanly("secondary writebraw failed");
	}

	/* Set up outbuf to return the correct size */
	reply_smb1_outbuf(req, 1, 0);

	if (numtowrite != 0) {

		if (numtowrite > 0xFFFF) {
			DEBUG(0,("reply_writebraw: Oversize secondary write "
				"raw requested (%u). Terminating\n",
				(unsigned int)numtowrite ));
			exit_server_cleanly("secondary writebraw failed");
		}

		if (tcount > nwritten+numtowrite) {
			DEBUG(3,("reply_writebraw: Client overestimated the "
				"write %d %d %d\n",
				(int)tcount,(int)nwritten,(int)numtowrite));
		}

		status = read_data_ntstatus(xconn->transport.sock, buf+4,
					    numtowrite);

		if (!NT_STATUS_IS_OK(status)) {
			/* Try and give an error message
			 * saying what client failed. */
			DEBUG(0, ("reply_writebraw: Oversize secondary write "
				  "raw read failed (%s) for client %s. "
				  "Terminating\n", nt_errstr(status),
				  smbXsrv_connection_dbg(xconn)));
			exit_server_cleanly("secondary writebraw failed");
		}

		/*
		 * We are not vulnerable to CVE-2017-12163
		 * here as we are guaranteed to have numtowrite
		 * bytes available - we just read from the client.
		 */
		nwritten = write_file(req,fsp,buf+4,startpos+nwritten,numtowrite);
		if (nwritten == -1) {
			TALLOC_FREE(buf);
			reply_nterror(req, map_nt_error_from_unix(errno));
			error_to_writebrawerr(req);
			goto out;
		}

		if (nwritten < (ssize_t)numtowrite) {
			SCVAL(req->outbuf,smb_rcls,ERRHRD);
			SSVAL(req->outbuf,smb_err,ERRdiskfull);
		}

		if (nwritten > 0) {
			total_written += nwritten;
		}
 	}

	TALLOC_FREE(buf);
	SSVAL(req->outbuf,smb_vwv0,total_written);

	status = sync_file(conn, fsp, write_through);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_writebraw: sync_file for %s returned %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		reply_nterror(req, status);
		error_to_writebrawerr(req);
		goto out;
	}

	DEBUG(3,("reply_writebraw: secondary write %s start=%.0f num=%d "
		"wrote=%d\n",
		fsp_fnum_dbg(fsp), (double)startpos, (int)numtowrite,
		(int)total_written));

	/* We won't return a status if write through is not selected - this
	 * follows what WfWg does */
	END_PROFILE(SMBwritebraw);

	if (!write_through && total_written==tcount) {

#if RABBIT_PELLET_FIX
		/*
		 * Fix for "rabbit pellet" mode, trigger an early TCP ack by
		 * sending a NBSSkeepalive. Thanks to DaveCB at Sun for this.
		 * JRA.
		 */
		if (!send_keepalive(xconn->transport.sock)) {
			exit_server_cleanly("reply_writebraw: send of "
				"keepalive failed");
		}
#endif
		TALLOC_FREE(req->outbuf);
	}
	return;

out:
	END_PROFILE(SMBwritebraw);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Reply to a writeunlock (core+).
****************************************************************************/

void reply_writeunlock(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	ssize_t nwritten = -1;
	size_t numtowrite;
	size_t remaining;
	off_t startpos;
	const char *data;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp;
	struct lock_struct lock;
	int saved_errno = 0;

	START_PROFILE(SMBwriteunlock);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwriteunlock);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwriteunlock);
		return;
	}

	status = check_any_access_fsp(fsp, FILE_WRITE_DATA|FILE_APPEND_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBwriteunlock);
		return;
	}

	numtowrite = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);
	data = (const char *)req->buf + 3;

	/*
	 * Ensure client isn't asking us to write more than
	 * they sent. CVE-2017-12163.
	 */
	remaining = smbreq_bufrem(req, data);
	if (numtowrite > remaining) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwriteunlock);
		return;
	}

	if (!fsp->print_file && numtowrite > 0) {
		init_strict_lock_struct(fsp,
				(uint64_t)req->smbpid,
				(uint64_t)startpos,
				(uint64_t)numtowrite,
				WRITE_LOCK,
				&lock);

		if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			END_PROFILE(SMBwriteunlock);
			return;
		}
	}

	/* The special X/Open SMB protocol handling of
	   zero length writes is *NOT* done for
	   this call */
	if(numtowrite == 0) {
		nwritten = 0;
	} else {
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
		saved_errno = errno;
	}

	status = sync_file(conn, fsp, False /* write through */);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_writeunlock: sync_file for %s returned %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		reply_nterror(req, status);
		goto out;
	}

	if(nwritten < 0) {
		reply_nterror(req, map_nt_error_from_unix(saved_errno));
		goto out;
	}

	if((nwritten < numtowrite) && (numtowrite != 0)) {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		goto out;
	}

	if (numtowrite && !fsp->print_file) {
		struct smbd_lock_element l = {
			.req_guid = smbd_request_guid(req, 0),
			.smblctx = req->smbpid,
			.brltype = UNLOCK_LOCK,
			.lock_flav = WINDOWS_LOCK,
			.offset = startpos,
			.count = numtowrite,
		};
		status = smbd_do_unlocking(req, fsp, 1, &l);
		if (NT_STATUS_V(status)) {
			reply_nterror(req, status);
			goto out;
		}
	}

	reply_smb1_outbuf(req, 1, 0);

	SSVAL(req->outbuf,smb_vwv0,nwritten);

	DEBUG(3, ("writeunlock %s num=%d wrote=%d\n",
		  fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten));

out:
	END_PROFILE(SMBwriteunlock);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a write.
****************************************************************************/

void reply_write(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	size_t numtowrite;
	size_t remaining;
	ssize_t nwritten = -1;
	off_t startpos;
	const char *data;
	files_struct *fsp;
	struct lock_struct lock;
	NTSTATUS status;
	int saved_errno = 0;

	START_PROFILE(SMBwrite);

	if (req->wct < 5) {
		END_PROFILE(SMBwrite);
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		reply_pipe_write(req);
		END_PROFILE(SMBwrite);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwrite);
		return;
	}

	status = check_any_access_fsp(fsp, FILE_WRITE_DATA|FILE_APPEND_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBwrite);
		return;
	}

	numtowrite = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);
	data = (const char *)req->buf + 3;

	/*
	 * Ensure client isn't asking us to write more than
	 * they sent. CVE-2017-12163.
	 */
	remaining = smbreq_bufrem(req, data);
	if (numtowrite > remaining) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwrite);
		return;
	}

	if (!fsp->print_file) {
		init_strict_lock_struct(fsp,
				(uint64_t)req->smbpid,
				(uint64_t)startpos,
				(uint64_t)numtowrite,
				WRITE_LOCK,
				&lock);

		if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			END_PROFILE(SMBwrite);
			return;
		}
	}

	/*
	 * X/Open SMB protocol says that if smb_vwv1 is
	 * zero then the file size should be extended or
	 * truncated to the size given in smb_vwv[2-3].
	 */

	if(numtowrite == 0) {
		struct file_modified_state state;

		/*
		 * This is actually an allocate call, and set EOF. JRA.
		 */
		prepare_file_modified(fsp, &state);
		nwritten = vfs_allocate_file_space(fsp, (off_t)startpos);
		if (nwritten < 0) {
			reply_nterror(req, NT_STATUS_DISK_FULL);
			goto out;
		}
		nwritten = vfs_set_filelen(fsp, (off_t)startpos);
		if (nwritten < 0) {
			reply_nterror(req, NT_STATUS_DISK_FULL);
			goto out;
		}
		mark_file_modified(fsp, true, &state);
	} else {
		nwritten = write_file(req,fsp,data,startpos,numtowrite);
	}

	status = sync_file(conn, fsp, False);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_write: sync_file for %s returned %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		reply_nterror(req, status);
		goto out;
	}

	if(nwritten < 0) {
		reply_nterror(req, map_nt_error_from_unix(saved_errno));
		goto out;
	}

	if((nwritten == 0) && (numtowrite != 0)) {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		goto out;
	}

	reply_smb1_outbuf(req, 1, 0);

	SSVAL(req->outbuf,smb_vwv0,nwritten);

	if (nwritten < (ssize_t)numtowrite) {
		SCVAL(req->outbuf,smb_rcls,ERRHRD);
		SSVAL(req->outbuf,smb_err,ERRdiskfull);
	}

	DEBUG(3, ("write %s num=%d wrote=%d\n", fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten));

out:
	END_PROFILE(SMBwrite);
	return;
}

/****************************************************************************
 Ensure a buffer is a valid writeX for recvfile purposes.
****************************************************************************/

#define STANDARD_WRITE_AND_X_HEADER_SIZE (smb_size - 4 + /* basic header */ \
						(2*14) + /* word count (including bcc) */ \
						1 /* pad byte */)

bool is_valid_writeX_buffer(struct smbXsrv_connection *xconn,
			    const uint8_t *inbuf)
{
	size_t numtowrite;
	unsigned int doff = 0;
	size_t len = smb_len_large(inbuf);
	uint16_t fnum;
	struct smbXsrv_open *op = NULL;
	struct files_struct *fsp = NULL;
	NTSTATUS status;

	if (is_encrypted_packet(inbuf)) {
		/* Can't do this on encrypted
		 * connections. */
		return false;
	}

	if (CVAL(inbuf,smb_com) != SMBwriteX) {
		return false;
	}

	if (CVAL(inbuf,smb_vwv0) != 0xFF ||
			CVAL(inbuf,smb_wct) != 14) {
		DEBUG(10,("is_valid_writeX_buffer: chained or "
			"invalid word length.\n"));
		return false;
	}

	fnum = SVAL(inbuf, smb_vwv2);
	status = smb1srv_open_lookup(xconn,
				     fnum,
				     0, /* now */
				     &op);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("is_valid_writeX_buffer: bad fnum\n"));
		return false;
	}
	fsp = op->compat;
	if (fsp == NULL) {
		DEBUG(10,("is_valid_writeX_buffer: bad fsp\n"));
		return false;
	}
	if (fsp->conn == NULL) {
		DEBUG(10,("is_valid_writeX_buffer: bad fsp->conn\n"));
		return false;
	}

	if (IS_IPC(fsp->conn)) {
		DEBUG(10,("is_valid_writeX_buffer: IPC$ tid\n"));
		return false;
	}
	if (IS_PRINT(fsp->conn)) {
		DEBUG(10,("is_valid_writeX_buffer: printing tid\n"));
		return false;
	}
	if (fsp_is_alternate_stream(fsp)) {
		DEBUG(10,("is_valid_writeX_buffer: stream fsp\n"));
		return false;
	}
	doff = SVAL(inbuf,smb_vwv11);

	numtowrite = SVAL(inbuf,smb_vwv10);

	if (len > doff && len - doff > 0xFFFF) {
		numtowrite |= (((size_t)SVAL(inbuf,smb_vwv9))<<16);
	}

	if (numtowrite == 0) {
		DEBUG(10,("is_valid_writeX_buffer: zero write\n"));
		return false;
	}

	/* Ensure the sizes match up. */
	if (doff < STANDARD_WRITE_AND_X_HEADER_SIZE) {
		/* no pad byte...old smbclient :-( */
		DEBUG(10,("is_valid_writeX_buffer: small doff %u (min %u)\n",
			(unsigned int)doff,
			(unsigned int)STANDARD_WRITE_AND_X_HEADER_SIZE));
		return false;
	}

	if (len - doff != numtowrite) {
		DEBUG(10,("is_valid_writeX_buffer: doff mismatch "
			"len = %u, doff = %u, numtowrite = %u\n",
			(unsigned int)len,
			(unsigned int)doff,
			(unsigned int)numtowrite ));
		return false;
	}

	DEBUG(10,("is_valid_writeX_buffer: true "
		"len = %u, doff = %u, numtowrite = %u\n",
		(unsigned int)len,
		(unsigned int)doff,
		(unsigned int)numtowrite ));

	return true;
}

/****************************************************************************
 Reply to a write and X.
****************************************************************************/

void reply_write_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smbXsrv_connection *xconn = req->xconn;
	files_struct *fsp;
	struct lock_struct lock;
	off_t startpos;
	size_t numtowrite;
	bool write_through;
	ssize_t nwritten;
	unsigned int smb_doff;
	unsigned int smblen;
	const char *data;
	NTSTATUS status;
	int saved_errno = 0;

	START_PROFILE(SMBwriteX);

	if ((req->wct != 12) && (req->wct != 14)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	numtowrite = SVAL(req->vwv+10, 0);
	smb_doff = SVAL(req->vwv+11, 0);
	smblen = smb_len(req->inbuf);

	if (req->unread_bytes > 0xFFFF ||
			(smblen > smb_doff &&
				smblen - smb_doff > 0xFFFF)) {
		numtowrite |= (((size_t)SVAL(req->vwv+9, 0))<<16);
	}

	if (req->unread_bytes) {
		/* Can't do a recvfile write on IPC$ */
		if (IS_IPC(conn)) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
	       	if (numtowrite != req->unread_bytes) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
	} else {
		/*
		 * This already protects us against CVE-2017-12163.
		 */
		if (smb_doff > smblen || smb_doff + numtowrite < numtowrite ||
				smb_doff + numtowrite > smblen) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
	}

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		if (req->unread_bytes) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
		reply_pipe_write_and_X(req);
		goto out;
	}

	fsp = file_fsp(req, SVAL(req->vwv+2, 0));
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+3, 0);
	write_through = BITSETW(req->vwv+7,0);

	if (!check_fsp(conn, req, fsp)) {
		goto out;
	}

	status = check_any_access_fsp(fsp, FILE_WRITE_DATA|FILE_APPEND_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	data = smb_base(req->inbuf) + smb_doff;

	if(req->wct == 14) {
		/*
		 * This is a large offset (64 bit) write.
		 */
		startpos |= (((off_t)IVAL(req->vwv+12, 0)) << 32);

	}

	/* X/Open SMB protocol says that, unlike SMBwrite
	if the length is zero then NO truncation is
	done, just a write of zero. To truncate a file,
	use SMBwrite. */

	if(numtowrite == 0) {
		nwritten = 0;
	} else {
		if (req->unread_bytes == 0) {
			status = schedule_aio_write_and_X(conn,
						req,
						fsp,
						data,
						startpos,
						numtowrite);

			if (NT_STATUS_IS_OK(status)) {
				/* write scheduled - we're done. */
				goto out;
			}
			if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
				/* Real error - report to client. */
				reply_nterror(req, status);
				goto out;
			}
			/* NT_STATUS_RETRY - fall through to sync write. */
		}

		init_strict_lock_struct(fsp,
				(uint64_t)req->smbpid,
				(uint64_t)startpos,
				(uint64_t)numtowrite,
				WRITE_LOCK,
				&lock);

		if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			goto out;
		}

		nwritten = write_file(req,fsp,data,startpos,numtowrite);
		saved_errno = errno;
	}

	if(nwritten < 0) {
		reply_nterror(req, map_nt_error_from_unix(saved_errno));
		goto out;
	}

	if((nwritten == 0) && (numtowrite != 0)) {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		goto out;
	}

	reply_smb1_outbuf(req, 6, 0);
	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */
	SSVAL(req->outbuf,smb_vwv2,nwritten);
	SSVAL(req->outbuf,smb_vwv4,nwritten>>16);

	DEBUG(3,("writeX %s num=%d wrote=%d\n",
		fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten));

	status = sync_file(conn, fsp, write_through);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("reply_write_and_X: sync_file for %s returned %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		reply_nterror(req, status);
		goto out;
	}

	END_PROFILE(SMBwriteX);
	return;

out:
	if (req->unread_bytes) {
		/* writeX failed. drain socket. */
		if (drain_socket(xconn->transport.sock, req->unread_bytes) !=
				req->unread_bytes) {
			smb_panic("failed to drain pending bytes");
		}
		req->unread_bytes = 0;
	}

	END_PROFILE(SMBwriteX);
	return;
}

/****************************************************************************
 Reply to a lseek.
****************************************************************************/

void reply_lseek(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	off_t startpos;
	off_t res= -1;
	int mode,umode;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBlseek);

	if (req->wct < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlseek);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		return;
	}

	mode = SVAL(req->vwv+1, 0) & 3;
	/* NB. This doesn't use IVAL_TO_SMB_OFF_T as startpos can be signed in this case. */
	startpos = (off_t)IVALS(req->vwv+2, 0);

	switch (mode) {
		case 0:
			umode = SEEK_SET;
			res = startpos;
			break;
		case 1:
			umode = SEEK_CUR;
			res = fh_get_pos(fsp->fh) + startpos;
			break;
		case 2:
			umode = SEEK_END;
			break;
		default:
			umode = SEEK_SET;
			res = startpos;
			break;
	}

	if (umode == SEEK_END) {
		if((res = SMB_VFS_LSEEK(fsp,startpos,umode)) == -1) {
			if(errno == EINVAL) {
				off_t current_pos = startpos;

				status = vfs_stat_fsp(fsp);
				if (!NT_STATUS_IS_OK(status)) {
					reply_nterror(req, status);
					END_PROFILE(SMBlseek);
					return;
				}

				current_pos += fsp->fsp_name->st.st_ex_size;
				if(current_pos < 0)
					res = SMB_VFS_LSEEK(fsp,0,SEEK_SET);
			}
		}

		if(res == -1) {
			reply_nterror(req, map_nt_error_from_unix(errno));
			END_PROFILE(SMBlseek);
			return;
		}
	}

	fh_set_pos(fsp->fh, res);

	reply_smb1_outbuf(req, 2, 0);
	SIVAL(req->outbuf,smb_vwv0,res);

	DEBUG(3,("lseek %s ofs=%.0f newpos = %.0f mode=%d\n",
		fsp_fnum_dbg(fsp), (double)startpos, (double)res, mode));

	END_PROFILE(SMBlseek);
	return;
}

static struct files_struct *file_sync_one_fn(struct files_struct *fsp,
					     void *private_data)
{
	connection_struct *conn = talloc_get_type_abort(
		private_data, connection_struct);

	if (conn != fsp->conn) {
		return NULL;
	}
	if (fsp_get_io_fd(fsp) == -1) {
		return NULL;
	}
	sync_file(conn, fsp, True /* write through */);

	return NULL;
}

/****************************************************************************
 Reply to a flush.
****************************************************************************/

void reply_flush(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint16_t fnum;
	files_struct *fsp;

	START_PROFILE(SMBflush);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fnum = SVAL(req->vwv+0, 0);
	fsp = file_fsp(req, fnum);

	if ((fnum != 0xFFFF) && !check_fsp(conn, req, fsp)) {
		return;
	}

	if (!fsp) {
		files_forall(req->sconn, file_sync_one_fn, conn);
	} else {
		NTSTATUS status = sync_file(conn, fsp, True);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5,("reply_flush: sync_file for %s returned %s\n",
				fsp_str_dbg(fsp), nt_errstr(status)));
			reply_nterror(req, status);
			END_PROFILE(SMBflush);
			return;
		}
	}

	reply_smb1_outbuf(req, 0, 0);

	DEBUG(3,("flush\n"));
	END_PROFILE(SMBflush);
	return;
}

/****************************************************************************
 Reply to a exit.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

static struct tevent_req *reply_exit_send(struct smb_request *smb1req);
static void reply_exit_done(struct tevent_req *req);

void reply_exit(struct smb_request *smb1req)
{
	struct tevent_req *req;

	/*
	 * Don't setup the profile charge here, take
	 * it in reply_exit_done(). Not strictly correct
	 * but better than the other SMB1 async
	 * code that double-charges at the moment.
	 */
	req = reply_exit_send(smb1req);
	if (req == NULL) {
		/* Not going async, profile here. */
		START_PROFILE(SMBexit);
		reply_force_doserror(smb1req, ERRDOS, ERRnomem);
		END_PROFILE(SMBexit);
		return;
	}

	/* We're async. This will complete later. */
	tevent_req_set_callback(req, reply_exit_done, smb1req);
	return;
}

struct reply_exit_state {
	struct tevent_queue *wait_queue;
};

static void reply_exit_wait_done(struct tevent_req *subreq);

/****************************************************************************
 Async SMB1 exit.
 Note, on failure here we deallocate and return NULL to allow the caller to
 SMB1 return an error of ERRnomem immediately.
****************************************************************************/

static struct tevent_req *reply_exit_send(struct smb_request *smb1req)
{
	struct tevent_req *req;
	struct reply_exit_state *state;
	struct tevent_req *subreq;
	files_struct *fsp;
	struct smbd_server_connection *sconn = smb1req->sconn;

	req = tevent_req_create(smb1req, &state,
			struct reply_exit_state);
	if (req == NULL) {
		return NULL;
	}
	state->wait_queue = tevent_queue_create(state,
				"reply_exit_wait_queue");
	if (tevent_req_nomem(state->wait_queue, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	for (fsp = sconn->files; fsp; fsp = fsp->next) {
		if (fsp->file_pid != smb1req->smbpid) {
			continue;
		}
		if (fsp->vuid != smb1req->vuid) {
			continue;
		}
		/*
		 * Flag the file as close in progress.
		 * This will prevent any more IO being
		 * done on it.
		 */
		fsp->fsp_flags.closing = true;

		if (fsp->num_aio_requests > 0) {
			/*
			 * Now wait until all aio requests on this fsp are
			 * finished.
			 *
			 * We don't set a callback, as we just want to block the
			 * wait queue and the talloc_free() of fsp->aio_request
			 * will remove the item from the wait queue.
			 */
			subreq = tevent_queue_wait_send(fsp->aio_requests,
						sconn->ev_ctx,
						state->wait_queue);
			if (tevent_req_nomem(subreq, req)) {
				TALLOC_FREE(req);
				return NULL;
			}
		}
	}

	/*
	 * Now we add our own waiter to the end of the queue,
	 * this way we get notified when all pending requests are finished
	 * and reply to the outstanding SMB1 request.
	 */
	subreq = tevent_queue_wait_send(state,
				sconn->ev_ctx,
				state->wait_queue);
	if (tevent_req_nomem(subreq, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	/*
	 * We're really going async - move the SMB1 request from
	 * a talloc stackframe above us to the conn talloc-context.
	 * We need this to stick around until the wait_done
	 * callback is invoked.
	 */
	smb1req = talloc_move(sconn, &smb1req);

	tevent_req_set_callback(subreq, reply_exit_wait_done, req);

	return req;
}

static void reply_exit_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);

	tevent_queue_wait_recv(subreq);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static NTSTATUS reply_exit_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static void reply_exit_done(struct tevent_req *req)
{
	struct smb_request *smb1req = tevent_req_callback_data(
		req, struct smb_request);
	struct smbd_server_connection *sconn = smb1req->sconn;
	struct smbXsrv_connection *xconn = smb1req->xconn;
	NTTIME now = timeval_to_nttime(&smb1req->request_time);
	struct smbXsrv_session *session = NULL;
	files_struct *fsp, *next;
	NTSTATUS status;

	/*
	 * Take the profile charge here. Not strictly
	 * correct but better than the other SMB1 async
	 * code that double-charges at the moment.
	 */
	START_PROFILE(SMBexit);

	status = reply_exit_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb1req);
		END_PROFILE(SMBexit);
		exit_server(__location__ ": reply_exit_recv failed");
		return;
	}

	/*
	 * Ensure the session is still valid.
	 */
	status = smb1srv_session_lookup(xconn,
					smb1req->vuid,
					now,
					&session);
	if (!NT_STATUS_IS_OK(status)) {
		reply_force_doserror(smb1req, ERRSRV, ERRinvnid);
		smb_request_done(smb1req);
		END_PROFILE(SMBexit);
		return;
	}

	/*
	 * Ensure the vuid is still valid - no one
	 * called reply_ulogoffX() in the meantime.
	 * reply_exit() doesn't have AS_USER set, so
	 * use set_current_user_info() directly.
	 * This is the same logic as in switch_message().
	 */
	if (session->global->auth_session_info != NULL) {
		set_current_user_info(
			session->global->auth_session_info->unix_info->sanitized_username,
			session->global->auth_session_info->unix_info->unix_name,
			session->global->auth_session_info->info->domain_name);
	}

	/* No more aio - do the actual closes. */
	for (fsp = sconn->files; fsp; fsp = next) {
		bool ok;
		next = fsp->next;

		if (fsp->file_pid != smb1req->smbpid) {
			continue;
		}
		if (fsp->vuid != smb1req->vuid) {
			continue;
		}
		if (!fsp->fsp_flags.closing) {
			continue;
		}

		/*
		 * reply_exit() has the DO_CHDIR flag set.
		 */
		ok = chdir_current_service(fsp->conn);
		if (!ok) {
			reply_force_doserror(smb1req, ERRSRV, ERRinvnid);
			smb_request_done(smb1req);
			END_PROFILE(SMBexit);
			return;
		}
		close_file_free(NULL, &fsp, SHUTDOWN_CLOSE);
	}

	reply_smb1_outbuf(smb1req, 0, 0);
	/*
	 * The following call is needed to push the
	 * reply data back out the socket after async
	 * return. Plus it frees smb1req.
	 */
	smb_request_done(smb1req);
	DBG_INFO("reply_exit complete\n");
	END_PROFILE(SMBexit);
	return;
}

static struct tevent_req *reply_close_send(struct smb_request *smb1req,
				files_struct *fsp);
static void reply_close_done(struct tevent_req *req);

void reply_close(struct smb_request *smb1req)
{
	connection_struct *conn = smb1req->conn;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp = NULL;
	START_PROFILE(SMBclose);

	if (smb1req->wct < 3) {
		reply_nterror(smb1req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBclose);
		return;
	}

	fsp = file_fsp(smb1req, SVAL(smb1req->vwv+0, 0));

	/*
	 * We can only use check_fsp if we know it's not a directory.
	 */

	if (!check_fsp_open(conn, smb1req, fsp)) {
		END_PROFILE(SMBclose);
		return;
	}

	DBG_NOTICE("Close %s fd=%d %s (numopen=%d)\n",
		  fsp->fsp_flags.is_directory ?
		  "directory" : "file",
		  fsp_get_pathref_fd(fsp), fsp_fnum_dbg(fsp),
		  conn->num_files_open);

	if (!fsp->fsp_flags.is_directory) {
		time_t t;

		/*
		 * Take care of any time sent in the close.
		 */

		t = srv_make_unix_date3(smb1req->vwv+1);
		set_close_write_time(fsp, time_t_to_full_timespec(t));
	}

	if (fsp->num_aio_requests != 0) {
		struct tevent_req *req;

		req = reply_close_send(smb1req, fsp);
		if (req == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		/* We're async. This will complete later. */
		tevent_req_set_callback(req, reply_close_done, smb1req);
		END_PROFILE(SMBclose);
		return;
	}

	/*
	 * close_file_free() returns the unix errno if an error was detected on
	 * close - normally this is due to a disk full error. If not then it
	 * was probably an I/O error.
	 */

	status = close_file_free(smb1req, &fsp, NORMAL_CLOSE);
done:
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(smb1req, status);
		END_PROFILE(SMBclose);
		return;
	}

	reply_smb1_outbuf(smb1req, 0, 0);
	END_PROFILE(SMBclose);
	return;
}

struct reply_close_state {
	files_struct *fsp;
	struct tevent_queue *wait_queue;
};

static void reply_close_wait_done(struct tevent_req *subreq);

/****************************************************************************
 Async SMB1 close.
 Note, on failure here we deallocate and return NULL to allow the caller to
 SMB1 return an error of ERRnomem immediately.
****************************************************************************/

static struct tevent_req *reply_close_send(struct smb_request *smb1req,
				files_struct *fsp)
{
	struct tevent_req *req;
	struct reply_close_state *state;
	struct tevent_req *subreq;
	struct smbd_server_connection *sconn = smb1req->sconn;

	req = tevent_req_create(smb1req, &state,
			struct reply_close_state);
	if (req == NULL) {
		return NULL;
	}
	state->wait_queue = tevent_queue_create(state,
				"reply_close_wait_queue");
	if (tevent_req_nomem(state->wait_queue, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	/*
	 * Flag the file as close in progress.
	 * This will prevent any more IO being
	 * done on it.
	 */
	fsp->fsp_flags.closing = true;

	/*
	 * Now wait until all aio requests on this fsp are
	 * finished.
	 *
	 * We don't set a callback, as we just want to block the
	 * wait queue and the talloc_free() of fsp->aio_request
	 * will remove the item from the wait queue.
	 */
	subreq = tevent_queue_wait_send(fsp->aio_requests,
					sconn->ev_ctx,
					state->wait_queue);
	if (tevent_req_nomem(subreq, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	/*
	 * Now we add our own waiter to the end of the queue,
	 * this way we get notified when all pending requests are finished
	 * and reply to the outstanding SMB1 request.
	 */
	subreq = tevent_queue_wait_send(state,
				sconn->ev_ctx,
				state->wait_queue);
	if (tevent_req_nomem(subreq, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	/*
	 * We're really going async - move the SMB1 request from
	 * a talloc stackframe above us to the conn talloc-context.
	 * We need this to stick around until the wait_done
	 * callback is invoked.
	 */
	smb1req = talloc_move(sconn, &smb1req);

	tevent_req_set_callback(subreq, reply_close_wait_done, req);

	return req;
}

static void reply_close_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);

	tevent_queue_wait_recv(subreq);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static NTSTATUS reply_close_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static void reply_close_done(struct tevent_req *req)
{
	struct smb_request *smb1req = tevent_req_callback_data(
			req, struct smb_request);
        struct reply_close_state *state = tevent_req_data(req,
                                                struct reply_close_state);
	NTSTATUS status;

	status = reply_close_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb1req);
		exit_server(__location__ ": reply_close_recv failed");
		return;
	}

	status = close_file_free(smb1req, &state->fsp, NORMAL_CLOSE);
	if (NT_STATUS_IS_OK(status)) {
		reply_smb1_outbuf(smb1req, 0, 0);
	} else {
		reply_nterror(smb1req, status);
	}
	/*
	 * The following call is needed to push the
	 * reply data back out the socket after async
	 * return. Plus it frees smb1req.
	 */
	smb_request_done(smb1req);
}

/****************************************************************************
 Reply to a writeclose (Core+ protocol).
****************************************************************************/

void reply_writeclose(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	size_t numtowrite;
	size_t remaining;
	ssize_t nwritten = -1;
	NTSTATUS close_status = NT_STATUS_OK;
	off_t startpos;
	const char *data;
	struct timespec mtime;
	files_struct *fsp;
	struct lock_struct lock;
	NTSTATUS status;

	START_PROFILE(SMBwriteclose);

	if (req->wct < 6) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwriteclose);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBwriteclose);
		return;
	}
	status = check_any_access_fsp(fsp, FILE_WRITE_DATA|FILE_APPEND_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBwriteclose);
		return;
	}

	numtowrite = SVAL(req->vwv+1, 0);
	startpos = IVAL_TO_SMB_OFF_T(req->vwv+2, 0);
	mtime = time_t_to_full_timespec(srv_make_unix_date3(req->vwv+4));
	data = (const char *)req->buf + 1;

	/*
	 * Ensure client isn't asking us to write more than
	 * they sent. CVE-2017-12163.
	 */
	remaining = smbreq_bufrem(req, data);
	if (numtowrite > remaining) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBwriteclose);
		return;
	}

	if (fsp->print_file == NULL) {
		init_strict_lock_struct(fsp,
				(uint64_t)req->smbpid,
				(uint64_t)startpos,
				(uint64_t)numtowrite,
				WRITE_LOCK,
				&lock);

		if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &lock)) {
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			END_PROFILE(SMBwriteclose);
			return;
		}
	}

	nwritten = write_file(req,fsp,data,startpos,numtowrite);

	set_close_write_time(fsp, mtime);

	/*
	 * More insanity. W2K only closes the file if writelen > 0.
	 * JRA.
	 */

	DEBUG(3,("writeclose %s num=%d wrote=%d (numopen=%d)\n",
		fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten,
		(numtowrite) ? conn->num_files_open - 1 : conn->num_files_open));

	if (numtowrite) {
		DEBUG(3,("reply_writeclose: zero length write doesn't close "
			 "file %s\n", fsp_str_dbg(fsp)));
		close_status = close_file_free(req, &fsp, NORMAL_CLOSE);
	}

	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		reply_nterror(req, NT_STATUS_DISK_FULL);
		goto out;
	}

	if(!NT_STATUS_IS_OK(close_status)) {
		reply_nterror(req, close_status);
		goto out;
	}

	reply_smb1_outbuf(req, 1, 0);

	SSVAL(req->outbuf,smb_vwv0,nwritten);

out:

	END_PROFILE(SMBwriteclose);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Reply to a lock.
****************************************************************************/

static void reply_lock_done(struct tevent_req *subreq);

void reply_lock(struct smb_request *req)
{
	struct tevent_req *subreq = NULL;
	connection_struct *conn = req->conn;
	files_struct *fsp;
	struct smbd_lock_element *lck = NULL;

	START_PROFILE(SMBlock);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlock);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBlock);
		return;
	}

	lck = talloc(req, struct smbd_lock_element);
	if (lck == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBlock);
		return;
	}

	*lck = (struct smbd_lock_element) {
		.req_guid = smbd_request_guid(req, 0),
		.smblctx = req->smbpid,
		.brltype = WRITE_LOCK,
		.lock_flav = WINDOWS_LOCK,
		.count = IVAL(req->vwv+1, 0),
		.offset = IVAL(req->vwv+3, 0),
	};

	DBG_NOTICE("lock fd=%d %s offset=%"PRIu64" count=%"PRIu64"\n",
		   fsp_get_io_fd(fsp),
		   fsp_fnum_dbg(fsp),
		   lck->offset,
		   lck->count);

	subreq = smbd_smb1_do_locks_send(
		fsp,
		req->sconn->ev_ctx,
		&req,
		fsp,
		0,
		false,		/* large_offset */
		1,
		lck);
	if (subreq == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBlock);
		return;
	}
	tevent_req_set_callback(subreq, reply_lock_done, NULL);
	END_PROFILE(SMBlock);
}

static void reply_lock_done(struct tevent_req *subreq)
{
	struct smb_request *req = NULL;
	NTSTATUS status;
	bool ok;

	START_PROFILE(SMBlock);

	ok = smbd_smb1_do_locks_extract_smbreq(subreq, talloc_tos(), &req);
	SMB_ASSERT(ok);

	status = smbd_smb1_do_locks_recv(subreq);
	TALLOC_FREE(subreq);

	if (NT_STATUS_IS_OK(status)) {
		reply_smb1_outbuf(req, 0, 0);
	} else {
		reply_nterror(req, status);
	}

	ok = smb1_srv_send(req->xconn,
			   (char *)req->outbuf,
			   true,
			   req->seqnum + 1,
			   IS_CONN_ENCRYPTED(req->conn));
	if (!ok) {
		exit_server_cleanly("reply_lock_done: smb1_srv_send failed.");
	}
	TALLOC_FREE(req);
	END_PROFILE(SMBlock);
}

/****************************************************************************
 Reply to a unlock.
****************************************************************************/

void reply_unlock(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	NTSTATUS status;
	files_struct *fsp;
	struct smbd_lock_element lck;

	START_PROFILE(SMBunlock);

	if (req->wct < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBunlock);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBunlock);
		return;
	}

	lck = (struct smbd_lock_element) {
		.req_guid = smbd_request_guid(req, 0),
		.smblctx = req->smbpid,
		.brltype = UNLOCK_LOCK,
		.lock_flav = WINDOWS_LOCK,
		.offset = IVAL(req->vwv+3, 0),
		.count = IVAL(req->vwv+1, 0),
	};

	status = smbd_do_unlocking(req, fsp, 1, &lck);

	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBunlock);
		return;
	}

	DBG_NOTICE("unlock fd=%d %s offset=%"PRIu64" count=%"PRIu64"\n",
		   fsp_get_io_fd(fsp),
		   fsp_fnum_dbg(fsp),
		   lck.offset,
		   lck.count);

	reply_smb1_outbuf(req, 0, 0);

	END_PROFILE(SMBunlock);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a tdis.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

static struct tevent_req *reply_tdis_send(struct smb_request *smb1req);
static void reply_tdis_done(struct tevent_req *req);

void reply_tdis(struct smb_request *smb1req)
{
	connection_struct *conn = smb1req->conn;
	struct tevent_req *req;

	/*
	 * Don't setup the profile charge here, take
	 * it in reply_tdis_done(). Not strictly correct
	 * but better than the other SMB1 async
	 * code that double-charges at the moment.
	 */

	if (conn == NULL) {
		/* Not going async, profile here. */
		START_PROFILE(SMBtdis);
		DBG_INFO("Invalid connection in tdis\n");
		reply_force_doserror(smb1req, ERRSRV, ERRinvnid);
		END_PROFILE(SMBtdis);
		return;
	}

	req = reply_tdis_send(smb1req);
	if (req == NULL) {
		/* Not going async, profile here. */
		START_PROFILE(SMBtdis);
		reply_force_doserror(smb1req, ERRDOS, ERRnomem);
		END_PROFILE(SMBtdis);
		return;
	}
	/* We're async. This will complete later. */
	tevent_req_set_callback(req, reply_tdis_done, smb1req);
	return;
}

struct reply_tdis_state {
	struct tevent_queue *wait_queue;
};

static void reply_tdis_wait_done(struct tevent_req *subreq);

/****************************************************************************
 Async SMB1 tdis.
 Note, on failure here we deallocate and return NULL to allow the caller to
 SMB1 return an error of ERRnomem immediately.
****************************************************************************/

static struct tevent_req *reply_tdis_send(struct smb_request *smb1req)
{
	struct tevent_req *req;
	struct reply_tdis_state *state;
	struct tevent_req *subreq;
	connection_struct *conn = smb1req->conn;
	files_struct *fsp;

	req = tevent_req_create(smb1req, &state,
			struct reply_tdis_state);
	if (req == NULL) {
		return NULL;
	}
	state->wait_queue = tevent_queue_create(state, "reply_tdis_wait_queue");
	if (tevent_req_nomem(state->wait_queue, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	/*
	 * Make sure that no new request will be able to use this tcon.
	 * This ensures that once all outstanding fsp->aio_requests
	 * on this tcon are done, we are safe to close it.
	 */
	conn->tcon->status = NT_STATUS_NETWORK_NAME_DELETED;

	for (fsp = conn->sconn->files; fsp; fsp = fsp->next) {
		if (fsp->conn != conn) {
			continue;
		}
		/*
		 * Flag the file as close in progress.
		 * This will prevent any more IO being
		 * done on it. Not strictly needed, but
		 * doesn't hurt to flag it as closing.
		 */
		fsp->fsp_flags.closing = true;

		if (fsp->num_aio_requests > 0) {
			/*
			 * Now wait until all aio requests on this fsp are
			 * finished.
			 *
			 * We don't set a callback, as we just want to block the
			 * wait queue and the talloc_free() of fsp->aio_request
			 * will remove the item from the wait queue.
			 */
			subreq = tevent_queue_wait_send(fsp->aio_requests,
						conn->sconn->ev_ctx,
						state->wait_queue);
			if (tevent_req_nomem(subreq, req)) {
				TALLOC_FREE(req);
				return NULL;
			}
		}
	}

	/*
	 * Now we add our own waiter to the end of the queue,
	 * this way we get notified when all pending requests are finished
	 * and reply to the outstanding SMB1 request.
	 */
	subreq = tevent_queue_wait_send(state,
				conn->sconn->ev_ctx,
				state->wait_queue);
	if (tevent_req_nomem(subreq, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	/*
	 * We're really going async - move the SMB1 request from
	 * a talloc stackframe above us to the sconn talloc-context.
	 * We need this to stick around until the wait_done
	 * callback is invoked.
	 */
	smb1req = talloc_move(smb1req->sconn, &smb1req);

	tevent_req_set_callback(subreq, reply_tdis_wait_done, req);

	return req;
}

static void reply_tdis_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);

	tevent_queue_wait_recv(subreq);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static NTSTATUS reply_tdis_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static void reply_tdis_done(struct tevent_req *req)
{
	struct smb_request *smb1req = tevent_req_callback_data(
		req, struct smb_request);
	NTSTATUS status;
	struct smbXsrv_tcon *tcon = smb1req->conn->tcon;
	bool ok;

	/*
	 * Take the profile charge here. Not strictly
	 * correct but better than the other SMB1 async
	 * code that double-charges at the moment.
	 */
	START_PROFILE(SMBtdis);

	status = reply_tdis_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb1req);
		END_PROFILE(SMBtdis);
		exit_server(__location__ ": reply_tdis_recv failed");
		return;
	}

	/*
	 * As we've been awoken, we may have changed
	 * directory in the meantime.
	 * reply_tdis() has the DO_CHDIR flag set.
	 */
	ok = chdir_current_service(smb1req->conn);
	if (!ok) {
		reply_force_doserror(smb1req, ERRSRV, ERRinvnid);
		smb_request_done(smb1req);
		END_PROFILE(SMBtdis);
	}

	status = smbXsrv_tcon_disconnect(tcon,
					 smb1req->vuid);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb1req);
		END_PROFILE(SMBtdis);
		exit_server(__location__ ": smbXsrv_tcon_disconnect failed");
		return;
	}

	/* smbXsrv_tcon_disconnect frees smb1req->conn. */
	smb1req->conn = NULL;

	TALLOC_FREE(tcon);

	reply_smb1_outbuf(smb1req, 0, 0);
	/*
	 * The following call is needed to push the
	 * reply data back out the socket after async
	 * return. Plus it frees smb1req.
	 */
	smb_request_done(smb1req);
	END_PROFILE(SMBtdis);
}

/****************************************************************************
 Reply to a echo.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_echo(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	int smb_reverb;
	int seq_num;

	START_PROFILE(SMBecho);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBecho);
		return;
	}

	smb_reverb = SVAL(req->vwv+0, 0);

	reply_smb1_outbuf(req, 1, req->buflen);

	/* copy any incoming data back out */
	if (req->buflen > 0) {
		memcpy(smb_buf(req->outbuf), req->buf, req->buflen);
	}

	if (smb_reverb > 100) {
		DEBUG(0,("large reverb (%d)?? Setting to 100\n",smb_reverb));
		smb_reverb = 100;
	}

	for (seq_num = 1 ; seq_num <= smb_reverb ; seq_num++) {

		SSVAL(req->outbuf,smb_vwv0,seq_num);

		show_msg((char *)req->outbuf);
		if (!smb1_srv_send(req->xconn,
				   (char *)req->outbuf,
				   true,
				   req->seqnum + 1,
				   IS_CONN_ENCRYPTED(conn) || req->encrypted))
			exit_server_cleanly("reply_echo: smb1_srv_send failed.");
	}

	DEBUG(3,("echo %d times\n", smb_reverb));

	TALLOC_FREE(req->outbuf);

	END_PROFILE(SMBecho);
	return;
}

/****************************************************************************
 Reply to a printopen.
****************************************************************************/

void reply_printopen(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBsplopen);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplopen);
		return;
	}

	if (!CAN_PRINT(conn)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBsplopen);
		return;
	}

	status = file_new(req, conn, &fsp);
	if(!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsplopen);
		return;
	}

	/* Open for exclusive use, write only. */
	status = print_spool_open(fsp, NULL, req->vuid);

	if (!NT_STATUS_IS_OK(status)) {
		file_free(req, fsp);
		reply_nterror(req, status);
		END_PROFILE(SMBsplopen);
		return;
	}

	reply_smb1_outbuf(req, 1, 0);
	SSVAL(req->outbuf,smb_vwv0,fsp->fnum);

	DEBUG(3,("openprint fd=%d %s\n",
		 fsp_get_io_fd(fsp), fsp_fnum_dbg(fsp)));

	END_PROFILE(SMBsplopen);
	return;
}

/****************************************************************************
 Reply to a printclose.
****************************************************************************/

void reply_printclose(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBsplclose);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplclose);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBsplclose);
                return;
        }

	if (!CAN_PRINT(conn)) {
		reply_force_doserror(req, ERRSRV, ERRerror);
		END_PROFILE(SMBsplclose);
		return;
	}

	DEBUG(3,("printclose fd=%d %s\n",
		 fsp_get_io_fd(fsp), fsp_fnum_dbg(fsp)));

	status = close_file_free(req, &fsp, NORMAL_CLOSE);

	if(!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsplclose);
		return;
	}

	reply_smb1_outbuf(req, 0, 0);

	END_PROFILE(SMBsplclose);
	return;
}

/****************************************************************************
 Reply to a printqueue.
****************************************************************************/

void reply_printqueue(struct smb_request *req)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	connection_struct *conn = req->conn;
	int max_count;
	int start_index;

	START_PROFILE(SMBsplretq);

	if (req->wct < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplretq);
		return;
	}

	max_count = SVAL(req->vwv+0, 0);
	start_index = SVAL(req->vwv+1, 0);

	/* we used to allow the client to get the cnum wrong, but that
	   is really quite gross and only worked when there was only
	   one printer - I think we should now only accept it if they
	   get it right (tridge) */
	if (!CAN_PRINT(conn)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBsplretq);
		return;
	}

	reply_smb1_outbuf(req, 2, 3);
	SSVAL(req->outbuf,smb_vwv0,0);
	SSVAL(req->outbuf,smb_vwv1,0);
	SCVAL(smb_buf(req->outbuf),0,1);
	SSVAL(smb_buf(req->outbuf),1,0);

	DEBUG(3,("printqueue start_index=%d max_count=%d\n",
		 start_index, max_count));

	{
		TALLOC_CTX *mem_ctx = talloc_tos();
		NTSTATUS status;
		WERROR werr;
		const char *sharename = lp_servicename(mem_ctx, lp_sub, SNUM(conn));
		struct rpc_pipe_client *cli = NULL;
		struct dcerpc_binding_handle *b = NULL;
		struct policy_handle handle;
		struct spoolss_DevmodeContainer devmode_ctr;
		union spoolss_JobInfo *info;
		uint32_t count;
		uint32_t num_to_get;
		uint32_t first;
		uint32_t i;

		ZERO_STRUCT(handle);

		status = rpc_pipe_open_interface(mem_ctx,
						 &ndr_table_spoolss,
						 conn->session_info,
						 conn->sconn->remote_address,
						 conn->sconn->local_address,
						 conn->sconn->msg_ctx,
						 &cli);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("reply_printqueue: "
				  "could not connect to spoolss: %s\n",
				  nt_errstr(status)));
			reply_nterror(req, status);
			goto out;
		}
		b = cli->binding_handle;

		ZERO_STRUCT(devmode_ctr);

		status = dcerpc_spoolss_OpenPrinter(b, mem_ctx,
						sharename,
						NULL, devmode_ctr,
						SEC_FLAG_MAXIMUM_ALLOWED,
						&handle,
						&werr);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}
		if (!W_ERROR_IS_OK(werr)) {
			reply_nterror(req, werror_to_ntstatus(werr));
			goto out;
		}

		werr = rpccli_spoolss_enumjobs(cli, mem_ctx,
					       &handle,
					       0, /* firstjob */
					       0xff, /* numjobs */
					       2, /* level */
					       0, /* offered */
					       &count,
					       &info);
		if (!W_ERROR_IS_OK(werr)) {
			reply_nterror(req, werror_to_ntstatus(werr));
			goto out;
		}

		if (max_count > 0) {
			first = start_index;
		} else {
			first = start_index + max_count + 1;
		}

		if (first >= count) {
			num_to_get = first;
		} else {
			num_to_get = first + MIN(ABS(max_count), count - first);
		}

		for (i = first; i < num_to_get; i++) {
			char blob[28];
			char *p = blob;
			struct timespec qtime = {
				.tv_sec = spoolss_Time_to_time_t(
					&info[i].info2.submitted),
			};
			int qstatus;
			size_t len = 0;
			uint16_t qrapjobid = pjobid_to_rap(sharename,
							info[i].info2.job_id);

			if (info[i].info2.status == JOB_STATUS_PRINTING) {
				qstatus = 2;
			} else {
				qstatus = 3;
			}

			srv_put_dos_date2_ts(p, 0, qtime);
			SCVAL(p, 4, qstatus);
			SSVAL(p, 5, qrapjobid);
			SIVAL(p, 7, info[i].info2.size);
			SCVAL(p, 11, 0);
			status = srvstr_push(blob, req->flags2, p+12,
				    info[i].info2.notify_name, 16, STR_ASCII, &len);
			if (!NT_STATUS_IS_OK(status)) {
				reply_nterror(req, status);
				goto out;
			}
			if (message_push_blob(
				    &req->outbuf,
				    data_blob_const(
					    blob, sizeof(blob))) == -1) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				goto out;
			}
		}

		if (count > 0) {
			SSVAL(req->outbuf,smb_vwv0,count);
			SSVAL(req->outbuf,smb_vwv1,
			      (max_count>0?first+count:first-1));
			SCVAL(smb_buf(req->outbuf),0,1);
			SSVAL(smb_buf(req->outbuf),1,28*count);
		}


		DEBUG(3, ("%u entries returned in queue\n",
			  (unsigned)count));

out:
		if (b && is_valid_policy_hnd(&handle)) {
			dcerpc_spoolss_ClosePrinter(b, mem_ctx, &handle, &werr);
		}

	}

	END_PROFILE(SMBsplretq);
	return;
}

/****************************************************************************
 Reply to a printwrite.
****************************************************************************/

void reply_printwrite(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	int numtowrite;
	const char *data;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBsplwr);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplwr);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBsplwr);
                return;
        }

	if (!fsp->print_file) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBsplwr);
		return;
	}

	status = check_any_access_fsp(fsp, FILE_WRITE_DATA|FILE_APPEND_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBsplwr);
		return;
	}

	numtowrite = SVAL(req->buf, 1);

	/*
	 * This already protects us against CVE-2017-12163.
	 */
	if (req->buflen < numtowrite + 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsplwr);
		return;
	}

	data = (const char *)req->buf + 3;

	if (write_file(req,fsp,data,(off_t)-1,numtowrite) != numtowrite) {
		reply_nterror(req, map_nt_error_from_unix(errno));
		END_PROFILE(SMBsplwr);
		return;
	}

	DEBUG(3, ("printwrite %s num=%d\n", fsp_fnum_dbg(fsp), numtowrite));

	reply_smb1_outbuf(req, 0, 0);

	END_PROFILE(SMBsplwr);
	return;
}

/****************************************************************************
 Reply to a mkdir.
****************************************************************************/

void reply_mkdir(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct files_struct *dirfsp = NULL;
	struct smb_filename *smb_dname = NULL;
	char *directory = NULL;
	NTSTATUS status;
	uint32_t ucf_flags;
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBmkdir);

	srvstr_get_path_req(ctx, req, &directory, (const char *)req->buf + 1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	ucf_flags = filename_create_ucf_flags(req, FILE_CREATE, 0);
	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(directory, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &directory);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert_dirfsp(ctx,
					 conn,
					 directory,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_dname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = create_directory(conn, req, dirfsp, smb_dname);

	DEBUG(5, ("create_directory returned %s\n", nt_errstr(status)));

	if (!NT_STATUS_IS_OK(status)) {

		if (!use_nt_status()
		    && NT_STATUS_EQUAL(status,
				       NT_STATUS_OBJECT_NAME_COLLISION)) {
			/*
			 * Yes, in the DOS error code case we get a
			 * ERRDOS:ERRnoaccess here. See BASE-SAMBA3ERROR
			 * samba4 torture test.
			 */
			status = NT_STATUS_DOS(ERRDOS, ERRnoaccess);
		}

		reply_nterror(req, status);
		goto out;
	}

	reply_smb1_outbuf(req, 0, 0);

	DEBUG(3, ("mkdir %s\n", smb_dname->base_name));
 out:
	TALLOC_FREE(smb_dname);
	END_PROFILE(SMBmkdir);
	return;
}

/****************************************************************************
 Reply to a rmdir.
****************************************************************************/

void reply_rmdir(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_filename *smb_dname = NULL;
	char *directory = NULL;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();
	struct files_struct *dirfsp = NULL;
	files_struct *fsp = NULL;
	int info = 0;
	NTTIME twrp = 0;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);

	START_PROFILE(SMBrmdir);

	srvstr_get_path_req(ctx, req, &directory, (const char *)req->buf + 1,
			    STR_TERMINATE, &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(directory, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &directory);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert_dirfsp(ctx,
					 conn,
					 directory,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_dname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,                                   /* conn */
		req,                                    /* req */
		dirfsp,					/* dirfsp */
		smb_dname,                              /* fname */
		DELETE_ACCESS,                          /* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |   /* share_access */
			FILE_SHARE_DELETE),
		FILE_OPEN,                              /* create_disposition*/
		FILE_DIRECTORY_FILE |
			FILE_OPEN_REPARSE_POINT,	/* create_options */
		FILE_ATTRIBUTE_DIRECTORY,               /* file_attributes */
		0,                                      /* oplock_request */
		NULL,					/* lease */
		0,                                      /* allocation_size */
		0,					/* private_flags */
		NULL,                                   /* sd */
		NULL,                                   /* ea_list */
		&fsp,                                   /* result */
		&info,                                  /* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				goto out;
			}
		}
		reply_nterror(req, status);
		goto out;
	}

	status = can_set_delete_on_close(fsp, FILE_ATTRIBUTE_DIRECTORY);
	if (!NT_STATUS_IS_OK(status)) {
		close_file_free(req, &fsp, ERROR_CLOSE);
		reply_nterror(req, status);
		goto out;
	}

	if (!set_delete_on_close(fsp, true,
			conn->session_info->security_token,
			conn->session_info->unix_token)) {
		close_file_free(req, &fsp, ERROR_CLOSE);
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	status = close_file_free(req, &fsp, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
	} else {
		reply_smb1_outbuf(req, 0, 0);
	}

	DEBUG(3, ("rmdir %s\n", smb_fname_str_dbg(smb_dname)));
 out:
	TALLOC_FREE(smb_dname);
	END_PROFILE(SMBrmdir);
	return;
}

/****************************************************************************
 Reply to a mv.
****************************************************************************/

void reply_mv(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	char *name = NULL;
	char *newname = NULL;
	const char *p;
	uint32_t attrs;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();
	struct files_struct *src_dirfsp = NULL;
	struct smb_filename *smb_fname_src = NULL;
	struct smb_filename *smb_fname_src_rel = NULL;
	uint32_t src_ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME src_twrp = 0;
	uint32_t dst_ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME dst_twrp = 0;

	START_PROFILE(SMBmv);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	attrs = SVAL(req->vwv+0, 0);

	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req(ctx, req, &name, p, STR_TERMINATE,
				       &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}
	p++;
	p += srvstr_get_path_req(ctx, req, &newname, p, STR_TERMINATE,
				       &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (!req->posix_pathnames) {
		/* The newname must begin with a ':' if the
		   name contains a ':'. */
		if (strchr_m(name, ':')) {
			if (newname[0] != ':') {
				reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
				goto out;
			}
		}
        }

	if (src_ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(name, &src_twrp);
	}
	status = smb1_strip_dfs_path(ctx, &src_ucf_flags, &name);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}
	status = filename_convert_dirfsp_rel(ctx,
					     conn,
					     conn->cwd_fsp,
					     name,
					     src_ucf_flags,
					     src_twrp,
					     &src_dirfsp,
					     &smb_fname_src,
					     &smb_fname_src_rel);

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	if (dst_ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(newname, &dst_twrp);
	}
	status = smb1_strip_dfs_path(ctx, &dst_ucf_flags, &newname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	DBG_NOTICE("%s -> %s\n", smb_fname_str_dbg(smb_fname_src), newname);

	status = rename_internals(ctx,
				  conn,
				  req,
				  src_dirfsp, /* src_dirfsp */
				  smb_fname_src,
				  smb_fname_src_rel,
				  attrs,
				  newname,
				  false,
				  DELETE_ACCESS);
	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				goto out;
			}
		}
		reply_nterror(req, status);
		goto out;
	}

	reply_smb1_outbuf(req, 0, 0);
 out:
	 TALLOC_FREE(smb_fname_src);
	 END_PROFILE(SMBmv);
}

/****************************************************************************
 Reply to a file copy.

 From MS-CIFS.

 This command was introduced in the LAN Manager 1.0 dialect
 It was rendered obsolete in the NT LAN Manager dialect.
 This command was used to perform server-side file copies, but
 is no longer used. Clients SHOULD
 NOT send requests using this command code.
 Servers receiving requests with this command code
 SHOULD return STATUS_NOT_IMPLEMENTED (ERRDOS/ERRbadfunc).
****************************************************************************/

void reply_copy(struct smb_request *req)
{
	START_PROFILE(SMBcopy);
	reply_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	END_PROFILE(SMBcopy);
	return;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Get a lock pid, dealing with large count requests.
****************************************************************************/

uint64_t get_lock_pid(const uint8_t *data, int data_offset,
		    bool large_file_format)
{
	if(!large_file_format)
		return (uint64_t)SVAL(data,SMB_LPID_OFFSET(data_offset));
	else
		return (uint64_t)SVAL(data,SMB_LARGE_LPID_OFFSET(data_offset));
}

/****************************************************************************
 Get a lock count, dealing with large count requests.
****************************************************************************/

uint64_t get_lock_count(const uint8_t *data, int data_offset,
			bool large_file_format)
{
	uint64_t count = 0;

	if(!large_file_format) {
		count = (uint64_t)IVAL(data,SMB_LKLEN_OFFSET(data_offset));
	} else {
		/*
		 * No BVAL, this is reversed!
		 */
		count = (((uint64_t) IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset))) << 32) |
			((uint64_t) IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset)));
	}

	return count;
}

/****************************************************************************
 Reply to a lockingX request.
****************************************************************************/

static void reply_lockingx_done(struct tevent_req *subreq);

void reply_lockingX(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	files_struct *fsp;
	unsigned char locktype;
	enum brl_type brltype;
	unsigned char oplocklevel;
	uint16_t num_ulocks;
	uint16_t num_locks;
	int32_t lock_timeout;
	uint16_t i;
	const uint8_t *data;
	bool large_file_format;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	struct smbd_lock_element *locks = NULL;
	struct tevent_req *subreq = NULL;

	START_PROFILE(SMBlockingX);

	if (req->wct < 8) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlockingX);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+2, 0));
	locktype = CVAL(req->vwv+3, 0);
	oplocklevel = CVAL(req->vwv+3, 1);
	num_ulocks = SVAL(req->vwv+6, 0);
	num_locks = SVAL(req->vwv+7, 0);
	lock_timeout = IVAL(req->vwv+4, 0);
	large_file_format = ((locktype & LOCKING_ANDX_LARGE_FILES) != 0);

	if (!check_fsp(conn, req, fsp)) {
		END_PROFILE(SMBlockingX);
		return;
	}

	data = req->buf;

	if (locktype & LOCKING_ANDX_CHANGE_LOCKTYPE) {
		/* we don't support these - and CANCEL_LOCK makes w2k
		   and XP reboot so I don't really want to be
		   compatible! (tridge) */
		reply_force_doserror(req, ERRDOS, ERRnoatomiclocks);
		END_PROFILE(SMBlockingX);
		return;
	}

	/* Check if this is an oplock break on a file
	   we have granted an oplock on.
	*/
	if (locktype & LOCKING_ANDX_OPLOCK_RELEASE) {
		/* Client can insist on breaking to none. */
		bool break_to_none = (oplocklevel == 0);
		bool result;

		DEBUG(5,("reply_lockingX: oplock break reply (%u) from client "
			 "for %s\n", (unsigned int)oplocklevel,
			 fsp_fnum_dbg(fsp)));

		/*
		 * Make sure we have granted an exclusive or batch oplock on
		 * this file.
		 */

		if (fsp->oplock_type == 0) {

			/* The Samba4 nbench simulator doesn't understand
			   the difference between break to level2 and break
			   to none from level2 - it sends oplock break
			   replies in both cases. Don't keep logging an error
			   message here - just ignore it. JRA. */

			DEBUG(5,("reply_lockingX: Error : oplock break from "
				 "client for %s (oplock=%d) and no "
				 "oplock granted on this file (%s).\n",
				 fsp_fnum_dbg(fsp), fsp->oplock_type,
				 fsp_str_dbg(fsp)));

			/* if this is a pure oplock break request then don't
			 * send a reply */
			if (num_locks == 0 && num_ulocks == 0) {
				END_PROFILE(SMBlockingX);
				return;
			}

			END_PROFILE(SMBlockingX);
			reply_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			return;
		}

		if ((fsp->sent_oplock_break == BREAK_TO_NONE_SENT) ||
		    (break_to_none)) {
			result = remove_oplock(fsp);
		} else {
			result = downgrade_oplock(fsp);
		}

		if (!result) {
			DEBUG(0, ("reply_lockingX: error in removing "
				  "oplock on file %s\n", fsp_str_dbg(fsp)));
			/* Hmmm. Is this panic justified? */
			smb_panic("internal tdb error");
		}

		/* if this is a pure oplock break request then don't send a
		 * reply */
		if (num_locks == 0 && num_ulocks == 0) {
			/* Sanity check - ensure a pure oplock break is not a
			   chained request. */
			if (CVAL(req->vwv+0, 0) != 0xff) {
				DEBUG(0,("reply_lockingX: Error : pure oplock "
					 "break is a chained %d request !\n",
					 (unsigned int)CVAL(req->vwv+0, 0)));
			}
			END_PROFILE(SMBlockingX);
			return;
		}
	}

	if (req->buflen <
	    (num_ulocks + num_locks) * (large_file_format ? 20 : 10)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBlockingX);
		return;
	}

	if (num_ulocks != 0) {
		struct smbd_lock_element *ulocks = NULL;
		bool ok;

		ulocks = talloc_array(
			req, struct smbd_lock_element, num_ulocks);
		if (ulocks == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBlockingX);
			return;
		}

		/*
		 * Data now points at the beginning of the list of
		 * smb_unlkrng structs
		 */
		for (i = 0; i < num_ulocks; i++) {
			ulocks[i].req_guid = smbd_request_guid(req,
				UINT16_MAX - i),
			ulocks[i].smblctx = get_lock_pid(
				data, i, large_file_format);
			ulocks[i].count = get_lock_count(
				data, i, large_file_format);
			ulocks[i].offset = get_lock_offset(
				data, i, large_file_format);
			ulocks[i].brltype = UNLOCK_LOCK;
			ulocks[i].lock_flav = WINDOWS_LOCK;
		}

		/*
		 * Unlock cancels pending locks
		 */

		ok = smbd_smb1_brl_finish_by_lock(
			fsp,
			large_file_format,
			ulocks[0],
			NT_STATUS_OK);
		if (ok) {
			reply_smb1_outbuf(req, 2, 0);
			SSVAL(req->outbuf, smb_vwv0, 0xff);
			SSVAL(req->outbuf, smb_vwv1, 0);
			END_PROFILE(SMBlockingX);
			return;
		}

		status = smbd_do_unlocking(
			req, fsp, num_ulocks, ulocks);
		TALLOC_FREE(ulocks);
		if (!NT_STATUS_IS_OK(status)) {
			END_PROFILE(SMBlockingX);
			reply_nterror(req, status);
			return;
		}
	}

	/* Now do any requested locks */
	data += ((large_file_format ? 20 : 10)*num_ulocks);

	/* Data now points at the beginning of the list
	   of smb_lkrng structs */

	if (locktype & LOCKING_ANDX_SHARED_LOCK) {
		brltype = READ_LOCK;
	} else {
		brltype = WRITE_LOCK;
	}

	locks = talloc_array(req, struct smbd_lock_element, num_locks);
	if (locks == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBlockingX);
		return;
	}

	for (i = 0; i < num_locks; i++) {
		locks[i].req_guid = smbd_request_guid(req, i),
		locks[i].smblctx = get_lock_pid(data, i, large_file_format);
		locks[i].count = get_lock_count(data, i, large_file_format);
		locks[i].offset = get_lock_offset(data, i, large_file_format);
		locks[i].brltype = brltype;
		locks[i].lock_flav = WINDOWS_LOCK;
	}

	if (locktype & LOCKING_ANDX_CANCEL_LOCK) {

		bool ok;

		if (num_locks == 0) {
			/* See smbtorture3 lock11 test */
			reply_smb1_outbuf(req, 2, 0);
			/* andx chain ends */
			SSVAL(req->outbuf, smb_vwv0, 0xff);
			SSVAL(req->outbuf, smb_vwv1, 0);
			END_PROFILE(SMBlockingX);
			return;
		}

		ok = smbd_smb1_brl_finish_by_lock(
			fsp,
			large_file_format,
			locks[0], /* Windows only cancels the first lock */
			NT_STATUS_FILE_LOCK_CONFLICT);

		if (!ok) {
			reply_force_doserror(req, ERRDOS, ERRcancelviolation);
			END_PROFILE(SMBlockingX);
			return;
		}

		reply_smb1_outbuf(req, 2, 0);
		SSVAL(req->outbuf, smb_vwv0, 0xff);
		SSVAL(req->outbuf, smb_vwv1, 0);
		END_PROFILE(SMBlockingX);
		return;
	}

	subreq = smbd_smb1_do_locks_send(
		fsp,
		req->sconn->ev_ctx,
		&req,
		fsp,
		lock_timeout,
		large_file_format,
		num_locks,
		locks);
	if (subreq == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBlockingX);
		return;
	}
	tevent_req_set_callback(subreq, reply_lockingx_done, NULL);
	END_PROFILE(SMBlockingX);
}

static void reply_lockingx_done(struct tevent_req *subreq)
{
	struct smb_request *req = NULL;
	NTSTATUS status;
	bool ok;

	START_PROFILE(SMBlockingX);

	ok = smbd_smb1_do_locks_extract_smbreq(subreq, talloc_tos(), &req);
	SMB_ASSERT(ok);

	status = smbd_smb1_do_locks_recv(subreq);
	TALLOC_FREE(subreq);

	DBG_DEBUG("smbd_smb1_do_locks_recv returned %s\n", nt_errstr(status));

	if (NT_STATUS_IS_OK(status)) {
		reply_smb1_outbuf(req, 2, 0);
		SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
		SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */
	} else {
		reply_nterror(req, status);
	}

	ok = smb1_srv_send(req->xconn,
			   (char *)req->outbuf,
			   true,
			   req->seqnum + 1,
			   IS_CONN_ENCRYPTED(req->conn));
	if (!ok) {
		exit_server_cleanly("reply_lock_done: smb1_srv_send failed.");
	}
	TALLOC_FREE(req);
	END_PROFILE(SMBlockingX);
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/****************************************************************************
 Reply to a SMBreadbmpx (read block multiplex) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_readbmpx(struct smb_request *req)
{
	START_PROFILE(SMBreadBmpx);
	reply_force_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBreadBmpx);
	return;
}

/****************************************************************************
 Reply to a SMBreadbs (read block multiplex secondary) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_readbs(struct smb_request *req)
{
	START_PROFILE(SMBreadBs);
	reply_force_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBreadBs);
	return;
}

/****************************************************************************
 Reply to a SMBsetattrE.
****************************************************************************/

void reply_setattrE(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct smb_file_time ft;
	files_struct *fsp;
	NTSTATUS status;

	START_PROFILE(SMBsetattrE);
	init_smb_file_time(&ft);

	if (req->wct < 7) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if(!fsp || (fsp->conn != conn)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		goto out;
	}

	/*
	 * Convert the DOS times into unix times.
	 */

	ft.atime = time_t_to_full_timespec(
	    srv_make_unix_date2(req->vwv+3));
	ft.mtime = time_t_to_full_timespec(
	    srv_make_unix_date2(req->vwv+5));
	ft.create_time = time_t_to_full_timespec(
	    srv_make_unix_date2(req->vwv+1));

	reply_smb1_outbuf(req, 0, 0);

	/* Ensure we have a valid stat struct for the source. */
	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = check_any_access_fsp(fsp, FILE_WRITE_ATTRIBUTES);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = smb_set_file_time(conn, fsp, fsp->fsp_name, &ft, true);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	DEBUG( 3, ( "reply_setattrE %s actime=%u modtime=%u "
	       " createtime=%u\n",
		fsp_fnum_dbg(fsp),
		(unsigned int)ft.atime.tv_sec,
		(unsigned int)ft.mtime.tv_sec,
		(unsigned int)ft.create_time.tv_sec
		));
 out:
	END_PROFILE(SMBsetattrE);
	return;
}


/* Back from the dead for OS/2..... JRA. */

/****************************************************************************
 Reply to a SMBwritebmpx (write block multiplex primary) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_writebmpx(struct smb_request *req)
{
	START_PROFILE(SMBwriteBmpx);
	reply_force_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBwriteBmpx);
	return;
}

/****************************************************************************
 Reply to a SMBwritebs (write block multiplex secondary) request.
 Always reply with an error, if someone has a platform really needs this,
 please contact vl@samba.org
****************************************************************************/

void reply_writebs(struct smb_request *req)
{
	START_PROFILE(SMBwriteBs);
	reply_force_doserror(req, ERRSRV, ERRuseSTD);
	END_PROFILE(SMBwriteBs);
	return;
}

/****************************************************************************
 Reply to a SMBgetattrE.
****************************************************************************/

void reply_getattrE(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	int mode;
	files_struct *fsp;
	struct timespec create_ts;
	NTSTATUS status;

	START_PROFILE(SMBgetattrE);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBgetattrE);
		return;
	}

	fsp = file_fsp(req, SVAL(req->vwv+0, 0));

	if(!fsp || (fsp->conn != conn)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		END_PROFILE(SMBgetattrE);
		return;
	}

	/* Do an fstat on this file */
	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		END_PROFILE(SMBgetattrE);
		return;
	}

	mode = fdos_mode(fsp);

	/*
	 * Convert the times into dos times. Set create
	 * date to be last modify date as UNIX doesn't save
	 * this.
	 */

	reply_smb1_outbuf(req, 11, 0);

	create_ts = get_create_timespec(conn, fsp, fsp->fsp_name);
	srv_put_dos_date2_ts((char *)req->outbuf, smb_vwv0, create_ts);
	srv_put_dos_date2_ts((char *)req->outbuf,
			     smb_vwv2,
			     fsp->fsp_name->st.st_ex_atime);
	/* Should we check pending modtime here ? JRA */
	srv_put_dos_date2_ts((char *)req->outbuf,
			     smb_vwv4,
			     fsp->fsp_name->st.st_ex_mtime);

	if (mode & FILE_ATTRIBUTE_DIRECTORY) {
		SIVAL(req->outbuf, smb_vwv6, 0);
		SIVAL(req->outbuf, smb_vwv8, 0);
	} else {
		uint32_t allocation_size = SMB_VFS_GET_ALLOC_SIZE(conn,fsp, &fsp->fsp_name->st);
		SIVAL(req->outbuf, smb_vwv6, (uint32_t)fsp->fsp_name->st.st_ex_size);
		SIVAL(req->outbuf, smb_vwv8, allocation_size);
	}
	SSVAL(req->outbuf,smb_vwv10, mode);

	DEBUG( 3, ( "reply_getattrE %s\n", fsp_fnum_dbg(fsp)));

	END_PROFILE(SMBgetattrE);
	return;
}

/****************************************************************************
 Reply to a SMBfindclose (stop trans2 directory search).
****************************************************************************/

void reply_findclose(struct smb_request *req)
{
	int dptr_num;
	struct smbd_server_connection *sconn = req->sconn;
	files_struct *fsp = NULL;

	START_PROFILE(SMBfindclose);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBfindclose);
		return;
	}

	dptr_num = SVALS(req->vwv+0, 0);

	DEBUG(3,("reply_findclose, dptr_num = %d\n", dptr_num));

	/*
	 * OS/2 seems to use -1 to indicate "close all directories"
	 * This has to mean on this specific connection struct.
	 */
	if (dptr_num == -1) {
		dptr_closecnum(req->conn);
	} else {
		fsp = dptr_fetch_lanman2_fsp(sconn, dptr_num);
		dptr_num = -1;
		if (fsp != NULL) {
			close_file_free(NULL, &fsp, NORMAL_CLOSE);
		}
	}

	reply_smb1_outbuf(req, 0, 0);

	DEBUG(3,("SMBfindclose dptr_num = %d\n", dptr_num));

	END_PROFILE(SMBfindclose);
	return;
}

/****************************************************************************
 Reply to a SMBfindnclose (stop FINDNOTIFYFIRST directory search).
****************************************************************************/

void reply_findnclose(struct smb_request *req)
{
	int dptr_num;

	START_PROFILE(SMBfindnclose);

	if (req->wct < 1) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBfindnclose);
		return;
	}

	dptr_num = SVAL(req->vwv+0, 0);

	DEBUG(3,("reply_findnclose, dptr_num = %d\n", dptr_num));

	/* We never give out valid handles for a
	   findnotifyfirst - so any dptr_num is ok here.
	   Just ignore it. */

	reply_smb1_outbuf(req, 0, 0);

	DEBUG(3,("SMB_findnclose dptr_num = %d\n", dptr_num));

	END_PROFILE(SMBfindnclose);
	return;
}
