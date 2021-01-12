/* 
   Unix SMB/CIFS implementation.
   service (connection) opening and closing
   Copyright (C) Andrew Tridgell 1992-1998

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
#include "system/filesys.h"
#include "system/passwd.h" /* uid_wrapper */
#include "../lib/tsocket/tsocket.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "../libcli/security/security.h"
#include "printing/pcap.h"
#include "passdb/lookup_sid.h"
#include "auth.h"
#include "../auth/auth_util.h"
#include "lib/param/loadparm.h"
#include "messages.h"
#include "lib/afs/afs_funcs.h"
#include "lib/util_path.h"

bool canonicalize_connect_path(connection_struct *conn)
{
	bool ret;
	struct smb_filename con_fname = { .base_name = conn->connectpath };
	struct smb_filename *resolved_fname = SMB_VFS_REALPATH(conn, talloc_tos(),
						&con_fname);
	if (resolved_fname == NULL) {
		return false;
	}
	ret = set_conn_connectpath(conn,resolved_fname->base_name);
	TALLOC_FREE(resolved_fname);
	return ret;
}

/****************************************************************************
 Ensure when setting connectpath it is a canonicalized (no ./ // or ../)
 absolute path stating in / and not ending in /.
****************************************************************************/

bool set_conn_connectpath(connection_struct *conn, const char *connectpath)
{
	char *destname;

	if (connectpath == NULL || connectpath[0] == '\0') {
		return false;
	}

	destname = canonicalize_absolute_path(conn, connectpath);
	if (destname == NULL) {
		return false;
	}

	DBG_DEBUG("service %s, connectpath = %s\n",
		  lp_const_servicename(SNUM(conn)), destname);

	talloc_free(conn->connectpath);
	conn->connectpath = destname;
	/*
	 * Ensure conn->cwd_fsp->fsp_name is initialized.
	 * start as conn->connectpath.
	 */
	TALLOC_FREE(conn->cwd_fsp->fsp_name);
	conn->cwd_fsp->fsp_name = synthetic_smb_fname(conn,
				conn->connectpath,
				NULL,
				NULL,
				0,
				0);
	if (conn->cwd_fsp->fsp_name == NULL) {
		return false;
	}
	return true;
}

/****************************************************************************
 Load parameters specific to a connection/service.
****************************************************************************/

void set_current_case_sensitive(connection_struct *conn, uint16_t flags)
{
	int snum;
	enum remote_arch_types ra_type;

	SMB_ASSERT(conn != NULL);

	snum = SNUM(conn);

	if ((conn == last_conn) && (last_flags == flags)) {
		return;
	}

	last_conn = conn;
	last_flags = flags;

	/*
	 * Obey the client case sensitivity requests - only for clients that
	 * support it. */
	switch (lp_case_sensitive(snum)) {
	case Auto:
		/*
		 * We need this uglyness due to DOS/Win9x clients that lie
		 * about case insensitivity. */
		ra_type = get_remote_arch();
		if (conn->sconn->using_smb2) {
			conn->case_sensitive = false;
		} else if ((ra_type != RA_SAMBA) && (ra_type != RA_CIFSFS)) {
			/*
			 * Client can't support per-packet case sensitive
			 * pathnames. */
			conn->case_sensitive = false;
		} else {
			conn->case_sensitive =
					!(flags & FLAG_CASELESS_PATHNAMES);
		}
	break;
	case True:
		conn->case_sensitive = true;
		break;
	default:
		conn->case_sensitive = false;
		break;
	}
	return;
}

bool chdir_current_service(connection_struct *conn)
{
	const struct smb_filename connectpath_fname = {
		.base_name = conn->connectpath,
	};
	int saved_errno = 0;
	char *utok_str = NULL;
	int ret;

	conn->lastused_count++;

	ret = vfs_ChDir(conn, &connectpath_fname);
	if (ret == 0) {
		return true;
	}
	saved_errno = errno;

	utok_str = utok_string(talloc_tos(),
			       conn->session_info->unix_token);
	if (utok_str == NULL) {
		errno = saved_errno;
		return false;
	}

	DBG_ERR("vfs_ChDir(%s) failed: %s. Current token: %s\n",
		conn->connectpath,
		strerror(saved_errno),
		utok_str);

	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return false;
}

/****************************************************************************
 do some basic sainity checks on the share.  
 This function modifies dev, ecode.
****************************************************************************/

static NTSTATUS share_sanity_checks(const struct tsocket_address *remote_address,
				    const char *rhost,
				    int snum,
				    fstring dev)
{
	char *raddr;

	raddr = tsocket_address_inet_addr_string(remote_address,
						 talloc_tos());
	if (raddr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!lp_snum_ok(snum) ||
	    !allow_access(lp_hosts_deny(snum), lp_hosts_allow(snum),
			  rhost, raddr)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (dev[0] == '?' || !dev[0]) {
		if (lp_printable(snum)) {
			fstrcpy(dev,"LPT1:");
		} else if (strequal(lp_fstype(snum), "IPC")) {
			fstrcpy(dev, "IPC");
		} else {
			fstrcpy(dev,"A:");
		}
	}

	if (!strupper_m(dev)) {
		DEBUG(2,("strupper_m %s failed\n", dev));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (lp_printable(snum)) {
		if (!strequal(dev, "LPT1:")) {
			return NT_STATUS_BAD_DEVICE_TYPE;
		}
	} else if (strequal(lp_fstype(snum), "IPC")) {
		if (!strequal(dev, "IPC")) {
			return NT_STATUS_BAD_DEVICE_TYPE;
		}
	} else if (!strequal(dev, "A:")) {
		return NT_STATUS_BAD_DEVICE_TYPE;
	}

	/* Behave as a printer if we are supposed to */
	if (lp_printable(snum) && (strcmp(dev, "A:") == 0)) {
		fstrcpy(dev, "LPT1:");
	}

	return NT_STATUS_OK;
}

/*
 * Go through lookup_name etc to find the force'd group.  
 *
 * Create a new token from src_token, replacing the primary group sid with the
 * one found.
 */

static NTSTATUS find_forced_group(bool force_user,
				  int snum, const char *username,
				  struct dom_sid *pgroup_sid,
				  gid_t *pgid)
{
	NTSTATUS result = NT_STATUS_NO_SUCH_GROUP;
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct dom_sid group_sid;
	enum lsa_SidType type;
	char *groupname;
	bool user_must_be_member = False;
	gid_t gid;

	groupname = lp_force_group(talloc_tos(), lp_sub, snum);
	if (groupname == NULL) {
		DEBUG(1, ("talloc_strdup failed\n"));
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (groupname[0] == '+') {
		user_must_be_member = True;
		groupname += 1;
	}

	groupname = talloc_string_sub(talloc_tos(), groupname,
				      "%S", lp_const_servicename(snum));
	if (groupname == NULL) {
		DEBUG(1, ("talloc_string_sub failed\n"));
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (!lookup_name_smbconf(talloc_tos(), groupname,
			 LOOKUP_NAME_ALL|LOOKUP_NAME_GROUP,
			 NULL, NULL, &group_sid, &type)) {
		DEBUG(10, ("lookup_name_smbconf(%s) failed\n",
			   groupname));
		goto done;
	}

	if ((type != SID_NAME_DOM_GRP) && (type != SID_NAME_ALIAS) &&
	    (type != SID_NAME_WKN_GRP)) {
		DEBUG(10, ("%s is a %s, not a group\n", groupname,
			   sid_type_lookup(type)));
		goto done;
	}

	if (!sid_to_gid(&group_sid, &gid)) {
		struct dom_sid_buf buf;
		DEBUG(10, ("sid_to_gid(%s) for %s failed\n",
			   dom_sid_str_buf(&group_sid, &buf), groupname));
		goto done;
	}

	/*
	 * If the user has been forced and the forced group starts with a '+',
	 * then we only set the group to be the forced group if the forced
	 * user is a member of that group.  Otherwise, the meaning of the '+'
	 * would be ignored.
	 */

	if (force_user && user_must_be_member) {
		if (user_in_group_sid(username, &group_sid)) {
			sid_copy(pgroup_sid, &group_sid);
			*pgid = gid;
			DEBUG(3,("Forced group %s for member %s\n",
				 groupname, username));
		} else {
			DEBUG(0,("find_forced_group: forced user %s is not a member "
				"of forced group %s. Disallowing access.\n",
				username, groupname ));
			result = NT_STATUS_MEMBER_NOT_IN_GROUP;
			goto done;
		}
	} else {
		sid_copy(pgroup_sid, &group_sid);
		*pgid = gid;
		DEBUG(3,("Forced group %s\n", groupname));
	}

	result = NT_STATUS_OK;
 done:
	TALLOC_FREE(frame);
	return result;
}

/****************************************************************************
  Create an auth_session_info structure for a connection_struct
****************************************************************************/

static NTSTATUS create_connection_session_info(struct smbd_server_connection *sconn,
					      TALLOC_CTX *mem_ctx, int snum,
                                              struct auth_session_info *session_info,
                                              struct auth_session_info **presult)
{
	struct auth_session_info *result;

        if (lp_guest_only(snum)) {
                return make_session_info_guest(mem_ctx, presult);
        }

	/*
	 * This is the normal security != share case where we have a
	 * valid vuid from the session setup.                 */

	if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
		if (!lp_guest_ok(snum)) {
			DBG_WARNING("guest user (from session setup) "
				  "not permitted to access this share "
				  "(%s)\n", lp_const_servicename(snum));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else {
		if (!user_ok_token(session_info->unix_info->unix_name,
				   session_info->info->domain_name,
				   session_info->security_token, snum)) {
			DBG_WARNING("user '%s' (from session setup) not "
				  "permitted to access this share "
				  "(%s)\n",
				  session_info->unix_info->unix_name,
				  lp_const_servicename(snum));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	result = copy_session_info(mem_ctx, session_info);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*presult = result;
	return NT_STATUS_OK;
}

/****************************************************************************
  Set relevant user and group settings corresponding to force user/group
  configuration for the given snum.
****************************************************************************/

NTSTATUS set_conn_force_user_group(connection_struct *conn, int snum)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	NTSTATUS status;

	if (*lp_force_user(talloc_tos(), lp_sub, snum)) {

		/*
		 * Replace conn->session_info with a completely faked up one
		 * from the username we are forced into :-)
		 */

		char *fuser;
		char *sanitized_username;
		struct auth_session_info *forced_serverinfo;
		bool guest;

		fuser = talloc_string_sub(conn, lp_force_user(talloc_tos(), lp_sub, snum), "%S",
					  lp_const_servicename(snum));
		if (fuser == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		guest = security_session_user_level(conn->session_info, NULL) < SECURITY_USER;

		status = make_session_info_from_username(
			conn, fuser,
			guest,
			&forced_serverinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* We don't want to replace the original sanitized_username
		   as it is the original user given in the connect attempt.
		   This is used in '%U' substitutions. */
		sanitized_username = discard_const_p(char,
			forced_serverinfo->unix_info->sanitized_username);
		TALLOC_FREE(sanitized_username);
		forced_serverinfo->unix_info->sanitized_username =
			talloc_move(forced_serverinfo->unix_info,
				&conn->session_info->unix_info->sanitized_username);

		TALLOC_FREE(conn->session_info);
		conn->session_info = forced_serverinfo;

		conn->force_user = true;
		DEBUG(3,("Forced user %s\n", fuser));
	}

	/*
	 * If force group is true, then override
	 * any groupid stored for the connecting user.
	 */

	if (*lp_force_group(talloc_tos(), lp_sub, snum)) {

		status = find_forced_group(
			conn->force_user, snum, conn->session_info->unix_info->unix_name,
			&conn->session_info->security_token->sids[1],
			&conn->session_info->unix_token->gid);

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/*
		 * We need to cache this gid, to use within
		 * change_to_user() separately from the conn->session_info
		 * struct. We only use conn->session_info directly if
		 * "force_user" was set.
		 */
		conn->force_group_gid = conn->session_info->unix_token->gid;
	}

	return NT_STATUS_OK;
}

static NTSTATUS notify_init_sconn(struct smbd_server_connection *sconn)
{
	NTSTATUS status;

	if (sconn->notify_ctx != NULL) {
		return NT_STATUS_OK;
	}

	sconn->notify_ctx = notify_init(sconn, sconn->msg_ctx,
					sconn, notify_callback);
	if (sconn->notify_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = messaging_register(sconn->msg_ctx, sconn,
				    MSG_SMB_NOTIFY_CANCEL_DELETED,
				    smbd_notify_cancel_deleted);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("messaging_register failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(sconn->notify_ctx);
		return status;
	}

	status = messaging_register(sconn->msg_ctx, sconn,
				    MSG_SMB_NOTIFY_STARTED,
				    smbd_notifyd_restarted);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("messaging_register failed: %s\n",
			  nt_errstr(status));
		messaging_deregister(sconn->msg_ctx,
				     MSG_SMB_NOTIFY_CANCEL_DELETED, sconn);
		TALLOC_FREE(sconn->notify_ctx);
		return status;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
  Make a connection, given the snum to connect to, and the vuser of the
  connecting user if appropriate.
****************************************************************************/

static NTSTATUS make_connection_snum(struct smbXsrv_connection *xconn,
					connection_struct *conn,
					int snum,
					struct smbXsrv_session *session,
					const char *pdev)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct smb_filename *smb_fname_cpath = NULL;
	fstring dev;
	int ret;
	bool on_err_call_dis_hook = false;
	uid_t effuid;
	gid_t effgid;
	NTSTATUS status;
	bool ok;

	fstrcpy(dev, pdev);

	status = share_sanity_checks(sconn->remote_address,
				       sconn->remote_hostname,
				       snum,
				       dev);
	if (NT_STATUS_IS_ERR(status)) {
		goto err_root_exit;
	}

	conn->params->service = snum;

	status = create_connection_session_info(sconn,
		conn, snum, session->global->auth_session_info,
		&conn->session_info);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("create_connection_session_info failed: %s\n",
			  nt_errstr(status)));
		goto err_root_exit;
	}

	if (lp_guest_only(snum)) {
		conn->force_user = true;
	}

	conn->num_files_open = 0;
	conn->lastused = conn->lastused_count = time(NULL);
	conn->printer = (strncmp(dev,"LPT",3) == 0);
	conn->ipc = ( (strncmp(dev,"IPC",3) == 0) ||
		      ( lp_enable_asu_support() && strequal(dev,"ADMIN$")) );

	/* Case options for the share. */
	conn_setup_case_options(conn);

	conn->encrypt_level = lp_smb_encrypt(snum);
	if (conn->encrypt_level > SMB_SIGNING_OFF) {
		if (lp_smb_encrypt(-1) == SMB_SIGNING_OFF) {
			if (conn->encrypt_level == SMB_SIGNING_REQUIRED) {
				DBG_ERR("Service [%s] requires encryption, but "
					"it is disabled globally!\n",
					lp_const_servicename(snum));
				status = NT_STATUS_ACCESS_DENIED;
				goto err_root_exit;
			}
			conn->encrypt_level = SMB_SIGNING_OFF;
		}
	}

	conn->veto_list = NULL;
	conn->hide_list = NULL;
	conn->veto_oplock_list = NULL;
	conn->aio_write_behind_list = NULL;

	conn->read_only = lp_read_only(SNUM(conn));

	status = set_conn_force_user_group(conn, snum);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_root_exit;
	}

	conn->vuid = session->global->session_wire_id;

	{
		char *s = talloc_sub_full(talloc_tos(),
					lp_const_servicename(SNUM(conn)),
					conn->session_info->unix_info->unix_name,
					conn->connectpath,
					conn->session_info->unix_token->gid,
					conn->session_info->unix_info->sanitized_username,
					conn->session_info->info->domain_name,
					lp_path(talloc_tos(), lp_sub, snum));
		if (!s) {
			status = NT_STATUS_NO_MEMORY;
			goto err_root_exit;
		}

		if (!set_conn_connectpath(conn,s)) {
			TALLOC_FREE(s);
			status = NT_STATUS_NO_MEMORY;
			goto err_root_exit;
		}
		DBG_NOTICE("Connect path is '%s' for service [%s]\n", s,
			   lp_const_servicename(snum));
		TALLOC_FREE(s);
	}

	/*
	 * Set up the share security descriptor.
	 * NOTE - we use the *INCOMING USER* session_info
	 * here, as does (indirectly) change_to_user(),
	 * which can be called on any incoming packet.
	 * This way we set up the share access based
	 * on the authenticated user, not the forced
	 * user. See bug:
	 *
	 * https://bugzilla.samba.org/show_bug.cgi?id=9878
	 */

	status = check_user_share_access(conn,
					session->global->auth_session_info,
					&conn->share_access,
					&conn->read_only);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_root_exit;
	}

	/* Initialise VFS function pointers */

	if (!smbd_vfs_init(conn)) {
		DBG_ERR("vfs_init failed for service %s\n",
			lp_const_servicename(snum));
		status = NT_STATUS_BAD_NETWORK_NAME;
		goto err_root_exit;
	}

/* ROOT Activities: */
	/* explicitly check widelinks here so that we can correctly warn
	 * in the logs. */
	widelinks_warning(snum);

	/*
	 * Enforce the max connections parameter.
	 */

	if ((lp_max_connections(snum) > 0)
	    && (count_current_connections(lp_const_servicename(SNUM(conn)), true) >=
		lp_max_connections(snum))) {

		DBG_WARNING("Max connections (%d) exceeded for %s\n",
			  lp_max_connections(snum),
			  lp_const_servicename(snum));
		status = NT_STATUS_INSUFFICIENT_RESOURCES;
		goto err_root_exit;
	}

	/* Invoke VFS make connection hook - this must be the first
	   filesystem operation that we do. */

	if (SMB_VFS_CONNECT(conn, lp_const_servicename(snum),
			    conn->session_info->unix_info->unix_name) < 0) {
		DBG_WARNING("SMB_VFS_CONNECT for service '%s' at '%s' failed: %s\n",
			    lp_const_servicename(snum), conn->connectpath,
			    strerror(errno));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_root_exit;
	}

	/* Any error exit after here needs to call the disconnect hook. */
	on_err_call_dis_hook = true;

	if ((!conn->printer) && (!conn->ipc) &&
	    lp_change_notify()) {

		status = notify_init_sconn(sconn);
		if (!NT_STATUS_IS_OK(status)) {
			goto err_root_exit;
		}
	}

	if (lp_kernel_oplocks(snum)) {
		init_kernel_oplocks(conn->sconn);
	}

	/*
	 * Fix compatibility issue pointed out by Volker.
	 * We pass the conn->connectpath to the preexec
	 * scripts as a parameter, so attempt to canonicalize
	 * it here before calling the preexec scripts.
	 * We ignore errors here, as it is possible that
	 * the conn->connectpath doesn't exist yet and
	 * the preexec scripts will create them.
	 */

	(void)canonicalize_connect_path(conn);

	/* Preexecs are done here as they might make the dir we are to ChDir
	 * to below */
	/* execute any "root preexec = " line */
	if (*lp_root_preexec(talloc_tos(), lp_sub, snum)) {
		char *cmd = talloc_sub_full(talloc_tos(),
					lp_const_servicename(SNUM(conn)),
					conn->session_info->unix_info->unix_name,
					conn->connectpath,
					conn->session_info->unix_token->gid,
					conn->session_info->unix_info->sanitized_username,
					conn->session_info->info->domain_name,
					lp_root_preexec(talloc_tos(), lp_sub, snum));
		DEBUG(5,("cmd=%s\n",cmd));
		ret = smbrun(cmd, NULL, NULL);
		TALLOC_FREE(cmd);
		if (ret != 0 && lp_root_preexec_close(snum)) {
			DEBUG(1,("root preexec gave %d - failing "
				 "connection\n", ret));
			status = NT_STATUS_ACCESS_DENIED;
			goto err_root_exit;
		}
	}

/* USER Activites: */
	if (!change_to_user_and_service(conn, conn->vuid)) {
		/* No point continuing if they fail the basic checks */
		DEBUG(0,("Can't become connected user!\n"));
		status = NT_STATUS_LOGON_FAILURE;
		goto err_root_exit;
	}

	effuid = geteuid();
	effgid = getegid();

	/* Remember that a different vuid can connect later without these
	 * checks... */

	/* Preexecs are done here as they might make the dir we are to ChDir
	 * to below */

	/* execute any "preexec = " line */
	if (*lp_preexec(talloc_tos(), lp_sub, snum)) {
		char *cmd = talloc_sub_full(talloc_tos(),
					lp_const_servicename(SNUM(conn)),
					conn->session_info->unix_info->unix_name,
					conn->connectpath,
					conn->session_info->unix_token->gid,
					conn->session_info->unix_info->sanitized_username,
					conn->session_info->info->domain_name,
					lp_preexec(talloc_tos(), lp_sub, snum));
		ret = smbrun(cmd, NULL, NULL);
		TALLOC_FREE(cmd);
		if (ret != 0 && lp_preexec_close(snum)) {
			DEBUG(1,("preexec gave %d - failing connection\n",
				 ret));
			status = NT_STATUS_ACCESS_DENIED;
			goto err_root_exit;
		}
	}

#ifdef WITH_FAKE_KASERVER
	if (lp_afs_share(snum)) {
		afs_login(conn);
	}
#endif

	/*
	 * we've finished with the user stuff - go back to root
	 * so the SMB_VFS_STAT call will only fail on path errors,
	 * not permission problems.
	 */
	change_to_root_user();
/* ROOT Activites: */

	/*
	 * Canonicalise the connect
	 * path here to ensure we don't have any symlinks in the
	 * connectpath. We will be checking all paths on this connection are
	 * below this directory. We must do this after the VFS init as we
	 * depend on the realpath() pointer in the vfs table. JRA.
	 */
	ok = canonicalize_connect_path(conn);
	if (!ok) {
		DBG_ERR("canonicalize_connect_path failed "
		"for service %s, path %s\n",
			lp_const_servicename(snum),
			conn->connectpath);
		status = NT_STATUS_BAD_NETWORK_NAME;
		goto err_root_exit;
	}

	/* Add veto/hide lists */
	if (!IS_IPC(conn) && !IS_PRINT(conn)) {
		set_namearray( &conn->veto_list,
			       lp_veto_files(talloc_tos(), lp_sub, snum));
		set_namearray( &conn->hide_list,
			       lp_hide_files(talloc_tos(), lp_sub, snum));
		set_namearray( &conn->veto_oplock_list,
			       lp_veto_oplock_files(talloc_tos(), lp_sub, snum));
		set_namearray( &conn->aio_write_behind_list,
				lp_aio_write_behind(talloc_tos(), lp_sub, snum));
	}
	smb_fname_cpath = synthetic_smb_fname(talloc_tos(),
					conn->connectpath,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname_cpath == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_root_exit;
	}

	/* win2000 does not check the permissions on the directory
	   during the tree connect, instead relying on permission
	   check during individual operations. To match this behaviour
	   I have disabled this chdir check (tridge) */
	/* the alternative is just to check the directory exists */

	if ((ret = SMB_VFS_STAT(conn, smb_fname_cpath)) != 0 ||
	    !S_ISDIR(smb_fname_cpath->st.st_ex_mode)) {
		if (ret == 0 && !S_ISDIR(smb_fname_cpath->st.st_ex_mode)) {
			DBG_ERR("'%s' is not a directory, when connecting to "
				 "[%s]\n", conn->connectpath,
				 lp_const_servicename(snum));
		} else {
			DBG_ERR("'%s' does not exist or permission denied "
				 "when connecting to [%s] Error was %s\n",
				 conn->connectpath,
				 lp_const_servicename(snum),
				 strerror(errno));
		}
		status = NT_STATUS_BAD_NETWORK_NAME;
		goto err_root_exit;
	}
	conn->base_share_dev = smb_fname_cpath->st.st_ex_dev;

	/* Figure out the characteristics of the underlying filesystem. This
	 * assumes that all the filesystem mounted within a share path have
	 * the same characteristics, which is likely but not guaranteed.
	 */

	conn->fs_capabilities = SMB_VFS_FS_CAPABILITIES(conn, &conn->ts_res);

	/*
	 * Print out the 'connected as' stuff here as we need
	 * to know the effective uid and gid we will be using
	 * (at least initially).
	 */

	if( DEBUGLVL( IS_IPC(conn) ? 3 : 2 ) ) {
		dbgtext( "%s (%s) ", get_remote_machine_name(),
			 tsocket_address_string(conn->sconn->remote_address,
						talloc_tos()) );
		dbgtext( "%s", srv_is_signing_active(xconn) ? "signed " : "");
		dbgtext( "connect to service %s ",
			 lp_const_servicename(snum) );
		dbgtext( "initially as user %s ",
			 conn->session_info->unix_info->unix_name );
		dbgtext( "(uid=%d, gid=%d) ", (int)effuid, (int)effgid );
		dbgtext( "(pid %d)\n", (int)getpid() );
	}

	conn->tcon_done = true;
	return NT_STATUS_OK;

  err_root_exit:

	TALLOC_FREE(smb_fname_cpath);
	/* We must exit this function as root. */
	if (geteuid() != 0) {
		change_to_root_user();
	}
	if (on_err_call_dis_hook) {
		/* Call VFS disconnect hook */
		SMB_VFS_DISCONNECT(conn);
	}
	return status;
}

/****************************************************************************
 Make a connection to a service from SMB1. Internal interface.
****************************************************************************/

static connection_struct *make_connection_smb1(struct smb_request *req,
					NTTIME now,
					int snum,
					const char *pdev,
					NTSTATUS *pstatus)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct smbXsrv_tcon *tcon;
	NTSTATUS status;
	struct connection_struct *conn;

	status = smb1srv_tcon_create(req->xconn, now, &tcon);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("make_connection_smb1: Couldn't find free tcon %s.\n",
			 nt_errstr(status)));
		*pstatus = status;
		return NULL;
	}

	conn = conn_new(req->sconn);
	if (!conn) {
		TALLOC_FREE(tcon);

		DEBUG(0,("make_connection_smb1: Couldn't find free connection.\n"));
		*pstatus = NT_STATUS_INSUFFICIENT_RESOURCES;
		return NULL;
	}

	conn->cnum = tcon->global->tcon_wire_id;
	conn->tcon = tcon;

	*pstatus = make_connection_snum(req->xconn,
					conn,
					snum,
					req->session,
					pdev);
	if (!NT_STATUS_IS_OK(*pstatus)) {
		conn_free(conn);
		TALLOC_FREE(tcon);
		return NULL;
	}

	tcon->global->share_name = lp_servicename(tcon->global, lp_sub, SNUM(conn));
	if (tcon->global->share_name == NULL) {
		conn_free(conn);
		TALLOC_FREE(tcon);
		*pstatus = NT_STATUS_NO_MEMORY;
		return NULL;
	}
	tcon->global->session_global_id =
		req->session->global->session_global_id;

	tcon->compat = talloc_move(tcon, &conn);
	tcon->status = NT_STATUS_OK;

	*pstatus = smbXsrv_tcon_update(tcon);
	if (!NT_STATUS_IS_OK(*pstatus)) {
		TALLOC_FREE(tcon);
		return NULL;
	}

	return tcon->compat;
}

/****************************************************************************
 Make a connection to a service from SMB2. External SMB2 interface.
 We must set cnum before claiming connection.
****************************************************************************/

connection_struct *make_connection_smb2(struct smbd_smb2_request *req,
					struct smbXsrv_tcon *tcon,
					int snum,
					const char *pdev,
					NTSTATUS *pstatus)
{
	struct smbd_server_connection *sconn = req->sconn;
	connection_struct *conn = conn_new(sconn);
	if (!conn) {
		DEBUG(0,("make_connection_smb2: Couldn't find free connection.\n"));
		*pstatus = NT_STATUS_INSUFFICIENT_RESOURCES;
		return NULL;
	}

	conn->cnum = tcon->global->tcon_wire_id;
	conn->tcon = tcon;

	*pstatus = make_connection_snum(req->xconn,
					conn,
					snum,
					req->session,
					pdev);
	if (!NT_STATUS_IS_OK(*pstatus)) {
		conn_free(conn);
		return NULL;
	}
	return conn;
}

/****************************************************************************
 Make a connection to a service. External SMB1 interface.
 *
 * @param service 
****************************************************************************/

connection_struct *make_connection(struct smb_request *req,
				   NTTIME now,
				   const char *service_in,
				   const char *pdev, uint64_t vuid,
				   NTSTATUS *status)
{
	struct smbd_server_connection *sconn = req->sconn;
	struct smbXsrv_session *session = req->session;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	uid_t euid;
	char *service = NULL;
	fstring dev;
	int snum = -1;

	fstrcpy(dev, pdev);

	/* This must ONLY BE CALLED AS ROOT. As it exits this function as
	 * root. */
	if (!non_root_mode() && (euid = geteuid()) != 0) {
		DEBUG(0,("make_connection: PANIC ERROR. Called as nonroot "
			 "(%u)\n", (unsigned int)euid ));
		smb_panic("make_connection: PANIC ERROR. Called as nonroot\n");
	}

	if (conn_num_open(sconn) > 2047) {
		*status = NT_STATUS_INSUFF_SERVER_RESOURCES;
		return NULL;
	}

	if (session == NULL) {
		DEBUG(1,("make_connection: refusing to connect with "
			 "no session setup\n"));
		*status = NT_STATUS_ACCESS_DENIED;
		return NULL;
	}

	/* Logic to try and connect to the correct [homes] share, preferably
	   without too many getpwnam() lookups.  This is particulary nasty for
	   winbind usernames, where the share name isn't the same as unix
	   username.
	*/

	if (strequal(service_in,HOMES_NAME)) {
		if (session->homes_snum == -1) {
			DEBUG(2, ("[homes] share not available for "
				  "this user because it was not found "
				  "or created at session setup "
				  "time\n"));
			*status = NT_STATUS_BAD_NETWORK_NAME;
			return NULL;
		}
		DEBUG(5, ("making a connection to [homes] service "
			  "created at session setup time\n"));
		return make_connection_smb1(req, now,
					    session->homes_snum,
					    dev, status);
	} else if ((session->homes_snum != -1)
		   && strequal(service_in,
			       lp_const_servicename(session->homes_snum))) {
		DEBUG(5, ("making a connection to 'homes' service [%s] "
			  "created at session setup time\n", service_in));
		return make_connection_smb1(req, now,
					    session->homes_snum,
					    dev, status);
	}

	service = talloc_strdup(talloc_tos(), service_in);
	if (!service) {
		*status = NT_STATUS_NO_MEMORY;
		return NULL;
	}

	if (!strlower_m(service)) {
		DEBUG(2, ("strlower_m %s failed\n", service));
		*status = NT_STATUS_INVALID_PARAMETER;
		return NULL;
	}

	snum = find_service(talloc_tos(), service, &service);
	if (!service) {
		*status = NT_STATUS_NO_MEMORY;
		return NULL;
	}

	if (snum < 0) {
		if (strequal(service,"IPC$") ||
		    (lp_enable_asu_support() && strequal(service,"ADMIN$"))) {
			DEBUG(3,("refusing IPC connection to %s\n", service));
			*status = NT_STATUS_ACCESS_DENIED;
			return NULL;
		}

		DEBUG(3,("%s (%s) couldn't find service %s\n",
			get_remote_machine_name(),
			tsocket_address_string(
				sconn->remote_address, talloc_tos()),
			service));
		*status = NT_STATUS_BAD_NETWORK_NAME;
		return NULL;
	}

	/* Handle non-Dfs clients attempting connections to msdfs proxy */
	if (lp_host_msdfs() && (*lp_msdfs_proxy(talloc_tos(), lp_sub, snum) != '\0'))  {
		DEBUG(3, ("refusing connection to dfs proxy share '%s' "
			  "(pointing to %s)\n", 
			service, lp_msdfs_proxy(talloc_tos(), lp_sub, snum)));
		*status = NT_STATUS_BAD_NETWORK_NAME;
		return NULL;
	}

	DEBUG(5, ("making a connection to 'normal' service %s\n", service));

	return make_connection_smb1(req, now, snum,
				    dev, status);
}

/****************************************************************************
 Close a cnum.
****************************************************************************/

void close_cnum(connection_struct *conn, uint64_t vuid)
{
	char rootpath[2] = { '/', '\0'};
	struct smb_filename root_fname = { .base_name = rootpath };
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	file_close_conn(conn);

	change_to_root_user();

	DEBUG(IS_IPC(conn)?3:2, ("%s (%s) closed connection to service %s\n",
				 get_remote_machine_name(),
				 tsocket_address_string(conn->sconn->remote_address,
							talloc_tos()),
				 lp_const_servicename(SNUM(conn))));

	/* make sure we leave the directory available for unmount */
	vfs_ChDir(conn, &root_fname);

	/* Call VFS disconnect hook */
	SMB_VFS_DISCONNECT(conn);

	/* execute any "postexec = " line */
	if (*lp_postexec(talloc_tos(), lp_sub, SNUM(conn)) &&
	    change_to_user_and_service(conn, vuid))  {
		char *cmd = talloc_sub_full(talloc_tos(),
					lp_const_servicename(SNUM(conn)),
					conn->session_info->unix_info->unix_name,
					conn->connectpath,
					conn->session_info->unix_token->gid,
					conn->session_info->unix_info->sanitized_username,
					conn->session_info->info->domain_name,
					lp_postexec(talloc_tos(), lp_sub, SNUM(conn)));
		smbrun(cmd, NULL, NULL);
		TALLOC_FREE(cmd);
		change_to_root_user();
	}

	change_to_root_user();
	/* execute any "root postexec = " line */
	if (*lp_root_postexec(talloc_tos(), lp_sub, SNUM(conn)))  {
		char *cmd = talloc_sub_full(talloc_tos(),
					lp_const_servicename(SNUM(conn)),
					conn->session_info->unix_info->unix_name,
					conn->connectpath,
					conn->session_info->unix_token->gid,
					conn->session_info->unix_info->sanitized_username,
					conn->session_info->info->domain_name,
					lp_root_postexec(talloc_tos(), lp_sub, SNUM(conn)));
		smbrun(cmd, NULL, NULL);
		TALLOC_FREE(cmd);
	}

	conn_free(conn);
}
