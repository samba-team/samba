/*
   Unix SMB/Netbios implementation.
   Version 3.0
   MSDFS services for Samba
   Copyright (C) Shirish Kalele 2000
   Copyright (C) Jeremy Allison 2007
   Copyright (C) Robin McCorkell 2015

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

#define DBGC_CLASS DBGC_MSDFS
#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "msdfs.h"
#include "auth.h"
#include "../auth/auth_util.h"
#include "lib/param/loadparm.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_dfsblobs.h"
#include "lib/tsocket/tsocket.h"

/**********************************************************************
 Parse a DFS pathname of the form \hostname\service\reqpath
 into the dfs_path structure.
 If POSIX pathnames is true, the pathname may also be of the
 form /hostname/service/reqpath.
 We cope with either here.

 Unfortunately, due to broken clients who might set the
 SVAL(inbuf,smb_flg2) & FLAGS2_DFS_PATHNAMES bit and then
 send a local path, we have to cope with that too....

 If conn != NULL then ensure the provided service is
 the one pointed to by the connection.

 This version does everything using pointers within one copy of the
 pathname string, talloced on the struct dfs_path pointer (which
 must be talloced). This may be too clever to live....
 JRA.
**********************************************************************/

static NTSTATUS parse_dfs_path(connection_struct *conn,
				const char *pathname,
				bool allow_wcards,
				bool allow_broken_path,
				struct dfs_path *pdp, /* MUST BE TALLOCED */
				bool *ppath_contains_wcard)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *pathname_local;
	char *p,*temp;
	char *servicename;
	char *eos_ptr;
	NTSTATUS status = NT_STATUS_OK;
	char sepchar;

	ZERO_STRUCTP(pdp);

	/*
	 * This is the only talloc we should need to do
	 * on the struct dfs_path. All the pointers inside
	 * it should point to offsets within this string.
	 */

	pathname_local = talloc_strdup(pdp, pathname);
	if (!pathname_local) {
		return NT_STATUS_NO_MEMORY;
	}
	/* Get a pointer to the terminating '\0' */
	eos_ptr = &pathname_local[strlen(pathname_local)];
	p = temp = pathname_local;

	/*
	 * Non-broken DFS paths *must* start with the
	 * path separator. For Windows this is always '\\',
	 * for posix paths this is always '/'.
	 */

	if (*pathname == '/') {
		pdp->posix_path = true;
		sepchar = '/';
	} else {
		pdp->posix_path = false;
		sepchar = '\\';
	}

	if (allow_broken_path && (*pathname != sepchar)) {
		DEBUG(10,("parse_dfs_path: path %s doesn't start with %c\n",
			pathname, sepchar ));
		/*
		 * Possibly client sent a local path by mistake.
		 * Try and convert to a local path.
		 * Note that this is an SMB1-only fallback
		 * to cope with known broken SMB1 clients.
		 */

		pdp->hostname = eos_ptr; /* "" */
		pdp->servicename = eos_ptr; /* "" */

		/* We've got no info about separators. */
		pdp->posix_path = lp_posix_pathnames();
		p = temp;
		DEBUG(10,("parse_dfs_path: trying to convert %s to a "
			"local path\n",
			temp));
		goto local_path;
	}

	/*
	 * Safe to use on talloc'ed string as it only shrinks.
	 * It also doesn't affect the eos_ptr.
	 */
	trim_char(temp,sepchar,sepchar);

	DEBUG(10,("parse_dfs_path: temp = |%s| after trimming %c's\n",
		temp, sepchar));

	/* Now tokenize. */
	/* Parse out hostname. */
	p = strchr_m(temp,sepchar);
	if(p == NULL) {
		DEBUG(10,("parse_dfs_path: can't parse hostname from path %s\n",
			temp));
		/*
		 * Possibly client sent a local path by mistake.
		 * Try and convert to a local path.
		 */

		pdp->hostname = eos_ptr; /* "" */
		pdp->servicename = eos_ptr; /* "" */

		p = temp;
		DEBUG(10,("parse_dfs_path: trying to convert %s "
			"to a local path\n",
			temp));
		goto local_path;
	}
	*p = '\0';
	pdp->hostname = temp;

	DEBUG(10,("parse_dfs_path: hostname: %s\n",pdp->hostname));

	/* Parse out servicename. */
	servicename = p+1;
	p = strchr_m(servicename,sepchar);
	if (p) {
		*p = '\0';
	}

	/* Is this really our servicename ? */
	if (conn && !( strequal(servicename, lp_servicename(talloc_tos(), lp_sub, SNUM(conn)))
			|| (strequal(servicename, HOMES_NAME)
			&& strequal(lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
				get_current_username()) )) ) {
		DEBUG(10,("parse_dfs_path: %s is not our servicename\n",
			servicename));

		/*
		 * Possibly client sent a local path by mistake.
		 * Try and convert to a local path.
		 */

		pdp->hostname = eos_ptr; /* "" */
		pdp->servicename = eos_ptr; /* "" */

		/* Repair the path - replace the sepchar's
		   we nulled out */
		servicename--;
		*servicename = sepchar;
		if (p) {
			*p = sepchar;
		}

		p = temp;
		DEBUG(10,("parse_dfs_path: trying to convert %s "
			"to a local path\n",
			temp));
		goto local_path;
	}

	pdp->servicename = servicename;

	DEBUG(10,("parse_dfs_path: servicename: %s\n",pdp->servicename));

	if(p == NULL) {
		/* Client sent self referral \server\share. */
		pdp->reqpath = eos_ptr; /* "" */
		return NT_STATUS_OK;
	}

	p++;

  local_path:

	*ppath_contains_wcard = False;

	pdp->reqpath = p;

	/* Rest is reqpath. */
	if (pdp->posix_path) {
		status = check_path_syntax_posix(pdp->reqpath);
	} else {
		if (allow_wcards) {
			status = check_path_syntax_wcard(pdp->reqpath,
					ppath_contains_wcard);
		} else {
			status = check_path_syntax(pdp->reqpath);
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("parse_dfs_path: '%s' failed with %s\n",
			p, nt_errstr(status) ));
		return status;
	}

	DEBUG(10,("parse_dfs_path: rest of the path: %s\n",pdp->reqpath));
	return NT_STATUS_OK;
}

/********************************************************
 Fake up a connection struct for the VFS layer, for use in
 applications (such as the python bindings), that do not want the
 global working directory changed under them.

 SMB_VFS_CONNECT requires root privileges.
*********************************************************/

static NTSTATUS create_conn_struct_as_root(TALLOC_CTX *ctx,
			    struct tevent_context *ev,
			    struct messaging_context *msg,
			    connection_struct **pconn,
			    int snum,
			    const char *path,
			    const struct auth_session_info *session_info)
{
	connection_struct *conn;
	char *connpath;
	const char *vfs_user;
	struct smbd_server_connection *sconn;
	const char *servicename = lp_const_servicename(snum);
	bool ok;

	sconn = talloc_zero(ctx, struct smbd_server_connection);
	if (sconn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sconn->ev_ctx = ev;
	sconn->msg_ctx = msg;

	conn = conn_new(sconn);
	if (conn == NULL) {
		TALLOC_FREE(sconn);
		return NT_STATUS_NO_MEMORY;
	}

	/* Now we have conn, we need to make sconn a child of conn,
	 * for a proper talloc tree */
	talloc_steal(conn, sconn);

	if (snum == -1 && servicename == NULL) {
		servicename = "Unknown Service (snum == -1)";
	}

	connpath = talloc_strdup(conn, path);
	if (!connpath) {
		TALLOC_FREE(conn);
		return NT_STATUS_NO_MEMORY;
	}
	connpath = talloc_string_sub(conn,
				     connpath,
				     "%S",
				     servicename);
	if (!connpath) {
		TALLOC_FREE(conn);
		return NT_STATUS_NO_MEMORY;
	}

	/* needed for smbd_vfs_init() */

	conn->params->service = snum;
	conn->cnum = TID_FIELD_INVALID;

	SMB_ASSERT(session_info != NULL);

	conn->session_info = copy_session_info(conn, session_info);
	if (conn->session_info == NULL) {
		DBG_ERR("copy_serverinfo failed\n");
		TALLOC_FREE(conn);
		return NT_STATUS_NO_MEMORY;
	}

	/* unix_info could be NULL in session_info */
	if (conn->session_info->unix_info != NULL) {
		vfs_user = conn->session_info->unix_info->unix_name;
	} else {
		vfs_user = get_current_username();
	}

	conn_setup_case_options(conn);

	set_conn_connectpath(conn, connpath);

	/*
	 * New code to check if there's a share security descriptor
	 * added from NT server manager. This is done after the
	 * smb.conf checks are done as we need a uid and token. JRA.
	 *
	 */
	share_access_check(conn->session_info->security_token,
			   servicename,
			   MAXIMUM_ALLOWED_ACCESS,
			   &conn->share_access);

	if ((conn->share_access & FILE_WRITE_DATA) == 0) {
		if ((conn->share_access & FILE_READ_DATA) == 0) {
			/* No access, read or write. */
			DBG_WARNING("connection to %s "
				    "denied due to security "
				    "descriptor.\n",
				    servicename);
			conn_free(conn);
			return NT_STATUS_ACCESS_DENIED;
		}
		conn->read_only = true;
	}

	if (!smbd_vfs_init(conn)) {
		NTSTATUS status = map_nt_error_from_unix(errno);
		DEBUG(0,("create_conn_struct: smbd_vfs_init failed.\n"));
		conn_free(conn);
		return status;
	}

	/* this must be the first filesystem operation that we do */
	if (SMB_VFS_CONNECT(conn, servicename, vfs_user) < 0) {
		DEBUG(0,("VFS connect failed!\n"));
		conn_free(conn);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ok = canonicalize_connect_path(conn);
	if (!ok) {
		DBG_ERR("Failed to canonicalize sharepath\n");
		conn_free(conn);
		return NT_STATUS_ACCESS_DENIED;
	}

	conn->fs_capabilities = SMB_VFS_FS_CAPABILITIES(conn, &conn->ts_res);
	conn->tcon_done = true;
	*pconn = talloc_move(ctx, &conn);

	return NT_STATUS_OK;
}

static int conn_struct_tos_destructor(struct conn_struct_tos *c)
{
	if (c->oldcwd_fname != NULL) {
		vfs_ChDir(c->conn, c->oldcwd_fname);
		TALLOC_FREE(c->oldcwd_fname);
	}
	SMB_VFS_DISCONNECT(c->conn);
	conn_free(c->conn);
	return 0;
}

/********************************************************
 Fake up a connection struct for the VFS layer, for use in
 applications (such as the python bindings), that do not want the
 global working directory changed under them.

 SMB_VFS_CONNECT requires root privileges.
 This temporary uses become_root() and unbecome_root().

 But further impersonation has to be cone by the caller.
*********************************************************/
NTSTATUS create_conn_struct_tos(struct messaging_context *msg,
				int snum,
				const char *path,
				const struct auth_session_info *session_info,
				struct conn_struct_tos **_c)
{
	struct conn_struct_tos *c = NULL;
	struct tevent_context *ev = NULL;
	NTSTATUS status;

	*_c = NULL;

	c = talloc_zero(talloc_tos(), struct conn_struct_tos);
	if (c == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ev = samba_tevent_context_init(c);
	if (ev == NULL) {
		TALLOC_FREE(c);
		return NT_STATUS_NO_MEMORY;
	}

	become_root();
	status = create_conn_struct_as_root(c,
					    ev,
					    msg,
					    &c->conn,
					    snum,
					    path,
					    session_info);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(c);
		return status;
	}

	talloc_set_destructor(c, conn_struct_tos_destructor);

	*_c = c;
	return NT_STATUS_OK;
}

/********************************************************
 Fake up a connection struct for the VFS layer.
 Note: this performs a vfs connect and CHANGES CWD !!!! JRA.

 See also the comment for create_conn_struct_tos() above!

 The CWD change is reverted by the destructor of
 conn_struct_tos when the current talloc_tos() is destroyed.
*********************************************************/
NTSTATUS create_conn_struct_tos_cwd(struct messaging_context *msg,
				    int snum,
				    const char *path,
				    const struct auth_session_info *session_info,
				    struct conn_struct_tos **_c)
{
	struct conn_struct_tos *c = NULL;
	struct smb_filename smb_fname_connectpath = {0};
	NTSTATUS status;

	*_c = NULL;

	status = create_conn_struct_tos(msg,
					snum,
					path,
					session_info,
					&c);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Windows seems to insist on doing trans2getdfsreferral() calls on
	 * the IPC$ share as the anonymous user. If we try to chdir as that
	 * user we will fail.... WTF ? JRA.
	 */

	c->oldcwd_fname = vfs_GetWd(c, c->conn);
	if (c->oldcwd_fname == NULL) {
		status = map_nt_error_from_unix(errno);
		DEBUG(3, ("vfs_GetWd failed: %s\n", strerror(errno)));
		TALLOC_FREE(c);
		return status;
	}

	smb_fname_connectpath = (struct smb_filename) {
		.base_name = c->conn->connectpath
	};

	if (vfs_ChDir(c->conn, &smb_fname_connectpath) != 0) {
		status = map_nt_error_from_unix(errno);
		DBG_NOTICE("Can't ChDir to new conn path %s. "
			   "Error was %s\n",
			   c->conn->connectpath, strerror(errno));
		TALLOC_FREE(c->oldcwd_fname);
		TALLOC_FREE(c);
		return status;
	}

	*_c = c;
	return NT_STATUS_OK;
}

/********************************************************
 Fake up a connection struct for the VFS layer.
 This takes an TALLOC_CTX and tevent_context from the
 caller and the resulting connection_struct is stable
 across the lifetime of mem_ctx and ev.

 Note: this performs a vfs connect and changes cwd.

 See also the comment for create_conn_struct_tos() above!
*********************************************************/

NTSTATUS create_conn_struct_cwd(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct messaging_context *msg,
				const struct auth_session_info *session_info,
				int snum,
				const char *path,
				struct connection_struct **c)
{
	NTSTATUS status;

	become_root();
	status = create_conn_struct_as_root(mem_ctx,
					    ev,
					    msg,
					    c,
					    snum,
					    path,
					    session_info);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(c);
		return status;
	}

	return NT_STATUS_OK;
}

static void shuffle_strlist(char **list, int count)
{
	int i;
	uint32_t r;
	char *tmp;

	for (i = count; i > 1; i--) {
		r = generate_random() % i;

		tmp = list[i-1];
		list[i-1] = list[r];
		list[r] = tmp;
	}
}

/**********************************************************************
 Parse the contents of a symlink to verify if it is an msdfs referral
 A valid referral is of the form:

 msdfs:server1\share1,server2\share2
 msdfs:server1\share1\pathname,server2\share2\pathname
 msdfs:server1/share1,server2/share2
 msdfs:server1/share1/pathname,server2/share2/pathname.

 Note that the alternate paths returned here must be of the canonicalized
 form:

 \server\share or
 \server\share\path\to\file,

 even in posix path mode. This is because we have no knowledge if the
 server we're referring to understands posix paths.
 **********************************************************************/

bool parse_msdfs_symlink(TALLOC_CTX *ctx,
			bool shuffle_referrals,
			const char *target,
			struct referral **ppreflist,
			size_t *prefcount)
{
	char *temp = NULL;
	char *prot;
	char **alt_path = NULL;
	size_t count = 0, i;
	struct referral *reflist = NULL;
	char *saveptr;

	temp = talloc_strdup(ctx, target);
	if (!temp) {
		return false;
	}
	prot = strtok_r(temp, ":", &saveptr);
	if (!prot) {
		DEBUG(0,("parse_msdfs_symlink: invalid path !\n"));
		TALLOC_FREE(temp);
		return false;
	}

	alt_path = talloc_array(ctx, char *, MAX_REFERRAL_COUNT);
	if (!alt_path) {
		TALLOC_FREE(temp);
		return false;
	}

	/* parse out the alternate paths */
	while((count<MAX_REFERRAL_COUNT) &&
	      ((alt_path[count] = strtok_r(NULL, ",", &saveptr)) != NULL)) {
		count++;
	}

	/* shuffle alternate paths */
	if (shuffle_referrals) {
		shuffle_strlist(alt_path, count);
	}

	DBG_DEBUG("count=%zu\n", count);

	if (count) {
		reflist = talloc_zero_array(ctx,
				struct referral, count);
		if(reflist == NULL) {
			TALLOC_FREE(temp);
			TALLOC_FREE(alt_path);
			return false;
		}
	} else {
		reflist = NULL;
	}

	for(i=0;i<count;i++) {
		char *p;

		/* Canonicalize link target.
		 * Replace all /'s in the path by a \ */
		string_replace(alt_path[i], '/', '\\');

		/* Remove leading '\\'s */
		p = alt_path[i];
		while (*p && (*p == '\\')) {
			p++;
		}

		reflist[i].alternate_path = talloc_asprintf(reflist,
				"\\%s",
				p);
		if (!reflist[i].alternate_path) {
			TALLOC_FREE(temp);
			TALLOC_FREE(alt_path);
			TALLOC_FREE(reflist);
			return false;
		}

		reflist[i].proximity = 0;
		reflist[i].ttl = REFERRAL_TTL;
		DBG_DEBUG("Created alt path: %s\n",
			reflist[i].alternate_path);
	}

	if (ppreflist != NULL) {
		*ppreflist = reflist;
	} else {
		TALLOC_FREE(reflist);
	}
	if (prefcount != NULL) {
		*prefcount = count;
	}
	TALLOC_FREE(temp);
	TALLOC_FREE(alt_path);
	return true;
}

/**********************************************************************
 Returns true if the unix path is a valid msdfs symlink.
**********************************************************************/

bool is_msdfs_link(connection_struct *conn,
		struct smb_filename *smb_fname)
{
	NTSTATUS status = SMB_VFS_READ_DFS_PATHAT(conn,
					talloc_tos(),
					conn->cwd_fsp,
					smb_fname,
					NULL,
					NULL);
	return (NT_STATUS_IS_OK(status));
}

/*****************************************************************
 Used by other functions to decide if a dfs path is remote,
 and to get the list of referred locations for that remote path.

 search_flag: For findfirsts, dfs links themselves are not
 redirected, but paths beyond the links are. For normal smb calls,
 even dfs links need to be redirected.

 consumedcntp: how much of the dfs path is being redirected. the client
 should try the remaining path on the redirected server.

 If this returns NT_STATUS_PATH_NOT_COVERED the contents of the msdfs
 link redirect are in targetpath.
*****************************************************************/

static NTSTATUS dfs_path_lookup(TALLOC_CTX *ctx,
		connection_struct *conn,
		const char *dfspath, /* Incoming complete dfs path */
		const struct dfs_path *pdp, /* Parsed out
					       server+share+extrapath. */
		uint32_t ucf_flags,
		int *consumedcntp,
		struct referral **ppreflist,
		size_t *preferral_count)
{
	char *p = NULL;
	char *q = NULL;
	NTSTATUS status;
	struct smb_filename *smb_fname = NULL;
	char *canon_dfspath = NULL; /* Canonicalized dfs path. (only '/'
				  components). */

	DEBUG(10,("dfs_path_lookup: Conn path = %s reqpath = %s\n",
		conn->connectpath, pdp->reqpath));

	/*
 	 * Note the unix path conversion here we're doing we
	 * throw away. We're looking for a symlink for a dfs
	 * resolution, if we don't find it we'll do another
	 * unix_convert later in the codepath.
	 */

	status = unix_convert(ctx, conn, pdp->reqpath, 0, &smb_fname,
			      ucf_flags);

	if (!NT_STATUS_IS_OK(status)) {
		if (!NT_STATUS_EQUAL(status,
				     NT_STATUS_OBJECT_PATH_NOT_FOUND)) {
			return status;
		}
		if (smb_fname == NULL || smb_fname->base_name == NULL) {
			return status;
		}
	}

	/* Optimization - check if we can redirect the whole path. */

	status = SMB_VFS_READ_DFS_PATHAT(conn,
					ctx,
					conn->cwd_fsp,
					smb_fname,
					ppreflist,
					preferral_count);

	if (NT_STATUS_IS_OK(status)) {
		/* XX_ALLOW_WCARD_XXX is called from search functions. */
		if (ucf_flags &
				(UCF_COND_ALLOW_WCARD_LCOMP|
				 UCF_ALWAYS_ALLOW_WCARD_LCOMP)) {
			DEBUG(6,("dfs_path_lookup (FindFirst) No redirection "
				 "for dfs link %s.\n", dfspath));
			status = NT_STATUS_OK;
			goto out;
		}

		DBG_INFO("%s resolves to a valid dfs link\n",
			dfspath);

		if (consumedcntp) {
			*consumedcntp = strlen(dfspath);
		}
		status = NT_STATUS_PATH_NOT_COVERED;
		goto out;
	}

	/* Prepare to test only for '/' components in the given path,
	 * so if a Windows path replace all '\\' characters with '/'.
	 * For a POSIX DFS path we know all separators are already '/'. */

	canon_dfspath = talloc_strdup(ctx, dfspath);
	if (!canon_dfspath) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	if (!pdp->posix_path) {
		string_replace(canon_dfspath, '\\', '/');
	}

	/*
	 * localpath comes out of unix_convert, so it has
	 * no trailing backslash. Make sure that canon_dfspath hasn't either.
	 * Fix for bug #4860 from Jan Martin <Jan.Martin@rwedea.com>.
	 */

	trim_char(canon_dfspath,0,'/');

	/*
	 * Redirect if any component in the path is a link.
	 * We do this by walking backwards through the
	 * local path, chopping off the last component
	 * in both the local path and the canonicalized
	 * DFS path. If we hit a DFS link then we're done.
	 */

	p = strrchr_m(smb_fname->base_name, '/');
	if (consumedcntp) {
		q = strrchr_m(canon_dfspath, '/');
	}

	while (p) {
		*p = '\0';
		if (q) {
			*q = '\0';
		}

		status = SMB_VFS_READ_DFS_PATHAT(conn,
					ctx,
					conn->cwd_fsp,
					smb_fname,
					ppreflist,
					preferral_count);

		if (NT_STATUS_IS_OK(status)) {
			DBG_INFO("Redirecting %s because "
				"parent %s is a dfs link\n",
				dfspath,
				smb_fname_str_dbg(smb_fname));

			if (consumedcntp) {
				*consumedcntp = strlen(canon_dfspath);
				DEBUG(10, ("dfs_path_lookup: Path consumed: %s "
					"(%d)\n",
					canon_dfspath,
					*consumedcntp));
			}

			status = NT_STATUS_PATH_NOT_COVERED;
			goto out;
		}

		/* Step back on the filesystem. */
		p = strrchr_m(smb_fname->base_name, '/');

		if (consumedcntp) {
			/* And in the canonicalized dfs path. */
			q = strrchr_m(canon_dfspath, '/');
		}
	}

	status = NT_STATUS_OK;
 out:

	TALLOC_FREE(smb_fname);
	return status;
}

/*****************************************************************
 Decides if a dfs pathname should be redirected or not.
 If not, the pathname is converted to a tcon-relative local unix path

 search_wcard_flag: this flag performs 2 functions both related
 to searches.  See resolve_dfs_path() and parse_dfs_path_XX()
 for details.

 This function can return NT_STATUS_OK, meaning use the returned path as-is
 (mapped into a local path).
 or NT_STATUS_NOT_COVERED meaning return a DFS redirect, or
 any other NT_STATUS error which is a genuine error to be
 returned to the client.
*****************************************************************/

static NTSTATUS dfs_redirect(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *path_in,
			uint32_t ucf_flags,
			bool allow_broken_path,
			char **pp_path_out,
			bool *ppath_contains_wcard)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	NTSTATUS status;
	bool search_wcard_flag = (ucf_flags &
		(UCF_COND_ALLOW_WCARD_LCOMP|UCF_ALWAYS_ALLOW_WCARD_LCOMP));
	struct dfs_path *pdp = talloc(ctx, struct dfs_path);

	if (!pdp) {
		return NT_STATUS_NO_MEMORY;
	}

	status = parse_dfs_path(conn, path_in, search_wcard_flag,
				allow_broken_path, pdp,
			ppath_contains_wcard);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(pdp);
		return status;
	}

	if (pdp->reqpath[0] == '\0') {
		TALLOC_FREE(pdp);
		*pp_path_out = talloc_strdup(ctx, "");
		if (!*pp_path_out) {
			return NT_STATUS_NO_MEMORY;
		}
		DEBUG(5,("dfs_redirect: self-referral.\n"));
		return NT_STATUS_OK;
	}

	/* If dfs pathname for a non-dfs share, convert to tcon-relative
	   path and return OK */

	if (!lp_msdfs_root(SNUM(conn))) {
		*pp_path_out = talloc_strdup(ctx, pdp->reqpath);
		TALLOC_FREE(pdp);
		if (!*pp_path_out) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}

	/* If it looked like a local path (zero hostname/servicename)
	 * just treat as a tcon-relative path. */

	if (pdp->hostname[0] == '\0' && pdp->servicename[0] == '\0') {
		*pp_path_out = talloc_strdup(ctx, pdp->reqpath);
		TALLOC_FREE(pdp);
		if (!*pp_path_out) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}

	if (!( strequal(pdp->servicename, lp_servicename(talloc_tos(), lp_sub, SNUM(conn)))
			|| (strequal(pdp->servicename, HOMES_NAME)
			&& strequal(lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
				conn->session_info->unix_info->sanitized_username) )) ) {

		/* The given sharename doesn't match this connection. */
		TALLOC_FREE(pdp);

		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	status = dfs_path_lookup(ctx,
				conn,
				path_in,
				pdp,
				ucf_flags,
				NULL, /* int *consumedcntp */
				NULL, /* struct referral **ppreflist */
				NULL); /* size_t *preferral_count */
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_PATH_NOT_COVERED)) {
			DEBUG(3,("dfs_redirect: Redirecting %s\n", path_in));
		} else {
			DEBUG(10,("dfs_redirect: dfs_path_lookup "
				"failed for %s with %s\n",
				path_in, nt_errstr(status) ));
		}
		return status;
	}

	DEBUG(3,("dfs_redirect: Not redirecting %s.\n", path_in));

	/* Form non-dfs tcon-relative path */
	*pp_path_out = talloc_strdup(ctx, pdp->reqpath);
	TALLOC_FREE(pdp);
	if (!*pp_path_out) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(3,("dfs_redirect: Path %s converted to non-dfs path %s\n",
				path_in,
				*pp_path_out));

	return NT_STATUS_OK;
}

/**********************************************************************
 Return a self referral.
**********************************************************************/

static NTSTATUS self_ref(TALLOC_CTX *ctx,
			const char *dfs_path,
			struct junction_map *jucn,
			int *consumedcntp,
			bool *self_referralp)
{
	struct referral *ref;

	*self_referralp = True;

	jucn->referral_count = 1;
	if((ref = talloc_zero(ctx, struct referral)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ref->alternate_path = talloc_strdup(ctx, dfs_path);
	if (!ref->alternate_path) {
		TALLOC_FREE(ref);
		return NT_STATUS_NO_MEMORY;
	}
	ref->proximity = 0;
	ref->ttl = REFERRAL_TTL;
	jucn->referral_list = ref;
	*consumedcntp = strlen(dfs_path);
	return NT_STATUS_OK;
}

/**********************************************************************
 Gets valid referrals for a dfs path and fills up the
 junction_map structure.
**********************************************************************/

NTSTATUS get_referred_path(TALLOC_CTX *ctx,
			   struct auth_session_info *session_info,
			   const char *dfs_path,
			   const struct tsocket_address *remote_address,
			   const struct tsocket_address *local_address,
			   bool allow_broken_path,
			   struct junction_map *jucn,
			   int *consumedcntp,
			   bool *self_referralp)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct conn_struct_tos *c = NULL;
	struct connection_struct *conn = NULL;
	int snum;
	NTSTATUS status = NT_STATUS_NOT_FOUND;
	bool dummy;
	struct dfs_path *pdp = talloc_zero(frame, struct dfs_path);

	if (!pdp) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	*self_referralp = False;

	status = parse_dfs_path(NULL, dfs_path, False, allow_broken_path,
				pdp, &dummy);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	jucn->service_name = talloc_strdup(ctx, pdp->servicename);
	jucn->volume_name = talloc_strdup(ctx, pdp->reqpath);
	if (!jucn->service_name || !jucn->volume_name) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* Verify the share is a dfs root */
	snum = lp_servicenumber(jucn->service_name);
	if(snum < 0) {
		char *service_name = NULL;
		if ((snum = find_service(ctx, jucn->service_name, &service_name)) < 0) {
			TALLOC_FREE(frame);
			return NT_STATUS_NOT_FOUND;
		}
		if (!service_name) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		TALLOC_FREE(jucn->service_name);
		jucn->service_name = talloc_strdup(ctx, service_name);
		if (!jucn->service_name) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (!lp_msdfs_root(snum) && (*lp_msdfs_proxy(talloc_tos(), lp_sub, snum) == '\0')) {
		DEBUG(3,("get_referred_path: |%s| in dfs path %s is not "
			"a dfs root.\n",
			pdp->servicename, dfs_path));
		TALLOC_FREE(frame);
		return NT_STATUS_NOT_FOUND;
	}

	/*
	 * Self referrals are tested with a anonymous IPC connection and
	 * a GET_DFS_REFERRAL call to \\server\share. (which means
	 * dp.reqpath[0] points to an empty string). create_conn_struct cd's
	 * into the directory and will fail if it cannot (as the anonymous
	 * user). Cope with this.
	 */

	if (pdp->reqpath[0] == '\0') {
		char *tmp;
		struct referral *ref;
		size_t refcount;

		if (*lp_msdfs_proxy(talloc_tos(), lp_sub, snum) == '\0') {
			TALLOC_FREE(frame);
			return self_ref(ctx,
					dfs_path,
					jucn,
					consumedcntp,
					self_referralp);
		}

		/*
		 * It's an msdfs proxy share. Redirect to
 		 * the configured target share.
 		 */

		tmp = talloc_asprintf(frame, "msdfs:%s",
				      lp_msdfs_proxy(frame, lp_sub, snum));
		if (tmp == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		if (!parse_msdfs_symlink(ctx,
				lp_msdfs_shuffle_referrals(snum),
				tmp,
				&ref,
				&refcount)) {
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_PARAMETER;
		}
		jucn->referral_count = refcount;
		jucn->referral_list = ref;
		*consumedcntp = strlen(dfs_path);
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	status = create_conn_struct_tos_cwd(global_messaging_context(),
					    snum,
					    lp_path(frame, lp_sub, snum),
					    session_info,
					    &c);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}
	conn = c->conn;

	/*
	 * TODO
	 *
	 * The remote and local address should be passed down to
	 * create_conn_struct_cwd.
	 */
	if (conn->sconn->remote_address == NULL) {
		conn->sconn->remote_address =
			tsocket_address_copy(remote_address, conn->sconn);
		if (conn->sconn->remote_address == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (conn->sconn->local_address == NULL) {
		conn->sconn->local_address =
			tsocket_address_copy(local_address, conn->sconn);
		if (conn->sconn->local_address == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* If this is a DFS path dfs_lookup should return
	 * NT_STATUS_PATH_NOT_COVERED. */

	status = dfs_path_lookup(ctx,
				conn,
				dfs_path,
				pdp,
				0, /* ucf_flags */
				consumedcntp,
				&jucn->referral_list,
				&jucn->referral_count);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_PATH_NOT_COVERED)) {
		DEBUG(3,("get_referred_path: No valid referrals for path %s\n",
			dfs_path));
		if (NT_STATUS_IS_OK(status)) {
			/*
			 * We are in an error path here (we
			 * know it's not a DFS path), but
			 * dfs_path_lookup() can return
			 * NT_STATUS_OK. Ensure we always
			 * return a valid error code.
			 *
			 * #9588 - ACLs are not inherited to directories
			 *         for DFS shares.
			 */
			status = NT_STATUS_NOT_FOUND;
		}
		goto err_exit;
	}

	status = NT_STATUS_OK;
 err_exit:
	TALLOC_FREE(frame);
	return status;
}

/******************************************************************
 Set up the DFS referral for the dfs pathname. This call returns
 the amount of the path covered by this server, and where the
 client should be redirected to. This is the meat of the
 TRANS2_GET_DFS_REFERRAL call.
******************************************************************/

int setup_dfs_referral(connection_struct *orig_conn,
			const char *dfs_path,
			int max_referral_level,
			char **ppdata, NTSTATUS *pstatus)
{
	char *pdata = *ppdata;
	int reply_size = 0;
	struct dfs_GetDFSReferral *r;
	DATA_BLOB blob = data_blob_null;
	NTSTATUS status;
	enum ndr_err_code ndr_err;

	r = talloc_zero(talloc_tos(), struct dfs_GetDFSReferral);
	if (r == NULL) {
		*pstatus = NT_STATUS_NO_MEMORY;
		return -1;
	}

	r->in.req.max_referral_level = max_referral_level;
	r->in.req.servername = talloc_strdup(r, dfs_path);
	if (r->in.req.servername == NULL) {
		talloc_free(r);
		*pstatus = NT_STATUS_NO_MEMORY;
		return -1;
	}

	status = SMB_VFS_GET_DFS_REFERRALS(orig_conn, r);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(r);
		*pstatus = status;
		return -1;
	}

	ndr_err = ndr_push_struct_blob(&blob, r,
				r->out.resp,
				(ndr_push_flags_fn_t)ndr_push_dfs_referral_resp);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(r);
		*pstatus = NT_STATUS_INVALID_PARAMETER;
		return -1;
	}

	pdata = (char *)SMB_REALLOC(pdata, blob.length);
	if(pdata == NULL) {
		TALLOC_FREE(r);
		DEBUG(0,("referral setup:"
			 "malloc failed for Realloc!\n"));
		return -1;
	}
	*ppdata = pdata;
	reply_size = blob.length;
	memcpy(pdata, blob.data, blob.length);
	TALLOC_FREE(r);

	*pstatus = NT_STATUS_OK;
	return reply_size;
}

/**********************************************************************
 The following functions are called by the NETDFS RPC pipe functions
 **********************************************************************/

/*********************************************************************
 Creates a junction structure from a DFS pathname
**********************************************************************/

bool create_junction(TALLOC_CTX *ctx,
		const char *dfs_path,
		bool allow_broken_path,
		struct junction_map *jucn)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	int snum;
	bool dummy;
	struct dfs_path *pdp = talloc(ctx,struct dfs_path);
	NTSTATUS status;

	if (!pdp) {
		return False;
	}
	status = parse_dfs_path(NULL, dfs_path, False, allow_broken_path,
				pdp, &dummy);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* check if path is dfs : validate first token */
	if (!is_myname_or_ipaddr(pdp->hostname)) {
		DEBUG(4,("create_junction: Invalid hostname %s "
			"in dfs path %s\n",
			pdp->hostname, dfs_path));
		TALLOC_FREE(pdp);
		return False;
	}

	/* Check for a non-DFS share */
	snum = lp_servicenumber(pdp->servicename);

	if(snum < 0 || !lp_msdfs_root(snum)) {
		DEBUG(4,("create_junction: %s is not an msdfs root.\n",
			pdp->servicename));
		TALLOC_FREE(pdp);
		return False;
	}

	jucn->service_name = talloc_strdup(ctx, pdp->servicename);
	jucn->volume_name = talloc_strdup(ctx, pdp->reqpath);
	jucn->comment = lp_comment(ctx, lp_sub, snum);

	TALLOC_FREE(pdp);
	if (!jucn->service_name || !jucn->volume_name || ! jucn->comment) {
		return False;
	}
	return True;
}

/**********************************************************************
 Forms a valid Unix pathname from the junction
 **********************************************************************/

static bool junction_to_local_path_tos(const struct junction_map *jucn,
				       struct auth_session_info *session_info,
				       char **pp_path_out,
				       connection_struct **conn_out)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct conn_struct_tos *c = NULL;
	int snum;
	char *path_out = NULL;
	NTSTATUS status;

	snum = lp_servicenumber(jucn->service_name);
	if(snum < 0) {
		return False;
	}
	status = create_conn_struct_tos_cwd(global_messaging_context(),
					    snum,
					    lp_path(talloc_tos(), lp_sub, snum),
					    session_info,
					    &c);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	path_out = talloc_asprintf(c,
			"%s/%s",
			lp_path(talloc_tos(), lp_sub, snum),
			jucn->volume_name);
	if (path_out == NULL) {
		TALLOC_FREE(c);
		return False;
	}
	*pp_path_out = path_out;
	*conn_out = c->conn;
	return True;
}

/*
 * Create a msdfs string in Samba format we can store
 * in a filesystem object (currently a symlink).
 */

char *msdfs_link_string(TALLOC_CTX *ctx,
			const struct referral *reflist,
			size_t referral_count)
{
	char *refpath = NULL;
	bool insert_comma = false;
	char *msdfs_link = NULL;
	size_t i;

	/* Form the msdfs_link contents */
	msdfs_link = talloc_strdup(ctx, "msdfs:");
	if (msdfs_link == NULL) {
		goto err;
	}

	for( i= 0; i < referral_count; i++) {
		refpath = talloc_strdup(ctx, reflist[i].alternate_path);

		if (refpath == NULL) {
			goto err;
		}

		/* Alternate paths always use Windows separators. */
		trim_char(refpath, '\\', '\\');
		if (*refpath == '\0') {
			if (i == 0) {
				insert_comma = false;
			}
			continue;
		}
		if (i > 0 && insert_comma) {
			msdfs_link = talloc_asprintf_append_buffer(msdfs_link,
					",%s",
					refpath);
		} else {
			msdfs_link = talloc_asprintf_append_buffer(msdfs_link,
					"%s",
					refpath);
		}

		if (msdfs_link == NULL) {
			goto err;
		}

		if (!insert_comma) {
			insert_comma = true;
		}

		TALLOC_FREE(refpath);
	}

	return msdfs_link;

  err:

	TALLOC_FREE(refpath);
	TALLOC_FREE(msdfs_link);
	return NULL;
}

bool create_msdfs_link(const struct junction_map *jucn,
		       struct auth_session_info *session_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *path = NULL;
	connection_struct *conn;
	struct smb_filename *smb_fname = NULL;
	bool ok;
	NTSTATUS status;
	bool ret = false;

	ok = junction_to_local_path_tos(jucn, session_info, &path, &conn);
	if (!ok) {
		goto out;
	}

	if (!CAN_WRITE(conn)) {
		const struct loadparm_substitution *lp_sub =
			loadparm_s3_global_substitution();
		int snum = lp_servicenumber(jucn->service_name);

		DBG_WARNING("Can't create DFS entry on read-only share %s\n",
			lp_servicename(frame, lp_sub, snum));
		goto out;
	}

	smb_fname = synthetic_smb_fname(frame,
				path,
				NULL,
				NULL,
				0,
				0);
	if (smb_fname == NULL) {
		goto out;
	}

	status = SMB_VFS_CREATE_DFS_PATHAT(conn,
				conn->cwd_fsp,
				smb_fname,
				jucn->referral_list,
				jucn->referral_count);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			int retval = SMB_VFS_UNLINKAT(conn,
						conn->cwd_fsp,
						smb_fname,
						0);
			if (retval != 0) {
				goto out;
			}
		}
		status = SMB_VFS_CREATE_DFS_PATHAT(conn,
				conn->cwd_fsp,
				smb_fname,
				jucn->referral_list,
				jucn->referral_count);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("SMB_VFS_CREATE_DFS_PATHAT failed "
				"%s - Error: %s\n",
				path,
				nt_errstr(status));
			goto out;
		}
	}

	ret = true;

out:
	TALLOC_FREE(frame);
	return ret;
}

bool remove_msdfs_link(const struct junction_map *jucn,
		       struct auth_session_info *session_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *path = NULL;
	connection_struct *conn;
	bool ret = False;
	struct smb_filename *smb_fname;
	bool ok;
	int retval;

	ok = junction_to_local_path_tos(jucn, session_info, &path, &conn);
	if (!ok) {
		TALLOC_FREE(frame);
		return false;
	}

	if (!CAN_WRITE(conn)) {
		const struct loadparm_substitution *lp_sub =
			loadparm_s3_global_substitution();
		int snum = lp_servicenumber(jucn->service_name);

		DBG_WARNING("Can't remove DFS entry on read-only share %s\n",
			lp_servicename(frame, lp_sub, snum));
		TALLOC_FREE(frame);
		return false;
	}

	smb_fname = synthetic_smb_fname(frame,
					path,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return false;
	}

	retval = SMB_VFS_UNLINKAT(conn,
			conn->cwd_fsp,
			smb_fname,
			0);
	if (retval == 0) {
		ret = True;
	}

	TALLOC_FREE(frame);
	return ret;
}

/*********************************************************************
 Return the number of DFS links at the root of this share.
*********************************************************************/

static size_t count_dfs_links(TALLOC_CTX *ctx,
			      struct auth_session_info *session_info,
			      int snum)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	size_t cnt = 0;
	const char *dname = NULL;
	char *talloced = NULL;
	const char *connect_path = lp_path(frame, lp_sub, snum);
	const char *msdfs_proxy = lp_msdfs_proxy(frame, lp_sub, snum);
	struct conn_struct_tos *c = NULL;
	connection_struct *conn = NULL;
	NTSTATUS status;
	struct smb_filename *smb_fname = NULL;
	struct smb_Dir *dir_hnd = NULL;
	long offset = 0;

	if(*connect_path == '\0') {
		TALLOC_FREE(frame);
		return 0;
	}

	/*
	 * Fake up a connection struct for the VFS layer.
	 */

	status = create_conn_struct_tos_cwd(global_messaging_context(),
					    snum,
					    connect_path,
					    session_info,
					    &c);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("create_conn_struct failed: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(frame);
		return 0;
	}
	conn = c->conn;

	/* Count a link for the msdfs root - convention */
	cnt = 1;

	/* No more links if this is an msdfs proxy. */
	if (*msdfs_proxy != '\0') {
		goto out;
	}

	smb_fname = synthetic_smb_fname(frame,
					".",
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		goto out;
	}

	/* Now enumerate all dfs links */
	dir_hnd = OpenDir(frame, conn, smb_fname, NULL, 0);
	if (dir_hnd == NULL) {
		goto out;
	}

        while ((dname = ReadDirName(dir_hnd, &offset, NULL, &talloced))
	       != NULL)
	{
		struct smb_filename *smb_dname =
			synthetic_smb_fname(frame,
					dname,
					NULL,
					NULL,
					0,
					0);
		if (smb_dname == NULL) {
			goto out;
		}
		if (is_msdfs_link(conn, smb_dname)) {
			if (cnt + 1 < cnt) {
				cnt = 0;
				goto out;
			}
			cnt++;
		}
		TALLOC_FREE(talloced);
		TALLOC_FREE(smb_dname);
	}

out:
	TALLOC_FREE(frame);
	return cnt;
}

/*********************************************************************
*********************************************************************/

static int form_junctions(TALLOC_CTX *ctx,
			  struct auth_session_info *session_info,
				int snum,
				struct junction_map *jucn,
				size_t jn_remain)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	size_t cnt = 0;
	const char *dname = NULL;
	char *talloced = NULL;
	const char *connect_path = lp_path(frame, lp_sub, snum);
	char *service_name = lp_servicename(frame, lp_sub, snum);
	const char *msdfs_proxy = lp_msdfs_proxy(frame, lp_sub, snum);
	struct conn_struct_tos *c = NULL;
	connection_struct *conn = NULL;
	struct referral *ref = NULL;
	struct smb_filename *smb_fname = NULL;
	struct smb_Dir *dir_hnd = NULL;
	long offset = 0;
	NTSTATUS status;

	if (jn_remain == 0) {
		TALLOC_FREE(frame);
		return 0;
	}

	if(*connect_path == '\0') {
		TALLOC_FREE(frame);
		return 0;
	}

	/*
	 * Fake up a connection struct for the VFS layer.
	 */

	status = create_conn_struct_tos_cwd(global_messaging_context(),
					    snum,
					    connect_path,
					    session_info,
					    &c);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("create_conn_struct failed: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(frame);
		return 0;
	}
	conn = c->conn;

	/* form a junction for the msdfs root - convention
	   DO NOT REMOVE THIS: NT clients will not work with us
	   if this is not present
	*/
	jucn[cnt].service_name = talloc_strdup(ctx,service_name);
	jucn[cnt].volume_name = talloc_strdup(ctx, "");
	if (!jucn[cnt].service_name || !jucn[cnt].volume_name) {
		goto out;
	}
	jucn[cnt].comment = "";
	jucn[cnt].referral_count = 1;

	ref = jucn[cnt].referral_list = talloc_zero(ctx, struct referral);
	if (jucn[cnt].referral_list == NULL) {
		goto out;
	}

	ref->proximity = 0;
	ref->ttl = REFERRAL_TTL;
	if (*msdfs_proxy != '\0') {
		ref->alternate_path = talloc_strdup(ctx,
						msdfs_proxy);
	} else {
		ref->alternate_path = talloc_asprintf(ctx,
			"\\\\%s\\%s",
			get_local_machine_name(),
			service_name);
	}

	if (!ref->alternate_path) {
		goto out;
	}
	cnt++;

	/* Don't enumerate if we're an msdfs proxy. */
	if (*msdfs_proxy != '\0') {
		goto out;
	}

	smb_fname = synthetic_smb_fname(frame,
					".",
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		goto out;
	}

	/* Now enumerate all dfs links */
	dir_hnd = OpenDir(frame, conn, smb_fname, NULL, 0);
	if (dir_hnd == NULL) {
		goto out;
	}

        while ((dname = ReadDirName(dir_hnd, &offset, NULL, &talloced))
	       != NULL)
	{
		struct smb_filename *smb_dname = NULL;

		if (cnt >= jn_remain) {
			DEBUG(2, ("form_junctions: ran out of MSDFS "
				"junction slots"));
			TALLOC_FREE(talloced);
			goto out;
		}
		smb_dname = synthetic_smb_fname(talloc_tos(),
				dname,
				NULL,
				NULL,
				0,
				0);
		if (smb_dname == NULL) {
			TALLOC_FREE(talloced);
			goto out;
		}

		status = SMB_VFS_READ_DFS_PATHAT(conn,
				ctx,
				conn->cwd_fsp,
				smb_dname,
				&jucn[cnt].referral_list,
				&jucn[cnt].referral_count);

		if (NT_STATUS_IS_OK(status)) {
			jucn[cnt].service_name = talloc_strdup(ctx,
							service_name);
			jucn[cnt].volume_name = talloc_strdup(ctx, dname);
			if (!jucn[cnt].service_name || !jucn[cnt].volume_name) {
				TALLOC_FREE(talloced);
				goto out;
			}
			jucn[cnt].comment = "";
			cnt++;
		}
		TALLOC_FREE(talloced);
		TALLOC_FREE(smb_dname);
	}

out:
	TALLOC_FREE(frame);
	return cnt;
}

struct junction_map *enum_msdfs_links(TALLOC_CTX *ctx,
				      struct auth_session_info *session_info,
				      size_t *p_num_jn)
{
	struct junction_map *jn = NULL;
	int i=0;
	size_t jn_count = 0;
	int sharecount = 0;

	*p_num_jn = 0;
	if(!lp_host_msdfs()) {
		return NULL;
	}

	/* Ensure all the usershares are loaded. */
	become_root();
	load_registry_shares();
	sharecount = load_usershare_shares(NULL, connections_snum_used);
	unbecome_root();

	for(i=0;i < sharecount;i++) {
		if(lp_msdfs_root(i)) {
			jn_count += count_dfs_links(ctx, session_info, i);
		}
	}
	if (jn_count == 0) {
		return NULL;
	}
	jn = talloc_array(ctx,  struct junction_map, jn_count);
	if (!jn) {
		return NULL;
	}
	for(i=0; i < sharecount; i++) {
		if (*p_num_jn >= jn_count) {
			break;
		}
		if(lp_msdfs_root(i)) {
			*p_num_jn += form_junctions(ctx,
					session_info,
					i,
					&jn[*p_num_jn],
					jn_count - *p_num_jn);
		}
	}
	return jn;
}

/******************************************************************************
 Core function to resolve a dfs pathname possibly containing a wildcard.  If
 ppath_contains_wcard != NULL, it will be set to true if a wildcard is
 detected during dfs resolution.
******************************************************************************/

NTSTATUS resolve_dfspath_wcard(TALLOC_CTX *ctx,
				connection_struct *conn,
				const char *name_in,
				uint32_t ucf_flags,
				bool allow_broken_path,
				char **pp_name_out,
				bool *ppath_contains_wcard)
{
	bool path_contains_wcard = false;
	NTSTATUS status = NT_STATUS_OK;

	status = dfs_redirect(ctx,
				conn,
				name_in,
				ucf_flags,
				allow_broken_path,
				pp_name_out,
				&path_contains_wcard);

	if (NT_STATUS_IS_OK(status) &&
				ppath_contains_wcard != NULL &&
				path_contains_wcard) {
		*ppath_contains_wcard = path_contains_wcard;
	}
	return status;
}
