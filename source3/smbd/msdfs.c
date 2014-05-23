/*
   Unix SMB/Netbios implementation.
   Version 3.0
   MSDFS services for Samba
   Copyright (C) Shirish Kalele 2000
   Copyright (C) Jeremy Allison 2007

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
#include "lib/param/loadparm.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_dfsblobs.h"

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

	pdp->posix_path = (lp_posix_pathnames() && *pathname == '/');

	sepchar = pdp->posix_path ? '/' : '\\';

	if (allow_broken_path && (*pathname != sepchar)) {
		DEBUG(10,("parse_dfs_path: path %s doesn't start with %c\n",
			pathname, sepchar ));
		/*
		 * Possibly client sent a local path by mistake.
		 * Try and convert to a local path.
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
	if (conn && !( strequal(servicename, lp_servicename(talloc_tos(), SNUM(conn)))
			|| (strequal(servicename, HOMES_NAME)
			&& strequal(lp_servicename(talloc_tos(), SNUM(conn)),
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

	if (session_info != NULL) {
		conn->session_info = copy_session_info(conn, session_info);
		if (conn->session_info == NULL) {
			DEBUG(0, ("copy_serverinfo failed\n"));
			TALLOC_FREE(conn);
			return NT_STATUS_NO_MEMORY;
		}
		vfs_user = conn->session_info->unix_info->unix_name;
	} else {
		/* use current authenticated user in absence of session_info */
		vfs_user = get_current_username();
	}

	set_conn_connectpath(conn, connpath);

	/*
	 * New code to check if there's a share security descripter
	 * added from NT server manager. This is done after the
	 * smb.conf checks are done as we need a uid and token. JRA.
	 *
	 */
	if (conn->session_info) {
		share_access_check(conn->session_info->security_token,
				   servicename,
				   MAXIMUM_ALLOWED_ACCESS,
				   &conn->share_access);

		if ((conn->share_access & FILE_WRITE_DATA) == 0) {
			if ((conn->share_access & FILE_READ_DATA) == 0) {
				/* No access, read or write. */
				DEBUG(3,("create_conn_struct: connection to %s "
					 "denied due to security "
					 "descriptor.\n",
					 servicename));
				conn_free(conn);
				return NT_STATUS_ACCESS_DENIED;
			} else {
				conn->read_only = true;
			}
		}
	} else {
		conn->share_access = 0;
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

	conn->fs_capabilities = SMB_VFS_FS_CAPABILITIES(conn, &conn->ts_res);
	*pconn = conn;

	return NT_STATUS_OK;
}

/********************************************************
 Fake up a connection struct for the VFS layer, for use in
 applications (such as the python bindings), that do not want the
 global working directory changed under them.

 SMB_VFS_CONNECT requires root privileges.
*********************************************************/

NTSTATUS create_conn_struct(TALLOC_CTX *ctx,
			    struct tevent_context *ev,
			    struct messaging_context *msg,
			    connection_struct **pconn,
			    int snum,
			    const char *path,
			    const struct auth_session_info *session_info)
{
	NTSTATUS status;
	become_root();
	status = create_conn_struct_as_root(ctx, ev,
					    msg, pconn,
					    snum, path,
					    session_info);
	unbecome_root();

	return status;
}

/********************************************************
 Fake up a connection struct for the VFS layer.
 Note: this performs a vfs connect and CHANGES CWD !!!! JRA.

 The old working directory is returned on *poldcwd, allocated on ctx.
*********************************************************/

NTSTATUS create_conn_struct_cwd(TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct messaging_context *msg,
				connection_struct **pconn,
				int snum,
				const char *path,
				const struct auth_session_info *session_info,
				char **poldcwd)
{
	connection_struct *conn;
	char *oldcwd;

	NTSTATUS status = create_conn_struct(ctx, ev,
					     msg, &conn,
					     snum, path,
					     session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Windows seems to insist on doing trans2getdfsreferral() calls on
	 * the IPC$ share as the anonymous user. If we try to chdir as that
	 * user we will fail.... WTF ? JRA.
	 */

	oldcwd = vfs_GetWd(ctx, conn);
	if (oldcwd == NULL) {
		status = map_nt_error_from_unix(errno);
		DEBUG(3, ("vfs_GetWd failed: %s\n", strerror(errno)));
		conn_free(conn);
		return status;
	}

	if (vfs_ChDir(conn,conn->connectpath) != 0) {
		status = map_nt_error_from_unix(errno);
		DEBUG(3,("create_conn_struct: Can't ChDir to new conn path %s. "
			"Error was %s\n",
			conn->connectpath, strerror(errno) ));
		conn_free(conn);
		return status;
	}

	*pconn = conn;
	*poldcwd = oldcwd;

	return NT_STATUS_OK;
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

static bool parse_msdfs_symlink(TALLOC_CTX *ctx,
				const char *target,
				struct referral **preflist,
				int *refcount)
{
	char *temp = NULL;
	char *prot;
	char **alt_path = NULL;
	int count = 0, i;
	struct referral *reflist;
	char *saveptr;

	temp = talloc_strdup(ctx, target);
	if (!temp) {
		return False;
	}
	prot = strtok_r(temp, ":", &saveptr);
	if (!prot) {
		DEBUG(0,("parse_msdfs_symlink: invalid path !\n"));
		return False;
	}

	alt_path = talloc_array(ctx, char *, MAX_REFERRAL_COUNT);
	if (!alt_path) {
		return False;
	}

	/* parse out the alternate paths */
	while((count<MAX_REFERRAL_COUNT) &&
	      ((alt_path[count] = strtok_r(NULL, ",", &saveptr)) != NULL)) {
		count++;
	}

	DEBUG(10,("parse_msdfs_symlink: count=%d\n", count));

	if (count) {
		reflist = *preflist = talloc_zero_array(ctx,
				struct referral, count);
		if(reflist == NULL) {
			TALLOC_FREE(alt_path);
			return False;
		}
	} else {
		reflist = *preflist = NULL;
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

		reflist[i].alternate_path = talloc_asprintf(ctx,
				"\\%s",
				p);
		if (!reflist[i].alternate_path) {
			return False;
		}

		reflist[i].proximity = 0;
		reflist[i].ttl = REFERRAL_TTL;
		DEBUG(10, ("parse_msdfs_symlink: Created alt path: %s\n",
					reflist[i].alternate_path));
	}

	*refcount = count;

	TALLOC_FREE(alt_path);
	return True;
}

/**********************************************************************
 Returns true if the unix path is a valid msdfs symlink and also
 returns the target string from inside the link.
**********************************************************************/

static bool is_msdfs_link_internal(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *path,
			char **pp_link_target,
			SMB_STRUCT_STAT *sbufp)
{
	int referral_len = 0;
#if defined(HAVE_BROKEN_READLINK)
	char link_target_buf[PATH_MAX];
#else
	char link_target_buf[7];
#endif
	size_t bufsize = 0;
	char *link_target = NULL;
	struct smb_filename smb_fname;

	if (pp_link_target) {
		bufsize = 1024;
		link_target = talloc_array(ctx, char, bufsize);
		if (!link_target) {
			return False;
		}
		*pp_link_target = link_target;
	} else {
		bufsize = sizeof(link_target_buf);
		link_target = link_target_buf;
	}

	ZERO_STRUCT(smb_fname);
	smb_fname.base_name = discard_const_p(char, path);

	if (SMB_VFS_LSTAT(conn, &smb_fname) != 0) {
		DEBUG(5,("is_msdfs_link_read_target: %s does not exist.\n",
			path));
		goto err;
	}
	if (!S_ISLNK(smb_fname.st.st_ex_mode)) {
		DEBUG(5,("is_msdfs_link_read_target: %s is not a link.\n",
					path));
		goto err;
	}
	if (sbufp != NULL) {
		*sbufp = smb_fname.st;
	}

	referral_len = SMB_VFS_READLINK(conn, path, link_target, bufsize - 1);
	if (referral_len == -1) {
		DEBUG(0,("is_msdfs_link_read_target: Error reading "
			"msdfs link %s: %s\n",
			path, strerror(errno)));
		goto err;
	}
	link_target[referral_len] = '\0';

	DEBUG(5,("is_msdfs_link_internal: %s -> %s\n",path,
				link_target));

	if (!strnequal(link_target, "msdfs:", 6)) {
		goto err;
	}
	return True;

  err:

	if (link_target != link_target_buf) {
		TALLOC_FREE(link_target);
	}
	return False;
}

/**********************************************************************
 Returns true if the unix path is a valid msdfs symlink.
**********************************************************************/

bool is_msdfs_link(connection_struct *conn,
		const char *path,
		SMB_STRUCT_STAT *sbufp)
{
	return is_msdfs_link_internal(talloc_tos(),
					conn,
					path,
					NULL,
					sbufp);
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
		bool search_flag, /* Called from a findfirst ? */
		int *consumedcntp,
		char **pp_targetpath)
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

	status = unix_convert(ctx, conn, pdp->reqpath, &smb_fname,
			      search_flag ? UCF_ALWAYS_ALLOW_WCARD_LCOMP : 0);

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

	if (is_msdfs_link_internal(ctx, conn, smb_fname->base_name,
				   pp_targetpath, NULL)) {
		if (search_flag) {
			DEBUG(6,("dfs_path_lookup (FindFirst) No redirection "
				 "for dfs link %s.\n", dfspath));
			status = NT_STATUS_OK;
			goto out;
		}

		DEBUG(6,("dfs_path_lookup: %s resolves to a "
			"valid dfs link %s.\n", dfspath,
			pp_targetpath ? *pp_targetpath : ""));

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

		if (is_msdfs_link_internal(ctx, conn,
					   smb_fname->base_name, pp_targetpath,
					   NULL)) {
			DEBUG(4, ("dfs_path_lookup: Redirecting %s because "
				  "parent %s is dfs link\n", dfspath,
				  smb_fname_str_dbg(smb_fname)));

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
			bool search_wcard_flag,
			bool allow_broken_path,
			char **pp_path_out,
			bool *ppath_contains_wcard)
{
	NTSTATUS status;
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

	if (!( strequal(pdp->servicename, lp_servicename(talloc_tos(), SNUM(conn)))
			|| (strequal(pdp->servicename, HOMES_NAME)
			&& strequal(lp_servicename(talloc_tos(), SNUM(conn)),
				conn->session_info->unix_info->sanitized_username) )) ) {

		/* The given sharename doesn't match this connection. */
		TALLOC_FREE(pdp);

		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	status = dfs_path_lookup(ctx, conn, path_in, pdp,
			search_wcard_flag, NULL, NULL);
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
			const char *dfs_path,
			bool allow_broken_path,
			struct junction_map *jucn,
			int *consumedcntp,
			bool *self_referralp)
{
	struct connection_struct *conn;
	char *targetpath = NULL;
	int snum;
	NTSTATUS status = NT_STATUS_NOT_FOUND;
	bool dummy;
	struct dfs_path *pdp = talloc(ctx, struct dfs_path);
	char *oldpath;

	if (!pdp) {
		return NT_STATUS_NO_MEMORY;
	}

	*self_referralp = False;

	status = parse_dfs_path(NULL, dfs_path, False, allow_broken_path,
				pdp, &dummy);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	jucn->service_name = talloc_strdup(ctx, pdp->servicename);
	jucn->volume_name = talloc_strdup(ctx, pdp->reqpath);
	if (!jucn->service_name || !jucn->volume_name) {
		TALLOC_FREE(pdp);
		return NT_STATUS_NO_MEMORY;
	}

	/* Verify the share is a dfs root */
	snum = lp_servicenumber(jucn->service_name);
	if(snum < 0) {
		char *service_name = NULL;
		if ((snum = find_service(ctx, jucn->service_name, &service_name)) < 0) {
			return NT_STATUS_NOT_FOUND;
		}
		if (!service_name) {
			return NT_STATUS_NO_MEMORY;
		}
		TALLOC_FREE(jucn->service_name);
		jucn->service_name = talloc_strdup(ctx, service_name);
		if (!jucn->service_name) {
			TALLOC_FREE(pdp);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (!lp_msdfs_root(snum) && (*lp_msdfs_proxy(talloc_tos(), snum) == '\0')) {
		DEBUG(3,("get_referred_path: |%s| in dfs path %s is not "
			"a dfs root.\n",
			pdp->servicename, dfs_path));
		TALLOC_FREE(pdp);
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
		int refcount;

		if (*lp_msdfs_proxy(talloc_tos(), snum) == '\0') {
			TALLOC_FREE(pdp);
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

		tmp = talloc_asprintf(talloc_tos(), "msdfs:%s",
				      lp_msdfs_proxy(talloc_tos(), snum));
		if (tmp == NULL) {
			TALLOC_FREE(pdp);
			return NT_STATUS_NO_MEMORY;
		}

		if (!parse_msdfs_symlink(ctx, tmp, &ref, &refcount)) {
			TALLOC_FREE(tmp);
			TALLOC_FREE(pdp);
			return NT_STATUS_INVALID_PARAMETER;
		}
		TALLOC_FREE(tmp);
		jucn->referral_count = refcount;
		jucn->referral_list = ref;
		*consumedcntp = strlen(dfs_path);
		TALLOC_FREE(pdp);
		return NT_STATUS_OK;
	}

	status = create_conn_struct_cwd(ctx,
					server_event_context(),
					server_messaging_context(),
					&conn, snum,
					lp_path(talloc_tos(), snum), NULL, &oldpath);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(pdp);
		return status;
	}

	/* If this is a DFS path dfs_lookup should return
	 * NT_STATUS_PATH_NOT_COVERED. */

	status = dfs_path_lookup(ctx, conn, dfs_path, pdp,
			False, consumedcntp, &targetpath);

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

	/* We know this is a valid dfs link. Parse the targetpath. */
	if (!parse_msdfs_symlink(ctx, targetpath,
				&jucn->referral_list,
				&jucn->referral_count)) {
		DEBUG(3,("get_referred_path: failed to parse symlink "
			"target %s\n", targetpath ));
		status = NT_STATUS_NOT_FOUND;
		goto err_exit;
	}

	status = NT_STATUS_OK;
 err_exit:
	vfs_ChDir(conn, oldpath);
	SMB_VFS_DISCONNECT(conn);
	conn_free(conn);
	TALLOC_FREE(pdp);
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
	jucn->comment = lp_comment(ctx, snum);

	TALLOC_FREE(pdp);
	if (!jucn->service_name || !jucn->volume_name || ! jucn->comment) {
		return False;
	}
	return True;
}

/**********************************************************************
 Forms a valid Unix pathname from the junction
 **********************************************************************/

static bool junction_to_local_path(const struct junction_map *jucn,
				   char **pp_path_out,
				   connection_struct **conn_out,
				   char **oldpath)
{
	int snum;
	NTSTATUS status;

	snum = lp_servicenumber(jucn->service_name);
	if(snum < 0) {
		return False;
	}
	status = create_conn_struct_cwd(talloc_tos(),
					server_event_context(),
					server_messaging_context(),
					conn_out,
					snum, lp_path(talloc_tos(), snum), NULL, oldpath);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	*pp_path_out = talloc_asprintf(*conn_out,
			"%s/%s",
			lp_path(talloc_tos(), snum),
			jucn->volume_name);
	if (!*pp_path_out) {
		vfs_ChDir(*conn_out, *oldpath);
		SMB_VFS_DISCONNECT(*conn_out);
		conn_free(*conn_out);
		return False;
	}
	return True;
}

bool create_msdfs_link(const struct junction_map *jucn)
{
	char *path = NULL;
	char *cwd;
	char *msdfs_link = NULL;
	connection_struct *conn;
	int i=0;
	bool insert_comma = False;
	bool ret = False;

	if(!junction_to_local_path(jucn, &path, &conn, &cwd)) {
		return False;
	}

	/* Form the msdfs_link contents */
	msdfs_link = talloc_strdup(conn, "msdfs:");
	if (!msdfs_link) {
		goto out;
	}
	for(i=0; i<jucn->referral_count; i++) {
		char *refpath = jucn->referral_list[i].alternate_path;

		/* Alternate paths always use Windows separators. */
		trim_char(refpath, '\\', '\\');
		if(*refpath == '\0') {
			if (i == 0) {
				insert_comma = False;
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

		if (!msdfs_link) {
			goto out;
		}
		if (!insert_comma) {
			insert_comma = True;
		}
	}

	DEBUG(5,("create_msdfs_link: Creating new msdfs link: %s -> %s\n",
		path, msdfs_link));

	if(SMB_VFS_SYMLINK(conn, msdfs_link, path) < 0) {
		if (errno == EEXIST) {
			struct smb_filename *smb_fname;

			smb_fname = synthetic_smb_fname(talloc_tos(), path,
							NULL, NULL);
			if (smb_fname == NULL) {
				errno = ENOMEM;
				goto out;
			}

			if(SMB_VFS_UNLINK(conn, smb_fname)!=0) {
				TALLOC_FREE(smb_fname);
				goto out;
			}
			TALLOC_FREE(smb_fname);
		}
		if (SMB_VFS_SYMLINK(conn, msdfs_link, path) < 0) {
			DEBUG(1,("create_msdfs_link: symlink failed "
				 "%s -> %s\nError: %s\n",
				 path, msdfs_link, strerror(errno)));
			goto out;
		}
	}

	ret = True;

out:
	vfs_ChDir(conn, cwd);
	SMB_VFS_DISCONNECT(conn);
	conn_free(conn);
	return ret;
}

bool remove_msdfs_link(const struct junction_map *jucn)
{
	char *path = NULL;
	char *cwd;
	connection_struct *conn;
	bool ret = False;
	struct smb_filename *smb_fname;

	if (!junction_to_local_path(jucn, &path, &conn, &cwd)) {
		return false;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(), path, NULL, NULL);
	if (smb_fname == NULL) {
		errno = ENOMEM;
		return false;
	}

	if( SMB_VFS_UNLINK(conn, smb_fname) == 0 ) {
		ret = True;
	}

	TALLOC_FREE(smb_fname);
	vfs_ChDir(conn, cwd);
	SMB_VFS_DISCONNECT(conn);
	conn_free(conn);
	return ret;
}

/*********************************************************************
 Return the number of DFS links at the root of this share.
*********************************************************************/

static int count_dfs_links(TALLOC_CTX *ctx, int snum)
{
	size_t cnt = 0;
	DIR *dirp = NULL;
	const char *dname = NULL;
	char *talloced = NULL;
	const char *connect_path = lp_path(talloc_tos(), snum);
	const char *msdfs_proxy = lp_msdfs_proxy(talloc_tos(), snum);
	connection_struct *conn;
	NTSTATUS status;
	char *cwd;

	if(*connect_path == '\0') {
		return 0;
	}

	/*
	 * Fake up a connection struct for the VFS layer.
	 */

	status = create_conn_struct_cwd(talloc_tos(),
					server_event_context(),
					server_messaging_context(),
					&conn,
					snum, connect_path, NULL, &cwd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("create_conn_struct failed: %s\n",
			  nt_errstr(status)));
		return 0;
	}

	/* Count a link for the msdfs root - convention */
	cnt = 1;

	/* No more links if this is an msdfs proxy. */
	if (*msdfs_proxy != '\0') {
		goto out;
	}

	/* Now enumerate all dfs links */
	dirp = SMB_VFS_OPENDIR(conn, ".", NULL, 0);
	if(!dirp) {
		goto out;
	}

	while ((dname = vfs_readdirname(conn, dirp, NULL, &talloced))
	       != NULL) {
		if (is_msdfs_link(conn,
				dname,
				NULL)) {
			cnt++;
		}
		TALLOC_FREE(talloced);
	}

	SMB_VFS_CLOSEDIR(conn,dirp);

out:
	vfs_ChDir(conn, cwd);
	SMB_VFS_DISCONNECT(conn);
	conn_free(conn);
	return cnt;
}

/*********************************************************************
*********************************************************************/

static int form_junctions(TALLOC_CTX *ctx,
				int snum,
				struct junction_map *jucn,
				size_t jn_remain)
{
	size_t cnt = 0;
	DIR *dirp = NULL;
	const char *dname = NULL;
	char *talloced = NULL;
	const char *connect_path = lp_path(talloc_tos(), snum);
	char *service_name = lp_servicename(talloc_tos(), snum);
	const char *msdfs_proxy = lp_msdfs_proxy(talloc_tos(), snum);
	connection_struct *conn;
	struct referral *ref = NULL;
	char *cwd;
	NTSTATUS status;

	if (jn_remain == 0) {
		return 0;
	}

	if(*connect_path == '\0') {
		return 0;
	}

	/*
	 * Fake up a connection struct for the VFS layer.
	 */

	status = create_conn_struct_cwd(ctx,
					server_event_context(),
					server_messaging_context(),
					&conn, snum, connect_path, NULL,
					&cwd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("create_conn_struct failed: %s\n",
			  nt_errstr(status)));
		return 0;
	}

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

	/* Now enumerate all dfs links */
	dirp = SMB_VFS_OPENDIR(conn, ".", NULL, 0);
	if(!dirp) {
		goto out;
	}

	while ((dname = vfs_readdirname(conn, dirp, NULL, &talloced))
	       != NULL) {
		char *link_target = NULL;
		if (cnt >= jn_remain) {
			DEBUG(2, ("form_junctions: ran out of MSDFS "
				"junction slots"));
			TALLOC_FREE(talloced);
			goto out;
		}
		if (is_msdfs_link_internal(ctx,
					conn,
					dname, &link_target,
					NULL)) {
			if (parse_msdfs_symlink(ctx,
					link_target,
					&jucn[cnt].referral_list,
					&jucn[cnt].referral_count)) {

				jucn[cnt].service_name = talloc_strdup(ctx,
								service_name);
				jucn[cnt].volume_name = talloc_strdup(ctx,
								dname);
				if (!jucn[cnt].service_name ||
						!jucn[cnt].volume_name) {
					TALLOC_FREE(talloced);
					goto out;
				}
				jucn[cnt].comment = "";
				cnt++;
			}
			TALLOC_FREE(link_target);
		}
		TALLOC_FREE(talloced);
	}

out:

	if (dirp) {
		SMB_VFS_CLOSEDIR(conn,dirp);
	}

	vfs_ChDir(conn, cwd);
	conn_free(conn);
	return cnt;
}

struct junction_map *enum_msdfs_links(TALLOC_CTX *ctx, size_t *p_num_jn)
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
			jn_count += count_dfs_links(ctx, i);
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
			*p_num_jn += form_junctions(ctx, i,
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
				bool dfs_pathnames,
				const char *name_in,
				bool allow_wcards,
				bool allow_broken_path,
				char **pp_name_out,
				bool *ppath_contains_wcard)
{
	bool path_contains_wcard;
	NTSTATUS status = NT_STATUS_OK;

	if (dfs_pathnames) {
		status = dfs_redirect(ctx,
					conn,
					name_in,
					allow_wcards,
					allow_broken_path,
					pp_name_out,
					&path_contains_wcard);

		if (NT_STATUS_IS_OK(status) && ppath_contains_wcard != NULL) {
			*ppath_contains_wcard = path_contains_wcard;
		}
	} else {
		/*
		 * Cheat and just return a copy of the in ptr.
		 * Once srvstr_get_path() uses talloc it'll
		 * be a talloced ptr anyway.
		 */
		*pp_name_out = discard_const_p(char, name_in);
	}
	return status;
}
