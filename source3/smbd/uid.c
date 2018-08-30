/* 
   Unix SMB/CIFS implementation.
   uid/user handling
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
#include "system/passwd.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "libcli/security/security.h"
#include "passdb/lookup_sid.h"
#include "auth.h"
#include "../auth/auth_util.h"
#include "lib/util/time_basic.h"
#include "lib/pthreadpool/pthreadpool_tevent.h"

static struct smb_vfs_ev_glue *smbd_impersonate_user_ev_glue_create(
				struct connection_struct *conn,
				uint64_t vuid,
				struct auth_session_info *session_info);

struct smbd_impersonate_debug_state {
	int dbg_lvl;
	const char *name;
};

static bool smbd_impersonate_debug_before_use(struct tevent_context *wrap_ev,
					      void *private_data,
					      struct tevent_context *main_ev,
					      const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev, location));

	return true;
}

static void smbd_impersonate_debug_after_use(struct tevent_context *wrap_ev,
					     void *private_data,
					     struct tevent_context *main_ev,
					     const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev, location));
}

static void smbd_impersonate_debug_before_fd_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_fd *fde,
						uint16_t flags,
						const char *handler_name,
						const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] "
	      "fde[%p] flags[0x%X] handler_name[%s] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev,
	      fde, flags, handler_name, location));
}

static void smbd_impersonate_debug_after_fd_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_fd *fde,
						uint16_t flags,
						const char *handler_name,
						const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] "
	      "fde[%p] flags[0x%X] handler_name[%s] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev,
	      fde, flags, handler_name, location));
}

static void smbd_impersonate_debug_before_timer_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_timer *te,
						struct timeval requested_time,
						struct timeval trigger_time,
						const char *handler_name,
						const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;
	struct timeval_buf requested_buf;
	struct timeval_buf trigger_buf;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] "
	      "te[%p] requested_time[%s] trigger_time[%s] handler_name[%s] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev, te,
	      timeval_str_buf(&requested_time, true, true, &requested_buf),
	      timeval_str_buf(&trigger_time, true, true, &trigger_buf),
	      handler_name, location));
}

static void smbd_impersonate_debug_after_timer_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_timer *te,
						struct timeval requested_time,
						struct timeval trigger_time,
						const char *handler_name,
						const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;
	struct timeval_buf requested_buf;
	struct timeval_buf trigger_buf;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] "
	      "te[%p] requested_time[%s] trigger_time[%s] handler_name[%s] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev, te,
	      timeval_str_buf(&requested_time, true, true, &requested_buf),
	      timeval_str_buf(&trigger_time, true, true, &trigger_buf),
	      handler_name, location));
}

static void smbd_impersonate_debug_before_immediate_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_immediate *im,
						const char *handler_name,
						const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] "
	      "im[%p] handler_name[%s] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev,
	      im, handler_name, location));
}

static void smbd_impersonate_debug_after_immediate_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_immediate *im,
						const char *handler_name,
						const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] "
	      "im[%p] handler_name[%s] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev,
	      im, handler_name, location));
}

static void smbd_impersonate_debug_before_signal_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_signal *se,
						int signum,
						int count,
						void *siginfo,
						const char *handler_name,
						const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] "
	      "se[%p] signum[%d] count[%d] siginfo[%p] handler_name[%s] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev,
	      se, signum, count, siginfo, handler_name, location));
}

static void smbd_impersonate_debug_after_signal_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_signal *se,
						int signum,
						int count,
						void *siginfo,
						const char *handler_name,
						const char *location)
{
	struct smbd_impersonate_debug_state *state =
		(struct smbd_impersonate_debug_state *)private_data;

	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] "
	      "se[%p] signum[%d] count[%d] siginfo[%p] handler_name[%s] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev,
	      se, signum, count, siginfo, handler_name, location));
}

static const struct tevent_wrapper_ops smbd_impersonate_debug_ops = {
	.name				= "smbd_impersonate_debug",
	.before_use			= smbd_impersonate_debug_before_use,
	.after_use			= smbd_impersonate_debug_after_use,
	.before_fd_handler		= smbd_impersonate_debug_before_fd_handler,
	.after_fd_handler		= smbd_impersonate_debug_after_fd_handler,
	.before_timer_handler		= smbd_impersonate_debug_before_timer_handler,
	.after_timer_handler		= smbd_impersonate_debug_after_timer_handler,
	.before_immediate_handler	= smbd_impersonate_debug_before_immediate_handler,
	.after_immediate_handler	= smbd_impersonate_debug_after_immediate_handler,
	.before_signal_handler		= smbd_impersonate_debug_before_signal_handler,
	.after_signal_handler		= smbd_impersonate_debug_after_signal_handler,
};

struct tevent_context *_smbd_impersonate_debug_create(struct tevent_context *main_ev,
						      const char *name,
						      int dbg_lvl,
						      const char *location)
{
	struct tevent_context *wrap_ev = NULL;
	struct smbd_impersonate_debug_state *state = NULL;

	wrap_ev = tevent_context_wrapper_create(main_ev,
					main_ev,
					&smbd_impersonate_debug_ops,
					&state,
					struct smbd_impersonate_debug_state);
	if (wrap_ev == NULL) {
		return NULL;
	}
	state->name = name;
	state->dbg_lvl = dbg_lvl;
	DEBUG(state->dbg_lvl, (
	      "%s: name[%s] wrap_ev[%p] state[%p] main_ev[%p] location[%s]\n",
	      __func__, state->name, wrap_ev, state, main_ev, location));

	return wrap_ev;
}

/* what user is current? */
extern struct current_user current_user;

/****************************************************************************
 Become the guest user without changing the security context stack.
****************************************************************************/

bool change_to_guest(void)
{
	struct passwd *pass;

	pass = Get_Pwnam_alloc(talloc_tos(), lp_guest_account());
	if (!pass) {
		return false;
	}

#ifdef AIX
	/* MWW: From AIX FAQ patch to WU-ftpd: call initgroups before 
	   setting IDs */
	initgroups(pass->pw_name, pass->pw_gid);
#endif

	set_sec_ctx(pass->pw_uid, pass->pw_gid, 0, NULL, NULL);

	current_user.conn = NULL;
	current_user.vuid = UID_FIELD_INVALID;
	current_user.need_chdir = false;
	current_user.done_chdir = false;

	TALLOC_FREE(pass);

	return true;
}

/****************************************************************************
 talloc free the conn->session_info if not used in the vuid cache.
****************************************************************************/

static void free_conn_session_info_if_unused(connection_struct *conn)
{
	unsigned int i;

	for (i = 0; i < VUID_CACHE_SIZE; i++) {
		struct vuid_cache_entry *ent;
		ent = &conn->vuid_cache->array[i];
		if (ent->vuid != UID_FIELD_INVALID &&
				conn->session_info == ent->session_info) {
			return;
		}
	}
	/* Not used, safe to free. */
	conn->user_ev_ctx = NULL;
	TALLOC_FREE(conn->user_vfs_evg);
	TALLOC_FREE(conn->session_info);
}

/****************************************************************************
  Setup the share access mask for a connection.
****************************************************************************/

static uint32_t create_share_access_mask(int snum,
				bool readonly_share,
				const struct security_token *token)
{
	uint32_t share_access = 0;

	share_access_check(token,
			lp_const_servicename(snum),
			MAXIMUM_ALLOWED_ACCESS,
			&share_access);

	if (readonly_share) {
		share_access &=
			~(SEC_FILE_WRITE_DATA | SEC_FILE_APPEND_DATA |
			  SEC_FILE_WRITE_EA | SEC_FILE_WRITE_ATTRIBUTE |
			  SEC_DIR_DELETE_CHILD );
	}

	if (security_token_has_privilege(token, SEC_PRIV_SECURITY)) {
		share_access |= SEC_FLAG_SYSTEM_SECURITY;
	}
	if (security_token_has_privilege(token, SEC_PRIV_RESTORE)) {
		share_access |= SEC_RIGHTS_PRIV_RESTORE;
	}
	if (security_token_has_privilege(token, SEC_PRIV_BACKUP)) {
		share_access |= SEC_RIGHTS_PRIV_BACKUP;
	}
	if (security_token_has_privilege(token, SEC_PRIV_TAKE_OWNERSHIP)) {
		share_access |= SEC_STD_WRITE_OWNER;
	}

	return share_access;
}

/*******************************************************************
 Calculate access mask and if this user can access this share.
********************************************************************/

NTSTATUS check_user_share_access(connection_struct *conn,
				const struct auth_session_info *session_info,
				uint32_t *p_share_access,
				bool *p_readonly_share)
{
	int snum = SNUM(conn);
	uint32_t share_access = 0;
	bool readonly_share = false;

	if (!user_ok_token(session_info->unix_info->unix_name,
			   session_info->info->domain_name,
			   session_info->security_token, snum)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	readonly_share = is_share_read_only_for_token(
		session_info->unix_info->unix_name,
		session_info->info->domain_name,
		session_info->security_token,
		conn);

	share_access = create_share_access_mask(snum,
					readonly_share,
					session_info->security_token);

	if ((share_access & (FILE_READ_DATA|FILE_WRITE_DATA)) == 0) {
		/* No access, read or write. */
		DBG_NOTICE("user %s connection to %s denied due to share "
			 "security descriptor.\n",
			 session_info->unix_info->unix_name,
			 lp_const_servicename(snum));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!readonly_share &&
	    !(share_access & FILE_WRITE_DATA)) {
		/* smb.conf allows r/w, but the security descriptor denies
		 * write. Fall back to looking at readonly. */
		readonly_share = true;
		DBG_INFO("falling back to read-only access-evaluation due to "
			 "security descriptor\n");
	}

	*p_share_access = share_access;
	*p_readonly_share = readonly_share;

	return NT_STATUS_OK;
}

/*******************************************************************
 Check if a username is OK.

 This sets up conn->session_info with a copy related to this vuser that
 later code can then mess with.
********************************************************************/

static bool check_user_ok(connection_struct *conn,
			uint64_t vuid,
			const struct auth_session_info *session_info,
			int snum)
{
	unsigned int i;
	bool readonly_share = false;
	bool admin_user = false;
	struct vuid_cache_entry *ent = NULL;
	uint32_t share_access = 0;
	NTSTATUS status;

	for (i=0; i<VUID_CACHE_SIZE; i++) {
		ent = &conn->vuid_cache->array[i];
		if (ent->vuid == vuid) {
			if (vuid == UID_FIELD_INVALID) {
				/*
				 * Slow path, we don't care
				 * about the array traversal.
				*/
				continue;
			}
			free_conn_session_info_if_unused(conn);
			conn->session_info = ent->session_info;
			conn->user_vfs_evg = ent->user_vfs_evg;
			conn->read_only = ent->read_only;
			conn->share_access = ent->share_access;
			conn->vuid = ent->vuid;
			conn->user_ev_ctx = smb_vfs_ev_glue_ev_ctx(
						conn->user_vfs_evg);
			SMB_ASSERT(conn->user_ev_ctx != NULL);
			return(True);
		}
	}

	status = check_user_share_access(conn,
					session_info,
					&share_access,
					&readonly_share);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	admin_user = token_contains_name_in_list(
		session_info->unix_info->unix_name,
		session_info->info->domain_name,
		NULL, session_info->security_token, lp_admin_users(snum));

	ent = &conn->vuid_cache->array[conn->vuid_cache->next_entry];

	conn->vuid_cache->next_entry =
		(conn->vuid_cache->next_entry + 1) % VUID_CACHE_SIZE;

	TALLOC_FREE(ent->session_info);

	/*
	 * If force_user was set, all session_info's are based on the same
	 * username-based faked one.
	 */

	ent->session_info = copy_session_info(
		conn, conn->force_user ? conn->session_info : session_info);

	if (ent->session_info == NULL) {
		ent->vuid = UID_FIELD_INVALID;
		return false;
	}

	if (admin_user) {
		DEBUG(2,("check_user_ok: user %s is an admin user. "
			"Setting uid as %d\n",
			ent->session_info->unix_info->unix_name,
			sec_initial_uid() ));
		ent->session_info->unix_token->uid = sec_initial_uid();
	}

	ent->user_vfs_evg = smbd_impersonate_user_ev_glue_create(conn,
							vuid, ent->session_info);
	if (ent->user_vfs_evg == NULL) {
		TALLOC_FREE(ent->session_info);
		ent->vuid = UID_FIELD_INVALID;
		return false;
	}

	/*
	 * It's actually OK to call check_user_ok() with
	 * vuid == UID_FIELD_INVALID as called from change_to_user_by_session().
	 * All this will do is throw away one entry in the cache.
	 */

	ent->vuid = vuid;
	ent->read_only = readonly_share;
	ent->share_access = share_access;
	free_conn_session_info_if_unused(conn);
	conn->session_info = ent->session_info;
	conn->vuid = ent->vuid;
	conn->user_vfs_evg = ent->user_vfs_evg;
	conn->user_ev_ctx = smb_vfs_ev_glue_ev_ctx(conn->user_vfs_evg);
	SMB_ASSERT(conn->user_ev_ctx != NULL);

	if (vuid == UID_FIELD_INVALID) {
		/*
		 * Not strictly needed, just make it really
		 * clear this entry is actually an unused one.
		 */
		ent->read_only = false;
		ent->share_access = 0;
		ent->session_info = NULL;
		ent->user_vfs_evg = NULL;
	}

	conn->read_only = readonly_share;
	conn->share_access = share_access;

	return(True);
}

/****************************************************************************
 Become the user of a connection number without changing the security context
 stack, but modify the current_user entries.
****************************************************************************/

static bool change_to_user_internal(connection_struct *conn,
				    const struct auth_session_info *session_info,
				    uint64_t vuid)
{
	int snum;
	gid_t gid;
	uid_t uid;
	char group_c;
	int num_groups = 0;
	gid_t *group_list = NULL;
	bool ok;

	if ((current_user.conn == conn) &&
	    (current_user.vuid == vuid) &&
	    (current_user.need_chdir == conn->tcon_done) &&
	    (current_user.ut.uid == session_info->unix_token->uid))
	{
		DBG_INFO("Skipping user change - already user\n");
		return true;
	}

	set_current_user_info(session_info->unix_info->sanitized_username,
			      session_info->unix_info->unix_name,
			      session_info->info->domain_name);

	snum = SNUM(conn);

	ok = check_user_ok(conn, vuid, session_info, snum);
	if (!ok) {
		DBG_WARNING("SMB user %s (unix user %s) "
			 "not permitted access to share %s.\n",
			 session_info->unix_info->sanitized_username,
			 session_info->unix_info->unix_name,
			 lp_const_servicename(snum));
		return false;
	}

	uid = conn->session_info->unix_token->uid;
	gid = conn->session_info->unix_token->gid;
	num_groups = conn->session_info->unix_token->ngroups;
	group_list  = conn->session_info->unix_token->groups;

	/*
	 * See if we should force group for this service. If so this overrides
	 * any group set in the force user code.
	 */
	if((group_c = *lp_force_group(talloc_tos(), snum))) {

		SMB_ASSERT(conn->force_group_gid != (gid_t)-1);

		if (group_c == '+') {
			int i;

			/*
			 * Only force group if the user is a member of the
			 * service group. Check the group memberships for this
			 * user (we already have this) to see if we should force
			 * the group.
			 */
			for (i = 0; i < num_groups; i++) {
				if (group_list[i] == conn->force_group_gid) {
					conn->session_info->unix_token->gid =
						conn->force_group_gid;
					gid = conn->force_group_gid;
					gid_to_sid(&conn->session_info->security_token
						   ->sids[1], gid);
					break;
				}
			}
		} else {
			conn->session_info->unix_token->gid = conn->force_group_gid;
			gid = conn->force_group_gid;
			gid_to_sid(&conn->session_info->security_token->sids[1],
				   gid);
		}
	}

	/*Set current_user since we will immediately also call set_sec_ctx() */
	current_user.ut.ngroups = num_groups;
	current_user.ut.groups  = group_list;

	set_sec_ctx(uid,
		    gid,
		    current_user.ut.ngroups,
		    current_user.ut.groups,
		    conn->session_info->security_token);

	current_user.conn = conn;
	current_user.vuid = vuid;
	current_user.need_chdir = conn->tcon_done;

	if (current_user.need_chdir) {
		ok = chdir_current_service(conn);
		if (!ok) {
			DBG_ERR("chdir_current_service() failed!\n");
			return false;
		}
		current_user.done_chdir = true;
	}

	if (CHECK_DEBUGLVL(DBGLVL_INFO)) {
		struct smb_filename *cwdfname = vfs_GetWd(talloc_tos(), conn);
		if (cwdfname == NULL) {
			return false;
		}
		DBG_INFO("Impersonated user: uid=(%d,%d), gid=(%d,%d), cwd=[%s]\n",
			 (int)getuid(),
			 (int)geteuid(),
			 (int)getgid(),
			 (int)getegid(),
			 cwdfname->base_name);
		TALLOC_FREE(cwdfname);
	}

	return true;
}

bool change_to_user(connection_struct *conn, uint64_t vuid)
{
	struct user_struct *vuser;
	int snum = SNUM(conn);

	if (!conn) {
		DEBUG(2,("Connection not open\n"));
		return(False);
	}

	vuser = get_valid_user_struct(conn->sconn, vuid);
	if (vuser == NULL) {
		/* Invalid vuid sent */
		DBG_WARNING("Invalid vuid %llu used on share %s.\n",
			    (unsigned long long)vuid,
			    lp_const_servicename(snum));
		return false;
	}

	return change_to_user_internal(conn, vuser->session_info, vuid);
}

bool change_to_user_by_fsp(struct files_struct *fsp)
{
	return change_to_user(fsp->conn, fsp->vuid);
}

static bool change_to_user_by_session(connection_struct *conn,
				      const struct auth_session_info *session_info)
{
	SMB_ASSERT(conn != NULL);
	SMB_ASSERT(session_info != NULL);

	return change_to_user_internal(conn, session_info, UID_FIELD_INVALID);
}

/****************************************************************************
 Go back to being root without changing the security context stack,
 but modify the current_user entries.
****************************************************************************/

bool smbd_change_to_root_user(void)
{
	set_root_sec_ctx();

	DEBUG(5,("change_to_root_user: now uid=(%d,%d) gid=(%d,%d)\n",
		(int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));

	current_user.conn = NULL;
	current_user.vuid = UID_FIELD_INVALID;
	current_user.need_chdir = false;
	current_user.done_chdir = false;

	return(True);
}

/****************************************************************************
 Become the user of an authenticated connected named pipe.
 When this is called we are currently running as the connection
 user. Doesn't modify current_user.
****************************************************************************/

bool smbd_become_authenticated_pipe_user(struct auth_session_info *session_info)
{
	if (!push_sec_ctx())
		return False;

	set_sec_ctx(session_info->unix_token->uid, session_info->unix_token->gid,
		    session_info->unix_token->ngroups, session_info->unix_token->groups,
		    session_info->security_token);

	DEBUG(5, ("Impersonated user: uid=(%d,%d), gid=(%d,%d)\n",
		 (int)getuid(),
		 (int)geteuid(),
		 (int)getgid(),
		 (int)getegid()));

	return True;
}

/****************************************************************************
 Unbecome the user of an authenticated connected named pipe.
 When this is called we are running as the authenticated pipe
 user and need to go back to being the connection user. Doesn't modify
 current_user.
****************************************************************************/

bool smbd_unbecome_authenticated_pipe_user(void)
{
	return pop_sec_ctx();
}

/****************************************************************************
 Utility functions used by become_xxx/unbecome_xxx.
****************************************************************************/

static void push_conn_ctx(void)
{
	struct conn_ctx *ctx_p;
	extern userdom_struct current_user_info;

	/* Check we don't overflow our stack */

	if (conn_ctx_stack_ndx == MAX_SEC_CTX_DEPTH) {
		DEBUG(0, ("Connection context stack overflow!\n"));
		smb_panic("Connection context stack overflow!\n");
	}

	/* Store previous user context */
	ctx_p = &conn_ctx_stack[conn_ctx_stack_ndx];

	ctx_p->conn = current_user.conn;
	ctx_p->vuid = current_user.vuid;
	ctx_p->need_chdir = current_user.need_chdir;
	ctx_p->done_chdir = current_user.done_chdir;
	ctx_p->user_info = current_user_info;

	DEBUG(4, ("push_conn_ctx(%llu) : conn_ctx_stack_ndx = %d\n",
		(unsigned long long)ctx_p->vuid, conn_ctx_stack_ndx));

	conn_ctx_stack_ndx++;
}

static void pop_conn_ctx(void)
{
	struct conn_ctx *ctx_p;

	/* Check for stack underflow. */

	if (conn_ctx_stack_ndx == 0) {
		DEBUG(0, ("Connection context stack underflow!\n"));
		smb_panic("Connection context stack underflow!\n");
	}

	conn_ctx_stack_ndx--;
	ctx_p = &conn_ctx_stack[conn_ctx_stack_ndx];

	set_current_user_info(ctx_p->user_info.smb_name,
			      ctx_p->user_info.unix_name,
			      ctx_p->user_info.domain);

	/*
	 * Check if the current context did a chdir_current_service()
	 * and restore the cwd_fname of the previous context
	 * if needed.
	 */
	if (current_user.done_chdir && ctx_p->need_chdir) {
		int ret;

		ret = vfs_ChDir(ctx_p->conn, ctx_p->conn->cwd_fname);
		if (ret != 0) {
			DBG_ERR("vfs_ChDir() failed!\n");
			smb_panic("vfs_ChDir() failed!\n");
		}
	}

	current_user.conn = ctx_p->conn;
	current_user.vuid = ctx_p->vuid;
	current_user.need_chdir = ctx_p->need_chdir;
	current_user.done_chdir = ctx_p->done_chdir;

	*ctx_p = (struct conn_ctx) {
		.vuid = UID_FIELD_INVALID,
	};
}

/****************************************************************************
 Temporarily become a root user.  Must match with unbecome_root(). Saves and
 restores the connection context.
****************************************************************************/

void smbd_become_root(void)
{
	 /*
	  * no good way to handle push_sec_ctx() failing without changing
	  * the prototype of become_root()
	  */
	if (!push_sec_ctx()) {
		smb_panic("become_root: push_sec_ctx failed");
	}
	push_conn_ctx();
	set_root_sec_ctx();
}

/* Unbecome the root user */

void smbd_unbecome_root(void)
{
	pop_sec_ctx();
	pop_conn_ctx();
}

bool become_guest(void)
{
	bool ok;

	ok = push_sec_ctx();
	if (!ok) {
		return false;
	}

	push_conn_ctx();

	ok = change_to_guest();
	if (!ok) {
		pop_sec_ctx();
		pop_conn_ctx();
		return false;
	}

	return true;
}

void unbecome_guest(void)
{
	pop_sec_ctx();
	pop_conn_ctx();
	return;
}

/****************************************************************************
 Push the current security context then force a change via change_to_user().
 Saves and restores the connection context.
****************************************************************************/

bool become_user(connection_struct *conn, uint64_t vuid)
{
	if (!push_sec_ctx())
		return False;

	push_conn_ctx();

	if (!change_to_user(conn, vuid)) {
		pop_sec_ctx();
		pop_conn_ctx();
		return False;
	}

	return True;
}

bool become_user_by_fsp(struct files_struct *fsp)
{
	return become_user(fsp->conn, fsp->vuid);
}

bool become_user_by_session(connection_struct *conn,
			    const struct auth_session_info *session_info)
{
	if (!push_sec_ctx())
		return false;

	push_conn_ctx();

	if (!change_to_user_by_session(conn, session_info)) {
		pop_sec_ctx();
		pop_conn_ctx();
		return false;
	}

	return true;
}

bool unbecome_user(void)
{
	pop_sec_ctx();
	pop_conn_ctx();
	return True;
}

/****************************************************************************
 Return the current user we are running effectively as on this connection.
 I'd like to make this return conn->session_info->unix_token->uid, but become_root()
 doesn't alter this value.
****************************************************************************/

uid_t get_current_uid(connection_struct *conn)
{
	return current_user.ut.uid;
}

/****************************************************************************
 Return the current group we are running effectively as on this connection.
 I'd like to make this return conn->session_info->unix_token->gid, but become_root()
 doesn't alter this value.
****************************************************************************/

gid_t get_current_gid(connection_struct *conn)
{
	return current_user.ut.gid;
}

/****************************************************************************
 Return the UNIX token we are running effectively as on this connection.
 I'd like to make this return &conn->session_info->unix_token-> but become_root()
 doesn't alter this value.
****************************************************************************/

const struct security_unix_token *get_current_utok(connection_struct *conn)
{
	return &current_user.ut;
}

/****************************************************************************
 Return the Windows token we are running effectively as on this connection.
 If this is currently a NULL token as we're inside become_root() - a temporary
 UNIX security override, then we search up the stack for the previous active
 token.
****************************************************************************/

const struct security_token *get_current_nttok(connection_struct *conn)
{
	if (current_user.nt_user_token) {
		return current_user.nt_user_token;
	}
	return sec_ctx_active_token();
}

uint64_t get_current_vuid(connection_struct *conn)
{
	return current_user.vuid;
}

struct smbd_impersonate_conn_vuid_state {
	struct connection_struct *conn;
	uint64_t vuid;
};

static bool smbd_impersonate_conn_vuid_before_use(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		const char *location)
{
	struct smbd_impersonate_conn_vuid_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_impersonate_conn_vuid_state);
	bool ok;

	DEBUG(11,("%s: wrap_ev[%p] main_ev[%p] location[%s]"
		  "old uid[%ju] old gid[%ju] vuid[%ju] cwd[%s]\n",
		  __func__, wrap_ev, main_ev, location,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  (uintmax_t)state->vuid, state->conn->cwd_fname->base_name));

	ok = become_user(state->conn, state->vuid);
	if (!ok) {
		smb_panic("smbd_impersonate_conn_vuid_before_use() - failed");
		return false;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));

	return true;
}

static void smbd_impersonate_conn_vuid_after_use(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		const char *location)
{
	struct smbd_impersonate_conn_vuid_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_impersonate_conn_vuid_state);
	bool ok;

	DEBUG(11,("%s: deimpersonating[%s] uid[%ju] gid[%ju] cwd[%s] "
		  "location[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name, location));

	ok = unbecome_user();
	if (!ok) {
		smb_panic("smbd_impersonate_conn_vuid_after_use() - failed");
		return;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_vuid_before_fd_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_fd *fde,
		uint16_t flags,
		const char *handler_name,
		const char *location)
{
	struct smbd_impersonate_conn_vuid_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_vuid_state);
	bool ok;

	DEBUG(11,("%s: fde[%p] flags[%ju] handler_name[%s] location[%s]\n",
		  __func__, fde, (uintmax_t)flags, handler_name, location));

	ok = change_to_user(state->conn, state->vuid);
	if (!ok) {
		smb_panic("smbd_impersonate_conn_vuid_before_use() - failed");
		return;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_vuid_after_fd_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_fd *fde,
		uint16_t flags,
		const char *handler_name,
		const char *location)
{
	DEBUG(11,("%s: fde[%p] handler_name[%s] location[%s]\n",
		  __func__, fde, handler_name, location));

	/* be lazy and defer change_to_root_user() */
}

static void smbd_impersonate_conn_vuid_before_timer_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_timer *te,
		struct timeval requested_time,
		struct timeval trigger_time,
		const char *handler_name,
		const char *location)
{
	struct smbd_impersonate_conn_vuid_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_vuid_state);
	struct timeval_buf requested_buf;
	struct timeval_buf trigger_buf;
	bool ok;

	DEBUG(11,("%s: te[%p] requested_time[%s] trigger_time[%s] "
		  "handler_name[%s] location[%s]\n",
		  __func__, te,
		  timeval_str_buf(&requested_time, true, true, &requested_buf),
		  timeval_str_buf(&trigger_time, true, true, &trigger_buf),
		  handler_name, location));

	ok = change_to_user(state->conn, state->vuid);
	if (!ok) {
		smb_panic("smbd_impersonate_conn_vuid_before_use() - failed");
		return;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_vuid_after_timer_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_timer *te,
		struct timeval requested_time,
		struct timeval trigger_time,
		const char *handler_name,
		const char *location)
{
	DEBUG(11,("%s: te[%p] handler_name[%s] location[%s]\n",
		  __func__, te, handler_name, location));

	/* be lazy and defer change_to_root_user() */
}

static void smbd_impersonate_conn_vuid_before_immediate_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_immediate *im,
		const char *handler_name,
		const char *location)
{
	struct smbd_impersonate_conn_vuid_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_vuid_state);
	bool ok;

	DEBUG(11,("%s: im[%p] handler_name[%s] location[%s]\n",
		  __func__, im, handler_name, location));

	ok = change_to_user(state->conn, state->vuid);
	if (!ok) {
		smb_panic("smbd_impersonate_conn_vuid_before_use() - failed");
		return;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_vuid_after_immediate_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_immediate *im,
		const char *handler_name,
		const char *location)
{
	DEBUG(11,("%s: im[%p] handler_name[%s] location[%s]\n",
		  __func__, im, handler_name, location));

	/* be lazy and defer unbecome_user() */
}

static void smbd_impersonate_conn_vuid_before_signal_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_signal *se,
		int signum,
		int count,
		void *siginfo,
		const char *handler_name,
		const char *location)
{
	struct smbd_impersonate_conn_vuid_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_vuid_state);
	bool ok;

	DEBUG(11,("%s: se[%p] signum[%d] count[%d] siginfo[%p] "
		  "handler_name[%s] location[%s]\n",
		  __func__, se, signum, count, siginfo, handler_name, location));

	ok = change_to_user(state->conn, state->vuid);
	if (!ok) {
		smb_panic("smbd_impersonate_conn_vuid_before_use() - failed");
		return;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_vuid_after_signal_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_signal *se,
		int signum,
		int count,
		void *siginfo,
		const char *handler_name,
		const char *location)
{
	DEBUG(11,("%s: se[%p] handler_name[%s] location[%s]\n",
		  __func__, se, handler_name, location));

	/* be lazy and defer change_to_root_user() */
}

static const struct tevent_wrapper_ops smbd_impersonate_conn_vuid_ops = {
	.name				= "smbd_impersonate_conn_vuid",
	.before_use			= smbd_impersonate_conn_vuid_before_use,
	.after_use			= smbd_impersonate_conn_vuid_after_use,
	.before_fd_handler		= smbd_impersonate_conn_vuid_before_fd_handler,
	.after_fd_handler		= smbd_impersonate_conn_vuid_after_fd_handler,
	.before_timer_handler		= smbd_impersonate_conn_vuid_before_timer_handler,
	.after_timer_handler		= smbd_impersonate_conn_vuid_after_timer_handler,
	.before_immediate_handler	= smbd_impersonate_conn_vuid_before_immediate_handler,
	.after_immediate_handler	= smbd_impersonate_conn_vuid_after_immediate_handler,
	.before_signal_handler		= smbd_impersonate_conn_vuid_before_signal_handler,
	.after_signal_handler		= smbd_impersonate_conn_vuid_after_signal_handler,
};

struct tevent_context *smbd_impersonate_conn_vuid_create(
				struct tevent_context *main_ev,
				struct connection_struct *conn,
				uint64_t vuid)
{
	struct tevent_context *ev = NULL;
	struct smbd_impersonate_conn_vuid_state *state = NULL;

	ev = tevent_context_wrapper_create(main_ev,
					   conn,
					   &smbd_impersonate_conn_vuid_ops,
					   &state,
					   struct smbd_impersonate_conn_vuid_state);
	if (ev == NULL) {
		return NULL;
	}
	state->conn = conn;
	state->vuid = vuid;

	return ev;
}

struct smbd_impersonate_conn_sess_state {
	struct connection_struct *conn;
	struct auth_session_info *session_info;
};

static bool smbd_impersonate_conn_sess_before_use(struct tevent_context *wrap_ev,
						  void *private_data,
						  struct tevent_context *main_ev,
						  const char *location)
{
	struct smbd_impersonate_conn_sess_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_sess_state);
	bool ok;

	DEBUG(11,("%s: impersonating user[%s] wrap_ev[%p] main_ev[%p] "
		  "location[%s] old uid[%ju] old gid[%ju] cwd[%s]\n",
		  __func__, state->session_info->unix_info->unix_name,
		  wrap_ev, main_ev, location,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));

	ok = become_user_by_session(state->conn, state->session_info);
	if (!ok) {
		return false;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));

	return true;
}

static void smbd_impersonate_conn_sess_after_use(struct tevent_context *wrap_ev,
						 void *private_data,
						 struct tevent_context *main_ev,
						 const char *location)
{
	struct smbd_impersonate_conn_sess_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_sess_state);
	bool ok;

	DEBUG(11,("%s: deimpersonating[%s] uid[%ju] gid[%ju] cwd[%s] "
		  "location[%s]\n",
		  __func__, state->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name, location));

	ok = unbecome_user();
	if (!ok) {
		smb_panic("smbd_impersonate_conn_sess_after_use() - failed");
		return;
	}

	DEBUG(11,("%s: deimpersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_sess_before_fd_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_fd *fde,
		uint16_t flags,
		const char *handler_name,
		const char *location)
{
	struct smbd_impersonate_conn_sess_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_sess_state);
	bool ok;

	DEBUG(11,("%s: fde[%p] flags[%ju] handler_name[%s] location[%s]\n",
		  __func__, fde, (uintmax_t)flags, handler_name, location));

	ok = change_to_user_by_session(state->conn, state->session_info);
	if (!ok) {
		smb_panic("smbd_impersonate_conn_sess_before_fd_handler failed");
		return;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_sess_after_fd_handler(struct tevent_context *wrap_ev,
							void *private_data,
							struct tevent_context *main_ev,
							struct tevent_fd *fde,
							uint16_t flags,
							const char *handler_name,
							const char *location)
{
	DEBUG(11,("%s: fde[%p] handler_name[%s] location[%s]\n",
		  __func__, fde, handler_name, location));

	/* be lazy and defer change_to_root_user() */
}

static void smbd_impersonate_conn_sess_before_timer_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_timer *te,
		struct timeval requested_time,
		struct timeval trigger_time,
		const char *handler_name,
		const char *location)
{
	struct smbd_impersonate_conn_sess_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_sess_state);
	struct timeval_buf requested_buf;
	struct timeval_buf trigger_buf;
	bool ok;

	DEBUG(11,("%s: te[%p] requested_time[%s] trigger_time[%s] "
		  "handler_name[%s] location[%s]\n",
		  __func__, te,
		  timeval_str_buf(&requested_time, true, true, &requested_buf),
		  timeval_str_buf(&trigger_time, true, true, &trigger_buf),
		  handler_name, location));

	ok = change_to_user_by_session(state->conn, state->session_info);
	if (!ok) {
		smb_panic("smbd_impersonate_conn_sess_before_tm_handler failed");
		return;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_sess_after_timer_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_timer *te,
		struct timeval requested_time,
		struct timeval trigger_time,
		const char *handler_name,
		const char *location)
{
	DEBUG(11,("%s: te[%p] handler_name[%s] location[%s]\n",
		  __func__, te, handler_name, location));

	/* be lazy and defer change_to_root_user() */
}

static void smbd_impersonate_conn_sess_before_immediate_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_immediate *im,
		const char *handler_name,
		const char *location)
{
	struct smbd_impersonate_conn_sess_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_sess_state);
	bool ok;

	DEBUG(11,("%s: im[%p] handler_name[%s] location[%s]\n",
		  __func__, im, handler_name, location));

	ok = change_to_user_by_session(state->conn, state->session_info);
	if (!ok) {
		smb_panic("smbd_impersonate_conn_sess_before_im_handler failed");
		return;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_sess_after_immediate_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_immediate *im,
		const char *handler_name,
		const char *location)
{
	DEBUG(11,("%s: im[%p] handler_name[%s] location[%s]\n",
		  __func__, im, handler_name, location));

	/* be lazy and defer unbecome_user() */
}

static void smbd_impersonate_conn_sess_before_signal_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_signal *se,
		int signum,
		int count,
		void *siginfo,
		const char *handler_name,
		const char *location)
{
	struct smbd_impersonate_conn_sess_state *state = talloc_get_type_abort(
		private_data, struct smbd_impersonate_conn_sess_state);
	bool ok;

	DEBUG(11,("%s: se[%p] signum[%d] count[%d] siginfo[%p] "
		  "handler_name[%s] location[%s]\n",
		  __func__, se, signum, count, siginfo, handler_name, location));

	ok = change_to_user_by_session(state->conn, state->session_info);
	if (!ok) {
		smb_panic("smbd_impersonate_conn_sess_before_si_handler failed");
		return;
	}

	DEBUG(11,("%s: impersonated user[%s] uid[%ju] gid[%ju] cwd[%s]\n",
		  __func__, state->conn->session_info->unix_info->unix_name,
		  (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  state->conn->cwd_fname->base_name));
}

static void smbd_impersonate_conn_sess_after_signal_handler(
		struct tevent_context *wrap_ev,
		void *private_data,
		struct tevent_context *main_ev,
		struct tevent_signal *se,
		int signum,
		int count,
		void *siginfo,
		const char *handler_name,
		const char *location)
{
	DEBUG(11,("%s: se[%p] handler_name[%s] location[%s]\n",
		  __func__, se, handler_name, location));

	/* be lazy and defer change_to_root_user() */
}

static const struct tevent_wrapper_ops smbd_impersonate_conn_sess_ops = {
	.name				= "smbd_impersonate_conn_sess",
	.before_use			= smbd_impersonate_conn_sess_before_use,
	.after_use			= smbd_impersonate_conn_sess_after_use,
	.before_fd_handler		= smbd_impersonate_conn_sess_before_fd_handler,
	.after_fd_handler		= smbd_impersonate_conn_sess_after_fd_handler,
	.before_timer_handler		= smbd_impersonate_conn_sess_before_timer_handler,
	.after_timer_handler		= smbd_impersonate_conn_sess_after_timer_handler,
	.before_immediate_handler	= smbd_impersonate_conn_sess_before_immediate_handler,
	.after_immediate_handler	= smbd_impersonate_conn_sess_after_immediate_handler,
	.before_signal_handler		= smbd_impersonate_conn_sess_before_signal_handler,
	.after_signal_handler		= smbd_impersonate_conn_sess_after_signal_handler,
};

struct tevent_context *smbd_impersonate_conn_sess_create(
				struct tevent_context *main_ev,
				struct connection_struct *conn,
				struct auth_session_info *session_info)
{
	struct tevent_context *ev = NULL;
	struct smbd_impersonate_conn_sess_state *state = NULL;

	ev = tevent_context_wrapper_create(main_ev,
					   conn,
					   &smbd_impersonate_conn_sess_ops,
					   &state,
					   struct smbd_impersonate_conn_sess_state);
	if (ev == NULL) {
		return NULL;
	}
	state->conn = conn;
	state->session_info = session_info;

	return ev;
}

struct smbd_impersonate_root_state {
	uint8_t _dummy;
};

static bool smbd_impersonate_root_before_use(struct tevent_context *wrap_ev,
					     void *private_data,
					     struct tevent_context *main_ev,
					     const char *location)
{
	DEBUG(11,("%s: wrap_ev[%p] main_ev[%p] location[%s]"
		  "uid[%ju] gid[%ju]\n",
		  __func__, wrap_ev, main_ev, location,
		  (uintmax_t)geteuid(), (uintmax_t)getegid()));

	become_root();
	return true;
}

static void smbd_impersonate_root_after_use(struct tevent_context *wrap_ev,
					    void *private_data,
					    struct tevent_context *main_ev,
					    const char *location)
{
	unbecome_root();

	DEBUG(11,("%s: uid[%ju] gid[%ju] location[%s]\n",
		  __func__, (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  location));
}

static void smbd_impersonate_root_before_fd_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_fd *fde,
						uint16_t flags,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: fde[%p] flags[%ju] handler_name[%s] location[%s]\n",
		  __func__, fde, (uintmax_t)flags, handler_name, location));

	smbd_impersonate_root_before_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_root_after_fd_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_fd *fde,
						uint16_t flags,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: fde[%p] handler_name[%s] location[%s]\n",
		  __func__, fde, handler_name, location));

	smbd_impersonate_root_after_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_root_before_timer_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_timer *te,
						struct timeval requested_time,
						struct timeval trigger_time,
						const char *handler_name,
						const char *location)
{
	struct timeval_buf requested_buf;
	struct timeval_buf trigger_buf;

	DEBUG(11,("%s: te[%p] requested_time[%s] trigger_time[%s] "
		  "handler_name[%s] location[%s]\n",
		  __func__, te,
		  timeval_str_buf(&requested_time, true, true, &requested_buf),
		  timeval_str_buf(&trigger_time, true, true, &trigger_buf),
		  handler_name, location));

	smbd_impersonate_root_before_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_root_after_timer_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_timer *te,
						struct timeval requested_time,
						struct timeval trigger_time,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: te[%p] handler_name[%s] location[%s]\n",
		  __func__, te, handler_name, location));

	smbd_impersonate_root_after_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_root_before_immediate_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_immediate *im,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: im[%p] handler_name[%s] location[%s]\n",
		  __func__, im, handler_name, location));

	smbd_impersonate_root_before_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_root_after_immediate_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_immediate *im,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: im[%p] handler_name[%s] location[%s]\n",
		  __func__, im, handler_name, location));

	smbd_impersonate_root_after_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_root_before_signal_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_signal *se,
						int signum,
						int count,
						void *siginfo,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: se[%p] signum[%d] count[%d] siginfo[%p] "
		  "handler_name[%s] location[%s]\n",
		  __func__, se, signum, count, siginfo, handler_name, location));

	smbd_impersonate_root_before_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_root_after_signal_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_signal *se,
						int signum,
						int count,
						void *siginfo,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: se[%p] handler_name[%s] location[%s]\n",
		  __func__, se, handler_name, location));

	smbd_impersonate_root_after_use(wrap_ev, private_data, main_ev, location);
}

static const struct tevent_wrapper_ops smbd_impersonate_root_ops = {
	.name				= "smbd_impersonate_root",
	.before_use			= smbd_impersonate_root_before_use,
	.after_use			= smbd_impersonate_root_after_use,
	.before_fd_handler		= smbd_impersonate_root_before_fd_handler,
	.after_fd_handler		= smbd_impersonate_root_after_fd_handler,
	.before_timer_handler		= smbd_impersonate_root_before_timer_handler,
	.after_timer_handler		= smbd_impersonate_root_after_timer_handler,
	.before_immediate_handler	= smbd_impersonate_root_before_immediate_handler,
	.after_immediate_handler	= smbd_impersonate_root_after_immediate_handler,
	.before_signal_handler		= smbd_impersonate_root_before_signal_handler,
	.after_signal_handler		= smbd_impersonate_root_after_signal_handler,
};

struct tevent_context *smbd_impersonate_root_create(struct tevent_context *main_ev)
{
	struct tevent_context *ev = NULL;
	struct smbd_impersonate_root_state *state = NULL;

	ev = tevent_context_wrapper_create(main_ev,
					   main_ev,
					   &smbd_impersonate_root_ops,
					   &state,
					   struct smbd_impersonate_root_state);
	if (ev == NULL) {
		return NULL;
	}

	return ev;
}

struct smbd_impersonate_guest_state {
	uint8_t _dummy;
};

static bool smbd_impersonate_guest_before_use(struct tevent_context *wrap_ev,
					      void *private_data,
					      struct tevent_context *main_ev,
					      const char *location)
{
	DEBUG(11,("%s: wrap_ev[%p] main_ev[%p] location[%s]"
		  "uid[%ju] gid[%ju]\n",
		  __func__, wrap_ev, main_ev, location,
		  (uintmax_t)geteuid(), (uintmax_t)getegid()));

	return become_guest();
}

static void smbd_impersonate_guest_after_use(struct tevent_context *wrap_ev,
					     void *private_data,
					     struct tevent_context *main_ev,
					     const char *location)
{
	unbecome_guest();

	DEBUG(11,("%s: uid[%ju] gid[%ju] location[%s]\n",
		  __func__, (uintmax_t)geteuid(), (uintmax_t)getegid(),
		  location));
}

static void smbd_impersonate_guest_before_fd_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_fd *fde,
						uint16_t flags,
						const char *handler_name,
						const char *location)
{
	bool ok;

	DEBUG(11,("%s: fde[%p] flags[%ju] handler_name[%s] location[%s]\n",
		  __func__, fde, (uintmax_t)flags, handler_name, location));

	ok = smbd_impersonate_guest_before_use(wrap_ev, private_data,
					        main_ev, location);
	if (!ok) {
		smb_panic("smbd_impersonate_guest_before_use() - failed");
		return;
	}
}

static void smbd_impersonate_guest_after_fd_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_fd *fde,
						uint16_t flags,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: fde[%p] handler_name[%s] location[%s]\n",
		  __func__, fde, handler_name, location));

	smbd_impersonate_guest_after_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_guest_before_timer_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_timer *te,
						struct timeval requested_time,
						struct timeval trigger_time,
						const char *handler_name,
						const char *location)
{
	bool ok;
	struct timeval_buf requested_buf;
	struct timeval_buf trigger_buf;

	DEBUG(11,("%s: te[%p] requested_time[%s] trigger_time[%s] "
		  "handler_name[%s] location[%s]\n",
		  __func__, te,
		  timeval_str_buf(&requested_time, true, true, &requested_buf),
		  timeval_str_buf(&trigger_time, true, true, &trigger_buf),
		  handler_name, location));

	ok = smbd_impersonate_guest_before_use(wrap_ev, private_data,
					       main_ev, location);
	if (!ok) {
		smb_panic("smbd_impersonate_guest_before_use() - failed");
		return;
	}
}

static void smbd_impersonate_guest_after_timer_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_timer *te,
						struct timeval requested_time,
						struct timeval trigger_time,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: te[%p] handler_name[%s] location[%s]\n",
		  __func__, te, handler_name, location));

	smbd_impersonate_guest_after_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_guest_before_immediate_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_immediate *im,
						const char *handler_name,
						const char *location)
{
	bool ok;

	DEBUG(11,("%s: im[%p] handler_name[%s] location[%s]\n",
		  __func__, im, handler_name, location));

	ok = smbd_impersonate_guest_before_use(wrap_ev, private_data,
					       main_ev, location);
	if (!ok) {
		smb_panic("smbd_impersonate_guest_before_use() - failed");
		return;
	}
}

static void smbd_impersonate_guest_after_immediate_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_immediate *im,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: im[%p] handler_name[%s] location[%s]\n",
		  __func__, im, handler_name, location));

	smbd_impersonate_guest_after_use(wrap_ev, private_data, main_ev, location);
}

static void smbd_impersonate_guest_before_signal_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_signal *se,
						int signum,
						int count,
						void *siginfo,
						const char *handler_name,
						const char *location)
{
	bool ok;

	DEBUG(11,("%s: se[%p] signum[%d] count[%d] siginfo[%p] "
		  "handler_name[%s] location[%s]\n",
		  __func__, se, signum, count, siginfo, handler_name, location));

	ok = smbd_impersonate_guest_before_use(wrap_ev, private_data,
					       main_ev, location);
	if (!ok) {
		smb_panic("smbd_impersonate_guest_before_use() - failed");
		return;
	}
}

static void smbd_impersonate_guest_after_signal_handler(struct tevent_context *wrap_ev,
						void *private_data,
						struct tevent_context *main_ev,
						struct tevent_signal *se,
						int signum,
						int count,
						void *siginfo,
						const char *handler_name,
						const char *location)
{
	DEBUG(11,("%s: se[%p] handler_name[%s] location[%s]\n",
		  __func__, se, handler_name, location));

	smbd_impersonate_guest_after_use(wrap_ev, private_data, main_ev, location);
}

static const struct tevent_wrapper_ops smbd_impersonate_guest_ops = {
	.name				= "smbd_impersonate_guest",
	.before_use			= smbd_impersonate_guest_before_use,
	.after_use			= smbd_impersonate_guest_after_use,
	.before_fd_handler		= smbd_impersonate_guest_before_fd_handler,
	.after_fd_handler		= smbd_impersonate_guest_after_fd_handler,
	.before_timer_handler		= smbd_impersonate_guest_before_timer_handler,
	.after_timer_handler		= smbd_impersonate_guest_after_timer_handler,
	.before_immediate_handler	= smbd_impersonate_guest_before_immediate_handler,
	.after_immediate_handler	= smbd_impersonate_guest_after_immediate_handler,
	.before_signal_handler		= smbd_impersonate_guest_before_signal_handler,
	.after_signal_handler		= smbd_impersonate_guest_after_signal_handler,
};

struct tevent_context *smbd_impersonate_guest_create(struct tevent_context *main_ev)
{
	struct tevent_context *ev = NULL;
	struct smbd_impersonate_guest_state *state = NULL;

	ev = tevent_context_wrapper_create(main_ev,
					   main_ev,
					   &smbd_impersonate_guest_ops,
					   &state,
					   struct smbd_impersonate_guest_state);
	if (ev == NULL) {
		return NULL;
	}

	return ev;
}

struct smbd_impersonate_tp_current_state {
	const void *conn_ptr;
	uint64_t vuid; /* SMB2 compat */
	struct security_unix_token partial_ut;
	bool chdir_safe;
	int saved_cwd_fd;
};

static int smbd_impersonate_tp_current_state_destructor(
		struct smbd_impersonate_tp_current_state *state)
{
	if (state->saved_cwd_fd != -1) {
		smb_panic(__location__);
	}

	return 0;
}

static bool smbd_impersonate_tp_current_before_job(struct pthreadpool_tevent *wrap,
						   void *private_data,
						   struct pthreadpool_tevent *main,
						   const char *location)
{
	struct smbd_impersonate_tp_current_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_impersonate_tp_current_state);

	if (state->conn_ptr != current_user.conn) {
		smb_panic(__location__);
	}

	if (state->vuid != current_user.vuid) {
		smb_panic(__location__);
	}

	if (state->partial_ut.uid != current_user.ut.uid) {
		smb_panic(__location__);
	}

	if (state->partial_ut.gid != current_user.ut.gid) {
		smb_panic(__location__);
	}

	if (state->partial_ut.ngroups != current_user.ut.ngroups) {
		smb_panic(__location__);
	}

	/*
	 * We don't verify the group list, we should have hit
	 * an assert before. We only want to catch programmer
	 * errors here!
	 *
	 * We just have a sync pool and want to make sure
	 * we're already in the correct state.
	 *
	 * So we don't do any active impersonation.
	 */

	/*
	 * we may need to remember the current working directory
	 * and later restore it in the after_job hook.
	 */
	if (state->chdir_safe) {
		int open_flags = O_RDONLY;
		bool ok;

#ifdef O_DIRECTORY
		open_flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
		open_flags |= O_CLOEXEC;
#endif

		state->saved_cwd_fd = open(".", open_flags);
		if (state->saved_cwd_fd == -1) {
			DBG_ERR("unable to open '.' with open_flags[0x%x] - %s\n",
				open_flags, strerror(errno));
			smb_panic("smbd_impersonate_tp_current_before_job: "
				  "unable to open cwd '.'");
			return false;
		}
		ok = smb_set_close_on_exec(state->saved_cwd_fd);
		SMB_ASSERT(ok);
	}

	return true;
}

static bool smbd_impersonate_tp_current_after_job(struct pthreadpool_tevent *wrap,
						  void *private_data,
						  struct pthreadpool_tevent *main,
						  const char *location)
{
	struct smbd_impersonate_tp_current_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_impersonate_tp_current_state);
	int ret;

	/*
	 * There's no impersonation to revert.
	 *
	 * But we may need to reset the current working directory.
	 */
	if (state->saved_cwd_fd == -1) {
		return true;
	}

	ret = fchdir(state->saved_cwd_fd);
	if (ret != 0) {
		DBG_ERR("unable to fchdir to the original directory - %s\n",
			strerror(errno));
		smb_panic("smbd_impersonate_tp_current_after_job: "
			  "unable restore cwd with fchdir.");
		return false;
	}

	close(state->saved_cwd_fd);
	state->saved_cwd_fd = -1;

	return true;
}

static const struct pthreadpool_tevent_wrapper_ops smbd_impersonate_tp_current_ops = {
	.name		= "smbd_impersonate_tp_current",
	.before_job	= smbd_impersonate_tp_current_before_job,
	.after_job	= smbd_impersonate_tp_current_after_job,
};

struct pthreadpool_tevent *smbd_impersonate_tp_current_create(
				TALLOC_CTX *mem_ctx,
				struct pthreadpool_tevent *sync_tp,
				struct connection_struct *conn,
				uint64_t vuid, bool chdir_safe,
				const struct security_unix_token *unix_token)
{
	struct pthreadpool_tevent *wrap_tp = NULL;
	struct smbd_impersonate_tp_current_state *state = NULL;
	size_t max_threads;

	max_threads = pthreadpool_tevent_max_threads(sync_tp);
	SMB_ASSERT(max_threads == 0);

	/*
	 * We have a fake threadpool without real threads.
	 * So we just provide a a wrapper that asserts that
	 * we are already in the required impersonation state.
	 */

	wrap_tp = pthreadpool_tevent_wrapper_create(sync_tp,
					mem_ctx,
					&smbd_impersonate_tp_current_ops,
					&state,
					struct smbd_impersonate_tp_current_state);
	if (wrap_tp == NULL) {
		return NULL;
	}

	state->conn_ptr = conn;
	state->vuid = vuid;
	state->partial_ut = *unix_token;
	state->partial_ut.groups = NULL;
	state->chdir_safe = chdir_safe;
	state->saved_cwd_fd = -1;

	if (chdir_safe) {
		pthreadpool_tevent_force_per_thread_cwd(wrap_tp, state);
	}

	talloc_set_destructor(state, smbd_impersonate_tp_current_state_destructor);

	return wrap_tp;
}

struct smbd_impersonate_tp_sess_state {
	const struct security_unix_token *unix_token;
};

static bool smbd_impersonate_tp_sess_before_job(struct pthreadpool_tevent *wrap,
						void *private_data,
						struct pthreadpool_tevent *main,
						const char *location)
{
	struct smbd_impersonate_tp_sess_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_impersonate_tp_sess_state);
	int ret;

	/* Become the correct credential on this thread. */
	ret = set_thread_credentials(state->unix_token->uid,
				     state->unix_token->gid,
				     (size_t)state->unix_token->ngroups,
				     state->unix_token->groups);
	if (ret != 0) {
		return false;
	}

	return true;
}

static bool smbd_impersonate_tp_sess_after_job(struct pthreadpool_tevent *wrap,
					       void *private_data,
					       struct pthreadpool_tevent *main,
					       const char *location)
{
	/*
	 * We skip the 'unbecome' here, if the following
	 * job cares, it already called set_thread_credentials() again.
	 *
	 * fd based jobs on the raw pool, don't really care...
	 */
	return true;
}

static const struct pthreadpool_tevent_wrapper_ops smbd_impersonate_tp_sess_ops = {
	.name		= "smbd_impersonate_tp_sess",
	.before_job	= smbd_impersonate_tp_sess_before_job,
	.after_job	= smbd_impersonate_tp_sess_after_job,
};

static struct pthreadpool_tevent *smbd_impersonate_tp_sess_create(
				TALLOC_CTX *mem_ctx,
				struct pthreadpool_tevent *main_tp,
				struct auth_session_info *session_info)
{
	struct pthreadpool_tevent *wrap_tp = NULL;
	struct smbd_impersonate_tp_sess_state *state = NULL;
	size_t max_threads;

	max_threads = pthreadpool_tevent_max_threads(main_tp);
	SMB_ASSERT(max_threads > 0);

	wrap_tp = pthreadpool_tevent_wrapper_create(main_tp,
					mem_ctx,
					&smbd_impersonate_tp_sess_ops,
					&state,
					struct smbd_impersonate_tp_sess_state);
	if (wrap_tp == NULL) {
		return NULL;
	}

	state->unix_token = copy_unix_token(state, session_info->unix_token);
	if (state->unix_token == NULL) {
		int saved_errno = errno;
		TALLOC_FREE(wrap_tp);
		errno = saved_errno;
		return NULL;
	}

	return wrap_tp;
}

struct smbd_impersonate_tp_become_state {
	void (*become_fn)(void);
	void (*unbecome_fn)(void);
	bool chdir_safe;
	int saved_cwd_fd;
};

static int smbd_impersonate_tp_become_state_destructor(
		struct smbd_impersonate_tp_become_state *state)
{
	if (state->saved_cwd_fd != -1) {
		smb_panic(__location__);
	}

	return 0;
}


static bool smbd_impersonate_tp_become_before_job(struct pthreadpool_tevent *wrap,
						   void *private_data,
						   struct pthreadpool_tevent *main,
						   const char *location)
{
	struct smbd_impersonate_tp_become_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_impersonate_tp_become_state);

	/*
	 * we may need to remember the current working directory
	 * and later restore it in the after_job hook.
	 */
	if (state->chdir_safe) {
		int open_flags = O_RDONLY;
		bool ok;

#ifdef O_DIRECTORY
		open_flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
		open_flags |= O_CLOEXEC;
#endif

		state->saved_cwd_fd = open(".", open_flags);
		if (state->saved_cwd_fd == -1) {
			DBG_ERR("unable to open '.' with open_flags[0x%x] - %s\n",
				open_flags, strerror(errno));
			smb_panic("smbd_impersonate_tp_current_before_job: "
				  "unable to open cwd '.'");
			return false;
		}
		ok = smb_set_close_on_exec(state->saved_cwd_fd);
		SMB_ASSERT(ok);
	}

	/*
	 * The function should abort on error...
	 */
	state->become_fn();

	return true;
}

static bool smbd_impersonate_tp_become_after_job(struct pthreadpool_tevent *wrap,
						  void *private_data,
						  struct pthreadpool_tevent *main,
						  const char *location)
{
	struct smbd_impersonate_tp_become_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_impersonate_tp_become_state);
	int ret;

	/*
	 * The function should abort on error...
	 */
	state->unbecome_fn();

	/*
	 * There's no impersonation to revert.
	 *
	 * But we may need to reset the current working directory.
	 */
	if (state->saved_cwd_fd == -1) {
		return true;
	}

	ret = fchdir(state->saved_cwd_fd);
	if (ret != 0) {
		DBG_ERR("unable to fchdir to the original directory - %s\n",
			strerror(errno));
		smb_panic("smbd_impersonate_tp_current_after_job: "
			  "unable restore cwd with fchdir.");
		return false;
	}

	close(state->saved_cwd_fd);
	state->saved_cwd_fd = -1;

	return true;
}

static const struct pthreadpool_tevent_wrapper_ops smbd_impersonate_tp_become_ops = {
	.name		= "smbd_impersonate_tp_become",
	.before_job	= smbd_impersonate_tp_become_before_job,
	.after_job	= smbd_impersonate_tp_become_after_job,
};

struct pthreadpool_tevent *smbd_impersonate_tp_become_create(
					TALLOC_CTX *mem_ctx,
					struct pthreadpool_tevent *sync_tp,
					bool chdir_safe,
					void (*become_fn)(void),
					void (*unbecome_fn)(void))
{
	struct pthreadpool_tevent *wrap_tp = NULL;
	struct smbd_impersonate_tp_become_state *state = NULL;
	size_t max_threads;

	max_threads = pthreadpool_tevent_max_threads(sync_tp);
	SMB_ASSERT(max_threads == 0);

	/*
	 * We have a fake threadpool without real threads.
	 * So we just provide a a wrapper that asserts that
	 * we are already in the required impersonation state.
	 */

	wrap_tp = pthreadpool_tevent_wrapper_create(sync_tp,
					mem_ctx,
					&smbd_impersonate_tp_become_ops,
					&state,
					struct smbd_impersonate_tp_become_state);
	if (wrap_tp == NULL) {
		return NULL;
	}

	state->become_fn = become_fn;
	state->unbecome_fn = unbecome_fn;
	state->chdir_safe = chdir_safe;
	state->saved_cwd_fd = -1;

	if (chdir_safe) {
		pthreadpool_tevent_force_per_thread_cwd(wrap_tp, state);
	}

	talloc_set_destructor(state, smbd_impersonate_tp_become_state_destructor);

	return wrap_tp;
}

struct smbd_impersonate_tp_root_state {
	const struct security_unix_token *fallback_token;
};

static bool smbd_impersonate_tp_root_before_job(struct pthreadpool_tevent *wrap,
						void *private_data,
						struct pthreadpool_tevent *main,
						const char *location)
{
	int ret;

	/*
	 * Become root in this thread.
	 */
	ret = set_thread_credentials(0, 0, 0, NULL);
	if (ret != 0) {
		return false;
	}

	return true;
}

static bool smbd_impersonate_tp_root_after_job(struct pthreadpool_tevent *wrap,
					       void *private_data,
					       struct pthreadpool_tevent *main,
					       const char *location)
{
	struct smbd_impersonate_tp_root_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_impersonate_tp_root_state);
	int ret;

	/*
	 * Move to a non root token again.
	 * We just use the one of the user_ev_ctx.
	 *
	 * The main goal is that we don't leave
	 * a thread arround with a root token.
	 */
	ret = set_thread_credentials(state->fallback_token->uid,
				     state->fallback_token->gid,
				     (size_t)state->fallback_token->ngroups,
				     state->fallback_token->groups);
	if (ret != 0) {
		return false;
	}

	return true;
}

static const struct pthreadpool_tevent_wrapper_ops smbd_impersonate_tp_root_ops = {
	.name		= "smbd_impersonate_tp_root",
	.before_job	= smbd_impersonate_tp_root_before_job,
	.after_job	= smbd_impersonate_tp_root_after_job,
};

static struct pthreadpool_tevent *smbd_impersonate_tp_root_create(
				TALLOC_CTX *mem_ctx,
				struct pthreadpool_tevent *main_tp,
				int snum,
				const struct security_unix_token *fallback_token)
{
	struct pthreadpool_tevent *wrap_tp = NULL;
	struct smbd_impersonate_tp_root_state *state = NULL;
	size_t max_threads;

	max_threads = pthreadpool_tevent_max_threads(main_tp);
	SMB_ASSERT(max_threads > 0);

	wrap_tp = pthreadpool_tevent_wrapper_create(main_tp,
				mem_ctx,
				&smbd_impersonate_tp_root_ops,
				&state,
				struct smbd_impersonate_tp_root_state);
	if (wrap_tp == NULL) {
		return NULL;
	}

	state->fallback_token = copy_unix_token(state, fallback_token);
	if (state->fallback_token == NULL) {
		int saved_errno = errno;
		TALLOC_FREE(wrap_tp);
		errno = saved_errno;
		return NULL;
	}

	return wrap_tp;
}

static struct smb_vfs_ev_glue *smbd_impersonate_user_ev_glue_create(
				struct connection_struct *conn,
				uint64_t vuid,
				struct auth_session_info *session_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct smb_vfs_ev_glue *user_vfs_evg = NULL;
	struct tevent_context *user_ev_ctx = NULL;
	struct pthreadpool_tevent *user_tp_fd_safe = NULL;
	struct pthreadpool_tevent *user_tp_path_safe = NULL;
	bool user_tp_path_sync = true;
	struct pthreadpool_tevent *user_tp_chdir_safe = NULL;
	bool user_tp_chdir_sync = true;
	struct pthreadpool_tevent *root_tp_fd_safe = NULL;
	struct pthreadpool_tevent *root_tp_path_safe = NULL;
	bool root_tp_path_sync = true;
	struct pthreadpool_tevent *root_tp_chdir_safe = NULL;
	bool root_tp_chdir_sync = true;
	size_t max_threads;

	if (vuid == UID_FIELD_INVALID) {
		user_ev_ctx = smbd_impersonate_conn_sess_create(
			conn->sconn->raw_ev_ctx, conn, session_info);
		if (user_ev_ctx == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
	} else {
		user_ev_ctx = smbd_impersonate_conn_vuid_create(
			conn->sconn->raw_ev_ctx, conn, vuid);
		if (user_ev_ctx == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
	}
	SMB_ASSERT(talloc_reparent(conn, frame, user_ev_ctx));

#ifdef HAVE_LINUX_THREAD_CREDENTIALS
	user_tp_path_sync = lp_parm_bool(SNUM(conn),
					 "smbd",
					 "force sync user path safe threadpool",
					 false);
	user_tp_chdir_sync = lp_parm_bool(SNUM(conn),
					  "smbd",
					  "force sync user chdir safe threadpool",
					  false);
	root_tp_path_sync = lp_parm_bool(SNUM(conn),
					 "smbd",
					 "force sync root path safe threadpool",
					 false);
	root_tp_chdir_sync = lp_parm_bool(SNUM(conn),
					  "smbd",
					  "force sync root chdir safe threadpool",
					  false);
#endif

	max_threads = pthreadpool_tevent_max_threads(conn->sconn->raw_thread_pool);
	if (max_threads == 0) {
		/*
		 * We don't have real threads, so we need to force
		 * the sync versions...
		 */
		user_tp_path_sync = true;
		user_tp_chdir_sync = true;
		root_tp_path_sync = true;
		root_tp_chdir_sync = true;
	}

	/*
	 * fd_safe is easy :-)
	 */
	user_tp_fd_safe = conn->sconn->raw_thread_pool;
	root_tp_fd_safe = conn->sconn->raw_thread_pool;

	if (user_tp_path_sync) {
		/*
		 * We don't have support for per thread credentials,
		 * so we just provide a sync thread pool with a wrapper
		 * that asserts that we are already in the required
		 * impersonation state.
		 */
		user_tp_path_safe = smbd_impersonate_tp_current_create(conn,
						conn->sconn->sync_thread_pool,
						conn,
						vuid,
						false, /* chdir_safe */
						session_info->unix_token);
		if (user_tp_path_safe == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
	} else {
		user_tp_path_safe = smbd_impersonate_tp_sess_create(conn,
						conn->sconn->raw_thread_pool,
						session_info);
		if (user_tp_path_safe == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
	}
	SMB_ASSERT(talloc_reparent(conn, frame, user_tp_path_safe));

	if (pthreadpool_tevent_per_thread_cwd(user_tp_path_safe)) {
		user_tp_chdir_safe = user_tp_path_safe;
	} else {
		user_tp_chdir_sync = true;
	}

	if (user_tp_chdir_sync) {
		/*
		 * We don't have support for per thread credentials,
		 * so we just provide a sync thread pool with a wrapper
		 * that asserts that we are already in the required
		 * impersonation state.
		 *
		 * And it needs to cleanup after [f]chdir() within
		 * the job...
		 */
		user_tp_chdir_safe = smbd_impersonate_tp_current_create(conn,
						conn->sconn->sync_thread_pool,
						conn,
						vuid,
						true, /* chdir_safe */
						session_info->unix_token);
		if (user_tp_chdir_safe == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
		SMB_ASSERT(talloc_reparent(conn, frame, user_tp_chdir_safe));
	} else {
		SMB_ASSERT(user_tp_chdir_safe != NULL);
	}

	if (root_tp_path_sync) {
		/*
		 * We don't have support for per thread credentials,
		 * so we just provide a sync thread pool with a wrapper
		 * that wrapps the job in become_root()/unbecome_root().
		 */
		root_tp_path_safe = smbd_impersonate_tp_become_create(conn,
						conn->sconn->sync_thread_pool,
						false, /* chdir_safe */
						become_root,
						unbecome_root);
		if (root_tp_path_safe == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
	} else {
		root_tp_path_safe = smbd_impersonate_tp_root_create(conn,
						conn->sconn->raw_thread_pool,
						SNUM(conn),
						session_info->unix_token);
		if (root_tp_path_safe == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
	}
	SMB_ASSERT(talloc_reparent(conn, frame, root_tp_path_safe));

	if (pthreadpool_tevent_per_thread_cwd(root_tp_path_safe)) {
		root_tp_chdir_safe = root_tp_path_safe;
	} else {
		root_tp_chdir_sync = true;
	}

	if (root_tp_chdir_sync) {
		/*
		 * We don't have support for per thread credentials,
		 * so we just provide a sync thread pool with a wrapper
		 * that wrapps the job in become_root()/unbecome_root().
		 *
		 * And it needs to cleanup after [f]chdir() within
		 * the job...
		 */
		root_tp_chdir_safe = smbd_impersonate_tp_become_create(conn,
						conn->sconn->sync_thread_pool,
						true, /* chdir_safe */
						become_root,
						unbecome_root);
		if (root_tp_chdir_safe == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
		SMB_ASSERT(talloc_reparent(conn, frame, root_tp_chdir_safe));
	} else {
		SMB_ASSERT(root_tp_chdir_safe != NULL);
	}

	user_vfs_evg = smb_vfs_ev_glue_create(conn,
					      user_ev_ctx,
					      user_tp_fd_safe,
					      user_tp_path_safe,
					      user_tp_chdir_safe,
					      conn->sconn->root_ev_ctx,
					      root_tp_fd_safe,
					      root_tp_path_safe,
					      root_tp_chdir_safe);
	if (user_vfs_evg == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	/*
	 * Make sure everything is a talloc child of user_vfs_evg
	 */
	SMB_ASSERT(talloc_reparent(frame, user_vfs_evg, user_ev_ctx));
	SMB_ASSERT(talloc_reparent(frame, user_vfs_evg, user_tp_path_safe));
	if (user_tp_path_safe != user_tp_chdir_safe) {
		SMB_ASSERT(talloc_reparent(frame, user_vfs_evg, user_tp_chdir_safe));
	}
	SMB_ASSERT(talloc_reparent(frame, user_vfs_evg, root_tp_path_safe));
	if (root_tp_path_safe != root_tp_chdir_safe) {
		SMB_ASSERT(talloc_reparent(frame, user_vfs_evg, root_tp_chdir_safe));
	}

	TALLOC_FREE(frame);
	return user_vfs_evg;
}
