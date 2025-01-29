/* 
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett 2001-2010
   Copyright (C) Jeremy Allison 2000-2001
   Copyright (C) Rafal Szczesniak 2002
   Copyright (C) Stefan Metzmacher 2005

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
#include "libcli/security/security.h"
#include "auth/credentials/credentials.h"
#include "param/param.h"
#include "auth/auth.h" /* for auth_user_info_dc */
#include "auth/session.h"
#include "auth/system_session_proto.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/*
  prevent the static system session being freed
 */
static int system_session_destructor(struct auth_session_info *info)
{
	return -1;
}

/* Create a security token for a session SYSTEM (the most
 * trusted/privileged account), including the local machine account as
 * the off-host credentials
 */ 
_PUBLIC_ struct auth_session_info *system_session(struct loadparm_context *lp_ctx)
{
	static struct auth_session_info *static_session;
	NTSTATUS nt_status;

	if (static_session) {
		return static_session;
	}

	/*
	 * Use NULL here, not the autofree context for this
	 * static pointer. The destructor prevents freeing this
	 * memory anyway.
	 */
	nt_status = auth_system_session_info(NULL,
					     lp_ctx,
					     &static_session);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(static_session);
		return NULL;
	}
	talloc_set_destructor(static_session, system_session_destructor);
	return static_session;
}

NTSTATUS auth_system_session_info(TALLOC_CTX *parent_ctx, 
				  struct loadparm_context *lp_ctx,
				  struct auth_session_info **_session_info) 
{
	NTSTATUS nt_status;
	struct auth_user_info_dc *user_info_dc = NULL;
	struct auth_session_info *session_info = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	bool ok;

	mem_ctx = talloc_new(parent_ctx);
	if (mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	
	nt_status = auth_system_user_info_dc(mem_ctx, lpcfg_netbios_name(lp_ctx),
					    &user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return nt_status;
	}

	/* references the user_info_dc into the session_info */
	nt_status = auth_generate_session_info(parent_ctx,
					       lp_ctx,
					       NULL /* sam_ctx */,
					       user_info_dc,
					       AUTH_SESSION_INFO_SIMPLE_PRIVILEGES,
					       &session_info);
	talloc_free(mem_ctx);

	NT_STATUS_NOT_OK_RETURN(nt_status);

	session_info->credentials = cli_credentials_init(session_info);
	if (!session_info->credentials) {
		talloc_free(session_info);
		return NT_STATUS_NO_MEMORY;
	}

	ok = cli_credentials_set_conf(session_info->credentials, lp_ctx);
	if (!ok) {
		talloc_free(session_info);
		return NT_STATUS_INTERNAL_ERROR;
	}

	cli_credentials_set_machine_account_pending(session_info->credentials, lp_ctx);
	*_session_info = session_info;

	return NT_STATUS_OK;
}

NTSTATUS auth_system_user_info_dc(TALLOC_CTX *mem_ctx, const char *netbios_name,
				 struct auth_user_info_dc **_user_info_dc)
{
	struct auth_user_info_dc *user_info_dc;
	struct auth_user_info *info;

	user_info_dc = talloc_zero(mem_ctx, struct auth_user_info_dc);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc);

	/* This returns a pointer to a struct dom_sid, which is the
	 * same as a 1 element list of struct dom_sid */
	user_info_dc->num_sids = 1;
	user_info_dc->sids = talloc(user_info_dc, struct auth_SidAttr);
	if (user_info_dc->sids == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	user_info_dc->sids[0] = (struct auth_SidAttr) {
		.sid = global_sid_System,
		.attrs = SE_GROUP_DEFAULT_FLAGS,
	};

	/* annoying, but the Anonymous really does have a session key, 
	   and it is all zeros! */
	user_info_dc->user_session_key = data_blob_talloc(user_info_dc, NULL, 16);
	if (user_info_dc->user_session_key.data == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	user_info_dc->lm_session_key = data_blob_talloc(user_info_dc, NULL, 16);
	if (user_info_dc->lm_session_key.data == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	data_blob_clear(&user_info_dc->user_session_key);
	data_blob_clear(&user_info_dc->lm_session_key);

	user_info_dc->info = info = talloc_zero(user_info_dc, struct auth_user_info);
	if (user_info_dc->info == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->account_name = talloc_strdup(info, "SYSTEM");
	if (info->account_name == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->domain_name = talloc_strdup(info, "NT AUTHORITY");
	if (info->domain_name == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->full_name = talloc_strdup(info, "System");
	if (info->full_name == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->logon_script = talloc_strdup(info, "");
	if (info->logon_script == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->profile_path = talloc_strdup(info, "");
	if (info->profile_path == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->home_directory = talloc_strdup(info, "");
	if (info->home_directory == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->home_drive = talloc_strdup(info, "");
	if (info->home_drive == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->logon_server = talloc_strdup(info, netbios_name);
	if (info->logon_server == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->last_logon = 0;
	info->last_logoff = 0;
	info->acct_expiry = 0;
	info->last_password_change = 0;
	info->allow_password_change = 0;
	info->force_password_change = 0;

	info->logon_count = 0;
	info->bad_password_count = 0;

	info->acct_flags = ACB_NORMAL;

	info->user_flags = 0;

	*_user_info_dc = user_info_dc;

	return NT_STATUS_OK;
}


static NTSTATUS auth_domain_admin_user_info_dc(TALLOC_CTX *mem_ctx,
					      const char *netbios_name,
					      const char *domain_name,
					      struct dom_sid *domain_sid,
					      struct auth_user_info_dc **_user_info_dc)
{
	struct auth_user_info_dc *user_info_dc;
	struct auth_user_info *info;

	user_info_dc = talloc_zero(mem_ctx, struct auth_user_info_dc);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc);

	user_info_dc->num_sids = 8;
	user_info_dc->sids = talloc_zero_array(user_info_dc,
					       struct auth_SidAttr,
					       user_info_dc->num_sids);
	if (user_info_dc->sids == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	user_info_dc->sids[PRIMARY_USER_SID_INDEX].sid = *domain_sid;
	sid_append_rid(&user_info_dc->sids[PRIMARY_USER_SID_INDEX].sid, DOMAIN_RID_ADMINISTRATOR);
	user_info_dc->sids[PRIMARY_USER_SID_INDEX].attrs = SE_GROUP_DEFAULT_FLAGS;

	user_info_dc->sids[PRIMARY_GROUP_SID_INDEX].sid = *domain_sid;
	sid_append_rid(&user_info_dc->sids[PRIMARY_GROUP_SID_INDEX].sid, DOMAIN_RID_USERS);
	user_info_dc->sids[PRIMARY_GROUP_SID_INDEX].attrs = SE_GROUP_DEFAULT_FLAGS;

	/* Add the primary group again. */
	user_info_dc->sids[2] = user_info_dc->sids[PRIMARY_GROUP_SID_INDEX];

	user_info_dc->sids[3].sid = global_sid_Builtin_Administrators;
	user_info_dc->sids[3].attrs = SE_GROUP_DEFAULT_FLAGS;

	user_info_dc->sids[4].sid = *domain_sid;
	sid_append_rid(&user_info_dc->sids[4].sid, DOMAIN_RID_ADMINS);
	user_info_dc->sids[4].attrs = SE_GROUP_DEFAULT_FLAGS;
	user_info_dc->sids[5].sid = *domain_sid;
	sid_append_rid(&user_info_dc->sids[5].sid, DOMAIN_RID_ENTERPRISE_ADMINS);
	user_info_dc->sids[5].attrs = SE_GROUP_DEFAULT_FLAGS;
	user_info_dc->sids[6].sid = *domain_sid;
	sid_append_rid(&user_info_dc->sids[6].sid, DOMAIN_RID_POLICY_ADMINS);
	user_info_dc->sids[6].attrs = SE_GROUP_DEFAULT_FLAGS;
	user_info_dc->sids[7].sid = *domain_sid;
	sid_append_rid(&user_info_dc->sids[7].sid, DOMAIN_RID_SCHEMA_ADMINS);
	user_info_dc->sids[7].attrs = SE_GROUP_DEFAULT_FLAGS;

	/* What should the session key be?*/
	user_info_dc->user_session_key = data_blob_talloc(user_info_dc, NULL, 16);
	if (user_info_dc->user_session_key.data == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	user_info_dc->lm_session_key = data_blob_talloc(user_info_dc, NULL, 16);
	if (user_info_dc->lm_session_key.data == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	data_blob_clear(&user_info_dc->user_session_key);
	data_blob_clear(&user_info_dc->lm_session_key);

	user_info_dc->info = info = talloc_zero(user_info_dc, struct auth_user_info);
	if (user_info_dc->info == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->account_name = talloc_strdup(info, "Administrator");
	if (info->account_name == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->domain_name = talloc_strdup(info, domain_name);
	if (info->domain_name == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->full_name = talloc_strdup(info, "Administrator");
	if (info->full_name == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->logon_script = talloc_strdup(info, "");
	if (info->logon_script == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->profile_path = talloc_strdup(info, "");
	if (info->profile_path == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->home_directory = talloc_strdup(info, "");
	if (info->home_directory == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->home_drive = talloc_strdup(info, "");
	if (info->home_drive == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->logon_server = talloc_strdup(info, netbios_name);
	if (info->logon_server == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->last_logon = 0;
	info->last_logoff = 0;
	info->acct_expiry = 0;
	info->last_password_change = 0;
	info->allow_password_change = 0;
	info->force_password_change = 0;

	info->logon_count = 0;
	info->bad_password_count = 0;

	info->acct_flags = ACB_NORMAL;

	info->user_flags = 0;

	*_user_info_dc = user_info_dc;

	return NT_STATUS_OK;
}

static NTSTATUS auth_domain_admin_session_info(TALLOC_CTX *parent_ctx,
					       struct loadparm_context *lp_ctx,
					       struct dom_sid *domain_sid,
					       struct auth_session_info **session_info)
{
	NTSTATUS nt_status;
	struct auth_user_info_dc *user_info_dc = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);

	NT_STATUS_HAVE_NO_MEMORY(mem_ctx);

	nt_status = auth_domain_admin_user_info_dc(mem_ctx,
						   lpcfg_netbios_name(lp_ctx),
						   lpcfg_workgroup(lp_ctx),
						   domain_sid,
						   &user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return nt_status;
	}

	nt_status = auth_generate_session_info(mem_ctx,
					       lp_ctx,
					       NULL /* sam_ctx */,
					       user_info_dc,
					       AUTH_SESSION_INFO_SIMPLE_PRIVILEGES|AUTH_SESSION_INFO_AUTHENTICATED|AUTH_SESSION_INFO_DEFAULT_GROUPS,
					       session_info);
	/* There is already a reference between the session_info and user_info_dc */
	if (NT_STATUS_IS_OK(nt_status)) {
		talloc_steal(parent_ctx, *session_info);
	}
	talloc_free(mem_ctx);
	return nt_status;
}

_PUBLIC_ struct auth_session_info *admin_session(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx, struct dom_sid *domain_sid)
{
	NTSTATUS nt_status;
	struct auth_session_info *session_info = NULL;
	nt_status = auth_domain_admin_session_info(mem_ctx,
						   lp_ctx,
						   domain_sid,
						   &session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return NULL;
	}
	return session_info;
}

_PUBLIC_ NTSTATUS auth_anonymous_session_info(TALLOC_CTX *parent_ctx, 
					      struct loadparm_context *lp_ctx,
					      struct auth_session_info **_session_info) 
{
	NTSTATUS nt_status;
	struct auth_user_info_dc *user_info_dc = NULL;
	struct auth_session_info *session_info = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	bool ok;

	if (mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	
	nt_status = auth_anonymous_user_info_dc(mem_ctx,
						lpcfg_netbios_name(lp_ctx),
						&user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return nt_status;
	}

	/* references the user_info_dc into the session_info */
	nt_status = auth_generate_session_info(parent_ctx,
					       lp_ctx,
					       NULL /* sam_ctx */,
					       user_info_dc,
					       AUTH_SESSION_INFO_SIMPLE_PRIVILEGES,
					       &session_info);
	talloc_free(mem_ctx);

	NT_STATUS_NOT_OK_RETURN(nt_status);

	session_info->credentials = cli_credentials_init(session_info);
	if (!session_info->credentials) {
		talloc_free(session_info);
		return NT_STATUS_NO_MEMORY;
	}

	ok = cli_credentials_set_conf(session_info->credentials, lp_ctx);
	if (!ok) {
		talloc_free(session_info);
		return NT_STATUS_INTERNAL_ERROR;
	}
	cli_credentials_set_anonymous(session_info->credentials);
	
	*_session_info = session_info;

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS auth_anonymous_user_info_dc(TALLOC_CTX *mem_ctx,
				    const char *netbios_name,
				    struct auth_user_info_dc **_user_info_dc)
{
	struct auth_user_info_dc *user_info_dc;
	struct auth_user_info *info;
	user_info_dc = talloc_zero(mem_ctx, struct auth_user_info_dc);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc);

	/* This returns a pointer to a struct dom_sid, which is the
	 * same as a 1 element list of struct dom_sid */
	user_info_dc->num_sids = 1;
	user_info_dc->sids = talloc(user_info_dc, struct auth_SidAttr);
	if (user_info_dc->sids == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	user_info_dc->sids[0] = (struct auth_SidAttr) {
		.sid = global_sid_Anonymous,
		.attrs = SE_GROUP_DEFAULT_FLAGS,
	};

	/* annoying, but the Anonymous really does have a session key... */
	user_info_dc->user_session_key = data_blob_talloc(user_info_dc, NULL, 16);
	if (user_info_dc->user_session_key.data == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	user_info_dc->lm_session_key = data_blob_talloc(user_info_dc, NULL, 16);
	if (user_info_dc->lm_session_key.data == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	/*  and it is all zeros! */
	data_blob_clear(&user_info_dc->user_session_key);
	data_blob_clear(&user_info_dc->lm_session_key);

	user_info_dc->info = info = talloc_zero(user_info_dc, struct auth_user_info);
	if (user_info_dc->info == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->account_name = talloc_strdup(info, "ANONYMOUS LOGON");
	if (info->account_name == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->domain_name = talloc_strdup(info, "NT AUTHORITY");
	if (info->domain_name == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->full_name = talloc_strdup(info, "Anonymous Logon");
	if (info->full_name == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->logon_script = talloc_strdup(info, "");
	if (info->logon_script == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->profile_path = talloc_strdup(info, "");
	if (info->profile_path == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->home_directory = talloc_strdup(info, "");
	if (info->home_directory == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->home_drive = talloc_strdup(info, "");
	if (info->home_drive == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->logon_server = talloc_strdup(info, netbios_name);
	if (info->logon_server == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	};

	info->last_logon = 0;
	info->last_logoff = 0;
	info->acct_expiry = 0;
	info->last_password_change = 0;
	info->allow_password_change = 0;
	info->force_password_change = 0;

	info->logon_count = 0;
	info->bad_password_count = 0;

	info->acct_flags = ACB_NORMAL;

	/* The user is not authenticated. */
	info->user_flags = NETLOGON_GUEST;

	*_user_info_dc = user_info_dc;

	return NT_STATUS_OK;
}

