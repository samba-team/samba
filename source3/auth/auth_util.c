/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett 2001-2011
   Copyright (C) Jeremy Allison 2000-2001
   Copyright (C) Rafal Szczesniak 2002
   Copyright (C) Volker Lendecke 2006-2008

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
#include "auth.h"
#include "lib/util_unixsids.h"
#include "../libcli/auth/libcli_auth.h"
#include "rpc_client/init_lsa.h"
#include "../libcli/security/security.h"
#include "../lib/util/util_pw.h"
#include "lib/winbind_util.h"
#include "passdb.h"
#include "../librpc/gen_ndr/ndr_auth.h"
#include "../auth/auth_sam_reply.h"
#include "../librpc/gen_ndr/idmap.h"
#include "lib/param/loadparm.h"
#include "../lib/tsocket/tsocket.h"
#include "rpc_client/util_netlogon.h"
#include "source4/auth/auth.h"
#include "auth/auth_util.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/****************************************************************************
 Create a UNIX user on demand.
****************************************************************************/

static int _smb_create_user(const char *domain, const char *unix_username, const char *homedir)
{
	TALLOC_CTX *ctx = talloc_tos();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *add_script;
	int ret;

	add_script = lp_add_user_script(ctx, lp_sub);
	if (!add_script || !*add_script) {
		return -1;
	}
	add_script = talloc_all_string_sub(ctx,
				add_script,
				"%u",
				unix_username);
	if (!add_script) {
		return -1;
	}
	if (domain) {
		add_script = talloc_all_string_sub(ctx,
					add_script,
					"%D",
					domain);
		if (!add_script) {
			return -1;
		}
	}
	if (homedir) {
		add_script = talloc_all_string_sub(ctx,
				add_script,
				"%H",
				homedir);
		if (!add_script) {
			return -1;
		}
	}
	ret = smbrun(add_script, NULL, NULL);
	flush_pwnam_cache();
	DEBUG(ret ? 0 : 3,
		("smb_create_user: Running the command `%s' gave %d\n",
		 add_script,ret));
	return ret;
}

/****************************************************************************
 Create an auth_usersupplied_data structure after appropriate mapping.
****************************************************************************/

NTSTATUS make_user_info_map(TALLOC_CTX *mem_ctx,
			    struct auth_usersupplied_info **user_info,
			    const char *smb_name,
			    const char *client_domain,
			    const char *workstation_name,
			    const struct tsocket_address *remote_address,
			    const struct tsocket_address *local_address,
			    const char *service_description,
			    const DATA_BLOB *lm_pwd,
			    const DATA_BLOB *nt_pwd,
			    const struct samr_Password *lm_interactive_pwd,
			    const struct samr_Password *nt_interactive_pwd,
			    const char *plaintext,
			    enum auth_password_state password_state)
{
	const char *domain;
	NTSTATUS result;
	bool was_mapped;
	char *internal_username = NULL;

	was_mapped = map_username(talloc_tos(), smb_name, &internal_username);
	if (!internal_username) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("Mapping user [%s]\\[%s] from workstation [%s]\n",
		 client_domain, smb_name, workstation_name));

	/*
	 * We let the auth stack canonicalize, username
	 * and domain.
	 */
	domain = client_domain;

	result = make_user_info(mem_ctx, user_info, smb_name, internal_username,
				client_domain, domain, workstation_name,
				remote_address, local_address,
				service_description, lm_pwd, nt_pwd,
				lm_interactive_pwd, nt_interactive_pwd,
				plaintext, password_state);
	if (NT_STATUS_IS_OK(result)) {
		/* We have tried mapping */
		(*user_info)->mapped_state = true;
		/* did we actually map the user to a different name? */
		(*user_info)->was_mapped = was_mapped;
	}
	return result;
}

/****************************************************************************
 Create an auth_usersupplied_data, making the DATA_BLOBs here. 
 Decrypt and encrypt the passwords.
****************************************************************************/

bool make_user_info_netlogon_network(TALLOC_CTX *mem_ctx,
				     struct auth_usersupplied_info **user_info,
				     const char *smb_name, 
				     const char *client_domain, 
				     const char *workstation_name,
				     const struct tsocket_address *remote_address,
				     const struct tsocket_address *local_address,
				     uint32_t logon_parameters,
				     const uchar *lm_network_pwd,
				     int lm_pwd_len,
				     const uchar *nt_network_pwd,
				     int nt_pwd_len)
{
	bool ret;
	NTSTATUS status;
	DATA_BLOB lm_blob = data_blob(lm_network_pwd, lm_pwd_len);
	DATA_BLOB nt_blob = data_blob(nt_network_pwd, nt_pwd_len);

	status = make_user_info_map(mem_ctx, user_info,
				    smb_name, client_domain, 
				    workstation_name,
				    remote_address,
				    local_address,
				    "SamLogon",
				    lm_pwd_len ? &lm_blob : NULL, 
				    nt_pwd_len ? &nt_blob : NULL,
				    NULL, NULL, NULL,
				    AUTH_PASSWORD_RESPONSE);

	if (NT_STATUS_IS_OK(status)) {
		(*user_info)->logon_parameters = logon_parameters;
	}
	ret = NT_STATUS_IS_OK(status) ? true : false;

	data_blob_free(&lm_blob);
	data_blob_free(&nt_blob);
	return ret;
}

/****************************************************************************
 Create an auth_usersupplied_data, making the DATA_BLOBs here. 
 Decrypt and encrypt the passwords.
****************************************************************************/

bool make_user_info_netlogon_interactive(TALLOC_CTX *mem_ctx,
					 struct auth_usersupplied_info **user_info,
					 const char *smb_name, 
					 const char *client_domain, 
					 const char *workstation_name,
					 const struct tsocket_address *remote_address,
					 const struct tsocket_address *local_address,
					 uint32_t logon_parameters,
					 const uchar chal[8], 
					 const uchar lm_interactive_pwd[16], 
					 const uchar nt_interactive_pwd[16])
{
	struct samr_Password lm_pwd;
	struct samr_Password nt_pwd;
	unsigned char local_lm_response[24];
	unsigned char local_nt_response[24];
	int rc;

	if (lm_interactive_pwd)
		memcpy(lm_pwd.hash, lm_interactive_pwd, sizeof(lm_pwd.hash));

	if (nt_interactive_pwd)
		memcpy(nt_pwd.hash, nt_interactive_pwd, sizeof(nt_pwd.hash));

	if (lm_interactive_pwd) {
		rc = SMBOWFencrypt(lm_pwd.hash, chal,
				   local_lm_response);
		if (rc != 0) {
			return false;
		}
	}

	if (nt_interactive_pwd) {
		rc = SMBOWFencrypt(nt_pwd.hash, chal,
			      local_nt_response);
		if (rc != 0) {
			return false;
		}
	}

	{
		bool ret;
		NTSTATUS nt_status;
		DATA_BLOB local_lm_blob = data_blob_null;
		DATA_BLOB local_nt_blob = data_blob_null;

		if (lm_interactive_pwd) {
			local_lm_blob = data_blob(local_lm_response,
						  sizeof(local_lm_response));
		}

		if (nt_interactive_pwd) {
			local_nt_blob = data_blob(local_nt_response,
						  sizeof(local_nt_response));
		}

		nt_status = make_user_info_map(
			mem_ctx,
			user_info, 
			smb_name, client_domain, workstation_name,
			remote_address,
			local_address,
			"SamLogon",
			lm_interactive_pwd ? &local_lm_blob : NULL,
			nt_interactive_pwd ? &local_nt_blob : NULL,
			lm_interactive_pwd ? &lm_pwd : NULL,
			nt_interactive_pwd ? &nt_pwd : NULL,
			NULL, AUTH_PASSWORD_HASH);

		if (NT_STATUS_IS_OK(nt_status)) {
			(*user_info)->logon_parameters = logon_parameters;
		}

		ret = NT_STATUS_IS_OK(nt_status) ? true : false;
		data_blob_free(&local_lm_blob);
		data_blob_free(&local_nt_blob);
		return ret;
	}
}


/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

bool make_user_info_for_reply(TALLOC_CTX *mem_ctx,
			      struct auth_usersupplied_info **user_info,
			      const char *smb_name, 
			      const char *client_domain,
			      const struct tsocket_address *remote_address,
			      const struct tsocket_address *local_address,
			      const char *service_description,
			      const uint8_t chal[8],
			      DATA_BLOB plaintext_password)
{

	DATA_BLOB local_lm_blob;
	DATA_BLOB local_nt_blob;
	NTSTATUS ret;
	char *plaintext_password_string;
	/*
	 * Not encrypted - do so.
	 */

	DEBUG(5,("make_user_info_for_reply: User passwords not in encrypted "
		 "format.\n"));
	if (plaintext_password.data && plaintext_password.length) {
		unsigned char local_lm_response[24];

#ifdef DEBUG_PASSWORD
		DEBUG(10,("Unencrypted password (len %d):\n",
			  (int)plaintext_password.length));
		dump_data(100, plaintext_password.data,
			  plaintext_password.length);
#endif

		SMBencrypt( (const char *)plaintext_password.data,
			    (const uchar*)chal, local_lm_response);
		local_lm_blob = data_blob(local_lm_response, 24);

		/* We can't do an NT hash here, as the password needs to be
		   case insensitive */
		local_nt_blob = data_blob_null; 
	} else {
		local_lm_blob = data_blob_null; 
		local_nt_blob = data_blob_null; 
	}

	plaintext_password_string = talloc_strndup(talloc_tos(),
						   (const char *)plaintext_password.data,
						   plaintext_password.length);
	if (!plaintext_password_string) {
		return false;
	}

	ret = make_user_info(mem_ctx,
		user_info, smb_name, smb_name, client_domain, client_domain, 
		get_remote_machine_name(),
		remote_address,
		local_address,
	        service_description,
		local_lm_blob.data ? &local_lm_blob : NULL,
		local_nt_blob.data ? &local_nt_blob : NULL,
		NULL, NULL,
		plaintext_password_string,
		AUTH_PASSWORD_PLAIN);

	if (plaintext_password_string) {
		memset(plaintext_password_string, '\0', strlen(plaintext_password_string));
		talloc_free(plaintext_password_string);
	}

	data_blob_free(&local_lm_blob);
	return NT_STATUS_IS_OK(ret) ? true : false;
}

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/

NTSTATUS make_user_info_for_reply_enc(TALLOC_CTX *mem_ctx,
				      struct auth_usersupplied_info **user_info,
                                      const char *smb_name,
                                      const char *client_domain,
				      const struct tsocket_address *remote_address,
				      const struct tsocket_address *local_address,
				      const char *service_description,
				      DATA_BLOB lm_resp, DATA_BLOB nt_resp)
{
	bool allow_raw = lp_raw_ntlmv2_auth();

	if (!allow_raw && nt_resp.length >= 48) {
		/*
		 * NTLMv2_RESPONSE has at least 48 bytes
		 * and should only be supported via NTLMSSP.
		 */
		DEBUG(2,("Rejecting raw NTLMv2 authentication with "
			 "user [%s\\%s] from[%s]\n",
			 client_domain, smb_name,
			 tsocket_address_string(remote_address, mem_ctx)));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return make_user_info(mem_ctx,
			      user_info, smb_name, smb_name,
			      client_domain, client_domain,
			      get_remote_machine_name(),
			      remote_address,
			      local_address,
			      service_description,
			      lm_resp.data && (lm_resp.length > 0) ? &lm_resp : NULL,
			      nt_resp.data && (nt_resp.length > 0) ? &nt_resp : NULL,
			      NULL, NULL, NULL,
			      AUTH_PASSWORD_RESPONSE);
}

/****************************************************************************
 Create a guest user_info blob, for anonymous authentication.
****************************************************************************/

bool make_user_info_guest(TALLOC_CTX *mem_ctx,
			  const struct tsocket_address *remote_address,
			  const struct tsocket_address *local_address,
			  const char *service_description,
			  struct auth_usersupplied_info **user_info)
{
	NTSTATUS nt_status;

	nt_status = make_user_info(mem_ctx,
				   user_info,
				   "","", 
				   "","", 
				   "", 
				   remote_address,
				   local_address,
				   service_description,
				   NULL, NULL, 
				   NULL, NULL, 
				   NULL,
				   AUTH_PASSWORD_RESPONSE);

	return NT_STATUS_IS_OK(nt_status) ? true : false;
}

static NTSTATUS log_nt_token(struct security_token *token)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *command;
	char *group_sidstr;
	struct dom_sid_buf buf;
	size_t i;

	if ((lp_log_nt_token_command(frame, lp_sub) == NULL) ||
	    (strlen(lp_log_nt_token_command(frame, lp_sub)) == 0)) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	group_sidstr = talloc_strdup(frame, "");
	for (i=1; i<token->num_sids; i++) {
		group_sidstr = talloc_asprintf(
			frame, "%s %s", group_sidstr,
			dom_sid_str_buf(&token->sids[i], &buf));
	}

	command = talloc_string_sub(
		frame, lp_log_nt_token_command(frame, lp_sub),
		"%s", dom_sid_str_buf(&token->sids[0], &buf));
	command = talloc_string_sub(frame, command, "%t", group_sidstr);

	if (command == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(8, ("running command: [%s]\n", command));
	if (smbrun(command, NULL, NULL) != 0) {
		DEBUG(0, ("Could not log NT token\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_ACCESS_DENIED;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/*
 * Create the token to use from server_info->info3 and
 * server_info->sids (the info3/sam groups). Find the unix gids.
 */

NTSTATUS create_local_token(TALLOC_CTX *mem_ctx,
			    const struct auth_serversupplied_info *server_info,
			    DATA_BLOB *session_key,
			    const char *smb_username, /* for ->sanitized_username, for %U subs */
			    struct auth_session_info **session_info_out)
{
	struct security_token *t;
	NTSTATUS status;
	size_t i;
	struct dom_sid tmp_sid;
	struct auth_session_info *session_info;
	struct unixid *ids;

	/* Ensure we can't possible take a code path leading to a
	 * null defref. */
	if (!server_info) {
		return NT_STATUS_LOGON_FAILURE;
	}

	if (!is_allowed_domain(server_info->info3->base.logon_domain.string)) {
		DBG_NOTICE("Authentication failed for user [%s] "
			   "from firewalled domain [%s]\n",
			   server_info->info3->base.account_name.string,
			   server_info->info3->base.logon_domain.string);
		return NT_STATUS_AUTHENTICATION_FIREWALL_FAILED;
	}

	if (server_info->cached_session_info != NULL) {
		session_info = copy_session_info(mem_ctx,
				server_info->cached_session_info);
		if (session_info == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		/* This is a potentially untrusted username for use in %U */
		session_info->unix_info->sanitized_username =
			talloc_alpha_strcpy(session_info->unix_info,
					    smb_username,
					    SAFE_NETBIOS_CHARS "$");
		if (session_info->unix_info->sanitized_username == NULL) {
			TALLOC_FREE(session_info);
			return NT_STATUS_NO_MEMORY;
		}

		session_info->unique_session_token = GUID_random();

		*session_info_out = session_info;
		return NT_STATUS_OK;
	}

	session_info = talloc_zero(mem_ctx, struct auth_session_info);
	if (!session_info) {
		return NT_STATUS_NO_MEMORY;
	}

	session_info->unix_token = talloc_zero(session_info, struct security_unix_token);
	if (!session_info->unix_token) {
		TALLOC_FREE(session_info);
		return NT_STATUS_NO_MEMORY;
	}

	session_info->unix_token->uid = server_info->utok.uid;
	session_info->unix_token->gid = server_info->utok.gid;

	session_info->unix_info = talloc_zero(session_info, struct auth_user_info_unix);
	if (!session_info->unix_info) {
		TALLOC_FREE(session_info);
		return NT_STATUS_NO_MEMORY;
	}

	session_info->unix_info->unix_name = talloc_strdup(session_info, server_info->unix_name);
	if (!session_info->unix_info->unix_name) {
		TALLOC_FREE(session_info);
		return NT_STATUS_NO_MEMORY;
	}

	/* This is a potentially untrusted username for use in %U */
	session_info->unix_info->sanitized_username =
		talloc_alpha_strcpy(session_info->unix_info,
				    smb_username,
				    SAFE_NETBIOS_CHARS "$");
	if (session_info->unix_info->sanitized_username == NULL) {
		TALLOC_FREE(session_info);
		return NT_STATUS_NO_MEMORY;
	}

	if (session_key) {
		data_blob_free(&session_info->session_key);
		session_info->session_key = data_blob_talloc(session_info,
								  session_key->data,
								  session_key->length);
		if (!session_info->session_key.data && session_key->length) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		session_info->session_key = data_blob_talloc( session_info, server_info->session_key.data,
							      server_info->session_key.length);
	}

	/* We need to populate session_info->info with the information found in server_info->info3 */
	status = make_user_info_SamBaseInfo(session_info, "", &server_info->info3->base,
					    server_info->guest == false,
					    &session_info->info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("conversion of info3 into auth_user_info failed!\n"));
		TALLOC_FREE(session_info);
		return status;
	}

	/*
	 * If the user name was mapped to some local unix user,
	 * we can not make much use of the SIDs the
	 * domain controller provided us with.
	 */
	if (server_info->nss_token) {
		char *found_username = NULL;
		status = create_token_from_username(session_info,
						    server_info->unix_name,
						    server_info->guest,
						    &session_info->unix_token->uid,
						    &session_info->unix_token->gid,
						    &found_username,
						    &session_info->security_token);
		if (NT_STATUS_IS_OK(status)) {
			session_info->unix_info->unix_name = found_username;
		}
	} else {
		status = create_local_nt_token_from_info3(session_info,
							  server_info->guest,
							  server_info->info3,
							  &server_info->extra,
							  &session_info->security_token);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Convert the SIDs to gids. */

	session_info->unix_token->ngroups = 0;
	session_info->unix_token->groups = NULL;

	t = session_info->security_token;

	ids = talloc_array(talloc_tos(), struct unixid,
			   t->num_sids);
	if (ids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!sids_to_unixids(t->sids, t->num_sids, ids)) {
		TALLOC_FREE(ids);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<t->num_sids; i++) {

		if (i == 0 && ids[i].type != ID_TYPE_BOTH) {
			continue;
		}

		if (ids[i].type != ID_TYPE_GID &&
		    ids[i].type != ID_TYPE_BOTH) {
			struct dom_sid_buf buf;
			DEBUG(10, ("Could not convert SID %s to gid, "
				   "ignoring it\n",
				   dom_sid_str_buf(&t->sids[i], &buf)));
			continue;
		}
		if (!add_gid_to_array_unique(session_info->unix_token,
					     ids[i].id,
					     &session_info->unix_token->groups,
					     &session_info->unix_token->ngroups)) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/*
	 * Add the "Unix Group" SID for each gid to catch mapped groups
	 * and their Unix equivalent.  This is to solve the backwards
	 * compatibility problem of 'valid users = +ntadmin' where
	 * ntadmin has been paired with "Domain Admins" in the group
	 * mapping table.  Otherwise smb.conf would need to be changed
	 * to 'valid user = "Domain Admins"'.  --jerry
	 *
	 * For consistency we also add the "Unix User" SID,
	 * so that the complete unix token is represented within
	 * the nt token.
	 */

	uid_to_unix_users_sid(session_info->unix_token->uid, &tmp_sid);
	add_sid_to_array_unique(session_info->security_token, &tmp_sid,
				&session_info->security_token->sids,
				&session_info->security_token->num_sids);

	gid_to_unix_groups_sid(session_info->unix_token->gid, &tmp_sid);
	add_sid_to_array_unique(session_info->security_token, &tmp_sid,
				&session_info->security_token->sids,
				&session_info->security_token->num_sids);

	for ( i=0; i<session_info->unix_token->ngroups; i++ ) {
		gid_to_unix_groups_sid(session_info->unix_token->groups[i], &tmp_sid);
		add_sid_to_array_unique(session_info->security_token, &tmp_sid,
					&session_info->security_token->sids,
					&session_info->security_token->num_sids);
	}

	security_token_debug(DBGC_AUTH, 10, session_info->security_token);
	debug_unix_user_token(DBGC_AUTH, 10,
			      session_info->unix_token->uid,
			      session_info->unix_token->gid,
			      session_info->unix_token->ngroups,
			      session_info->unix_token->groups);

	status = log_nt_token(session_info->security_token);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	session_info->unique_session_token = GUID_random();

	*session_info_out = session_info;
	return NT_STATUS_OK;
}

NTSTATUS auth3_user_info_dc_add_hints(struct auth_user_info_dc *user_info_dc,
				      uid_t uid,
				      gid_t gid,
				      uint32_t flags)
{
	uint32_t orig_num_sids = user_info_dc->num_sids;
	struct dom_sid tmp_sid = { 0, };
	NTSTATUS status;

	/*
	 * We add S-5-88-1-X in order to pass the uid
	 * for the unix token.
	 */
	sid_compose(&tmp_sid,
		    &global_sid_Unix_NFS_Users,
		    (uint32_t)uid);
	status = add_sid_to_array_unique(user_info_dc->sids,
					 &tmp_sid,
					 &user_info_dc->sids,
					 &user_info_dc->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("add_sid_to_array_unique failed: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	/*
	 * We add S-5-88-2-X in order to pass the gid
	 * for the unix token.
	 */
	sid_compose(&tmp_sid,
		    &global_sid_Unix_NFS_Groups,
		    (uint32_t)gid);
	status = add_sid_to_array_unique(user_info_dc->sids,
					 &tmp_sid,
					 &user_info_dc->sids,
					 &user_info_dc->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("add_sid_to_array_unique failed: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	/*
	 * We add S-5-88-3-X in order to pass some flags
	 * (AUTH3_UNIX_HINT_*) to auth3_create_session_info().
	 */
	sid_compose(&tmp_sid,
		    &global_sid_Unix_NFS_Mode,
		    flags);
	status = add_sid_to_array_unique(user_info_dc->sids,
					 &tmp_sid,
					 &user_info_dc->sids,
					 &user_info_dc->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("add_sid_to_array_unique failed: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	return NT_STATUS_OK;

fail:
	user_info_dc->num_sids = orig_num_sids;
	return status;
}

NTSTATUS auth3_session_info_create(TALLOC_CTX *mem_ctx,
				   const struct auth_user_info_dc *user_info_dc,
				   const char *original_user_name,
				   uint32_t session_info_flags,
				   struct auth_session_info **session_info_out)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct auth_session_info *session_info = NULL;
	uid_t hint_uid = -1;
	bool found_hint_uid = false;
	uid_t hint_gid = -1;
	bool found_hint_gid = false;
	uint32_t hint_flags = 0;
	bool found_hint_flags = false;
	bool need_getpwuid = false;
	struct unixid *ids = NULL;
	uint32_t num_gids = 0;
	gid_t *gids = NULL;
	struct dom_sid tmp_sid = { 0, };
	NTSTATUS status;
	size_t i;
	bool ok;

	*session_info_out = NULL;

	if (user_info_dc->num_sids == 0) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_TOKEN;
	}

	if (user_info_dc->info == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_TOKEN;
	}

	if (user_info_dc->info->account_name == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_TOKEN;
	}

	session_info = talloc_zero(mem_ctx, struct auth_session_info);
	if (session_info == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	/* keep this under frame for easier cleanup */
	talloc_reparent(mem_ctx, frame, session_info);

	session_info->info = auth_user_info_copy(session_info,
						 user_info_dc->info);
	if (session_info->info == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	session_info->security_token = talloc_zero(session_info,
						   struct security_token);
	if (session_info->security_token == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Avoid a lot of reallocations and allocate what we'll
	 * use in most cases.
	 */
	session_info->security_token->sids = talloc_zero_array(
						session_info->security_token,
						struct dom_sid,
						user_info_dc->num_sids);
	if (session_info->security_token->sids == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = PRIMARY_USER_SID_INDEX; i < user_info_dc->num_sids; i++) {
		struct security_token *nt_token = session_info->security_token;
		int cmp;

		/*
		 * S-1-5-88-X-Y sids are only used to give hints
		 * to the unix token construction.
		 *
		 * S-1-5-88-1-Y gives the uid=Y
		 * S-1-5-88-2-Y gives the gid=Y
		 * S-1-5-88-3-Y gives flags=Y: AUTH3_UNIX_HINT_*
		 */
		cmp = dom_sid_compare_domain(&global_sid_Unix_NFS,
					     &user_info_dc->sids[i]);
		if (cmp == 0) {
			bool match;
			uint32_t hint = 0;

			match = sid_peek_rid(&user_info_dc->sids[i], &hint);
			if (!match) {
				continue;
			}

			match = dom_sid_in_domain(&global_sid_Unix_NFS_Users,
						  &user_info_dc->sids[i]);
			if (match) {
				if (found_hint_uid) {
					TALLOC_FREE(frame);
					return NT_STATUS_INVALID_TOKEN;
				}
				found_hint_uid = true;
				hint_uid = (uid_t)hint;
				continue;
			}

			match = dom_sid_in_domain(&global_sid_Unix_NFS_Groups,
						  &user_info_dc->sids[i]);
			if (match) {
				if (found_hint_gid) {
					TALLOC_FREE(frame);
					return NT_STATUS_INVALID_TOKEN;
				}
				found_hint_gid = true;
				hint_gid = (gid_t)hint;
				continue;
			}

			match = dom_sid_in_domain(&global_sid_Unix_NFS_Mode,
						  &user_info_dc->sids[i]);
			if (match) {
				if (found_hint_flags) {
					TALLOC_FREE(frame);
					return NT_STATUS_INVALID_TOKEN;
				}
				found_hint_flags = true;
				hint_flags = hint;
				continue;
			}

			continue;
		}

		status = add_sid_to_array_unique(nt_token->sids,
						 &user_info_dc->sids[i],
						 &nt_token->sids,
						 &nt_token->num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	}

	/*
	 * We need at least one usable SID
	 */
	if (session_info->security_token->num_sids == 0) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_TOKEN;
	}

	/*
	 * We need all tree hints: uid, gid, flags
	 * or none of them.
	 */
	if (found_hint_uid || found_hint_gid || found_hint_flags) {
		if (!found_hint_uid) {
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_TOKEN;
		}

		if (!found_hint_gid) {
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_TOKEN;
		}

		if (!found_hint_flags) {
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_TOKEN;
		}
	}

	if (session_info->info->authenticated) {
		session_info_flags |= AUTH_SESSION_INFO_AUTHENTICATED;
	}

	status = finalize_local_nt_token(session_info->security_token,
					 session_info_flags);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * unless set otherwise, the session key is the user session
	 * key from the auth subsystem
	 */
	if (user_info_dc->user_session_key.length != 0) {
		session_info->session_key = data_blob_dup_talloc(session_info,
						user_info_dc->user_session_key);
		if (session_info->session_key.data == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (!(session_info_flags & AUTH_SESSION_INFO_UNIX_TOKEN)) {
		goto done;
	}

	session_info->unix_token = talloc_zero(session_info, struct security_unix_token);
	if (session_info->unix_token == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	session_info->unix_token->uid = -1;
	session_info->unix_token->gid = -1;

	session_info->unix_info = talloc_zero(session_info, struct auth_user_info_unix);
	if (session_info->unix_info == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* Convert the SIDs to uid/gids. */

	ids = talloc_zero_array(frame, struct unixid,
				session_info->security_token->num_sids);
	if (ids == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	if (!(hint_flags & AUTH3_UNIX_HINT_DONT_TRANSLATE_FROM_SIDS)) {
		ok = sids_to_unixids(session_info->security_token->sids,
				     session_info->security_token->num_sids,
				     ids);
		if (!ok) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (found_hint_uid) {
		session_info->unix_token->uid = hint_uid;
	} else if (ids[0].type == ID_TYPE_UID) {
		/*
		 * The primary SID resolves to a UID only.
		 */
		session_info->unix_token->uid = ids[0].id;
	} else if (ids[0].type == ID_TYPE_BOTH) {
		/*
		 * The primary SID resolves to a UID and GID,
		 * use it as uid and add it as first element
		 * to the groups array.
		 */
		session_info->unix_token->uid = ids[0].id;

		ok = add_gid_to_array_unique(session_info->unix_token,
					     session_info->unix_token->uid,
					     &session_info->unix_token->groups,
					     &session_info->unix_token->ngroups);
		if (!ok) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		/*
		 * It we can't get a uid, we can't imporsonate
		 * the user.
		 */
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_TOKEN;
	}

	if (found_hint_gid) {
		session_info->unix_token->gid = hint_gid;
	} else {
		need_getpwuid = true;
	}

	if (hint_flags & AUTH3_UNIX_HINT_QUALIFIED_NAME) {
		session_info->unix_info->unix_name =
			talloc_asprintf(session_info->unix_info,
					"%s%c%s",
					session_info->info->domain_name,
					*lp_winbind_separator(),
					session_info->info->account_name);
		if (session_info->unix_info->unix_name == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	} else if (hint_flags & AUTH3_UNIX_HINT_ISLOLATED_NAME) {
		session_info->unix_info->unix_name =
			talloc_strdup(session_info->unix_info,
				      session_info->info->account_name);
		if (session_info->unix_info->unix_name == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		need_getpwuid = true;
	}

	if (need_getpwuid) {
		struct passwd *pwd = NULL;

		/*
		 * Ask the system for the primary gid
		 * and the real unix name.
		 */
		pwd = getpwuid_alloc(frame, session_info->unix_token->uid);
		if (pwd == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_TOKEN;
		}
		if (!found_hint_gid) {
			session_info->unix_token->gid = pwd->pw_gid;
		}

		session_info->unix_info->unix_name =
			talloc_strdup(session_info->unix_info, pwd->pw_name);
		if (session_info->unix_info->unix_name == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		TALLOC_FREE(pwd);
	}

	ok = add_gid_to_array_unique(session_info->unix_token,
				     session_info->unix_token->gid,
				     &session_info->unix_token->groups,
				     &session_info->unix_token->ngroups);
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* This is a potentially untrusted username for use in %U */
	session_info->unix_info->sanitized_username =
		talloc_alpha_strcpy(session_info->unix_info,
				    original_user_name,
				    SAFE_NETBIOS_CHARS "$");
	if (session_info->unix_info->sanitized_username == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i < session_info->security_token->num_sids; i++) {

		if (ids[i].type != ID_TYPE_GID &&
		    ids[i].type != ID_TYPE_BOTH) {
			struct security_token *nt_token =
				session_info->security_token;
			struct dom_sid_buf buf;

			DEBUG(10, ("Could not convert SID %s to gid, "
				   "ignoring it\n",
				   dom_sid_str_buf(&nt_token->sids[i], &buf)));
			continue;
		}

		ok = add_gid_to_array_unique(session_info->unix_token,
					     ids[i].id,
					     &session_info->unix_token->groups,
					     &session_info->unix_token->ngroups);
		if (!ok) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}
	TALLOC_FREE(ids);

	/*
	 * Now we must get any groups this user has been
	 * added to in /etc/group and merge them in.
	 * This has to be done in every code path
	 * that creates an NT token, as remote users
	 * may have been added to the local /etc/group
	 * database. Tokens created merely from the
	 * info3 structs (via the DC or via the krb5 PAC)
	 * won't have these local groups. Note the
	 * groups added here will only be UNIX groups
	 * (S-1-22-2-XXXX groups) as getgroups_unix_user()
	 * turns off winbindd before calling getgroups().
	 *
	 * NB. This is duplicating work already
	 * done in the 'unix_user:' case of
	 * create_token_from_sid() but won't
	 * do anything other than be inefficient
	 * in that case.
	 */
	if (!(hint_flags & AUTH3_UNIX_HINT_DONT_EXPAND_UNIX_GROUPS)) {
		ok = getgroups_unix_user(frame,
					 session_info->unix_info->unix_name,
					 session_info->unix_token->gid,
					 &gids, &num_gids);
		if (!ok) {
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_TOKEN;
		}
	}

	for (i=0; i < num_gids; i++) {

		ok = add_gid_to_array_unique(session_info->unix_token,
					     gids[i],
					     &session_info->unix_token->groups,
					     &session_info->unix_token->ngroups);
		if (!ok) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}
	TALLOC_FREE(gids);

	if (hint_flags & AUTH3_UNIX_HINT_DONT_TRANSLATE_TO_SIDS) {
		/*
		 * We should not translate the unix token uid/gids
		 * to S-1-22-X-Y SIDs.
		 */
		goto done;
	}

	/*
	 * Add the "Unix Group" SID for each gid to catch mapped groups
	 * and their Unix equivalent.  This is to solve the backwards
	 * compatibility problem of 'valid users = +ntadmin' where
	 * ntadmin has been paired with "Domain Admins" in the group
	 * mapping table.  Otherwise smb.conf would need to be changed
	 * to 'valid user = "Domain Admins"'.  --jerry
	 *
	 * For consistency we also add the "Unix User" SID,
	 * so that the complete unix token is represented within
	 * the nt token.
	 */

	uid_to_unix_users_sid(session_info->unix_token->uid, &tmp_sid);
	status = add_sid_to_array_unique(session_info->security_token, &tmp_sid,
					 &session_info->security_token->sids,
					 &session_info->security_token->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	gid_to_unix_groups_sid(session_info->unix_token->gid, &tmp_sid);
	status = add_sid_to_array_unique(session_info->security_token, &tmp_sid,
					 &session_info->security_token->sids,
					 &session_info->security_token->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	for (i=0; i < session_info->unix_token->ngroups; i++ ) {
		struct security_token *nt_token = session_info->security_token;

		gid_to_unix_groups_sid(session_info->unix_token->groups[i],
				       &tmp_sid);
		status = add_sid_to_array_unique(nt_token->sids,
						 &tmp_sid,
						 &nt_token->sids,
						 &nt_token->num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	}

done:
	security_token_debug(DBGC_AUTH, 10, session_info->security_token);
	if (session_info->unix_token != NULL) {
		debug_unix_user_token(DBGC_AUTH, 10,
				      session_info->unix_token->uid,
				      session_info->unix_token->gid,
				      session_info->unix_token->ngroups,
				      session_info->unix_token->groups);
	}

	status = log_nt_token(session_info->security_token);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	session_info->unique_session_token = GUID_random();
	
	*session_info_out = talloc_move(mem_ctx, &session_info);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/***************************************************************************
 Make (and fill) a server_info struct from a 'struct passwd' by conversion
 to a struct samu
***************************************************************************/

NTSTATUS make_server_info_pw(TALLOC_CTX *mem_ctx,
			     const char *unix_username,
			     const struct passwd *pwd,
			     struct auth_serversupplied_info **server_info)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = NULL;
	struct auth_serversupplied_info *result;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result = make_server_info(tmp_ctx);
	if (result == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = passwd_to_SamInfo3(result,
				    unix_username,
				    pwd,
				    &result->info3,
				    &result->extra);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	result->unix_name = talloc_strdup(result, unix_username);
	if (result->unix_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result->utok.uid = pwd->pw_uid;
	result->utok.gid = pwd->pw_gid;

	*server_info = talloc_steal(mem_ctx, result);
	status = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return status;
}

static NTSTATUS get_guest_info3(TALLOC_CTX *mem_ctx,
				struct netr_SamInfo3 *info3)
{
	const char *guest_account = lp_guest_account();
	struct dom_sid domain_sid;
	struct passwd *pwd;
	const char *tmp;

	pwd = Get_Pwnam_alloc(mem_ctx, guest_account);
	if (pwd == NULL) {
		DEBUG(0,("SamInfo3_for_guest: Unable to locate guest "
			 "account [%s]!\n", guest_account));
		return NT_STATUS_NO_SUCH_USER;
	}

	/* Set account name */
	tmp = talloc_strdup(mem_ctx, pwd->pw_name);
	if (tmp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	init_lsa_String(&info3->base.account_name, tmp);

	/* Set domain name */
	tmp = talloc_strdup(mem_ctx, get_global_sam_name());
	if (tmp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	init_lsa_StringLarge(&info3->base.logon_domain, tmp);

	/* Domain sid */
	sid_copy(&domain_sid, get_global_sam_sid());

	info3->base.domain_sid = dom_sid_dup(mem_ctx, &domain_sid);
	if (info3->base.domain_sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Guest rid */
	info3->base.rid = DOMAIN_RID_GUEST;

	/* Primary gid */
	info3->base.primary_gid = DOMAIN_RID_GUESTS;

	/* Set as guest */
	info3->base.user_flags = NETLOGON_GUEST;

	TALLOC_FREE(pwd);
	return NT_STATUS_OK;
}

/***************************************************************************
 Make (and fill) a user_info struct for a guest login.
 This *must* succeed for smbd to start. If there is no mapping entry for
 the guest gid, then create one.

 The resulting structure is a 'session_info' because
 create_local_token() has already been called on it.  This is quite
 nasty, as the auth subsystem isn't expect this, but the behavior is
 left as-is for now.
***************************************************************************/

static NTSTATUS make_new_session_info_guest(TALLOC_CTX *mem_ctx,
		struct auth_session_info **_session_info,
		struct auth_serversupplied_info **_server_info)
{
	struct auth_session_info *session_info = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	const char *guest_account = lp_guest_account();
	const char *domain = lp_netbios_name();
	struct netr_SamInfo3 info3;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(info3);

	status = get_guest_info3(tmp_ctx, &info3);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("get_guest_info3 failed with %s\n",
			  nt_errstr(status)));
		goto done;
	}

	status = make_server_info_info3(tmp_ctx,
					guest_account,
					domain,
					&server_info,
					&info3);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("make_server_info_info3 failed with %s\n",
			  nt_errstr(status)));
		goto done;
	}

	server_info->guest = true;

	/* This should not be done here (we should produce a server
	 * info, and later construct a session info from it), but for
	 * now this does not change the previous behavior */
	status = create_local_token(tmp_ctx, server_info, NULL,
				    server_info->info3->base.account_name.string,
				    &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("create_local_token failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	/*
	 * It's ugly, but for now it's
	 * needed to force Builtin_Guests
	 * here, because memberships of
	 * Builtin_Guests might be incomplete.
	 */
	status = add_sid_to_array_unique(session_info->security_token,
					 &global_sid_Builtin_Guests,
					 &session_info->security_token->sids,
					 &session_info->security_token->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to force Builtin_Guests to nt token\n");
		goto done;
	}

	/* annoying, but the Guest really does have a session key, and it is
	   all zeros! */
	session_info->session_key = data_blob_talloc_zero(session_info, 16);

	*_session_info = talloc_move(mem_ctx, &session_info);
	*_server_info = talloc_move(mem_ctx, &server_info);

	status = NT_STATUS_OK;
done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/***************************************************************************
 Make (and fill) a auth_session_info struct for a system user login.
 This *must* succeed for smbd to start.
***************************************************************************/

static NTSTATUS make_new_session_info_system(TALLOC_CTX *mem_ctx,
					    struct auth_session_info **session_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct auth_user_info_dc *user_info_dc = NULL;
	uid_t uid = -1;
	gid_t gid = -1;
	uint32_t hint_flags = 0;
	uint32_t session_info_flags = 0;
	NTSTATUS status;

	status = auth_system_user_info_dc(frame, lp_netbios_name(),
					  &user_info_dc);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("auth_system_user_info_dc failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	/*
	 * Just get the initial uid/gid
	 * and don't expand the unix groups.
	 */
	uid = sec_initial_uid();
	gid = sec_initial_gid();
	hint_flags |= AUTH3_UNIX_HINT_DONT_EXPAND_UNIX_GROUPS;

	/*
	 * Also avoid sid mapping to gids,
	 * as well as adding the unix_token uid/gids as
	 * S-1-22-X-Y SIDs to the nt token.
	 */
	hint_flags |= AUTH3_UNIX_HINT_DONT_TRANSLATE_FROM_SIDS;
	hint_flags |= AUTH3_UNIX_HINT_DONT_TRANSLATE_TO_SIDS;

	/*
	 * The unix name will be "NT AUTHORITY+SYSTEM",
	 * where '+' is the "winbind separator" character.
	 */
	hint_flags |= AUTH3_UNIX_HINT_QUALIFIED_NAME;
	status = auth3_user_info_dc_add_hints(user_info_dc,
					      uid,
					      gid,
					      hint_flags);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("auth3_user_info_dc_add_hints failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;
	session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	status = auth3_session_info_create(mem_ctx, user_info_dc,
					   user_info_dc->info->account_name,
					   session_info_flags,
					   session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("auth3_session_info_create failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

done:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS make_new_session_info_anonymous(TALLOC_CTX *mem_ctx,
					struct auth_session_info **session_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *guest_account = lp_guest_account();
	struct auth_user_info_dc *user_info_dc = NULL;
	struct passwd *pwd = NULL;
	uint32_t hint_flags = 0;
	uint32_t session_info_flags = 0;
	NTSTATUS status;

	/*
	 * We use the guest account for the unix token
	 * while we use a true anonymous nt token.
	 *
	 * It's very important to have a separate
	 * nt token for anonymous.
	 */

	pwd = Get_Pwnam_alloc(frame, guest_account);
	if (pwd == NULL) {
		DBG_ERR("Unable to locate guest account [%s]!\n",
			guest_account);
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	status = auth_anonymous_user_info_dc(frame, lp_netbios_name(),
					     &user_info_dc);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("auth_anonymous_user_info_dc failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	/*
	 * Note we don't pass AUTH3_UNIX_HINT_QUALIFIED_NAME
	 * nor AUTH3_UNIX_HINT_ISOLATED_NAME here
	 * as we want the unix name be found by getpwuid_alloc().
	 */

	status = auth3_user_info_dc_add_hints(user_info_dc,
					      pwd->pw_uid,
					      pwd->pw_gid,
					      hint_flags);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("auth3_user_info_dc_add_hints failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	/*
	 * In future we may want to remove
	 * AUTH_SESSION_INFO_DEFAULT_GROUPS.
	 *
	 * Similar to Windows with EveryoneIncludesAnonymous
	 * and RestrictAnonymous.
	 *
	 * We may introduce AUTH_SESSION_INFO_ANON_WORLD...
	 *
	 * But for this is required to keep the existing tests
	 * working.
	 */
	session_info_flags |= AUTH_SESSION_INFO_DEFAULT_GROUPS;
	session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;
	session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	status = auth3_session_info_create(mem_ctx, user_info_dc,
					   "",
					   session_info_flags,
					   session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("auth3_session_info_create failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

done:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
  Fake a auth_session_info just from a username (as a
  session_info structure, with create_local_token() already called on
  it.
****************************************************************************/

NTSTATUS make_session_info_from_username(TALLOC_CTX *mem_ctx,
					 const char *username,
					 bool is_guest,
					 struct auth_session_info **session_info)
{
	struct passwd *pwd;
	NTSTATUS status;
	struct auth_serversupplied_info *result;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pwd = Get_Pwnam_alloc(tmp_ctx, username);
	if (pwd == NULL) {
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	status = make_server_info_pw(tmp_ctx, pwd->pw_name, pwd, &result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	result->nss_token = true;
	result->guest = is_guest;

	/* Now turn the server_info into a session_info with the full token etc */
	status = create_local_token(mem_ctx,
				    result,
				    NULL,
				    pwd->pw_name,
				    session_info);

done:
	talloc_free(tmp_ctx);

	return status;
}

/* This function MUST only used to create the cached server_info for
 * guest.
 *
 * This is a lossy conversion.  Variables known to be lost so far
 * include:
 *
 * - nss_token (not needed because the only read doesn't happen
 * for the GUEST user, as this routine populates ->security_token
 *
 * - extra (not needed because the guest account must have valid RIDs per the output of get_guest_info3())
 *
 * - The 'server_info' parameter allows the missing 'info3' to be copied across.
 */
static struct auth_serversupplied_info *copy_session_info_serverinfo_guest(TALLOC_CTX *mem_ctx,
									   const struct auth_session_info *src,
									   struct auth_serversupplied_info *server_info)
{
	struct auth_serversupplied_info *dst;
	NTSTATUS status;

	dst = make_server_info(mem_ctx);
	if (dst == NULL) {
		return NULL;
	}

	/* This element must be provided to convert back to an auth_serversupplied_info */
	SMB_ASSERT(src->unix_info);

	dst->guest = true;

	/* This element must be provided to convert back to an
	 * auth_serversupplied_info.  This needs to be from the
	 * auth_session_info because the group values in particular
	 * may change during create_local_token() processing */
	SMB_ASSERT(src->unix_token);
	dst->utok.uid = src->unix_token->uid;
	dst->utok.gid = src->unix_token->gid;
	dst->utok.ngroups = src->unix_token->ngroups;
	if (src->unix_token->ngroups != 0) {
		dst->utok.groups = (gid_t *)talloc_memdup(
			dst, src->unix_token->groups,
			sizeof(gid_t)*dst->utok.ngroups);
	} else {
		dst->utok.groups = NULL;
	}

	/* We must have a security_token as otherwise the lossy
	 * conversion without nss_token would cause create_local_token
	 * to take the wrong path */
	SMB_ASSERT(src->security_token);

	dst->session_key = data_blob_talloc( dst, src->session_key.data,
						src->session_key.length);

	/* This is OK because this functions is only used for the
	 * GUEST account, which has all-zero keys for both values */
	dst->lm_session_key = data_blob_talloc(dst, src->session_key.data,
						src->session_key.length);

	status = copy_netr_SamInfo3(dst,
				    server_info->info3,
				    &dst->info3);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(dst);
		return NULL;
	}

	dst->unix_name = talloc_strdup(dst, src->unix_info->unix_name);
	if (!dst->unix_name) {
		TALLOC_FREE(dst);
		return NULL;
	}

	dst->cached_session_info = src;
	return dst;
}

/*
 * Set a new session key. Used in the rpc server where we have to override the
 * SMB level session key with SystemLibraryDTC
 */

bool session_info_set_session_key(struct auth_session_info *info,
				 DATA_BLOB session_key)
{
	TALLOC_FREE(info->session_key.data);

	info->session_key = data_blob_talloc(
		info, session_key.data, session_key.length);

	return (info->session_key.data != NULL);
}

static struct auth_session_info *guest_info = NULL;
static struct auth_session_info *anonymous_info = NULL;

static struct auth_serversupplied_info *guest_server_info = NULL;

bool init_guest_session_info(TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;

	if (guest_info != NULL)
		return true;

	status = make_new_session_info_guest(mem_ctx,
					     &guest_info,
					     &guest_server_info);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	status = make_new_session_info_anonymous(mem_ctx,
						 &anonymous_info);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return true;
}

bool reinit_guest_session_info(TALLOC_CTX *mem_ctx)
{
	TALLOC_FREE(guest_info);
	TALLOC_FREE(guest_server_info);
	TALLOC_FREE(anonymous_info);

	DBG_DEBUG("Reinitialing guest info\n");

	return init_guest_session_info(mem_ctx);
}

NTSTATUS make_server_info_guest(TALLOC_CTX *mem_ctx,
				struct auth_serversupplied_info **server_info)
{
	/* This is trickier than it would appear to need to be because
	 * we are trying to avoid certain costly operations when the
	 * structure is converted to a 'auth_session_info' again in
	 * create_local_token() */
	*server_info = copy_session_info_serverinfo_guest(mem_ctx, guest_info, guest_server_info);
	return (*server_info != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;
}

NTSTATUS make_session_info_guest(TALLOC_CTX *mem_ctx,
				struct auth_session_info **session_info)
{
	*session_info = copy_session_info(mem_ctx, guest_info);
	return (*session_info != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;
}

NTSTATUS make_server_info_anonymous(TALLOC_CTX *mem_ctx,
				    struct auth_serversupplied_info **server_info)
{
	if (anonymous_info == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/*
	 * This is trickier than it would appear to need to be because
	 * we are trying to avoid certain costly operations when the
	 * structure is converted to a 'auth_session_info' again in
	 * create_local_token()
	 *
	 * We use a guest server_info, but with the anonymous session info,
	 * which means create_local_token() will return a copy
	 * of the anonymous token.
	 *
	 * The server info is just used as legacy in order to
	 * keep existing code working. Maybe some debug messages
	 * will still refer to guest instead of anonymous.
	 */
	*server_info = copy_session_info_serverinfo_guest(mem_ctx, anonymous_info,
							  guest_server_info);
	if (*server_info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

NTSTATUS make_session_info_anonymous(TALLOC_CTX *mem_ctx,
				     struct auth_session_info **session_info)
{
	if (anonymous_info == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	*session_info = copy_session_info(mem_ctx, anonymous_info);
	if (*session_info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static struct auth_session_info *system_info = NULL;

NTSTATUS init_system_session_info(TALLOC_CTX *mem_ctx)
{
	if (system_info != NULL)
		return NT_STATUS_OK;

	return make_new_session_info_system(mem_ctx, &system_info);
}

NTSTATUS make_session_info_system(TALLOC_CTX *mem_ctx,
				struct auth_session_info **session_info)
{
	if (system_info == NULL) return NT_STATUS_UNSUCCESSFUL;
	*session_info = copy_session_info(mem_ctx, system_info);
	return (*session_info != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;
}

const struct auth_session_info *get_session_info_system(void)
{
    return system_info;
}

/***************************************************************************
 Purely internal function for make_server_info_info3
***************************************************************************/

static NTSTATUS check_account(TALLOC_CTX *mem_ctx, const char *domain,
			      const char *username,
			      const struct dom_sid *sid,
			      char **found_username,
			      struct passwd **pwd,
			      bool *username_was_mapped)
{
	char *orig_dom_user = NULL;
	char *dom_user = NULL;
	char *lower_username = NULL;
	char *real_username = NULL;
	struct passwd *passwd;

	lower_username = talloc_strdup(mem_ctx, username);
	if (!lower_username) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!strlower_m( lower_username )) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	orig_dom_user = talloc_asprintf(mem_ctx,
				"%s%c%s",
				domain,
				*lp_winbind_separator(),
				lower_username);
	if (!orig_dom_user) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Get the passwd struct.  Try to create the account if necessary. */

	*username_was_mapped = map_username(mem_ctx, orig_dom_user, &dom_user);
	if (!dom_user) {
		return NT_STATUS_NO_MEMORY;
	}

	passwd = smb_getpwnam(mem_ctx, dom_user, &real_username, false);
	if (!passwd && !*username_was_mapped) {
		struct dom_sid_buf buf;
		uid_t uid;
		bool ok;

		DBG_DEBUG("Failed to find authenticated user %s via "
			  "getpwnam(), fallback to sid_to_uid(%s).\n",
			  dom_user, dom_sid_str_buf(sid, &buf));

		ok = sid_to_uid(sid, &uid);
		if (!ok) {
			DBG_ERR("Failed to convert SID %s to a UID (dom_user[%s])\n",
				dom_sid_str_buf(sid, &buf), dom_user);
			return NT_STATUS_NO_SUCH_USER;
		}
		passwd = getpwuid_alloc(mem_ctx, uid);
		if (!passwd) {
			DBG_ERR("Failed to find local account with UID %lld for SID %s (dom_user[%s])\n",
				(long long)uid,
				dom_sid_str_buf(sid, &buf),
				dom_user);
			return NT_STATUS_NO_SUCH_USER;
		}
		real_username = talloc_strdup(mem_ctx, passwd->pw_name);
	}
	if (!passwd) {
		DEBUG(3, ("Failed to find authenticated user %s via "
			  "getpwnam(), denying access.\n", dom_user));
		return NT_STATUS_NO_SUCH_USER;
	}

	if (!real_username) {
		return NT_STATUS_NO_MEMORY;
	}

	*pwd = passwd;

	/* This is pointless -- there is no support for differing
	   unix and windows names.  Make sure to always store the 
	   one we actually looked up and succeeded. Have I mentioned
	   why I hate the 'winbind use default domain' parameter?   
	                                 --jerry              */

	*found_username = talloc_strdup( mem_ctx, real_username );

	return NT_STATUS_OK;
}

/****************************************************************************
 Wrapper to allow the getpwnam() call to strip the domain name and 
 try again in case a local UNIX user is already there.  Also run through 
 the username if we fallback to the username only.
 ****************************************************************************/

struct passwd *smb_getpwnam( TALLOC_CTX *mem_ctx, const char *domuser,
			     char **p_save_username, bool create )
{
	struct passwd *pw = NULL;
	char *p = NULL;
	const char *username = NULL;

	/* we only save a copy of the username it has been mangled 
	   by winbindd use default domain */
	*p_save_username = NULL;

	/* don't call map_username() here since it has to be done higher 
	   up the stack so we don't call it multiple times */

	username = talloc_strdup(mem_ctx, domuser);
	if (!username) {
		return NULL;
	}

	p = strchr_m( username, *lp_winbind_separator() );

	/* code for a DOMAIN\user string */

	if ( p ) {
		const char *domain = NULL;

		/* split the domain and username into 2 strings */
		*p = '\0';
		domain = username;
		p++;
		username = p;

		if (strequal(domain, get_global_sam_name())) {
			/*
			 * This typically don't happen
			 * as check_sam_Security()
			 * don't call make_server_info_info3()
			 * and thus check_account().
			 *
			 * But we better keep this.
			 */
			goto username_only;
		}

		pw = Get_Pwnam_alloc( mem_ctx, domuser );
		if (pw == NULL) {
			return NULL;
		}
		/* make sure we get the case of the username correct */
		/* work around 'winbind use default domain = yes' */

		if ( lp_winbind_use_default_domain() &&
		     !strchr_m( pw->pw_name, *lp_winbind_separator() ) ) {
			*p_save_username = talloc_asprintf(mem_ctx,
							"%s%c%s",
							domain,
							*lp_winbind_separator(),
							pw->pw_name);
			if (!*p_save_username) {
				TALLOC_FREE(pw);
				return NULL;
			}
		} else {
			*p_save_username = talloc_strdup(mem_ctx, pw->pw_name);
		}

		/* whew -- done! */
		return pw;

	}

	/* just lookup a plain username */
username_only:
	pw = Get_Pwnam_alloc(mem_ctx, username);

	/* Create local user if requested but only if winbindd
	   is not running.  We need to protect against cases
	   where winbindd is failing and then prematurely
	   creating users in /etc/passwd */

	if ( !pw && create && !winbind_ping() ) {
		/* Don't add a machine account. */
		if (username[strlen(username)-1] == '$')
			return NULL;

		_smb_create_user(NULL, username, NULL);
		pw = Get_Pwnam_alloc(mem_ctx, username);
	}

	/* one last check for a valid passwd struct */

	if (pw) {
		*p_save_username = talloc_strdup(mem_ctx, pw->pw_name);
	}
	return pw;
}

/***************************************************************************
 Make a server_info struct from the info3 returned by a domain logon 
***************************************************************************/

NTSTATUS make_server_info_info3(TALLOC_CTX *mem_ctx, 
				const char *sent_nt_username,
				const char *domain,
				struct auth_serversupplied_info **server_info,
				const struct netr_SamInfo3 *info3)
{
	NTSTATUS nt_status;
	char *found_username = NULL;
	const char *nt_domain;
	const char *nt_username;
	struct dom_sid user_sid;
	struct dom_sid group_sid;
	bool username_was_mapped;
	struct passwd *pwd;
	struct auth_serversupplied_info *result;
	struct dom_sid sid;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	/* 
	   Here is where we should check the list of
	   trusted domains, and verify that the SID 
	   matches.
	*/

	if (!sid_compose(&user_sid, info3->base.domain_sid, info3->base.rid)) {
		nt_status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!sid_compose(&group_sid, info3->base.domain_sid,
			 info3->base.primary_gid)) {
		nt_status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	nt_username = talloc_strdup(tmp_ctx, info3->base.account_name.string);
	if (!nt_username) {
		/* If the server didn't give us one, just use the one we sent
		 * them */
		nt_username = sent_nt_username;
	}

	nt_domain = talloc_strdup(mem_ctx, info3->base.logon_domain.string);
	if (!nt_domain) {
		/* If the server didn't give us one, just use the one we sent
		 * them */
		nt_domain = domain;
	}

	/* If getpwnam() fails try the add user script (2.2.x behavior).

	   We use the _unmapped_ username here in an attempt to provide
	   consistent username mapping behavior between kerberos and NTLM[SSP]
	   authentication in domain mode security.  I.E. Username mapping
	   should be applied to the fully qualified username
	   (e.g. DOMAIN\user) and not just the login name.  Yes this means we
	   called map_username() unnecessarily in make_user_info_map() but
	   that is how the current code is designed.  Making the change here
	   is the least disruptive place.  -- jerry */

	/* this call will try to create the user if necessary */

	sid_copy(&sid, info3->base.domain_sid);
	sid_append_rid(&sid, info3->base.rid);

	nt_status = check_account(tmp_ctx,
				  nt_domain,
				  nt_username,
				  &sid,
				  &found_username,
				  &pwd,
				  &username_was_mapped);

	if (!NT_STATUS_IS_OK(nt_status)) {
		/* Handle 'map to guest = Bad Uid */
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER) &&
		    (lp_security() == SEC_ADS || lp_security() == SEC_DOMAIN) &&
		    lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_UID) {
			DBG_NOTICE("Try to map %s to guest account",
				   nt_username);
			nt_status = make_server_info_guest(tmp_ctx, &result);
			if (NT_STATUS_IS_OK(nt_status)) {
				*server_info = talloc_move(mem_ctx, &result);
			}
		}
		goto out;
	} else if ((lp_security() == SEC_ADS || lp_security() == SEC_DOMAIN) &&
		   !is_myname(domain) && pwd->pw_uid < lp_min_domain_uid()) {
		/*
		 * !is_myname(domain) because when smbd starts tries to setup
		 * the guest user info, calling this function with nobody
		 * username. Nobody is usually uid 65535 but it can be changed
		 * to a regular user with 'guest account' parameter
		 */
		nt_status = NT_STATUS_INVALID_TOKEN;
		DBG_NOTICE("Username '%s%s%s' is invalid on this system, "
			   "it does not meet 'min domain uid' "
			   "restriction (%u < %u): %s\n",
			   nt_domain, lp_winbind_separator(), nt_username,
			   pwd->pw_uid, lp_min_domain_uid(),
			   nt_errstr(nt_status));
		goto out;
	}

	result = make_server_info(tmp_ctx);
	if (result == NULL) {
		DEBUG(4, ("make_server_info failed!\n"));
		nt_status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	result->unix_name = talloc_strdup(result, found_username);

	/* copy in the info3 */
	nt_status = copy_netr_SamInfo3(result,
				       info3,
				       &result->info3);
	if (!NT_STATUS_IS_OK(nt_status)) {
		goto out;
	}

	/* Fill in the unix info we found on the way */

	result->utok.uid = pwd->pw_uid;
	result->utok.gid = pwd->pw_gid;

	/* ensure we are never given NULL session keys */

	if (all_zero(info3->base.key.key, sizeof(info3->base.key.key))) {
		result->session_key = data_blob_null;
	} else {
		result->session_key = data_blob_talloc(
			result, info3->base.key.key,
			sizeof(info3->base.key.key));
	}

	if (all_zero(info3->base.LMSessKey.key,
		     sizeof(info3->base.LMSessKey.key))) {
		result->lm_session_key = data_blob_null;
	} else {
		result->lm_session_key = data_blob_talloc(
			result, info3->base.LMSessKey.key,
			sizeof(info3->base.LMSessKey.key));
	}

	result->nss_token |= username_was_mapped;

	result->guest = (info3->base.user_flags & NETLOGON_GUEST);

	*server_info = talloc_move(mem_ctx, &result);

	nt_status = NT_STATUS_OK;
out:
	talloc_free(tmp_ctx);

	return nt_status;
}

/*****************************************************************************
 Make a server_info struct from the wbcAuthUserInfo returned by a domain logon
******************************************************************************/

NTSTATUS make_server_info_wbcAuthUserInfo(TALLOC_CTX *mem_ctx,
					  const char *sent_nt_username,
					  const char *domain,
					  const struct wbcAuthUserInfo *info,
					  struct auth_serversupplied_info **server_info)
{
	struct netr_SamInfo3 info3;
	struct netr_SamInfo6 *info6;

	info6 = wbcAuthUserInfo_to_netr_SamInfo6(mem_ctx, info);
	if (!info6) {
		return NT_STATUS_NO_MEMORY;
	}

	info3.base = info6->base;
	info3.sidcount = info6->sidcount;
	info3.sids = info6->sids;

	return make_server_info_info3(mem_ctx,
				      sent_nt_username, domain,
				      server_info, &info3);
}

/**
 * Verify whether or not given domain is trusted.
 *
 * This should only be used on a DC.
 *
 * @param domain_name name of the domain to be verified
 * @return true if domain is one of the trusted ones or
 *         false if otherwise
 **/

bool is_trusted_domain(const char* dom_name)
{
	bool ret;

	if (!IS_DC) {
		return false;
	}

	if (dom_name == NULL || dom_name[0] == '\0') {
		return false;
	}

	if (strequal(dom_name, get_global_sam_name())) {
		return false;
	}

	become_root();
	DEBUG (5,("is_trusted_domain: Checking for domain trust with "
		  "[%s]\n", dom_name ));
	ret = pdb_get_trusteddom_pw(dom_name, NULL, NULL, NULL);
	unbecome_root();

	return ret;
}



/*
  on a logon error possibly map the error to success if "map to guest"
  is set approriately
*/
NTSTATUS do_map_to_guest_server_info(TALLOC_CTX *mem_ctx,
				     NTSTATUS status,
				     const char *user,
				     const char *domain,
				     struct auth_serversupplied_info **server_info)
{
	user = user ? user : "";
	domain = domain ? domain : "";

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
		if ((lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_USER) ||
		    (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_PASSWORD)) {
			DEBUG(3,("No such user %s [%s] - using guest account\n",
				 user, domain));
			return make_server_info_guest(mem_ctx, server_info);
		}
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		if (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_PASSWORD) {
			DEBUG(3,("Registered username %s for guest access\n",
				user));
			return make_server_info_guest(mem_ctx, server_info);
		}
	}

	return status;
}

/*
  Extract session key from a session info and return it in a blob
  if intent is KEY_USE_16BYTES, truncate it to 16 bytes

  See sections 3.2.4.15 and 3.3.4.2 of MS-SMB
  Also see https://lists.samba.org/archive/cifs-protocol/2012-January/002265.html for details

  Note that returned session_key is referencing the original key, it is supposed to be
  short-lived. If original session_info->session_key is gone, the reference will be broken.
*/
NTSTATUS session_extract_session_key(const struct auth_session_info *session_info, DATA_BLOB *session_key, enum session_key_use_intent intent)
{

	if (session_key == NULL || session_info == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (session_info->session_key.length == 0) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	*session_key = session_info->session_key;
	if (intent == KEY_USE_16BYTES) {
		session_key->length = MIN(session_info->session_key.length, 16);
	}
	return NT_STATUS_OK;
}
