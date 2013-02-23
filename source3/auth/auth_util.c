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
#include "../libcli/auth/libcli_auth.h"
#include "../lib/crypto/arcfour.h"
#include "rpc_client/init_lsa.h"
#include "../libcli/security/security.h"
#include "../lib/util/util_pw.h"
#include "lib/winbind_util.h"
#include "passdb.h"
#include "../librpc/gen_ndr/ndr_auth.h"
#include "../auth/auth_sam_reply.h"
#include "../librpc/gen_ndr/idmap.h"
#include "lib/param/loadparm.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/****************************************************************************
 Create a UNIX user on demand.
****************************************************************************/

static int _smb_create_user(const char *domain, const char *unix_username, const char *homedir)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *add_script;
	int ret;

	add_script = lp_adduser_script(ctx);
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
	ret = smbrun(add_script,NULL);
	flush_pwnam_cache();
	DEBUG(ret ? 0 : 3,
		("smb_create_user: Running the command `%s' gave %d\n",
		 add_script,ret));
	return ret;
}

/****************************************************************************
 Create an auth_usersupplied_data structure after appropriate mapping.
****************************************************************************/

NTSTATUS make_user_info_map(struct auth_usersupplied_info **user_info,
			    const char *smb_name,
			    const char *client_domain,
			    const char *workstation_name,
			    const struct tsocket_address *remote_address,
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

	domain = client_domain;

	/* If you connect to a Windows domain member using a bogus domain name,
	 * the Windows box will map the BOGUS\user to SAMNAME\user.  Thus, if
	 * the Windows box is a DC the name will become DOMAIN\user and be
	 * authenticated against AD, if the Windows box is a member server but
	 * not a DC the name will become WORKSTATION\user.  A standalone
	 * non-domain member box will also map to WORKSTATION\user.
	 * This also deals with the client passing in a "" domain */

	if (!is_trusted_domain(domain) &&
	    !strequal(domain, my_sam_name()) &&
	    !strequal(domain, get_global_sam_name()))
	{
		if (lp_map_untrusted_to_domain())
			domain = my_sam_name();
		else
			domain = get_global_sam_name();
		DEBUG(5, ("Mapped domain from [%s] to [%s] for user [%s] from "
			  "workstation [%s]\n",
			  client_domain, domain, smb_name, workstation_name));
	}

	/* We know that the given domain is trusted (and we are allowing them),
	 * it is our global SAM name, or for legacy behavior it is our
	 * primary domain name */

	result = make_user_info(user_info, smb_name, internal_username,
			      client_domain, domain, workstation_name,
			      remote_address, lm_pwd, nt_pwd,
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

bool make_user_info_netlogon_network(struct auth_usersupplied_info **user_info,
				     const char *smb_name, 
				     const char *client_domain, 
				     const char *workstation_name,
				     const struct tsocket_address *remote_address,
				     uint32 logon_parameters,
				     const uchar *lm_network_pwd,
				     int lm_pwd_len,
				     const uchar *nt_network_pwd,
				     int nt_pwd_len)
{
	bool ret;
	NTSTATUS status;
	DATA_BLOB lm_blob = data_blob(lm_network_pwd, lm_pwd_len);
	DATA_BLOB nt_blob = data_blob(nt_network_pwd, nt_pwd_len);

	status = make_user_info_map(user_info,
				    smb_name, client_domain, 
				    workstation_name,
				    remote_address,
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

bool make_user_info_netlogon_interactive(struct auth_usersupplied_info **user_info,
					 const char *smb_name, 
					 const char *client_domain, 
					 const char *workstation_name,
					 const struct tsocket_address *remote_address,
					 uint32 logon_parameters,
					 const uchar chal[8], 
					 const uchar lm_interactive_pwd[16], 
					 const uchar nt_interactive_pwd[16])
{
	struct samr_Password lm_pwd;
	struct samr_Password nt_pwd;
	unsigned char local_lm_response[24];
	unsigned char local_nt_response[24];

	if (lm_interactive_pwd)
		memcpy(lm_pwd.hash, lm_interactive_pwd, sizeof(lm_pwd.hash));

	if (nt_interactive_pwd)
		memcpy(nt_pwd.hash, nt_interactive_pwd, sizeof(nt_pwd.hash));

	if (lm_interactive_pwd)
		SMBOWFencrypt(lm_pwd.hash, chal,
			      local_lm_response);

	if (nt_interactive_pwd)
		SMBOWFencrypt(nt_pwd.hash, chal,
			      local_nt_response);

	{
		bool ret;
		NTSTATUS nt_status;
		DATA_BLOB local_lm_blob;
		DATA_BLOB local_nt_blob;

		if (lm_interactive_pwd) {
			local_lm_blob = data_blob(local_lm_response,
						  sizeof(local_lm_response));
		}

		if (nt_interactive_pwd) {
			local_nt_blob = data_blob(local_nt_response,
						  sizeof(local_nt_response));
		}

		nt_status = make_user_info_map(
			user_info, 
			smb_name, client_domain, workstation_name,
			remote_address,
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

bool make_user_info_for_reply(struct auth_usersupplied_info **user_info,
			      const char *smb_name, 
			      const char *client_domain,
			      const struct tsocket_address *remote_address,
			      const uint8 chal[8],
			      DATA_BLOB plaintext_password)
{

	DATA_BLOB local_lm_blob;
	DATA_BLOB local_nt_blob;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
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

	ret = make_user_info(
		user_info, smb_name, smb_name, client_domain, client_domain, 
		get_remote_machine_name(),
		remote_address,
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

NTSTATUS make_user_info_for_reply_enc(struct auth_usersupplied_info **user_info,
                                      const char *smb_name,
                                      const char *client_domain,
				      const struct tsocket_address *remote_address,
                                      DATA_BLOB lm_resp, DATA_BLOB nt_resp)
{
	return make_user_info(user_info, smb_name, smb_name, 
			      client_domain, client_domain, 
			      get_remote_machine_name(),
			      remote_address,
			      lm_resp.data && (lm_resp.length > 0) ? &lm_resp : NULL,
			      nt_resp.data && (nt_resp.length > 0) ? &nt_resp : NULL,
			      NULL, NULL, NULL,
			      AUTH_PASSWORD_RESPONSE);
}

/****************************************************************************
 Create a guest user_info blob, for anonymous authentication.
****************************************************************************/

bool make_user_info_guest(const struct tsocket_address *remote_address,
			  struct auth_usersupplied_info **user_info)
{
	NTSTATUS nt_status;

	nt_status = make_user_info(user_info, 
				   "","", 
				   "","", 
				   "", 
				   remote_address,
				   NULL, NULL, 
				   NULL, NULL, 
				   NULL,
				   AUTH_PASSWORD_RESPONSE);

	return NT_STATUS_IS_OK(nt_status) ? true : false;
}

static NTSTATUS log_nt_token(struct security_token *token)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *command;
	char *group_sidstr;
	size_t i;

	if ((lp_log_nt_token_command(frame) == NULL) ||
	    (strlen(lp_log_nt_token_command(frame)) == 0)) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	group_sidstr = talloc_strdup(frame, "");
	for (i=1; i<token->num_sids; i++) {
		group_sidstr = talloc_asprintf(
			frame, "%s %s", group_sidstr,
			sid_string_talloc(frame, &token->sids[i]));
	}

	command = talloc_string_sub(
		frame, lp_log_nt_token_command(frame),
		"%s", sid_string_talloc(frame, &token->sids[0]));
	command = talloc_string_sub(frame, command, "%t", group_sidstr);

	if (command == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(8, ("running command: [%s]\n", command));
	if (smbrun(command, NULL) != 0) {
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
	fstring tmp;

	/* Ensure we can't possible take a code path leading to a
	 * null defref. */
	if (!server_info) {
		return NT_STATUS_LOGON_FAILURE;
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
	alpha_strcpy(tmp, smb_username, ". _-$", sizeof(tmp));
	session_info->unix_info->sanitized_username =
				talloc_strdup(session_info->unix_info, tmp);

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

	if (server_info->security_token) {
		/* Just copy the token, it has already been finalised
		 * (nasty hack to support a cached guest/system session_info
		 */

		session_info->security_token = dup_nt_token(session_info, server_info->security_token);
		if (!session_info->security_token) {
			TALLOC_FREE(session_info);
			return NT_STATUS_NO_MEMORY;
		}

		session_info->unix_token->ngroups = server_info->utok.ngroups;
		if (server_info->utok.ngroups != 0) {
			session_info->unix_token->groups = (gid_t *)talloc_memdup(
				session_info->unix_token, server_info->utok.groups,
				sizeof(gid_t)*session_info->unix_token->ngroups);
		} else {
			session_info->unix_token->groups = NULL;
		}

		*session_info_out = session_info;
		return NT_STATUS_OK;
	}

	/*
	 * If winbind is not around, we can not make much use of the SIDs the
	 * domain controller provided us with. Likewise if the user name was
	 * mapped to some local unix user.
	 */

	if (((lp_server_role() == ROLE_DOMAIN_MEMBER) && !winbind_ping()) ||
	    (server_info->nss_token)) {
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
			DEBUG(10, ("Could not convert SID %s to gid, "
				   "ignoring it\n",
				   sid_string_dbg(&t->sids[i])));
			continue;
		}
		if (!add_gid_to_array_unique(session_info, ids[i].id,
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

	*session_info_out = session_info;
	return NT_STATUS_OK;
}

/***************************************************************************
 Make (and fill) a server_info struct from a 'struct passwd' by conversion
 to a struct samu
***************************************************************************/

NTSTATUS make_server_info_pw(struct auth_serversupplied_info **server_info,
                             char *unix_username,
			     struct passwd *pwd)
{
	NTSTATUS status;
	struct samu *sampass = NULL;
	char *qualified_name = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	struct dom_sid u_sid;
	enum lsa_SidType type;
	struct auth_serversupplied_info *result;

	/*
	 * The SID returned in server_info->sam_account is based
	 * on our SAM sid even though for a pure UNIX account this should
	 * not be the case as it doesn't really exist in the SAM db.
	 * This causes lookups on "[in]valid users" to fail as they
	 * will lookup this name as a "Unix User" SID to check against
	 * the user token. Fix this by adding the "Unix User"\unix_username
	 * SID to the sid array. The correct fix should probably be
	 * changing the server_info->sam_account user SID to be a
	 * S-1-22 Unix SID, but this might break old configs where
	 * plaintext passwords were used with no SAM backend.
	 */

	mem_ctx = talloc_init("make_server_info_pw_tmp");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	qualified_name = talloc_asprintf(mem_ctx, "%s\\%s",
					unix_users_domain_name(),
					unix_username );
	if (!qualified_name) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	if (!lookup_name(mem_ctx, qualified_name, LOOKUP_NAME_ALL,
						NULL, NULL,
						&u_sid, &type)) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	TALLOC_FREE(mem_ctx);

	if (type != SID_NAME_USER) {
		return NT_STATUS_NO_SUCH_USER;
	}

	if ( !(sampass = samu_new( NULL )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	status = samu_set_unix( sampass, pwd );
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* In pathological cases the above call can set the account
	 * name to the DOMAIN\username form. Reset the account name
	 * using unix_username */
	pdb_set_username(sampass, unix_username, PDB_SET);

	/* set the user sid to be the calculated u_sid */
	pdb_set_user_sid(sampass, &u_sid, PDB_SET);

	result = make_server_info(NULL);
	if (result == NULL) {
		TALLOC_FREE(sampass);
		return NT_STATUS_NO_MEMORY;
	}

	status = samu_to_SamInfo3(result, sampass, lp_netbios_name(),
				  &result->info3, &result->extra);
	TALLOC_FREE(sampass);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Failed to convert samu to info3: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(result);
		return status;
	}

	result->unix_name = talloc_strdup(result, unix_username);

	if (result->unix_name == NULL) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	result->utok.uid = pwd->pw_uid;
	result->utok.gid = pwd->pw_gid;

	*server_info = result;

	return NT_STATUS_OK;
}

static NTSTATUS get_system_info3(TALLOC_CTX *mem_ctx,
				 struct netr_SamInfo3 *info3)
{
	NTSTATUS status;
	struct dom_sid *system_sid;

	/* Set account name */
	init_lsa_String(&info3->base.account_name, "SYSTEM");

	/* Set domain name */
	init_lsa_StringLarge(&info3->base.logon_domain, "NT AUTHORITY");


	/* The SID set here will be overwirtten anyway, but try and make it SID_NT_SYSTEM anyway */
	/* Domain sid is NT_AUTHORITY */
	
	system_sid = dom_sid_parse_talloc(mem_ctx, SID_NT_SYSTEM);
	if (system_sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	
	status = dom_sid_split_rid(mem_ctx, system_sid, &info3->base.domain_sid, 
				   &info3->base.rid);
	TALLOC_FREE(system_sid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	/* Primary gid is the same */
	info3->base.primary_gid = info3->base.rid;

	return NT_STATUS_OK;
}

static NTSTATUS get_guest_info3(TALLOC_CTX *mem_ctx,
				struct netr_SamInfo3 *info3)
{
	const char *guest_account = lp_guestaccount();
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

static NTSTATUS make_new_session_info_guest(struct auth_session_info **session_info, struct auth_serversupplied_info **server_info)
{
	static const char zeros[16] = {0};
	const char *guest_account = lp_guestaccount();
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
					server_info,
					&info3);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("make_server_info_info3 failed with %s\n",
			  nt_errstr(status)));
		goto done;
	}

	(*server_info)->guest = true;

	/* This should not be done here (we should produce a server
	 * info, and later construct a session info from it), but for
	 * now this does not change the previous behavior */
	status = create_local_token(tmp_ctx, *server_info, NULL,
				    (*server_info)->info3->base.account_name.string,
				    session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("create_local_token failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}
	talloc_steal(NULL, *session_info);
	talloc_steal(NULL, *server_info);

	/* annoying, but the Guest really does have a session key, and it is
	   all zeros! */
	(*session_info)->session_key = data_blob(zeros, sizeof(zeros));

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
	NTSTATUS status;
	struct auth_serversupplied_info *server_info;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	server_info = make_server_info(tmp_ctx);
	if (!server_info) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(0, ("failed making server_info\n"));
		goto done;
	}

	server_info->info3 = talloc_zero(server_info, struct netr_SamInfo3);
	if (!server_info->info3) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(0, ("talloc failed setting info3\n"));
		goto done;
	}

	status = get_system_info3(server_info, server_info->info3);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed creating system info3 with %s\n",
			  nt_errstr(status)));
		goto done;
	}

	server_info->utok.uid = sec_initial_uid();
	server_info->utok.gid = sec_initial_gid();
	server_info->unix_name = talloc_asprintf(server_info,
						 "NT AUTHORITY%cSYSTEM",
						 *lp_winbind_separator());

	if (!server_info->unix_name) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(0, ("talloc_asprintf failed setting unix_name\n"));
		goto done;
	}

	server_info->security_token = talloc_zero(server_info, struct security_token);
	if (!server_info->security_token) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(0, ("talloc failed setting security token\n"));
		goto done;
	}

	status = add_sid_to_array_unique(server_info->security_token->sids,
					 &global_sid_System,
					 &server_info->security_token->sids,
					 &server_info->security_token->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* SYSTEM has all privilages */
	server_info->security_token->privilege_mask = ~0;

	/* Now turn the server_info into a session_info with the full token etc */
	status = create_local_token(mem_ctx, server_info, NULL, "SYSTEM", session_info);
	talloc_free(server_info);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("create_local_token failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	talloc_steal(mem_ctx, *session_info);

done:
	TALLOC_FREE(tmp_ctx);
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

	pwd = Get_Pwnam_alloc(talloc_tos(), username);
	if (pwd == NULL) {
		return NT_STATUS_NO_SUCH_USER;
	}

	status = make_server_info_pw(&result, pwd->pw_name, pwd);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	result->nss_token = true;
	result->guest = is_guest;

	/* Now turn the server_info into a session_info with the full token etc */
	status = create_local_token(mem_ctx, result, NULL, pwd->pw_name, session_info);
	TALLOC_FREE(result);
	TALLOC_FREE(pwd);

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

	dst = make_server_info(mem_ctx);
	if (dst == NULL) {
		return NULL;
	}

	/* This element must be provided to convert back to an auth_serversupplied_info */
	SMB_ASSERT(src->unix_info);

	dst->guest = true;
	dst->system = false;

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

	dst->security_token = dup_nt_token(dst, src->security_token);
	if (!dst->security_token) {
		TALLOC_FREE(dst);
		return NULL;
	}

	dst->session_key = data_blob_talloc( dst, src->session_key.data,
						src->session_key.length);

	/* This is OK because this functions is only used for the
	 * GUEST account, which has all-zero keys for both values */
	dst->lm_session_key = data_blob_talloc(dst, src->session_key.data,
						src->session_key.length);

	dst->info3 = copy_netr_SamInfo3(dst, server_info->info3);
	if (!dst->info3) {
		TALLOC_FREE(dst);
		return NULL;
	}

	dst->unix_name = talloc_strdup(dst, src->unix_info->unix_name);
	if (!dst->unix_name) {
		TALLOC_FREE(dst);
		return NULL;
	}

	return dst;
}

struct auth_session_info *copy_session_info(TALLOC_CTX *mem_ctx,
					     const struct auth_session_info *src)
{
	struct auth_session_info *dst;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_blob(
		&blob, talloc_tos(), src,
		(ndr_push_flags_fn_t)ndr_push_auth_session_info);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("copy_session_info(): ndr_push_auth_session_info failed: "
			   "%s\n", ndr_errstr(ndr_err)));
		return NULL;
	}

	dst = talloc(mem_ctx, struct auth_session_info);
	if (dst == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(blob.data);
		return NULL;
	}

	ndr_err = ndr_pull_struct_blob(
		&blob, dst, dst,
		(ndr_pull_flags_fn_t)ndr_pull_auth_session_info);
	TALLOC_FREE(blob.data);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("copy_session_info(): ndr_pull_auth_session_info failed: "
			   "%s\n", ndr_errstr(ndr_err)));
		TALLOC_FREE(dst);
		return NULL;
	}

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

static struct auth_serversupplied_info *guest_server_info = NULL;

bool init_guest_info(void)
{
	if (guest_info != NULL)
		return true;

	return NT_STATUS_IS_OK(make_new_session_info_guest(&guest_info, &guest_server_info));
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

static struct auth_session_info *system_info = NULL;

NTSTATUS init_system_session_info(void)
{
	if (system_info != NULL)
		return NT_STATUS_OK;

	return make_new_session_info_system(NULL, &system_info);
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
			      const char *username, char **found_username,
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

	passwd = smb_getpwnam(mem_ctx, dom_user, &real_username, true );
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
	char *username = NULL;

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
		pw = Get_Pwnam_alloc( mem_ctx, domuser );
		if ( pw ) {
			/* make sure we get the case of the username correct */
			/* work around 'winbind use default domain = yes' */

			if ( lp_winbind_use_default_domain() &&
			     !strchr_m( pw->pw_name, *lp_winbind_separator() ) ) {
				char *domain;

				/* split the domain and username into 2 strings */
				*p = '\0';
				domain = username;

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

		/* setup for lookup of just the username */
		/* remember that p and username are overlapping memory */

		p++;
		username = talloc_strdup(mem_ctx, p);
		if (!username) {
			return NULL;
		}
	}

	/* just lookup a plain username */

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
				struct netr_SamInfo3 *info3)
{
	static const char zeros[16] = {0, };

	NTSTATUS nt_status = NT_STATUS_OK;
	char *found_username = NULL;
	const char *nt_domain;
	const char *nt_username;
	struct dom_sid user_sid;
	struct dom_sid group_sid;
	bool username_was_mapped;
	struct passwd *pwd;
	struct auth_serversupplied_info *result;

	/* 
	   Here is where we should check the list of
	   trusted domains, and verify that the SID 
	   matches.
	*/

	if (!sid_compose(&user_sid, info3->base.domain_sid, info3->base.rid)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!sid_compose(&group_sid, info3->base.domain_sid,
			 info3->base.primary_gid)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	nt_username = talloc_strdup(mem_ctx, info3->base.account_name.string);
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

	nt_status = check_account(mem_ctx, nt_domain, sent_nt_username,
				     &found_username, &pwd,
				     &username_was_mapped);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	result = make_server_info(NULL);
	if (result == NULL) {
		DEBUG(4, ("make_server_info failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	result->unix_name = talloc_strdup(result, found_username);

	/* copy in the info3 */
	result->info3 = copy_netr_SamInfo3(result, info3);
	if (result->info3 == NULL) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	/* Fill in the unix info we found on the way */

	result->utok.uid = pwd->pw_uid;
	result->utok.gid = pwd->pw_gid;

	/* ensure we are never given NULL session keys */

	if (memcmp(info3->base.key.key, zeros, sizeof(zeros)) == 0) {
		result->session_key = data_blob_null;
	} else {
		result->session_key = data_blob_talloc(
			result, info3->base.key.key,
			sizeof(info3->base.key.key));
	}

	if (memcmp(info3->base.LMSessKey.key, zeros, 8) == 0) {
		result->lm_session_key = data_blob_null;
	} else {
		result->lm_session_key = data_blob_talloc(
			result, info3->base.LMSessKey.key,
			sizeof(info3->base.LMSessKey.key));
	}

	result->nss_token |= username_was_mapped;

	result->guest = (info3->base.user_flags & NETLOGON_GUEST);

	*server_info = result;

	return NT_STATUS_OK;
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
	struct netr_SamInfo3 *info3;

	info3 = wbcAuthUserInfo_to_netr_SamInfo3(mem_ctx, info);
	if (!info3) {
		return NT_STATUS_NO_MEMORY;
	}

	return make_server_info_info3(mem_ctx,
				      sent_nt_username, domain,
				      server_info, info3);
}

/**
 * Verify whether or not given domain is trusted.
 *
 * @param domain_name name of the domain to be verified
 * @return true if domain is one of the trusted ones or
 *         false if otherwise
 **/

bool is_trusted_domain(const char* dom_name)
{
	struct dom_sid trustdom_sid;
	bool ret;

	/* no trusted domains for a standalone server */

	if ( lp_server_role() == ROLE_STANDALONE )
		return false;

	if (dom_name == NULL || dom_name[0] == '\0') {
		return false;
	}

	if (strequal(dom_name, get_global_sam_name())) {
		return false;
	}

	/* if we are a DC, then check for a direct trust relationships */

	if ( IS_DC ) {
		become_root();
		DEBUG (5,("is_trusted_domain: Checking for domain trust with "
			  "[%s]\n", dom_name ));
		ret = pdb_get_trusteddom_pw(dom_name, NULL, NULL, NULL);
		unbecome_root();
		if (ret)
			return true;
	}
	else {
		wbcErr result;

		/* If winbind is around, ask it */

		result = wb_is_trusted_domain(dom_name);

		if (result == WBC_ERR_SUCCESS) {
			return true;
		}

		if (result == WBC_ERR_DOMAIN_NOT_FOUND) {
			/* winbind could not find the domain */
			return false;
		}

		/* The only other possible result is that winbind is not up
		   and running. We need to update the trustdom_cache
		   ourselves */

		update_trustdom_cache();
	}

	/* now the trustdom cache should be available a DC could still
	 * have a transitive trust so fall back to the cache of trusted
	 * domains (like a domain member would use  */

	if ( trustdom_cache_fetch(dom_name, &trustdom_sid) ) {
		return true;
	}

	return false;
}



/*
  on a logon error possibly map the error to success if "map to guest"
  is set approriately
*/
NTSTATUS do_map_to_guest_server_info(NTSTATUS status,
				     struct auth_serversupplied_info **server_info,
				     const char *user, const char *domain)
{
	user = user ? user : "";
	domain = domain ? domain : "";

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
		if ((lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_USER) ||
		    (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_PASSWORD)) {
			DEBUG(3,("No such user %s [%s] - using guest account\n",
				 user, domain));
			return make_server_info_guest(NULL, server_info);
		}
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		if (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_PASSWORD) {
			DEBUG(3,("Registered username %s for guest access\n",
				user));
			return make_server_info_guest(NULL, server_info);
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
