/* 
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett 2001
   Copyright (C) Jeremy Allison 2000-2001
   Copyright (C) Rafal Szczesniak 2002
   Copyright (C) Stefan Metzmacher 2005

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
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "libcli/auth/libcli_auth.h"
#include "dsdb/samdb/samdb.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"

/* this default function can be used by mostly all backends
 * which don't want to set a challenge
 */
NTSTATUS auth_get_challenge_not_implemented(struct auth_method_context *ctx, TALLOC_CTX *mem_ctx, DATA_BLOB *challenge)
{
	/* we don't want to set a challenge */
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************************
 Create an auth_usersupplied_data structure after appropriate mapping.
****************************************************************************/

NTSTATUS map_user_info(TALLOC_CTX *mem_ctx,
		       const struct auth_usersupplied_info *user_info,
		       struct auth_usersupplied_info **user_info_mapped)
{
	const char *domain;
	char *account_name;
	char *d;
	DEBUG(5,("map_user_info: Mapping user [%s]\\[%s] from workstation [%s]\n",
		user_info->client.domain_name, user_info->client.account_name, user_info->workstation_name));

	account_name = talloc_strdup(mem_ctx, user_info->client.account_name);
	if (!account_name) {
		return NT_STATUS_NO_MEMORY;
	}
	
	/* don't allow "" as a domain, fixes a Win9X bug 
	   where it doens't supply a domain for logon script
	   'net use' commands.                                 */

	/* Split user@realm names into user and realm components.  This is TODO to fix with proper userprincipalname support */
	if (user_info->client.domain_name && *user_info->client.domain_name) {
		domain = user_info->client.domain_name;
	} else if (strchr_m(user_info->client.account_name, '@')) {
		d = strchr_m(account_name, '@');
		if (!d) {
			return NT_STATUS_INTERNAL_ERROR;
		}
		d[0] = '\0';
		d++;
		domain = d;
	} else {
		domain = lp_workgroup();
	}

	*user_info_mapped = talloc(mem_ctx, struct auth_usersupplied_info);
	if (!*user_info_mapped) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_reference(*user_info_mapped, user_info);
	**user_info_mapped = *user_info;
	(*user_info_mapped)->mapped_state = True;
	(*user_info_mapped)->mapped.domain_name = talloc_strdup(*user_info_mapped, domain);
	(*user_info_mapped)->mapped.account_name = talloc_strdup(*user_info_mapped, account_name);
	talloc_free(account_name);
	if (!(*user_info_mapped)->mapped.domain_name 
	    || !(*user_info_mapped)->mapped.account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Create an auth_usersupplied_data structure after appropriate mapping.
****************************************************************************/

 NTSTATUS encrypt_user_info(TALLOC_CTX *mem_ctx, struct auth_context *auth_context, 
			   enum auth_password_state to_state,
			   const struct auth_usersupplied_info *user_info_in,
			   const struct auth_usersupplied_info **user_info_encrypted)
{
	NTSTATUS nt_status;
	struct auth_usersupplied_info *user_info_temp;
	switch (to_state) {
	case AUTH_PASSWORD_RESPONSE:
		switch (user_info_in->password_state) {
		case AUTH_PASSWORD_PLAIN:
		{
			const struct auth_usersupplied_info *user_info_temp2;
			nt_status = encrypt_user_info(mem_ctx, auth_context, 
						      AUTH_PASSWORD_HASH, 
						      user_info_in, &user_info_temp2);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return nt_status;
			}
			user_info_in = user_info_temp2;
			/* fall through */
		}
		case AUTH_PASSWORD_HASH:
		{
			const uint8_t *challenge;
			DATA_BLOB chall_blob;
			user_info_temp = talloc(mem_ctx, struct auth_usersupplied_info);
			if (!user_info_temp) {
				return NT_STATUS_NO_MEMORY;
			}
			talloc_reference(user_info_temp, user_info_in);
			*user_info_temp = *user_info_in;
			user_info_temp->mapped_state = to_state;
			
			nt_status = auth_get_challenge(auth_context, &challenge);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return nt_status;
			}
			
			chall_blob = data_blob_talloc(mem_ctx, challenge, 8);
			if (lp_client_ntlmv2_auth()) {
				DATA_BLOB names_blob = NTLMv2_generate_names_blob(mem_ctx, lp_netbios_name(), lp_workgroup());
				DATA_BLOB lmv2_response, ntlmv2_response, lmv2_session_key, ntlmv2_session_key;
				
				if (!SMBNTLMv2encrypt_hash(user_info_temp,
							   user_info_in->client.account_name, 
							   user_info_in->client.domain_name, 
							   user_info_in->password.hash.nt->hash, &chall_blob,
							   &names_blob,
							   &lmv2_response, &ntlmv2_response, 
							   &lmv2_session_key, &ntlmv2_session_key)) {
					data_blob_free(&names_blob);
					return NT_STATUS_NO_MEMORY;
				}
				data_blob_free(&names_blob);
				user_info_temp->password.response.lanman = lmv2_response;
				user_info_temp->password.response.nt = ntlmv2_response;
				
				data_blob_free(&lmv2_session_key);
				data_blob_free(&ntlmv2_session_key);
			} else {
				DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, 24);
				SMBOWFencrypt(user_info_in->password.hash.nt->hash, challenge, blob.data);

				user_info_temp->password.response.nt = blob;
				if (lp_client_lanman_auth() && user_info_in->password.hash.lanman) {
					DATA_BLOB lm_blob = data_blob_talloc(mem_ctx, NULL, 24);
					SMBOWFencrypt(user_info_in->password.hash.lanman->hash, challenge, blob.data);
					user_info_temp->password.response.lanman = lm_blob;
				} else {
					/* if not sending the LM password, send the NT password twice */
					user_info_temp->password.response.lanman = user_info_temp->password.response.nt;
				}
			}

			user_info_in = user_info_temp;
			/* fall through */
		}
		case AUTH_PASSWORD_RESPONSE:
			*user_info_encrypted = user_info_in;
		}
		break;
	case AUTH_PASSWORD_HASH:
	{	
		switch (user_info_in->password_state) {
		case AUTH_PASSWORD_PLAIN:
		{
			struct samr_Password lanman;
			struct samr_Password nt;
			
			user_info_temp = talloc(mem_ctx, struct auth_usersupplied_info);
			if (!user_info_temp) {
				return NT_STATUS_NO_MEMORY;
			}
			talloc_reference(user_info_temp, user_info_in);
			*user_info_temp = *user_info_in;
			user_info_temp->mapped_state = to_state;
			
			if (E_deshash(user_info_in->password.plaintext, lanman.hash)) {
				user_info_temp->password.hash.lanman = talloc(user_info_temp,
									      struct samr_Password);
				*user_info_temp->password.hash.lanman = lanman;
			} else {
				user_info_temp->password.hash.lanman = NULL;
			}
			
			E_md4hash(user_info_in->password.plaintext, nt.hash);
			user_info_temp->password.hash.nt = talloc(user_info_temp,
								   struct samr_Password);
			*user_info_temp->password.hash.nt = nt;
			
			user_info_in = user_info_temp;
			/* fall through */
		}
		case AUTH_PASSWORD_HASH:
			*user_info_encrypted = user_info_in;
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
			break;
		}
		break;
	}
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

/***************************************************************************
 Make a server_info struct from the info3 returned by a domain logon 
***************************************************************************/
NTSTATUS make_server_info_netlogon_validation(TALLOC_CTX *mem_ctx,
					      const char *account_name,
					      uint16_t validation_level,
					      union netr_Validation *validation,
					      struct auth_serversupplied_info **_server_info)
{
	struct auth_serversupplied_info *server_info;
	struct netr_SamBaseInfo *base = NULL;
	int i;

	switch (validation_level) {
	case 2:
		if (!validation || !validation->sam2) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		base = &validation->sam2->base;
		break;
	case 3:
		if (!validation || !validation->sam3) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		base = &validation->sam3->base;
		break;
	case 6:
		if (!validation || !validation->sam6) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		base = &validation->sam6->base;
		break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	server_info = talloc(mem_ctx, struct auth_serversupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(server_info);

	/*
	   Here is where we should check the list of
	   trusted domains, and verify that the SID 
	   matches.
	*/
	server_info->account_sid = dom_sid_add_rid(server_info, base->domain_sid, base->rid);
	NT_STATUS_HAVE_NO_MEMORY(server_info->account_sid);


	server_info->primary_group_sid = dom_sid_add_rid(server_info, base->domain_sid, base->primary_gid);
	NT_STATUS_HAVE_NO_MEMORY(server_info->primary_group_sid);

	server_info->n_domain_groups = base->groups.count;
	if (base->groups.count) {
		server_info->domain_groups = talloc_array(server_info, struct dom_sid*, base->groups.count);
		NT_STATUS_HAVE_NO_MEMORY(server_info->domain_groups);
	} else {
		server_info->domain_groups = NULL;
	}

	for (i = 0; i < base->groups.count; i++) {
		server_info->domain_groups[i] = dom_sid_add_rid(server_info, base->domain_sid, base->groups.rids[i].rid);
		NT_STATUS_HAVE_NO_MEMORY(server_info->domain_groups[i]);
	}

	/* Copy 'other' sids.  We need to do sid filtering here to
 	   prevent possible elevation of privileges.  See:

           http://www.microsoft.com/windows2000/techinfo/administration/security/sidfilter.asp
         */

	if (validation_level == 3) {
		struct dom_sid **dgrps = server_info->domain_groups;
		size_t sidcount = server_info->n_domain_groups + validation->sam3->sidcount;
		size_t n_dgrps = server_info->n_domain_groups;

		if (validation->sam3->sidcount > 0) {
			dgrps = talloc_realloc(server_info, dgrps, struct dom_sid*, sidcount);
			NT_STATUS_HAVE_NO_MEMORY(dgrps);

			for (i = 0; i < validation->sam3->sidcount; i++) {
				dgrps[n_dgrps + i] = talloc_reference(dgrps, validation->sam3->sids[i].sid);
			}
		}

		server_info->n_domain_groups = sidcount;
		server_info->domain_groups = dgrps;

		/* Where are the 'global' sids?... */
	}

	if (base->account_name.string) {
		server_info->account_name = talloc_reference(server_info, base->account_name.string);
	} else {
		server_info->account_name = talloc_strdup(server_info, account_name);
		NT_STATUS_HAVE_NO_MEMORY(server_info->account_name);
	}

	server_info->domain_name = talloc_reference(server_info, base->domain.string);
	server_info->full_name = talloc_reference(server_info, base->full_name.string);
	server_info->logon_script = talloc_reference(server_info, base->logon_script.string);
	server_info->profile_path = talloc_reference(server_info, base->profile_path.string);
	server_info->home_directory = talloc_reference(server_info, base->home_directory.string);
	server_info->home_drive = talloc_reference(server_info, base->home_drive.string);
	server_info->logon_server = talloc_reference(server_info, base->logon_server.string);
	server_info->last_logon = base->last_logon;
	server_info->last_logoff = base->last_logoff;
	server_info->acct_expiry = base->acct_expiry;
	server_info->last_password_change = base->last_password_change;
	server_info->allow_password_change = base->allow_password_change;
	server_info->force_password_change = base->force_password_change;
	server_info->logon_count = base->logon_count;
	server_info->bad_password_count = base->bad_password_count;
	server_info->acct_flags = base->acct_flags;

	server_info->authenticated = True;

	/* ensure we are never given NULL session keys */

	if (all_zero(base->key.key, sizeof(base->key.key))) {
		server_info->user_session_key = data_blob(NULL, 0);
	} else {
		server_info->user_session_key = data_blob_talloc(server_info, base->key.key, sizeof(base->key.key));
		NT_STATUS_HAVE_NO_MEMORY(server_info->user_session_key.data);
	}

	if (all_zero(base->LMSessKey.key, sizeof(base->LMSessKey.key))) {
		server_info->lm_session_key = data_blob(NULL, 0);
	} else {
		server_info->lm_session_key = data_blob_talloc(server_info, base->LMSessKey.key, sizeof(base->LMSessKey.key));
		NT_STATUS_HAVE_NO_MEMORY(server_info->lm_session_key.data);
	}

	*_server_info = server_info;
	return NT_STATUS_OK;
}


NTSTATUS auth_anonymous_server_info(TALLOC_CTX *mem_ctx, struct auth_serversupplied_info **_server_info) 
{
	struct auth_serversupplied_info *server_info;
	server_info = talloc(mem_ctx, struct auth_serversupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(server_info);

	server_info->account_sid = dom_sid_parse_talloc(server_info, SID_NT_ANONYMOUS);
	NT_STATUS_HAVE_NO_MEMORY(server_info->account_sid);

	/* is this correct? */
	server_info->primary_group_sid = dom_sid_parse_talloc(server_info, SID_BUILTIN_GUESTS);
	NT_STATUS_HAVE_NO_MEMORY(server_info->primary_group_sid);

	server_info->n_domain_groups = 0;
	server_info->domain_groups = NULL;

	/* annoying, but the Anonymous really does have a session key, 
	   and it is all zeros! */
	server_info->user_session_key = data_blob_talloc(server_info, NULL, 16);
	NT_STATUS_HAVE_NO_MEMORY(server_info->user_session_key.data);

	server_info->lm_session_key = data_blob_talloc(server_info, NULL, 16);
	NT_STATUS_HAVE_NO_MEMORY(server_info->lm_session_key.data);

	data_blob_clear(&server_info->user_session_key);
	data_blob_clear(&server_info->lm_session_key);

	server_info->account_name = talloc_strdup(server_info, "ANONYMOUS LOGON");
	NT_STATUS_HAVE_NO_MEMORY(server_info->account_name);

	server_info->domain_name = talloc_strdup(server_info, "NT AUTHORITY");
	NT_STATUS_HAVE_NO_MEMORY(server_info->domain_name);

	server_info->full_name = talloc_strdup(server_info, "Anonymous Logon");
	NT_STATUS_HAVE_NO_MEMORY(server_info->full_name);

	server_info->logon_script = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->logon_script);

	server_info->profile_path = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->profile_path);

	server_info->home_directory = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_directory);

	server_info->home_drive = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_drive);

	server_info->logon_server = talloc_strdup(server_info, lp_netbios_name());
	NT_STATUS_HAVE_NO_MEMORY(server_info->logon_server);

	server_info->last_logon = 0;
	server_info->last_logoff = 0;
	server_info->acct_expiry = 0;
	server_info->last_password_change = 0;
	server_info->allow_password_change = 0;
	server_info->force_password_change = 0;

	server_info->logon_count = 0;
	server_info->bad_password_count = 0;

	server_info->acct_flags = ACB_NORMAL;

	server_info->authenticated = False;

	*_server_info = server_info;

	return NT_STATUS_OK;
}

NTSTATUS auth_system_server_info(TALLOC_CTX *mem_ctx, struct auth_serversupplied_info **_server_info) 
{
	struct auth_serversupplied_info *server_info;
	server_info = talloc(mem_ctx, struct auth_serversupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(server_info);

	server_info->account_sid = dom_sid_parse_talloc(server_info, SID_NT_SYSTEM);
	NT_STATUS_HAVE_NO_MEMORY(server_info->account_sid);

	/* is this correct? */
	server_info->primary_group_sid = dom_sid_parse_talloc(server_info, SID_BUILTIN_ADMINISTRATORS);
	NT_STATUS_HAVE_NO_MEMORY(server_info->primary_group_sid);

	server_info->n_domain_groups = 0;
	server_info->domain_groups = NULL;

	/* annoying, but the Anonymous really does have a session key, 
	   and it is all zeros! */
	server_info->user_session_key = data_blob_talloc(server_info, NULL, 16);
	NT_STATUS_HAVE_NO_MEMORY(server_info->user_session_key.data);

	server_info->lm_session_key = data_blob_talloc(server_info, NULL, 16);
	NT_STATUS_HAVE_NO_MEMORY(server_info->lm_session_key.data);

	data_blob_clear(&server_info->user_session_key);
	data_blob_clear(&server_info->lm_session_key);

	server_info->account_name = talloc_strdup(server_info, "SYSTEM");
	NT_STATUS_HAVE_NO_MEMORY(server_info->account_name);

	server_info->domain_name = talloc_strdup(server_info, "NT AUTHORITY");
	NT_STATUS_HAVE_NO_MEMORY(server_info->domain_name);

	server_info->full_name = talloc_strdup(server_info, "System");
	NT_STATUS_HAVE_NO_MEMORY(server_info->full_name);

	server_info->logon_script = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->logon_script);

	server_info->profile_path = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->profile_path);

	server_info->home_directory = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_directory);

	server_info->home_drive = talloc_strdup(server_info, "");
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_drive);

	server_info->logon_server = talloc_strdup(server_info, lp_netbios_name());
	NT_STATUS_HAVE_NO_MEMORY(server_info->logon_server);

	server_info->last_logon = 0;
	server_info->last_logoff = 0;
	server_info->acct_expiry = 0;
	server_info->last_password_change = 0;
	server_info->allow_password_change = 0;
	server_info->force_password_change = 0;

	server_info->logon_count = 0;
	server_info->bad_password_count = 0;

	server_info->acct_flags = ACB_NORMAL;

	server_info->authenticated = True;

	*_server_info = server_info;

	return NT_STATUS_OK;
}

NTSTATUS auth_generate_session_info(TALLOC_CTX *mem_ctx, 
				    struct auth_serversupplied_info *server_info, 
				    struct auth_session_info **_session_info) 
{
	struct auth_session_info *session_info;
	NTSTATUS nt_status;

	session_info = talloc(mem_ctx, struct auth_session_info);
	NT_STATUS_HAVE_NO_MEMORY(session_info);

	session_info->server_info = talloc_reference(session_info, server_info);

	/* unless set otherwise, the session key is the user session
	 * key from the auth subsystem */ 
	session_info->session_key = server_info->user_session_key;

	nt_status = security_token_create(session_info,
					  server_info->account_sid,
					  server_info->primary_group_sid,
					  server_info->n_domain_groups,
					  server_info->domain_groups,
					  server_info->authenticated,
					  &session_info->security_token);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	session_info->credentials = NULL;

	*_session_info = session_info;
	return NT_STATUS_OK;
}

NTSTATUS auth_anonymous_session_info(TALLOC_CTX *parent_ctx, 
				     struct auth_session_info **_session_info) 
{
	NTSTATUS nt_status;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_session_info *session_info = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	
	nt_status = auth_anonymous_server_info(mem_ctx,
					       &server_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return nt_status;
	}

	/* references the server_info into the session_info */
	nt_status = auth_generate_session_info(parent_ctx, server_info, &session_info);
	talloc_free(mem_ctx);

	NT_STATUS_NOT_OK_RETURN(nt_status);

	session_info->credentials = cli_credentials_init(session_info);
	if (!session_info->credentials) {
		return NT_STATUS_NO_MEMORY;
	}

	cli_credentials_set_conf(session_info->credentials);
	cli_credentials_set_anonymous(session_info->credentials);
	
	*_session_info = session_info;

	return NT_STATUS_OK;
}

struct auth_session_info *anonymous_session(TALLOC_CTX *mem_ctx) 
{
	NTSTATUS nt_status;
	struct auth_session_info *session_info = NULL;
	nt_status = auth_anonymous_session_info(mem_ctx, &session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return NULL;
	}
	return session_info;
}

NTSTATUS auth_system_session_info(TALLOC_CTX *parent_ctx, 
				  struct auth_session_info **_session_info) 
{
	NTSTATUS nt_status;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_session_info *session_info = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	
	nt_status = auth_system_server_info(mem_ctx,
					    &server_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return nt_status;
	}

	/* references the server_info into the session_info */
	nt_status = auth_generate_session_info(parent_ctx, server_info, &session_info);
	talloc_free(mem_ctx);

	NT_STATUS_NOT_OK_RETURN(nt_status);

	session_info->credentials = cli_credentials_init(session_info);
	if (!session_info->credentials) {
		return NT_STATUS_NO_MEMORY;
	}

	cli_credentials_set_conf(session_info->credentials);

	if (lp_parm_bool(-1,"system","anonymous", False)) {
		cli_credentials_set_anonymous(session_info->credentials);
	} else {
		cli_credentials_set_machine_account_pending(session_info->credentials);
	}
	*_session_info = session_info;

	return NT_STATUS_OK;
}

_PUBLIC_ struct auth_session_info *system_session(TALLOC_CTX *mem_ctx) 
{
	NTSTATUS nt_status;
	struct auth_session_info *session_info = NULL;
	nt_status = auth_system_session_info(mem_ctx, &session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return NULL;
	}
	return session_info;
}

/****************************************************************************
 prints a struct auth_session_info security token to debug output.
****************************************************************************/
void auth_session_info_debug(int dbg_lev, 
			     const struct auth_session_info *session_info)
{
	if (!session_info) {
		DEBUG(dbg_lev, ("Session Info: (NULL)\n"));
		return;	
	}

	security_token_debug(dbg_lev, session_info->security_token);
}

/**
 * Squash an NT_STATUS in line with security requirements.
 * In an attempt to avoid giving the whole game away when users
 * are authenticating, NT replaces both NT_STATUS_NO_SUCH_USER and 
 * NT_STATUS_WRONG_PASSWORD with NT_STATUS_LOGON_FAILURE in certain situations 
 * (session setups in particular).
 *
 * @param nt_status NTSTATUS input for squashing.
 * @return the 'squashed' nt_status
 **/
NTSTATUS auth_nt_status_squash(NTSTATUS nt_status)
{
	if NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER) {
		/* Match WinXP and don't give the game away */
		return NT_STATUS_LOGON_FAILURE;
	} else if NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD) {
		/* Match WinXP and don't give the game away */
		return NT_STATUS_LOGON_FAILURE;
	}

	return nt_status;
}
