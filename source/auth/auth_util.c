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
#include "librpc/gen_ndr/ndr_samr.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "libcli/security/security.h"
#include "auth/auth.h"

/* this default function can be used by mostly all backends
 * which don't want to set a challlenge
 */
NTSTATUS auth_get_challenge_not_implemented(struct auth_method_context *ctx, TALLOC_CTX *mem_ctx, DATA_BLOB *challenge)
{
	/* we don't want to set a challenge */
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/
NTSTATUS make_user_info(TALLOC_CTX *mem_ctx,
                               const char *c_account_name,
                               const char *account_name,
                               const char *c_domain_name, 
                               const char *domain_name,
                               const char *workstation_name, 
                               const char *remote_host, 
                               DATA_BLOB *lm_password, DATA_BLOB *nt_password,
                               DATA_BLOB *lm_interactive_password, DATA_BLOB *nt_interactive_password,
                               DATA_BLOB *plaintext_password, BOOL encrypted, uint32_t flags,
			       struct auth_usersupplied_info **_user_info)
{
	struct auth_usersupplied_info *user_info;
	DATA_BLOB blob;

	DEBUG(5,("attempting to make a user_info for %s (%s)\n", account_name, c_account_name));

	user_info = talloc(mem_ctx, struct auth_usersupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(user_info);

	DEBUG(5,("making strings for %s's user_info struct\n", account_name));

	user_info->client.account_name = talloc_strdup(user_info, c_account_name);
	NT_STATUS_HAVE_NO_MEMORY(user_info->client.account_name);

	user_info->account_name = talloc_strdup(user_info, account_name);
	NT_STATUS_HAVE_NO_MEMORY(user_info->account_name);

	user_info->client.domain_name = talloc_strdup(user_info, c_domain_name);
	if (c_domain_name && !user_info->client.domain_name) {
		return NT_STATUS_NO_MEMORY;
	}

	user_info->domain_name = talloc_strdup(user_info, domain_name);
	NT_STATUS_HAVE_NO_MEMORY(user_info->domain_name);

	user_info->workstation_name = talloc_strdup(user_info, workstation_name);
	NT_STATUS_HAVE_NO_MEMORY(user_info->workstation_name);

	user_info->remote_host = talloc_strdup(user_info, remote_host);
	NT_STATUS_HAVE_NO_MEMORY(user_info->remote_host);

	DEBUG(5,("making blobs for %s's user_info struct\n", account_name));

	if (lm_password) {
		blob = data_blob_dup_talloc(user_info, lm_password);
		NT_STATUS_HAVE_NO_MEMORY(blob.data);
	} else {
		blob = data_blob(NULL, 0);
	}
	user_info->lm_resp = blob;

	if (nt_password) {
		blob = data_blob_dup_talloc(user_info, nt_password);
		NT_STATUS_HAVE_NO_MEMORY(blob.data);
	} else {
		blob = data_blob(NULL, 0);
	}
	user_info->nt_resp = blob;

	if (lm_interactive_password) {
		blob = data_blob_dup_talloc(user_info, lm_interactive_password);
		NT_STATUS_HAVE_NO_MEMORY(blob.data);
	} else {
		blob = data_blob(NULL, 0);
	}
	user_info->lm_interactive_password = blob;

	if (nt_interactive_password) {
		blob = data_blob_dup_talloc(user_info, nt_interactive_password);
		NT_STATUS_HAVE_NO_MEMORY(blob.data);
	} else {
		blob = data_blob(NULL, 0);
	}
	user_info->nt_interactive_password = blob;

	if (plaintext_password) {
		blob = data_blob_dup_talloc(user_info, plaintext_password);
		NT_STATUS_HAVE_NO_MEMORY(blob.data);
	} else {
		blob = data_blob(NULL, 0);
	}
	user_info->plaintext_password = blob;

	user_info->encrypted = encrypted;

	DEBUG(10,("made an %sencrypted user_info for %s (%s)\n", encrypted ? "":"un" , account_name, c_account_name));

	*_user_info = user_info;

	return NT_STATUS_OK;
}

/****************************************************************************
 Create an auth_usersupplied_data structure after appropriate mapping.
****************************************************************************/

NTSTATUS make_user_info_map(TALLOC_CTX *mem_ctx,
			    const char *c_account_name,
			    const char *c_domain_name,
			    const char *workstation_name,
 			    DATA_BLOB *lm_password, DATA_BLOB *nt_password,
 			    DATA_BLOB *lm_interactive_password, DATA_BLOB *nt_interactive_password,
			    DATA_BLOB *plaintext, BOOL encrypted,
			    struct auth_usersupplied_info **user_info)
{
	const char *domain;
	const char *account_name;
	char *d;
	DEBUG(5,("make_user_info_map: Mapping user [%s]\\[%s] from workstation [%s]\n",
		c_domain_name, c_account_name, workstation_name));

	account_name = c_account_name;

	/* don't allow "" as a domain, fixes a Win9X bug 
	   where it doens't supply a domain for logon script
	   'net use' commands.                                 */

	/* Split user@realm names into user and realm components.  This is TODO to fix with proper userprincipalname support */
	if (c_domain_name && *c_domain_name) {
		domain = c_domain_name;
	} else if (strchr_m(c_account_name, '@')) {
		account_name = talloc_strdup(mem_ctx, c_account_name);
		if (!account_name) {
			return NT_STATUS_NO_MEMORY;
		}
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

	return make_user_info(mem_ctx,
			      c_account_name, account_name, 
			      c_domain_name, domain,
			      workstation_name,
			      workstation_name,
			      lm_password, nt_password,
			      lm_interactive_password, nt_interactive_password,
			      plaintext, encrypted, 0x00,
			      user_info);
}

/****************************************************************************
 Create an auth_usersupplied_data, making the DATA_BLOBs here. 
 Decrypt and encrypt the passwords.
****************************************************************************/
NTSTATUS make_user_info_netlogon_network(TALLOC_CTX *mem_ctx,
					 const char *c_account_name,
					 const char *c_domain_name,
					 const char *workstation_name,
					 const uint8_t *lm_network_password, int lm_password_len,
					 const uint8_t *nt_network_password, int nt_password_len,
					 struct auth_usersupplied_info **user_info)
{
	DATA_BLOB lm_blob = data_blob_const(lm_network_password, lm_password_len);
	DATA_BLOB nt_blob = data_blob_const(nt_network_password, nt_password_len);

	return make_user_info_map(mem_ctx,
				  c_account_name,
				  c_domain_name, 
				  workstation_name, 
				  lm_password_len ? &lm_blob : NULL, 
				  nt_password_len ? &nt_blob : NULL,
				  NULL, NULL, NULL, True,
				  user_info);
}

/****************************************************************************
 Create an auth_usersupplied_data, making the DATA_BLOBs here. 
 Decrypt and encrypt the passwords.
****************************************************************************/
NTSTATUS make_user_info_netlogon_interactive(TALLOC_CTX *mem_ctx,
					     const char *c_account_name,
					     const char *c_domain_name,
					     const char *workstation_name,
					     const uint8_t chal[8],
					     const struct samr_Password *lm_interactive_password,
					     const struct samr_Password *nt_interactive_password,
					     struct auth_usersupplied_info **user_info)
{
	NTSTATUS nt_status;
	DATA_BLOB local_lm_blob;
	DATA_BLOB local_nt_blob;
	
	DATA_BLOB lm_interactive_blob;
	DATA_BLOB nt_interactive_blob;
	uint8_t local_lm_response[24];
	uint8_t local_nt_response[24];

	SMBOWFencrypt(lm_interactive_password->hash, chal, local_lm_response);
	SMBOWFencrypt(nt_interactive_password->hash, chal, local_nt_response);

	local_lm_blob = data_blob_const(local_lm_response, sizeof(local_lm_response));
	lm_interactive_blob = data_blob_const(lm_interactive_password->hash, 
					      sizeof(lm_interactive_password->hash));

	local_nt_blob = data_blob_const(local_nt_response, sizeof(local_nt_response));
	nt_interactive_blob = data_blob_const(nt_interactive_password->hash, 
					      sizeof(nt_interactive_password->hash));
	
	nt_status = make_user_info_map(mem_ctx,
				       c_account_name,
				       c_domain_name, 
				       workstation_name,
				       &local_lm_blob,
				       &local_nt_blob,
				       &lm_interactive_blob,
				       &nt_interactive_blob,
				       NULL, True,
				       user_info);
	return nt_status;
}

/****************************************************************************
 Create an auth_usersupplied_data structure
****************************************************************************/
NTSTATUS make_user_info_for_reply_enc(TALLOC_CTX *mem_ctx,
				      const char *c_account_name,
				      const char *c_domain_name,
				      const char *workstation_name,
                                      DATA_BLOB lm_resp, DATA_BLOB nt_resp,
				      struct auth_usersupplied_info **user_info)
{
	return make_user_info_map(mem_ctx,
				  c_account_name,
				  c_domain_name,
				  workstation_name,
				  lm_resp.data ? &lm_resp : NULL,
				  nt_resp.data ? &nt_resp : NULL,
				  NULL, NULL, NULL, True,
				  user_info);
}

/****************************************************************************
 Create a anonymous user_info blob, for anonymous authenticaion.
****************************************************************************/
NTSTATUS make_user_info_anonymous(TALLOC_CTX *mem_ctx, struct auth_usersupplied_info **user_info) 
{
	return make_user_info(mem_ctx,
			      "", "", "", "", "", "",
			      NULL, NULL, NULL, NULL, 
			      NULL, True, 0x00,
			      user_info);
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

		dgrps = talloc_realloc(server_info, dgrps, struct dom_sid*, sidcount);
		NT_STATUS_HAVE_NO_MEMORY(dgrps);

		for (i = 0; i < validation->sam3->sidcount; i++) {
			dgrps[n_dgrps + i] = talloc_reference(dgrps, validation->sam3->sids[i].sid);
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

	*_session_info = session_info;
	return NT_STATUS_OK;
}

/****************************************************************************
 prints a struct auth_session_info security token to debug output.
****************************************************************************/
void auth_session_info_debug(int dbg_lev, 
			     const struct auth_session_info *session_info)
{
	if (!session_info) {
		DEBUGC(dbg_class, dbg_lev, ("Session Info: (NULL)\n"));
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
