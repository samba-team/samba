/* 
   Unix SMB/CIFS implementation.
   
   Extract the user/system database from a remote SamSync server

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   
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
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_samr.h"


/**
 * Decrypt and extract the user's passwords.  
 * 
 * The writes decrypted (no longer 'RID encrypted' or arcfour encrypted) passwords back into the structure
 */
static NTSTATUS fix_user(TALLOC_CTX *mem_ctx,
			 struct creds_CredentialState *creds,
			 enum netr_SamDatabaseID database,
			 struct netr_DELTA_ENUM *delta,
			 char **error_string) 
{

	uint32_t rid = delta->delta_id_union.rid;
	struct netr_DELTA_USER *user = delta->delta_union.user;
	struct samr_Password lm_hash;
	struct samr_Password nt_hash;
	const char *username = user->account_name.string;
	NTSTATUS nt_status;

	if (user->lm_password_present) {
		sam_rid_crypt(rid, user->lmpassword.hash, lm_hash.hash, 0);
		user->lmpassword = lm_hash;
	}

	if (user->nt_password_present) {
		sam_rid_crypt(rid, user->ntpassword.hash, nt_hash.hash, 0);
		user->ntpassword = nt_hash;
	}

	if (user->user_private_info.SensitiveData) {
		DATA_BLOB data;
		struct netr_USER_KEYS keys;
		data.data = user->user_private_info.SensitiveData;
		data.length = user->user_private_info.DataLength;
		creds_arcfour_crypt(creds, data.data, data.length);
		user->user_private_info.SensitiveData = data.data;
		user->user_private_info.DataLength = data.length;

		nt_status = ndr_pull_struct_blob(&data, mem_ctx, &keys, (ndr_pull_flags_fn_t)ndr_pull_netr_USER_KEYS);
		if (NT_STATUS_IS_OK(nt_status)) {
			if (keys.keys.keys2.lmpassword.length == 16) {
				sam_rid_crypt(rid, keys.keys.keys2.lmpassword.pwd.hash, lm_hash.hash, 0);
				user->lmpassword = lm_hash;
				user->lm_password_present = True;
			}
			if (keys.keys.keys2.ntpassword.length == 16) {
				sam_rid_crypt(rid, keys.keys.keys2.ntpassword.pwd.hash, nt_hash.hash, 0);
				user->ntpassword = nt_hash;
				user->nt_password_present = True;
			}
		} else {
			*error_string = talloc_asprintf(mem_ctx, "Failed to parse Sensitive Data for %s:\n", username);
			dump_data(10, data.data, data.length);
			return nt_status;
		}
	}
	return NT_STATUS_OK;
}

/**
 * Decrypt and extract the secrets
 * 
 * The writes decrypted secrets back into the structure
 */
static NTSTATUS fix_secret(TALLOC_CTX *mem_ctx,
			   struct creds_CredentialState *creds,
			   enum netr_SamDatabaseID database,
			   struct netr_DELTA_ENUM *delta,
			   char **error_string) 
{
	struct netr_DELTA_SECRET *secret = delta->delta_union.secret;
	creds_arcfour_crypt(creds, secret->current_cipher.cipher_data, 
			    secret->current_cipher.maxlen); 

	creds_arcfour_crypt(creds, secret->old_cipher.cipher_data, 
			    secret->old_cipher.maxlen); 

	return NT_STATUS_OK;
}

/**
 * Fix up the delta, dealing with encryption issues so that the final
 * callback need only do the printing or application logic
 */

static NTSTATUS fix_delta(TALLOC_CTX *mem_ctx, 		
			  struct creds_CredentialState *creds,
			  enum netr_SamDatabaseID database,
			  struct netr_DELTA_ENUM *delta,
			  char **error_string)
{
	NTSTATUS nt_status = NT_STATUS_OK;
	*error_string = NULL;
	switch (delta->delta_type) {
	case NETR_DELTA_USER:
	{
		nt_status = fix_user(mem_ctx, 
				     creds,
				     database,
				     delta,
				     error_string);
		break;
	}
	case NETR_DELTA_SECRET:
	{
		nt_status = fix_secret(mem_ctx, 
				       creds,
				       database,
				       delta,
				       error_string);
		break;
	}
	default:
		break;
	}
	return nt_status;
}

NTSTATUS libnet_SamSync_netlogon(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_SamSync *r)
{
	NTSTATUS nt_status, dbsync_nt_status;
	TALLOC_CTX *samsync_ctx, *loop_ctx, *delta_ctx;
	struct creds_CredentialState *creds;
	struct netr_DatabaseSync dbsync;
	struct cli_credentials *machine_account;
	struct dcerpc_binding *b;
	struct dcerpc_pipe *p;
	const enum netr_SamDatabaseID database_ids[] = {SAM_DATABASE_DOMAIN, SAM_DATABASE_BUILTIN, SAM_DATABASE_PRIVS}; 
	int i;

	/* TODO: This is bogus */
	const char **bindings = lp_passwordserver();
	const char *binding;

	if (bindings && bindings[0]) {
		binding = bindings[0];
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	samsync_ctx = talloc_named(mem_ctx, 0, "SamSync top context");

	if (!r->machine_account) { 
		machine_account = cli_credentials_init(samsync_ctx);
		if (!machine_account) {
			talloc_free(samsync_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		cli_credentials_set_conf(machine_account);
		nt_status = cli_credentials_set_machine_account(machine_account);
		if (!NT_STATUS_IS_OK(nt_status)) {
			r->error_string = talloc_strdup(mem_ctx, "Could not obtain machine account password - are we joined to the domain?");
			talloc_free(samsync_ctx);
			return nt_status;
		}
	} else {
		machine_account = r->machine_account;
	}

	if (cli_credentials_get_secure_channel_type(machine_account) != SEC_CHAN_BDC) {
		r->error_string
			= talloc_asprintf(mem_ctx, 
					  "Our join to domain %s is not as a BDC (%d), please rejoin as a BDC",
					  
					  cli_credentials_get_domain(machine_account),
					  cli_credentials_get_secure_channel_type(machine_account));
		talloc_free(samsync_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/* Connect to DC (take a binding string for now) */

	nt_status = dcerpc_parse_binding(samsync_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(nt_status)) {
		r->error_string = talloc_asprintf(mem_ctx, "Bad binding string %s\n", binding);
		talloc_free(samsync_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* We like schannel */
	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= DCERPC_SCHANNEL | DCERPC_SEAL /* | DCERPC_SCHANNEL_128 */;

	/* Setup schannel */
	nt_status = dcerpc_pipe_connect_b(samsync_ctx, &p, b, 
					  DCERPC_NETLOGON_UUID,
					  DCERPC_NETLOGON_VERSION,
					  machine_account, ctx->event_ctx);

	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(samsync_ctx);
		return nt_status;
	}

	/* get NETLOGON credentails */

	nt_status = dcerpc_schannel_creds(p->conn->security_state.generic_state, samsync_ctx, &creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		r->error_string = talloc_strdup(mem_ctx, "Could not obtain NETLOGON credentials from DCERPC/GENSEC layer");
		talloc_free(samsync_ctx);
		return nt_status;
	}

	dbsync.in.logon_server = talloc_asprintf(samsync_ctx, "\\\\%s", dcerpc_server_name(p));
	dbsync.in.computername = cli_credentials_get_workstation(machine_account);
	dbsync.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(dbsync.in.return_authenticator);

	for (i=0;i< ARRAY_SIZE(database_ids); i++) { 
		dbsync.in.sync_context = 0;
		dbsync.in.database_id = database_ids[i]; 
		
		do {
			int d;
			loop_ctx = talloc_named(samsync_ctx, 0, "DatabaseSync loop context");
			creds_client_authenticator(creds, &dbsync.in.credential);
			
			dbsync_nt_status = dcerpc_netr_DatabaseSync(p, loop_ctx, &dbsync);
			if (!NT_STATUS_IS_OK(dbsync_nt_status) &&
			    !NT_STATUS_EQUAL(dbsync_nt_status, STATUS_MORE_ENTRIES)) {
				r->error_string = talloc_asprintf(samsync_ctx, "DatabaseSync failed - %s", nt_errstr(nt_status));
				talloc_free(samsync_ctx);
				return nt_status;
			}
			
			if (!creds_client_check(creds, &dbsync.out.return_authenticator.cred)) {
				r->error_string = talloc_strdup(samsync_ctx, "Credential chaining failed");
				talloc_free(samsync_ctx);
				return NT_STATUS_ACCESS_DENIED;
			}
			
			dbsync.in.sync_context = dbsync.out.sync_context;
			
			for (d=0; d < dbsync.out.delta_enum_array->num_deltas; d++) {
				char *error_string = NULL;
				delta_ctx = talloc_named(loop_ctx, 0, "DatabaseSync delta context");
				nt_status = fix_delta(delta_ctx, 
						      creds, 
						      dbsync.in.database_id,
						      &dbsync.out.delta_enum_array->delta_enum[d], 
						      &error_string);
				if (!NT_STATUS_IS_OK(nt_status)) {
					r->error_string = talloc_steal(samsync_ctx, error_string);
					talloc_free(samsync_ctx);
					return nt_status;
				}
				nt_status = r->delta_fn(delta_ctx, 
								 r->fn_ctx,
								 creds,
								 dbsync.in.database_id,
								 &dbsync.out.delta_enum_array->delta_enum[d], 
								 &error_string);
				if (!NT_STATUS_IS_OK(nt_status)) {
					r->error_string = talloc_steal(samsync_ctx, error_string);
					talloc_free(samsync_ctx);
					return nt_status;
				}
				talloc_free(delta_ctx);
			}
			talloc_free(loop_ctx);
		} while (NT_STATUS_EQUAL(dbsync_nt_status, STATUS_MORE_ENTRIES));
		nt_status = dbsync_nt_status;
	}
	talloc_free(samsync_ctx);
	return nt_status;
}

