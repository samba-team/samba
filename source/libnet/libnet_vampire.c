/* 
   Unix SMB/CIFS implementation.
   
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

static NTSTATUS vampire_samdump_handle_user(TALLOC_CTX *mem_ctx,
					    struct creds_CredentialState *creds,
					    struct netr_DELTA_ENUM *delta) 
{
	uint32_t rid = delta->delta_id_union.rid;
	struct netr_DELTA_USER *user = delta->delta_union.user;
	struct samr_Password lm_hash;
	struct samr_Password nt_hash;
	struct samr_Password *lm_hash_p = NULL;
	struct samr_Password *nt_hash_p = NULL;
	const char *username = user->account_name.string;
	char *hex_lm_password;
	char *hex_nt_password;

	NTSTATUS nt_status;

	if (user->lm_password_present) {
		sam_rid_crypt(rid, user->lmpassword.hash, lm_hash.hash, 0);
		lm_hash_p = &lm_hash;
	}

	if (user->nt_password_present) {
		sam_rid_crypt(rid, user->ntpassword.hash, nt_hash.hash, 0);
		nt_hash_p = &nt_hash;
	}

	if (user->user_private_info.SensitiveData) {
		DATA_BLOB data;
		struct netr_USER_KEYS keys;
		data.data = user->user_private_info.SensitiveData;
		data.length = user->user_private_info.DataLength;
		creds_arcfour_crypt(creds, data.data, data.length);
		nt_status = ndr_pull_struct_blob(&data, mem_ctx, &keys, (ndr_pull_flags_fn_t)ndr_pull_netr_USER_KEYS);
		if (NT_STATUS_IS_OK(nt_status)) {
			if (keys.keys.keys2.lmpassword.length == 16) {
				sam_rid_crypt(rid, keys.keys.keys2.lmpassword.pwd.hash, lm_hash.hash, 0);
				lm_hash_p = &lm_hash;
			}
			if (keys.keys.keys2.ntpassword.length == 16) {
				sam_rid_crypt(rid, keys.keys.keys2.ntpassword.pwd.hash, nt_hash.hash, 0);
				nt_hash_p = &nt_hash;
			}
		} else {
			DEBUG(1, ("Failed to parse Sensitive Data for %s:\n", username));
			dump_data(10, data.data, data.length);
			return nt_status;
		}
	}

	hex_lm_password = smbpasswd_sethexpwd(mem_ctx, lm_hash_p, user->acct_flags);
	hex_nt_password = smbpasswd_sethexpwd(mem_ctx, nt_hash_p, user->acct_flags);

	printf("%s:%d:%s:%s:%s:LCT-%08X\n", username,
	       rid, hex_lm_password, hex_nt_password,
	       smbpasswd_encode_acb_info(mem_ctx, user->acct_flags),
	       (unsigned int)nt_time_to_unix(user->last_password_change));

	return NT_STATUS_OK;
}

static NTSTATUS libnet_samdump_fn(TALLOC_CTX *mem_ctx, 		
				  void *private, 			
				  struct creds_CredentialState *creds,
				  enum netr_SamDatabaseID database,
				  struct netr_DELTA_ENUM *delta,
				  char **error_string)
{
	NTSTATUS nt_status = NT_STATUS_OK;
	*error_string = NULL;
	switch (database) {
	case SAM_DATABASE_DOMAIN: 
	{
		switch (delta->delta_type) {
		case NETR_DELTA_USER:
		{
			nt_status = vampire_samdump_handle_user(mem_ctx, 
								creds,
								delta);
			break;
		}
		}
		break;
	}
	}
	return nt_status;
}

static NTSTATUS libnet_SamSync_netlogon(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_SamSync *r)
{
	NTSTATUS nt_status, dbsync_nt_status;
	TALLOC_CTX *loop_ctx, *delta_ctx;
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
	}

	machine_account = cli_credentials_init(mem_ctx);
	if (!machine_account) {
		return NT_STATUS_NO_MEMORY;
	}

	cli_credentials_set_conf(machine_account);
	nt_status = cli_credentials_set_machine_account(machine_account);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		r->netlogon.error_string = talloc_strdup(mem_ctx, "Could not obtain machine account password - are we joined to the domain?");
		return nt_status;
	}
	
	if (cli_credentials_get_secure_channel_type(machine_account) != SEC_CHAN_BDC) {
		r->netlogon.error_string
			= talloc_asprintf(mem_ctx, 
					  "Our join to domain %s is not as a BDC (%d), please rejoin as a BDC",
					  
					  cli_credentials_get_domain(machine_account),
					  cli_credentials_get_secure_channel_type(machine_account));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/* Connect to DC (take a binding string for now) */

	nt_status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(nt_status)) {
		r->netlogon.error_string = talloc_asprintf(mem_ctx, "Bad binding string %s\n", binding);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* We like schannel */
	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= DCERPC_SCHANNEL | DCERPC_SEAL | DCERPC_SCHANNEL_128;

	/* Setup schannel */
	nt_status = dcerpc_pipe_connect_b(mem_ctx, &p, b, 
					  DCERPC_NETLOGON_UUID,
					  DCERPC_NETLOGON_VERSION,
					  machine_account);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	/* get NETLOGON credentails */

	nt_status = dcerpc_schannel_creds(p->conn->security_state.generic_state, mem_ctx, &creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		r->netlogon.error_string = talloc_strdup(mem_ctx, "Could not obtain NETLOGON credentials from DCERPC/GENSEC layer");
		return nt_status;
	}

	dbsync.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	dbsync.in.computername = cli_credentials_get_workstation(machine_account);
	dbsync.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(dbsync.in.return_authenticator);

	for (i=0;i< ARRAY_SIZE(database_ids); i++) { 
		dbsync.in.sync_context = 0;
		dbsync.in.database_id = database_ids[i]; 
		
		do {
			int d;
			loop_ctx = talloc_named(mem_ctx, 0, "DatabaseSync loop context");
			creds_client_authenticator(creds, &dbsync.in.credential);
			
			dbsync_nt_status = dcerpc_netr_DatabaseSync(p, loop_ctx, &dbsync);
			if (!NT_STATUS_IS_OK(dbsync_nt_status) &&
			    !NT_STATUS_EQUAL(dbsync_nt_status, STATUS_MORE_ENTRIES)) {
				r->netlogon.error_string = talloc_asprintf(mem_ctx, "DatabaseSync failed - %s", nt_errstr(nt_status));
				return nt_status;
			}
			
			if (!creds_client_check(creds, &dbsync.out.return_authenticator.cred)) {
				r->netlogon.error_string = talloc_strdup(mem_ctx, "Credential chaining failed");
				return NT_STATUS_ACCESS_DENIED;
			}
			
			dbsync.in.sync_context = dbsync.out.sync_context;
			
			for (d=0; d < dbsync.out.delta_enum_array->num_deltas; d++) {
				char *error_string = NULL;
				delta_ctx = talloc_named(loop_ctx, 0, "DatabaseSync delta context");
				nt_status = r->netlogon.delta_fn(delta_ctx, 
								 r->netlogon.fn_ctx,
								 creds,
								 dbsync.in.database_id,
								 &dbsync.out.delta_enum_array->delta_enum[d], 
								 &error_string);
				if (!NT_STATUS_IS_OK(nt_status)) {
					r->netlogon.error_string = talloc_steal(mem_ctx, error_string);
					talloc_free(delta_ctx);
					return nt_status;
				}
				talloc_free(delta_ctx);
			}
			talloc_free(loop_ctx);
		} while (NT_STATUS_EQUAL(dbsync_nt_status, STATUS_MORE_ENTRIES));
		nt_status = dbsync_nt_status;
	}
	return nt_status;
}

NTSTATUS libnet_SamDump_netlogon(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_SamDump *r)
{
	NTSTATUS nt_status;
	union libnet_SamSync r2;

	r2.netlogon.level = LIBNET_SAMDUMP_NETLOGON;
	r2.netlogon.error_string = NULL;
	r2.netlogon.delta_fn = libnet_samdump_fn;
	r2.netlogon.fn_ctx = NULL;
	nt_status = libnet_SamSync_netlogon(ctx, mem_ctx, &r2);
	r->generic.error_string = r2.netlogon.error_string;

	
	return nt_status;
}



NTSTATUS libnet_SamDump_generic(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_SamDump *r)
{
	NTSTATUS nt_status;
	union libnet_SamDump r2;

	r2.generic.level = LIBNET_SAMDUMP_NETLOGON;
	r2.generic.error_string = NULL;
	nt_status = libnet_SamDump(ctx, mem_ctx, &r2);
	r->generic.error_string = r2.netlogon.error_string;

	
	return nt_status;
}

NTSTATUS libnet_SamDump(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_SamDump *r)
{
	switch (r->generic.level) {
	case LIBNET_SAMDUMP_GENERIC:
		return libnet_SamDump_generic(ctx, mem_ctx, r);
	case LIBNET_SAMDUMP_NETLOGON:
		return libnet_SamDump_netlogon(ctx, mem_ctx, r);
	}

	return NT_STATUS_INVALID_LEVEL;
}
