/* 
   Unix SMB/CIFS implementation.
   
   Extract kerberos keys from a remote SamSync server

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
#include "system/kerberos.h"

static NTSTATUS samdump_keytab_handle_user(TALLOC_CTX *mem_ctx,
					    const char *keytab_name,
					    struct creds_CredentialState *creds,
					    struct netr_DELTA_ENUM *delta) 
{
	struct netr_DELTA_USER *user = delta->delta_union.user;
	const char *username = user->account_name.string;
	struct cli_credentials *credentials;
	int ret;

	if (!user->nt_password_present) {
		/* We can't do anything here */
		return NT_STATUS_OK;
	}

	credentials = cli_credentials_init(mem_ctx);
	if (!credentials) {
		return NT_STATUS_NO_MEMORY;
	}
	cli_credentials_set_conf(credentials);
	cli_credentials_set_username(credentials, username, CRED_SPECIFIED);

	/* We really should consult ldap in the main SamSync code, and
	 * pass a value in here */
	cli_credentials_set_kvno(credentials, 0);
	cli_credentials_set_nt_hash(credentials, &user->ntpassword, CRED_SPECIFIED);
	ret = cli_credentials_set_keytab_name(credentials, keytab_name, CRED_SPECIFIED);
	if (ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ret = cli_credentials_update_keytab(credentials);
	if (ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	return NT_STATUS_OK;
}

static NTSTATUS libnet_samdump_keytab_fn(TALLOC_CTX *mem_ctx, 		
					 void *private, 			
					 struct creds_CredentialState *creds,
					 enum netr_SamDatabaseID database,
					 struct netr_DELTA_ENUM *delta,
					 char **error_string)
{
	NTSTATUS nt_status = NT_STATUS_OK;
	const char *keytab_name = private;

	*error_string = NULL;
	switch (delta->delta_type) {
	case NETR_DELTA_USER:
	{
		/* not interested in builtin users */
		if (database == SAM_DATABASE_DOMAIN) {
			nt_status = samdump_keytab_handle_user(mem_ctx, 
							       keytab_name,
							       creds,
							       delta);
			break;
		}
	}
	default:
		/* Can't dump them all right now */
		break;
	}
	return nt_status;
}

static NTSTATUS libnet_SamDump_keytab_netlogon(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_SamDump_keytab *r)
{
	NTSTATUS nt_status;
	struct libnet_SamSync r2;

	r2.error_string = NULL;
	r2.delta_fn = libnet_samdump_keytab_fn;
	r2.fn_ctx = r->keytab_name;
	r2.machine_account = NULL; /* TODO:  Create a machine account, fill this in, and the delete it */
	nt_status = libnet_SamSync_netlogon(ctx, mem_ctx, &r2);
	r->error_string = r2.error_string;

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	return nt_status;
}



static NTSTATUS libnet_SamDump_keytab_generic(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_SamDump_keytab *r)
{
	NTSTATUS nt_status;
	struct libnet_SamDump_keytab r2;
	r2.level = LIBNET_SAMDUMP_NETLOGON;
	r2.error_string = NULL;
	r2.keytab_name = r->keytab_name;
	nt_status = libnet_SamDump_keytab(ctx, mem_ctx, &r2);
	r->error_string = r2.error_string;
	
	return nt_status;
}

NTSTATUS libnet_SamDump_keytab(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_SamDump_keytab *r)
{
	switch (r->level) {
	case LIBNET_SAMDUMP_GENERIC:
		return libnet_SamDump_keytab_generic(ctx, mem_ctx, r);
	case LIBNET_SAMDUMP_NETLOGON:
		return libnet_SamDump_keytab_netlogon(ctx, mem_ctx, r);
	}

	return NT_STATUS_INVALID_LEVEL;
}
