/* 
   Unix SMB/CIFS implementation.
   
   Extract kerberos keys from a remote SamSync server

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   
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
#include "libnet/libnet.h"
#include "system/kerberos.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"

static NTSTATUS samdump_keytab_handle_user(TALLOC_CTX *mem_ctx,
					    const char *keytab_name,
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

NTSTATUS libnet_SamDump_keytab(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_SamDump_keytab *r)
{
	NTSTATUS nt_status;
	struct libnet_SamSync r2;

	r2.out.error_string            = NULL;
	r2.in.binding_string           = r->in.binding_string;
	r2.in.rid_crypt                = true;
	r2.in.init_fn                  = NULL;
	r2.in.delta_fn                 = libnet_samdump_keytab_fn;
	r2.in.fn_ctx                   = discard_const(r->in.keytab_name);
	r2.in.machine_account          = r->in.machine_account;
	nt_status                      = libnet_SamSync_netlogon(ctx, mem_ctx, &r2);
	r->out.error_string            = r2.out.error_string;
	talloc_steal(mem_ctx, r->out.error_string);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	return nt_status;
}
