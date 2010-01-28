/*
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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
#include "../libds/common/flags.h"
#include "auth/auth.h"
#include "kdc/kdc.h"
#include "param/param.h"
#include "kdc/pac-glue.h"

/* Given the right private pointer from hdb_samba4, get a PAC from the attached ldb messages */
static krb5_error_code samba_wdc_get_pac(void *priv, krb5_context context,
					 struct hdb_entry_ex *client,
					 krb5_pac *pac)
{
	TALLOC_CTX *mem_ctx;
	DATA_BLOB *pac_blob;
	krb5_error_code ret;
	NTSTATUS nt_status;

	mem_ctx = talloc_named(client->ctx, 0, "samba_get_pac context");
	if (!mem_ctx) {
		return ENOMEM;
	}

	nt_status = samba_kdc_get_pac_blob(mem_ctx, client, &pac_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return EINVAL;
	}

	ret = samba_make_krb5_pac(context, pac_blob, pac);

	talloc_free(mem_ctx);
	return ret;
}

/* Resign (and reform, including possibly new groups) a PAC */

static krb5_error_code samba_wdc_reget_pac(void *priv, krb5_context context,
					   const krb5_principal client_principal,
					   struct hdb_entry_ex *client,
					   struct hdb_entry_ex *server, krb5_pac *pac)
{
	struct samba_kdc_entry *p = talloc_get_type(server->ctx, struct samba_kdc_entry);
	TALLOC_CTX *mem_ctx = talloc_named(p, 0, "samba_kdc_reget_pac context");
	DATA_BLOB *pac_blob;
	krb5_error_code ret;
	NTSTATUS nt_status;

	if (!mem_ctx) {
		return ENOMEM;
	}

	pac_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (!pac_blob) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	/* The user account may be set not to want the PAC */
	if (!samba_princ_needs_pac(server)) {
		talloc_free(mem_ctx);
		return EINVAL;
	}

	nt_status = samba_kdc_update_pac_blob(mem_ctx, context,
					      p->kdc_db_ctx->ic_ctx,
					      pac, pac_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Building PAC failed: %s\n",
			  nt_errstr(nt_status)));
		talloc_free(mem_ctx);
		return EINVAL;
	}

	/* We now completly regenerate this pac */
	krb5_pac_free(context, *pac);

	ret = samba_make_krb5_pac(context, pac_blob, pac);

	talloc_free(mem_ctx);
	return ret;
}

/* Given an hdb entry (and in particular it's private member), consult
 * the account_ok routine in auth/auth_sam.c for consistancy */
static krb5_error_code samba_wdc_check_client_access(void *priv,
						     krb5_context context,
						     krb5_kdc_configuration *config,
						     hdb_entry_ex *client_ex, const char *client_name,
						     hdb_entry_ex *server_ex, const char *server_name,
						     KDC_REQ *req,
						     krb5_data *e_data)
{
	krb5_error_code ret;
	NTSTATUS nt_status;
	TALLOC_CTX *tmp_ctx;
	struct samba_kdc_entry *p;
	char *workstation = NULL;
	HostAddresses *addresses = req->req_body.addresses;
	int i;
	bool password_change;

	tmp_ctx = talloc_new(client_ex->ctx);
	p = talloc_get_type(client_ex->ctx, struct samba_kdc_entry);

	if (!tmp_ctx) {
		return ENOMEM;
	}

	if (addresses) {
		for (i=0; i < addresses->len; i++) {
			if (addresses->val->addr_type == KRB5_ADDRESS_NETBIOS) {
				workstation = talloc_strndup(tmp_ctx, addresses->val->address.data, MIN(addresses->val->address.length, 15));
				if (workstation) {
					break;
				}
			}
		}
	}

	/* Strip space padding */
	if (workstation) {
		i = MIN(strlen(workstation), 15);
		for (; i > 0 && workstation[i - 1] == ' '; i--) {
			workstation[i - 1] = '\0';
		}
	}

	password_change = (server_ex && server_ex->entry.flags.change_pw);

	/* we allow all kinds of trusts here */
	nt_status = authsam_account_ok(tmp_ctx,
				       p->kdc_db_ctx->samdb,
				       MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT | MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT,
				       p->realm_dn,
				       p->msg,
				       workstation,
				       client_name, true, password_change);

	if (NT_STATUS_IS_OK(nt_status)) {
		/* Now do the standard Heimdal check */
		ret = kdc_check_flags(context, config,
				      client_ex, client_name,
				      server_ex, server_name,
				      req->msg_type == krb_as_req);
	} else {
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_PASSWORD_MUST_CHANGE))
			ret = KRB5KDC_ERR_KEY_EXPIRED;
		else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_PASSWORD_EXPIRED))
			ret = KRB5KDC_ERR_KEY_EXPIRED;
		else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCOUNT_EXPIRED))
			ret = KRB5KDC_ERR_CLIENT_REVOKED;
		else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCOUNT_DISABLED))
			ret = KRB5KDC_ERR_CLIENT_REVOKED;
		else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_LOGON_HOURS))
			ret = KRB5KDC_ERR_CLIENT_REVOKED;
		else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCOUNT_LOCKED_OUT))
			ret = KRB5KDC_ERR_CLIENT_REVOKED;
		else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_WORKSTATION))
			ret = KRB5KDC_ERR_POLICY;
		else
			ret = KRB5KDC_ERR_POLICY;

		samba_kdc_build_edata_reply(tmp_ctx, e_data, nt_status);
	}

	return ret;
}

static krb5_error_code samba_wdc_plugin_init(krb5_context context, void **ptr)
{
	*ptr = NULL;
	return 0;
}

static void samba_wdc_plugin_fini(void *ptr)
{
	return;
}

struct krb5plugin_windc_ftable windc_plugin_table = {
	.minor_version = KRB5_WINDC_PLUGING_MINOR,
	.init = samba_wdc_plugin_init,
	.fini = samba_wdc_plugin_fini,
	.pac_generate = samba_wdc_get_pac,
	.pac_verify = samba_wdc_reget_pac,
	.client_access = samba_wdc_check_client_access,
};


