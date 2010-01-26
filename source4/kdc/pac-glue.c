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
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "auth/auth.h"
#include "auth/auth_sam.h"
#include "auth/auth_sam_reply.h"
#include "kdc/kdc.h"
#include "param/param.h"

struct krb5_dh_moduli;
struct _krb5_krb_auth_data;

static krb5_error_code	samba_kdc_plugin_init(krb5_context context, void **ptr)
{
	*ptr = NULL;
	return 0;
}

static void	samba_kdc_plugin_fini(void *ptr)
{
	return;
}

NTSTATUS samba_get_logon_info_pac_blob(TALLOC_CTX *mem_ctx,
				       struct smb_iconv_convenience *ic,
				       struct auth_serversupplied_info *info,
				       DATA_BLOB *pac_data)
{
	struct netr_SamInfo3 *info3;
	union PAC_INFO pac_info;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	ZERO_STRUCT(pac_info);

	nt_status = auth_convert_server_info_saminfo3(mem_ctx, info, &info3);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Getting Samba info failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	pac_info.logon_info.info = talloc_zero(mem_ctx, struct PAC_LOGON_INFO);
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	pac_info.logon_info.info->info3 = *info3;

	ndr_err = ndr_push_union_blob(pac_data, mem_ctx, ic, &pac_info,
				      PAC_TYPE_LOGON_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	return NT_STATUS_OK;
}

krb5_error_code samba_make_krb5_pac(krb5_context context,
				    DATA_BLOB *pac_blob,
				    krb5_pac *pac)
{
	krb5_data pac_data;
	krb5_error_code ret;

	ret = krb5_data_copy(&pac_data, pac_blob->data, pac_blob->length);
	if (ret != 0) {
		return ret;
	}

	ret = krb5_pac_init(context, pac);
	if (ret != 0) {
		krb5_data_free(&pac_data);
		return ret;
	}

	ret = krb5_pac_add_buffer(context, *pac, PAC_TYPE_LOGON_INFO, &pac_data);
	krb5_data_free(&pac_data);
	if (ret != 0) {
		return ret;
	}

	return ret;
}

bool samba_princ_needs_pac(struct hdb_entry_ex *princ)
{

	struct hdb_samba4_private *p = talloc_get_type(princ->ctx, struct hdb_samba4_private);
	unsigned int userAccountControl;


	/* The service account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(p->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		return false;
	}

	return true;
}

NTSTATUS samba_kdc_get_pac_blob(TALLOC_CTX *mem_ctx,
				struct hdb_entry_ex *client,
				DATA_BLOB **_pac_blob)
{
	struct hdb_samba4_private *p = talloc_get_type(client->ctx, struct hdb_samba4_private);
	struct auth_serversupplied_info *server_info;
	DATA_BLOB *pac_blob;
	NTSTATUS nt_status;

	/* The user account may be set not to want the PAC */
	if ( ! samba_princ_needs_pac(client)) {
		*_pac_blob = NULL;
		return NT_STATUS_OK;
	}

	pac_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (!pac_blob) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = authsam_make_server_info(mem_ctx, p->samdb,
					     lp_netbios_name(p->lp_ctx),
					     lp_sam_name(p->lp_ctx),
					     p->realm_dn,
					     p->msg,
					     data_blob(NULL, 0),
					     data_blob(NULL, 0),
					     &server_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Getting user info for PAC failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	nt_status = samba_get_logon_info_pac_blob(mem_ctx,
						  p->iconv_convenience,
						  server_info, pac_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Building PAC failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	*_pac_blob = pac_blob;
	return NT_STATUS_OK;
}

NTSTATUS samba_kdc_update_pac_blob(TALLOC_CTX *mem_ctx,
				   krb5_context context,
				   struct smb_iconv_convenience *ic,
				   krb5_pac *pac, DATA_BLOB *pac_blob)
{
	struct auth_serversupplied_info *server_info;
	krb5_error_code ret;
	NTSTATUS nt_status;

	ret = kerberos_pac_to_server_info(mem_ctx, ic, *pac,
					  context, &server_info);
	if (ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	nt_status = samba_get_logon_info_pac_blob(mem_ctx, ic,
						  server_info, pac_blob);

	return nt_status;
}

/* Given the right private pointer from hdb_samba4, get a PAC from the attached ldb messages */
static krb5_error_code samba_kdc_get_pac(void *priv, krb5_context context,
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

static krb5_error_code samba_kdc_reget_pac(void *priv, krb5_context context,
					   const krb5_principal client_principal,
					   struct hdb_entry_ex *client,
					   struct hdb_entry_ex *server, krb5_pac *pac)
{
	struct hdb_samba4_private *p = talloc_get_type(server->ctx, struct hdb_samba4_private);
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
	if ( ! samba_princ_needs_pac(server)) {
		talloc_free(mem_ctx);
		return EINVAL;
	}

	nt_status = samba_kdc_update_pac_blob(mem_ctx, context,
					      p->iconv_convenience,
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

void samba_kdc_build_edata_reply(TALLOC_CTX *tmp_ctx, krb5_data *e_data,
				 NTSTATUS nt_status)
{
	PA_DATA pa;
	unsigned char *buf;
	size_t len;
	krb5_error_code ret = 0;

	if (!e_data)
		return;

	pa.padata_type		= KRB5_PADATA_PW_SALT;
	pa.padata_value.length	= 12;
	pa.padata_value.data	= malloc(pa.padata_value.length);
	if (!pa.padata_value.data) {
		e_data->length = 0;
		e_data->data = NULL;
		return;
	}

	SIVAL(pa.padata_value.data, 0, NT_STATUS_V(nt_status));
	SIVAL(pa.padata_value.data, 4, 0);
	SIVAL(pa.padata_value.data, 8, 1);

	ASN1_MALLOC_ENCODE(PA_DATA, buf, len, &pa, &len, ret);
	free(pa.padata_value.data);

	e_data->data   = buf;
	e_data->length = len;

	return;
}

/* Given an hdb entry (and in particular it's private member), consult
 * the account_ok routine in auth/auth_sam.c for consistancy */


static krb5_error_code samba_kdc_check_client_access(void *priv,
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
	struct hdb_samba4_private *p;
	char *workstation = NULL;
	HostAddresses *addresses = req->req_body.addresses;
	int i;
	bool password_change;

	tmp_ctx = talloc_new(client_ex->ctx);
	p = talloc_get_type(client_ex->ctx, struct hdb_samba4_private);

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
				       p->samdb,
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

struct krb5plugin_windc_ftable windc_plugin_table = {
	.minor_version = KRB5_WINDC_PLUGING_MINOR,
	.init = samba_kdc_plugin_init,
	.fini = samba_kdc_plugin_fini,
	.pac_generate = samba_kdc_get_pac,
	.pac_verify = samba_kdc_reget_pac,
	.client_access = samba_kdc_check_client_access,
};

