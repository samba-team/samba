/* 
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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
#include "kdc/kdc.h"
#include "dsdb/common/flags.h"
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "auth/auth.h"
#include "auth/auth_sam.h"
#include "auth/auth_sam_reply.h"
#include "param/param.h"

struct krb5_dh_moduli;
struct _krb5_krb_auth_data;

krb5_error_code	samba_kdc_plugin_init(krb5_context context, void **ptr) 
{
	*ptr = NULL;
	return 0;
}

void	samba_kdc_plugin_fini(void *ptr) 
{
	return;
}

static krb5_error_code make_pac(krb5_context context,
				TALLOC_CTX *mem_ctx, 
				struct smb_iconv_convenience *iconv_convenience,
				struct auth_serversupplied_info *server_info,
				krb5_pac *pac) 
{
	struct PAC_LOGON_INFO_CTR logon_info;
	struct netr_SamInfo3 *info3;
	krb5_data pac_data;
	NTSTATUS nt_status;
	enum ndr_err_code ndr_err;
	DATA_BLOB pac_out;
	krb5_error_code ret;

	ZERO_STRUCT(logon_info);

	nt_status = auth_convert_server_info_saminfo3(mem_ctx, server_info, &info3);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Getting Samba info failed: %s\n", nt_errstr(nt_status)));
		return EINVAL;
	}

	logon_info.info = talloc_zero(mem_ctx, struct PAC_LOGON_INFO);
	if (!mem_ctx) {
		return ENOMEM;
	}

	logon_info.info->info3 = *info3;

	ndr_err = ndr_push_struct_blob(&pac_out, mem_ctx, iconv_convenience, &logon_info,
				       (ndr_push_flags_fn_t)ndr_push_PAC_LOGON_INFO_CTR);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC (presig) push failed: %s\n", nt_errstr(nt_status)));
		return EINVAL;
	}

	ret = krb5_data_copy(&pac_data, pac_out.data, pac_out.length);
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

/* Given the right private pointer from hdb_ldb, get a PAC from the attached ldb messages */
krb5_error_code samba_kdc_get_pac(void *priv,
				  krb5_context context, 
				  struct hdb_entry_ex *client,
				  krb5_pac *pac)
{
	krb5_error_code ret;
	NTSTATUS nt_status;
	struct auth_serversupplied_info *server_info;
	struct hdb_ldb_private *private = talloc_get_type(client->ctx, struct hdb_ldb_private);
	TALLOC_CTX *mem_ctx = talloc_named(private, 0, "samba_get_pac context");
	unsigned int userAccountControl;

	if (!mem_ctx) {
		return ENOMEM;
	}

	/* The user account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(private->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		*pac = NULL;
		return 0;
	}

	nt_status = authsam_make_server_info(mem_ctx, private->samdb, 
					     private->netbios_name,
					     private->msg, 
					     private->realm_ref_msg,
					     data_blob(NULL, 0),
					     data_blob(NULL, 0),
					     &server_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Getting user info for PAC failed: %s\n",
			  nt_errstr(nt_status)));
		return ENOMEM;
	}

	ret = make_pac(context, mem_ctx, private->iconv_convenience, server_info, pac);

	talloc_free(mem_ctx);
	return ret;
}

/* Resign (and reform, including possibly new groups) a PAC */

krb5_error_code samba_kdc_reget_pac(void *priv, krb5_context context,
				const krb5_principal client_principal,
				struct hdb_entry_ex *client,  
				struct hdb_entry_ex *server, krb5_pac *pac)
{
	NTSTATUS nt_status;
	enum ndr_err_code ndr_err;
	krb5_error_code ret;

	unsigned int userAccountControl;

	struct hdb_ldb_private *private = talloc_get_type(server->ctx, struct hdb_ldb_private);
	krb5_data k5pac_in;
	DATA_BLOB pac_in;

	struct PAC_LOGON_INFO_CTR logon_info;
	union netr_Validation validation;
	struct auth_serversupplied_info *server_info_out;

	TALLOC_CTX *mem_ctx = talloc_named(private, 0, "samba_get_pac context");
	
	if (!mem_ctx) {
		return ENOMEM;
	}

	/* The service account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(private->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		*pac = NULL;
		return 0;
	}

	ret = krb5_pac_get_buffer(context, *pac, PAC_TYPE_LOGON_INFO, &k5pac_in);
	if (ret != 0) {
		return ret;
	}

	pac_in = data_blob_talloc(mem_ctx, k5pac_in.data, k5pac_in.length);
	krb5_data_free(&k5pac_in);
	if (!pac_in.data) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}
		
	ndr_err = ndr_pull_struct_blob(&pac_in, mem_ctx, private->iconv_convenience, &logon_info,
				       (ndr_pull_flags_fn_t)ndr_pull_PAC_LOGON_INFO_CTR);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err) || !logon_info.info) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status)));
		talloc_free(mem_ctx);
		return EINVAL;
	}

	/* Pull this right into the normal auth sysstem structures */
	validation.sam3 = &logon_info.info->info3;
	nt_status = make_server_info_netlogon_validation(mem_ctx,
							 "",
							 3, &validation,
							 &server_info_out); 
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	/* We will compleatly regenerate this pac */
	krb5_pac_free(context, *pac);

	ret = make_pac(context, mem_ctx, private->iconv_convenience, server_info_out, pac);

	talloc_free(mem_ctx);
	return ret;
}

static void samba_kdc_build_edata_reply(TALLOC_CTX *tmp_ctx, krb5_data *e_data,
				       NTSTATUS nt_status)
{
	PA_DATA pa;
	unsigned char *buf;
	size_t len;
	krb5_error_code ret = 0;
	uint32_t *tmp;

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


krb5_error_code samba_kdc_check_client_access(void *priv, 
					      krb5_context context, hdb_entry_ex *entry_ex, 
					      KDC_REQ *req,
					      krb5_data *e_data)
{
	krb5_error_code ret;
	NTSTATUS nt_status;
	TALLOC_CTX *tmp_ctx = talloc_new(entry_ex->ctx);
	struct hdb_ldb_private *private = talloc_get_type(entry_ex->ctx, struct hdb_ldb_private);
	char *name, *workstation = NULL;
	HostAddresses *addresses = req->req_body.addresses;
	int i;

	if (!tmp_ctx) {
		return ENOMEM;
	}
	
	ret = krb5_unparse_name(context, entry_ex->entry.principal, &name);
	if (ret != 0) {
		talloc_free(tmp_ctx);
		return ret;
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

	nt_status = authsam_account_ok(tmp_ctx, 
				       private->samdb, 
				       MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT | MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT,
				       private->msg,
				       private->realm_ref_msg,
				       workstation,
				       name);
	free(name);

	if (NT_STATUS_IS_OK(nt_status))
		return 0;

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

	return ret;
}

