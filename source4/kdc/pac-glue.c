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
#include <ldb.h>
#include "auth/auth.h"
#include "auth/auth_sam_reply.h"
#include "kdc/kdc-glue.h"
#include "kdc/pac-glue.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/samdb.h"
#include "auth/kerberos/pac_utils.h"

static
NTSTATUS samba_get_logon_info_pac_blob(TALLOC_CTX *mem_ctx,
				       struct auth_user_info_dc *info,
				       DATA_BLOB *pac_data)
{
	struct netr_SamInfo3 *info3;
	union PAC_INFO pac_info;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	ZERO_STRUCT(pac_info);

	nt_status = auth_convert_user_info_dc_saminfo3(mem_ctx, info, &info3);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Getting Samba info failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	pac_info.logon_info.info = talloc_zero(mem_ctx, struct PAC_LOGON_INFO);
	if (!pac_info.logon_info.info) {
		return NT_STATUS_NO_MEMORY;
	}

	pac_info.logon_info.info->info3 = *info3;

	ndr_err = ndr_push_union_blob(pac_data, mem_ctx, &pac_info,
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
				    DATA_BLOB *deleg_blob,
				    krb5_pac *pac)
{
	krb5_data pac_data;
	krb5_data deleg_data;
	krb5_error_code ret;

        /* The user account may be set not to want the PAC */
	if (!pac_blob) {
		return 0;
	}

	ret = krb5_data_copy(&pac_data, pac_blob->data, pac_blob->length);
	if (ret != 0) {
		return ret;
	}

	ZERO_STRUCT(deleg_data);
	if (deleg_blob) {
		ret = krb5_data_copy(&deleg_data,
				     deleg_blob->data,
				     deleg_blob->length);
		if (ret != 0) {
			krb5_data_free(&pac_data);
			return ret;
		}
	}

	ret = krb5_pac_init(context, pac);
	if (ret != 0) {
		krb5_data_free(&pac_data);
		krb5_data_free(&deleg_data);
		return ret;
	}

	ret = krb5_pac_add_buffer(context, *pac, PAC_TYPE_LOGON_INFO, &pac_data);
	krb5_data_free(&pac_data);
	if (ret != 0) {
		krb5_data_free(&deleg_data);
		return ret;
	}

	if (deleg_blob) {
		ret = krb5_pac_add_buffer(context, *pac,
					  PAC_TYPE_CONSTRAINED_DELEGATION,
					  &deleg_data);
		krb5_data_free(&deleg_data);
		if (ret != 0) {
			return ret;
		}
	}

	return ret;
}

bool samba_princ_needs_pac(struct hdb_entry_ex *princ)
{

	struct samba_kdc_entry *p = talloc_get_type(princ->ctx, struct samba_kdc_entry);
	uint32_t userAccountControl;


	/* The service account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(p->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		return false;
	}

	return true;
}

/* Was the krbtgt in this DB (ie, should we check the incoming signature) and was it an RODC */
int samba_krbtgt_is_in_db(struct hdb_entry_ex *princ, bool *is_in_db, bool *is_untrusted)
{
	NTSTATUS status;
	struct samba_kdc_entry *p = talloc_get_type(princ->ctx, struct samba_kdc_entry);
	int rodc_krbtgt_number, trust_direction;
	uint32_t rid;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	if (!mem_ctx) {
		return ENOMEM;
	}
	
	trust_direction = ldb_msg_find_attr_as_int(p->msg, "trustDirection", 0);

	if (trust_direction != 0) {
		/* Domain trust - we cannot check the sig, but we trust it for a correct PAC
		   
		   This is exactly where we should flag for SID
		   validation when we do inter-foreest trusts
		 */
		talloc_free(mem_ctx);
		*is_untrusted = false;
		*is_in_db = false;
		return 0;
	}

	/* The lack of password controls etc applies to krbtgt by
	 * virtue of being that particular RID */
	status = dom_sid_split_rid(NULL, samdb_result_dom_sid(mem_ctx, p->msg, "objectSid"), NULL, &rid);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return EINVAL;
	}

	rodc_krbtgt_number = ldb_msg_find_attr_as_int(p->msg, "msDS-SecondaryKrbTgtNumber", -1);

	if (p->kdc_db_ctx->my_krbtgt_number == 0) {
		if (rid == DOMAIN_RID_KRBTGT) {
			*is_untrusted = false;
			*is_in_db = true;
			talloc_free(mem_ctx);
			return 0;
		} else if (rodc_krbtgt_number != -1) {
			*is_in_db = true;
			*is_untrusted = true;
			talloc_free(mem_ctx);
			return 0;
		}
	} else if ((rid != DOMAIN_RID_KRBTGT) && (rodc_krbtgt_number == p->kdc_db_ctx->my_krbtgt_number)) {
		talloc_free(mem_ctx);
		*is_untrusted = false;
		*is_in_db = true;
		return 0;
	} else if (rid == DOMAIN_RID_KRBTGT) {
		/* krbtgt viewed from an RODC */
		talloc_free(mem_ctx);
		*is_untrusted = false;
		*is_in_db = false;
		return 0;
	}

	/* Another RODC */
	talloc_free(mem_ctx);
	*is_untrusted = true;
	*is_in_db = false;
	return 0;
}

NTSTATUS samba_kdc_get_pac_blob(TALLOC_CTX *mem_ctx,
				struct hdb_entry_ex *client,
				DATA_BLOB **_pac_blob)
{
	struct samba_kdc_entry *p = talloc_get_type(client->ctx, struct samba_kdc_entry);
	struct auth_user_info_dc *user_info_dc;
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

	nt_status = authsam_make_user_info_dc(mem_ctx, p->kdc_db_ctx->samdb,
					     lpcfg_netbios_name(p->kdc_db_ctx->lp_ctx),
					     lpcfg_sam_name(p->kdc_db_ctx->lp_ctx),
					     p->realm_dn,
					     p->msg,
					     data_blob(NULL, 0),
					     data_blob(NULL, 0),
					     &user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Getting user info for PAC failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	nt_status = samba_get_logon_info_pac_blob(mem_ctx, user_info_dc, pac_blob);
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
				   const krb5_pac pac, DATA_BLOB *pac_blob,
				   struct PAC_SIGNATURE_DATA *pac_srv_sig,
				   struct PAC_SIGNATURE_DATA *pac_kdc_sig)
{
	struct auth_user_info_dc *user_info_dc;
	krb5_error_code ret;
	NTSTATUS nt_status;

	ret = kerberos_pac_to_user_info_dc(mem_ctx, pac,
					   context, &user_info_dc, pac_srv_sig, pac_kdc_sig);
	if (ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	nt_status = samba_get_logon_info_pac_blob(mem_ctx, 
						  user_info_dc, pac_blob);

	return nt_status;
}

NTSTATUS samba_kdc_update_delegation_info_blob(TALLOC_CTX *mem_ctx,
				krb5_context context,
				const krb5_pac pac,
				const krb5_principal server_principal,
				const krb5_principal proxy_principal,
				DATA_BLOB *new_blob)
{
	krb5_data old_data;
	DATA_BLOB old_blob;
	krb5_error_code ret;
	NTSTATUS nt_status;
	enum ndr_err_code ndr_err;
	union PAC_INFO info;
	struct PAC_CONSTRAINED_DELEGATION _d;
	struct PAC_CONSTRAINED_DELEGATION *d = NULL;
	char *server = NULL;
	char *proxy = NULL;
	uint32_t i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_CONSTRAINED_DELEGATION, &old_data);
	if (ret == ENOENT) {
		ZERO_STRUCT(old_data);
	} else if (ret) {
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	old_blob.length = old_data.length;
	old_blob.data = (uint8_t *)old_data.data;

	ZERO_STRUCT(info);
	if (old_blob.length > 0) {
		ndr_err = ndr_pull_union_blob(&old_blob, mem_ctx,
				&info, PAC_TYPE_CONSTRAINED_DELEGATION,
				(ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			krb5_data_free(&old_data);
			nt_status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(0,("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status)));
			talloc_free(tmp_ctx);
			return nt_status;
		}
	} else {
		ZERO_STRUCT(_d);
		info.constrained_delegation.info = &_d;
	}
	krb5_data_free(&old_data);

	ret = krb5_unparse_name(context, server_principal, &server);
	if (ret) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = krb5_unparse_name_flags(context, proxy_principal,
				      KRB5_PRINCIPAL_UNPARSE_NO_REALM, &proxy);
	if (ret) {
		SAFE_FREE(server);
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	d = info.constrained_delegation.info;
	i = d->num_transited_services;
	d->proxy_target.string = server;
	d->transited_services = talloc_realloc(mem_ctx, d->transited_services,
					       struct lsa_String, i + 1);
	d->transited_services[i].string = proxy;
	d->num_transited_services = i + 1;

	ndr_err = ndr_push_union_blob(new_blob, mem_ctx,
				&info, PAC_TYPE_CONSTRAINED_DELEGATION,
				(ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	SAFE_FREE(server);
	SAFE_FREE(proxy);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		krb5_data_free(&old_data);
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status)));
		talloc_free(tmp_ctx);
		return nt_status;
	}

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/* this function allocates 'data' using malloc.
 * The caller is responsible for freeing it */
void samba_kdc_build_edata_reply(NTSTATUS nt_status, DATA_BLOB *e_data)
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

/* function to map policy errors */
krb5_error_code samba_kdc_map_policy_err(NTSTATUS nt_status)
{
	krb5_error_code ret;

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

	return ret;
}

/* Given a kdc entry, consult the account_ok routine in auth/auth_sam.c
 * for consistency */
NTSTATUS samba_kdc_check_client_access(struct samba_kdc_entry *kdc_entry,
				       const char *client_name,
				       const char *workstation,
				       bool password_change)
{
	TALLOC_CTX *tmp_ctx;
	NTSTATUS nt_status;

	tmp_ctx = talloc_named(NULL, 0, "samba_kdc_check_client_access");
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* we allow all kinds of trusts here */
	nt_status = authsam_account_ok(tmp_ctx,
				       kdc_entry->kdc_db_ctx->samdb,
				       MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT |
				       MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT,
				       kdc_entry->realm_dn, kdc_entry->msg,
				       workstation, client_name,
				       true, password_change);

	talloc_free(tmp_ctx);
	return nt_status;
}

int kdc_check_pac(krb5_context context,
		  DATA_BLOB srv_sig,
		  struct PAC_SIGNATURE_DATA *kdc_sig,
		  hdb_entry_ex *ent)
{
	krb5_enctype etype;
	int ret;
	krb5_keyblock keyblock;
	Key *key;
	if (kdc_sig->type == CKSUMTYPE_HMAC_MD5) {
		etype = ETYPE_ARCFOUR_HMAC_MD5;
	} else {
		ret = krb5_cksumtype_to_enctype(context, 
						kdc_sig->type,
						&etype);
		if (ret != 0) {
			return ret;
		}
	}

#if HDB_ENCTYPE2KEY_TAKES_KEYSET
	ret = hdb_enctype2key(context, &ent->entry, NULL, etype, &key);
#else
	ret = hdb_enctype2key(context, &ent->entry, etype, &key);
#endif

	if (ret != 0) {
		return ret;
	}

	keyblock = key->key;

	return check_pac_checksum(srv_sig, kdc_sig,
				 context, &keyblock);
}



