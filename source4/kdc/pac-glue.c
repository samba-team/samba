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

#include "lib/replace/replace.h"
#include "lib/replace/system/kerberos.h"
#include "lib/replace/system/filesys.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/talloc_stack.h"

#include "auth/auth_sam_reply.h"
#include "auth/kerberos/kerberos.h"
#include "auth/kerberos/pac_utils.h"
#include "auth/authn_policy.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libds/common/flags.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "param/param.h"
#include "source4/auth/auth.h"
#include "source4/dsdb/common/util.h"
#include "source4/dsdb/samdb/samdb.h"
#include "source4/kdc/authn_policy_util.h"
#include "source4/kdc/samba_kdc.h"
#include "source4/kdc/pac-glue.h"
#include "source4/kdc/ad_claims.h"
#include "source4/kdc/pac-blobs.h"

#include <ldb.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_KERBEROS

static
NTSTATUS samba_get_logon_info_pac_blob(TALLOC_CTX *mem_ctx,
				       const struct auth_user_info_dc *info,
				       const struct PAC_DOMAIN_GROUP_MEMBERSHIP *override_resource_groups,
				       const enum auth_group_inclusion group_inclusion,
				       DATA_BLOB *pac_data)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct netr_SamInfo3 *info3 = NULL;
	struct PAC_DOMAIN_GROUP_MEMBERSHIP *_resource_groups = NULL;
	struct PAC_DOMAIN_GROUP_MEMBERSHIP **resource_groups = NULL;
	union PAC_INFO pac_info = {};
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status = NT_STATUS_OK;

	*pac_data = data_blob_null;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (override_resource_groups == NULL) {
		resource_groups = &_resource_groups;
	} else if (group_inclusion != AUTH_EXCLUDE_RESOURCE_GROUPS) {
		/*
		 * It doesn't make sense to override resource groups if we claim
		 * to want resource groups from user_info_dc.
		 */
		DBG_ERR("supplied resource groups with invalid group inclusion parameter: %u\n",
			group_inclusion);
		nt_status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	nt_status = auth_convert_user_info_dc_saminfo3(tmp_ctx, info,
						       group_inclusion,
						       &info3,
						       resource_groups);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_WARNING("Getting Samba info failed: %s\n",
			    nt_errstr(nt_status));
		goto out;
	}

	pac_info.logon_info.info = talloc_zero(tmp_ctx, struct PAC_LOGON_INFO);
	if (!pac_info.logon_info.info) {
		nt_status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	pac_info.logon_info.info->info3 = *info3;
	if (_resource_groups != NULL) {
		pac_info.logon_info.info->resource_groups = *_resource_groups;
	}

	if (override_resource_groups != NULL) {
		pac_info.logon_info.info->resource_groups = *override_resource_groups;
	}

	if (group_inclusion != AUTH_EXCLUDE_RESOURCE_GROUPS) {
		/*
		 * Set the resource groups flag based on whether any groups are
		 * present. Otherwise, the flag is propagated from the
		 * originating PAC.
		 */
		if (pac_info.logon_info.info->resource_groups.groups.count > 0) {
			pac_info.logon_info.info->info3.base.user_flags |= NETLOGON_RESOURCE_GROUPS;
		} else {
			pac_info.logon_info.info->info3.base.user_flags &= ~NETLOGON_RESOURCE_GROUPS;
		}
	}

	ndr_err = ndr_push_union_blob(pac_data, mem_ctx, &pac_info,
				      PAC_TYPE_LOGON_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("PAC_LOGON_INFO (presig) push failed: %s\n",
			    nt_errstr(nt_status));
		goto out;
	}

out:
	talloc_free(tmp_ctx);
	return nt_status;
}

static
NTSTATUS samba_get_upn_info_pac_blob(TALLOC_CTX *mem_ctx,
				     const struct auth_user_info_dc *info,
				     DATA_BLOB *upn_data)
{
	TALLOC_CTX *tmp_ctx = NULL;
	union PAC_INFO pac_upn = {};
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status = NT_STATUS_OK;
	bool ok;

	*upn_data = data_blob_null;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pac_upn.upn_dns_info.upn_name = info->info->user_principal_name;
	pac_upn.upn_dns_info.dns_domain_name = strupper_talloc(tmp_ctx,
						info->info->dns_domain_name);
	if (pac_upn.upn_dns_info.dns_domain_name == NULL) {
		nt_status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	if (info->info->user_principal_constructed) {
		pac_upn.upn_dns_info.flags |= PAC_UPN_DNS_FLAG_CONSTRUCTED;
	}

	pac_upn.upn_dns_info.flags |= PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID;

	pac_upn.upn_dns_info.ex.sam_name_and_sid.samaccountname
		= info->info->account_name;

	pac_upn.upn_dns_info.ex.sam_name_and_sid.objectsid
		= &info->sids[PRIMARY_USER_SID_INDEX].sid;

	ndr_err = ndr_push_union_blob(upn_data, mem_ctx, &pac_upn,
				      PAC_TYPE_UPN_DNS_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("PAC UPN_DNS_INFO (presig) push failed: %s\n",
			    nt_errstr(nt_status));
		goto out;
	}

	ok = data_blob_pad(mem_ctx, upn_data, 8);
	if (!ok) {
		talloc_free(upn_data);
		nt_status = NT_STATUS_NO_MEMORY;
		goto out;
	}

out:
	talloc_free(tmp_ctx);
	return nt_status;
}

static
NTSTATUS samba_get_cred_info_ndr_blob(TALLOC_CTX *mem_ctx,
				      const struct ldb_message *msg,
				      DATA_BLOB *cred_blob)
{
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;
	struct samr_Password *lm_hash = NULL;
	struct samr_Password *nt_hash = NULL;
	struct PAC_CREDENTIAL_NTLM_SECPKG ntlm_secpkg = {
		.version = 0,
	};
	DATA_BLOB ntlm_blob = data_blob_null;
	struct PAC_CREDENTIAL_SUPPLEMENTAL_SECPKG secpkgs[1] = {{
		.credential_size = 0,
	}};
	struct PAC_CREDENTIAL_DATA cred_data = {
		.credential_count = 0,
	};
	struct PAC_CREDENTIAL_DATA_NDR cred_ndr = {};

	*cred_blob = data_blob_null;

	lm_hash = samdb_result_hash(mem_ctx, msg, "dBCSPwd");
	if (lm_hash != NULL) {
		bool zero = all_zero(lm_hash->hash, 16);
		if (zero) {
			lm_hash = NULL;
		}
	}
	if (lm_hash != NULL) {
		DBG_INFO("Passing LM password hash through credentials set\n");
		ntlm_secpkg.flags |= PAC_CREDENTIAL_NTLM_HAS_LM_HASH;
		ntlm_secpkg.lm_password = *lm_hash;
		ZERO_STRUCTP(lm_hash);
		TALLOC_FREE(lm_hash);
	}

	nt_hash = samdb_result_hash(mem_ctx, msg, "unicodePwd");
	if (nt_hash != NULL) {
		bool zero = all_zero(nt_hash->hash, 16);
		if (zero) {
			nt_hash = NULL;
		}
	}
	if (nt_hash != NULL) {
		DBG_INFO("Passing NT password hash through credentials set\n");
		ntlm_secpkg.flags |= PAC_CREDENTIAL_NTLM_HAS_NT_HASH;
		ntlm_secpkg.nt_password = *nt_hash;
		ZERO_STRUCTP(nt_hash);
		TALLOC_FREE(nt_hash);
	}

	if (ntlm_secpkg.flags == 0) {
		return NT_STATUS_OK;
	}

#ifdef DEBUG_PASSWORD
	if (DEBUGLVL(11)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_NTLM_SECPKG, &ntlm_secpkg);
	}
#endif

	ndr_err = ndr_push_struct_blob(&ntlm_blob, mem_ctx, &ntlm_secpkg,
			(ndr_push_flags_fn_t)ndr_push_PAC_CREDENTIAL_NTLM_SECPKG);
	ZERO_STRUCT(ntlm_secpkg);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("PAC_CREDENTIAL_NTLM_SECPKG (presig) push failed: %s\n",
			    nt_errstr(nt_status));
		return nt_status;
	}

	DBG_DEBUG("NTLM credential BLOB (len %zu) for user\n",
		  ntlm_blob.length);
	dump_data_pw("PAC_CREDENTIAL_NTLM_SECPKG",
		     ntlm_blob.data, ntlm_blob.length);

	secpkgs[0].package_name.string = discard_const_p(char, "NTLM");
	secpkgs[0].credential_size = ntlm_blob.length;
	secpkgs[0].credential = ntlm_blob.data;

	cred_data.credential_count = ARRAY_SIZE(secpkgs);
	cred_data.credentials = secpkgs;

#ifdef DEBUG_PASSWORD
	if (DEBUGLVL(11)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_DATA, &cred_data);
	}
#endif

	cred_ndr.ctr.data = &cred_data;

#ifdef DEBUG_PASSWORD
	if (DEBUGLVL(11)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_DATA_NDR, &cred_ndr);
	}
#endif

	ndr_err = ndr_push_struct_blob(cred_blob, mem_ctx, &cred_ndr,
			(ndr_push_flags_fn_t)ndr_push_PAC_CREDENTIAL_DATA_NDR);
	data_blob_clear(&ntlm_blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("PAC_CREDENTIAL_DATA_NDR (presig) push failed: %s\n",
			    nt_errstr(nt_status));
		return nt_status;
	}

	DBG_DEBUG("Created credential BLOB (len %zu) for user\n",
		  cred_blob->length);
	dump_data_pw("PAC_CREDENTIAL_DATA_NDR",
		     cred_blob->data, cred_blob->length);

	return NT_STATUS_OK;
}

static
krb5_error_code samba_kdc_encrypt_pac_credentials(krb5_context context,
						  const krb5_keyblock *pkreplykey,
						  const DATA_BLOB *cred_ndr_blob,
						  TALLOC_CTX *mem_ctx,
						  DATA_BLOB *cred_info_blob)
{
#ifdef SAMBA4_USES_HEIMDAL
	krb5_crypto cred_crypto;
	krb5_enctype cred_enctype;
	krb5_data cred_ndr_crypt;
	struct PAC_CREDENTIAL_INFO pac_cred_info = { .version = 0, };
	krb5_error_code ret;
	const char *krb5err;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	*cred_info_blob = data_blob_null;

	ret = krb5_crypto_init(context, pkreplykey, ETYPE_NULL,
			       &cred_crypto);
	if (ret != 0) {
		krb5err = krb5_get_error_message(context, ret);
		DBG_WARNING("Failed initializing cred data crypto: %s\n", krb5err);
		krb5_free_error_message(context, krb5err);
		return ret;
	}

	ret = krb5_crypto_getenctype(context, cred_crypto, &cred_enctype);
	if (ret != 0) {
		DBG_WARNING("Failed getting crypto type for key\n");
		krb5_crypto_destroy(context, cred_crypto);
		return ret;
	}

	DBG_DEBUG("Plain cred_ndr_blob (len %zu)\n",
		  cred_ndr_blob->length);
	dump_data_pw("PAC_CREDENTIAL_DATA_NDR",
		     cred_ndr_blob->data, cred_ndr_blob->length);

	ret = krb5_encrypt(context, cred_crypto,
			   KRB5_KU_OTHER_ENCRYPTED,
			   cred_ndr_blob->data, cred_ndr_blob->length,
			   &cred_ndr_crypt);
	krb5_crypto_destroy(context, cred_crypto);
	if (ret != 0) {
		krb5err = krb5_get_error_message(context, ret);
		DBG_WARNING("Failed crypt of cred data: %s\n", krb5err);
		krb5_free_error_message(context, krb5err);
		return ret;
	}

	pac_cred_info.encryption_type = cred_enctype;
	pac_cred_info.encrypted_data.length = cred_ndr_crypt.length;
	pac_cred_info.encrypted_data.data = (uint8_t *)cred_ndr_crypt.data;

	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_INFO, &pac_cred_info);
	}

	ndr_err = ndr_push_struct_blob(cred_info_blob, mem_ctx, &pac_cred_info,
			(ndr_push_flags_fn_t)ndr_push_PAC_CREDENTIAL_INFO);
	krb5_data_free(&cred_ndr_crypt);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("PAC_CREDENTIAL_INFO (presig) push failed: %s\n",
			    nt_errstr(nt_status));
		return KRB5KDC_ERR_SVC_UNAVAILABLE;
	}

	DBG_DEBUG("Encrypted credential BLOB (len %zu) with alg %"PRId32"\n",
		  cred_info_blob->length, pac_cred_info.encryption_type);
	dump_data_pw("PAC_CREDENTIAL_INFO",
		      cred_info_blob->data, cred_info_blob->length);

	return 0;
#else /* SAMBA4_USES_HEIMDAL */
	TALLOC_CTX *tmp_ctx = NULL;
	krb5_key cred_key;
	krb5_enctype cred_enctype;
	struct PAC_CREDENTIAL_INFO pac_cred_info = { .version = 0, };
	krb5_error_code code = 0;
	const char *krb5err;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;
	krb5_data cred_ndr_data;
	krb5_enc_data cred_ndr_crypt;
	size_t enc_len = 0;

	*cred_info_blob = data_blob_null;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	code = krb5_k_create_key(context,
				 pkreplykey,
				 &cred_key);
	if (code != 0) {
		krb5err = krb5_get_error_message(context, code);
		DBG_WARNING("Failed initializing cred data crypto: %s\n", krb5err);
		krb5_free_error_message(context, krb5err);
		goto out;
	}

	cred_enctype = krb5_k_key_enctype(context, cred_key);

	DBG_DEBUG("Plain cred_ndr_blob (len %zu)\n",
		  cred_ndr_blob->length);
	dump_data_pw("PAC_CREDENTIAL_DATA_NDR",
		     cred_ndr_blob->data, cred_ndr_blob->length);

	pac_cred_info.encryption_type = cred_enctype;

	cred_ndr_data = smb_krb5_data_from_blob(*cred_ndr_blob);

	code = krb5_c_encrypt_length(context,
				     cred_enctype,
				     cred_ndr_data.length,
				     &enc_len);
	if (code != 0) {
		krb5err = krb5_get_error_message(context, code);
		DBG_WARNING("Failed initializing cred data crypto: %s\n", krb5err);
		krb5_free_error_message(context, krb5err);
		goto out;
	}

	pac_cred_info.encrypted_data = data_blob_talloc_zero(tmp_ctx, enc_len);
	if (pac_cred_info.encrypted_data.data == NULL) {
		DBG_ERR("Out of memory\n");
		code = ENOMEM;
		goto out;
	}

	cred_ndr_crypt.ciphertext = smb_krb5_data_from_blob(pac_cred_info.encrypted_data);

	code = krb5_k_encrypt(context,
			      cred_key,
			      KRB5_KU_OTHER_ENCRYPTED,
			      NULL,
			      &cred_ndr_data,
			      &cred_ndr_crypt);
	krb5_k_free_key(context, cred_key);
	if (code != 0) {
		krb5err = krb5_get_error_message(context, code);
		DBG_WARNING("Failed crypt of cred data: %s\n", krb5err);
		krb5_free_error_message(context, krb5err);
		goto out;
	}

	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_INFO, &pac_cred_info);
	}

	ndr_err = ndr_push_struct_blob(cred_info_blob, mem_ctx, &pac_cred_info,
			(ndr_push_flags_fn_t)ndr_push_PAC_CREDENTIAL_INFO);
	TALLOC_FREE(pac_cred_info.encrypted_data.data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("PAC_CREDENTIAL_INFO (presig) push failed: %s\n",
			    nt_errstr(nt_status));
		code = KRB5KDC_ERR_SVC_UNAVAILABLE;
		goto out;
	}

	DBG_DEBUG("Encrypted credential BLOB (len %zu) with alg %"PRId32"\n",
		  cred_info_blob->length, pac_cred_info.encryption_type);
	dump_data_pw("PAC_CREDENTIAL_INFO",
		      cred_info_blob->data, cred_info_blob->length);

out:
	talloc_free(tmp_ctx);
	return code;
#endif /* SAMBA4_USES_HEIMDAL */
}


/**
 * @brief Create a PAC with the given blobs (logon, credentials, upn and
 * delegation).
 *
 * @param[in] context   The KRB5 context to use.
 *
 * @param[in] logon_blob Fill the logon info PAC buffer with the given blob,
 *                       use NULL to ignore it.
 *
 * @param[in] cred_blob  Fill the credentials info PAC buffer with the given
 *                       blob, use NULL to ignore it.
 *
 * @param[in] upn_blob  Fill the UPN info PAC buffer with the given blob, use
 *                      NULL to ignore it.
 *
 * @param[in] deleg_blob Fill the delegation info PAC buffer with the given
 *                       blob, use NULL to ignore it.
 *
 * @param[in] client_claims_blob Fill the client claims info PAC buffer with the
 *                               given blob, use NULL to ignore it.
 *
 * @param[in] device_info_blob Fill the device info PAC buffer with the given
 *                             blob, use NULL to ignore it.
 *
 * @param[in] device_claims_blob Fill the device claims info PAC buffer with the given
 *                               blob, use NULL to ignore it.
 *
 * @param[in] pac        The pac buffer to fill. This should be allocated with
 *                       krb5_pac_init() already.
 *
 * @returns 0 on success or a corresponding KRB5 error.
 */
static
krb5_error_code samba_make_krb5_pac(krb5_context context,
				    const DATA_BLOB *logon_blob,
				    const DATA_BLOB *cred_blob,
				    const DATA_BLOB *upn_blob,
				    const DATA_BLOB *pac_attrs_blob,
				    const DATA_BLOB *requester_sid_blob,
				    const DATA_BLOB *deleg_blob,
				    const DATA_BLOB *client_claims_blob,
				    const DATA_BLOB *device_info_blob,
				    const DATA_BLOB *device_claims_blob,
				    krb5_pac pac)
{
	krb5_data logon_data;
	krb5_error_code ret;
	char null_byte = '\0';
	krb5_data null_data = smb_krb5_make_data(&null_byte, 0);

	/* The user account may be set not to want the PAC */
	if (logon_blob == NULL) {
		return 0;
	}

	logon_data = smb_krb5_data_from_blob(*logon_blob);
	ret = krb5_pac_add_buffer(context, pac, PAC_TYPE_LOGON_INFO, &logon_data);
	if (ret != 0) {
		return ret;
	}

	if (device_info_blob != NULL) {
		krb5_data device_info_data = smb_krb5_data_from_blob(*device_info_blob);
		ret = krb5_pac_add_buffer(context, pac,
					  PAC_TYPE_DEVICE_INFO,
					  &device_info_data);
		if (ret != 0) {
			return ret;
		}
	}

	if (client_claims_blob != NULL) {
		krb5_data client_claims_data;
		krb5_data *data = NULL;

		if (client_claims_blob->length != 0) {
			client_claims_data = smb_krb5_data_from_blob(*client_claims_blob);
			data = &client_claims_data;
		} else {
			data = &null_data;
		}

		ret = krb5_pac_add_buffer(context, pac,
					  PAC_TYPE_CLIENT_CLAIMS_INFO,
					  data);
		if (ret != 0) {
			return ret;
		}
	}

	if (device_claims_blob != NULL) {
		krb5_data device_claims_data = smb_krb5_data_from_blob(*device_claims_blob);
		ret = krb5_pac_add_buffer(context, pac,
					  PAC_TYPE_DEVICE_CLAIMS_INFO,
					  &device_claims_data);
		if (ret != 0) {
			return ret;
		}
	}

	if (cred_blob != NULL) {
		krb5_data cred_data = smb_krb5_data_from_blob(*cred_blob);
		ret = krb5_pac_add_buffer(context, pac,
					  PAC_TYPE_CREDENTIAL_INFO,
					  &cred_data);
		if (ret != 0) {
			return ret;
		}
	}

#ifdef SAMBA4_USES_HEIMDAL
	/*
	 * null_data will be filled by the generic KDC code in the caller
	 * here we just add it in order to have it before
	 * PAC_TYPE_UPN_DNS_INFO
	 *
	 * Not needed with MIT Kerberos - asn
	 */
	ret = krb5_pac_add_buffer(context, pac,
				  PAC_TYPE_LOGON_NAME,
				  &null_data);
	if (ret != 0) {
		return ret;
	}
#endif

	if (upn_blob != NULL) {
		krb5_data upn_data = smb_krb5_data_from_blob(*upn_blob);
		ret = krb5_pac_add_buffer(context, pac,
					  PAC_TYPE_UPN_DNS_INFO,
					  &upn_data);
		if (ret != 0) {
			return ret;
		}
	}

	if (pac_attrs_blob != NULL) {
		krb5_data pac_attrs_data = smb_krb5_data_from_blob(*pac_attrs_blob);
		ret = krb5_pac_add_buffer(context, pac,
					  PAC_TYPE_ATTRIBUTES_INFO,
					  &pac_attrs_data);
		if (ret != 0) {
			return ret;
		}
	}

	if (requester_sid_blob != NULL) {
		krb5_data requester_sid_data = smb_krb5_data_from_blob(*requester_sid_blob);
		ret = krb5_pac_add_buffer(context, pac,
					  PAC_TYPE_REQUESTER_SID,
					  &requester_sid_data);
		if (ret != 0) {
			return ret;
		}
	}

	if (deleg_blob != NULL) {
		krb5_data deleg_data = smb_krb5_data_from_blob(*deleg_blob);
		ret = krb5_pac_add_buffer(context, pac,
					  PAC_TYPE_CONSTRAINED_DELEGATION,
					  &deleg_data);
		if (ret != 0) {
			return ret;
		}
	}

	return ret;
}

bool samba_princ_needs_pac(const struct samba_kdc_entry *skdc_entry)
{

	uint32_t userAccountControl;

	/* The service account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(skdc_entry->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		return false;
	}

	return true;
}

static krb5_error_code samba_client_requested_pac(krb5_context context,
						  const krb5_const_pac pac,
						  TALLOC_CTX *mem_ctx,
						  bool *requested_pac)
{
	enum ndr_err_code ndr_err;
	krb5_data k5pac_attrs_in;
	DATA_BLOB pac_attrs_in;
	union PAC_INFO pac_attrs;
	krb5_error_code ret;

	*requested_pac = true;

	ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_ATTRIBUTES_INFO,
				  &k5pac_attrs_in);
	if (ret != 0) {
		return ret == ENOENT ? 0 : ret;
	}

	pac_attrs_in = data_blob_const(k5pac_attrs_in.data,
				       k5pac_attrs_in.length);

	ndr_err = ndr_pull_union_blob(&pac_attrs_in, mem_ctx, &pac_attrs,
				      PAC_TYPE_ATTRIBUTES_INFO,
				      (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
	smb_krb5_free_data_contents(context, &k5pac_attrs_in);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("can't parse the PAC ATTRIBUTES_INFO: %s\n", nt_errstr(nt_status));
		return map_errno_from_nt_status(nt_status);
	}

	if (pac_attrs.attributes_info.flags & (PAC_ATTRIBUTE_FLAG_PAC_WAS_GIVEN_IMPLICITLY
					       | PAC_ATTRIBUTE_FLAG_PAC_WAS_REQUESTED)) {
		*requested_pac = true;
	} else {
		*requested_pac = false;
	}

	return 0;
}

/* Was the krbtgt in this DB (ie, should we check the incoming signature) and was it an RODC */
krb5_error_code samba_krbtgt_is_in_db(const struct samba_kdc_entry *p,
				      bool *is_in_db,
				      bool *is_trusted)
{
	NTSTATUS status;
	krb5_error_code ret;
	int rodc_krbtgt_number, trust_direction;
	struct dom_sid sid;
	uint32_t rid;

	trust_direction = ldb_msg_find_attr_as_int(p->msg, "trustDirection", 0);

	if (trust_direction != 0) {
		/* Domain trust - we cannot check the sig, but we trust it for a correct PAC

		   This is exactly where we should flag for SID
		   validation when we do inter-forest trusts
		 */
		*is_trusted = true;
		*is_in_db = false;
		return 0;
	}

	/* The lack of password controls etc applies to krbtgt by
	 * virtue of being that particular RID */
	ret = samdb_result_dom_sid_buf(p->msg, "objectSid", &sid);
	if (ret) {
		return ret;
	}

	status = dom_sid_split_rid(NULL, &sid, NULL, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		return map_errno_from_nt_status(status);
	}

	rodc_krbtgt_number = ldb_msg_find_attr_as_int(p->msg, "msDS-SecondaryKrbTgtNumber", -1);

	if (p->kdc_db_ctx->my_krbtgt_number == 0) {
		if (rid == DOMAIN_RID_KRBTGT) {
			*is_trusted = true;
			*is_in_db = true;
			return 0;
		} else if (rodc_krbtgt_number != -1) {
			*is_in_db = true;
			*is_trusted = false;
			return 0;
		}
	} else if ((rid != DOMAIN_RID_KRBTGT) && (rodc_krbtgt_number == p->kdc_db_ctx->my_krbtgt_number)) {
		*is_trusted = true;
		*is_in_db = true;
		return 0;
	} else if (rid == DOMAIN_RID_KRBTGT) {
		/* krbtgt viewed from an RODC */
		*is_trusted = true;
		*is_in_db = false;
		return 0;
	}

	/* Another RODC */
	*is_trusted = false;
	*is_in_db = false;
	return 0;
}

/*
 * Because the KDC does not limit protocol transition, two new well-known SIDs
 * were introduced to give this control to the resource administrator. These
 * SIDs identify whether protocol transition has occurred, and can be used with
 * standard access control lists to grant or limit access as needed.
 *
 * https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview
 */
static
NTSTATUS samba_kdc_add_asserted_identity(enum samba_asserted_identity ai,
					 struct auth_user_info_dc *user_info_dc)
{
	const struct dom_sid *ai_sid = NULL;

	switch (ai) {
	case SAMBA_ASSERTED_IDENTITY_SERVICE:
		ai_sid = &global_sid_Asserted_Identity_Service;
		break;
	case SAMBA_ASSERTED_IDENTITY_AUTHENTICATION_AUTHORITY:
		ai_sid = &global_sid_Asserted_Identity_Authentication_Authority;
		break;
	case SAMBA_ASSERTED_IDENTITY_IGNORE:
		return NT_STATUS_OK;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	return add_sid_to_array_attrs_unique(
		user_info_dc,
		ai_sid,
		SE_GROUP_DEFAULT_FLAGS,
		&user_info_dc->sids,
		&user_info_dc->num_sids);
}

static
NTSTATUS samba_kdc_add_claims_valid(struct auth_user_info_dc *user_info_dc)
{
	return add_sid_to_array_attrs_unique(
		user_info_dc,
		&global_sid_Claims_Valid,
		SE_GROUP_DEFAULT_FLAGS,
		&user_info_dc->sids,
		&user_info_dc->num_sids);
}

static
NTSTATUS samba_kdc_add_fresh_public_key_identity(struct auth_user_info_dc *user_info_dc)
{
	return add_sid_to_array_attrs_unique(
		user_info_dc,
		&global_sid_Fresh_Public_Key_Identity,
		SE_GROUP_DEFAULT_FLAGS,
		&user_info_dc->sids,
		&user_info_dc->num_sids);
}

static NTSTATUS samba_kdc_add_compounded_auth(struct auth_user_info_dc *user_info_dc)
{
	return add_sid_to_array_attrs_unique(
		user_info_dc,
		&global_sid_Compounded_Authentication,
		SE_GROUP_DEFAULT_FLAGS,
		&user_info_dc->sids,
		&user_info_dc->num_sids);
}

static bool samba_kdc_entry_is_trust(const struct samba_kdc_entry *entry)
{
	return entry != NULL && entry->is_trust;
}

/*
 * Return true if this entry has an associated PAC issued or signed by a KDC
 * that our KDC trusts. We trust the main krbtgt account, but we don’t trust any
 * RODC krbtgt besides ourselves.
 */
static bool samba_krb5_pac_is_trusted(const struct samba_kdc_entry_pac pac)
{
	if (pac.pac == NULL) {
		return false;
	}

#ifdef HAVE_KRB5_PAC_IS_TRUSTED /* Heimdal */
	return krb5_pac_is_trusted(pac.pac);
#else /* MIT */
	return pac.pac_is_trusted;
#endif /* HAVE_KRB5_PAC_IS_TRUSTED */
}

#ifdef HAVE_KRB5_PAC_IS_TRUSTED /* Heimdal */
struct samba_kdc_entry_pac samba_kdc_entry_pac(krb5_const_pac pac,
					       struct samba_kdc_entry *entry,
					       const struct samba_kdc_entry *krbtgt)
{
	return (struct samba_kdc_entry_pac) {
		.entry = entry,
		.krbtgt = krbtgt,
		.pac = pac,
	};
}
#else /* MIT */
struct samba_kdc_entry_pac samba_kdc_entry_pac_from_trusted(krb5_const_pac pac,
							    struct samba_kdc_entry *entry,
							    const struct samba_kdc_entry *krbtgt,
							    bool is_trusted)
{
	return (struct samba_kdc_entry_pac) {
		.entry = entry,
		.krbtgt = krbtgt,
		.pac = pac,
		.pac_is_trusted = is_trusted,
	};
}
#endif /* HAVE_KRB5_PAC_IS_TRUSTED */

static bool samba_kdc_entry_pac_issued_by_trust(const struct samba_kdc_entry_pac entry)
{
	return entry.pac != NULL && samba_kdc_entry_is_trust(entry.krbtgt);
}

/*
 * Return true if a principal is represented.
 *
 * This only returns false if the following are
 * all NULL pointers:
 *
 * struct samba_kdc_entry *entry;
 * const struct samba_kdc_entry *krbtgt;
 * krb5_const_pac pac;
 *
 * This should only for a 'device_pac_entry' if FAST was not used
 * and there's no decive ticket. Or similar cases where it
 * represents optional things.
 */
static bool samba_kdc_entry_pac_valid_principal(
		const struct samba_kdc_entry_pac entry)
{
	return entry.pac != NULL || entry.entry != NULL || entry.krbtgt != NULL;
}

static
NTSTATUS samba_kdc_get_logon_info_blob(TALLOC_CTX *mem_ctx,
				       const struct auth_user_info_dc *user_info_dc,
				       const enum auth_group_inclusion group_inclusion,
				       DATA_BLOB **_logon_info_blob)
{
	DATA_BLOB *logon_blob = NULL;
	NTSTATUS nt_status;

	*_logon_info_blob = NULL;

	logon_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (logon_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = samba_get_logon_info_pac_blob(logon_blob,
						  user_info_dc,
						  NULL,
						  group_inclusion,
						  logon_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("Building PAC LOGON INFO failed: %s\n",
			nt_errstr(nt_status));
		talloc_free(logon_blob);
		return nt_status;
	}

	*_logon_info_blob = logon_blob;

	return NT_STATUS_OK;
}

static
NTSTATUS samba_kdc_get_cred_ndr_blob(TALLOC_CTX *mem_ctx,
				     const struct samba_kdc_entry *p,
				     DATA_BLOB **_cred_ndr_blob)
{
	DATA_BLOB *cred_blob = NULL;
	NTSTATUS nt_status;

	SMB_ASSERT(_cred_ndr_blob != NULL);

	*_cred_ndr_blob = NULL;

	cred_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (cred_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = samba_get_cred_info_ndr_blob(cred_blob,
						 p->msg,
						 cred_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("Building PAC CRED INFO failed: %s\n",
			nt_errstr(nt_status));
		talloc_free(cred_blob);
		return nt_status;
	}

	*_cred_ndr_blob = cred_blob;

	return NT_STATUS_OK;
}

static
NTSTATUS samba_kdc_get_upn_info_blob(TALLOC_CTX *mem_ctx,
				     const struct auth_user_info_dc *user_info_dc,
				     DATA_BLOB **_upn_info_blob)
{
	DATA_BLOB *upn_blob = NULL;
	NTSTATUS nt_status;

	*_upn_info_blob = NULL;

	upn_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (upn_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = samba_get_upn_info_pac_blob(upn_blob,
						user_info_dc,
						upn_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("Building PAC UPN INFO failed: %s\n",
			nt_errstr(nt_status));
		talloc_free(upn_blob);
		return nt_status;
	}

	*_upn_info_blob = upn_blob;

	return NT_STATUS_OK;
}

static
NTSTATUS samba_kdc_get_pac_attrs_blob(TALLOC_CTX *mem_ctx,
				      uint64_t pac_attributes,
				      DATA_BLOB **_pac_attrs_blob)
{
	DATA_BLOB *pac_attrs_blob = NULL;
	union PAC_INFO pac_attrs = {};
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	SMB_ASSERT(_pac_attrs_blob != NULL);

	*_pac_attrs_blob = NULL;

	pac_attrs_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (pac_attrs_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Set the length of the flags in bits. */
	pac_attrs.attributes_info.flags_length = 2;
	pac_attrs.attributes_info.flags = pac_attributes;

	ndr_err = ndr_push_union_blob(pac_attrs_blob, pac_attrs_blob, &pac_attrs,
				      PAC_TYPE_ATTRIBUTES_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("PAC ATTRIBUTES_INFO (presig) push failed: %s\n",
			    nt_errstr(nt_status));
		DBG_ERR("Building PAC ATTRIBUTES failed: %s\n",
			nt_errstr(nt_status));

		talloc_free(pac_attrs_blob);
		return nt_status;
	}

	*_pac_attrs_blob = pac_attrs_blob;

	return NT_STATUS_OK;
}

static
NTSTATUS samba_kdc_get_requester_sid_blob(TALLOC_CTX *mem_ctx,
					  const struct auth_user_info_dc *user_info_dc,
					  DATA_BLOB **_requester_sid_blob)
{
	DATA_BLOB *requester_sid_blob = NULL;
	NTSTATUS nt_status;

	SMB_ASSERT(_requester_sid_blob != NULL);

	*_requester_sid_blob = NULL;

	requester_sid_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (requester_sid_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (user_info_dc->num_sids > 0) {
		union PAC_INFO pac_requester_sid = {};
		enum ndr_err_code ndr_err;

		pac_requester_sid.requester_sid.sid = user_info_dc->sids[PRIMARY_USER_SID_INDEX].sid;

		ndr_err = ndr_push_union_blob(requester_sid_blob, requester_sid_blob,
					      &pac_requester_sid,
					      PAC_TYPE_REQUESTER_SID,
					      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			nt_status = ndr_map_error2ntstatus(ndr_err);
			DBG_WARNING("PAC_REQUESTER_SID (presig) push failed: %s\n",
				    nt_errstr(nt_status));
			DBG_ERR("Building PAC REQUESTER SID failed: %s\n",
				nt_errstr(nt_status));

			talloc_free(requester_sid_blob);
			return nt_status;
		}
	}

	*_requester_sid_blob = requester_sid_blob;

	return NT_STATUS_OK;
}

static
krb5_error_code samba_kdc_get_claims_data_from_db(struct ldb_context *samdb,
						  struct samba_kdc_entry *entry,
						  struct claims_data **claims_data_out);

static
NTSTATUS samba_kdc_get_claims_blob(TALLOC_CTX *mem_ctx,
				   struct claims_data *claims_data,
				   const DATA_BLOB **_claims_blob)
{
	DATA_BLOB *claims_blob = NULL;
	NTSTATUS nt_status;

	SMB_ASSERT(_claims_blob != NULL);

	*_claims_blob = NULL;

	claims_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (claims_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = claims_data_encoded_claims_set(claims_blob,
						   claims_data,
						   claims_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(claims_blob);
		return nt_status;
	}

	*_claims_blob = claims_blob;

	return NT_STATUS_OK;
}

krb5_error_code samba_kdc_get_user_info_from_db(TALLOC_CTX *mem_ctx,
						struct samba_kdc_db_context *kdc_db_ctx,
						struct samba_kdc_entry *entry,
						const struct ldb_message *msg,
						const struct auth_user_info_dc **info_out)
{
	NTSTATUS nt_status;

	if (kdc_db_ctx == NULL) {
		return EINVAL;
	}

	if (msg == NULL) {
		return EINVAL;
	}

	if (info_out == NULL) {
		return EINVAL;
	}

	if (entry == NULL) {
		return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	}

	*info_out = NULL;

	if (entry->info_from_db == NULL) {
		struct auth_user_info_dc *info_from_db = NULL;
		struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;

		nt_status = authsam_make_user_info_dc(entry,
						      kdc_db_ctx->samdb,
						      lpcfg_netbios_name(lp_ctx),
						      lpcfg_sam_name(lp_ctx),
						      lpcfg_sam_dnsname(lp_ctx),
						      entry->realm_dn,
						      msg,
						      data_blob_null,
						      data_blob_null,
						      &info_from_db);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("Getting user info for PAC failed: %s\n",
				nt_errstr(nt_status));
			/* NT_STATUS_OBJECT_NAME_NOT_FOUND is mapped to ENOENT. */
			return map_errno_from_nt_status(nt_status);
		}

		entry->info_from_db = info_from_db;
	}

	*info_out = entry->info_from_db;

	return 0;
}

/*
 * Check whether a PAC contains the Authentication Authority Asserted Identity
 * SID.
 */
static krb5_error_code samba_kdc_pac_contains_asserted_identity(
	krb5_context context,
	const struct samba_kdc_entry_pac entry,
	bool *contains_out)
{
	TALLOC_CTX *frame = NULL;
	struct auth_user_info_dc *info = NULL;
	krb5_error_code ret = 0;

	if (contains_out == NULL) {
		ret = EINVAL;
		goto out;
	}
	*contains_out = false;

	frame = talloc_stackframe();

	/*
	 * Extract our info from the PAC. This does a bit of unnecessary work,
	 * setting up fields we don’t care about — we only want the SIDs.
	 */
	ret = kerberos_pac_to_user_info_dc(frame,
					   entry.pac,
					   context,
					   &info,
					   AUTH_EXCLUDE_RESOURCE_GROUPS,
					   NULL /* pac_srv_sig */,
					   NULL /* pac_kdc_sig */,
					   /* Ignore the resource groups. */
					   NULL /* resource_groups */);
	if (ret) {
		const char *krb5err = krb5_get_error_message(context, ret);
		DBG_ERR("kerberos_pac_to_user_info_dc failed: %s\n",
			krb5err != NULL ? krb5err : "?");
		krb5_free_error_message(context, krb5err);

		goto out;
	}

	/* Determine whether the PAC contains the Asserted Identity SID. */
	*contains_out = sid_attrs_contains_sid(
		info->sids,
		info->num_sids,
		&global_sid_Asserted_Identity_Authentication_Authority);

out:
	talloc_free(frame);
	return ret;
}

static krb5_error_code samba_kdc_get_user_info_from_pac(TALLOC_CTX *mem_ctx,
							krb5_context context,
							struct samba_kdc_db_context *kdc_db_ctx,
							const struct samba_kdc_entry_pac entry,
							const struct auth_user_info_dc **info_out,
							const struct PAC_DOMAIN_GROUP_MEMBERSHIP **resource_groups_out)
{
	TALLOC_CTX *frame = NULL;
	struct ldb_context *samdb = kdc_db_ctx->samdb;
	struct auth_user_info_dc *info = NULL;
	struct PAC_DOMAIN_GROUP_MEMBERSHIP *resource_groups = NULL;
	krb5_error_code ret = 0;
	NTSTATUS nt_status;

	if (samdb == NULL) {
		ret = EINVAL;
		goto out;
	}

	if (!samba_krb5_pac_is_trusted(entry)) {
		ret = EINVAL;
		goto out;
	}

	if (info_out == NULL) {
		ret = EINVAL;
		goto out;
	}

	*info_out = NULL;
	if (resource_groups_out != NULL) {
		*resource_groups_out = NULL;
	}

	if (entry.entry == NULL || entry.entry->info_from_pac == NULL) {
		frame = talloc_stackframe();

		ret = kerberos_pac_to_user_info_dc(frame,
						   entry.pac,
						   context,
						   &info,
						   AUTH_EXCLUDE_RESOURCE_GROUPS,
						   NULL,
						   NULL,
						   &resource_groups);
		if (ret) {
			const char *krb5err = krb5_get_error_message(context, ret);
			DBG_ERR("kerberos_pac_to_user_info_dc failed: %s\n",
				krb5err != NULL ? krb5err : "?");
			krb5_free_error_message(context, krb5err);

			goto out;
		}

		/*
		 * We need to expand group memberships within our local domain,
		 * as the token might be generated by a trusted domain.
		 */
		nt_status = authsam_update_user_info_dc(frame,
							samdb,
							info);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("authsam_update_user_info_dc failed: %s\n",
				nt_errstr(nt_status));

			ret = map_errno_from_nt_status(nt_status);
			goto out;
		}

		if (entry.entry != NULL) {
			entry.entry->info_from_pac = talloc_steal(entry.entry, info);
			entry.entry->resource_groups_from_pac = talloc_steal(entry.entry, resource_groups);
		}
	}


	if (entry.entry != NULL) {
		/* Note: the caller does not own this! */
		*info_out = entry.entry->info_from_pac;

		if (resource_groups_out != NULL) {
			/* Note: the caller does not own this! */
			*resource_groups_out = entry.entry->resource_groups_from_pac;
		}
	} else {
		*info_out = talloc_steal(mem_ctx, info);

		if (resource_groups_out != NULL) {
			*resource_groups_out = talloc_steal(mem_ctx, resource_groups);
		}
	}

out:
	talloc_free(frame);
	return ret;
}

static
krb5_error_code samba_kdc_get_user_info_dc(TALLOC_CTX *mem_ctx,
					   krb5_context context,
					   struct samba_kdc_db_context *kdc_db_ctx,
					   const struct samba_kdc_entry_pac entry,
					   const struct auth_user_info_dc **info_out,
					   const struct PAC_DOMAIN_GROUP_MEMBERSHIP **resource_groups_out)
{
	const struct auth_user_info_dc *info = NULL;
	struct auth_user_info_dc *info_shallow_copy = NULL;
	bool pac_contains_asserted_identity = false;
	krb5_error_code ret = 0;
	NTSTATUS nt_status;

	*info_out = NULL;
	if (resource_groups_out != NULL) {
		*resource_groups_out = NULL;
	}

	if (samba_krb5_pac_is_trusted(entry)) {
		return samba_kdc_get_user_info_from_pac(mem_ctx,
							context,
							kdc_db_ctx,
							entry,
							info_out,
							resource_groups_out);
	}

	if (entry.entry == NULL) {
		return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	}

	/*
	 * In this case the RWDC discards the PAC an RODC generated.
	 * Windows adds the asserted_identity in this case too.
	 *
	 * Note that SAMBA_KDC_FLAG_CONSTRAINED_DELEGATION
	 * generates KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN.
	 * So we can always use
	 * SAMBA_ASSERTED_IDENTITY_AUTHENTICATION_AUTHORITY
	 * here.
	 */
	ret = samba_kdc_get_user_info_from_db(mem_ctx,
					      kdc_db_ctx,
					      entry.entry,
					      entry.entry->msg,
					      &info);
	if (ret) {
		const char *krb5err = krb5_get_error_message(context, ret);
		DBG_ERR("samba_kdc_get_user_info_from_db: %s\n",
			krb5err != NULL ? krb5err : "?");
		krb5_free_error_message(context, krb5err);

		return KRB5KDC_ERR_TGT_REVOKED;
	}

	/* Make a shallow copy of the user_info_dc structure. */
	nt_status = authsam_shallow_copy_user_info_dc(mem_ctx,
						      info,
						      &info_shallow_copy);
	info = NULL;

	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("Failed to allocate user_info_dc SIDs: %s\n",
			nt_errstr(nt_status));
		return map_errno_from_nt_status(nt_status);
	}

	/* Determine whether the PAC contains the Asserted Identity SID. */
	ret = samba_kdc_pac_contains_asserted_identity(
		context, entry, &pac_contains_asserted_identity);
	if (ret) {
		return ret;
	}

	if (pac_contains_asserted_identity) {
		nt_status = samba_kdc_add_asserted_identity(
			SAMBA_ASSERTED_IDENTITY_AUTHENTICATION_AUTHORITY,
			info_shallow_copy);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("Failed to add asserted identity: %s\n",
				nt_errstr(nt_status));
			TALLOC_FREE(info_shallow_copy);
			return KRB5KDC_ERR_TGT_REVOKED;
		}
	}

	nt_status = samba_kdc_add_claims_valid(info_shallow_copy);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("Failed to add Claims Valid: %s\n",
			nt_errstr(nt_status));
		TALLOC_FREE(info_shallow_copy);
		return KRB5KDC_ERR_TGT_REVOKED;
	}

	*info_out = info_shallow_copy;

	return 0;
}

static NTSTATUS samba_kdc_update_delegation_info_blob(TALLOC_CTX *mem_ctx,
						      krb5_context context,
						      const krb5_const_pac pac,
						      const krb5_const_principal server_principal,
						      const krb5_const_principal proxy_principal,
						      DATA_BLOB *new_blob)
{
	krb5_data old_data = {};
	DATA_BLOB old_blob;
	krb5_error_code ret;
	NTSTATUS nt_status = NT_STATUS_OK;
	enum ndr_err_code ndr_err;
	union PAC_INFO info = {};
	struct PAC_CONSTRAINED_DELEGATION _d = {};
	struct PAC_CONSTRAINED_DELEGATION *d = NULL;
	char *server = NULL;
	char *proxy = NULL;
	uint32_t i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	if (tmp_ctx == NULL) {
		nt_status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_CONSTRAINED_DELEGATION, &old_data);
	if (ret == ENOENT) {
		/* OK. */
	} else if (ret) {
		nt_status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	old_blob.length = old_data.length;
	old_blob.data = (uint8_t *)old_data.data;

	if (old_blob.length > 0) {
		ndr_err = ndr_pull_union_blob(&old_blob, tmp_ctx,
				&info, PAC_TYPE_CONSTRAINED_DELEGATION,
				(ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			smb_krb5_free_data_contents(context, &old_data);
			nt_status = ndr_map_error2ntstatus(ndr_err);
			DBG_ERR("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status));
			goto out;
		}
	} else {
		info.constrained_delegation.info = &_d;
	}
	smb_krb5_free_data_contents(context, &old_data);

	ret = krb5_unparse_name_flags(context, server_principal,
				      KRB5_PRINCIPAL_UNPARSE_NO_REALM, &server);
	if (ret) {
		nt_status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	ret = krb5_unparse_name(context, proxy_principal, &proxy);
	if (ret) {
		SAFE_FREE(server);
		nt_status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	d = info.constrained_delegation.info;
	i = d->num_transited_services;
	d->proxy_target.string = server;
	d->transited_services = talloc_realloc(mem_ctx, d->transited_services,
					       struct lsa_String, i + 1);
	if (d->transited_services == NULL) {
		SAFE_FREE(server);
		SAFE_FREE(proxy);
		nt_status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}
	d->transited_services[i].string = proxy;
	d->num_transited_services = i + 1;

	ndr_err = ndr_push_union_blob(new_blob, mem_ctx,
				&info, PAC_TYPE_CONSTRAINED_DELEGATION,
				(ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	SAFE_FREE(server);
	SAFE_FREE(proxy);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		smb_krb5_free_data_contents(context, &old_data);
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status));
		goto out;
	}

out:
	talloc_free(tmp_ctx);
	return nt_status;
}

/* function to map policy errors */
krb5_error_code samba_kdc_map_policy_err(NTSTATUS nt_status)
{
	krb5_error_code ret;

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_PASSWORD_MUST_CHANGE))
		ret = KRB5KDC_ERR_KEY_EXP;
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_PASSWORD_EXPIRED))
		ret = KRB5KDC_ERR_KEY_EXP;
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
				       kdc_entry->current_nttime,
				       MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT |
				       MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT,
				       kdc_entry->realm_dn, kdc_entry->msg,
				       workstation, client_name,
				       true, password_change);

	kdc_entry->reject_status = nt_status;
	talloc_free(tmp_ctx);
	return nt_status;
}

static krb5_error_code samba_get_requester_sid(TALLOC_CTX *mem_ctx,
					       krb5_const_pac pac,
					       krb5_context context,
					       struct dom_sid *sid)
{
	NTSTATUS nt_status;
	enum ndr_err_code ndr_err;
	krb5_error_code ret = 0;

	DATA_BLOB pac_requester_sid_in;
	krb5_data k5pac_requester_sid_in;

	union PAC_INFO info;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_REQUESTER_SID,
				  &k5pac_requester_sid_in);
	if (ret != 0) {
		goto out;
	}

	pac_requester_sid_in = data_blob_const(k5pac_requester_sid_in.data,
					       k5pac_requester_sid_in.length);

	ndr_err = ndr_pull_union_blob(&pac_requester_sid_in, tmp_ctx, &info,
				      PAC_TYPE_REQUESTER_SID,
				      (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
	smb_krb5_free_data_contents(context, &k5pac_requester_sid_in);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("can't parse the PAC REQUESTER_SID: %s\n", nt_errstr(nt_status));
		ret = map_errno_from_nt_status(nt_status);
		goto out;
	}

	*sid = info.requester_sid.sid;

out:
	talloc_free(tmp_ctx);
	return ret;
}

/* Does a parse and SID check, but no crypto. */
static krb5_error_code samba_kdc_validate_pac_blob(
		krb5_context context,
		const struct samba_kdc_entry_pac client)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct auth_user_info_dc *pac_user_info = NULL;
	struct dom_sid client_sid;
	struct dom_sid pac_sid;
	krb5_error_code code;
	bool ok;

	/*
	 * First, try to get the SID from the requester SID buffer in the PAC.
	 */
	code = samba_get_requester_sid(frame, client.pac, context, &pac_sid);

	if (code == ENOENT) {
		/*
		 * If the requester SID buffer isn't present, fall back to the
		 * SID in the LOGON_INFO PAC buffer.
		 */
		code = kerberos_pac_to_user_info_dc(frame,
						    client.pac,
						    context,
						    &pac_user_info,
						    AUTH_EXCLUDE_RESOURCE_GROUPS,
						    NULL,
						    NULL,
						    NULL);
		if (code != 0) {
			goto out;
		}

		if (pac_user_info->num_sids == 0) {
			code = EINVAL;
			goto out;
		}

		pac_sid = pac_user_info->sids[PRIMARY_USER_SID_INDEX].sid;
	} else if (code != 0) {
		goto out;
	}

	code = samdb_result_dom_sid_buf(client.entry->msg,
					"objectSid",
					&client_sid);
	if (code) {
		goto out;
	}

	ok = dom_sid_equal(&pac_sid, &client_sid);
	if (!ok) {
		struct dom_sid_buf buf1;
		struct dom_sid_buf buf2;

		DBG_ERR("SID mismatch between PAC and looked up client: "
			"PAC[%s] != CLI[%s]\n",
			dom_sid_str_buf(&pac_sid, &buf1),
			dom_sid_str_buf(&client_sid, &buf2));
			code = KRB5KDC_ERR_TGT_REVOKED;
		goto out;
	}

	code = 0;
out:
	TALLOC_FREE(frame);
	return code;
}


/*
 * In the RODC case, to confirm that the returned user is permitted to
 * be replicated to the KDC (krbgtgt_xxx user) represented by *rodc
 */
static WERROR samba_rodc_confirm_user_is_allowed(uint32_t num_object_sids,
						 const struct dom_sid *object_sids,
						 const struct samba_kdc_entry *rodc,
						 const struct samba_kdc_entry *object)
{
	int ret;
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();
	const char *rodc_attrs[] = { "msDS-KrbTgtLink",
				     "msDS-NeverRevealGroup",
				     "msDS-RevealOnDemandGroup",
				     "userAccountControl",
				     "objectSid",
				     NULL };
	struct ldb_result *rodc_machine_account = NULL;
	struct ldb_dn *rodc_machine_account_dn = samdb_result_dn(rodc->kdc_db_ctx->samdb,
						 frame,
						 rodc->msg,
						 "msDS-KrbTgtLinkBL",
						 NULL);
	const struct dom_sid *rodc_machine_account_sid = NULL;

	if (rodc_machine_account_dn == NULL) {
		DBG_ERR("krbtgt account %s has no msDS-KrbTgtLinkBL to find RODC machine account for allow/deny list\n",
			ldb_dn_get_linearized(rodc->msg->dn));
		TALLOC_FREE(frame);
		return WERR_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	/*
	 * Follow the link and get the RODC account (the krbtgt
	 * account is the krbtgt_XXX account, but the
	 * msDS-NeverRevealGroup and msDS-RevealOnDemandGroup is on
	 * the RODC$ account)
	 *
	 * We need DSDB_SEARCH_SHOW_EXTENDED_DN as we get a SID lists
	 * out of the extended DNs
	 */

	ret = dsdb_search_dn(rodc->kdc_db_ctx->samdb,
			     frame,
			     &rodc_machine_account,
			     rodc_machine_account_dn,
			     rodc_attrs,
			     DSDB_SEARCH_SHOW_EXTENDED_DN);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to fetch RODC machine account %s pointed to by %s to check allow/deny list: %s\n",
			ldb_dn_get_linearized(rodc_machine_account_dn),
			ldb_dn_get_linearized(rodc->msg->dn),
			ldb_errstring(rodc->kdc_db_ctx->samdb));
		TALLOC_FREE(frame);
		return WERR_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	if (rodc_machine_account->count != 1) {
		DBG_ERR("Failed to fetch RODC machine account %s pointed to by %s to check allow/deny list: (%d)\n",
			ldb_dn_get_linearized(rodc_machine_account_dn),
			ldb_dn_get_linearized(rodc->msg->dn),
			rodc_machine_account->count);
		TALLOC_FREE(frame);
		return WERR_DS_DRA_BAD_DN;
	}

	/* if the object SID is equal to the user_sid, allow */
	rodc_machine_account_sid = samdb_result_dom_sid(frame,
					  rodc_machine_account->msgs[0],
					  "objectSid");
	if (rodc_machine_account_sid == NULL) {
		TALLOC_FREE(frame);
		return WERR_DS_DRA_BAD_DN;
	}

	werr = samdb_confirm_rodc_allowed_to_repl_to_sid_list(rodc->kdc_db_ctx->samdb,
							      rodc_machine_account_sid,
							      rodc_machine_account->msgs[0],
							      object->msg,
							      num_object_sids,
							      object_sids);

	TALLOC_FREE(frame);
	return werr;
}

/*
 * Perform an access check for the client attempting to authenticate to the
 * server. ‘client_info’ must be talloc-allocated so that we can make a
 * reference to it.
 */
static
krb5_error_code samba_kdc_allowed_to_authenticate_to(TALLOC_CTX *mem_ctx,
						     struct samba_kdc_db_context *kdc_db_ctx,
						     const struct samba_kdc_entry *client,
						     const struct auth_user_info_dc *client_info,
						     const struct auth_user_info_dc *device_info,
						     const struct auth_claims auth_claims,
						     const struct samba_kdc_entry *server,
						     struct authn_audit_info **server_audit_info_out,
						     NTSTATUS *status_out)
{
	struct ldb_context *samdb = kdc_db_ctx->samdb;
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	krb5_error_code ret = 0;
	NTSTATUS status;
	_UNUSED_ NTSTATUS _status;
	struct dom_sid server_sid = {};
	const struct authn_server_policy *server_policy = server->server_policy;

	if (status_out != NULL) {
		*status_out = NT_STATUS_OK;
	}

	ret = samdb_result_dom_sid_buf(server->msg, "objectSid", &server_sid);
	if (ret) {
		/*
		 * Ignore the return status — we are already in an error path,
		 * and overwriting the real error code with the audit info
		 * status is unhelpful.
		 */
		_status = authn_server_policy_audit_info(mem_ctx,
							 server_policy,
							 client_info,
							 AUTHN_AUDIT_EVENT_OTHER_ERROR,
							 AUTHN_AUDIT_REASON_NONE,
							 dsdb_ldb_err_to_ntstatus(ret),
							 server_audit_info_out);
		goto out;
	}

	if (dom_sid_equal(&client_info->sids[PRIMARY_USER_SID_INDEX].sid, &server_sid)) {
		/* Authenticating to ourselves is always allowed. */
		status = authn_server_policy_audit_info(mem_ctx,
							server_policy,
							client_info,
							AUTHN_AUDIT_EVENT_OK,
							AUTHN_AUDIT_REASON_NONE,
							NT_STATUS_OK,
							server_audit_info_out);
		if (!NT_STATUS_IS_OK(status)) {
			ret = KRB5KRB_ERR_GENERIC;
		}
		goto out;
	}

	status = authn_policy_authenticate_to_service(mem_ctx,
						      samdb,
						      lp_ctx,
						      AUTHN_POLICY_AUTH_TYPE_KERBEROS,
						      client_info,
						      device_info,
						      auth_claims,
						      server_policy,
						      (struct authn_policy_flags) { .force_compounded_authentication = true },
						      server_audit_info_out);
	if (!NT_STATUS_IS_OK(status)) {
		if (status_out != NULL) {
			*status_out = status;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)) {
			ret = KRB5KDC_ERR_POLICY;
		} else if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			ret = KRB5KDC_ERR_POLICY;
		} else {
			ret = KRB5KRB_ERR_GENERIC;
		}
	}

out:
	return ret;
}

static krb5_error_code samba_kdc_add_domain_group_sid(struct PAC_DEVICE_INFO *info,
						      const struct netr_SidAttr *sid)
{
	uint32_t i;
	uint32_t rid;
	NTSTATUS status;

	uint32_t domain_group_count = info->domain_group_count;
	struct PAC_DOMAIN_GROUP_MEMBERSHIP *domain_group = NULL;
	struct samr_RidWithAttribute *rids = NULL;

	for (i = 0; i < domain_group_count; ++i) {
		struct PAC_DOMAIN_GROUP_MEMBERSHIP *this_domain_group
			= &info->domain_groups[i];

		if (dom_sid_in_domain(this_domain_group->domain_sid, sid->sid)) {
			domain_group = this_domain_group;
			break;
		}
	}

	if (domain_group == NULL) {
		struct PAC_DOMAIN_GROUP_MEMBERSHIP *domain_groups = NULL;

		if (domain_group_count == UINT32_MAX) {
			return EINVAL;
		}

		domain_groups = talloc_realloc(
			info,
			info->domain_groups,
			struct PAC_DOMAIN_GROUP_MEMBERSHIP,
			domain_group_count + 1);
		if (domain_groups == NULL) {
			return ENOMEM;
		}

		info->domain_groups = domain_groups;

		domain_group = &info->domain_groups[domain_group_count++];
		*domain_group = (struct PAC_DOMAIN_GROUP_MEMBERSHIP) {};

		status = dom_sid_split_rid(info->domain_groups,
					   sid->sid,
					   &domain_group->domain_sid,
					   &rid);
		if (!NT_STATUS_IS_OK(status)) {
			return map_errno_from_nt_status(status);
		}
	} else {
		status = dom_sid_split_rid(NULL,
					   sid->sid,
					   NULL,
					   &rid);
		if (!NT_STATUS_IS_OK(status)) {
			return map_errno_from_nt_status(status);
		}
	}

	if (domain_group->groups.count == UINT32_MAX) {
		return EINVAL;
	}

	rids = talloc_realloc(info->domain_groups,
			      domain_group->groups.rids,
			      struct samr_RidWithAttribute,
			      domain_group->groups.count + 1);
	if (rids == NULL) {
		return ENOMEM;
	}

	domain_group->groups.rids = rids;

	domain_group->groups.rids[domain_group->groups.count] = (struct samr_RidWithAttribute) {
		.rid = rid,
		.attributes = sid->attributes,
	};

	++domain_group->groups.count;

	info->domain_group_count = domain_group_count;

	return 0;
}

static krb5_error_code samba_kdc_make_device_info(TALLOC_CTX *mem_ctx,
						  const struct netr_SamInfo3 *info3,
						  struct PAC_DOMAIN_GROUP_MEMBERSHIP *resource_groups,
						  union PAC_INFO *info)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct PAC_DEVICE_INFO *device_info = NULL;
	uint32_t i;
	krb5_error_code ret = 0;

	*info = (union PAC_INFO) {};

	info->device_info.info = NULL;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	device_info = talloc(tmp_ctx, struct PAC_DEVICE_INFO);
	if (device_info == NULL) {
		ret = ENOMEM;
		goto out;
	}

	device_info->rid = info3->base.rid;
	device_info->primary_gid = info3->base.primary_gid;
	device_info->domain_sid = info3->base.domain_sid;
	device_info->groups = info3->base.groups;

	device_info->sid_count = 0;
	device_info->sids = NULL;

	if (resource_groups != NULL) {
		/*
		 * The account's resource groups all belong to the same domain,
		 * so we can add them all in one go.
		 */
		device_info->domain_group_count = 1;
		device_info->domain_groups = talloc_move(device_info, &resource_groups);
	} else {
		device_info->domain_group_count = 0;
		device_info->domain_groups = NULL;
	}

	for (i = 0; i < info3->sidcount; ++i) {
		const struct netr_SidAttr *device_sid = &info3->sids[i];

		if (dom_sid_has_account_domain(device_sid->sid)) {
			ret = samba_kdc_add_domain_group_sid(device_info, device_sid);
			if (ret != 0) {
				goto out;
			}
		} else {
			device_info->sids = talloc_realloc(device_info, device_info->sids,
							   struct netr_SidAttr,
							   device_info->sid_count + 1);
			if (device_info->sids == NULL) {
				ret = ENOMEM;
				goto out;
			}

			device_info->sids[device_info->sid_count].sid = dom_sid_dup(device_info->sids, device_sid->sid);
			if (device_info->sids[device_info->sid_count].sid == NULL) {
				ret = ENOMEM;
				goto out;
			}

			device_info->sids[device_info->sid_count].attributes = device_sid->attributes;

			++device_info->sid_count;
		}
	}

	info->device_info.info = talloc_steal(mem_ctx, device_info);

out:
	talloc_free(tmp_ctx);
	return ret;
}

static krb5_error_code samba_kdc_get_device_info_pac_blob(TALLOC_CTX *mem_ctx,
							  union PAC_INFO *info,
							  DATA_BLOB **_device_info_blob)
{
	DATA_BLOB *device_info_blob = NULL;
	enum ndr_err_code ndr_err;

	*_device_info_blob = NULL;

	device_info_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (device_info_blob == NULL) {
		DBG_ERR("Out of memory\n");
		return ENOMEM;
	}

	ndr_err = ndr_push_union_blob(device_info_blob, device_info_blob,
				      info, PAC_TYPE_DEVICE_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("PAC_DEVICE_INFO (presig) push failed: %s\n",
			    nt_errstr(nt_status));
		talloc_free(device_info_blob);
		return map_errno_from_nt_status(nt_status);
	}

	*_device_info_blob = device_info_blob;

	return 0;
}

static krb5_error_code samba_kdc_get_device_info_blob(TALLOC_CTX *mem_ctx,
						      krb5_context context,
						      struct samba_kdc_db_context *kdc_db_ctx,
						      const struct auth_user_info_dc *device_info,
						      DATA_BLOB **device_info_blob)
{
	TALLOC_CTX *frame = NULL;
	krb5_error_code code = EINVAL;
	NTSTATUS nt_status;
	struct netr_SamInfo3 *info3 = NULL;
	struct PAC_DOMAIN_GROUP_MEMBERSHIP *resource_groups = NULL;

	union PAC_INFO info;

	frame = talloc_stackframe();

	nt_status = auth_convert_user_info_dc_saminfo3(frame, device_info,
						       AUTH_INCLUDE_RESOURCE_GROUPS_COMPRESSED,
						       &info3,
						       &resource_groups);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_WARNING("Getting Samba info failed: %s\n",
			    nt_errstr(nt_status));
		talloc_free(frame);
		return nt_status_to_krb5(nt_status);
	}

	code = samba_kdc_make_device_info(frame,
					  info3,
					  resource_groups,
					  &info);
	if (code != 0) {
		talloc_free(frame);
		return code;
	}

	code = samba_kdc_get_device_info_pac_blob(mem_ctx,
						  &info,
						  device_info_blob);

	talloc_free(frame);
	return code;
}

/**
 * @brief Verify a PAC
 *
 * @param mem_ctx   A talloc memory context
 *
 * @param context   A krb5 context
 *
 * @param samdb     An open samdb connection.
 *
 * @param flags     Bitwise OR'ed flags
 *
 * @param client    The client samba kdc PAC entry.

 * @param krbtgt    The krbtgt samba kdc entry.
 *
 * @return A Kerberos error code.
 */
krb5_error_code samba_kdc_verify_pac(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     struct samba_kdc_db_context *kdc_db_ctx,
				     uint32_t flags,
				     const struct samba_kdc_entry_pac client,
				     const struct samba_kdc_entry *krbtgt)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct pac_blobs *pac_blobs = NULL;
	krb5_error_code code = EINVAL;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		code = ENOMEM;
		goto done;
	}

	if (client.entry != NULL) {
		/*
		 * Check the objectSID of the client and pac data are the same.
		 * Does a parse and SID check, but no crypto.
		 */
		code = samba_kdc_validate_pac_blob(context, client);
		if (code != 0) {
			goto done;
		}
	}

	if (!samba_krb5_pac_is_trusted(client)) {
		const struct auth_user_info_dc *user_info_dc = NULL;
		WERROR werr;

		struct dom_sid *object_sids = NULL;
		uint32_t j;

		if (client.entry == NULL) {
			code = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
			goto done;
		}

		code = samba_kdc_get_user_info_from_db(tmp_ctx,
						       kdc_db_ctx,
						       client.entry,
						       client.entry->msg,
						       &user_info_dc);
		if (code) {
			const char *krb5_err = krb5_get_error_message(context, code);
			DBG_ERR("Getting user info for PAC failed: %s\n",
				krb5_err != NULL ? krb5_err : "<unknown>");
			krb5_free_error_message(context, krb5_err);

			code = KRB5KDC_ERR_TGT_REVOKED;
			goto done;
		}

		/*
		 * Check if the SID list in the user_info_dc intersects
		 * correctly with the RODC allow/deny lists.
		 */
		object_sids = talloc_array(tmp_ctx, struct dom_sid, user_info_dc->num_sids);
		if (object_sids == NULL) {
			code = ENOMEM;
			goto done;
		}

		for (j = 0; j < user_info_dc->num_sids; ++j) {
			object_sids[j] = user_info_dc->sids[j].sid;
		}

		werr = samba_rodc_confirm_user_is_allowed(user_info_dc->num_sids,
							  object_sids,
							  krbtgt,
							  client.entry);
		if (!W_ERROR_IS_OK(werr)) {
			code = KRB5KDC_ERR_TGT_REVOKED;
			if (W_ERROR_EQUAL(werr,
					  WERR_DOMAIN_CONTROLLER_NOT_FOUND)) {
				code = KRB5KDC_ERR_POLICY;
			}
			goto done;
		}

		/*
		 * The RODC PAC data isn't trusted for authorization as it may
		 * be stale. The only thing meaningful we can do with an RODC
		 * account on a full DC is exchange the RODC TGT for a 'real'
		 * TGT.
		 *
		 * So we match Windows (at least server 2022) and
		 * don't allow S4U2Self.
		 *
		 * https://lists.samba.org/archive/cifs-protocol/2022-April/003673.html
		 */
		if (flags & SAMBA_KDC_FLAG_PROTOCOL_TRANSITION) {
			code = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
			goto done;
		}
	}

	/* Check the types of the given PAC */

	code = pac_blobs_from_krb5_pac(tmp_ctx,
				       context,
				       client.pac,
				       &pac_blobs);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_ensure_exists(pac_blobs,
				       PAC_TYPE_LOGON_INFO);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_ensure_exists(pac_blobs,
				       PAC_TYPE_LOGON_NAME);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_ensure_exists(pac_blobs,
				       PAC_TYPE_SRV_CHECKSUM);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_ensure_exists(pac_blobs,
				       PAC_TYPE_KDC_CHECKSUM);
	if (code != 0) {
		goto done;
	}

	if (!(flags & SAMBA_KDC_FLAG_CONSTRAINED_DELEGATION)) {
		code = pac_blobs_ensure_exists(pac_blobs,
					       PAC_TYPE_REQUESTER_SID);
		if (code != 0) {
			code = KRB5KDC_ERR_TGT_REVOKED;
			goto done;
		}
	}

	code = 0;

done:
	talloc_free(tmp_ctx);

	return code;
}

static
krb5_error_code samba_kdc_get_claims_data(TALLOC_CTX *mem_ctx,
					  krb5_context context,
					  struct samba_kdc_db_context *kdc_db_ctx,
					  struct samba_kdc_entry_pac entry,
					  struct claims_data **claims_data_out);

krb5_error_code samba_kdc_get_pac(TALLOC_CTX *mem_ctx,
				  krb5_context context,
				  struct samba_kdc_db_context *kdc_db_ctx,
				  uint32_t flags,
				  struct samba_kdc_entry *client,
				  const krb5_const_principal server_principal,
				  const struct samba_kdc_entry *server,
				  const struct samba_kdc_entry_pac device,
				  const krb5_keyblock *pk_reply_key,
				  uint64_t pac_attributes,
				  krb5_pac new_pac,
				  struct authn_audit_info **server_audit_info_out,
				  NTSTATUS *status_out)
{
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB *logon_blob = NULL;
	DATA_BLOB *cred_ndr = NULL;
	DATA_BLOB **cred_ndr_ptr = NULL;
	DATA_BLOB _cred_blob = data_blob_null;
	DATA_BLOB *cred_blob = NULL;
	DATA_BLOB *upn_blob = NULL;
	DATA_BLOB *pac_attrs_blob = NULL;
	DATA_BLOB *requester_sid_blob = NULL;
	const DATA_BLOB *client_claims_blob = NULL;
	krb5_error_code ret;
	NTSTATUS nt_status;
	bool is_krbtgt = false;
	enum auth_group_inclusion group_inclusion;
	bool is_s4u2self = flags & SAMBA_KDC_FLAG_PROTOCOL_TRANSITION;
	enum samba_asserted_identity asserted_identity =
		(is_s4u2self) ?
			SAMBA_ASSERTED_IDENTITY_SERVICE :
			SAMBA_ASSERTED_IDENTITY_AUTHENTICATION_AUTHORITY;
	bool pkinit_freshness = flags & SAMBA_KDC_FLAG_PKINIT_FRESHNESS_USED;
	const struct auth_user_info_dc *user_info_dc_const = NULL;
	struct auth_user_info_dc *user_info_dc = NULL;
	struct auth_claims auth_claims = {};

	if (server_audit_info_out != NULL) {
		*server_audit_info_out = NULL;
	}

	if (status_out != NULL) {
		*status_out = NT_STATUS_OK;
	}

	{
		int result = smb_krb5_principal_is_tgs(context, server_principal);
		if (result == -1) {
			TALLOC_FREE(frame);
			return ENOMEM;
		}

		is_krbtgt = result;
	}

	/* Only include resource groups in a service ticket. */
	if (is_krbtgt) {
		group_inclusion = AUTH_EXCLUDE_RESOURCE_GROUPS;
	} else if (server->supported_enctypes & KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED) {
		group_inclusion = AUTH_INCLUDE_RESOURCE_GROUPS;
	} else {
		group_inclusion = AUTH_INCLUDE_RESOURCE_GROUPS_COMPRESSED;
	}

	if (pk_reply_key != NULL) {
		cred_ndr_ptr = &cred_ndr;
	}

	ret = samba_kdc_get_user_info_from_db(frame,
					      kdc_db_ctx,
					      client,
					      client->msg,
					      &user_info_dc_const);
	if (ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	/* Make a shallow copy of the user_info_dc structure. */
	nt_status = authsam_shallow_copy_user_info_dc(frame,
						      user_info_dc_const,
						      &user_info_dc);
	user_info_dc_const = NULL;

	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("Failed to allocate user_info_dc SIDs: %s\n",
			nt_errstr(nt_status));
		TALLOC_FREE(frame);
		return map_errno_from_nt_status(nt_status);
	}

	nt_status = samba_kdc_add_asserted_identity(asserted_identity,
						    user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("Failed to add asserted identity: %s\n",
			nt_errstr(nt_status));
		TALLOC_FREE(frame);
		return map_errno_from_nt_status(nt_status);
	}

	nt_status = samba_kdc_add_claims_valid(user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("Failed to add Claims Valid: %s\n",
			nt_errstr(nt_status));
		TALLOC_FREE(frame);
		return map_errno_from_nt_status(nt_status);
	}

	if (pkinit_freshness) {
		nt_status = samba_kdc_add_fresh_public_key_identity(user_info_dc);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("Failed to add Fresh Public Key Identity: %s\n",
				nt_errstr(nt_status));
			TALLOC_FREE(frame);
			return map_errno_from_nt_status(nt_status);
		}
	}

	ret = samba_kdc_get_claims_data_from_db(kdc_db_ctx->samdb,
						client,
						&auth_claims.user_claims);
	if (ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	nt_status = samba_kdc_get_claims_blob(frame,
					      auth_claims.user_claims,
					      &client_claims_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return map_errno_from_nt_status(nt_status);
	}

	/*
	 * For an S4U2Self request, the authentication policy is not enforced.
	 */
	if (!is_s4u2self &&
	    authn_policy_restrictions_present(server->server_policy))
	{
		const struct auth_user_info_dc *device_info_dc = NULL;

		if (samba_kdc_entry_pac_valid_principal(device)) {
			ret = samba_kdc_get_user_info_dc(frame,
							 context,
							 kdc_db_ctx,
							 device,
							 &device_info_dc,
							 NULL /* resource_groups_out */);
			if (ret) {
				TALLOC_FREE(frame);
				return ret;
			}

			ret = samba_kdc_get_claims_data(frame,
							context,
							kdc_db_ctx,
							device,
							&auth_claims.device_claims);
			if (ret) {
				TALLOC_FREE(frame);
				return ret;
			}
		}

		/*
		 * Allocate the audit info and output status on to the parent
		 * mem_ctx, not the temporary context.
		 */
		ret = samba_kdc_allowed_to_authenticate_to(mem_ctx,
							   kdc_db_ctx,
							   client,
							   user_info_dc,
							   device_info_dc,
							   auth_claims,
							   server,
							   server_audit_info_out,
							   status_out);
		if (ret) {
			TALLOC_FREE(frame);
			return ret;
		}
	}

	nt_status = samba_kdc_get_logon_info_blob(frame,
						  user_info_dc,
						  group_inclusion,
						  &logon_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(frame);
		return map_errno_from_nt_status(nt_status);
	}

	if (cred_ndr_ptr != NULL) {
		nt_status = samba_kdc_get_cred_ndr_blob(frame,
							client,
							cred_ndr_ptr);
		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(frame);
			return map_errno_from_nt_status(nt_status);
		}
	}

	nt_status = samba_kdc_get_upn_info_blob(frame,
						user_info_dc,
						&upn_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(frame);
		return map_errno_from_nt_status(nt_status);
	}

	if (is_krbtgt) {
		nt_status = samba_kdc_get_pac_attrs_blob(frame,
							 pac_attributes,
							 &pac_attrs_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(frame);
			return map_errno_from_nt_status(nt_status);
		}

		nt_status = samba_kdc_get_requester_sid_blob(frame,
							     user_info_dc,
							     &requester_sid_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(frame);
			return map_errno_from_nt_status(nt_status);
		}
	}

	if (pk_reply_key != NULL && cred_ndr != NULL) {
		ret = samba_kdc_encrypt_pac_credentials(context,
							pk_reply_key,
							cred_ndr,
							frame,
							&_cred_blob);
		if (ret != 0) {
			TALLOC_FREE(frame);
			return ret;
		}
		cred_blob = &_cred_blob;
	}

	ret = samba_make_krb5_pac(context,
				  logon_blob,
				  cred_blob,
				  upn_blob,
				  pac_attrs_blob,
				  requester_sid_blob,
				  NULL, /* deleg_blob */
				  client_claims_blob,
				  NULL, /* device_info_blob */
				  NULL, /* device_claims_blob */
				  new_pac);

	TALLOC_FREE(frame);
	return ret;
}

/**
 * @brief Update a PAC
 *
 * @param mem_ctx   A talloc memory context
 *
 * @param context   A krb5 context
 *
 * @param samdb     An open samdb connection.
 *
 * @param lp_ctx    A loadparm context.
 *
 * @param flags     Bitwise OR'ed flags
 *
 * @param device_pac_is_trusted Whether the device's PAC was issued by a trusted server,
 *                              as opposed to an RODC.
 *
 * @param client    The client samba kdc PAC entry.
 *
 * @param server_principal  The server principal
 *
 * @param server    The server samba kdc entry.
 *
 * @param delegated_proxy_principal The delegated proxy principal used for
 *                                  updating the constrained delegation PAC
 *                                  buffer.
 *
 * @param delegated_proxy   The delegated proxy kdc PAC entry.
 *
 * @param device    The computer's samba kdc PAC entry; used for compound
 *                  authentication.
 *
 * @param new_pac                   The new already allocated PAC
 *
 * @return A Kerberos error code. If no PAC should be returned, the code will be
 * ENOATTR!
 */
krb5_error_code samba_kdc_update_pac(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     struct samba_kdc_db_context *kdc_db_ctx,
				     uint32_t flags,
				     const struct samba_kdc_entry_pac client,
				     const krb5_const_principal server_principal,
				     const struct samba_kdc_entry *server,
				     const krb5_const_principal delegated_proxy_principal,
				     const struct samba_kdc_entry_pac delegated_proxy,
				     const struct samba_kdc_entry_pac device,
				     krb5_pac new_pac,
				     struct authn_audit_info **server_audit_info_out,
				     NTSTATUS *status_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	krb5_error_code code = EINVAL;
	NTSTATUS nt_status;
	DATA_BLOB *pac_blob = NULL;
	DATA_BLOB *upn_blob = NULL;
	DATA_BLOB *deleg_blob = NULL;
	DATA_BLOB *requester_sid_blob = NULL;
	const DATA_BLOB *client_claims_blob = NULL;
	DATA_BLOB device_claims_blob = {};
	const DATA_BLOB *device_claims_blob_ptr = NULL;
	struct auth_claims pac_claims = {};
	DATA_BLOB *device_info_blob = NULL;
	bool is_tgs = false;
	bool server_restrictions_present = false;
	struct pac_blobs *pac_blobs = NULL;
	const struct auth_user_info_dc *user_info_dc_const = NULL;
	const struct auth_user_info_dc *device_info_dc = NULL;
	const struct PAC_DOMAIN_GROUP_MEMBERSHIP *_resource_groups = NULL;
	enum auth_group_inclusion group_inclusion;
	bool compounded_auth = false;
	bool need_device = false;
	size_t i = 0;

	if (server_audit_info_out != NULL) {
		*server_audit_info_out = NULL;
	}

	if (status_out != NULL) {
		*status_out = NT_STATUS_OK;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		code = ENOMEM;
		goto done;
	}

	{
		int result = smb_krb5_principal_is_tgs(context, server_principal);
		if (result == -1) {
			code = ENOMEM;
			goto done;
		}

		is_tgs = result;
	}

	/* Only include resource groups in a service ticket. */
	if (is_tgs) {
		group_inclusion = AUTH_EXCLUDE_RESOURCE_GROUPS;
	} else if (server->supported_enctypes & KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED) {
		group_inclusion = AUTH_INCLUDE_RESOURCE_GROUPS;
	} else {
		group_inclusion = AUTH_INCLUDE_RESOURCE_GROUPS_COMPRESSED;
	}

	/*
	 * If we are creating a TGT, resource groups from our domain are not to
	 * be put into the PAC. Instead, we take the resource groups directly
	 * from the original PAC and copy them unmodified into the new one.
	 */
	code = samba_kdc_get_user_info_dc(tmp_ctx,
					  context,
					  kdc_db_ctx,
					  client,
					  &user_info_dc_const,
					  is_tgs ? &_resource_groups : NULL);
	if (code != 0) {
		const char *err_str = krb5_get_error_message(context, code);
		DBG_ERR("samba_kdc_get_user_info_dc failed: %s\n",
			err_str != NULL ? err_str : "<unknown>");
		krb5_free_error_message(context, err_str);

		goto done;
	}

	/* Fetch the user’s claims. */
	code = samba_kdc_get_claims_data(tmp_ctx,
					 context,
					 kdc_db_ctx,
					 client,
					 &pac_claims.user_claims);
	if (code) {
		goto done;
	}

	if (!is_tgs) {
		server_restrictions_present = authn_policy_restrictions_present(
							server->server_policy);

		if (samba_kdc_entry_pac_valid_principal(device)) {
			compounded_auth = server->supported_enctypes &
				KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED;

			if (server_restrictions_present || compounded_auth) {
				need_device = true;
			}
		}
	}

	if (need_device) {
		code = samba_kdc_get_user_info_dc(tmp_ctx,
						  context,
						  kdc_db_ctx,
						  device,
						  &device_info_dc,
						  NULL /* resource_groups_out */);
		if (code) {
			goto done;
		}

		/*
		 * [MS-KILE] 3.3.5.7.4 Compound Identity: the client claims from
		 * the device PAC become the device claims in the new PAC.
		 */
		code = samba_kdc_get_claims_data(tmp_ctx,
						 context,
						 kdc_db_ctx,
						 device,
						 &pac_claims.device_claims);
		if (code) {
			goto done;
		}

		if (compounded_auth) {
			nt_status = claims_data_encoded_claims_set(tmp_ctx,
								   pac_claims.device_claims,
								   &device_claims_blob);
			if (!NT_STATUS_IS_OK(nt_status)) {
				DBG_ERR("claims_data_encoded_claims_set failed: %s\n",
					nt_errstr(nt_status));
				code = map_errno_from_nt_status(nt_status);
				goto done;
			}

			device_claims_blob_ptr = &device_claims_blob;

			code = samba_kdc_get_device_info_blob(tmp_ctx,
							      context,
							      kdc_db_ctx,
							      device_info_dc,
							      &device_info_blob);
			if (code != 0) {
				goto done;
			}
		}
	}

	if (delegated_proxy_principal != NULL) {
		deleg_blob = talloc_zero(tmp_ctx, DATA_BLOB);
		if (deleg_blob == NULL) {
			code = ENOMEM;
			goto done;
		}

		nt_status = samba_kdc_update_delegation_info_blob(
				deleg_blob,
				context,
				client.pac,
				server_principal,
				delegated_proxy_principal,
				deleg_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("update delegation info blob failed: %s\n",
				nt_errstr(nt_status));
			code = map_errno_from_nt_status(nt_status);
			goto done;
		}
	}

	/*
	 * Enforce the AllowedToAuthenticateTo part of an authentication policy,
	 * if one is present.
	 */
	if (server_restrictions_present) {
		struct samba_kdc_entry_pac auth_entry;
		const struct auth_user_info_dc *auth_user_info_dc = NULL;
		struct auth_claims auth_claims = {};

		if (samba_kdc_entry_pac_valid_principal(delegated_proxy)) {
			auth_entry = delegated_proxy;

			code = samba_kdc_get_user_info_dc(tmp_ctx,
							  context,
							  kdc_db_ctx,
							  delegated_proxy,
							  &auth_user_info_dc,
							  NULL /* resource_groups_out */);
			if (code) {
				goto done;
			}

			/* Fetch the delegated proxy claims. */
			code = samba_kdc_get_claims_data(tmp_ctx,
							 context,
							 kdc_db_ctx,
							 auth_entry,
							 &auth_claims.user_claims);
			if (code) {
				goto done;
			}

			auth_claims.device_claims = pac_claims.device_claims;
		} else {
			auth_entry = client;
			auth_user_info_dc = user_info_dc_const;
			auth_claims = pac_claims;
		}

		/*
		 * Allocate the audit info and output status on to the parent
		 * mem_ctx, not the temporary context.
		 */
		code = samba_kdc_allowed_to_authenticate_to(mem_ctx,
							    kdc_db_ctx,
							    auth_entry.entry,
							    auth_user_info_dc,
							    device_info_dc,
							    auth_claims,
							    server,
							    server_audit_info_out,
							    status_out);
		if (code) {
			goto done;
		}
	}

	if (compounded_auth) {
		struct auth_user_info_dc *user_info_dc_shallow_copy = NULL;

		/* Make a shallow copy of the user_info_dc structure. */
		nt_status = authsam_shallow_copy_user_info_dc(tmp_ctx,
							      user_info_dc_const,
							      &user_info_dc_shallow_copy);
		user_info_dc_const = NULL;

		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("Failed to copy user_info_dc: %s\n",
				nt_errstr(nt_status));

			code = KRB5KDC_ERR_TGT_REVOKED;
			goto done;
		}

		nt_status = samba_kdc_add_compounded_auth(user_info_dc_shallow_copy);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("Failed to add Compounded Authentication: %s\n",
				nt_errstr(nt_status));

			code = KRB5KDC_ERR_TGT_REVOKED;
			goto done;
		}

		/* We can now set back to the const, it will not be modified */
		user_info_dc_const = user_info_dc_shallow_copy;
	}

	if (samba_krb5_pac_is_trusted(client)) {
		pac_blob = talloc_zero(tmp_ctx, DATA_BLOB);
		if (pac_blob == NULL) {
			code = ENOMEM;
			goto done;
		}

		nt_status = samba_get_logon_info_pac_blob(tmp_ctx,
							  user_info_dc_const,
							  _resource_groups,
							  group_inclusion,
							  pac_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("samba_get_logon_info_pac_blob failed: %s\n",
				nt_errstr(nt_status));

			code = map_errno_from_nt_status(nt_status);
			goto done;
		}

		/*
		 * TODO: we need claim translation over trusts,
		 * for now we just clear them...
		 */
		if (samba_kdc_entry_pac_issued_by_trust(client)) {
			client_claims_blob = &data_blob_null;
		}
	} else {
		nt_status = samba_kdc_get_logon_info_blob(tmp_ctx,
							  user_info_dc_const,
							  group_inclusion,
							  &pac_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("samba_kdc_get_logon_info_blob failed: %s\n",
				nt_errstr(nt_status));
			code = KRB5KDC_ERR_TGT_REVOKED;
			goto done;
		}

		nt_status = samba_kdc_get_upn_info_blob(tmp_ctx,
							user_info_dc_const,
							&upn_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("samba_kdc_get_upn_info_blob failed: %s\n",
				nt_errstr(nt_status));
			code = KRB5KDC_ERR_TGT_REVOKED;
			goto done;
		}

		if (is_tgs) {
			nt_status = samba_kdc_get_requester_sid_blob(tmp_ctx,
								     user_info_dc_const,
								     &requester_sid_blob);
			if (!NT_STATUS_IS_OK(nt_status)) {
				DBG_ERR("samba_kdc_get_requester_sid_blob failed: %s\n",
					nt_errstr(nt_status));
				code = KRB5KDC_ERR_TGT_REVOKED;
				goto done;
			}
		}

		/* Don't trust RODC-issued claims. Regenerate them. */
		nt_status = samba_kdc_get_claims_blob(tmp_ctx,
						      pac_claims.user_claims,
						      &client_claims_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("samba_kdc_get_claims_blob failed: %s\n",
				nt_errstr(nt_status));
			code = map_errno_from_nt_status(nt_status);
			goto done;
		}
	}

	/* Check the types of the given PAC */
	code = pac_blobs_from_krb5_pac(tmp_ctx,
				       context,
				       client.pac,
				       &pac_blobs);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_replace_existing(pac_blobs,
					  PAC_TYPE_LOGON_INFO,
					  pac_blob);
	if (code != 0) {
		goto done;
	}

#ifdef SAMBA4_USES_HEIMDAL
	/* Not needed with MIT Kerberos */
	code = pac_blobs_replace_existing(pac_blobs,
					  PAC_TYPE_LOGON_NAME,
					  &data_blob_null);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_replace_existing(pac_blobs,
					  PAC_TYPE_SRV_CHECKSUM,
					  &data_blob_null);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_replace_existing(pac_blobs,
					  PAC_TYPE_KDC_CHECKSUM,
					  &data_blob_null);
	if (code != 0) {
		goto done;
	}
#endif

	code = pac_blobs_add_blob(pac_blobs,
				  PAC_TYPE_CONSTRAINED_DELEGATION,
				  deleg_blob);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_add_blob(pac_blobs,
				  PAC_TYPE_UPN_DNS_INFO,
				  upn_blob);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_add_blob(pac_blobs,
				  PAC_TYPE_CLIENT_CLAIMS_INFO,
				  client_claims_blob);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_add_blob(pac_blobs,
				  PAC_TYPE_DEVICE_INFO,
				  device_info_blob);
	if (code != 0) {
		goto done;
	}

	code = pac_blobs_add_blob(pac_blobs,
				  PAC_TYPE_DEVICE_CLAIMS_INFO,
				  device_claims_blob_ptr);
	if (code != 0) {
		goto done;
	}

	if (!samba_krb5_pac_is_trusted(client) || !is_tgs) {
		pac_blobs_remove_blob(pac_blobs,
				      PAC_TYPE_ATTRIBUTES_INFO);
	}

	if (!is_tgs) {
		pac_blobs_remove_blob(pac_blobs,
				      PAC_TYPE_REQUESTER_SID);
	}

	code = pac_blobs_add_blob(pac_blobs,
				  PAC_TYPE_REQUESTER_SID,
				  requester_sid_blob);
	if (code != 0) {
		goto done;
	}

	/*
	 * The server account may be set not to want the PAC.
	 *
	 * While this is wasteful if the above calculations were done
	 * and now thrown away, this is cleaner as we do any ticket
	 * signature checking etc always.
	 *
	 * UF_NO_AUTH_DATA_REQUIRED is the rare case and most of the
	 * time (eg not accepting a ticket from the RODC) we do not
	 * need to re-generate anything anyway.
	 */
	if (!samba_princ_needs_pac(server)) {
		code = ENOATTR;
		goto done;
	}

	if (samba_krb5_pac_is_trusted(client) && !is_tgs) {
		/*
		 * The client may have requested no PAC when obtaining the
		 * TGT.
		 */
		bool requested_pac = false;

		code = samba_client_requested_pac(context,
						  client.pac,
						  tmp_ctx,
						  &requested_pac);
		if (code != 0 || !requested_pac) {
			if (!requested_pac) {
				code = ENOATTR;
			}
			goto done;
		}
	}

	for (i = 0; i < pac_blobs->num_types; ++i) {
		krb5_data type_data;
		const DATA_BLOB *type_blob = pac_blobs->type_blobs[i].data;
		uint32_t type = pac_blobs->type_blobs[i].type;

		static char null_byte = '\0';
		const krb5_data null_data = smb_krb5_make_data(&null_byte, 0);

#ifndef SAMBA4_USES_HEIMDAL
		/* Not needed with MIT Kerberos */
		switch(type) {
		case PAC_TYPE_LOGON_NAME:
		case PAC_TYPE_SRV_CHECKSUM:
		case PAC_TYPE_KDC_CHECKSUM:
		case PAC_TYPE_FULL_CHECKSUM:
			continue;
		default:
			break;
		}
#endif

		if (type_blob != NULL) {
			type_data = smb_krb5_data_from_blob(*type_blob);
			/*
			 * Passing a NULL pointer into krb5_pac_add_buffer() is
			 * not allowed, so pass null_data instead if needed.
			 */
			code = krb5_pac_add_buffer(context,
						   new_pac,
						   type,
						   (type_data.data != NULL) ? &type_data : &null_data);
			if (code != 0) {
				goto done;
			}
		} else if (samba_krb5_pac_is_trusted(client)) {
			/*
			 * Convey the buffer from the original PAC if we can
			 * trust it.
			 */

			code = krb5_pac_get_buffer(context,
						   client.pac,
						   type,
						   &type_data);
			if (code != 0) {
				goto done;
			}
			/*
			 * Passing a NULL pointer into krb5_pac_add_buffer() is
			 * not allowed, so pass null_data instead if needed.
			 */
			code = krb5_pac_add_buffer(context,
						   new_pac,
						   type,
						   (type_data.data != NULL) ? &type_data : &null_data);
			smb_krb5_free_data_contents(context, &type_data);
			if (code != 0) {
				goto done;
			}
		}
	}

	code = 0;
done:
	TALLOC_FREE(tmp_ctx);
	return code;
}

static
krb5_error_code samba_kdc_get_claims_data_from_pac(TALLOC_CTX *mem_ctx,
						   krb5_context context,
						   struct samba_kdc_entry_pac entry,
						   struct claims_data **claims_data_out);

static
krb5_error_code samba_kdc_get_claims_data(TALLOC_CTX *mem_ctx,
					  krb5_context context,
					  struct samba_kdc_db_context *kdc_db_ctx,
					  struct samba_kdc_entry_pac entry,
					  struct claims_data **claims_data_out)
{
	if (samba_kdc_entry_pac_issued_by_trust(entry)) {
		NTSTATUS status;

		/*
		 * TODO: we need claim translation over trusts; for now we just
		 * clear them…
		 */
		status = claims_data_from_encoded_claims_set(mem_ctx,
							     NULL,
							     claims_data_out);
		if (!NT_STATUS_IS_OK(status)) {
			return map_errno_from_nt_status(status);
		}

		return 0;
	}

	if (samba_krb5_pac_is_trusted(entry)) {
		return samba_kdc_get_claims_data_from_pac(mem_ctx,
							  context,
							  entry,
							  claims_data_out);
	}

	return samba_kdc_get_claims_data_from_db(kdc_db_ctx->samdb,
						 entry.entry,
						 claims_data_out);
}

static
krb5_error_code samba_kdc_get_claims_data_from_pac(TALLOC_CTX *mem_ctx,
						   krb5_context context,
						   struct samba_kdc_entry_pac entry,
						   struct claims_data **claims_data_out)
{
	TALLOC_CTX *frame = NULL;
	krb5_data claims_info = {};
	struct claims_data *claims_data = NULL;
	NTSTATUS status = NT_STATUS_OK;
	krb5_error_code code;

	if (!samba_krb5_pac_is_trusted(entry)) {
		code = EINVAL;
		goto out;
	}

	if (samba_kdc_entry_pac_issued_by_trust(entry)) {
		code = EINVAL;
		goto out;
	}

	if (claims_data_out == NULL) {
		code = EINVAL;
		goto out;
	}

	*claims_data_out = NULL;

	if (entry.entry != NULL && entry.entry->claims_from_pac_are_initialized) {
		/* Note: the caller does not own this! */
		*claims_data_out = entry.entry->claims_from_pac;
		return 0;
	}

	frame = talloc_stackframe();

	/* Fetch the claims from the PAC. */
	code = krb5_pac_get_buffer(context, entry.pac,
				   PAC_TYPE_CLIENT_CLAIMS_INFO,
				   &claims_info);
	if (code == ENOENT) {
		/* OK. */
		krb5_clear_error_message(context);
		code = 0;
	} else if (code != 0) {
		DBG_ERR("Error getting CLIENT_CLAIMS_INFO from PAC\n");
		goto out;
	} else if (claims_info.length) {
		DATA_BLOB claims_blob = data_blob_const(claims_info.data,
							claims_info.length);

		status = claims_data_from_encoded_claims_set(frame,
							     &claims_blob,
							     &claims_data);
		if (!NT_STATUS_IS_OK(status)) {
			code = map_errno_from_nt_status(status);
			goto out;
		}
	}

	if (entry.entry != NULL) {
		/* Note: the caller does not own this! */
		entry.entry->claims_from_pac = talloc_steal(entry.entry,
							    claims_data);
		entry.entry->claims_from_pac_are_initialized = true;
	} else {
		talloc_steal(mem_ctx, claims_data);
	}

	*claims_data_out = claims_data;

out:
	smb_krb5_free_data_contents(context, &claims_info);
	talloc_free(frame);
	return code;
}

static
krb5_error_code samba_kdc_get_claims_data_from_db(struct ldb_context *samdb,
						  struct samba_kdc_entry *entry,
						  struct claims_data **claims_data_out)
{
	TALLOC_CTX *frame = NULL;

	struct claims_data *claims_data = NULL;
	struct CLAIMS_SET *claims_set = NULL;
	NTSTATUS status = NT_STATUS_OK;
	krb5_error_code code;

	if (samdb == NULL) {
		code = EINVAL;
		goto out;
	}

	if (claims_data_out == NULL) {
		code = EINVAL;
		goto out;
	}

	if (entry == NULL) {
		code = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
		goto out;
	}

	*claims_data_out = NULL;

	if (entry->claims_from_db_are_initialized) {
		/* Note: the caller does not own this! */
		*claims_data_out = entry->claims_from_db;
		return 0;
	}

	frame = talloc_stackframe();

	code = get_claims_set_for_principal(samdb,
					    frame,
					    entry->msg,
					    &claims_set);
	if (code) {
		DBG_ERR("Failed to fetch claims\n");
		goto out;
	}

	if (claims_set != NULL) {
		status = claims_data_from_claims_set(claims_data,
						     claims_set,
						     &claims_data);
		if (!NT_STATUS_IS_OK(status)) {
			code = map_errno_from_nt_status(status);
			goto out;
		}
	}

	entry->claims_from_db = talloc_steal(entry,
					     claims_data);
	entry->claims_from_db_are_initialized = true;

	/* Note: the caller does not own this! */
	*claims_data_out = entry->claims_from_db;

out:
	talloc_free(frame);
	return code;
}

krb5_error_code samba_kdc_check_device(TALLOC_CTX *mem_ctx,
				       krb5_context context,
				       struct samba_kdc_db_context *kdc_db_ctx,
				       const struct samba_kdc_entry_pac device,
				       const struct authn_kerberos_client_policy *client_policy,
				       struct authn_audit_info **client_audit_info_out,
				       NTSTATUS *status_out)
{
	TALLOC_CTX *frame = NULL;
	struct ldb_context *samdb = kdc_db_ctx->samdb;
	struct loadparm_context *lp_ctx = kdc_db_ctx->lp_ctx;
	krb5_error_code code = 0;
	NTSTATUS nt_status;
	const struct auth_user_info_dc *device_info = NULL;
	struct authn_audit_info *client_audit_info = NULL;
	struct auth_claims auth_claims = {};

	if (status_out != NULL) {
		*status_out = NT_STATUS_OK;
	}

	if (!authn_policy_device_restrictions_present(client_policy)) {
		return 0;
	}

	if (device.entry == NULL || device.pac == NULL) {
		NTSTATUS out_status = NT_STATUS_INVALID_WORKSTATION;

		nt_status = authn_kerberos_client_policy_audit_info(mem_ctx,
								    client_policy,
								    NULL /* client_info */,
								    AUTHN_AUDIT_EVENT_KERBEROS_DEVICE_RESTRICTION,
								    AUTHN_AUDIT_REASON_FAST_REQUIRED,
								    out_status,
								    client_audit_info_out);
		if (!NT_STATUS_IS_OK(nt_status)) {
			code = KRB5KRB_ERR_GENERIC;
		} else if (authn_kerberos_client_policy_is_enforced(client_policy)) {
			code = KRB5KDC_ERR_POLICY;

			if (status_out != NULL) {
				*status_out = out_status;
			}
		} else {
			/* OK. */
			code = 0;
		}

		goto out;
	}

	frame = talloc_stackframe();

	code = samba_kdc_get_user_info_dc(frame,
					  context,
					  kdc_db_ctx,
					  device,
					  &device_info,
					  NULL);
	if (code) {
		goto out;
	}

	/*
	 * The device claims become the *user* claims for the purpose of
	 * evaluating a conditional ACE expression.
	 */
	code = samba_kdc_get_claims_data(frame,
					 context,
					 kdc_db_ctx,
					 device,
					 &auth_claims.user_claims);
	if (code) {
		goto out;
	}

	nt_status = authn_policy_authenticate_from_device(frame,
							  samdb,
							  lp_ctx,
							  device_info,
							  auth_claims,
							  client_policy,
							  &client_audit_info);
	if (client_audit_info != NULL) {
		*client_audit_info_out = talloc_move(mem_ctx, &client_audit_info);
	}
	if (!NT_STATUS_IS_OK(nt_status)) {
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_AUTHENTICATION_FIREWALL_FAILED)) {
			code = KRB5KDC_ERR_POLICY;
		} else {
			code = KRB5KRB_ERR_GENERIC;
		}

		goto out;
	}

out:
	talloc_free(frame);
	return code;
}

/*
 * This method is called for S4U2Proxy requests and implements the
 * resource-based constrained delegation variant, which can support
 * cross-realm delegation.
 */
krb5_error_code samba_kdc_check_s4u2proxy_rbcd(
		krb5_context context,
		struct samba_kdc_db_context *kdc_db_ctx,
		krb5_const_principal client_principal,
		krb5_const_principal server_principal,
		struct samba_kdc_entry_pac client,
		struct samba_kdc_entry_pac device,
		struct samba_kdc_entry *proxy_skdc_entry)
{
	krb5_error_code code;
	enum ndr_err_code ndr_err;
	char *client_name = NULL;
	char *server_name = NULL;
	const char *proxy_dn = NULL;
	const DATA_BLOB *data = NULL;
	const struct auth_user_info_dc *user_info_dc = NULL;
	const struct auth_user_info_dc *device_info_dc = NULL;
	struct auth_claims auth_claims = {};
	struct security_descriptor *rbcd_security_descriptor = NULL;
	struct security_token *security_token = NULL;
	uint32_t session_info_flags =
		AUTH_SESSION_INFO_DEFAULT_GROUPS |
		AUTH_SESSION_INFO_DEVICE_DEFAULT_GROUPS |
		AUTH_SESSION_INFO_SIMPLE_PRIVILEGES |
		AUTH_SESSION_INFO_FORCE_COMPOUNDED_AUTHENTICATION;
	/*
	 * Testing shows that although Windows grants SEC_ADS_GENERIC_ALL access
	 * in security descriptors it creates for RBCD, its KDC only requires
	 * SEC_ADS_CONTROL_ACCESS for the access check to succeed.
	 */
	uint32_t access_desired = SEC_ADS_CONTROL_ACCESS;
	uint32_t access_granted = 0;
	NTSTATUS nt_status;
	TALLOC_CTX *mem_ctx = NULL;

	mem_ctx = talloc_named(kdc_db_ctx,
			       0,
			       "samba_kdc_check_s4u2proxy_rbcd");
	if (mem_ctx == NULL) {
		errno = ENOMEM;
		code = errno;

		return code;
	}

	code = samba_kdc_get_user_info_dc(mem_ctx,
					  context,
					  kdc_db_ctx,
					  client,
					  &user_info_dc,
					  NULL /* resource_groups_out */);
	if (code != 0) {
		goto out;
	}

	code = samba_kdc_get_claims_data(mem_ctx,
					 context,
					 kdc_db_ctx,
					 client,
					 &auth_claims.user_claims);
	if (code) {
		goto out;
	}

	if (samba_kdc_entry_pac_valid_principal(device)) {
		code = samba_kdc_get_user_info_dc(mem_ctx,
						  context,
						  kdc_db_ctx,
						  device,
						  &device_info_dc,
						  NULL /* resource_groups_out */);
		if (code) {
			goto out;
		}

		code = samba_kdc_get_claims_data(mem_ctx,
						 context,
						 kdc_db_ctx,
						 device,
						 &auth_claims.device_claims);
		if (code) {
			goto out;
		}
	}

	proxy_dn = ldb_dn_get_linearized(proxy_skdc_entry->msg->dn);
	if (proxy_dn == NULL) {
		DBG_ERR("ldb_dn_get_linearized failed for proxy_dn!\n");
		if (errno == 0) {
			errno = ENOMEM;
		}
		code = errno;

		goto out;
	}

	rbcd_security_descriptor = talloc_zero(mem_ctx,
					       struct security_descriptor);
	if (rbcd_security_descriptor == NULL) {
		errno = ENOMEM;
		code = errno;

		goto out;
	}

	code = krb5_unparse_name_flags(context,
				       client_principal,
				       KRB5_PRINCIPAL_UNPARSE_DISPLAY,
				       &client_name);
	if (code != 0) {
		DBG_ERR("Unable to parse client_principal!\n");
		goto out;
	}

	code = krb5_unparse_name_flags(context,
				       server_principal,
				       KRB5_PRINCIPAL_UNPARSE_DISPLAY,
				       &server_name);
	if (code != 0) {
		DBG_ERR("Unable to parse server_principal!\n");
		goto out;
	}

	DBG_INFO("Check delegation from client[%s] to server[%s] via "
		 "proxy[%s]\n",
		 client_name,
		 server_name,
		 proxy_dn);

	if (!(user_info_dc->info->user_flags & NETLOGON_GUEST)) {
		session_info_flags |= AUTH_SESSION_INFO_AUTHENTICATED;
	}

	if (device_info_dc != NULL && !(device_info_dc->info->user_flags & NETLOGON_GUEST)) {
		session_info_flags |= AUTH_SESSION_INFO_DEVICE_AUTHENTICATED;
	}

	nt_status = auth_generate_security_token(mem_ctx,
						 kdc_db_ctx->lp_ctx,
						 kdc_db_ctx->samdb,
						 user_info_dc,
						 device_info_dc,
						 auth_claims,
						 session_info_flags,
						 &security_token);
	if (!NT_STATUS_IS_OK(nt_status)) {
		code = map_errno_from_nt_status(nt_status);
		goto out;
	}

	data = ldb_msg_find_ldb_val(proxy_skdc_entry->msg,
				    "msDS-AllowedToActOnBehalfOfOtherIdentity");
	if (data == NULL) {
		DBG_WARNING("Could not find security descriptor "
			    "msDS-AllowedToActOnBehalfOfOtherIdentity in "
			    "proxy[%s]\n",
			    proxy_dn);
		code = KRB5KDC_ERR_BADOPTION;
		goto out;
	}

	ndr_err = ndr_pull_struct_blob(
			data,
			mem_ctx,
			rbcd_security_descriptor,
			(ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		errno = ndr_map_error2errno(ndr_err);
		DBG_ERR("Failed to unmarshall "
			"msDS-AllowedToActOnBehalfOfOtherIdentity "
			"security descriptor of proxy[%s]\n",
			proxy_dn);
		code = KRB5KDC_ERR_BADOPTION;
		goto out;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(security_token, security_token);
		NDR_PRINT_DEBUG(security_descriptor, rbcd_security_descriptor);
	}

	nt_status = sec_access_check_ds(rbcd_security_descriptor,
					security_token,
					access_desired,
					&access_granted,
					NULL,
					NULL);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_WARNING("RBCD: sec_access_check_ds(access_desired=%#08x, "
			    "access_granted:%#08x) failed with: %s\n",
			    access_desired,
			    access_granted,
			    nt_errstr(nt_status));

		code = KRB5KDC_ERR_BADOPTION;
		goto out;
	}

	DBG_NOTICE("RBCD: Access granted for client[%s]\n", client_name);

	code = 0;
out:
	SAFE_FREE(client_name);
	SAFE_FREE(server_name);

	TALLOC_FREE(mem_ctx);
	return code;
}
