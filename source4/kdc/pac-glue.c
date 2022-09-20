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
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/talloc_stack.h"

#include "auth/auth_sam_reply.h"
#include "auth/kerberos/kerberos.h"
#include "auth/kerberos/pac_utils.h"
#include "libcli/security/security.h"
#include "libds/common/flags.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "param/param.h"
#include "source4/auth/auth.h"
#include "source4/dsdb/common/util.h"
#include "source4/dsdb/samdb/samdb.h"
#include "source4/kdc/samba_kdc.h"
#include "source4/kdc/pac-glue.h"

#include <ldb.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_KERBEROS

static
NTSTATUS samba_get_logon_info_pac_blob(TALLOC_CTX *mem_ctx,
				       const struct auth_user_info_dc *info,
				       DATA_BLOB *pac_data,
				       DATA_BLOB *requester_sid_blob)
{
	struct netr_SamInfo3 *info3;
	union PAC_INFO pac_info;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	ZERO_STRUCT(pac_info);

	*pac_data = data_blob_null;
	if (requester_sid_blob != NULL) {
		*requester_sid_blob = data_blob_null;
	}

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
		DEBUG(1, ("PAC_LOGON_INFO (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	if (requester_sid_blob != NULL && info->num_sids > 0) {
		union PAC_INFO pac_requester_sid;

		ZERO_STRUCT(pac_requester_sid);

		pac_requester_sid.requester_sid.sid = info->sids[0];

		ndr_err = ndr_push_union_blob(requester_sid_blob, mem_ctx,
					      &pac_requester_sid,
					      PAC_TYPE_REQUESTER_SID,
					      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			nt_status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(1, ("PAC_REQUESTER_SID (presig) push failed: %s\n",
				  nt_errstr(nt_status)));
			return nt_status;
		}
	}

	return NT_STATUS_OK;
}

static
NTSTATUS samba_get_upn_info_pac_blob(TALLOC_CTX *mem_ctx,
				     const struct auth_user_info_dc *info,
				     DATA_BLOB *upn_data)
{
	union PAC_INFO pac_upn;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;
	bool ok;

	ZERO_STRUCT(pac_upn);

	*upn_data = data_blob_null;

	pac_upn.upn_dns_info.upn_name = info->info->user_principal_name;
	pac_upn.upn_dns_info.dns_domain_name = strupper_talloc(mem_ctx,
						info->info->dns_domain_name);
	if (pac_upn.upn_dns_info.dns_domain_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	if (info->info->user_principal_constructed) {
		pac_upn.upn_dns_info.flags |= PAC_UPN_DNS_FLAG_CONSTRUCTED;
	}

	pac_upn.upn_dns_info.flags |= PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID;

	pac_upn.upn_dns_info.ex.sam_name_and_sid.samaccountname
		= info->info->account_name;

	pac_upn.upn_dns_info.ex.sam_name_and_sid.objectsid
		= &info->sids[0];

	ndr_err = ndr_push_union_blob(upn_data, mem_ctx, &pac_upn,
				      PAC_TYPE_UPN_DNS_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC UPN_DNS_INFO (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	ok = data_blob_pad(mem_ctx, upn_data, 8);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static
NTSTATUS samba_get_pac_attrs_blob(TALLOC_CTX *mem_ctx,
				  uint64_t pac_attributes,
				  DATA_BLOB *pac_attrs_data)
{
	union PAC_INFO pac_attrs;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;

	ZERO_STRUCT(pac_attrs);

	*pac_attrs_data = data_blob_null;

	/* Set the length of the flags in bits. */
	pac_attrs.attributes_info.flags_length = 2;
	pac_attrs.attributes_info.flags = pac_attributes;

	ndr_err = ndr_push_union_blob(pac_attrs_data, mem_ctx, &pac_attrs,
				      PAC_TYPE_ATTRIBUTES_INFO,
				      (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC ATTRIBUTES_INFO (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	return NT_STATUS_OK;
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
	struct PAC_CREDENTIAL_DATA_NDR cred_ndr;

	ZERO_STRUCT(cred_ndr);

	*cred_blob = data_blob_null;

	lm_hash = samdb_result_hash(mem_ctx, msg, "dBCSPwd");
	if (lm_hash != NULL) {
		bool zero = all_zero(lm_hash->hash, 16);
		if (zero) {
			lm_hash = NULL;
		}
	}
	if (lm_hash != NULL) {
		DEBUG(5, ("Passing LM password hash through credentials set\n"));
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
		DEBUG(5, ("Passing LM password hash through credentials set\n"));
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
		DEBUG(1, ("PAC_CREDENTIAL_NTLM_SECPKG (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	DEBUG(10, ("NTLM credential BLOB (len %zu) for user\n",
		  ntlm_blob.length));
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
		DEBUG(1, ("PAC_CREDENTIAL_DATA_NDR (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	DEBUG(10, ("Created credential BLOB (len %zu) for user\n",
		  cred_blob->length));
	dump_data_pw("PAC_CREDENTIAL_DATA_NDR",
		     cred_blob->data, cred_blob->length);

	return NT_STATUS_OK;
}

#ifdef SAMBA4_USES_HEIMDAL
krb5_error_code samba_kdc_encrypt_pac_credentials(krb5_context context,
						  const krb5_keyblock *pkreplykey,
						  const DATA_BLOB *cred_ndr_blob,
						  TALLOC_CTX *mem_ctx,
						  DATA_BLOB *cred_info_blob)
{
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
		DEBUG(1, ("Failed initializing cred data crypto: %s\n", krb5err));
		krb5_free_error_message(context, krb5err);
		return ret;
	}

	ret = krb5_crypto_getenctype(context, cred_crypto, &cred_enctype);
	if (ret != 0) {
		DEBUG(1, ("Failed getting crypto type for key\n"));
		krb5_crypto_destroy(context, cred_crypto);
		return ret;
	}

	DEBUG(10, ("Plain cred_ndr_blob (len %zu)\n",
		  cred_ndr_blob->length));
	dump_data_pw("PAC_CREDENTIAL_DATA_NDR",
		     cred_ndr_blob->data, cred_ndr_blob->length);

	ret = krb5_encrypt(context, cred_crypto,
			   KRB5_KU_OTHER_ENCRYPTED,
			   cred_ndr_blob->data, cred_ndr_blob->length,
			   &cred_ndr_crypt);
	krb5_crypto_destroy(context, cred_crypto);
	if (ret != 0) {
		krb5err = krb5_get_error_message(context, ret);
		DEBUG(1, ("Failed crypt of cred data: %s\n", krb5err));
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
		DEBUG(1, ("PAC_CREDENTIAL_INFO (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return KRB5KDC_ERR_SVC_UNAVAILABLE;
	}

	DEBUG(10, ("Encrypted credential BLOB (len %zu) with alg %d\n",
		  cred_info_blob->length, (int)pac_cred_info.encryption_type));
	dump_data_pw("PAC_CREDENTIAL_INFO",
		      cred_info_blob->data, cred_info_blob->length);

	return 0;
}
#else /* SAMBA4_USES_HEIMDAL */
krb5_error_code samba_kdc_encrypt_pac_credentials(krb5_context context,
						  const krb5_keyblock *pkreplykey,
						  const DATA_BLOB *cred_ndr_blob,
						  TALLOC_CTX *mem_ctx,
						  DATA_BLOB *cred_info_blob)
{
	krb5_key cred_key;
	krb5_enctype cred_enctype;
	struct PAC_CREDENTIAL_INFO pac_cred_info = { .version = 0, };
	krb5_error_code code;
	const char *krb5err;
	enum ndr_err_code ndr_err;
	NTSTATUS nt_status;
	krb5_data cred_ndr_data;
	krb5_enc_data cred_ndr_crypt;
	size_t enc_len = 0;

	*cred_info_blob = data_blob_null;

	code = krb5_k_create_key(context,
				 pkreplykey,
				 &cred_key);
	if (code != 0) {
		krb5err = krb5_get_error_message(context, code);
		DEBUG(1, ("Failed initializing cred data crypto: %s\n", krb5err));
		krb5_free_error_message(context, krb5err);
		return code;
	}

	cred_enctype = krb5_k_key_enctype(context, cred_key);

	DEBUG(10, ("Plain cred_ndr_blob (len %zu)\n",
		  cred_ndr_blob->length));
	dump_data_pw("PAC_CREDENTIAL_DATA_NDR",
		     cred_ndr_blob->data, cred_ndr_blob->length);

	pac_cred_info.encryption_type = cred_enctype;

	cred_ndr_data.magic = 0;
	cred_ndr_data.data = (char *)cred_ndr_blob->data;
	cred_ndr_data.length = cred_ndr_blob->length;

	code = krb5_c_encrypt_length(context,
				     cred_enctype,
				     cred_ndr_data.length,
				     &enc_len);
	if (code != 0) {
		krb5err = krb5_get_error_message(context, code);
		DEBUG(1, ("Failed initializing cred data crypto: %s\n", krb5err));
		krb5_free_error_message(context, krb5err);
		return code;
	}

	pac_cred_info.encrypted_data = data_blob_talloc_zero(mem_ctx, enc_len);
	if (pac_cred_info.encrypted_data.data == NULL) {
		DBG_ERR("Out of memory\n");
		return ENOMEM;
	}

	cred_ndr_crypt.ciphertext.length = enc_len;
	cred_ndr_crypt.ciphertext.data = (char *)pac_cred_info.encrypted_data.data;

	code = krb5_k_encrypt(context,
			      cred_key,
			      KRB5_KU_OTHER_ENCRYPTED,
			      NULL,
			      &cred_ndr_data,
			      &cred_ndr_crypt);
	krb5_k_free_key(context, cred_key);
	if (code != 0) {
		krb5err = krb5_get_error_message(context, code);
		DEBUG(1, ("Failed crypt of cred data: %s\n", krb5err));
		krb5_free_error_message(context, krb5err);
		return code;
	}

	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(PAC_CREDENTIAL_INFO, &pac_cred_info);
	}

	ndr_err = ndr_push_struct_blob(cred_info_blob, mem_ctx, &pac_cred_info,
			(ndr_push_flags_fn_t)ndr_push_PAC_CREDENTIAL_INFO);
	TALLOC_FREE(pac_cred_info.encrypted_data.data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1, ("PAC_CREDENTIAL_INFO (presig) push failed: %s\n",
			  nt_errstr(nt_status)));
		return KRB5KDC_ERR_SVC_UNAVAILABLE;
	}

	DEBUG(10, ("Encrypted credential BLOB (len %zu) with alg %d\n",
		  cred_info_blob->length, (int)pac_cred_info.encryption_type));
	dump_data_pw("PAC_CREDENTIAL_INFO",
		      cred_info_blob->data, cred_info_blob->length);

	return 0;
}
#endif /* SAMBA4_USES_HEIMDAL */


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
 * @param[in] pac        The pac buffer to fill. This should be allocated with
 *                       krb5_pac_init() already.
 *
 * @returns 0 on success or a corresponding KRB5 error.
 */
krb5_error_code samba_make_krb5_pac(krb5_context context,
				    const DATA_BLOB *logon_blob,
				    const DATA_BLOB *cred_blob,
				    const DATA_BLOB *upn_blob,
				    const DATA_BLOB *pac_attrs_blob,
				    const DATA_BLOB *requester_sid_blob,
				    const DATA_BLOB *deleg_blob,
				    krb5_pac pac)
{
	krb5_data logon_data;
	krb5_error_code ret;
#ifdef SAMBA4_USES_HEIMDAL
	char null_byte = '\0';
	krb5_data null_data = smb_krb5_make_data(&null_byte, 1);
#endif

	/* The user account may be set not to want the PAC */
	if (logon_blob == NULL) {
		return 0;
	}

	logon_data = smb_krb5_data_from_blob(*logon_blob);
	ret = krb5_pac_add_buffer(context, pac, PAC_TYPE_LOGON_INFO, &logon_data);
	if (ret != 0) {
		return ret;
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

bool samba_princ_needs_pac(struct samba_kdc_entry *skdc_entry)
{

	uint32_t userAccountControl;

	/* The service account may be set not to want the PAC */
	userAccountControl = ldb_msg_find_attr_as_uint(skdc_entry->msg, "userAccountControl", 0);
	if (userAccountControl & UF_NO_AUTH_DATA_REQUIRED) {
		return false;
	}

	return true;
}

int samba_client_requested_pac(krb5_context context,
			       const krb5_pac *pac,
			       TALLOC_CTX *mem_ctx,
			       bool *requested_pac)
{
	enum ndr_err_code ndr_err;
	krb5_data k5pac_attrs_in;
	DATA_BLOB pac_attrs_in;
	union PAC_INFO pac_attrs;
	int ret;

	*requested_pac = true;

	ret = krb5_pac_get_buffer(context, *pac, PAC_TYPE_ATTRIBUTES_INFO,
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
		DEBUG(0,("can't parse the PAC ATTRIBUTES_INFO: %s\n", nt_errstr(nt_status)));
		return EINVAL;
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
int samba_krbtgt_is_in_db(struct samba_kdc_entry *p,
			  bool *is_in_db,
			  bool *is_untrusted)
{
	NTSTATUS status;
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

/*
 * Because the KDC does not limit protocol transition, two new well-known SIDs
 * were introduced to give this control to the resource administrator. These
 * SIDs identify whether protocol transition has occurred, and can be used with
 * standard access control lists to grant or limit access as needed.
 *
 * https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview
 */
static NTSTATUS samba_add_asserted_identity(TALLOC_CTX *mem_ctx,
					    enum samba_asserted_identity ai,
					    struct auth_user_info_dc *user_info_dc)
{
	struct dom_sid ai_sid;
	const char *sid_str = NULL;

	switch (ai) {
	case SAMBA_ASSERTED_IDENTITY_SERVICE:
		sid_str = SID_SERVICE_ASSERTED_IDENTITY;
		break;
	case SAMBA_ASSERTED_IDENTITY_AUTHENTICATION_AUTHORITY:
		sid_str = SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY;
		break;
	case SAMBA_ASSERTED_IDENTITY_IGNORE:
		return NT_STATUS_OK;
	}

	dom_sid_parse(sid_str, &ai_sid);

	return add_sid_to_array_unique(user_info_dc,
				       &ai_sid,
				       &user_info_dc->sids,
				       &user_info_dc->num_sids);
}

/*
 * Look up the user's info in the database and create a auth_user_info_dc
 * structure. If the resulting structure is not talloc_free()d, it will be
 * reused on future calls to this function.
 */
NTSTATUS samba_kdc_get_user_info_from_db(struct samba_kdc_entry *skdc_entry,
                                         struct ldb_message *msg,
                                         struct auth_user_info_dc **user_info_dc)
{
	if (skdc_entry->user_info_dc == NULL) {
		NTSTATUS nt_status;
		struct loadparm_context *lp_ctx = skdc_entry->kdc_db_ctx->lp_ctx;

		nt_status = authsam_make_user_info_dc(skdc_entry,
						      skdc_entry->kdc_db_ctx->samdb,
						      lpcfg_netbios_name(lp_ctx),
						      lpcfg_sam_name(lp_ctx),
						      lpcfg_sam_dnsname(lp_ctx),
						      skdc_entry->realm_dn,
						      msg,
						      data_blob_null,
						      data_blob_null,
						      &skdc_entry->user_info_dc);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	}

	*user_info_dc = skdc_entry->user_info_dc;
	return NT_STATUS_OK;
}

NTSTATUS samba_kdc_get_pac_blobs(TALLOC_CTX *mem_ctx,
				 struct samba_kdc_entry *p,
				 enum samba_asserted_identity asserted_identity,
				 DATA_BLOB **_logon_info_blob,
				 DATA_BLOB **_cred_ndr_blob,
				 DATA_BLOB **_upn_info_blob,
				 DATA_BLOB **_pac_attrs_blob,
				 uint64_t pac_attributes,
				 DATA_BLOB **_requester_sid_blob)
{
	struct auth_user_info_dc *user_info_dc = NULL;
	DATA_BLOB *logon_blob = NULL;
	DATA_BLOB *cred_blob = NULL;
	DATA_BLOB *upn_blob = NULL;
	DATA_BLOB *pac_attrs_blob = NULL;
	DATA_BLOB *requester_sid_blob = NULL;
	NTSTATUS nt_status;

	*_logon_info_blob = NULL;
	if (_cred_ndr_blob != NULL) {
		*_cred_ndr_blob = NULL;
	}
	*_upn_info_blob = NULL;
	if (_pac_attrs_blob != NULL) {
		*_pac_attrs_blob = NULL;
	}
	if (_requester_sid_blob != NULL) {
		*_requester_sid_blob = NULL;
	}

	logon_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (logon_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (_cred_ndr_blob != NULL) {
		cred_blob = talloc_zero(mem_ctx, DATA_BLOB);
		if (cred_blob == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	upn_blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (upn_blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (_pac_attrs_blob != NULL) {
		pac_attrs_blob = talloc_zero(mem_ctx, DATA_BLOB);
		if (pac_attrs_blob == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (_requester_sid_blob != NULL) {
		requester_sid_blob = talloc_zero(mem_ctx, DATA_BLOB);
		if (requester_sid_blob == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	nt_status = samba_kdc_get_user_info_from_db(p,
						    p->msg,
						    &user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Getting user info for PAC failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	nt_status = samba_add_asserted_identity(mem_ctx,
						asserted_identity,
						user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_ERR("Failed to add assertied identity!\n");
		return nt_status;
	}

	nt_status = samba_get_logon_info_pac_blob(logon_blob,
						  user_info_dc,
						  logon_blob,
						  requester_sid_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Building PAC LOGON INFO failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	if (cred_blob != NULL) {
		nt_status = samba_get_cred_info_ndr_blob(cred_blob,
							 p->msg,
							 cred_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("Building PAC CRED INFO failed: %s\n",
				  nt_errstr(nt_status)));
			return nt_status;
		}
	}

	nt_status = samba_get_upn_info_pac_blob(upn_blob,
						user_info_dc,
						upn_blob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Building PAC UPN INFO failed: %s\n",
			  nt_errstr(nt_status)));
		return nt_status;
	}

	if (pac_attrs_blob != NULL) {
		nt_status = samba_get_pac_attrs_blob(pac_attrs_blob,
						     pac_attributes,
						     pac_attrs_blob);

		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("Building PAC ATTRIBUTES failed: %s\n",
				  nt_errstr(nt_status)));
			return nt_status;
		}
	}

	*_logon_info_blob = logon_blob;
	if (_cred_ndr_blob != NULL) {
		*_cred_ndr_blob = cred_blob;
	}
	*_upn_info_blob = upn_blob;
	if (_pac_attrs_blob != NULL) {
		*_pac_attrs_blob = pac_attrs_blob;
	}
	if (_requester_sid_blob != NULL) {
		*_requester_sid_blob = requester_sid_blob;
	}
	return NT_STATUS_OK;
}

NTSTATUS samba_kdc_update_pac_blob(TALLOC_CTX *mem_ctx,
				   krb5_context context,
				   struct ldb_context *samdb,
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

	/*
	 * We need to expand group memberships within our local domain,
	 * as the token might be generated by a trusted domain.
	 */
	nt_status = authsam_update_user_info_dc(mem_ctx,
						samdb,
						user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = samba_get_logon_info_pac_blob(mem_ctx,
						  user_info_dc, pac_blob, NULL);

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
			smb_krb5_free_data_contents(context, &old_data);
			nt_status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(0,("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status)));
			talloc_free(tmp_ctx);
			return nt_status;
		}
	} else {
		ZERO_STRUCT(_d);
		info.constrained_delegation.info = &_d;
	}
	smb_krb5_free_data_contents(context, &old_data);

	ret = krb5_unparse_name_flags(context, server_principal,
				      KRB5_PRINCIPAL_UNPARSE_NO_REALM, &server);
	if (ret) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = krb5_unparse_name(context, proxy_principal, &proxy);
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
		smb_krb5_free_data_contents(context, &old_data);
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the PAC LOGON_INFO: %s\n", nt_errstr(nt_status)));
		talloc_free(tmp_ctx);
		return nt_status;
	}

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
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
					       krb5_pac pac,
					       krb5_context context,
					       struct dom_sid *sid)
{
	NTSTATUS nt_status;
	enum ndr_err_code ndr_err;
	krb5_error_code ret;

	DATA_BLOB pac_requester_sid_in;
	krb5_data k5pac_requester_sid_in;

	union PAC_INFO info;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_REQUESTER_SID,
				  &k5pac_requester_sid_in);
	if (ret != 0) {
		talloc_free(tmp_ctx);
		return ret;
	}

	pac_requester_sid_in = data_blob_const(k5pac_requester_sid_in.data,
					       k5pac_requester_sid_in.length);

	ndr_err = ndr_pull_union_blob(&pac_requester_sid_in, tmp_ctx, &info,
				      PAC_TYPE_REQUESTER_SID,
				      (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
	smb_krb5_free_data_contents(context, &k5pac_requester_sid_in);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("can't parse the PAC REQUESTER_SID: %s\n", nt_errstr(nt_status)));
		talloc_free(tmp_ctx);
		return EINVAL;
	}

	*sid = info.requester_sid.sid;

	talloc_free(tmp_ctx);
	return 0;
}

/* Does a parse and SID check, but no crypto. */
krb5_error_code samba_kdc_validate_pac_blob(
		krb5_context context,
		struct samba_kdc_entry *client_skdc_entry,
		const krb5_pac pac)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct auth_user_info_dc *pac_user_info = NULL;
	struct dom_sid *client_sid = NULL;
	struct dom_sid pac_sid;
	krb5_error_code code;
	bool ok;

	/*
	 * First, try to get the SID from the requester SID buffer in the PAC.
	 */
	code = samba_get_requester_sid(frame, pac, context, &pac_sid);

	if (code == ENOENT) {
		/*
		 * If the requester SID buffer isn't present, fall back to the
		 * SID in the LOGON_INFO PAC buffer.
		 */
		code = kerberos_pac_to_user_info_dc(frame,
						    pac,
						    context,
						    &pac_user_info,
						    NULL,
						    NULL);
		if (code != 0) {
			goto out;
		}

		if (pac_user_info->num_sids == 0) {
			code = EINVAL;
			goto out;
		}

		pac_sid = pac_user_info->sids[0];
	} else if (code != 0) {
		goto out;
	}

	client_sid = samdb_result_dom_sid(frame,
					  client_skdc_entry->msg,
					  "objectSid");

	ok = dom_sid_equal(&pac_sid, client_sid);
	if (!ok) {
		struct dom_sid_buf buf1;
		struct dom_sid_buf buf2;

		DBG_ERR("SID mismatch between PAC and looked up client: "
			"PAC[%s] != CLI[%s]\n",
			dom_sid_str_buf(&pac_sid, &buf1),
			dom_sid_str_buf(client_sid, &buf2));
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
WERROR samba_rodc_confirm_user_is_allowed(uint32_t num_object_sids,
					  struct dom_sid *object_sids,
					  struct samba_kdc_entry *rodc,
					  struct samba_kdc_entry *object)
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

/**
 * @brief Update a PAC
 *
 * @param mem_ctx   A talloc memory context
 *
 * @param context   A krb5 context
 *
 * @param samdb     An open samdb connection.
 *
 * @param flags     Bitwise OR'ed flags
 *
 * @param client    The client samba kdc entry.

 * @param server_principal  The server principal

 * @param server    The server samba kdc entry.

 * @param krbtgt    The krbtgt samba kdc entry.
 *
 * @param delegated_proxy_principal The delegated proxy principal used for
 *                                  updating the constrained delegation PAC
 *                                  buffer.

 * @param old_pac                   The old PAC

 * @param new_pac                   The new already allocated PAC

 * @return A Kerberos error code. If no PAC should be returned, the code will be
 * ENODATA!
 */
krb5_error_code samba_kdc_update_pac(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     struct ldb_context *samdb,
				     uint32_t flags,
				     struct samba_kdc_entry *client,
				     const krb5_principal server_principal,
				     struct samba_kdc_entry *server,
				     struct samba_kdc_entry *krbtgt,
				     const krb5_principal delegated_proxy_principal,
				     const krb5_pac old_pac,
				     krb5_pac new_pac)
{
	krb5_error_code code = EINVAL;
	NTSTATUS nt_status;
	DATA_BLOB *pac_blob = NULL;
	DATA_BLOB *upn_blob = NULL;
	DATA_BLOB *deleg_blob = NULL;
	DATA_BLOB *requester_sid_blob = NULL;
	bool is_untrusted = flags & SAMBA_KDC_FLAG_KRBTGT_IS_UNTRUSTED;
	int is_tgs = false;
	size_t num_types = 0;
	uint32_t *types = NULL;
	/*
	 * FIXME: Do we really still need forced_next_type? With MIT Kerberos
	 * the PAC buffers do not get ordered and it works just fine. We are
	 * not aware of any issues in this regard. This might be just ancient
	 * code.
	 */
	uint32_t forced_next_type = 0;
	size_t i = 0;
	ssize_t logon_info_idx = -1;
	ssize_t delegation_idx = -1;
	ssize_t logon_name_idx = -1;
	ssize_t upn_dns_info_idx = -1;
	ssize_t srv_checksum_idx = -1;
	ssize_t kdc_checksum_idx = -1;
	ssize_t tkt_checksum_idx = -1;
	ssize_t attrs_info_idx = -1;
	ssize_t requester_sid_idx = -1;

	if (client != NULL) {
		/*
		 * Check the objectSID of the client and pac data are the same.
		 * Does a parse and SID check, but no crypto.
		 */
		code = samba_kdc_validate_pac_blob(context,
						   client,
						   old_pac);
		if (code != 0) {
			goto done;
		}
	}

	if (delegated_proxy_principal != NULL) {
		deleg_blob = talloc_zero(mem_ctx, DATA_BLOB);
		if (deleg_blob == NULL) {
			code = ENOMEM;
			goto done;
		}

		nt_status = samba_kdc_update_delegation_info_blob(
				mem_ctx,
				context,
				old_pac,
				server_principal,
				delegated_proxy_principal,
				deleg_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("update delegation info blob failed: %s\n",
				nt_errstr(nt_status));
			code = EINVAL;
			goto done;
		}
	}

	if (is_untrusted) {
		struct auth_user_info_dc *user_info_dc = NULL;
		WERROR werr;
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
		enum samba_asserted_identity asserted_identity =
			SAMBA_ASSERTED_IDENTITY_AUTHENTICATION_AUTHORITY;

		if (client == NULL) {
			code = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
			goto done;
		}

		nt_status = samba_kdc_get_pac_blobs(mem_ctx,
						    client,
						    asserted_identity,
						    &pac_blob,
						    NULL,
						    &upn_blob,
						    NULL,
						    PAC_ATTRIBUTE_FLAG_PAC_WAS_GIVEN_IMPLICITLY,
						    &requester_sid_blob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("samba_kdc_get_pac_blobs failed: %s\n",
				nt_errstr(nt_status));
			code = KRB5KDC_ERR_TGT_REVOKED;
			goto done;
		}

		nt_status = samba_kdc_get_user_info_from_db(client,
							    client->msg,
							    &user_info_dc);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("samba_kdc_get_user_info_from_db failed: %s\n",
				nt_errstr(nt_status));
			code = KRB5KDC_ERR_TGT_REVOKED;
			goto done;
		}

		/*
		 * Check if the SID list in the user_info_dc intersects
		 * correctly with the RODC allow/deny lists.
		 */
		werr = samba_rodc_confirm_user_is_allowed(user_info_dc->num_sids,
							  user_info_dc->sids,
							  krbtgt,
							  client);
		TALLOC_FREE(user_info_dc);
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
	} else {
		pac_blob = talloc_zero(mem_ctx, DATA_BLOB);
		if (pac_blob == NULL) {
			code = ENOMEM;
			goto done;
		}

		nt_status = samba_kdc_update_pac_blob(mem_ctx,
						      context,
						      samdb,
						      old_pac,
						      pac_blob,
						      NULL,
						      NULL);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DBG_ERR("samba_kdc_update_pac_blob failed: %s\n",
				 nt_errstr(nt_status));
			code = EINVAL;
			goto done;
		}
	}

	/* Check the types of the given PAC */
	code = krb5_pac_get_types(context, old_pac, &num_types, &types);
	if (code != 0) {
		DBG_ERR("krb5_pac_get_types failed\n");
		goto done;
	}

	for (i = 0; i < num_types; i++) {
		switch (types[i]) {
		case PAC_TYPE_LOGON_INFO:
			if (logon_info_idx != -1) {
				DBG_WARNING("logon info type[%u] twice [%zd] "
					    "and [%zu]: \n",
					    types[i],
					    logon_info_idx,
					    i);
				code = EINVAL;
				goto done;
			}
			logon_info_idx = i;
			break;
		case PAC_TYPE_CONSTRAINED_DELEGATION:
			if (delegation_idx != -1) {
				DBG_WARNING("constrained delegation type[%u] "
					    "twice [%zd] and [%zu]: \n",
					    types[i],
					    delegation_idx,
					    i);
				code = EINVAL;
				goto done;
			}
			delegation_idx = i;
			break;
		case PAC_TYPE_LOGON_NAME:
			if (logon_name_idx != -1) {
				DBG_WARNING("logon name type[%u] twice [%zd] "
					    "and [%zu]: \n",
					    types[i],
					    logon_name_idx,
					    i);
				code = EINVAL;
				goto done;
			}
			logon_name_idx = i;
			break;
		case PAC_TYPE_UPN_DNS_INFO:
			if (upn_dns_info_idx != -1) {
				DBG_WARNING("upn dns info type[%u] twice [%zd] "
					    "and [%zu]: \n",
					    types[i],
					    upn_dns_info_idx,
					    i);
				code = EINVAL;
				goto done;
			}
			upn_dns_info_idx = i;
			break;
		case PAC_TYPE_SRV_CHECKSUM:
			if (srv_checksum_idx != -1) {
				DBG_WARNING("srv checksum type[%u] twice [%zd] "
					    "and [%zu]: \n",
					    types[i],
					    srv_checksum_idx,
					    i);
				code = EINVAL;
				goto done;
			}
			srv_checksum_idx = i;
			break;
		case PAC_TYPE_KDC_CHECKSUM:
			if (kdc_checksum_idx != -1) {
				DBG_WARNING("kdc checksum type[%u] twice [%zd] "
					    "and [%zu]: \n",
					    types[i],
					    kdc_checksum_idx,
					    i);
				code = EINVAL;
				goto done;
			}
			kdc_checksum_idx = i;
			break;
		case PAC_TYPE_TICKET_CHECKSUM:
			if (tkt_checksum_idx != -1) {
				DBG_WARNING("ticket checksum type[%u] twice "
					    "[%zd] and [%zu]: \n",
					    types[i],
					    tkt_checksum_idx,
					    i);
				code = EINVAL;
				goto done;
			}
			tkt_checksum_idx = i;
			break;
		case PAC_TYPE_ATTRIBUTES_INFO:
			if (attrs_info_idx != -1) {
				DBG_WARNING("attributes info type[%u] twice "
					    "[%zd] and [%zu]: \n",
					    types[i],
					    attrs_info_idx,
					    i);
				code = EINVAL;
				goto done;
			}
			attrs_info_idx = i;
			break;
		case PAC_TYPE_REQUESTER_SID:
			if (requester_sid_idx != -1) {
				DBG_WARNING("requester sid type[%u] twice"
					    "[%zd] and [%zu]: \n",
					    types[i],
					    requester_sid_idx,
					    i);
				code = EINVAL;
				goto done;
			}
			requester_sid_idx = i;
			break;
		default:
			continue;
		}
	}

	if (logon_info_idx == -1) {
		DBG_WARNING("PAC_TYPE_LOGON_INFO missing\n");
		code = EINVAL;
		goto done;
	}
	if (logon_name_idx == -1) {
		DBG_WARNING("PAC_TYPE_LOGON_NAME missing\n");
		code = EINVAL;
		goto done;
	}
	if (srv_checksum_idx == -1) {
		DBG_WARNING("PAC_TYPE_SRV_CHECKSUM missing\n");
		code = EINVAL;
		goto done;
	}
	if (kdc_checksum_idx == -1) {
		DBG_WARNING("PAC_TYPE_KDC_CHECKSUM missing\n");
		code = EINVAL;
		goto done;
	}
	if (!(flags & SAMBA_KDC_FLAG_CONSTRAINED_DELEGATION) &&
	    requester_sid_idx == -1) {
		DBG_WARNING("PAC_TYPE_REQUESTER_SID missing\n");
		code = KRB5KDC_ERR_TGT_REVOKED;
		goto done;
	}

	/*
	 * The server account may be set not to want the PAC.
	 *
	 * While this is wasteful if the above cacluations were done
	 * and now thrown away, this is cleaner as we do any ticket
	 * signature checking etc always.
	 *
	 * UF_NO_AUTH_DATA_REQUIRED is the rare case and most of the
	 * time (eg not accepting a ticket from the RODC) we do not
	 * need to re-generate anything anyway.
	 */
	if (!samba_princ_needs_pac(server)) {
		code = ENODATA;
		goto done;
	}

	is_tgs = smb_krb5_principal_is_tgs(context, server_principal);
	if (is_tgs == -1) {
		code = ENOMEM;
		goto done;
	}

	if (!is_untrusted && !is_tgs) {
		/*
		 * The client may have requested no PAC when obtaining the
		 * TGT.
		 */
		bool requested_pac = false;

		code = samba_client_requested_pac(context,
						  &old_pac,
						  mem_ctx,
						  &requested_pac);
		if (code != 0 || !requested_pac) {
			if (!requested_pac) {
				code = ENODATA;
			}
			goto done;
		}
	}

#define MAX_PAC_BUFFERS 128 /* Avoid infinite loops */

	for (i = 0; i < MAX_PAC_BUFFERS;) {
		const uint8_t zero_byte = 0;
		krb5_data type_data;
		DATA_BLOB type_blob = data_blob_null;
		uint32_t type;

		if (forced_next_type != 0) {
			/*
			 * We need to inject possible missing types
			 */
			type = forced_next_type;
			forced_next_type = 0;
		} else if (i < num_types) {
			type = types[i];
			i++;
		} else {
			break;
		}

		switch (type) {
		case PAC_TYPE_LOGON_INFO:
			type_blob = *pac_blob;

			if (delegation_idx == -1 && deleg_blob != NULL) {
				/* inject CONSTRAINED_DELEGATION behind */
				forced_next_type =
					PAC_TYPE_CONSTRAINED_DELEGATION;
			}
			break;
		case PAC_TYPE_CONSTRAINED_DELEGATION:
			/*
			 * This is generated in the main KDC code
			 */
			if (flags & SAMBA_KDC_FLAG_SKIP_PAC_BUFFER) {
				continue;
			}

			if (deleg_blob != NULL) {
				type_blob = *deleg_blob;
			}
			break;
		case PAC_TYPE_CREDENTIAL_INFO:
			/*
			 * Note that we copy the credential blob,
			 * as it's only usable with the PKINIT based
			 * AS-REP reply key, it's only available on the
			 * host which did the AS-REQ/AS-REP exchange.
			 *
			 * This matches Windows 2008R2...
			 */
			break;
		case PAC_TYPE_LOGON_NAME:
			/*
			 * This is generated in the main KDC code
			 */
			if (flags & SAMBA_KDC_FLAG_SKIP_PAC_BUFFER) {
				continue;
			}

			type_blob = data_blob_const(&zero_byte, 1);

			if (upn_dns_info_idx == -1 && upn_blob != NULL) {
				/* inject UPN_DNS_INFO behind */
				forced_next_type = PAC_TYPE_UPN_DNS_INFO;
			}
			break;
		case PAC_TYPE_UPN_DNS_INFO:
			/*
			 * Replace in the RODC case, otherwise
			 * upn_blob is NULL and we just copy.
			 */
			if (upn_blob != NULL) {
				type_blob = *upn_blob;
			}
			break;
		case PAC_TYPE_SRV_CHECKSUM:
			/*
			 * This is generated in the main KDC code
			 */
			if (flags & SAMBA_KDC_FLAG_SKIP_PAC_BUFFER) {
				continue;
			}

			type_blob = data_blob_const(&zero_byte, 1);

			if (requester_sid_idx == -1 && requester_sid_blob != NULL) {
				/* inject REQUESTER_SID behind */
				forced_next_type = PAC_TYPE_REQUESTER_SID;
			}
			break;
		case PAC_TYPE_KDC_CHECKSUM:
			/*
			 * This is generated in the main KDC code
			 */
			if (flags & SAMBA_KDC_FLAG_SKIP_PAC_BUFFER) {
				continue;
			}

			type_blob = data_blob_const(&zero_byte, 1);

			break;
		case PAC_TYPE_TICKET_CHECKSUM:
			/*
			 * This is generated in the main KDC code
			 */
			if (flags & SAMBA_KDC_FLAG_SKIP_PAC_BUFFER) {
				continue;
			}

			type_blob = data_blob_const(&zero_byte, 1);

			break;
		case PAC_TYPE_ATTRIBUTES_INFO:
			if (!is_untrusted && is_tgs) {
				/* just copy... */
				break;
			}

			continue;
		case PAC_TYPE_REQUESTER_SID:
			if (!is_tgs) {
				continue;
			}

			/*
			 * Replace in the RODC case, otherwise
			 * requester_sid_blob is NULL and we just copy.
			 */
			if (requester_sid_blob != NULL) {
				type_blob = *requester_sid_blob;
			}
			break;
		default:
			/* just copy... */
			break;
		}

		if (type_blob.length != 0) {
			code = smb_krb5_copy_data_contents(&type_data,
							   type_blob.data,
							   type_blob.length);
			if (code != 0) {
				goto done;
			}
		} else {
			code = krb5_pac_get_buffer(context,
						   old_pac,
						   type,
						   &type_data);
			if (code != 0) {
				goto done;
			}
		}

		code = krb5_pac_add_buffer(context,
					   new_pac,
					   type,
					   &type_data);
		smb_krb5_free_data_contents(context, &type_data);
		if (code != 0) {
			goto done;
		}
	}

	code = 0;
done:
	TALLOC_FREE(pac_blob);
	TALLOC_FREE(upn_blob);
	TALLOC_FREE(deleg_blob);
	SAFE_FREE(types);
	return code;
}
