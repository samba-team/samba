/*
   Unix SMB/CIFS implementation.

   endpoint server for the backupkey interface

   Copyright (C) Matthieu Patou <mat@samba.org> 2010

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
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_backupkey.h"
#include "dsdb/common/util.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "../lib/util/util_ldb.h"
#include "param/param.h"
#include "auth/session.h"
#include "system/network.h"
#include <com_err.h>
#include <hx509.h>
#include <hcrypto/rsa.h>
#include <hcrypto/bn.h>
#include <hcrypto/sha.h>
#include <hcrypto/evp.h>
#include <hcrypto/hmac.h>
#include <der.h>
#include "../lib/tsocket/tsocket.h"
#include "../libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/crypto/arcfour.h"
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#if HAVE_GCRYPT_H
#include <gcrypt.h>
#endif


static const unsigned rsa_with_var_num[] = { 1, 2, 840, 113549, 1, 1, 1 };
/* Equivalent to asn1_oid_id_pkcs1_rsaEncryption*/
static const AlgorithmIdentifier _hx509_signature_rsa_with_var_num = {
	{ 7, discard_const_p(unsigned, rsa_with_var_num) }, NULL
};

static NTSTATUS set_lsa_secret(TALLOC_CTX *mem_ctx,
			       struct ldb_context *ldb,
			       const char *name,
			       const DATA_BLOB *lsa_secret)
{
	struct ldb_message *msg;
	struct ldb_result *res;
	struct ldb_dn *domain_dn;
	struct ldb_dn *system_dn;
	struct ldb_val val;
	int ret;
	char *name2;
	struct timeval now = timeval_current();
	NTTIME nt_now = timeval_to_nttime(&now);
	const char *attrs[] = {
		NULL
	};

	domain_dn = ldb_get_default_basedn(ldb);
	if (!domain_dn) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * This function is a lot like dcesrv_lsa_CreateSecret
	 * in the rpc_server/lsa directory
	 * The reason why we duplicate the effort here is that:
	 * * we want to keep the former function static
	 * * we want to avoid the burden of doing LSA calls
	 *   when we can just manipulate the secrets directly
	 * * taillor the function to the particular needs of backup protocol
	 */

	system_dn = samdb_search_dn(ldb, msg, domain_dn, "(&(objectClass=container)(cn=System))");
	if (system_dn == NULL) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}

	name2 = talloc_asprintf(msg, "%s Secret", name);
	if (name2 == NULL) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_search(ldb, mem_ctx, &res, system_dn, LDB_SCOPE_SUBTREE, attrs,
			   "(&(cn=%s)(objectclass=secret))",
			   ldb_binary_encode_string(mem_ctx, name2));

	if (ret != LDB_SUCCESS ||  res->count != 0 ) {
		DEBUG(2, ("Secret %s already exists !\n", name2));
		talloc_free(msg);
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	/*
	 * We don't care about previous value as we are
	 * here only if the key didn't exists before
	 */

	msg->dn = ldb_dn_copy(mem_ctx, system_dn);
	if (msg->dn == NULL) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}
	if (!ldb_dn_add_child_fmt(msg->dn, "cn=%s", name2)) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_msg_add_string(msg, "cn", name2);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}
	ret = ldb_msg_add_string(msg, "objectClass", "secret");
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}
	ret = samdb_msg_add_uint64(ldb, mem_ctx, msg, "priorSetTime", nt_now);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}
	val.data = lsa_secret->data;
	val.length = lsa_secret->length;
	ret = ldb_msg_add_value(msg, "currentValue", &val, NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}
	ret = samdb_msg_add_uint64(ldb, mem_ctx, msg, "lastSetTime", nt_now);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * create the secret with DSDB_MODIFY_RELAX
	 * otherwise dsdb/samdb/ldb_modules/objectclass.c forbid
	 * the create of LSA secret object
	 */
	ret = dsdb_add(ldb, msg, DSDB_MODIFY_RELAX);
	if (ret != LDB_SUCCESS) {
		DEBUG(2,("Failed to create secret record %s: %s\n",
			ldb_dn_get_linearized(msg->dn),
			ldb_errstring(ldb)));
		talloc_free(msg);
		return NT_STATUS_ACCESS_DENIED;
	}

	talloc_free(msg);
	return NT_STATUS_OK;
}

/* This function is pretty much like dcesrv_lsa_QuerySecret */
static NTSTATUS get_lsa_secret(TALLOC_CTX *mem_ctx,
			       struct ldb_context *ldb,
			       const char *name,
			       DATA_BLOB *lsa_secret)
{
	TALLOC_CTX *tmp_mem;
	struct ldb_result *res;
	struct ldb_dn *domain_dn;
	struct ldb_dn *system_dn;
	const struct ldb_val *val;
	uint8_t *data;
	const char *attrs[] = {
		"currentValue",
		NULL
	};
	int ret;

	lsa_secret->data = NULL;
	lsa_secret->length = 0;

	domain_dn = ldb_get_default_basedn(ldb);
	if (!domain_dn) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	tmp_mem = talloc_new(mem_ctx);
	if (tmp_mem == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	system_dn = samdb_search_dn(ldb, tmp_mem, domain_dn, "(&(objectClass=container)(cn=System))");
	if (system_dn == NULL) {
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_search(ldb, mem_ctx, &res, system_dn, LDB_SCOPE_SUBTREE, attrs,
			   "(&(cn=%s Secret)(objectclass=secret))",
			   ldb_binary_encode_string(tmp_mem, name));

	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_mem);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else if (res->count == 0) {
		return NT_STATUS_RESOURCE_NAME_NOT_FOUND;
	} else if (res->count > 1) {
		DEBUG(2, ("Secret %s collision\n", name));
		talloc_free(tmp_mem);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	val = ldb_msg_find_ldb_val(res->msgs[0], "currentValue");
	if (val == NULL) {
		/*
		 * The secret object is here but we don't have the secret value
		 * The most common case is a RODC
		 */
		*lsa_secret = data_blob_null;
		talloc_free(tmp_mem);
		return NT_STATUS_OK;
	}

	data = val->data;
	lsa_secret->data = talloc_move(mem_ctx, &data);
	lsa_secret->length = val->length;

	talloc_free(tmp_mem);
	return NT_STATUS_OK;
}

static DATA_BLOB *reverse_and_get_blob(TALLOC_CTX *mem_ctx, BIGNUM *bn)
{
	DATA_BLOB blob;
	DATA_BLOB *rev = talloc(mem_ctx, DATA_BLOB);
	uint32_t i;

	blob.length = BN_num_bytes(bn);
	blob.data = talloc_array(mem_ctx, uint8_t, blob.length);

	if (blob.data == NULL) {
		return NULL;
	}

	BN_bn2bin(bn, blob.data);

	rev->data = talloc_array(mem_ctx, uint8_t, blob.length);
	if (rev->data == NULL) {
		return NULL;
	}

	for(i=0; i < blob.length; i++) {
		rev->data[i] = blob.data[blob.length - i -1];
	}
	rev->length = blob.length;
	talloc_free(blob.data);
	return rev;
}

static BIGNUM *reverse_and_get_bignum(TALLOC_CTX *mem_ctx, DATA_BLOB *blob)
{
	BIGNUM *ret;
	DATA_BLOB rev;
	uint32_t i;

	rev.data = talloc_array(mem_ctx, uint8_t, blob->length);
	if (rev.data == NULL) {
		return NULL;
	}

	for(i=0; i < blob->length; i++) {
		rev.data[i] = blob->data[blob->length - i -1];
	}
	rev.length = blob->length;

	ret = BN_bin2bn(rev.data, rev.length, NULL);
	talloc_free(rev.data);

	return ret;
}

static NTSTATUS get_pk_from_raw_keypair_params(TALLOC_CTX *ctx,
				struct bkrp_exported_RSA_key_pair *keypair,
				hx509_private_key *pk)
{
	hx509_context hctx;
	RSA *rsa;
	struct hx509_private_key_ops *ops;

	hx509_context_init(&hctx);
	ops = hx509_find_private_alg(&_hx509_signature_rsa_with_var_num.algorithm);
	if (ops == NULL) {
		DEBUG(2, ("Not supported algorithm\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (hx509_private_key_init(pk, ops, NULL) != 0) {
		hx509_context_free(&hctx);
		return NT_STATUS_NO_MEMORY;
	}

	rsa = RSA_new();
	if (rsa ==NULL) {
		hx509_context_free(&hctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	rsa->n = reverse_and_get_bignum(ctx, &(keypair->modulus));
	if (rsa->n == NULL) {
		RSA_free(rsa);
		hx509_context_free(&hctx);
		return NT_STATUS_INVALID_PARAMETER;
	}
	rsa->d = reverse_and_get_bignum(ctx, &(keypair->private_exponent));
	if (rsa->d == NULL) {
		RSA_free(rsa);
		hx509_context_free(&hctx);
		return NT_STATUS_INVALID_PARAMETER;
	}
	rsa->p = reverse_and_get_bignum(ctx, &(keypair->prime1));
	if (rsa->p == NULL) {
		RSA_free(rsa);
		hx509_context_free(&hctx);
		return NT_STATUS_INVALID_PARAMETER;
	}
	rsa->q = reverse_and_get_bignum(ctx, &(keypair->prime2));
	if (rsa->q == NULL) {
		RSA_free(rsa);
		hx509_context_free(&hctx);
		return NT_STATUS_INVALID_PARAMETER;
	}
	rsa->dmp1 = reverse_and_get_bignum(ctx, &(keypair->exponent1));
	if (rsa->dmp1 == NULL) {
		RSA_free(rsa);
		hx509_context_free(&hctx);
		return NT_STATUS_INVALID_PARAMETER;
	}
	rsa->dmq1 = reverse_and_get_bignum(ctx, &(keypair->exponent2));
	if (rsa->dmq1 == NULL) {
		RSA_free(rsa);
		hx509_context_free(&hctx);
		return NT_STATUS_INVALID_PARAMETER;
	}
	rsa->iqmp = reverse_and_get_bignum(ctx, &(keypair->coefficient));
	if (rsa->iqmp == NULL) {
		RSA_free(rsa);
		hx509_context_free(&hctx);
		return NT_STATUS_INVALID_PARAMETER;
	}
	rsa->e = reverse_and_get_bignum(ctx, &(keypair->public_exponent));
	if (rsa->e == NULL) {
		RSA_free(rsa);
		hx509_context_free(&hctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	hx509_private_key_assign_rsa(*pk, rsa);

	hx509_context_free(&hctx);
	return NT_STATUS_OK;
}

static WERROR get_and_verify_access_check(TALLOC_CTX *sub_ctx,
					  uint32_t version,
					  uint8_t *key_and_iv,
					  uint8_t *access_check,
					  uint32_t access_check_len,
					  struct auth_session_info *session_info)
{
	heim_octet_string iv;
	heim_octet_string access_check_os;
	hx509_crypto crypto;

	DATA_BLOB blob_us;
	uint32_t key_len;
	uint32_t iv_len;
	int res;
	enum ndr_err_code ndr_err;
	hx509_context hctx;

	struct dom_sid *access_sid = NULL;
	struct dom_sid *caller_sid = NULL;
	
	/* This one should not be freed */
	const AlgorithmIdentifier *alg;

	switch (version) {
	case 2:
		key_len = 24;
		iv_len = 8;
		alg = hx509_crypto_des_rsdi_ede3_cbc();
		break;

	case 3:
		key_len = 32;
		iv_len = 16;
		alg =hx509_crypto_aes256_cbc();
		break;

	default:
		return WERR_INVALID_DATA;
	}

	hx509_context_init(&hctx);
	res = hx509_crypto_init(hctx, NULL,
				&(alg->algorithm),
				&crypto);
	hx509_context_free(&hctx);

	if (res != 0) {
		return WERR_INVALID_DATA;
	}

	res = hx509_crypto_set_key_data(crypto, key_and_iv, key_len);

	iv.data = talloc_memdup(sub_ctx, key_len + key_and_iv, iv_len);
	iv.length = iv_len;

	if (res != 0) {
		hx509_crypto_destroy(crypto);
		return WERR_INVALID_DATA;
	}

	hx509_crypto_set_padding(crypto, HX509_CRYPTO_PADDING_NONE);
	res = hx509_crypto_decrypt(crypto,
		access_check,
		access_check_len,
		&iv,
		&access_check_os);

	if (res != 0) {
		hx509_crypto_destroy(crypto);
		return WERR_INVALID_DATA;
	}

	blob_us.data = access_check_os.data;
	blob_us.length = access_check_os.length;

	hx509_crypto_destroy(crypto);

	switch (version) {
	case 2:
	{
		uint32_t hash_size = 20;
		uint8_t hash[hash_size];
		struct sha sctx;
		struct bkrp_access_check_v2 uncrypted_accesscheckv2;

		ndr_err = ndr_pull_struct_blob(&blob_us, sub_ctx, &uncrypted_accesscheckv2,
					(ndr_pull_flags_fn_t)ndr_pull_bkrp_access_check_v2);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			/* Unable to unmarshall */
			der_free_octet_string(&access_check_os);
			return WERR_INVALID_DATA;
		}
		if (uncrypted_accesscheckv2.magic != 0x1) {
			/* wrong magic */
			der_free_octet_string(&access_check_os);
			return WERR_INVALID_DATA;
		}

		SHA1_Init(&sctx);
		SHA1_Update(&sctx, blob_us.data, blob_us.length - hash_size);
		SHA1_Final(hash, &sctx);
		der_free_octet_string(&access_check_os);
		/*
		 * We free it after the sha1 calculation because blob.data
		 * point to the same area
		 */

		if (memcmp(hash, uncrypted_accesscheckv2.hash, hash_size) != 0) {
			DEBUG(2, ("Wrong hash value in the access check in backup key remote protocol\n"));
			return WERR_INVALID_DATA;
		}
		access_sid = &(uncrypted_accesscheckv2.sid);
		break;
	}
	case 3:
	{
		uint32_t hash_size = 64;
		uint8_t hash[hash_size];
		struct hc_sha512state sctx;
		struct bkrp_access_check_v3 uncrypted_accesscheckv3;

		ndr_err = ndr_pull_struct_blob(&blob_us, sub_ctx, &uncrypted_accesscheckv3,
					(ndr_pull_flags_fn_t)ndr_pull_bkrp_access_check_v3);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			/* Unable to unmarshall */
			der_free_octet_string(&access_check_os);
			return WERR_INVALID_DATA;
		}
		if (uncrypted_accesscheckv3.magic != 0x1) {
			/* wrong magic */
			der_free_octet_string(&access_check_os);
			return WERR_INVALID_DATA;
		}

		SHA512_Init(&sctx);
		SHA512_Update(&sctx, blob_us.data, blob_us.length - hash_size);
		SHA512_Final(hash, &sctx);
		der_free_octet_string(&access_check_os);
		/*
		 * We free it after the sha1 calculation because blob.data
		 * point to the same area
		 */

		if (memcmp(hash, uncrypted_accesscheckv3.hash, hash_size) != 0) {
			DEBUG(2, ("Wrong hash value in the access check in backup key remote protocol\n"));
			return WERR_INVALID_DATA;
		}
		access_sid = &(uncrypted_accesscheckv3.sid);
		break;
	}
	default:
		/* Never reached normally as we filtered at the switch / case level */
		return WERR_INVALID_DATA;
	}
	
	caller_sid = &session_info->security_token->sids[PRIMARY_USER_SID_INDEX];
	
	if (!dom_sid_equal(caller_sid, access_sid)) {
		return WERR_INVALID_ACCESS;
	}
	return WERR_OK;
}

/* 
 * We have some data, such as saved website or IMAP passwords that the
 * client has in profile on-disk.  This needs to be decrypted.  This
 * version gives the server the data over the network (protected by
 * the X.509 certificate and public key encryption, and asks that it
 * be decrypted returned for short-term use, protected only by the
 * negotiated transport encryption.
 *
 * The data is NOT stored in the LSA, but a X.509 certificate, public
 * and private keys used to encrypt the data will be stored.  There is
 * only one active encryption key pair and certificate per domain, it
 * is pointed at with G$BCKUPKEY_PREFERRED in the LSA secrets store.
 *
 * The potentially multiple valid decrypting key pairs are in turn
 * stored in the LSA secrets store as G$BCKUPKEY_keyGuidString.
 *
 */
static WERROR bkrp_client_wrap_decrypt_data(struct dcesrv_call_state *dce_call,
					    TALLOC_CTX *mem_ctx,
					    struct bkrp_BackupKey *r,
					    struct ldb_context *ldb_ctx)
{
	struct bkrp_client_side_wrapped uncrypt_request;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	char *guid_string;
	char *cert_secret_name;
	DATA_BLOB lsa_secret;
	DATA_BLOB *uncrypted_data;
	NTSTATUS status;
	uint32_t requested_version;
	
	blob.data = r->in.data_in;
	blob.length = r->in.data_in_len;

	if (r->in.data_in_len < 4 || r->in.data_in == NULL) {
		return WERR_INVALID_PARAM;
	}

	/* 
	 * We check for the version here, so we can actually print the
	 * message as we are unlikely to parse it with NDR.
	 */
	requested_version = IVAL(r->in.data_in, 0);
	if ((requested_version != BACKUPKEY_CLIENT_WRAP_VERSION2)
	    && (requested_version != BACKUPKEY_CLIENT_WRAP_VERSION3)) {
		DEBUG(1, ("Request for unknown BackupKey sub-protocol %d\n", requested_version));
		return WERR_INVALID_PARAMETER;
	}
	
	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &uncrypt_request,
				       (ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_wrapped);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INVALID_PARAM;
	}

	if ((uncrypt_request.version != BACKUPKEY_CLIENT_WRAP_VERSION2)
	    && (uncrypt_request.version != BACKUPKEY_CLIENT_WRAP_VERSION3)) {
		DEBUG(1, ("Request for unknown BackupKey sub-protocol %d\n", uncrypt_request.version));
		return WERR_INVALID_PARAMETER;
	}

	guid_string = GUID_string(mem_ctx, &uncrypt_request.guid);
	if (guid_string == NULL) {
		return WERR_NOMEM;
	}

	cert_secret_name = talloc_asprintf(mem_ctx,
					   "BCKUPKEY_%s",
					   guid_string);
	if (cert_secret_name == NULL) {
		return WERR_NOMEM;
	}

	status = get_lsa_secret(mem_ctx,
				ldb_ctx,
				cert_secret_name,
				&lsa_secret);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Error while fetching secret %s\n", cert_secret_name));
		return WERR_INVALID_DATA;
	} else if (lsa_secret.length == 0) {
		/* we do not have the real secret attribute, like if we are an RODC */
		return WERR_INVALID_PARAMETER;
	} else {
		hx509_context hctx;
		struct bkrp_exported_RSA_key_pair keypair;
		hx509_private_key pk;
		uint32_t i, res;
		heim_octet_string reversed_secret;
		heim_octet_string uncrypted_secret;
		AlgorithmIdentifier alg;
		DATA_BLOB blob_us;
		WERROR werr;

		ndr_err = ndr_pull_struct_blob(&lsa_secret, mem_ctx, &keypair, (ndr_pull_flags_fn_t)ndr_pull_bkrp_exported_RSA_key_pair);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(2, ("Unable to parse the ndr encoded cert in key %s\n", cert_secret_name));
			return WERR_FILE_NOT_FOUND;
		}

		status = get_pk_from_raw_keypair_params(mem_ctx, &keypair, &pk);
		if (!NT_STATUS_IS_OK(status)) {
			return WERR_INTERNAL_ERROR;
		}

		reversed_secret.data = talloc_array(mem_ctx, uint8_t,
						    uncrypt_request.encrypted_secret_len);
		if (reversed_secret.data == NULL) {
			hx509_private_key_free(&pk);
			return WERR_NOMEM;
		}

		/* The secret has to be reversed ... */
		for(i=0; i< uncrypt_request.encrypted_secret_len; i++) {
			uint8_t *reversed = (uint8_t *)reversed_secret.data;
			uint8_t *uncrypt = uncrypt_request.encrypted_secret;
			reversed[i] = uncrypt[uncrypt_request.encrypted_secret_len - 1 - i];
		}
		reversed_secret.length = uncrypt_request.encrypted_secret_len;

		/*
		 * Let's try to decrypt the secret now that
		 * we have the private key ...
		 */
		hx509_context_init(&hctx);
		res = hx509_private_key_private_decrypt(hctx, &reversed_secret,
							 &alg.algorithm, pk,
							 &uncrypted_secret);
		hx509_context_free(&hctx);
		hx509_private_key_free(&pk);
		if (res != 0) {
			/* We are not able to decrypt the secret, looks like something is wrong */
			return WERR_INVALID_PARAMETER;
		}
		blob_us.data = uncrypted_secret.data;
		blob_us.length = uncrypted_secret.length;

		if (uncrypt_request.version == 2) {
			struct bkrp_encrypted_secret_v2 uncrypted_secretv2;

			ndr_err = ndr_pull_struct_blob(&blob_us, mem_ctx, &uncrypted_secretv2,
					(ndr_pull_flags_fn_t)ndr_pull_bkrp_encrypted_secret_v2);
			der_free_octet_string(&uncrypted_secret);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				/* Unable to unmarshall */
				return WERR_INVALID_DATA;
			}
			if (uncrypted_secretv2.magic != 0x20) {
				/* wrong magic */
				return WERR_INVALID_DATA;
			}

			werr = get_and_verify_access_check(mem_ctx, 2,
							   uncrypted_secretv2.payload_key,
							   uncrypt_request.access_check,
							   uncrypt_request.access_check_len,
							   dce_call->conn->auth_state.session_info);
			if (!W_ERROR_IS_OK(werr)) {
				return werr;
			}
			uncrypted_data = talloc(mem_ctx, DATA_BLOB);
			if (uncrypted_data == NULL) {
				return WERR_INVALID_DATA;
			}

			uncrypted_data->data = uncrypted_secretv2.secret;
			uncrypted_data->length = uncrypted_secretv2.secret_len;
		}
		if (uncrypt_request.version == 3) {
			struct bkrp_encrypted_secret_v3 uncrypted_secretv3;

			ndr_err = ndr_pull_struct_blob(&blob_us, mem_ctx, &uncrypted_secretv3,
					(ndr_pull_flags_fn_t)ndr_pull_bkrp_encrypted_secret_v3);

			der_free_octet_string(&uncrypted_secret);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				/* Unable to unmarshall */
				return WERR_INVALID_DATA;
			}

			if (uncrypted_secretv3.magic1 != 0x30  ||
			    uncrypted_secretv3.magic2 != 0x6610 ||
			    uncrypted_secretv3.magic3 != 0x800e) {
				/* wrong magic */
				return WERR_INVALID_DATA;
			}

			/* 
			 * Confirm that the caller is permitted to
			 * read this particular data.  Because one key
			 * pair is used per domain, the caller could
			 * have stolen the profile data on-disk and
			 * would otherwise be able to read the
			 * passwords.
			 */
			
			werr = get_and_verify_access_check(mem_ctx, 3,
							   uncrypted_secretv3.payload_key,
							   uncrypt_request.access_check,
							   uncrypt_request.access_check_len,
							   dce_call->conn->auth_state.session_info);
			if (!W_ERROR_IS_OK(werr)) {
				return werr;
			}

			uncrypted_data = talloc(mem_ctx, DATA_BLOB);
			if (uncrypted_data == NULL) {
				return WERR_INVALID_DATA;
			}

			uncrypted_data->data = uncrypted_secretv3.secret;
			uncrypted_data->length = uncrypted_secretv3.secret_len;
		}

		/*
		 * Yeah if we are here all looks pretty good:
		 * - hash is ok
		 * - user sid is the same as the one in access check
		 * - we were able to decrypt the whole stuff
		 */
	}

	if (uncrypted_data->data == NULL) {
		return WERR_INVALID_DATA;
	}

	/* There is a magic value a the beginning of the data
	 * we can use an adhoc structure but as the
	 * parent structure is just an array of bytes it a lot of work
	 * work just prepending 4 bytes
	 */
	*(r->out.data_out) = talloc_zero_array(mem_ctx, uint8_t, uncrypted_data->length + 4);
	W_ERROR_HAVE_NO_MEMORY(*(r->out.data_out));
	memcpy(4+*(r->out.data_out), uncrypted_data->data, uncrypted_data->length);
	*(r->out.data_out_len) = uncrypted_data->length + 4;

	return WERR_OK;
}

/*
 * Strictly, this function no longer uses Heimdal in order to generate an RSA
 * key, but GnuTLS.
 *
 * The resulting key is then imported into Heimdal's RSA structure.
 *
 * We use GnuTLS because it can reliably generate 2048 bit keys every time.
 * Windows clients strictly require 2048, no more since it won't fit and no
 * less either. Heimdal would almost always generate a smaller key.
 */
static WERROR create_heimdal_rsa_key(TALLOC_CTX *ctx, hx509_context *hctx,
				     hx509_private_key *pk, RSA **rsa)
{
	int ret;
	uint8_t *p0 = NULL;
	const uint8_t *p;
	size_t len;
	int bits = 2048;
	int RSA_returned_bits;
	gnutls_x509_privkey gtls_key;
	WERROR werr;

	*rsa = NULL;

	gnutls_global_init();
#ifdef HAVE_GCRYPT_H
	DEBUG(3,("Enabling QUICK mode in gcrypt\n"));
	gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
#endif
	ret = gnutls_x509_privkey_init(&gtls_key);
	if (ret != 0) {
		gnutls_global_deinit();
		return WERR_INTERNAL_ERROR;
	}

	/* 
	 * Unlike Heimdal's RSA_generate_key_ex(), this generates a
	 * 2048 bit key 100% of the time.  The heimdal code had a ~1/8
	 * chance of doing so, chewing vast quantities of computation
	 * and entropy in the process.
	 */
	
	ret = gnutls_x509_privkey_generate(gtls_key, GNUTLS_PK_RSA, bits, 0);
	if (ret != 0) {
		werr = WERR_INTERNAL_ERROR;
		goto done;
	}

	/* No need to check error code, this SHOULD fail */
	gnutls_x509_privkey_export(gtls_key, GNUTLS_X509_FMT_DER, NULL, &len);

	if (len < 1) {
		werr = WERR_INTERNAL_ERROR;
		goto done;
	}

	p0 = talloc_size(ctx, len);
	if (p0 == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}
	p = p0;

	/* 
	 * Only this GnuTLS export function correctly exports the key,
	 * we can't use gnutls_rsa_params_export_raw() because while
	 * it appears to be fixed in more recent versions, in the
	 * Ubuntu 14.04 version 2.12.23 (at least) it incorrectly
	 * exports one of the key parameters (qInv).  Additionally, we
	 * would have to work around subtle differences in big number
	 * representations.
	 * 
	 * We need access to the RSA parameters directly (in the
	 * parameter RSA **rsa) as the caller has to manually encode
	 * them in a non-standard data structure.
	 */
	ret = gnutls_x509_privkey_export(gtls_key, GNUTLS_X509_FMT_DER, p0, &len);

	if (ret != 0) {
		werr = WERR_INTERNAL_ERROR;
		goto done;
	}

	/*
	 * To dump the key we can use :
	 * rk_dumpdata("h5lkey", p0, len);
	 */
	ret = hx509_parse_private_key(*hctx, &_hx509_signature_rsa_with_var_num ,
				       p0, len, HX509_KEY_FORMAT_DER, pk);

	if (ret != 0) {
		werr = WERR_INTERNAL_ERROR;
		goto done;
	}

	*rsa = d2i_RSAPrivateKey(NULL, &p, len);
	TALLOC_FREE(p0);

	if (*rsa == NULL) {
		hx509_private_key_free(pk);
		werr = WERR_INTERNAL_ERROR;
		goto done;
	}

	RSA_returned_bits = BN_num_bits((*rsa)->n);
	DEBUG(6, ("GnuTLS returned an RSA private key with %d bits\n", RSA_returned_bits));

	if (RSA_returned_bits != bits) {
		DEBUG(0, ("GnuTLS unexpectedly returned an RSA private key with %d bits, needed %d\n", RSA_returned_bits, bits));
		hx509_private_key_free(pk);
		werr = WERR_INTERNAL_ERROR;
		goto done;
	}

	werr = WERR_OK;

done:
	if (p0 != NULL) {
		memset(p0, 0, len);
		TALLOC_FREE(p0);
	}

	gnutls_x509_privkey_deinit(gtls_key);
	gnutls_global_deinit();
	return werr;
}

static WERROR self_sign_cert(TALLOC_CTX *ctx, hx509_context *hctx, hx509_request *req,
				time_t lifetime, hx509_private_key *private_key,
				hx509_cert *cert, DATA_BLOB *guidblob)
{
	SubjectPublicKeyInfo spki;
	hx509_name subject = NULL;
	hx509_ca_tbs tbs;
	struct heim_bit_string uniqueid;
	struct heim_integer serialnumber;
	int ret, i;

	uniqueid.data = talloc_memdup(ctx, guidblob->data, guidblob->length);
	if (uniqueid.data == NULL) {
		return WERR_NOMEM;
	}
	/* uniqueid is a bit string in which each byte represent 1 bit (1 or 0)
	 * so as 1 byte is 8 bits we need to provision 8 times more space as in the
	 * blob
	 */
	uniqueid.length = 8 * guidblob->length;

	serialnumber.data = talloc_array(ctx, uint8_t,
					    guidblob->length);
	if (serialnumber.data == NULL) {
		talloc_free(uniqueid.data);
		return WERR_NOMEM;
	}

	/* Native AD generates certificates with serialnumber in reversed notation */
	for (i = 0; i < guidblob->length; i++) {
		uint8_t *reversed = (uint8_t *)serialnumber.data;
		uint8_t *uncrypt = guidblob->data;
		reversed[i] = uncrypt[guidblob->length - 1 - i];
	}
	serialnumber.length = guidblob->length;
	serialnumber.negative = 0;

	memset(&spki, 0, sizeof(spki));

	ret = hx509_request_get_name(*hctx, *req, &subject);
	if (ret !=0) {
		goto fail_subject;
	}
	ret = hx509_request_get_SubjectPublicKeyInfo(*hctx, *req, &spki);
	if (ret !=0) {
		goto fail_spki;
	}

	ret = hx509_ca_tbs_init(*hctx, &tbs);
	if (ret !=0) {
		goto fail_tbs;
	}

	ret = hx509_ca_tbs_set_spki(*hctx, tbs, &spki);
	if (ret !=0) {
		goto fail;
	}
	ret = hx509_ca_tbs_set_subject(*hctx, tbs, subject);
	if (ret !=0) {
		goto fail;
	}
	ret = hx509_ca_tbs_set_ca(*hctx, tbs, 1);
	if (ret !=0) {
		goto fail;
	}
	ret = hx509_ca_tbs_set_notAfter_lifetime(*hctx, tbs, lifetime);
	if (ret !=0) {
		goto fail;
	}
	ret = hx509_ca_tbs_set_unique(*hctx, tbs, &uniqueid, &uniqueid);
	if (ret !=0) {
		goto fail;
	}
	ret = hx509_ca_tbs_set_serialnumber(*hctx, tbs, &serialnumber);
	if (ret !=0) {
		goto fail;
	}
	ret = hx509_ca_sign_self(*hctx, tbs, *private_key, cert);
	if (ret !=0) {
		goto fail;
	}
	hx509_name_free(&subject);
	free_SubjectPublicKeyInfo(&spki);
	hx509_ca_tbs_free(&tbs);

	return WERR_OK;

fail:
	hx509_ca_tbs_free(&tbs);
fail_tbs:
	free_SubjectPublicKeyInfo(&spki);
fail_spki:
	hx509_name_free(&subject);
fail_subject:
	talloc_free(uniqueid.data);
	talloc_free(serialnumber.data);
	return WERR_INTERNAL_ERROR;
}

static WERROR create_req(TALLOC_CTX *ctx, hx509_context *hctx, hx509_request *req,
			 hx509_private_key *signer,RSA **rsa, const char *dn)
{
	int ret;
	SubjectPublicKeyInfo key;

	hx509_name name;
	WERROR werr;

	werr = create_heimdal_rsa_key(ctx, hctx, signer, rsa);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	hx509_request_init(*hctx, req);
	ret = hx509_parse_name(*hctx, dn, &name);
	if (ret != 0) {
		RSA_free(*rsa);
		hx509_private_key_free(signer);
		hx509_request_free(req);
		hx509_name_free(&name);
		return WERR_INTERNAL_ERROR;
	}

	ret = hx509_request_set_name(*hctx, *req, name);
	if (ret != 0) {
		RSA_free(*rsa);
		hx509_private_key_free(signer);
		hx509_request_free(req);
		hx509_name_free(&name);
		return WERR_INTERNAL_ERROR;
	}
	hx509_name_free(&name);

	ret = hx509_private_key2SPKI(*hctx, *signer, &key);
	if (ret != 0) {
		RSA_free(*rsa);
		hx509_private_key_free(signer);
		hx509_request_free(req);
		return WERR_INTERNAL_ERROR;
	}
	ret = hx509_request_set_SubjectPublicKeyInfo(*hctx, *req, &key);
	if (ret != 0) {
		RSA_free(*rsa);
		hx509_private_key_free(signer);
		free_SubjectPublicKeyInfo(&key);
		hx509_request_free(req);
		return WERR_INTERNAL_ERROR;
	}

	free_SubjectPublicKeyInfo(&key);

	return WERR_OK;
}

/* Return an error when we fail to generate a certificate */
static WERROR generate_bkrp_cert(TALLOC_CTX *ctx, struct dcesrv_call_state *dce_call, struct ldb_context *ldb_ctx, const char *dn)
{
	heim_octet_string data;
	WERROR werr;
	RSA *rsa;
	hx509_context hctx;
	hx509_private_key pk;
	hx509_request req;
	hx509_cert cert;
	DATA_BLOB blob;
	DATA_BLOB blobkeypair;
	DATA_BLOB *tmp;
	int ret;
	bool ok = true;
	struct GUID guid = GUID_random();
	NTSTATUS status;
	char *secret_name;
	struct bkrp_exported_RSA_key_pair keypair;
	enum ndr_err_code ndr_err;
	uint32_t nb_seconds_validity = 3600 * 24 * 365;

	DEBUG(6, ("Trying to generate a certificate\n"));
	hx509_context_init(&hctx);
	werr = create_req(ctx, &hctx, &req, &pk, &rsa, dn);
	if (!W_ERROR_IS_OK(werr)) {
		hx509_context_free(&hctx);
		return werr;
	}

	status = GUID_to_ndr_blob(&guid, ctx, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		hx509_context_free(&hctx);
		hx509_private_key_free(&pk);
		RSA_free(rsa);
		return WERR_INVALID_DATA;
	}

	werr = self_sign_cert(ctx, &hctx, &req, nb_seconds_validity, &pk, &cert, &blob);
	if (!W_ERROR_IS_OK(werr)) {
		hx509_private_key_free(&pk);
		hx509_context_free(&hctx);
		return WERR_INVALID_DATA;
	}

	ret = hx509_cert_binary(hctx, cert, &data);
	if (ret !=0) {
		hx509_cert_free(cert);
		hx509_private_key_free(&pk);
		hx509_context_free(&hctx);
		return WERR_INVALID_DATA;
	}

	keypair.cert.data = talloc_memdup(ctx, data.data, data.length);
	keypair.cert.length = data.length;

	/*
	 * Heimdal's bignum are big endian and the
	 * structure expect it to be in little endian
	 * so we reverse the buffer to make it work
	 */
	tmp = reverse_and_get_blob(ctx, rsa->e);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.public_exponent = *tmp;
		SMB_ASSERT(tmp->length <= 4);
		/*
		 * The value is now in little endian but if can happen that the length is
		 * less than 4 bytes.
		 * So if we have less than 4 bytes we pad with zeros so that it correctly
		 * fit into the structure.
		 */
		if (tmp->length < 4) {
			/*
			 * We need the expo to fit 4 bytes
			 */
			keypair.public_exponent.data = talloc_zero_array(ctx, uint8_t, 4);
			memcpy(keypair.public_exponent.data, tmp->data, tmp->length);
			keypair.public_exponent.length = 4;
		}
	}

	tmp = reverse_and_get_blob(ctx,rsa->d);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.private_exponent = *tmp;
	}

	tmp = reverse_and_get_blob(ctx,rsa->n);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.modulus = *tmp;
	}

	tmp = reverse_and_get_blob(ctx,rsa->p);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.prime1 = *tmp;
	}

	tmp = reverse_and_get_blob(ctx,rsa->q);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.prime2 = *tmp;
	}

	tmp = reverse_and_get_blob(ctx,rsa->dmp1);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.exponent1 = *tmp;
	}

	tmp = reverse_and_get_blob(ctx,rsa->dmq1);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.exponent2 = *tmp;
	}

	tmp = reverse_and_get_blob(ctx,rsa->iqmp);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.coefficient = *tmp;
	}

	/* One of the keypair allocation was wrong */
	if (ok == false) {
		der_free_octet_string(&data);
		hx509_cert_free(cert);
		hx509_private_key_free(&pk);
		hx509_context_free(&hctx);
		RSA_free(rsa);
		return WERR_INVALID_DATA;
	}
	keypair.certificate_len = keypair.cert.length;
	ndr_err = ndr_push_struct_blob(&blobkeypair, ctx, &keypair, (ndr_push_flags_fn_t)ndr_push_bkrp_exported_RSA_key_pair);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		der_free_octet_string(&data);
		hx509_cert_free(cert);
		hx509_private_key_free(&pk);
		hx509_context_free(&hctx);
		RSA_free(rsa);
		return WERR_INVALID_DATA;
	}

	secret_name = talloc_asprintf(ctx, "BCKUPKEY_%s", GUID_string(ctx, &guid));
	if (secret_name == NULL) {
		der_free_octet_string(&data);
		hx509_cert_free(cert);
		hx509_private_key_free(&pk);
		hx509_context_free(&hctx);
		RSA_free(rsa);
		return WERR_OUTOFMEMORY;
	}

	status = set_lsa_secret(ctx, ldb_ctx, secret_name, &blobkeypair);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to save the secret %s\n", secret_name));
	}
	talloc_free(secret_name);

	GUID_to_ndr_blob(&guid, ctx, &blob);
	status = set_lsa_secret(ctx, ldb_ctx, "BCKUPKEY_PREFERRED", &blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to save the secret BCKUPKEY_PREFERRED\n"));
	}

	der_free_octet_string(&data);
	hx509_cert_free(cert);
	hx509_private_key_free(&pk);
	hx509_context_free(&hctx);
	RSA_free(rsa);
	return WERR_OK;
}

static WERROR bkrp_retrieve_client_wrap_key(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					    struct bkrp_BackupKey *r, struct ldb_context *ldb_ctx)
{
	struct GUID guid;
	char *guid_string;
	DATA_BLOB lsa_secret;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	/*
	 * here we basicaly need to return our certificate
	 * search for lsa secret BCKUPKEY_PREFERRED first
	 */

	status = get_lsa_secret(mem_ctx,
				ldb_ctx,
				"BCKUPKEY_PREFERRED",
				&lsa_secret);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RESOURCE_NAME_NOT_FOUND)) {
		/* Ok we can be in this case if there was no certs */
		struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
		char *dn = talloc_asprintf(mem_ctx, "CN=%s",
					   lpcfg_realm(lp_ctx));
		
		WERROR werr =  generate_bkrp_cert(mem_ctx, dce_call, ldb_ctx, dn);
		if (!W_ERROR_IS_OK(werr)) {
			return WERR_INVALID_PARAMETER;
		}
		status = get_lsa_secret(mem_ctx,
					ldb_ctx,
					"BCKUPKEY_PREFERRED",
					&lsa_secret);
		
		if (!NT_STATUS_IS_OK(status)) {
			/* Ok we really don't manage to get this certs ...*/
			DEBUG(2, ("Unable to locate BCKUPKEY_PREFERRED after cert generation\n"));
			return WERR_FILE_NOT_FOUND;
		}
	} else if (!NT_STATUS_IS_OK(status)) {
		return WERR_INTERNAL_ERROR;
	}

	if (lsa_secret.length == 0) {
		DEBUG(1, ("No secret in BCKUPKEY_PREFERRED, are we an undetected RODC?\n"));
		return WERR_INTERNAL_ERROR;
	} else {
		char *cert_secret_name;

		status = GUID_from_ndr_blob(&lsa_secret, &guid);
		if (!NT_STATUS_IS_OK(status)) {
			return WERR_FILE_NOT_FOUND;
		}

		guid_string = GUID_string(mem_ctx, &guid);
		if (guid_string == NULL) {
			/* We return file not found because the client
			 * expect this error
			 */
			return WERR_FILE_NOT_FOUND;
		}

		cert_secret_name = talloc_asprintf(mem_ctx,
							"BCKUPKEY_%s",
							guid_string);
		status = get_lsa_secret(mem_ctx,
					ldb_ctx,
					cert_secret_name,
					&lsa_secret);
		if (!NT_STATUS_IS_OK(status)) {
			return WERR_FILE_NOT_FOUND;
		}

		if (lsa_secret.length != 0) {
			struct bkrp_exported_RSA_key_pair keypair;
			ndr_err = ndr_pull_struct_blob(&lsa_secret, mem_ctx, &keypair,
					(ndr_pull_flags_fn_t)ndr_pull_bkrp_exported_RSA_key_pair);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return WERR_FILE_NOT_FOUND;
			}
			*(r->out.data_out_len) = keypair.cert.length;
			*(r->out.data_out) = talloc_memdup(mem_ctx, keypair.cert.data, keypair.cert.length);
			W_ERROR_HAVE_NO_MEMORY(*(r->out.data_out));
			return WERR_OK;
		} else {
			DEBUG(1, ("No or broken secret called %s\n", cert_secret_name));
			return WERR_INTERNAL_ERROR;
		}
	}

	return WERR_NOT_SUPPORTED;
}

static WERROR generate_bkrp_server_wrap_key(TALLOC_CTX *ctx, struct ldb_context *ldb_ctx)
{
	struct GUID guid = GUID_random();
	enum ndr_err_code ndr_err;
	DATA_BLOB blob_wrap_key, guid_blob;
	struct bkrp_dc_serverwrap_key wrap_key;
	NTSTATUS status;
	char *secret_name;
	TALLOC_CTX *frame = talloc_stackframe();
	
	generate_random_buffer(wrap_key.key, sizeof(wrap_key.key));

	ndr_err = ndr_push_struct_blob(&blob_wrap_key, ctx, &wrap_key, (ndr_push_flags_fn_t)ndr_push_bkrp_dc_serverwrap_key);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return WERR_INVALID_DATA;
	}

	secret_name = talloc_asprintf(frame, "BCKUPKEY_%s", GUID_string(ctx, &guid));
	if (secret_name == NULL) {
		TALLOC_FREE(frame);
		return WERR_NOMEM;
	}

	status = set_lsa_secret(frame, ldb_ctx, secret_name, &blob_wrap_key);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to save the secret %s\n", secret_name));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}
	
	status = GUID_to_ndr_blob(&guid, frame, &guid_blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to save the secret %s\n", secret_name));
		TALLOC_FREE(frame);
	}
	
	status = set_lsa_secret(frame, ldb_ctx, "BCKUPKEY_P", &guid_blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to save the secret %s\n", secret_name));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}
	
	TALLOC_FREE(frame);

	return WERR_OK;
}

/*
 * Find the specified decryption keys from the LSA secrets store as
 * G$BCKUPKEY_keyGuidString.
 */

static WERROR bkrp_do_retrieve_server_wrap_key(TALLOC_CTX *mem_ctx, struct ldb_context *ldb_ctx,
					       struct bkrp_dc_serverwrap_key *server_key,
					       struct GUID *guid)
{
	NTSTATUS status;
	DATA_BLOB guid_binary, lsa_secret;
	char *secret_name;
	char *guid_string;
	enum ndr_err_code ndr_err;

	guid_string = GUID_string(mem_ctx, guid);
	if (guid_string == NULL) {
		/* We return file not found because the client
		 * expect this error
		 */
		return WERR_FILE_NOT_FOUND;
	}

	secret_name = talloc_asprintf(mem_ctx, "BCKUPKEY_%s", guid_string);
	if (secret_name == NULL) {
		return WERR_NOMEM;
	}
	
	status = get_lsa_secret(mem_ctx, ldb_ctx, secret_name, &lsa_secret);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Error while fetching secret %s\n", secret_name));
		return WERR_INVALID_DATA;
	} else if (guid_binary.length == 0) {
		/* RODC case, we do not have secrets locally */
		DEBUG(1, ("Unable to fetch value for secret %s, are we an undetected RODC?\n",
			  secret_name));
		return WERR_INTERNAL_ERROR;
	}
	ndr_err = ndr_pull_struct_blob(&lsa_secret, mem_ctx, server_key,
				       (ndr_pull_flags_fn_t)ndr_pull_bkrp_dc_serverwrap_key);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(2, ("Unable to parse the ndr encoded server wrap key %s\n", secret_name));
		return WERR_INVALID_DATA;
	}

	return WERR_OK;
}

/*
 * Find the current, preferred ServerWrap Key by looking at
 * G$BCKUPKEY_P in the LSA secrets store.
 *
 * Then find the current decryption keys from the LSA secrets store as
 * G$BCKUPKEY_keyGuidString.
 */

static WERROR bkrp_do_retrieve_default_server_wrap_key(TALLOC_CTX *mem_ctx,
						       struct ldb_context *ldb_ctx,
						       struct bkrp_dc_serverwrap_key *server_key,
						       struct GUID *returned_guid)
{
	NTSTATUS status;
	DATA_BLOB guid_binary;

	status = get_lsa_secret(mem_ctx, ldb_ctx, "BCKUPKEY_P", &guid_binary);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Error while fetching secret BCKUPKEY_P to find current GUID\n"));
		return WERR_FILE_NOT_FOUND;
	} else if (guid_binary.length == 0) {
		/* RODC case, we do not have secrets locally */
		DEBUG(1, ("Unable to fetch value for secret BCKUPKEY_P, are we an undetected RODC?\n"));
		return WERR_INTERNAL_ERROR;
	}

	status = GUID_from_ndr_blob(&guid_binary, returned_guid);
	if (!NT_STATUS_IS_OK(status)) {
		return WERR_FILE_NOT_FOUND;
	}

	return bkrp_do_retrieve_server_wrap_key(mem_ctx, ldb_ctx,
						server_key, returned_guid);
}

static WERROR bkrp_server_wrap_decrypt_data(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					    struct bkrp_BackupKey *r ,struct ldb_context *ldb_ctx)
{
	WERROR werr;
	struct bkrp_server_side_wrapped decrypt_request;
	DATA_BLOB sid_blob, encrypted_blob, symkey_blob;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct bkrp_dc_serverwrap_key server_key;
	struct bkrp_rc4encryptedpayload rc4payload;
	struct dom_sid *caller_sid;
	uint8_t symkey[20]; /* SHA-1 hash len */
	uint8_t mackey[20]; /* SHA-1 hash len */
	uint8_t mac[20]; /* SHA-1 hash len */
	unsigned int hash_len;
	HMAC_CTX ctx;

	blob.data = r->in.data_in;
	blob.length = r->in.data_in_len;

	if (r->in.data_in_len == 0 || r->in.data_in == NULL) {
		return WERR_INVALID_PARAM;
	}

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &decrypt_request,
				       (ndr_pull_flags_fn_t)ndr_pull_bkrp_server_side_wrapped);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INVALID_PARAM;
	}

	if (decrypt_request.magic != BACKUPKEY_SERVER_WRAP_VERSION) {
		return WERR_INVALID_PARAM;
	}
	
	werr = bkrp_do_retrieve_server_wrap_key(mem_ctx, ldb_ctx, &server_key,
						&decrypt_request.guid);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	dump_data_pw("server_key: \n", server_key.key, sizeof(server_key.key));
	
	dump_data_pw("r2: \n", decrypt_request.r2, sizeof(decrypt_request.r2));
	
	/*
	 * This is *not* the leading 64 bytes, as indicated in MS-BKRP 3.1.4.1.1
	 * BACKUPKEY_BACKUP_GUID, it really is the whole key 
	 */
	HMAC(EVP_sha1(), server_key.key, sizeof(server_key.key),
	     decrypt_request.r2, sizeof(decrypt_request.r2),
	     symkey, &hash_len);

	dump_data_pw("symkey: \n", symkey, hash_len);

	/* rc4 decrypt sid and secret using sym key */
	symkey_blob = data_blob_const(symkey, sizeof(symkey));
	
	encrypted_blob = data_blob_const(decrypt_request.rc4encryptedpayload,
					 decrypt_request.ciphertext_length);
	
	arcfour_crypt_blob(encrypted_blob.data, encrypted_blob.length, &symkey_blob);

	ndr_err = ndr_pull_struct_blob(&encrypted_blob, mem_ctx, &rc4payload,
				       (ndr_pull_flags_fn_t)ndr_pull_bkrp_rc4encryptedpayload);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INVALID_PARAM;
	}

	if (decrypt_request.payload_length != rc4payload.secret_data.length) {
		return WERR_INVALID_PARAM;
	}
	
	dump_data_pw("r3: \n", rc4payload.r3, sizeof(rc4payload.r3));

	/*
	 * This is *not* the leading 64 bytes, as indicated in MS-BKRP 3.1.4.1.1
	 * BACKUPKEY_BACKUP_GUID, it really is the whole key 
	 */
	HMAC(EVP_sha1(), server_key.key, sizeof(server_key.key),
	     rc4payload.r3, sizeof(rc4payload.r3),
	     mackey, &hash_len);

	dump_data_pw("mackey: \n", mackey, sizeof(mackey));

	ndr_err = ndr_push_struct_blob(&sid_blob, mem_ctx, &rc4payload.sid,
				       (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INTERNAL_ERROR;
	}

	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, mackey, hash_len, EVP_sha1(), NULL);
	/* SID field */
	HMAC_Update(&ctx, sid_blob.data, sid_blob.length);
	/* Secret field */
	HMAC_Update(&ctx, rc4payload.secret_data.data, rc4payload.secret_data.length);
	HMAC_Final(&ctx, mac, &hash_len);
	HMAC_CTX_cleanup(&ctx);

	dump_data_pw("mac: \n", mac, sizeof(mac));
	dump_data_pw("rc4payload.mac: \n", rc4payload.mac, sizeof(rc4payload.mac));
	
	if (memcmp(mac, rc4payload.mac, sizeof(mac)) != 0) {
		return WERR_INVALID_ACCESS;
	}

	caller_sid = &dce_call->conn->auth_state.session_info->security_token->sids[PRIMARY_USER_SID_INDEX];

	if (!dom_sid_equal(&rc4payload.sid, caller_sid)) {
		return WERR_INVALID_ACCESS;
	}

	*(r->out.data_out) = rc4payload.secret_data.data;
	*(r->out.data_out_len) = rc4payload.secret_data.length;
	
	return WERR_OK;
}

/* 
 * For BACKUPKEY_RESTORE_GUID we need to check the first 4 bytes to
 * determine what type of restore is wanted.
 * 
 * See MS-BKRP 3.1.4.1.4 BACKUPKEY_RESTORE_GUID point 1.
 */

static WERROR bkrp_generic_decrypt_data(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct bkrp_BackupKey *r, struct ldb_context *ldb_ctx)
{
	if (r->in.data_in_len < 4 || r->in.data_in == NULL) {
		return WERR_INVALID_PARAM;
	}

	if (IVAL(r->in.data_in, 0) == BACKUPKEY_SERVER_WRAP_VERSION) {
		return bkrp_server_wrap_decrypt_data(dce_call, mem_ctx, r, ldb_ctx);
	}
	
	return bkrp_client_wrap_decrypt_data(dce_call, mem_ctx, r, ldb_ctx);
}
	
/* 
 * We have some data, such as saved website or IMAP passwords that the
 * client would like to put into the profile on-disk.  This needs to
 * be encrypted.  This version gives the server the data over the
 * network (protected only by the negotiated transport encryption),
 * and asks that it be encrypted and returned for long-term storage.
 *
 * The data is NOT stored in the LSA, but a key to encrypt the data
 * will be stored.  There is only one active encryption key per domain,
 * it is pointed at with G$BCKUPKEY_P in the LSA secrets store.  
 *
 * The potentially multiple valid decryptiong keys (and the encryption
 * key) are in turn stored in the LSA secrets store as
 * G$BCKUPKEY_keyGuidString.
 *
 */

static WERROR bkrp_server_wrap_encrypt_data(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					    struct bkrp_BackupKey *r ,struct ldb_context *ldb_ctx)
{
	DATA_BLOB sid_blob, encrypted_blob, symkey_blob, server_wrapped_blob;
	WERROR werr;
	struct dom_sid *caller_sid;
	uint8_t symkey[20]; /* SHA-1 hash len */
	uint8_t mackey[20]; /* SHA-1 hash len */
	unsigned int hash_len;
	struct bkrp_rc4encryptedpayload rc4payload;
	HMAC_CTX ctx;
	struct bkrp_dc_serverwrap_key server_key;
	enum ndr_err_code ndr_err;
	struct bkrp_server_side_wrapped server_side_wrapped;
	struct GUID guid;
	
	if (r->in.data_in_len == 0 || r->in.data_in == NULL) {
		return WERR_INVALID_PARAM;
	}

	werr = bkrp_do_retrieve_default_server_wrap_key(mem_ctx,
							ldb_ctx, &server_key,
							&guid);
	
	if (!W_ERROR_IS_OK(werr)) {
		if (W_ERROR_EQUAL(werr, WERR_FILE_NOT_FOUND)) {
			/* Generate the server wrap key since one wasn't found */
			werr =  generate_bkrp_server_wrap_key(mem_ctx, 
							      ldb_ctx);
			if (!W_ERROR_IS_OK(werr)) {
				return WERR_INVALID_PARAMETER;
			}
			werr = bkrp_do_retrieve_default_server_wrap_key(mem_ctx,
									ldb_ctx,
									&server_key,
									&guid);
			
			if (W_ERROR_EQUAL(werr, WERR_FILE_NOT_FOUND)) {
				/* Ok we really don't manage to get this secret ...*/
				return WERR_FILE_NOT_FOUND;
			}
		} else {
			/* In theory we should NEVER reach this point as it
			   should only appear in a rodc server */
			/* we do not have the real secret attribute */
			return WERR_INVALID_PARAMETER;
		}
	}

	caller_sid = &dce_call->conn->auth_state.session_info->security_token->sids[PRIMARY_USER_SID_INDEX];

	dump_data_pw("server_key: \n", server_key.key, sizeof(server_key.key));
	
	/* 
	 * This is the key derivation step, so that the HMAC and RC4
	 * operations over the user-supplied data are not able to
	 * disclose the master key.  By using random data, the symkey
	 * and mackey values are unique for this operation, and
	 * discovering these (by reversing the RC4 over the
	 * attacker-controlled data) does not return something able to
	 * be used to decyrpt the encrypted data of other users 
	 */
	generate_random_buffer(server_side_wrapped.r2, sizeof(server_side_wrapped.r2));

	dump_data_pw("r2: \n", server_side_wrapped.r2, sizeof(server_side_wrapped.r2));

	generate_random_buffer(rc4payload.r3, sizeof(rc4payload.r3));

	dump_data_pw("r3: \n", rc4payload.r3, sizeof(rc4payload.r3));


	/*
	 * This is *not* the leading 64 bytes, as indicated in MS-BKRP 3.1.4.1.1
	 * BACKUPKEY_BACKUP_GUID, it really is the whole key 
	 */
	HMAC(EVP_sha1(), server_key.key, sizeof(server_key.key),
	     server_side_wrapped.r2, sizeof(server_side_wrapped.r2),
	     symkey, &hash_len);

	dump_data_pw("symkey: \n", symkey, hash_len);

	/*
	 * This is *not* the leading 64 bytes, as indicated in MS-BKRP 3.1.4.1.1
	 * BACKUPKEY_BACKUP_GUID, it really is the whole key 
	 */
	HMAC(EVP_sha1(), server_key.key, sizeof(server_key.key),
	     rc4payload.r3, sizeof(rc4payload.r3),
	     mackey, &hash_len);

	dump_data_pw("mackey: \n", mackey, sizeof(mackey));

	ndr_err = ndr_push_struct_blob(&sid_blob, mem_ctx, caller_sid,
				       (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INTERNAL_ERROR;
	}

	rc4payload.secret_data.data = r->in.data_in;
	rc4payload.secret_data.length = r->in.data_in_len;
	

	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, mackey, 20, EVP_sha1(), NULL);
	/* SID field */
	HMAC_Update(&ctx, sid_blob.data, sid_blob.length);
	/* Secret field */
	HMAC_Update(&ctx, rc4payload.secret_data.data, rc4payload.secret_data.length);
	HMAC_Final(&ctx, rc4payload.mac, &hash_len);
	HMAC_CTX_cleanup(&ctx);

	dump_data_pw("rc4payload.mac: \n", rc4payload.mac, sizeof(rc4payload.mac));
	
	rc4payload.sid = *caller_sid;

	ndr_err = ndr_push_struct_blob(&encrypted_blob, mem_ctx, &rc4payload,
				       (ndr_push_flags_fn_t)ndr_push_bkrp_rc4encryptedpayload);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INTERNAL_ERROR;
	}

	/* rc4 encrypt sid and secret using sym key */
	symkey_blob = data_blob_const(symkey, sizeof(symkey));
	arcfour_crypt_blob(encrypted_blob.data, encrypted_blob.length, &symkey_blob);

	/* create server wrap structure */

	server_side_wrapped.payload_length = rc4payload.secret_data.length;
	server_side_wrapped.ciphertext_length = encrypted_blob.length;
	server_side_wrapped.guid = guid;
	server_side_wrapped.rc4encryptedpayload = encrypted_blob.data;
	
	ndr_err = ndr_push_struct_blob(&server_wrapped_blob, mem_ctx, &server_side_wrapped,
				       (ndr_push_flags_fn_t)ndr_push_bkrp_server_side_wrapped);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INTERNAL_ERROR;
	}

	
	*(r->out.data_out) = server_wrapped_blob.data;
	*(r->out.data_out_len) = server_wrapped_blob.length;
	
	return WERR_OK;
}

static WERROR dcesrv_bkrp_BackupKey(struct dcesrv_call_state *dce_call,
				    TALLOC_CTX *mem_ctx, struct bkrp_BackupKey *r)
{
	WERROR error = WERR_INVALID_PARAM;
	struct ldb_context *ldb_ctx;
	bool is_rodc;
	const char *addr = "unknown";
	/* At which level we start to add more debug of what is done in the protocol */
	const int debuglevel = 4;

	if (DEBUGLVL(debuglevel)) {
		const struct tsocket_address *remote_address;
		remote_address = dcesrv_connection_get_remote_address(dce_call->conn);
		if (tsocket_address_is_inet(remote_address, "ip")) {
			addr = tsocket_address_inet_addr_string(remote_address, mem_ctx);
			W_ERROR_HAVE_NO_MEMORY(addr);
		}
	}

	if (lpcfg_server_role(dce_call->conn->dce_ctx->lp_ctx) != ROLE_ACTIVE_DIRECTORY_DC) {
		return WERR_NOT_SUPPORTED;
	}

	if (!dce_call->conn->auth_state.auth_info ||
		dce_call->conn->auth_state.auth_info->auth_level != DCERPC_AUTH_LEVEL_PRIVACY) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	ldb_ctx = samdb_connect(mem_ctx, dce_call->event_ctx,
				dce_call->conn->dce_ctx->lp_ctx,
				system_session(dce_call->conn->dce_ctx->lp_ctx), 0);

	if (samdb_rodc(ldb_ctx, &is_rodc) != LDB_SUCCESS) {
		talloc_unlink(mem_ctx, ldb_ctx);
		return WERR_INVALID_PARAM;
	}

	if (!is_rodc) {
		if(strncasecmp(GUID_string(mem_ctx, r->in.guidActionAgent),
			BACKUPKEY_RESTORE_GUID, strlen(BACKUPKEY_RESTORE_GUID)) == 0) {
			DEBUG(debuglevel, ("Client %s requested to decrypt a wrapped secret\n", addr));
			error = bkrp_generic_decrypt_data(dce_call, mem_ctx, r, ldb_ctx);
		}

		if (strncasecmp(GUID_string(mem_ctx, r->in.guidActionAgent),
			BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, strlen(BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID)) == 0) {
			DEBUG(debuglevel, ("Client %s requested certificate for client wrapped secret\n", addr));
			error = bkrp_retrieve_client_wrap_key(dce_call, mem_ctx, r, ldb_ctx);
		}

		if (strncasecmp(GUID_string(mem_ctx, r->in.guidActionAgent),
			BACKUPKEY_RESTORE_GUID_WIN2K, strlen(BACKUPKEY_RESTORE_GUID_WIN2K)) == 0) {
			DEBUG(debuglevel, ("Client %s requested to decrypt a server side wrapped secret\n", addr));
			error = bkrp_server_wrap_decrypt_data(dce_call, mem_ctx, r, ldb_ctx);
		}

		if (strncasecmp(GUID_string(mem_ctx, r->in.guidActionAgent),
			BACKUPKEY_BACKUP_GUID, strlen(BACKUPKEY_BACKUP_GUID)) == 0) {
			DEBUG(debuglevel, ("Client %s requested a server wrapped secret\n", addr));
			error = bkrp_server_wrap_encrypt_data(dce_call, mem_ctx, r, ldb_ctx);
		}
	}
	/*else: I am a RODC so I don't handle backup key protocol */

	talloc_unlink(mem_ctx, ldb_ctx);
	return error;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_backupkey_s.c"
