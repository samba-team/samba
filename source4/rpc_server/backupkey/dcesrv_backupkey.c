/*
   Unix SMB/CIFS implementation.

   endpoint server for the backupkey interface

   Copyright (C) Matthieu Patou <mat@samba.org> 2010
   Copyright (C) Andreas Schneider <asn@samba.org> 2015

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
#include "rpc_server/common/common.h"
#include "librpc/gen_ndr/ndr_backupkey.h"
#include "dsdb/common/util.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "../lib/util/util_ldb.h"
#include "param/param.h"
#include "auth/session.h"
#include "system/network.h"

#include "../lib/tsocket/tsocket.h"
#include "../libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libds/common/roles.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include "lib/crypto/gnutls_helpers.h"

#define DCESRV_INTERFACE_BACKUPKEY_BIND(context, iface) \
	dcesrv_interface_backupkey_bind(context, iface)
static NTSTATUS dcesrv_interface_backupkey_bind(struct dcesrv_connection_context *context,
						const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_require_privacy(context, iface);
}

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
	}
	if (res->count == 0) {
		talloc_free(tmp_mem);
		return NT_STATUS_RESOURCE_NAME_NOT_FOUND;
	}
	if (res->count > 1) {
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

static int reverse_and_get_bignum(TALLOC_CTX *mem_ctx,
				  DATA_BLOB blob,
				  gnutls_datum_t *datum)
{
	uint32_t i;

	datum->data = talloc_array(mem_ctx, uint8_t, blob.length);
	if (datum->data == NULL) {
		return -1;
	}

	for(i = 0; i < blob.length; i++) {
		datum->data[i] = blob.data[blob.length - i - 1];
	}
	datum->size = blob.length;

	return 0;
}

static NTSTATUS get_pk_from_raw_keypair_params(TALLOC_CTX *ctx,
				struct bkrp_exported_RSA_key_pair *keypair,
				gnutls_privkey_t *pk)
{
	gnutls_x509_privkey_t x509_privkey = NULL;
	gnutls_privkey_t privkey = NULL;
	gnutls_datum_t m, e, d, p, q, u, e1, e2;
	int rc;

	rc = reverse_and_get_bignum(ctx, keypair->modulus, &m);
	if (rc != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	rc = reverse_and_get_bignum(ctx, keypair->public_exponent, &e);
	if (rc != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	rc = reverse_and_get_bignum(ctx, keypair->private_exponent, &d);
	if (rc != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	rc = reverse_and_get_bignum(ctx, keypair->prime1, &p);
	if (rc != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	rc = reverse_and_get_bignum(ctx, keypair->prime2, &q);
	if (rc != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	rc = reverse_and_get_bignum(ctx, keypair->coefficient, &u);
	if (rc != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	rc = reverse_and_get_bignum(ctx, keypair->exponent1, &e1);
	if (rc != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	rc = reverse_and_get_bignum(ctx, keypair->exponent2, &e2);
	if (rc != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	rc = gnutls_x509_privkey_init(&x509_privkey);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_privkey_init failed - %s\n",
			gnutls_strerror(rc));
		return NT_STATUS_INTERNAL_ERROR;
	}

	rc = gnutls_x509_privkey_import_rsa_raw2(x509_privkey,
						 &m,
						 &e,
						 &d,
						 &p,
						 &q,
						 &u,
						 &e1,
						 &e2);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_privkey_import_rsa_raw2 failed - %s\n",
			gnutls_strerror(rc));
		return NT_STATUS_INTERNAL_ERROR;
	}

	rc = gnutls_privkey_init(&privkey);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_privkey_init failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_privkey_deinit(x509_privkey);
		return NT_STATUS_INTERNAL_ERROR;
	}

	rc = gnutls_privkey_import_x509(privkey,
					x509_privkey,
					GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_privkey_import_x509 failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_privkey_deinit(x509_privkey);
		return NT_STATUS_INTERNAL_ERROR;
	}

	*pk = privkey;

	return NT_STATUS_OK;
}

static WERROR get_and_verify_access_check(TALLOC_CTX *sub_ctx,
					  uint32_t version,
					  uint8_t *key_and_iv,
					  uint8_t *access_check,
					  uint32_t access_check_len,
					  struct auth_session_info *session_info)
{
	struct bkrp_access_check_v2 uncrypted_accesscheckv2;
	struct bkrp_access_check_v3 uncrypted_accesscheckv3;
	gnutls_cipher_hd_t cipher_handle = { 0 };
	gnutls_cipher_algorithm_t cipher_algo;
	DATA_BLOB blob_us;
	enum ndr_err_code ndr_err;
	gnutls_datum_t key;
	gnutls_datum_t iv;

	struct dom_sid *access_sid = NULL;
	struct dom_sid *caller_sid = NULL;
	int rc;

	switch (version) {
	case 2:
		cipher_algo = GNUTLS_CIPHER_3DES_CBC;
		break;
	case 3:
		cipher_algo = GNUTLS_CIPHER_AES_256_CBC;
		break;
	default:
		return WERR_INVALID_DATA;
	}

	key.data = key_and_iv;
	key.size = gnutls_cipher_get_key_size(cipher_algo);

	iv.data = key_and_iv + key.size;
	iv.size = gnutls_cipher_get_iv_size(cipher_algo);

	/* Allocate data structure for the plaintext */
	blob_us = data_blob_talloc_zero(sub_ctx, access_check_len);
	if (blob_us.data == NULL) {
		return WERR_INVALID_DATA;
	}

	rc = gnutls_cipher_init(&cipher_handle,
				cipher_algo,
				&key,
				&iv);
	if (rc < 0) {
		DBG_ERR("gnutls_cipher_init failed: %s\n",
			gnutls_strerror(rc));
		return WERR_INVALID_DATA;
	}

	rc = gnutls_cipher_decrypt2(cipher_handle,
				    access_check,
				    access_check_len,
				    blob_us.data,
				    blob_us.length);
	gnutls_cipher_deinit(cipher_handle);
	if (rc < 0) {
		DBG_ERR("gnutls_cipher_decrypt2 failed: %s\n",
			gnutls_strerror(rc));
		return WERR_INVALID_DATA;
	}

	switch (version) {
	case 2:
	{
		uint32_t hash_size = 20;
		uint8_t hash[hash_size];
		gnutls_hash_hd_t dig_ctx;

		ndr_err = ndr_pull_struct_blob(&blob_us, sub_ctx, &uncrypted_accesscheckv2,
					(ndr_pull_flags_fn_t)ndr_pull_bkrp_access_check_v2);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			/* Unable to unmarshall */
			return WERR_INVALID_DATA;
		}
		if (uncrypted_accesscheckv2.magic != 0x1) {
			/* wrong magic */
			return WERR_INVALID_DATA;
		}

		gnutls_hash_init(&dig_ctx, GNUTLS_DIG_SHA1);
		gnutls_hash(dig_ctx,
			    blob_us.data,
			    blob_us.length - hash_size);
		gnutls_hash_deinit(dig_ctx, hash);
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
		gnutls_hash_hd_t dig_ctx;

		ndr_err = ndr_pull_struct_blob(&blob_us, sub_ctx, &uncrypted_accesscheckv3,
					(ndr_pull_flags_fn_t)ndr_pull_bkrp_access_check_v3);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			/* Unable to unmarshall */
			return WERR_INVALID_DATA;
		}
		if (uncrypted_accesscheckv3.magic != 0x1) {
			/* wrong magic */
			return WERR_INVALID_DATA;
		}

		gnutls_hash_init(&dig_ctx, GNUTLS_DIG_SHA512);
		gnutls_hash(dig_ctx,
			    blob_us.data,
			    blob_us.length - hash_size);
		gnutls_hash_deinit(dig_ctx, hash);

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
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct bkrp_client_side_wrapped uncrypt_request;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	char *guid_string;
	char *cert_secret_name;
	DATA_BLOB lsa_secret;
	DATA_BLOB *uncrypted_data = NULL;
	NTSTATUS status;
	uint32_t requested_version;

	blob.data = r->in.data_in;
	blob.length = r->in.data_in_len;

	if (r->in.data_in_len < 4 || r->in.data_in == NULL) {
		return WERR_INVALID_PARAMETER;
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
		return WERR_INVALID_PARAMETER;
	}

	if ((uncrypt_request.version != BACKUPKEY_CLIENT_WRAP_VERSION2)
	    && (uncrypt_request.version != BACKUPKEY_CLIENT_WRAP_VERSION3)) {
		DEBUG(1, ("Request for unknown BackupKey sub-protocol %d\n", uncrypt_request.version));
		return WERR_INVALID_PARAMETER;
	}

	guid_string = GUID_string(mem_ctx, &uncrypt_request.guid);
	if (guid_string == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	cert_secret_name = talloc_asprintf(mem_ctx,
					   "BCKUPKEY_%s",
					   guid_string);
	if (cert_secret_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
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
		struct bkrp_exported_RSA_key_pair keypair;
		gnutls_privkey_t privkey = NULL;
		gnutls_datum_t reversed_secret;
		gnutls_datum_t uncrypted_secret;
		uint32_t i;
		DATA_BLOB blob_us;
		WERROR werr;
		int rc;

		ndr_err = ndr_pull_struct_blob(&lsa_secret, mem_ctx, &keypair, (ndr_pull_flags_fn_t)ndr_pull_bkrp_exported_RSA_key_pair);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(2, ("Unable to parse the ndr encoded cert in key %s\n", cert_secret_name));
			return WERR_FILE_NOT_FOUND;
		}

		status = get_pk_from_raw_keypair_params(mem_ctx,
							&keypair,
							&privkey);
		if (!NT_STATUS_IS_OK(status)) {
			return WERR_INTERNAL_ERROR;
		}

		reversed_secret.data = talloc_array(mem_ctx, uint8_t,
						    uncrypt_request.encrypted_secret_len);
		if (reversed_secret.data == NULL) {
			gnutls_privkey_deinit(privkey);
			return WERR_NOT_ENOUGH_MEMORY;
		}

		/* The secret has to be reversed ... */
		for(i=0; i< uncrypt_request.encrypted_secret_len; i++) {
			uint8_t *reversed = (uint8_t *)reversed_secret.data;
			uint8_t *uncrypt = uncrypt_request.encrypted_secret;
			reversed[i] = uncrypt[uncrypt_request.encrypted_secret_len - 1 - i];
		}
		reversed_secret.size = uncrypt_request.encrypted_secret_len;

		/*
		 * Let's try to decrypt the secret now that
		 * we have the private key ...
		 */
		rc = gnutls_privkey_decrypt_data(privkey,
						 0,
						 &reversed_secret,
						 &uncrypted_secret);
		gnutls_privkey_deinit(privkey);
		if (rc != GNUTLS_E_SUCCESS) {
			/* We are not able to decrypt the secret, looks like something is wrong */
			return WERR_INVALID_PARAMETER;
		}
		blob_us.data = uncrypted_secret.data;
		blob_us.length = uncrypted_secret.size;

		if (uncrypt_request.version == 2) {
			struct bkrp_encrypted_secret_v2 uncrypted_secretv2;

			ndr_err = ndr_pull_struct_blob(&blob_us, mem_ctx, &uncrypted_secretv2,
					(ndr_pull_flags_fn_t)ndr_pull_bkrp_encrypted_secret_v2);
			gnutls_free(uncrypted_secret.data);
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
							   session_info);
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
			gnutls_free(uncrypted_secret.data);
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
							   session_info);
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

static DATA_BLOB *reverse_and_get_blob(TALLOC_CTX *mem_ctx,
				       gnutls_datum_t *datum)
{
	DATA_BLOB *blob;
	size_t i;

	blob = talloc(mem_ctx, DATA_BLOB);
	if (blob == NULL) {
		return NULL;
	}

	blob->length = datum->size;
	if (datum->data[0] == '\0') {
		/* The datum has a leading byte zero, skip it */
		blob->length = datum->size - 1;
	}
	blob->data = talloc_zero_array(mem_ctx, uint8_t, blob->length);
	if (blob->data == NULL) {
		talloc_free(blob);
		return NULL;
	}

	for (i = 0; i < blob->length; i++) {
		blob->data[i] = datum->data[datum->size - i - 1];
	}

	return blob;
}

static WERROR create_privkey_rsa(gnutls_privkey_t *pk)
{
	int bits = 2048;
	gnutls_x509_privkey_t x509_privkey = NULL;
	gnutls_privkey_t privkey = NULL;
	int rc;

	rc = gnutls_x509_privkey_init(&x509_privkey);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_privkey_init failed - %s\n",
			gnutls_strerror(rc));
		return WERR_INTERNAL_ERROR;
	}

	rc = gnutls_x509_privkey_generate(x509_privkey,
					  GNUTLS_PK_RSA,
					  bits,
					  0);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_privkey_generate failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_privkey_deinit(x509_privkey);
		return WERR_INTERNAL_ERROR;
	}

	rc = gnutls_privkey_init(&privkey);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_privkey_init failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_privkey_deinit(x509_privkey);
		return WERR_INTERNAL_ERROR;
	}

	rc = gnutls_privkey_import_x509(privkey,
					x509_privkey,
					GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_privkey_import_x509 failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_privkey_deinit(x509_privkey);
		return WERR_INTERNAL_ERROR;
	}

	*pk = privkey;

	return WERR_OK;
}

static WERROR self_sign_cert(TALLOC_CTX *mem_ctx,
			     time_t lifetime,
			     const char *dn,
			     gnutls_privkey_t issuer_privkey,
			     gnutls_x509_crt_t *certificate,
			     DATA_BLOB *guidblob)
{
	gnutls_datum_t unique_id;
	gnutls_datum_t serial_number;
	gnutls_x509_crt_t issuer_cert;
	gnutls_x509_privkey_t x509_issuer_privkey;
	time_t activation = time(NULL);
	time_t expiry = activation + lifetime;
	const char *error_string;
	uint8_t *reversed;
	size_t i;
	int rc;

	unique_id.size = guidblob->length;
	unique_id.data = talloc_memdup(mem_ctx,
				       guidblob->data,
				       guidblob->length);
	if (unique_id.data == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	reversed = talloc_array(mem_ctx, uint8_t, guidblob->length);
	if (reversed == NULL) {
		talloc_free(unique_id.data);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/* Native AD generates certificates with serialnumber in reversed notation */
	for (i = 0; i < guidblob->length; i++) {
		uint8_t *uncrypt = guidblob->data;
		reversed[i] = uncrypt[guidblob->length - i - 1];
	}
	serial_number.size = guidblob->length;
	serial_number.data = reversed;

	/* Create certificate to sign */
	rc = gnutls_x509_crt_init(&issuer_cert);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_init failed - %s\n",
			gnutls_strerror(rc));
		return WERR_NOT_ENOUGH_MEMORY;
	}

	rc = gnutls_x509_crt_set_dn(issuer_cert, dn, &error_string);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_set_dn failed - %s (%s)\n",
			gnutls_strerror(rc),
			error_string);
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	rc = gnutls_x509_crt_set_issuer_dn(issuer_cert, dn, &error_string);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_set_issuer_dn failed - %s (%s)\n",
			gnutls_strerror(rc),
			error_string);
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	/* Get x509 privkey for subjectPublicKeyInfo */
	rc = gnutls_x509_privkey_init(&x509_issuer_privkey);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_privkey_init failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	rc = gnutls_privkey_export_x509(issuer_privkey,
					&x509_issuer_privkey);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_privkey_init failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_privkey_deinit(x509_issuer_privkey);
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	/* Set subjectPublicKeyInfo */
	rc = gnutls_x509_crt_set_key(issuer_cert, x509_issuer_privkey);
	gnutls_x509_privkey_deinit(x509_issuer_privkey);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_set_pubkey failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	rc = gnutls_x509_crt_set_activation_time(issuer_cert, activation);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_set_activation_time failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	rc = gnutls_x509_crt_set_expiration_time(issuer_cert, expiry);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_set_expiration_time failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	rc = gnutls_x509_crt_set_version(issuer_cert, 3);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_set_version failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	rc = gnutls_x509_crt_set_subject_unique_id(issuer_cert,
						   unique_id.data,
						   unique_id.size);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_set_subject_key_id failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	rc = gnutls_x509_crt_set_issuer_unique_id(issuer_cert,
						  unique_id.data,
						  unique_id.size);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_set_issuer_unique_id failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	rc = gnutls_x509_crt_set_serial(issuer_cert,
					serial_number.data,
					serial_number.size);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_set_serial failed - %s\n",
			gnutls_strerror(rc));
		gnutls_x509_crt_deinit(issuer_cert);
		return WERR_INVALID_PARAMETER;
	}

	rc = gnutls_x509_crt_privkey_sign(issuer_cert,
					  issuer_cert,
					  issuer_privkey,
					  GNUTLS_DIG_SHA1,
					  0);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_privkey_sign failed - %s\n",
			gnutls_strerror(rc));
		return WERR_INVALID_PARAMETER;
	}

	*certificate = issuer_cert;

	return WERR_OK;
}

/* Return an error when we fail to generate a certificate */
static WERROR generate_bkrp_cert(TALLOC_CTX *mem_ctx,
				 struct dcesrv_call_state *dce_call,
				 struct ldb_context *ldb_ctx,
				 const char *dn)
{
	WERROR werr;
	gnutls_privkey_t issuer_privkey = NULL;
	gnutls_x509_crt_t cert = NULL;
	gnutls_datum_t cert_blob;
	gnutls_datum_t m, e, d, p, q, u, e1, e2;
	DATA_BLOB blob;
	DATA_BLOB blobkeypair;
	DATA_BLOB *tmp;
	bool ok = true;
	struct GUID guid = GUID_random();
	NTSTATUS status;
	char *secret_name;
	struct bkrp_exported_RSA_key_pair keypair;
	enum ndr_err_code ndr_err;
	time_t nb_seconds_validity = 3600 * 24 * 365;
	int rc;

	DEBUG(6, ("Trying to generate a certificate\n"));
	werr = create_privkey_rsa(&issuer_privkey);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	status = GUID_to_ndr_blob(&guid, mem_ctx, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		gnutls_privkey_deinit(issuer_privkey);
		return WERR_INVALID_DATA;
	}

	werr = self_sign_cert(mem_ctx,
			      nb_seconds_validity,
			      dn,
			      issuer_privkey,
			      &cert,
			      &blob);
	if (!W_ERROR_IS_OK(werr)) {
		gnutls_privkey_deinit(issuer_privkey);
		return WERR_INVALID_DATA;
	}

	rc = gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_DER, &cert_blob);
	if (rc != GNUTLS_E_SUCCESS) {
		DBG_ERR("gnutls_x509_crt_export2 failed - %s\n",
			gnutls_strerror(rc));
		gnutls_privkey_deinit(issuer_privkey);
		gnutls_x509_crt_deinit(cert);
		return WERR_INVALID_DATA;
	}

	keypair.cert.length = cert_blob.size;
	keypair.cert.data = talloc_memdup(mem_ctx, cert_blob.data, cert_blob.size);
	gnutls_x509_crt_deinit(cert);
	gnutls_free(cert_blob.data);
	if (keypair.cert.data == NULL) {
		gnutls_privkey_deinit(issuer_privkey);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	rc = gnutls_privkey_export_rsa_raw(issuer_privkey,
					   &m,
					   &e,
					   &d,
					   &p,
					   &q,
					   &u,
					   &e1,
					   &e2);
	if (rc != GNUTLS_E_SUCCESS) {
		gnutls_privkey_deinit(issuer_privkey);
		return WERR_INVALID_DATA;
	}

	/*
	 * Heimdal's bignum are big endian and the
	 * structure expect it to be in little endian
	 * so we reverse the buffer to make it work
	 */
	tmp = reverse_and_get_blob(mem_ctx, &e);
	if (tmp == NULL) {
		ok = false;
	} else {
		SMB_ASSERT(tmp->length <= 4);
		keypair.public_exponent = *tmp;
	}

	tmp = reverse_and_get_blob(mem_ctx, &d);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.private_exponent = *tmp;
	}

	tmp = reverse_and_get_blob(mem_ctx, &m);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.modulus = *tmp;
	}

	tmp = reverse_and_get_blob(mem_ctx, &p);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.prime1 = *tmp;
	}

	tmp = reverse_and_get_blob(mem_ctx, &q);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.prime2 = *tmp;
	}

	tmp = reverse_and_get_blob(mem_ctx, &e1);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.exponent1 = *tmp;
	}

	tmp = reverse_and_get_blob(mem_ctx, &e2);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.exponent2 = *tmp;
	}

	tmp = reverse_and_get_blob(mem_ctx, &u);
	if (tmp == NULL) {
		ok = false;
	} else {
		keypair.coefficient = *tmp;
	}

	/* One of the keypair allocation was wrong */
	if (ok == false) {
		gnutls_privkey_deinit(issuer_privkey);
		return WERR_INVALID_DATA;
	}

	keypair.certificate_len = keypair.cert.length;
	ndr_err = ndr_push_struct_blob(&blobkeypair,
				       mem_ctx,
				       &keypair,
				       (ndr_push_flags_fn_t)ndr_push_bkrp_exported_RSA_key_pair);
	gnutls_privkey_deinit(issuer_privkey);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INVALID_DATA;
	}

	secret_name = talloc_asprintf(mem_ctx, "BCKUPKEY_%s", GUID_string(mem_ctx, &guid));
	if (secret_name == NULL) {
		return WERR_OUTOFMEMORY;
	}

	status = set_lsa_secret(mem_ctx, ldb_ctx, secret_name, &blobkeypair);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to save the secret %s\n", secret_name));
	}
	talloc_free(secret_name);

	GUID_to_ndr_blob(&guid, mem_ctx, &blob);
	status = set_lsa_secret(mem_ctx, ldb_ctx, "BCKUPKEY_PREFERRED", &blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to save the secret BCKUPKEY_PREFERRED\n"));
	}

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
		return WERR_NOT_ENOUGH_MEMORY;
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
	DATA_BLOB lsa_secret;
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
		return WERR_NOT_ENOUGH_MEMORY;
	}

	status = get_lsa_secret(mem_ctx, ldb_ctx, secret_name, &lsa_secret);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Error while fetching secret %s\n", secret_name));
		return WERR_INVALID_DATA;
	}
	if (lsa_secret.length == 0) {
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
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	WERROR werr;
	struct bkrp_server_side_wrapped decrypt_request;
	DATA_BLOB sid_blob, encrypted_blob;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct bkrp_dc_serverwrap_key server_key;
	struct bkrp_rc4encryptedpayload rc4payload;
	struct dom_sid *caller_sid;
	uint8_t symkey[20]; /* SHA-1 hash len */
	uint8_t mackey[20]; /* SHA-1 hash len */
	uint8_t mac[20]; /* SHA-1 hash len */
	gnutls_hmac_hd_t hmac_hnd;
	gnutls_cipher_hd_t cipher_hnd;
	gnutls_datum_t cipher_key;
	int rc;

	blob.data = r->in.data_in;
	blob.length = r->in.data_in_len;

	if (r->in.data_in_len == 0 || r->in.data_in == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	ndr_err = ndr_pull_struct_blob_all(&blob, mem_ctx, &decrypt_request,
					   (ndr_pull_flags_fn_t)ndr_pull_bkrp_server_side_wrapped);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INVALID_PARAMETER;
	}

	if (decrypt_request.magic != BACKUPKEY_SERVER_WRAP_VERSION) {
		return WERR_INVALID_PARAMETER;
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

	rc = gnutls_hmac_init(&hmac_hnd,
			      GNUTLS_MAC_SHA1,
			      server_key.key,
			      sizeof(server_key.key));
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	rc = gnutls_hmac(hmac_hnd,
		    decrypt_request.r2,
		    sizeof(decrypt_request.r2));

	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	gnutls_hmac_output(hmac_hnd, symkey);
	dump_data_pw("symkey: \n", symkey, sizeof(symkey));

	/* rc4 decrypt sid and secret using sym key */
	cipher_key.data = symkey;
	cipher_key.size = sizeof(symkey);

	encrypted_blob = data_blob_const(decrypt_request.rc4encryptedpayload,
					 decrypt_request.ciphertext_length);

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&cipher_key,
				NULL);
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}
	rc = gnutls_cipher_encrypt2(cipher_hnd,
				    encrypted_blob.data,
				    encrypted_blob.length,
				    encrypted_blob.data,
				    encrypted_blob.length);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	ndr_err = ndr_pull_struct_blob_all(&encrypted_blob, mem_ctx, &rc4payload,
					   (ndr_pull_flags_fn_t)ndr_pull_bkrp_rc4encryptedpayload);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INVALID_PARAMETER;
	}

	if (decrypt_request.payload_length != rc4payload.secret_data.length) {
		return WERR_INVALID_PARAMETER;
	}

	dump_data_pw("r3: \n", rc4payload.r3, sizeof(rc4payload.r3));

	/*
	 * This is *not* the leading 64 bytes, as indicated in MS-BKRP 3.1.4.1.1
	 * BACKUPKEY_BACKUP_GUID, it really is the whole key
	 */
	rc = gnutls_hmac(hmac_hnd,
			 rc4payload.r3,
			 sizeof(rc4payload.r3));
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	gnutls_hmac_deinit(hmac_hnd, mackey);

	dump_data_pw("mackey: \n", mackey, sizeof(mackey));

	ndr_err = ndr_push_struct_blob(&sid_blob, mem_ctx, &rc4payload.sid,
				       (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INTERNAL_ERROR;
	}

	rc = gnutls_hmac_init(&hmac_hnd,
			      GNUTLS_MAC_SHA1,
			      mackey,
			      sizeof(mackey));
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	/* SID field */
	rc = gnutls_hmac(hmac_hnd,
			 sid_blob.data,
			 sid_blob.length);
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	/* Secret field */
	rc = gnutls_hmac(hmac_hnd,
			 rc4payload.secret_data.data,
			 rc4payload.secret_data.length);
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	gnutls_hmac_deinit(hmac_hnd, mac);
	dump_data_pw("mac: \n", mac, sizeof(mac));
	dump_data_pw("rc4payload.mac: \n", rc4payload.mac, sizeof(rc4payload.mac));

	if (memcmp(mac, rc4payload.mac, sizeof(mac)) != 0) {
		return WERR_INVALID_ACCESS;
	}

	caller_sid = &session_info->security_token->sids[PRIMARY_USER_SID_INDEX];

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
		return WERR_INVALID_PARAMETER;
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
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	DATA_BLOB sid_blob, encrypted_blob, server_wrapped_blob;
	WERROR werr;
	struct dom_sid *caller_sid;
	uint8_t symkey[20]; /* SHA-1 hash len */
	uint8_t mackey[20]; /* SHA-1 hash len */
	struct bkrp_rc4encryptedpayload rc4payload;
	gnutls_hmac_hd_t hmac_hnd;
	struct bkrp_dc_serverwrap_key server_key;
	enum ndr_err_code ndr_err;
	struct bkrp_server_side_wrapped server_side_wrapped;
	struct GUID guid;
	gnutls_cipher_hd_t cipher_hnd;
	gnutls_datum_t cipher_key;
	int rc;

	if (r->in.data_in_len == 0 || r->in.data_in == NULL) {
		return WERR_INVALID_PARAMETER;
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

	caller_sid = &session_info->security_token->sids[PRIMARY_USER_SID_INDEX];

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
	rc = gnutls_hmac_init(&hmac_hnd,
			      GNUTLS_MAC_SHA1,
			      server_key.key,
			      sizeof(server_key.key));
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	rc = gnutls_hmac(hmac_hnd,
			 server_side_wrapped.r2,
			 sizeof(server_side_wrapped.r2));
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}
	gnutls_hmac_output(hmac_hnd, symkey);
	dump_data_pw("symkey: \n", symkey, sizeof(symkey));

	/*
	 * This is *not* the leading 64 bytes, as indicated in MS-BKRP 3.1.4.1.1
	 * BACKUPKEY_BACKUP_GUID, it really is the whole key
	 */
	rc = gnutls_hmac(hmac_hnd,
			 rc4payload.r3,
			 sizeof(rc4payload.r3));
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}
	gnutls_hmac_deinit(hmac_hnd, mackey);
	dump_data_pw("mackey: \n", mackey, sizeof(mackey));

	ndr_err = ndr_push_struct_blob(&sid_blob, mem_ctx, caller_sid,
				       (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INTERNAL_ERROR;
	}

	rc4payload.secret_data.data = r->in.data_in;
	rc4payload.secret_data.length = r->in.data_in_len;

	rc = gnutls_hmac_init(&hmac_hnd,
			      GNUTLS_MAC_SHA1,
			      mackey,
			      sizeof(mackey));
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	/* SID field */
	rc = gnutls_hmac(hmac_hnd,
			 sid_blob.data,
			 sid_blob.length);
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	/* Secret field */
	rc = gnutls_hmac(hmac_hnd,
			 rc4payload.secret_data.data,
			 rc4payload.secret_data.length);
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

	gnutls_hmac_deinit(hmac_hnd, rc4payload.mac);
	dump_data_pw("rc4payload.mac: \n", rc4payload.mac, sizeof(rc4payload.mac));

	rc4payload.sid = *caller_sid;

	ndr_err = ndr_push_struct_blob(&encrypted_blob, mem_ctx, &rc4payload,
				       (ndr_push_flags_fn_t)ndr_push_bkrp_rc4encryptedpayload);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_INTERNAL_ERROR;
	}

	/* rc4 encrypt sid and secret using sym key */
	cipher_key.data = symkey;
	cipher_key.size = sizeof(symkey);

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&cipher_key,
				NULL);
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}
	rc = gnutls_cipher_encrypt2(cipher_hnd,
				    encrypted_blob.data,
				    encrypted_blob.length,
				    encrypted_blob.data,
				    encrypted_blob.length);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
	}

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
	WERROR error = WERR_INVALID_PARAMETER;
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

	/*
	 * Save the current remote session details so they can used by the
	 * audit logging module. This allows the audit logging to report the
	 * remote users details, rather than the system users details.
	 */
	ldb_ctx = dcesrv_samdb_connect_as_system(mem_ctx, dce_call);

	if (samdb_rodc(ldb_ctx, &is_rodc) != LDB_SUCCESS) {
		talloc_unlink(mem_ctx, ldb_ctx);
		return WERR_INVALID_PARAMETER;
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
