/*
   Unix SMB/CIFS implementation.
   test suite for backupkey remote protocol rpc operations

   Copyright (C) Matthieu Patou 2010-2011

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
#include "../libcli/security/security.h"
#include "librpc/gen_ndr/ndr_backupkey_c.h"
#include "librpc/gen_ndr/ndr_backupkey.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "torture/rpc/torture_rpc.h"
#include "torture/ndr/ndr.h"
#include "lib/cmdline/popt_common.h"
#include "libcli/auth/proto.h"
#include "lib/crypto/arcfour.h"
#include <com_err.h>
#include <hcrypto/sha.h>
#include <system/network.h>
#include <hx509.h>
#include <der.h>
#include <hcrypto/rsa.h>
#include <hcrypto/hmac.h>
#include <hcrypto/sha.h>
#include <hcrypto/evp.h>

enum test_wrong {
	WRONG_MAGIC,
	WRONG_R2,
	WRONG_PAYLOAD_LENGTH,
	WRONG_CIPHERTEXT_LENGTH,
	SHORT_PAYLOAD_LENGTH,
	SHORT_CIPHERTEXT_LENGTH,
	ZERO_PAYLOAD_LENGTH,
	ZERO_CIPHERTEXT_LENGTH,
	RIGHT_KEY,
	WRONG_KEY,
	WRONG_SID,
};

/* Our very special and valued secret */
/* No need to put const as we cast the array in uint8_t
 * we will get a warning about the discared const
 */
static const char secret[] = "tata yoyo mais qu'est ce qu'il y a sous ton grand chapeau ?";

/* Get the SID from a user */
static struct dom_sid *get_user_sid(struct torture_context *tctx,
				    TALLOC_CTX *mem_ctx,
				    const char *user)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	struct lsa_Close c;
	NTSTATUS status;
	struct policy_handle handle;
	struct lsa_LookupNames l;
	struct lsa_TransSidArray sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String lsa_name;
	uint32_t count = 0;
	struct dom_sid *result;
	TALLOC_CTX *tmp_ctx;
	struct dcerpc_pipe *p2;
	struct dcerpc_binding_handle *b;

	const char *domain = cli_credentials_get_domain(cmdline_credentials);

	torture_assert_ntstatus_ok(tctx,
				torture_rpc_connection(tctx, &p2, &ndr_table_lsarpc),
				"could not open lsarpc pipe");
	b = p2->binding_handle;

	if (!(tmp_ctx = talloc_new(mem_ctx))) {
		return NULL;
	}
	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = "\\";
	r.in.attr = &attr;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy2_r(b, tmp_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx,
				"OpenPolicy2 failed - %s\n",
				nt_errstr(status));
		talloc_free(tmp_ctx);
		return NULL;
	}
	if (!NT_STATUS_IS_OK(r.out.result)) {
		torture_comment(tctx,
				"OpenPolicy2_ failed - %s\n",
				nt_errstr(r.out.result));
		talloc_free(tmp_ctx);
		return NULL;
	}

	sids.count = 0;
	sids.sids = NULL;

	lsa_name.string = talloc_asprintf(tmp_ctx, "%s\\%s", domain, user);

	l.in.handle = &handle;
	l.in.num_names = 1;
	l.in.names = &lsa_name;
	l.in.sids = &sids;
	l.in.level = 1;
	l.in.count = &count;
	l.out.count = &count;
	l.out.sids = &sids;
	l.out.domains = &domains;

	status = dcerpc_lsa_LookupNames_r(b, tmp_ctx, &l);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx,
				"LookupNames of %s failed - %s\n",
				lsa_name.string,
				nt_errstr(status));
		talloc_free(tmp_ctx);
		return NULL;
	}

	if (domains->count == 0) {
		return NULL;
	}

	result = dom_sid_add_rid(mem_ctx,
				 domains->domains[0].sid,
				 l.out.sids->sids[0].rid);
	c.in.handle = &handle;
	c.out.handle = &handle;

	status = dcerpc_lsa_Close_r(b, tmp_ctx, &c);

	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx,
				"dcerpc_lsa_Close failed - %s\n",
				nt_errstr(status));
		talloc_free(tmp_ctx);
		return NULL;
	}

	if (!NT_STATUS_IS_OK(c.out.result)) {
		torture_comment(tctx,
				"dcerpc_lsa_Close failed - %s\n",
				nt_errstr(c.out.result));
		talloc_free(tmp_ctx);
		return NULL;
	}

	talloc_free(tmp_ctx);
	talloc_free(p2);

	torture_comment(tctx, "Get_user_sid finished\n");
	return result;
}

/*
 * Create a bkrp_encrypted_secret_vX structure
 * the version depends on the version parameter
 * the structure is returned as a blob.
 * The broken flag is to indicate if we want
 * to create a non conform to specification structre
 */
static DATA_BLOB *create_unencryptedsecret(TALLOC_CTX *mem_ctx,
					   bool broken,
					   int version)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	DATA_BLOB *blob = talloc_zero(mem_ctx, DATA_BLOB);
	enum ndr_err_code ndr_err;

	if (version == 2) {
		struct bkrp_encrypted_secret_v2 unenc_sec;

		ZERO_STRUCT(unenc_sec);
		unenc_sec.secret_len = sizeof(secret);
		unenc_sec.secret = discard_const_p(uint8_t, secret);
		generate_random_buffer(unenc_sec.payload_key,
				       sizeof(unenc_sec.payload_key));

		ndr_err = ndr_push_struct_blob(blob, blob, &unenc_sec,
				(ndr_push_flags_fn_t)ndr_push_bkrp_encrypted_secret_v2);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return NULL;
		}

		if (broken) {
			/* The magic value is correctly set by the NDR push
			 * but we want to test the behavior of the server
			 * if a differrent value is provided
			 */
			((uint8_t*)blob->data)[4] = 79; /* A great year !!! */
		}
	}

	if (version == 3) {
		struct bkrp_encrypted_secret_v3 unenc_sec;

		ZERO_STRUCT(unenc_sec);
		unenc_sec.secret_len = sizeof(secret);
		unenc_sec.secret = discard_const_p(uint8_t, secret);
		generate_random_buffer(unenc_sec.payload_key,
				       sizeof(unenc_sec.payload_key));

		ndr_err = ndr_push_struct_blob(blob, blob, &unenc_sec,
					(ndr_push_flags_fn_t)ndr_push_bkrp_encrypted_secret_v3);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return NULL;
		}

		if (broken) {
			/*
			 * The magic value is correctly set by the NDR push
			 * but we want to test the behavior of the server
			 * if a differrent value is provided
			 */
			((uint8_t*)blob->data)[4] = 79; /* A great year !!! */
		}
	}
	talloc_free(tmp_ctx);
	return blob;
}

/*
 * Create an access check structure, the format depends on the version parameter.
 * If broken is specified then we create a stucture that isn't conform to the 
 * specification.
 *
 * If the structure can't be created then NULL is returned.
 */
static DATA_BLOB *create_access_check(struct torture_context *tctx,
				      struct dcerpc_pipe *p,
				      TALLOC_CTX *mem_ctx,
				      const char *user,
				      bool broken,
				      uint32_t version)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	DATA_BLOB *blob = talloc_zero(mem_ctx, DATA_BLOB);
	enum ndr_err_code ndr_err;
	const struct dom_sid *sid = get_user_sid(tctx, tmp_ctx, user);

	if (sid == NULL) {
		return NULL;
	}

	if (version == 2) {
		struct bkrp_access_check_v2 access_struct;
		struct sha sctx;
		uint8_t nonce[32];

		ZERO_STRUCT(access_struct);
		generate_random_buffer(nonce, sizeof(nonce));
		access_struct.nonce_len = sizeof(nonce);
		access_struct.nonce = nonce;
		access_struct.sid = *sid;

		ndr_err = ndr_push_struct_blob(blob, blob, &access_struct,
				(ndr_push_flags_fn_t)ndr_push_bkrp_access_check_v2);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return NULL;
		}

		/*
		 * We pushed the whole structure including a null hash
		 * but the hash need to be calculated only up to the hash field
		 * so we reduce the size of what has to be calculated
		 */

		SHA1_Init(&sctx);
		SHA1_Update(&sctx, blob->data,
			    blob->length - sizeof(access_struct.hash));
		SHA1_Final(blob->data + blob->length - sizeof(access_struct.hash),
			   &sctx);

		/* Altering the SHA */
		if (broken) {
			blob->data[blob->length - 1]++;
		}
	}

	if (version == 3) {
		struct bkrp_access_check_v3 access_struct;
		struct hc_sha512state sctx;
		uint8_t nonce[32];

		ZERO_STRUCT(access_struct);
		generate_random_buffer(nonce, sizeof(nonce));
		access_struct.nonce_len = sizeof(nonce);
		access_struct.nonce = nonce;
		access_struct.sid = *sid;

		ndr_err = ndr_push_struct_blob(blob, blob, &access_struct,
				(ndr_push_flags_fn_t)ndr_push_bkrp_access_check_v3);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return NULL;
		}

		/*We pushed the whole structure including a null hash
		* but the hash need to be calculated only up to the hash field
		* so we reduce the size of what has to be calculated
		*/

		SHA512_Init(&sctx);
		SHA512_Update(&sctx, blob->data,
			      blob->length - sizeof(access_struct.hash));
		SHA512_Final(blob->data + blob->length - sizeof(access_struct.hash),
			     &sctx);

		/* Altering the SHA */
		if (broken) {
			blob->data[blob->length -1]++;
		}
	}
	talloc_free(tmp_ctx);
	return blob;
}


static DATA_BLOB *encrypt_blob(struct torture_context *tctx,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *key,
				    DATA_BLOB *iv,
				    DATA_BLOB *to_encrypt,
				    const AlgorithmIdentifier *alg)
{
	hx509_crypto crypto;
	hx509_context hctx;
	heim_octet_string ivos;
	heim_octet_string *encrypted;
	DATA_BLOB *blob = talloc_zero(mem_ctx, DATA_BLOB);
	int res;

	ivos.data = talloc_array(mem_ctx, uint8_t, iv->length);
	ivos.length = iv->length;
	memcpy(ivos.data, iv->data, iv->length);

	hx509_context_init(&hctx);
	res = hx509_crypto_init(hctx, NULL, &alg->algorithm, &crypto);
	if (res) {
		torture_comment(tctx,
				"error while doing the init of the crypto object\n");
		hx509_context_free(&hctx);
		return NULL;
	}
	res = hx509_crypto_set_key_data(crypto, key->data, key->length);
	if (res) {
		torture_comment(tctx,
				"error while setting the key of the crypto object\n");
		hx509_context_free(&hctx);
		return NULL;
	}

	hx509_crypto_set_padding(crypto, HX509_CRYPTO_PADDING_NONE);
	res = hx509_crypto_encrypt(crypto,
				   to_encrypt->data,
				   to_encrypt->length,
				   &ivos,
				   &encrypted);
	if (res) {
		torture_comment(tctx, "error while encrypting\n");
		hx509_crypto_destroy(crypto);
		hx509_context_free(&hctx);
		return NULL;
	}

	*blob = data_blob_talloc(blob, encrypted->data, encrypted->length);
	der_free_octet_string(encrypted);
	free(encrypted);
	hx509_crypto_destroy(crypto);
	hx509_context_free(&hctx);
	return blob;
}

/*
 * Certs used for this protocol have a GUID in the issuer_uniq_id field.
 * This function fetch it.
 */
static struct GUID *get_cert_guid(struct torture_context *tctx,
				  TALLOC_CTX *mem_ctx,
				  uint8_t *cert_data,
				  uint32_t cert_len)
{
	hx509_context hctx;
	hx509_cert cert;
	heim_bit_string subjectuniqid;
	DATA_BLOB data;
	int hret;
	uint32_t size;
	struct GUID *guid = talloc_zero(mem_ctx, struct GUID);
	NTSTATUS status;

	hx509_context_init(&hctx);

	hret = hx509_cert_init_data(hctx, cert_data, cert_len, &cert);
	if (hret) {
		torture_comment(tctx, "error while loading the cert\n");
		hx509_context_free(&hctx);
		return NULL;
	}
	hret = hx509_cert_get_issuer_unique_id(hctx, cert, &subjectuniqid);
	if (hret) {
		torture_comment(tctx, "error while getting the issuer_uniq_id\n");
		hx509_cert_free(cert);
		hx509_context_free(&hctx);
		return NULL;
	}

	/* The subjectuniqid is a bit string,
	 * which means that the real size has to be divided by 8
	 * to have the number of bytes
	 */
	hx509_cert_free(cert);
	hx509_context_free(&hctx);
	size = subjectuniqid.length / 8;
	data = data_blob_const(subjectuniqid.data, size);

	status = GUID_from_data_blob(&data, guid);
	der_free_bit_string(&subjectuniqid);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	return guid;
}

/*
 * Encrypt a blob with the private key of the certificate
 * passed as a parameter.
 */
static DATA_BLOB *encrypt_blob_pk(struct torture_context *tctx,
				  TALLOC_CTX *mem_ctx,
				  uint8_t *cert_data,
				  uint32_t cert_len,
				  DATA_BLOB *to_encrypt)
{
	hx509_context hctx;
	hx509_cert cert;
	heim_octet_string secretdata;
	heim_octet_string encrypted;
	heim_oid encryption_oid;
	DATA_BLOB *blob;
	int hret;

	hx509_context_init(&hctx);

	hret = hx509_cert_init_data(hctx, cert_data, cert_len, &cert);
	if (hret) {
		torture_comment(tctx, "error while loading the cert\n");
		hx509_context_free(&hctx);
		return NULL;
	}

	secretdata.data = to_encrypt->data;
	secretdata.length = to_encrypt->length;
	hret = hx509_cert_public_encrypt(hctx, &secretdata,
					  cert, &encryption_oid,
					  &encrypted);
	hx509_cert_free(cert);
	hx509_context_free(&hctx);
	if (hret) {
		torture_comment(tctx, "error while encrypting\n");
		return NULL;
	}

	blob = talloc_zero(mem_ctx, DATA_BLOB);
	if (blob == NULL) {
		der_free_oid(&encryption_oid);
		der_free_octet_string(&encrypted);
		return NULL;
	}

	*blob = data_blob_talloc(blob, encrypted.data, encrypted.length);
	der_free_octet_string(&encrypted);
	der_free_oid(&encryption_oid);
	if (blob->data == NULL) {
		return NULL;
	}

	return blob;
}


static struct bkrp_BackupKey *createRetreiveBackupKeyGUIDStruct(struct torture_context *tctx,
				struct dcerpc_pipe *p, int version, DATA_BLOB *out)
{
	struct dcerpc_binding *binding;
	struct bkrp_client_side_wrapped data;
	struct GUID *g = talloc(tctx, struct GUID);
	struct bkrp_BackupKey *r = talloc_zero(tctx, struct bkrp_BackupKey);
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	NTSTATUS status;

	if (r == NULL) {
		return NULL;
	}

	binding = dcerpc_binding_dup(tctx, p->binding);
	if (binding == NULL) {
		return NULL;
	}

	status = dcerpc_binding_set_flags(binding, DCERPC_SEAL|DCERPC_AUTH_SPNEGO, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	ZERO_STRUCT(data);
	status = GUID_from_string(BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, g);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	r->in.guidActionAgent = g;
	data.version = version;
	ndr_err = ndr_push_struct_blob(&blob, tctx, &data,
			(ndr_push_flags_fn_t)ndr_push_bkrp_client_side_wrapped);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NULL;
	}
	r->in.data_in = blob.data;
	r->in.data_in_len = blob.length;
	r->out.data_out = &out->data;
	r->out.data_out_len = talloc(r, uint32_t);
	return r;
}

static struct bkrp_BackupKey *createRestoreGUIDStruct(struct torture_context *tctx,
				struct dcerpc_pipe *p, int version, DATA_BLOB *out,
				bool norevert,
				bool broken_version,
				bool broken_user,
				bool broken_magic_secret,
				bool broken_magic_access,
				bool broken_hash_access,
				bool broken_cert_guid)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct bkrp_client_side_wrapped data;
	DATA_BLOB *xs;
	DATA_BLOB *sec;
	DATA_BLOB *enc_sec;
	DATA_BLOB *enc_xs;
	DATA_BLOB *blob2;
	DATA_BLOB enc_sec_reverted;
	DATA_BLOB des3_key;
	DATA_BLOB aes_key;
	DATA_BLOB iv;
	DATA_BLOB out_blob;
	struct GUID *guid, *g;
	int t;
	uint32_t size;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	const char *user;
	struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, version, &out_blob);
	if (r == NULL) {
		return NULL;
	}

	if (broken_user) {
		/* we take a fake user*/
		user = "guest";
	} else {
		user = cli_credentials_get_username(cmdline_credentials);
	}


	torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
					"Get GUID");
	torture_assert_werr_ok(tctx, r->out.result,
			       "Get GUID");

	/*
	 * We have to set it outside of the function createRetreiveBackupKeyGUIDStruct
	 * the len of the blob, this is due to the fact that they don't have the
	 * same size (one is 32bits the other 64bits)
	 */
	out_blob.length = *r->out.data_out_len;

	sec = create_unencryptedsecret(tctx, broken_magic_secret, version);
	if (sec == NULL) {
		return NULL;
	}

	xs = create_access_check(tctx, p, tctx, user, broken_hash_access, version);
	if (xs == NULL) {
		return NULL;
	}

	if (broken_magic_access){
		/* The start of the access_check structure contains the 
		 * GUID of the certificate
		 */
		xs->data[0]++;
	}

	enc_sec = encrypt_blob_pk(tctx, tctx, out_blob.data, out_blob.length, sec);
	if (!enc_sec) {
		return NULL;
	}
	enc_sec_reverted.data = talloc_array(tctx, uint8_t, enc_sec->length);
	if (enc_sec_reverted.data == NULL) {
		return NULL;
	}
	enc_sec_reverted.length = enc_sec->length;

	/*
	* We DO NOT revert the array on purpose it's in order to check that
	* when the server is not able to decrypt then it answer the correct error
	*/
	if (norevert) {
		for(t=0; t< enc_sec->length; t++) {
			enc_sec_reverted.data[t] = ((uint8_t*)enc_sec->data)[t];
		}
	} else {
		for(t=0; t< enc_sec->length; t++) {
			enc_sec_reverted.data[t] = ((uint8_t*)enc_sec->data)[enc_sec->length - t -1];
		}
	}

	size = sec->length;
	if (version ==2) {
		const AlgorithmIdentifier *alg = hx509_crypto_des_rsdi_ede3_cbc();
		iv.data = sec->data+(size - 8);
		iv.length = 8;

		des3_key.data = sec->data+(size - 32);
		des3_key.length = 24;

		enc_xs = encrypt_blob(tctx, tctx, &des3_key, &iv, xs, alg);
	}
	if (version == 3) {
		const AlgorithmIdentifier *alg = hx509_crypto_aes256_cbc();
		iv.data = sec->data+(size-16);
		iv.length = 16;

		aes_key.data = sec->data+(size-48);
		aes_key.length = 32;

		enc_xs = encrypt_blob(tctx, tctx, &aes_key, &iv, xs, alg);
	}

	if (!enc_xs) {
		return NULL;
	}

	/* To cope with the fact that heimdal do padding at the end for the moment */
	enc_xs->length = xs->length;

	guid = get_cert_guid(tctx, tctx, out_blob.data, out_blob.length);
	if (guid == NULL) {
		return NULL;
	}

	if (broken_version) {
		data.version = 1;
	} else {
		data.version = version;
	}

	data.guid = *guid;
	data.encrypted_secret = enc_sec_reverted.data;
	data.access_check = enc_xs->data;
	data.encrypted_secret_len = enc_sec->length;
	data.access_check_len = enc_xs->length;

	/* We want the blob to persist after this function so we don't
	 * allocate it in the stack
	 */
	blob2 = talloc(tctx, DATA_BLOB);
	if (blob2 == NULL) {
		return NULL;
	}

	ndr_err = ndr_push_struct_blob(blob2, tctx, &data,
			(ndr_push_flags_fn_t)ndr_push_bkrp_client_side_wrapped);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NULL;
	}

	if (broken_cert_guid) {
		blob2->data[12]++;
	}

	ZERO_STRUCT(*r);

	g = talloc(tctx, struct GUID);
	if (g == NULL) {
		return NULL;
	}

	status = GUID_from_string(BACKUPKEY_RESTORE_GUID, g);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	r->in.guidActionAgent = g;
	r->in.data_in = blob2->data;
	r->in.data_in_len = blob2->length;
	r->in.param = 0;
	r->out.data_out = &(out->data);
	r->out.data_out_len = talloc(r, uint32_t);
	return r;
}

/* Check that we are able to receive the certificate of the DCs
 * used for client wrap version of the backup key protocol
 */
static bool test_RetreiveBackupKeyGUID(struct torture_context *tctx,
					struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
				dcerpc_bkrp_BackupKey_r(b, tctx, r),
				"Get GUID");

		out_blob.length = *r->out.data_out_len;
		torture_assert_werr_equal(tctx,
						r->out.result,
						WERR_OK,
						"Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(tctx,
						dcerpc_bkrp_BackupKey_r(b, tctx, r),
						NT_STATUS_ACCESS_DENIED,
						"Get GUID");
	}
	return true;
}

/* Test to check the failure to recover a secret because the 
 * secret blob is not reversed
 */
static bool test_RestoreGUID_ko(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	enum ndr_err_code ndr_err;
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_client_side_unwrapped resp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 2, &out_blob,
					true, false, false, false, false, false, false);
		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct failed");
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		ndr_err = ndr_pull_struct_blob(&out_blob, tctx, &resp, (ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_unwrapped);
		torture_assert_int_equal(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), 0, "Unable to unmarshall bkrp_client_side_unwrapped");
		torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_PARAM, "Wrong error code");
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

static bool test_RestoreGUID_wrongversion(struct torture_context *tctx,
					  struct dcerpc_pipe *p)
{
	enum ndr_err_code ndr_err;
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_client_side_unwrapped resp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 2, &out_blob,
					false, true, false, false, false, false, false);
		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct failed");
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		ndr_err = ndr_pull_struct_blob(&out_blob, tctx, &resp, (ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_unwrapped);
		torture_assert_int_equal(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), 0, "Unable to unmarshall bkrp_client_side_unwrapped");
		torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_PARAM, "Wrong error code on wrong version");
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

static bool test_RestoreGUID_wronguser(struct torture_context *tctx,
				       struct dcerpc_pipe *p)
{
	enum ndr_err_code ndr_err;
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_client_side_unwrapped resp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 2, &out_blob,
					false, false, true, false, false, false, false);
		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct failed");
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		ndr_err = ndr_pull_struct_blob(&out_blob, tctx, &resp, (ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_unwrapped);
		torture_assert_int_equal(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), 0, "Unable to unmarshall bkrp_client_side_unwrapped");
		torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_ACCESS, "Restore GUID");
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

static bool test_RestoreGUID_v3(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	enum ndr_err_code ndr_err;
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_client_side_unwrapped resp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 3, &out_blob,
					false, false, false, false, false, false, false);
		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct failed");
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		ndr_err = ndr_pull_struct_blob(&out_blob, tctx, &resp, (ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_unwrapped);
		torture_assert_int_equal(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), 1, "Unable to unmarshall bkrp_client_side_unwrapped");
		torture_assert_werr_equal(tctx, r->out.result, WERR_OK, "Restore GUID");
		torture_assert_str_equal(tctx, (char*)resp.secret.data, secret, "Wrong secret");
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

static bool test_RestoreGUID(struct torture_context *tctx,
			     struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_client_side_unwrapped resp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 2, &out_blob,
					false, false, false, false, false, false, false);
		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct failed");
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		torture_assert_werr_equal(tctx, r->out.result, WERR_OK, "Restore GUID");
		torture_assert_ndr_err_equal(tctx,
					     ndr_pull_struct_blob(&out_blob, tctx, &resp,
								(ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_unwrapped),
					     NDR_ERR_SUCCESS,
					     "Unable to unmarshall bkrp_client_side_unwrapped");
		torture_assert_str_equal(tctx, (char*)resp.secret.data, secret, "Wrong secret");
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

static bool test_RestoreGUID_badmagiconsecret(struct torture_context *tctx,
					      struct dcerpc_pipe *p)
{
	enum ndr_err_code ndr_err;
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_client_side_unwrapped resp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 3, &out_blob,
					false, false, false, true, false, false, false);
		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct failed");
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		ndr_err = ndr_pull_struct_blob(&out_blob, tctx, &resp, (ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_unwrapped);
		torture_assert_int_equal(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), 0, "Unable to unmarshall bkrp_client_side_unwrapped");
		torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_DATA, "Wrong error code while providing bad magic in secret");
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

static bool test_RestoreGUID_emptyrequest(struct torture_context *tctx,
					  struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 3, &out_blob,
					false, false, false, true, false, false, true);

		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct failed");
		r->in.data_in = talloc(tctx, uint8_t);
		r->in.data_in_len = 0;
		r->in.param = 0;
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_PARAM, "Bad error code on wrong has in access check");
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

static bool test_RestoreGUID_badcertguid(struct torture_context *tctx,
					 struct dcerpc_pipe *p)
{
	enum ndr_err_code ndr_err;
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_client_side_unwrapped resp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 3, &out_blob,
					false, false, false, false, false, false, true);
		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct() failed");
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		ndr_err = ndr_pull_struct_blob(&out_blob, tctx, &resp, (ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_unwrapped);
		torture_assert_int_equal(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), 0, "Unable to unmarshall bkrp_client_side_unwrapped");

		/* 
		 * Windows 2012R2 has, presumably, a programming error
		 * returning an NTSTATUS code on this interface 
		 */
		if (W_ERROR_V(r->out.result) != NT_STATUS_V(NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_DATA, "Bad error code on wrong has in access check");
		}
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

static bool test_RestoreGUID_badmagicaccesscheck(struct torture_context *tctx,
						 struct dcerpc_pipe *p)
{
	enum ndr_err_code ndr_err;
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_client_side_unwrapped resp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 2, &out_blob,
					false, false, false, false, true, false, false);
		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct failed");
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		ndr_err = ndr_pull_struct_blob(&out_blob, tctx, &resp, (ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_unwrapped);
		torture_assert_int_equal(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), 0, "Unable to unmarshall bkrp_client_side_unwrapped");
		torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_DATA, "Bad error code on wrong has in access check");
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

static bool test_RestoreGUID_badhashaccesscheck(struct torture_context *tctx,
						struct dcerpc_pipe *p)
{
	enum ndr_err_code ndr_err;
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_client_side_unwrapped resp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		struct bkrp_BackupKey *r = createRestoreGUIDStruct(tctx, p, 2, &out_blob,
					false, false, false, false, false, true, false);
		torture_assert(tctx, r != NULL, "createRestoreGUIDStruct failed");
		torture_assert_ntstatus_ok(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r), "Restore GUID");
		out_blob.length = *r->out.data_out_len;
		ndr_err = ndr_pull_struct_blob(&out_blob, tctx, &resp, (ndr_pull_flags_fn_t)ndr_pull_bkrp_client_side_unwrapped);
		torture_assert_int_equal(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), 0, "Unable to unmarshall bkrp_client_side_unwrapped");
		torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_DATA, "Bad error code on wrong has in access check");
	} else {
		struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
		torture_assert_ntstatus_equal(tctx, dcerpc_bkrp_BackupKey_r(b, tctx, r),
			NT_STATUS_ACCESS_DENIED, "Get GUID");
	}
	return true;
}

/* 
 * Check that the RSA modulus in the certificate of the DCs has 2048 bits.
 */
static bool test_RetreiveBackupKeyGUID_2048bits(struct torture_context *tctx,
					struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	struct bkrp_BackupKey *r = createRetreiveBackupKeyGUIDStruct(tctx, p, 2, &out_blob);
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	hx509_context hctx;
	int hret;
	hx509_cert cert;
	SubjectPublicKeyInfo spki;
	RSA *rsa;
	int RSA_returned_bits;

	torture_assert(tctx, r != NULL, "createRetreiveBackupKeyGUIDStruct failed");
	
	hx509_context_init(&hctx);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		const unsigned char *spki_spk_data;
		torture_assert_ntstatus_ok(tctx,
				dcerpc_bkrp_BackupKey_r(b, tctx, r),
				"Get GUID");

		torture_assert_werr_ok(tctx, r->out.result,
				       "Get GUID");

		out_blob.length = *r->out.data_out_len;

		hret = hx509_cert_init_data(hctx, out_blob.data, out_blob.length, &cert);
		torture_assert_int_equal(tctx, hret, 0, "hx509_cert_init_data failed");

		hret = hx509_cert_get_SPKI(hctx, cert , &spki);
		torture_assert_int_equal(tctx, hret, 0, "hx509_cert_get_SPKI failed");

		/* We must take a copy, as d2i_RSAPublicKey *changes* the input parameter */
		spki_spk_data = spki.subjectPublicKey.data;
		rsa = d2i_RSAPublicKey(NULL, &spki_spk_data, spki.subjectPublicKey.length / 8);
		torture_assert_int_equal(tctx, rsa != NULL, 1, "d2i_RSAPublicKey failed");

		RSA_returned_bits = BN_num_bits(rsa->n);
		torture_assert_int_equal(tctx,
						RSA_returned_bits,
						2048,
						"RSA Key doesn't have 2048 bits");

		RSA_free(rsa);

		/* 
		 * Because we prevented spki from being changed above,
		 * we can now safely call this to free it 
		 */
		free_SubjectPublicKeyInfo(&spki);
		hx509_cert_free(cert);
		hx509_context_free(&hctx);

	} else {
		torture_assert_ntstatus_equal(tctx,
						dcerpc_bkrp_BackupKey_r(b, tctx, r),
						NT_STATUS_ACCESS_DENIED,
						"Get GUID");
	}
	return true;
}

static bool test_ServerWrap_encrypt_decrypt(struct torture_context *tctx,
					    struct dcerpc_pipe *p)
{
	struct bkrp_BackupKey r;
	struct GUID guid;
	DATA_BLOB plaintext = data_blob_const(secret, sizeof(secret));
	DATA_BLOB encrypted;
	uint32_t enclen;
	DATA_BLOB decrypted;
	uint32_t declen;
	struct dcerpc_binding_handle *b = p->binding_handle;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	ZERO_STRUCT(r);

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	/* Encrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_BACKUP_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = plaintext.data;
	r.in.data_in_len = plaintext.length;
	r.in.param = 0;
	r.out.data_out = &encrypted.data;
	r.out.data_out_len = &enclen;
	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					   "encrypt");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					      NT_STATUS_ACCESS_DENIED,
					      "encrypt");
		return true;
	}
	torture_assert_werr_ok(tctx,
			       r.out.result,
			       "encrypt");
	encrypted.length = *r.out.data_out_len;
	
	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = encrypted.data;
	r.in.data_in_len = encrypted.length;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");
	torture_assert_werr_ok(tctx,
			       r.out.result,
			       "decrypt");
	decrypted.length = *r.out.data_out_len;

	/* Compare */
	torture_assert_data_blob_equal(tctx, plaintext, decrypted, "Decrypt failed");

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID_WIN2K, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = encrypted.data;
	r.in.data_in_len = encrypted.length;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");
	torture_assert_werr_ok(tctx,
			       r.out.result,
			       "decrypt");
	decrypted.length = *r.out.data_out_len;

	/* Compare */
	torture_assert_data_blob_equal(tctx, plaintext, decrypted, "Decrypt failed");
	return true;
}

static bool test_ServerWrap_decrypt_wrong_keyGUID(struct torture_context *tctx,
						  struct dcerpc_pipe *p)
{
	struct bkrp_BackupKey r;
	struct GUID guid;
	DATA_BLOB plaintext = data_blob_const(secret, sizeof(secret));
	DATA_BLOB encrypted;
	uint32_t enclen;
	DATA_BLOB decrypted;
	uint32_t declen;
	struct dcerpc_binding_handle *b = p->binding_handle;
	enum ndr_err_code ndr_err;
	struct bkrp_server_side_wrapped server_side_wrapped;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	ZERO_STRUCT(r);

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	/* Encrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_BACKUP_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = plaintext.data;
	r.in.data_in_len = plaintext.length;
	r.in.param = 0;
	r.out.data_out = &encrypted.data;
	r.out.data_out_len = &enclen;
	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					   "encrypt");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					      NT_STATUS_ACCESS_DENIED,
					      "encrypt");
		return true;
	}
	torture_assert_werr_ok(tctx,
			       r.out.result,
			       "encrypt");
	encrypted.length = *r.out.data_out_len;

	ndr_err = ndr_pull_struct_blob(&encrypted, tctx, &server_side_wrapped,
				       (ndr_pull_flags_fn_t)ndr_pull_bkrp_server_side_wrapped);
	torture_assert_ndr_err_equal(tctx, ndr_err, NDR_ERR_SUCCESS, "pull of server_side_wrapped");

	/* Change the GUID */
	server_side_wrapped.guid = GUID_random();

	ndr_err = ndr_push_struct_blob(&encrypted, tctx, &server_side_wrapped,
				       (ndr_push_flags_fn_t)ndr_push_bkrp_server_side_wrapped);
	torture_assert_ndr_err_equal(tctx, ndr_err, NDR_ERR_SUCCESS, "push of server_side_wrapped");
	
	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = encrypted.data;
	r.in.data_in_len = encrypted.length;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");
	torture_assert_werr_equal(tctx,
				  r.out.result,
				  WERR_INVALID_DATA,
				  "decrypt should fail with WERR_INVALID_DATA");

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID_WIN2K, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = encrypted.data;
	r.in.data_in_len = encrypted.length;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");
	torture_assert_werr_equal(tctx,
				  r.out.result,
				  WERR_INVALID_DATA,
				  "decrypt should fail with WERR_INVALID_DATA");

	return true;
}

static bool test_ServerWrap_decrypt_empty_request(struct torture_context *tctx,
						 struct dcerpc_pipe *p)
{
	struct bkrp_BackupKey r;
	struct GUID guid;
	DATA_BLOB decrypted;
	uint32_t declen;
	struct dcerpc_binding_handle *b = p->binding_handle;
	uint8_t short_request[4] = { 1, 0, 0, 0 };
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	ZERO_STRUCT(r);

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = short_request;
	r.in.data_in_len = 0;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					   "encrypt");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					      NT_STATUS_ACCESS_DENIED,
					      "encrypt");
		return true;
	}
	torture_assert_werr_equal(tctx,
				  r.out.result,
				  WERR_INVALID_PARAM,
				  "decrypt should fail with WERR_INVALID_PARAM");

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID_WIN2K, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = short_request;
	r.in.data_in_len = 0;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");
	torture_assert_werr_equal(tctx,
				  r.out.result,
				  WERR_INVALID_PARAM,
				  "decrypt should fail with WERR_INVALID_PARAM");

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = NULL;
	r.in.data_in_len = 0;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_equal(tctx,
				      dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				      NT_STATUS_INVALID_PARAMETER_MIX,
				      "decrypt");

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID_WIN2K, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = NULL;
	r.in.data_in_len = 0;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_equal(tctx,
				      dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				      NT_STATUS_INVALID_PARAMETER_MIX,
				      "decrypt");

	return true;
}


static bool test_ServerWrap_decrypt_short_request(struct torture_context *tctx,
						 struct dcerpc_pipe *p)
{
	struct bkrp_BackupKey r;
	struct GUID guid;
	DATA_BLOB decrypted;
	uint32_t declen;
	struct dcerpc_binding_handle *b = p->binding_handle;
	uint8_t short_request[4] = { 1, 0, 0, 0 };
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	ZERO_STRUCT(r);

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = short_request;
	r.in.data_in_len = 4;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					   "encrypt");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					      NT_STATUS_ACCESS_DENIED,
					      "encrypt");
		return true;
	}
	torture_assert_werr_equal(tctx,
				  r.out.result,
				  WERR_INVALID_PARAM,
				  "decrypt should fail with WERR_INVALID_PARM");

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID_WIN2K, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = short_request;
	r.in.data_in_len = 4;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");
	torture_assert_werr_equal(tctx,
				  r.out.result,
				  WERR_INVALID_PARAM,
				  "decrypt should fail with WERR_INVALID_PARAM");

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = short_request;
	r.in.data_in_len = 1;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");
	torture_assert_werr_equal(tctx,
				  r.out.result,
				  WERR_INVALID_PARAM,
				  "decrypt should fail with WERR_INVALID_PARAM");

	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID_WIN2K, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = short_request;
	r.in.data_in_len = 1;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");
	torture_assert_werr_equal(tctx,
				  r.out.result,
				  WERR_INVALID_PARAM,
				  "decrypt should fail with WERR_INVALID_PARAM");

	return true;
}

static bool test_ServerWrap_encrypt_decrypt_manual(struct torture_context *tctx,
						   struct bkrp_server_side_wrapped *server_side_wrapped,
						   enum test_wrong wrong)
{
        struct dcerpc_pipe *lsa_p;
	struct dcerpc_binding_handle *lsa_b;
	struct lsa_OpenSecret r_secret;
	struct lsa_QuerySecret r_query_secret;
	struct policy_handle *handle, sec_handle;
	struct bkrp_BackupKey r;
	struct GUID preferred_key_guid;
	DATA_BLOB plaintext = data_blob_const(secret, sizeof(secret));
	DATA_BLOB preferred_key, preferred_key_clear, session_key,
		decrypt_key, decrypt_key_clear, encrypted_blob, symkey_blob,
		sid_blob;
	struct bkrp_dc_serverwrap_key server_key;
	struct lsa_DATA_BUF_PTR bufp1;
	char *key_guid_string;
	struct bkrp_rc4encryptedpayload rc4payload;
	struct dom_sid *caller_sid;
	uint8_t symkey[20]; /* SHA-1 hash len */
	uint8_t mackey[20]; /* SHA-1 hash len */
	uint8_t mac[20]; /* SHA-1 hash len */
	unsigned int hash_len;
	HMAC_CTX ctx;
	ZERO_STRUCT(r);
	ZERO_STRUCT(r_secret);
	ZERO_STRUCT(r_query_secret);

	/* Now read BCKUPKEY_P and prove we can do a matching decrypt and encrypt */
	
	torture_assert_ntstatus_ok(tctx,
				   torture_rpc_connection(tctx, &lsa_p, &ndr_table_lsarpc),
				   "Opening LSA pipe");
	lsa_b = lsa_p->binding_handle;

	torture_assert(tctx, test_lsa_OpenPolicy2(lsa_b, tctx, &handle), "OpenPolicy failed");
	r_secret.in.name.string = "G$BCKUPKEY_P";
	
	r_secret.in.handle = handle;
	r_secret.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r_secret.out.sec_handle = &sec_handle;
	
	torture_comment(tctx, "Testing OpenSecret\n");
	
	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenSecret_r(lsa_b, tctx, &r_secret),
				   "OpenSecret failed");
	torture_assert_ntstatus_ok(tctx, r_secret.out.result,
				   "OpenSecret failed");
	
	r_query_secret.in.sec_handle = &sec_handle;
	r_query_secret.in.new_val = &bufp1;
	bufp1.buf = NULL;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QuerySecret_r(lsa_b, tctx, &r_query_secret),
		"QuerySecret failed");
	torture_assert_ntstatus_ok(tctx, r_query_secret.out.result,
				   "QuerySecret failed");
	
	
	preferred_key.data = r_query_secret.out.new_val->buf->data;
	preferred_key.length = r_query_secret.out.new_val->buf->size;
	torture_assert_ntstatus_ok(tctx, dcerpc_fetch_session_key(lsa_p, &session_key),
				   "dcerpc_fetch_session_key failed");
	
	torture_assert_ntstatus_ok(tctx,
				   sess_decrypt_blob(tctx,
						     &preferred_key, &session_key, &preferred_key_clear),
				   "sess_decrypt_blob failed");
	
	torture_assert_ntstatus_ok(tctx, GUID_from_ndr_blob(&preferred_key_clear, &preferred_key_guid),
				   "GUID parse failed");
	
	torture_assert_guid_equal(tctx, server_side_wrapped->guid,
				  preferred_key_guid,
				  "GUID didn't match value pointed at by G$BCKUPKEY_P");

	/* And read BCKUPKEY_<guid> and get the actual key */
	
	key_guid_string = GUID_string(tctx, &server_side_wrapped->guid);
	r_secret.in.name.string = talloc_asprintf(tctx, "G$BCKUPKEY_%s", key_guid_string);
	
	r_secret.in.handle = handle;
	r_secret.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r_secret.out.sec_handle = &sec_handle;
	
	torture_comment(tctx, "Testing OpenSecret\n");
	
	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenSecret_r(lsa_b, tctx, &r_secret),
				   "OpenSecret failed");
	torture_assert_ntstatus_ok(tctx, r_secret.out.result,
				   "OpenSecret failed");
	
	r_query_secret.in.sec_handle = &sec_handle;
	r_query_secret.in.new_val = &bufp1;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QuerySecret_r(lsa_b, tctx, &r_query_secret),
				   "QuerySecret failed");
	torture_assert_ntstatus_ok(tctx, r_query_secret.out.result,
				   "QuerySecret failed");
	
	
	decrypt_key.data = r_query_secret.out.new_val->buf->data;
	decrypt_key.length = r_query_secret.out.new_val->buf->size;
	
	torture_assert_ntstatus_ok(tctx,
				   sess_decrypt_blob(tctx,
						     &decrypt_key, &session_key, &decrypt_key_clear),
				   "sess_decrypt_blob failed");
	
	torture_assert_ndr_err_equal(tctx, ndr_pull_struct_blob(&decrypt_key_clear, tctx, &server_key,
								(ndr_pull_flags_fn_t)ndr_pull_bkrp_dc_serverwrap_key),
				     NDR_ERR_SUCCESS, "Failed to parse server_key");

	torture_assert_int_equal(tctx, server_key.magic, 1, "Failed to correctly decrypt server key");

	/*
	 * This is *not* the leading 64 bytes, as indicated in MS-BKRP 3.1.4.1.1
	 * BACKUPKEY_BACKUP_GUID, it really is the whole key 
	 */
	HMAC(EVP_sha1(), server_key.key, sizeof(server_key.key),
	     server_side_wrapped->r2, sizeof(server_side_wrapped->r2),
	     symkey, &hash_len);
	
	/* rc4 decrypt sid and secret using sym key */
	symkey_blob = data_blob_const(symkey, sizeof(symkey));
	
	encrypted_blob = data_blob_talloc(tctx, server_side_wrapped->rc4encryptedpayload,
					  server_side_wrapped->ciphertext_length);
	
	arcfour_crypt_blob(encrypted_blob.data, encrypted_blob.length, &symkey_blob);

	torture_assert_ndr_err_equal(tctx, ndr_pull_struct_blob(&encrypted_blob, tctx, &rc4payload,
				       (ndr_pull_flags_fn_t)ndr_pull_bkrp_rc4encryptedpayload),
				     NDR_ERR_SUCCESS, "Failed to parse rc4encryptedpayload");

	torture_assert_int_equal(tctx, rc4payload.secret_data.length,
				 server_side_wrapped->payload_length,
				 "length of decrypted payload not the length declared in surrounding structure");

	/*
	 * This is *not* the leading 64 bytes, as indicated in MS-BKRP 3.1.4.1.1
	 * BACKUPKEY_BACKUP_GUID, it really is the whole key 
	 */
	HMAC(EVP_sha1(), server_key.key, sizeof(server_key.key),
	     rc4payload.r3, sizeof(rc4payload.r3),
	     mackey, &hash_len);
	
	torture_assert_ndr_err_equal(tctx, ndr_push_struct_blob(&sid_blob, tctx, &rc4payload.sid,
								(ndr_push_flags_fn_t)ndr_push_dom_sid),
				     NDR_ERR_SUCCESS, "unable to push SID");

	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, mackey, hash_len, EVP_sha1(), NULL);
	/* SID field */
	HMAC_Update(&ctx, sid_blob.data, sid_blob.length);
	/* Secret field */
	HMAC_Update(&ctx, rc4payload.secret_data.data, rc4payload.secret_data.length);
	HMAC_Final(&ctx, mac, &hash_len);
	HMAC_CTX_cleanup(&ctx);

	torture_assert_mem_equal(tctx, mac, rc4payload.mac, sizeof(mac), "mac not correct");
	torture_assert_int_equal(tctx, rc4payload.secret_data.length,
				 plaintext.length, "decrypted data is not correct length");
	torture_assert_mem_equal(tctx, rc4payload.secret_data.data,
				 plaintext.data, plaintext.length,
				 "decrypted data is not correct");

	/* Not strictly correct all the time, but good enough for this test */
	caller_sid = get_user_sid(tctx, tctx, cli_credentials_get_username(cmdline_credentials));

	torture_assert_sid_equal(tctx, &rc4payload.sid, caller_sid, "Secret saved with wrong SID");

	
	/* RE-encrypt */

	if (wrong == WRONG_SID) {
		rc4payload.sid.sub_auths[rc4payload.sid.num_auths - 1] = DOMAIN_RID_KRBTGT;
	}

	dump_data_pw("mackey: \n", mackey, sizeof(mackey));

	torture_assert_ndr_err_equal(tctx,
				     ndr_push_struct_blob(&sid_blob, tctx, &rc4payload.sid,
							  (ndr_push_flags_fn_t)ndr_push_dom_sid),
				     NDR_ERR_SUCCESS,
				     "push of sid failed");

	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, mackey, 20, EVP_sha1(), NULL);
	/* SID field */
	HMAC_Update(&ctx, sid_blob.data, sid_blob.length);
	/* Secret field */
	HMAC_Update(&ctx, rc4payload.secret_data.data, rc4payload.secret_data.length);
	HMAC_Final(&ctx, rc4payload.mac, &hash_len);
	HMAC_CTX_cleanup(&ctx);

	dump_data_pw("rc4payload.mac: \n", rc4payload.mac, sizeof(rc4payload.mac));
	
	torture_assert_ndr_err_equal(tctx,
				     ndr_push_struct_blob(&encrypted_blob, tctx, &rc4payload,
							  (ndr_push_flags_fn_t)ndr_push_bkrp_rc4encryptedpayload),
				     NDR_ERR_SUCCESS,
				     "push of rc4payload failed");

	if (wrong == WRONG_KEY) {
		symkey_blob.data[0] = 78;
		symkey_blob.data[1] = 78;
		symkey_blob.data[2] = 78;
	}
	
	/* rc4 encrypt sid and secret using sym key */
	arcfour_crypt_blob(encrypted_blob.data, encrypted_blob.length, &symkey_blob);

	/* re-create server wrap structure */

	torture_assert_int_equal(tctx, encrypted_blob.length,
				 server_side_wrapped->ciphertext_length,
				 "expected encrypted length not to change");
	if (wrong == RIGHT_KEY) {
		torture_assert_mem_equal(tctx, server_side_wrapped->rc4encryptedpayload,
					 encrypted_blob.data,
					 encrypted_blob.length,
					 "expected encrypted data not to change");
	}
						 
	server_side_wrapped->payload_length = rc4payload.secret_data.length;
	server_side_wrapped->ciphertext_length = encrypted_blob.length;
	server_side_wrapped->rc4encryptedpayload = encrypted_blob.data;

	return true;
}


static bool test_ServerWrap_decrypt_wrong_stuff(struct torture_context *tctx,
						struct dcerpc_pipe *p,
						enum test_wrong wrong)
{
	struct bkrp_BackupKey r;
	struct GUID guid;
	DATA_BLOB plaintext = data_blob_const(secret, sizeof(secret));
	DATA_BLOB encrypted;
	uint32_t enclen;
	DATA_BLOB decrypted;
	uint32_t declen;
	struct dcerpc_binding_handle *b = p->binding_handle;
	enum ndr_err_code ndr_err;
	struct bkrp_server_side_wrapped server_side_wrapped;
	bool repush = false;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	ZERO_STRUCT(r);

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	/* Encrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_BACKUP_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = plaintext.data;
	r.in.data_in_len = plaintext.length;
	r.in.param = 0;
	r.out.data_out = &encrypted.data;
	r.out.data_out_len = &enclen;
	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					   "encrypt");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_bkrp_BackupKey_r(b, tctx, &r),
					      NT_STATUS_ACCESS_DENIED,
					      "encrypt");
		return true;
	}
	torture_assert_werr_ok(tctx,
			       r.out.result,
			       "encrypt");
	encrypted.length = *r.out.data_out_len;

	ndr_err = ndr_pull_struct_blob(&encrypted, tctx, &server_side_wrapped,
				       (ndr_pull_flags_fn_t)ndr_pull_bkrp_server_side_wrapped);
	torture_assert_ndr_err_equal(tctx, ndr_err, NDR_ERR_SUCCESS, "pull of server_side_wrapped");

	torture_assert_int_equal(tctx, server_side_wrapped.payload_length, plaintext.length,
				 "wrong payload length");

	switch (wrong) {
	case WRONG_MAGIC:
		/* Change the magic.  Forced by our NDR layer, so do it raw */
		SIVAL(encrypted.data, 0, 78);  /* valid values are 1-3 */
		break;
	case WRONG_R2:
		server_side_wrapped.r2[0] = 78;
		server_side_wrapped.r2[1] = 78;
		server_side_wrapped.r2[3] = 78;
		repush = true;
		break;
	case WRONG_PAYLOAD_LENGTH:
		server_side_wrapped.payload_length = UINT32_MAX - 8;
		repush = true;
		break;
	case WRONG_CIPHERTEXT_LENGTH:
		/* 
		 * Change the ciphertext len.  We can't push this if
		 * we have it wrong, so do it raw
		 */
		SIVAL(encrypted.data, 8, UINT32_MAX - 8);  /* valid values are 1-3 */
		break;
	case SHORT_PAYLOAD_LENGTH:
		server_side_wrapped.payload_length = server_side_wrapped.payload_length - 8;
		repush = true;
		break;
	case SHORT_CIPHERTEXT_LENGTH:
		/* 
		 * Change the ciphertext len.  We can't push this if
		 * we have it wrong, so do it raw
		 */
		SIVAL(encrypted.data, 8, server_side_wrapped.ciphertext_length - 8);  /* valid values are 1-3 */
		break;
	case ZERO_PAYLOAD_LENGTH:
		server_side_wrapped.payload_length = 0;
		repush = true;
		break;
	case ZERO_CIPHERTEXT_LENGTH:
		/* 
		 * Change the ciphertext len.  We can't push this if
		 * we have it wrong, so do it raw
		 */
		SIVAL(encrypted.data, 8, 0);  /* valid values are 1-3 */
		break;

	case RIGHT_KEY:
	case WRONG_KEY:
	case WRONG_SID:
		torture_assert(tctx,
			       test_ServerWrap_encrypt_decrypt_manual(tctx, &server_side_wrapped, wrong),
			       "test_ServerWrap_encrypt_decrypt_manual failed");
		repush = true;
		break;
	}

	if (repush) {
		ndr_err = ndr_push_struct_blob(&encrypted, tctx, &server_side_wrapped,
					       (ndr_push_flags_fn_t)ndr_push_bkrp_server_side_wrapped);
		torture_assert_ndr_err_equal(tctx, ndr_err, NDR_ERR_SUCCESS, "push of server_side_wrapped");
	}
	
	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = encrypted.data;
	r.in.data_in_len = encrypted.length;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");

	if ((wrong == WRONG_R2 || wrong == WRONG_KEY)
	    && W_ERROR_EQUAL(r.out.result, WERR_INVALID_SID)) {
		torture_assert_werr_equal(tctx,
					  r.out.result,
					  WERR_INVALID_SID,
					  "decrypt should fail with WERR_INVALID_SID or WERR_INVALID_PARAM");
	} else if (wrong == RIGHT_KEY) {
		torture_assert_werr_equal(tctx,
					  r.out.result,
					  WERR_OK,
					  "decrypt should succeed!");
	} else if (wrong == WRONG_SID) {
		torture_assert_werr_equal(tctx,
					  r.out.result,
					  WERR_INVALID_ACCESS,
					  "decrypt should fail with WERR_INVALID_ACCESS");
	} else {
		torture_assert_werr_equal(tctx,
					  r.out.result,
					  WERR_INVALID_PARAM,
					  "decrypt should fail with WERR_INVALID_PARAM");
	}
	
	/* Decrypt */
	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(BACKUPKEY_RESTORE_GUID_WIN2K, &guid),
				   "obtain GUID");

	r.in.guidActionAgent = &guid;
	r.in.data_in = encrypted.data;
	r.in.data_in_len = encrypted.length;
	r.in.param = 0;
	r.out.data_out = &(decrypted.data);
	r.out.data_out_len = &declen;
	torture_assert_ntstatus_ok(tctx,
				   dcerpc_bkrp_BackupKey_r(b, tctx, &r),
				   "decrypt");

	if ((wrong == WRONG_R2 || wrong == WRONG_KEY)
	    && W_ERROR_EQUAL(r.out.result, WERR_INVALID_SID)) {
		torture_assert_werr_equal(tctx,
					  r.out.result,
					  WERR_INVALID_SID,
					  "decrypt should fail with WERR_INVALID_SID or WERR_INVALID_PARAM");
	} else if (wrong == RIGHT_KEY) {
		torture_assert_werr_equal(tctx,
					  r.out.result,
					  WERR_OK,
					  "decrypt should succeed!");
	} else if (wrong == WRONG_SID) {
		torture_assert_werr_equal(tctx,
					  r.out.result,
					  WERR_INVALID_ACCESS,
					  "decrypt should fail with WERR_INVALID_ACCESS");
	} else {
		torture_assert_werr_equal(tctx,
					  r.out.result,
					  WERR_INVALID_PARAM,
					  "decrypt should fail with WERR_INVALID_PARAM");
	}
	
	return true;
}

static bool test_ServerWrap_decrypt_wrong_magic(struct torture_context *tctx,
						struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, WRONG_MAGIC);
}

static bool test_ServerWrap_decrypt_wrong_r2(struct torture_context *tctx,
						struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, WRONG_R2);
}

static bool test_ServerWrap_decrypt_wrong_payload_length(struct torture_context *tctx,
							 struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, WRONG_PAYLOAD_LENGTH);
}

static bool test_ServerWrap_decrypt_short_payload_length(struct torture_context *tctx,
							 struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, SHORT_PAYLOAD_LENGTH);
}

static bool test_ServerWrap_decrypt_zero_payload_length(struct torture_context *tctx,
							 struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, ZERO_PAYLOAD_LENGTH);
}

static bool test_ServerWrap_decrypt_wrong_ciphertext_length(struct torture_context *tctx,
							 struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, WRONG_CIPHERTEXT_LENGTH);
}

static bool test_ServerWrap_decrypt_short_ciphertext_length(struct torture_context *tctx,
							 struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, SHORT_CIPHERTEXT_LENGTH);
}

static bool test_ServerWrap_decrypt_zero_ciphertext_length(struct torture_context *tctx,
							   struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, ZERO_CIPHERTEXT_LENGTH);
}

static bool test_ServerWrap_encrypt_decrypt_remote_key(struct torture_context *tctx,
						       struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, RIGHT_KEY);
}

static bool test_ServerWrap_encrypt_decrypt_wrong_key(struct torture_context *tctx,
						       struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, WRONG_KEY);
}

static bool test_ServerWrap_encrypt_decrypt_wrong_sid(struct torture_context *tctx,
						      struct dcerpc_pipe *p)
{
	return test_ServerWrap_decrypt_wrong_stuff(tctx, p, WRONG_SID);
}

struct torture_suite *torture_rpc_backupkey(TALLOC_CTX *mem_ctx)
{
	struct torture_rpc_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "backupkey");

	tcase = torture_suite_add_rpc_iface_tcase(suite, "backupkey",
						  &ndr_table_backupkey);

	torture_rpc_tcase_add_test(tcase, "retreive_backup_key_guid",
				   test_RetreiveBackupKeyGUID);

	torture_rpc_tcase_add_test(tcase, "restore_guid",
				   test_RestoreGUID);

	torture_rpc_tcase_add_test(tcase, "restore_guid version 3",
				   test_RestoreGUID_v3);

/* We double the test in order to be sure that we don't mess stuff (ie. freeing static stuff) */

	torture_rpc_tcase_add_test(tcase, "restore_guid_2nd",
				   test_RestoreGUID);

	torture_rpc_tcase_add_test(tcase, "unable_to_decrypt_secret",
				   test_RestoreGUID_ko);

	torture_rpc_tcase_add_test(tcase, "wrong_user_restore_guid",
				   test_RestoreGUID_wronguser);

	torture_rpc_tcase_add_test(tcase, "wrong_version_restore_guid",
				   test_RestoreGUID_wrongversion);

	torture_rpc_tcase_add_test(tcase, "bad_magic_on_secret_restore_guid",
				   test_RestoreGUID_badmagiconsecret);

	torture_rpc_tcase_add_test(tcase, "bad_hash_on_secret_restore_guid",
				   test_RestoreGUID_badhashaccesscheck);

	torture_rpc_tcase_add_test(tcase, "bad_magic_on_accesscheck_restore_guid",
				   test_RestoreGUID_badmagicaccesscheck);

	torture_rpc_tcase_add_test(tcase, "bad_cert_guid_restore_guid",
				   test_RestoreGUID_badcertguid);

	torture_rpc_tcase_add_test(tcase, "empty_request_restore_guid",
				   test_RestoreGUID_emptyrequest);

	torture_rpc_tcase_add_test(tcase, "retreive_backup_key_guid_2048_bits",
				   test_RetreiveBackupKeyGUID_2048bits);

	torture_rpc_tcase_add_test(tcase, "server_wrap_encrypt_decrypt",
				   test_ServerWrap_encrypt_decrypt);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_wrong_keyGUID",
				   test_ServerWrap_decrypt_wrong_keyGUID);

	torture_rpc_tcase_add_test(tcase, "server_wrap_empty_request",
				   test_ServerWrap_decrypt_empty_request);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_short_request",
				   test_ServerWrap_decrypt_short_request);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_wrong_magic",
				   test_ServerWrap_decrypt_wrong_magic);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_wrong_r2",
				   test_ServerWrap_decrypt_wrong_r2);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_wrong_payload_length",
				   test_ServerWrap_decrypt_wrong_payload_length);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_short_payload_length",
				   test_ServerWrap_decrypt_short_payload_length);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_zero_payload_length",
				   test_ServerWrap_decrypt_zero_payload_length);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_wrong_ciphertext_length",
				   test_ServerWrap_decrypt_wrong_ciphertext_length);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_short_ciphertext_length",
				   test_ServerWrap_decrypt_short_ciphertext_length);

	torture_rpc_tcase_add_test(tcase, "server_wrap_decrypt_zero_ciphertext_length",
				   test_ServerWrap_decrypt_zero_ciphertext_length);

	torture_rpc_tcase_add_test(tcase, "server_wrap_encrypt_decrypt_remote_key", 
				   test_ServerWrap_encrypt_decrypt_remote_key);
	
	torture_rpc_tcase_add_test(tcase, "server_wrap_encrypt_decrypt_wrong_key",
				   test_ServerWrap_encrypt_decrypt_wrong_key);

	torture_rpc_tcase_add_test(tcase, "server_wrap_encrypt_decrypt_wrong_sid",
				   test_ServerWrap_encrypt_decrypt_wrong_sid);

	return suite;
}
