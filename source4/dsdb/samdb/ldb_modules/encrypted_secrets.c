/*
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

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

/*
 * Encrypt the samba secret attributes on disk.  This is intended to
 * mitigate the inadvertent disclosure of the sam.ldb file, and to mitigate
 * memory read attacks.
 *
 * Currently the key file is stored in the same directory as sam.ldb but
 * this could be changed at a later date to use an HSM or similar mechanism
 * to protect the key.
 *
 * Data is encrypted with AES 128 GCM. The encryption uses gnutls where
 * available and if it supports AES 128 GCM AEAD modes, otherwise the
 * samba internal implementation is used.
 *
 */

#include "includes.h"
#include <ldb_module.h>

#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

#ifdef TEST_ENCRYPTED_SECRETS
	#define BUILD_WITH_SAMBA_AES_GCM
	#ifdef HAVE_GNUTLS_AEAD
		#define BUILD_WITH_GNUTLS_AEAD
	#endif
#else
	#ifdef HAVE_GNUTLS_AEAD
		#define BUILD_WITH_GNUTLS_AEAD
	#else
		#define BUILD_WITH_SAMBA_AES_GCM
	#endif
#endif

#ifdef BUILD_WITH_GNUTLS_AEAD
	#include <gnutls/gnutls.h>
	#include <gnutls/crypto.h>
#endif /* BUILD_WITH_GNUTLS_AEAD */

#ifdef BUILD_WITH_SAMBA_AES_GCM
	#include "lib/crypto/crypto.h"
#endif /* BUILD_WITH_SAMBA_AES_GCM */

static const char * const secret_attributes[] = {DSDB_SECRET_ATTRIBUTES};
static const size_t num_secret_attributes = ARRAY_SIZE(secret_attributes);

#define SECRET_ATTRIBUTE_VERSION 1
#define SECRET_ENCRYPTION_ALGORITHM ENC_SECRET_AES_128_AEAD
#define NUMBER_OF_KEYS 1
#define SECRETS_KEY_FILE "encrypted_secrets.key"


struct es_data {
	/*
	 * Should secret attributes be encrypted and decrypted?
	 */
	bool encrypt_secrets;
	/*
	 * Encryption keys for secret attributes
	 */
	DATA_BLOB keys[NUMBER_OF_KEYS];
#ifdef BUILD_WITH_GNUTLS_AEAD
	/*
	 * The gnutls algorithm used to encrypt attributes
	 */
	int encryption_algorithm;
#endif /* BUILD_WITH_GNUTLS_AEAD */
};

/*
 * @brief Get the key used to encrypt and decrypt secret attributes on disk.
 *
 * @param data the private context data for this module.
 *
 * @return A data blob containing the key.
 *         This should be treated as read only.
 */
static const DATA_BLOB get_key(const struct es_data *data) {

	return data->keys[0];
}

/*
 * @brief Get the directory containing the key files.
 *
 * @param ctx talloc memory context that will own the return value
 * @param ldb ldb context, to allow logging
 *
 * @return zero terminated string, the directory containing the key file
 *         allocated on ctx.
 *
 */
static const char* get_key_directory(TALLOC_CTX *ctx, struct ldb_context *ldb)
{

	const char *sam_ldb_path = NULL;
	const char *private_dir  = NULL;
	char *p = NULL;


	/*
	 * Work out where *our* key file is. It must be in
	 * the same directory as sam.ldb
	 */
	sam_ldb_path = ldb_get_opaque(ldb, "ldb_url");
	if (sam_ldb_path == NULL) {
		ldb_set_errstring(ldb, "Unable to get ldb_url\n");
		return NULL;
	}

	if (strncmp("tdb://", sam_ldb_path, 6) == 0) {
		sam_ldb_path += 6;
	}
	private_dir = talloc_strdup(ctx, sam_ldb_path);
	if (private_dir == NULL) {
		ldb_set_errstring(ldb,
				  "Out of memory building encrypted "
				  "secrets key\n");
		return NULL;
	}

	p = strrchr(private_dir, '/');
	if (p != NULL) {
		*p = '\0';
	} else {
		private_dir = talloc_strdup(ctx, ".");
	}

	return private_dir;
}

/*
 * @brief log details of an error that set errno
 *
 * @param ldb ldb context, to allow logging.
 * @param err the value of errno.
 * @param desc extra text to help describe the error.
 *
 */
static void log_error(struct ldb_context *ldb, int err, const char *desc)
{
	char buf[1024];
	int e = strerror_r(err, buf, sizeof(buf));
	if (e != 0) {
		strlcpy(buf, "Unknown error", sizeof(buf)-1);
	}
	ldb_asprintf_errstring(ldb, "Error (%d) %s - %s\n", err, buf, desc);
}

/*
 * @brief Load the keys into the encrypted secrets module context.
 *
 * @param module the current ldb module
 * @param data the private data for the current module
 *
 * Currently the keys are stored in a binary file in the same directory
 * as the database.
 *
 * @return an LDB result code.
 *
 */
static int load_keys(struct ldb_module *module, struct es_data *data)
{

	const char *key_dir  = NULL;
	const char *key_path = NULL;

	struct ldb_context *ldb = NULL;
	FILE *fp = NULL;
	const int key_size = 16;
	int read;
	DATA_BLOB key = data_blob_null;

	TALLOC_CTX *frame = talloc_stackframe();

	ldb = ldb_module_get_ctx(module);
	key_dir = get_key_directory(frame, ldb);
	if (key_dir == NULL) {
		TALLOC_FREE(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	key_path = talloc_asprintf(frame, "%s/%s", key_dir, SECRETS_KEY_FILE);
	if (key_path == NULL) {
		TALLOC_FREE(frame);
		return ldb_oom(ldb);
	}


	key = data_blob_talloc_zero(module, key_size);
	key.length = key_size;

	fp = fopen(key_path, "rb");
	if (fp == NULL) {
		TALLOC_FREE(frame);
		data_blob_free(&key);
		if (errno == ENOENT) {
			ldb_debug(ldb,
				  LDB_DEBUG_WARNING,
				  "No encrypted secrets key file. "
				  "Secret attributes will not be encrypted or "
				  "decrypted\n");
			data->encrypt_secrets = false;
			return LDB_SUCCESS;
		} else {
			log_error(ldb,
				  errno,
				  "Opening encrypted_secrets key file\n");
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	read = fread(key.data, 1, key.length, fp);
	fclose(fp);
	if (read == 0) {
		TALLOC_FREE(frame);
		ldb_debug(ldb,
			  LDB_DEBUG_WARNING,
			  "Zero length encrypted secrets key file. "
			  "Secret attributes will not be encrypted or "
			  "decrypted\n");
		data->encrypt_secrets = false;
		return LDB_SUCCESS;
	}
	if (read != key.length) {
		TALLOC_FREE(frame);
		if (errno) {
			log_error(ldb,
				  errno,
				  "Reading encrypted_secrets key file\n");
		} else {
			ldb_debug(ldb,
				  LDB_DEBUG_ERROR,
				  "Invalid encrypted_secrets key file, "
				  "only %d bytes read should be %d bytes\n",
				  read,
				  key_size);
		}
		return LDB_ERR_OPERATIONS_ERROR;
	}

	data->keys[0] = key;
	data->encrypt_secrets = true;
#ifdef BUILD_WITH_GNUTLS_AEAD
	data->encryption_algorithm = GNUTLS_CIPHER_AES_128_GCM;
#endif
	TALLOC_FREE(frame);

	return LDB_SUCCESS;

}

/*
 * @brief should this element be encrypted.
 *
 * @param el the element to examine
 *
 * @return true if the element should be encrypted,
 *         false otherwise.
 */
static bool should_encrypt(const struct ldb_message_element *el)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(secret_attributes); i++) {
		if (strcasecmp(secret_attributes[i], el->name) == 0) {
			return true;
		}
	}
	return false;
}

/*
 * @brief Round a size up to a multiple of the encryption cipher block size.
 *
 * @param block_size The cipher block size
 * @param size The size to round
 *
 * @return Size rounded up to the nearest multiple of block_size
 */
#ifdef BUILD_WITH_GNUTLS_AEAD
static size_t round_to_block_size(size_t block_size, size_t size)
{
	if ((size % block_size) == 0) {
		return size;
	} else {
		return ((int)(size/block_size) + 1) * block_size;
	}
}
#endif /* BUILD_WITH_GNUTLS_AEAD */

/*
 * @brief Create an new EncryptedSecret owned by the supplied talloc context.
 *
 * Create a new encrypted secret and initialise the header.
 *
 * @param ldb ldb context, to allow logging.
 * @param ctx The talloc memory context that will own the new EncryptedSecret
 *
 * @return pointer to the new encrypted secret, or NULL if there was an error
 */
static struct EncryptedSecret *makeEncryptedSecret(struct ldb_context *ldb,
						   TALLOC_CTX *ctx)
{
	struct EncryptedSecret *es = NULL;

	es = talloc_zero_size(ctx, sizeof(struct EncryptedSecret));
	if (es == NULL) {
		ldb_set_errstring(ldb,
				  "Out of memory, allocating "
				   "struct EncryptedSecret\n");
		return NULL;
	}
	es->header.magic     = ENCRYPTED_SECRET_MAGIC_VALUE;
	es->header.version   = SECRET_ATTRIBUTE_VERSION;
	es->header.algorithm = SECRET_ENCRYPTION_ALGORITHM;
	es->header.flags     = 0;
	return es;
}

/*
 * @brief Allocate and populate a data blob with a PlaintextSecret structure.
 *
 * Allocate a new data blob and populate it with a serialised PlaintextSecret,
 * containing the ldb_val
 *
 * @param ctx The talloc memory context that will own the allocated memory.
 * @param ldb ldb context, to allow logging.
 * @param val The ldb value to serialise.
 *
 * @return The populated data blob or data_blob_null if there was an error.
 */
static DATA_BLOB makePlainText(TALLOC_CTX *ctx,
			       struct ldb_context *ldb,
			       const struct ldb_val val)
{
	struct PlaintextSecret ps = { .cleartext = data_blob_null};
	DATA_BLOB pt = data_blob_null;
	int rc;

	ps.cleartext.length = val.length;
	ps.cleartext.data   = val.data;

	rc = ndr_push_struct_blob(&pt,
				  ctx,
				  &ps,
				  (ndr_push_flags_fn_t)
					ndr_push_PlaintextSecret);
	if (!NDR_ERR_CODE_IS_SUCCESS(rc)) {
		ldb_set_errstring(ldb,
				  "Unable to ndr push PlaintextSecret\n");
		return data_blob_null;
	}
	return pt;
}

#ifdef BUILD_WITH_SAMBA_AES_GCM
/*
 * @brief Encrypt an ldb value using an aead algorithm.
 *
 * This function uses the samba internal implementation to perform the encryption. However
 * the encrypted data and tag are stored in a manner compatible with gnutls,
 * so the gnutls aead functions can be used to decrypt and verify the data.
 *
 * @param err  Pointer to an error code, set to:
 *             LDB_SUCESS               If the value was successfully encrypted
 *             LDB_ERR_OPERATIONS_ERROR If there was an error.
 *
 * @param ctx  Talloc memory context the will own the memory allocated
 * @param ldb  ldb context, to allow logging.
 * @param val  The ldb value to encrypt, not altered or freed
 * @param data The context data for this module.
 *
 * @return The encrypted ldb_val, or data_blob_null if there was an error.
 */
static struct ldb_val samba_encrypt_aead(int *err,
					 TALLOC_CTX *ctx,
					 struct ldb_context *ldb,
					 const struct ldb_val val,
					 const struct es_data *data)
{
	struct aes_gcm_128_context cctx;
	struct EncryptedSecret *es = NULL;
	DATA_BLOB pt = data_blob_null;
	struct ldb_val enc = data_blob_null;
	DATA_BLOB key_blob = data_blob_null;
	int rc;
	TALLOC_CTX *frame = talloc_stackframe();

	es = makeEncryptedSecret(ldb, frame);
	if (es == NULL) {
		goto error_exit;
	}

	pt = makePlainText(frame, ldb, val);
	if (pt.length == 0) {
		goto error_exit;
	}

	/*
	 * Set the encryption key
	 */
	key_blob = get_key(data);
	if (key_blob.length != AES_BLOCK_SIZE) {
		ldb_asprintf_errstring(ldb,
				       "Invalid EncryptedSecrets key size, "
				       "expected %u bytes and is %zu bytes\n",
				       AES_BLOCK_SIZE,
				       key_blob.length);
		goto error_exit;
	}

	/*
	 * Set the initialisation vector
	 */
	{
		uint8_t *iv = talloc_zero_size(frame, AES_GCM_128_IV_SIZE);
		if (iv == NULL) {
			ldb_set_errstring(ldb,
					  "Out of memory allocating iv\n");
			goto error_exit;
		}

		generate_random_buffer(iv, AES_GCM_128_IV_SIZE);

		es->iv.length = AES_GCM_128_IV_SIZE;
		es->iv.data   = iv;
	}

	/*
	 * Encrypt the value, and append the GCM digest to the encrypted
	 * data so that it can be decrypted and validated by the
	 * gnutls aead decryption routines.
	 */
	{
		uint8_t *ct = talloc_zero_size(frame, pt.length + AES_BLOCK_SIZE);
		if (ct == NULL) {
			ldb_oom(ldb);
			goto error_exit;
		}

		memcpy(ct, pt.data, pt.length);
		es->encrypted.length = pt.length + AES_BLOCK_SIZE;
		es->encrypted.data   = ct;
	}

	aes_gcm_128_init(&cctx, key_blob.data, es->iv.data);
	aes_gcm_128_updateA(&cctx,
		    (uint8_t *)&es->header,
		    sizeof(struct EncryptedSecretHeader));
	aes_gcm_128_crypt(&cctx, es->encrypted.data, pt.length);
	aes_gcm_128_updateC(&cctx, es->encrypted.data, pt.length);
	aes_gcm_128_digest(&cctx, &es->encrypted.data[pt.length]);

	rc = ndr_push_struct_blob(&enc,
				  ctx,
				  es,
				  (ndr_push_flags_fn_t)
					ndr_push_EncryptedSecret);
	if (!NDR_ERR_CODE_IS_SUCCESS(rc)) {
		ldb_set_errstring(ldb,
				  "Unable to ndr push EncryptedSecret\n");
		goto error_exit;
	}
	TALLOC_FREE(frame);
	return enc;

error_exit:
	*err = LDB_ERR_OPERATIONS_ERROR;
	TALLOC_FREE(frame);
	return data_blob_null;
}

/*
 * @brief Decrypt data encrypted using an aead algorithm.
 *
 * Decrypt the data in ed and insert it into ev. The data was encrypted
 * with the samba aes gcm implementation.
 *
 * @param err  Pointer to an error code, set to:
 *             LDB_SUCESS               If the value was successfully decrypted
 *             LDB_ERR_OPERATIONS_ERROR If there was an error.
 *
 * @param ctx  Talloc memory context that will own the memory allocated
 * @param ldb  ldb context, to allow logging.
 * @param ev   The value to be updated with the decrypted data.
 * @param ed   The data to decrypt.
 * @param data The context data for this module.
 *
 * @return ev is updated with the unencrypted data.
 */
static void samba_decrypt_aead(int *err,
			       TALLOC_CTX *ctx,
			       struct ldb_context *ldb,
			       struct EncryptedSecret *es,
			       struct PlaintextSecret *ps,
			       const struct es_data *data)
{
	struct aes_gcm_128_context cctx;
	DATA_BLOB pt = data_blob_null;
	DATA_BLOB key_blob = data_blob_null;
	uint8_t sig[AES_BLOCK_SIZE] = {0, };
	int rc;
	int cmp;
	TALLOC_CTX *frame = talloc_stackframe();

	/*
	 * Set the encryption key
	 */
	key_blob = get_key(data);
	if (key_blob.length != AES_BLOCK_SIZE) {
		ldb_asprintf_errstring(ldb,
				       "Invalid EncryptedSecrets key size, "
				       "expected %u bytes and is %zu bytes\n",
				       AES_BLOCK_SIZE,
				       key_blob.length);
		goto error_exit;
	}

	if (es->iv.length < AES_GCM_128_IV_SIZE) {
		ldb_asprintf_errstring(ldb,
				       "Invalid EncryptedSecrets iv size, "
				       "expected %u bytes and is %zu bytes\n",
				       AES_GCM_128_IV_SIZE,
				       es->iv.length);
		goto error_exit;
	}

	if (es->encrypted.length < AES_BLOCK_SIZE) {
		ldb_asprintf_errstring(ldb,
				       "Invalid EncryptedData size, "
				       "expected %u bytes and is %zu bytes\n",
				       AES_BLOCK_SIZE,
				       es->encrypted.length);
		goto error_exit;
	}

	pt.length = es->encrypted.length - AES_BLOCK_SIZE;
	pt.data   = talloc_zero_size(ctx, pt.length);
	if (pt.data == NULL) {
		ldb_set_errstring(ldb,
			          "Out of memory allocating space for "
				  "plain text\n");
		goto error_exit;
	}
	memcpy(pt.data, es->encrypted.data, pt.length);

	aes_gcm_128_init(&cctx, key_blob.data, es->iv.data);
	aes_gcm_128_updateA(&cctx,
		    (uint8_t *)&es->header,
		    sizeof(struct EncryptedSecretHeader));
	aes_gcm_128_updateC(&cctx, pt.data, pt.length);
	aes_gcm_128_crypt(&cctx, pt.data, pt.length);
	aes_gcm_128_digest(&cctx, sig);

	/*
	 * Check the authentication tag
	 */
	cmp = memcmp(&es->encrypted.data[pt.length], sig, AES_BLOCK_SIZE);
	if (cmp != 0) {
		ldb_set_errstring(ldb,
				  "Tag does not match, "
				  "data corrupted or altered\n");
		goto error_exit;
	}

	rc = ndr_pull_struct_blob(&pt,
				  ctx,
				  ps,
				  (ndr_pull_flags_fn_t)
					ndr_pull_PlaintextSecret);
	if(!NDR_ERR_CODE_IS_SUCCESS(rc)) {
		ldb_asprintf_errstring(ldb,
				       "Error(%d)  unpacking decrypted data, "
				       "data possibly corrupted or altered\n",
				       rc);
		goto error_exit;
	}
	TALLOC_FREE(frame);
	return;

error_exit:
	*err = LDB_ERR_OPERATIONS_ERROR;
	TALLOC_FREE(frame);
	return;
}
#endif /* BUILD_WITH_SAMBA_AES_GCM */

#ifdef BUILD_WITH_GNUTLS_AEAD

/*
 * Helper function converts a data blob to a gnutls_datum_t.
 * Note that this does not copy the data.
 *      So the returned value should be treated as read only.
 *      And that changes to the length of the underlying DATA_BLOB
 *      will not be reflected in the returned object.
 *
 */
static const gnutls_datum_t convert_from_data_blob(DATA_BLOB blob) {

	const gnutls_datum_t datum = {
		.size = blob.length,
		.data = blob.data,
	};
	return datum;
}

/*
 * @brief Get the gnutls algorithm needed to decrypt the EncryptedSecret
 *
 * @param ldb ldb context, to allow logging.
 * @param es  the encrypted secret
 *
 * @return The gnutls algoritm number, or 0 if there is no match.
 *
 */
static int gnutls_get_algorithm(struct ldb_context *ldb,
				struct EncryptedSecret *es) {

	switch (es->header.algorithm) {
	case ENC_SECRET_AES_128_AEAD:
		return GNUTLS_CIPHER_AES_128_GCM;
	default:
		ldb_asprintf_errstring(ldb,
				       "Unsupported encryption algorithm %d\n",
				       es->header.algorithm);
		return 0;
	}
}

/*
 *
 * @param err  Pointer to an error code, set to:
 *             LDB_SUCESS               If the value was successfully encrypted
 *             LDB_ERR_OPERATIONS_ERROR If there was an error.
 *
 * @param ctx  Talloc memory context the will own the memory allocated
 * @param ldb  ldb context, to allow logging.
 * @param val  The ldb value to encrypt, not altered or freed
 * @param data The context data for this module.
 *
 * @return The encrypted ldb_val, or data_blob_null if there was an error.
 */
static struct ldb_val gnutls_encrypt_aead(int *err,
					  TALLOC_CTX *ctx,
					  struct ldb_context *ldb,
					  const struct ldb_val val,
					  const struct es_data *data)
{
	struct EncryptedSecret *es = NULL;
	struct ldb_val enc = data_blob_null;
	DATA_BLOB pt = data_blob_null;
	gnutls_aead_cipher_hd_t cipher_hnd;
	int rc;

	TALLOC_CTX *frame = talloc_stackframe();

	es = makeEncryptedSecret(ldb, frame);
	if (es == NULL) {
		goto error_exit;
	}

	pt = makePlainText(frame, ldb, val);
	if (pt.length == 0) {
		goto error_exit;
	}

	/*
	 * Set the encryption key and initialize the encryption handle.
	 */
	{
		const size_t key_size = gnutls_cipher_get_key_size(
			data->encryption_algorithm);
		gnutls_datum_t cipher_key;
		DATA_BLOB key_blob = get_key(data);

		if (key_blob.length != key_size) {
			ldb_asprintf_errstring(ldb,
					       "Invalid EncryptedSecrets key "
					       "size, expected %zu bytes and "
					       "it is %zu bytes\n",
					       key_size,
					       key_blob.length);
			goto error_exit;
		}
		cipher_key = convert_from_data_blob(key_blob);

		rc = gnutls_aead_cipher_init(&cipher_hnd,
					     data->encryption_algorithm,
					     &cipher_key);
		if (rc !=0) {
			ldb_asprintf_errstring(ldb,
					       "gnutls_aead_cipher_init failed "
					       "%s - %s\n",
					       gnutls_strerror_name(rc),
					       gnutls_strerror(rc));
			goto error_exit;
		}

	}

	/*
	 * Set the initialisation vector
	 */
	{
		unsigned iv_size = gnutls_cipher_get_iv_size(
			data->encryption_algorithm);
		uint8_t *iv;

		iv = talloc_zero_size(frame, iv_size);
		if (iv == NULL) {
			ldb_set_errstring(ldb,
					  "Out of memory allocating IV\n");
			goto error_exit_handle;
		}

		rc = gnutls_rnd(GNUTLS_RND_NONCE, iv, iv_size);
		if (rc !=0) {
			ldb_asprintf_errstring(ldb,
					       "gnutls_rnd failed %s - %s\n",
					       gnutls_strerror_name(rc),
					       gnutls_strerror(rc));
			goto error_exit_handle;
		}
		es->iv.length = iv_size;
		es->iv.data   = iv;
	}

	/*
	 * Encrypt the value.
	 */
	{
		const unsigned block_size = gnutls_cipher_get_block_size(
			data->encryption_algorithm);
		const unsigned tag_size = gnutls_cipher_get_tag_size(
			data->encryption_algorithm);
		const size_t ed_size = round_to_block_size(
			block_size,
			sizeof(struct PlaintextSecret) + val.length);
		const size_t en_size = ed_size + tag_size;
		uint8_t *ct = talloc_zero_size(frame, en_size);
		size_t el = en_size;

		if (ct == NULL) {
			ldb_set_errstring(ldb,
					  "Out of memory allocation cipher "
					  "text\n");
			goto error_exit_handle;
		}

		rc = gnutls_aead_cipher_encrypt(
			cipher_hnd,
			es->iv.data,
			es->iv.length,
			&es->header,
			sizeof(struct EncryptedSecretHeader),
			tag_size,
			pt.data,
			pt.length,
			ct,
			&el);
		if (rc !=0) {
			ldb_asprintf_errstring(ldb,
					       "gnutls_aead_cipher_encrypt '"
					       "failed %s - %s\n",
					       gnutls_strerror_name(rc),
					       gnutls_strerror(rc));
			*err = LDB_ERR_OPERATIONS_ERROR;
			return data_blob_null;
		}
		es->encrypted.length = el;
		es->encrypted.data   = ct;
		gnutls_aead_cipher_deinit(cipher_hnd);
	}

	rc = ndr_push_struct_blob(&enc,
				  ctx,
				  es,
				  (ndr_push_flags_fn_t)
					ndr_push_EncryptedSecret);
	if (!NDR_ERR_CODE_IS_SUCCESS(rc)) {
		ldb_set_errstring(ldb,
				  "Unable to ndr push EncryptedSecret\n");
		goto error_exit;
	}
	TALLOC_FREE(frame);
	return enc;

error_exit_handle:
	gnutls_aead_cipher_deinit(cipher_hnd);
error_exit:
	*err = LDB_ERR_OPERATIONS_ERROR;
	TALLOC_FREE(frame);
	return data_blob_null;
}

/*
 * @brief Decrypt data encrypted using an aead algorithm.
 *
 * Decrypt the data in ed and insert it into ev. The data was encrypted
 * with one of the gnutls aead compatable algorithms.
 *
 * @param err  Pointer to an error code, set to:
 *             LDB_SUCESS               If the value was successfully decrypted
 *             LDB_ERR_OPERATIONS_ERROR If there was an error.
 *
 * @param ctx  The talloc context that will own the PlaintextSecret
 * @param ldb  ldb context, to allow logging.
 * @param ev   The value to be updated with the decrypted data.
 * @param ed   The data to decrypt.
 * @param data The context data for this module.
 *
 * @return ev is updated with the unencrypted data.
 */
static void gnutls_decrypt_aead(int *err,
				TALLOC_CTX *ctx,
				struct ldb_context *ldb,
				struct EncryptedSecret *es,
				struct PlaintextSecret *ps,
				const struct es_data *data)
{

	gnutls_aead_cipher_hd_t cipher_hnd;
	DATA_BLOB pt = data_blob_null;
	const unsigned tag_size =
		gnutls_cipher_get_tag_size(es->header.algorithm);
	int rc;

	/*
	 * Get the encryption key and initialise the encryption handle
	 */
	{
		gnutls_datum_t cipher_key;
		DATA_BLOB key_blob;
		const int algorithm = gnutls_get_algorithm(ldb, es);
		const size_t key_size = gnutls_cipher_get_key_size(algorithm);
		key_blob   = get_key(data);

		if (algorithm == 0) {
			goto error_exit;
		}

		if (key_blob.length != key_size) {
			ldb_asprintf_errstring(ldb,
					       "Invalid EncryptedSecrets key "
					       "size, expected %zu bytes and "
					       "it is %zu bytes\n",
					       key_size,
					       key_blob.length);
			goto error_exit;
		}
		cipher_key = convert_from_data_blob(key_blob);

		rc = gnutls_aead_cipher_init(
			&cipher_hnd,
			algorithm,
			&cipher_key);
		if (rc != 0) {
			ldb_asprintf_errstring(ldb,
					       "gnutls_aead_cipher_init failed "
					       "%s - %s\n",
					       gnutls_strerror_name(rc),
					       gnutls_strerror(rc));
			goto error_exit;
		}
	}

	/*
	 * Decrypt and validate the encrypted value
	 */

	pt.length = es->encrypted.length;
	pt.data = talloc_zero_size(ctx, es->encrypted.length);

	if (pt.data == NULL) {
		ldb_set_errstring(ldb,
				  "Out of memory allocating plain text\n");
		goto error_exit_handle;
	}

	rc = gnutls_aead_cipher_decrypt(cipher_hnd,
					es->iv.data,
					es->iv.length,
					&es->header,
					sizeof(struct EncryptedSecretHeader),
					tag_size,
					es->encrypted.data,
					es->encrypted.length,
					pt.data,
					&pt.length);
	if (rc != 0) {
		/*
		 * Typically this will indicate that the data has been
		 * corrupted i.e. the tag comparison has failed.
		 * At the moment gnutls does not provide a separate
		 * error code to indicate this
		 */
		ldb_asprintf_errstring(ldb,
				       "gnutls_aead_cipher_decrypt failed "
				       "%s - %s. Data possibly corrupted or "
				       "altered\n",
				       gnutls_strerror_name(rc),
				       gnutls_strerror(rc));
		goto error_exit_handle;
	}
	gnutls_aead_cipher_deinit(cipher_hnd);

	rc = ndr_pull_struct_blob(&pt,
				  ctx,
				  ps,
				  (ndr_pull_flags_fn_t)
					ndr_pull_PlaintextSecret);
	if(!NDR_ERR_CODE_IS_SUCCESS(rc)) {
		ldb_asprintf_errstring(ldb,
				       "Error(%d) unpacking decrypted data, "
				       "data possibly corrupted or altered\n",
				       rc);
		goto error_exit;
	}
	return;

error_exit_handle:
	gnutls_aead_cipher_deinit(cipher_hnd);
error_exit:
	*err = LDB_ERR_OPERATIONS_ERROR;
	return;
}
#endif /* BUILD_WITH_GNUTLS_AEAD */

/*
 * @brief Encrypt an attribute value using the default encryption algorithm.
 *
 * Returns an encrypted copy of the value, the original value is left intact.
 * The original content of val is encrypted and wrapped in an encrypted_value
 * structure.
 *
 * @param err  Pointer to an error code, set to:
 *             LDB_SUCESS               If the value was successfully encrypted
 *             LDB_ERR_OPERATIONS_ERROR If there was an error.
 *
 * @param ctx  Talloc memory context the will own the memory allocated
 * @param ldb  ldb context, to allow logging.
 * @param val  The ldb value to encrypt, not altered or freed
 * @param data The context data for this module.
 *
 * @return The encrypted ldb_val, or data_blob_null if there was an error.
 */
static struct ldb_val encrypt_value(int *err,
				    TALLOC_CTX *ctx,
				    struct ldb_context *ldb,
				    const struct ldb_val val,
				    const struct es_data *data)
{
#ifdef BUILD_WITH_GNUTLS_AEAD
	return gnutls_encrypt_aead(err, ctx, ldb, val, data);
#elif defined BUILD_WITH_SAMBA_AES_GCM
	return samba_encrypt_aead(err, ctx, ldb, val, data);
#endif
}

/*
 * @brief Encrypt all the values on an ldb_message_element
 *
 * Returns a copy of the original attribute with all values encrypted
 * by encrypt_value(), the original attribute is left intact.
 *
 * @param err  Pointer to an error code, set to:
 *             LDB_SUCESS               If the value was successfully encrypted
 *             LDB_ERR_OPERATIONS_ERROR If there was an error.
 *
 * @param ctx  Talloc memory context the will own the memory allocated
 *             for the new ldb_message_element.
 * @param ldb  ldb context, to allow logging.
 * @param el   The ldb_message_elemen to encrypt, not altered or freed
 * @param data The context data for this module.
 *
 * @return Pointer encrypted lsb_message_element, will be NULL if there was
 *         an error.
 */
static struct ldb_message_element *encrypt_element(
	int *err,
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	const struct ldb_message_element *el,
	const struct es_data *data)
{
	struct ldb_message_element* enc;
	int i;

	enc = talloc_zero(ctx, struct ldb_message_element);
	if (enc == NULL) {
		ldb_set_errstring(ldb,
				  "Out of memory, allocating ldb_message_"
				  "element\n");
		*err = LDB_ERR_OPERATIONS_ERROR;
		return NULL;
	}

	enc->flags	= el->flags;
	enc->num_values	= el->num_values;
	enc->values	= talloc_array(enc, struct ldb_val, enc->num_values);
	if (enc->values == NULL) {
		TALLOC_FREE(enc);
		ldb_set_errstring(ldb,
				  "Out of memory, allocating values array\n");
		*err = LDB_ERR_OPERATIONS_ERROR;
		return NULL;
	}

	enc->name = talloc_strdup(enc, el->name);
	if (enc->name == NULL) {
		TALLOC_FREE(enc);
		ldb_set_errstring(ldb,
				  "Out of memory, copying element name\n");
		*err = LDB_ERR_OPERATIONS_ERROR;
		return NULL;
	}

	for (i = 0; i < el->num_values; i++) {
		enc->values[i] =
			encrypt_value(
				err,
				enc->values,
				ldb,
				el->values[i],
				data);
		if (*err != LDB_SUCCESS) {
			TALLOC_FREE(enc);
			return NULL;
		}
	}
	return enc;
}

/*
 * @brief Encrypt all the secret attributes on an ldb_message
 *
 * Encrypt all the secret attributes on an ldb_message. Any secret
 * attributes are removed from message and encrypted copies of the
 * attributes added.  In the event of an error the contents of the
 * message will be inconsistent.
 *
 * @param err Pointer to an error code, set to:
 *            LDB_SUCESS               If the value was successfully encrypted
 *            LDB_ERR_OPERATIONS_ERROR If there was an error.
 * @param ldb ldb context, to allow logging.
 * @param msg The ldb_message to have it's secret attributes encrypted.
 *
 * @param data The context data for this module.
 */
static const struct ldb_message *encrypt_secret_attributes(
	int *err,
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	const struct ldb_message *msg,
	const struct es_data *data)
{

	struct ldb_message *encrypted_msg = NULL;

	int i;

	if (ldb_dn_is_special(msg->dn)) {
		return NULL;
	}

	for (i = 0; i < msg->num_elements; i++) {

		const struct ldb_message_element *el = &msg->elements[i];
		if (should_encrypt(el)) {
			struct ldb_message_element* enc = NULL;
			if (encrypted_msg == NULL) {
				encrypted_msg = ldb_msg_copy_shallow(ctx, msg);
				encrypted_msg->dn = msg->dn;
			}
			enc = encrypt_element(err,
					      msg->elements,
					      ldb,
					      el,
					      data);
			if (*err != LDB_SUCCESS) {
				return NULL;
			}
			encrypted_msg->elements[i] = *enc;
		}
	}
	return encrypted_msg;
}

/*
 * @brief Check the encrypted secret header to ensure it's valid
 *
 * Check an Encrypted secret and ensure it's header is valid.
 * A header is assumed to be valid if it:
 *  - it starts with the MAGIC_VALUE
 *  - The version number is valid
 *  - The algorithm is valid
 *
 *  @param val The EncryptedSecret to check.
 *
 *  @return true if the header is valid, false otherwise.
 *
 */
static bool check_header(struct EncryptedSecret *es)
{
	struct EncryptedSecretHeader *eh;

	eh = &es->header;
	if (eh->magic != ENCRYPTED_SECRET_MAGIC_VALUE) {
		/*
		 * Does not start with the magic value so not
		 * an encrypted_value
		 */
		return false;
	}

	if (eh->version > SECRET_ATTRIBUTE_VERSION) {
		/*
		 * Invalid version, so not an encrypted value
		 */
		return false;
	}

	if (eh->algorithm != ENC_SECRET_AES_128_AEAD) {
		/*
		 * Invalid algorithm, so not an encrypted value
		 */
		return false;
	}
	/*
	 * Length looks ok, starts with magic value, and the version and
	 * algorithm are valid
	 */
	return true;
}
/*
 * @brief Decrypt an attribute value.
 *
 * Returns a decrypted copy of the value, the original value is left intact.
 *
 * @param err  Pointer to an error code, set to:
 *             LDB_SUCESS               If the value was successfully decrypted
 *             LDB_ERR_OPERATIONS_ERROR If there was an error.
 *
 * @param ctx  Talloc memory context the will own the memory allocated
 * @param ldb  ldb context, to allow logging.
 * @param val  The ldb value to decrypt, not altered or freed
 * @param data The context data for this module.
 *
 * @return The decrypted ldb_val, or data_blob_null if there was an error.
 */
static struct ldb_val decrypt_value(int *err,
				    TALLOC_CTX *ctx,
				    struct ldb_context *ldb,
				    const struct ldb_val val,
				    const struct es_data *data)
{

	struct ldb_val dec;

	struct EncryptedSecret es;
	struct PlaintextSecret ps = { data_blob_null};
	int rc;
	TALLOC_CTX *frame = talloc_stackframe();

	rc = ndr_pull_struct_blob(&val,
				  frame,
				  &es,
				  (ndr_pull_flags_fn_t)
					ndr_pull_EncryptedSecret);
	if(!NDR_ERR_CODE_IS_SUCCESS(rc)) {
		ldb_asprintf_errstring(ldb,
				       "Error(%d)  unpacking encrypted secret, "
				       "data possibly corrupted or altered\n",
				       rc);
		*err = LDB_ERR_OPERATIONS_ERROR;
		TALLOC_FREE(frame);
		return data_blob_null;
	}
	if (!check_header(&es)) {
		/*
		* Header is invalid so can't be an encrypted value
		*/
		ldb_set_errstring(ldb, "Invalid EncryptedSecrets header\n");
		*err = LDB_ERR_OPERATIONS_ERROR;
		return data_blob_null;
	}
#ifdef BUILD_WITH_GNUTLS_AEAD
	gnutls_decrypt_aead(err, frame, ldb, &es, &ps, data);
#elif defined BUILD_WITH_SAMBA_AES_GCM
	samba_decrypt_aead(err, frame, ldb, &es, &ps, data);
#endif

	if (*err != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		return data_blob_null;
	}

	dec = data_blob_talloc(ctx,
			       ps.cleartext.data,
			       ps.cleartext.length);
	if (dec.data == NULL) {
		TALLOC_FREE(frame);
		ldb_set_errstring(ldb, "Out of memory, copying value\n");
		*err = LDB_ERR_OPERATIONS_ERROR;
		return data_blob_null;
	}

	TALLOC_FREE(frame);
	return dec;
}

/*
 * @brief Decrypt all the encrypted values on an ldb_message_element
 *
 * Returns a copy of the original attribute with all values decrypted by
 * decrypt_value(), the original attribute is left intact.
 *
 * @param err  Pointer to an error code, set to:
 *             LDB_SUCESS               If the value was successfully encrypted
 *             LDB_ERR_OPERATIONS_ERROR If there was an error.
 *
 * @param ctx  Talloc memory context the will own the memory allocated
 *             for the new ldb_message_element.
 * @param ldb  ldb context, to allow logging.
 * @param el   The ldb_message_elemen to decrypt, not altered or freed
 * @param data The context data for this module.
 *
 * @return Pointer decrypted lsb_message_element, will be NULL if there was
 *         an error.
 */
static struct ldb_message_element *decrypt_element(
	int *err,
	TALLOC_CTX *ctx,
	struct ldb_context *ldb,
	struct ldb_message_element* el,
	struct es_data *data)
{
	int i;
	struct ldb_message_element* dec =
		talloc_zero(ctx, struct ldb_message_element);

	*err = LDB_SUCCESS;
	if (dec == NULL) {
		ldb_set_errstring(ldb,
				  "Out of memory, allocating "
				  "ldb_message_element\n");
		*err = LDB_ERR_OPERATIONS_ERROR;
		return NULL;
	}
	dec->num_values = el->num_values;

	dec->values = talloc_array(dec, struct ldb_val, dec->num_values);
	if (dec->values == NULL) {
		TALLOC_FREE(dec);
		ldb_set_errstring(ldb,
				  "Out of memory, allocating values array\n");
		*err = LDB_ERR_OPERATIONS_ERROR;
		return NULL;
	}

	dec->name = talloc_strdup(dec, el->name);
	if (dec->name == NULL) {
		TALLOC_FREE(dec);
		ldb_set_errstring(ldb, "Out of memory, copying element name\n");
		*err = LDB_ERR_OPERATIONS_ERROR;
		return NULL;
	}

	for (i = 0; i < el->num_values; i++) {
		dec->values[i] =
			decrypt_value(err,
				      el->values,
				      ldb,
				      el->values[i],
				      data);
		if (*err != LDB_SUCCESS) {
			TALLOC_FREE(dec);
			return NULL;
		}
	}
	return dec;
}


/*
 * @brief Decrypt all the secret attributes on an ldb_message
 *
 * Decrypt all the secret attributes on an ldb_message. Any secret attributes
 * are removed from message and decrypted copies of the attributes added.
 * In the event of an error the contents of the message will be inconsistent.
 *
 * @param ldb ldb context, to allow logging.
 * @param msg The ldb_message to have it's secret attributes encrypted.
 * @param data The context data for this module.
 *
 * @returns ldb status code
 *          LDB_SUCESS               If the value was successfully encrypted
 *          LDB_ERR_OPERATIONS_ERROR If there was an error.
 */
static int decrypt_secret_attributes(struct ldb_context *ldb,
				      struct ldb_message *msg,
				      struct es_data *data)
{

	int i, ret;

	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	for (i = 0; i < num_secret_attributes; i++) {
		struct ldb_message_element *el =
			ldb_msg_find_element(msg, secret_attributes[i]);
		if (el != NULL) {
			const int flags = el->flags;
			struct ldb_message_element* dec =
				decrypt_element(&ret,
						msg->elements,
						ldb,
						el,
						data);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			ldb_msg_remove_element(msg, el);
			ret = ldb_msg_add(msg, dec, flags);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}
	return LDB_SUCCESS;
}

static int es_search_post_process(struct ldb_module *module,
				   struct ldb_message *msg)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct es_data *data =
		talloc_get_type(ldb_module_get_private(module),
				struct es_data);


	/*
	 * Decrypt any encrypted secret attributes
	 */
	if (data->encrypt_secrets) {
		int err = decrypt_secret_attributes(ldb, msg, data);
		if (err !=  LDB_SUCCESS) {
			return err;
		}
	}
	return LDB_SUCCESS;
}

/*
  hook search operations
*/
struct es_context {
	struct ldb_module *module;
	struct ldb_request *req;
};

static int es_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct es_context *ec;
	int ret;


	ec = talloc_get_type(req->context, struct es_context);

	if (!ares) {
		return ldb_module_done(ec->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ec->req, ares->controls,
				       ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		/*
		 * for each record returned decrypt any encrypted attributes
		 */
		ret = es_search_post_process(ec->module, ares->message);
		if (ret != 0) {
			return ldb_module_done(ec->req, NULL, NULL,
					       LDB_ERR_OPERATIONS_ERROR);
		}
		return ldb_module_send_entry(ec->req,
				             ares->message, ares->controls);

	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(ec->req, ares->referral);

	case LDB_REPLY_DONE:

		return ldb_module_done(ec->req, ares->controls,
				       ares->response, LDB_SUCCESS);
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

static int es_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct es_context *ec;
	struct ldb_request *down_req;
	int ret;

	/* There are no encrypted attributes on special DNs */
	if (ldb_dn_is_special(req->op.search.base)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	ec = talloc(req, struct es_context);
	if (ec == NULL) {
		return ldb_oom(ldb);
	}

	ec->module = module;
	ec->req = req;
	ret = ldb_build_search_req_ex(&down_req,
				      ldb,
				      ec,
				      req->op.search.base,
				      req->op.search.scope,
				      req->op.search.tree,
				      req->op.search.attrs,
				      req->controls,
				      ec,
				      es_callback,
				      req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	/* perform the search */
	return ldb_next_request(module, down_req);
}
static int es_add(struct ldb_module *module, struct ldb_request *req)
{

	struct es_data *data =
		talloc_get_type(ldb_module_get_private(module),
				struct es_data);
	const struct ldb_message *encrypted_msg = NULL;
	struct ldb_context *ldb = NULL;
	int rc = LDB_SUCCESS;

	if (!data->encrypt_secrets) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);
	encrypted_msg = encrypt_secret_attributes(&rc,
						  req,
						  ldb,
						  req->op.add.message,
						  data);
	if (rc != LDB_SUCCESS) {
		return rc;
	}
	/*
	 * If we did not encrypt any of the attributes
	 * continue on to the next module
	 */
	if (encrypted_msg == NULL) {
		return ldb_next_request(module, req);
	}

	/*
	 * Encrypted an attribute, now need to build a copy of the request
	 * so that we're not altering the original callers copy
	 */
	{
		struct ldb_request* new_req = NULL;
		rc = ldb_build_add_req(&new_req,
				       ldb,
				       req,
				       encrypted_msg,
				       req->controls,
				       req,
				       dsdb_next_callback,
				       req);
		if (rc != LDB_SUCCESS) {
			return rc;
		}
		return ldb_next_request(module, new_req);
	}
}

static int es_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct es_data *data =
		talloc_get_type(ldb_module_get_private(module),
				struct es_data);
	const struct ldb_message *encrypted_msg = NULL;
	struct ldb_context *ldb = NULL;
	int rc = LDB_SUCCESS;

	if (!data->encrypt_secrets) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);
	encrypted_msg = encrypt_secret_attributes(&rc,
						  req,
						  ldb,
						  req->op.mod.message,
						  data);
	if (rc != LDB_SUCCESS) {
		return rc;
	}
	/*
	 * If we did not encrypt any of the attributes
	 * continue on to the next module
	 */
	if (encrypted_msg == NULL) {
		return ldb_next_request(module, req);
	}


	/*
	 * Encrypted an attribute, now need to build a copy of the request
	 * so that we're not altering the original callers copy
	 */
	{
		struct ldb_request* new_req = NULL;
		rc = ldb_build_mod_req(&new_req,
				       ldb,
				       req,
				       encrypted_msg,
				       req->controls,
				       req,
				       dsdb_next_callback,
				       req);
		if (rc != LDB_SUCCESS) {
			return rc;
		}
		return ldb_next_request(module, new_req);
	}
}

static int es_delete(struct ldb_module *module, struct ldb_request *req)
{
	return ldb_next_request(module, req);
}

static int es_rename(struct ldb_module *module, struct ldb_request *req)
{
	return ldb_next_request(module, req);
}
static int es_init(struct ldb_module *ctx)
{
	struct es_data *data;
	int ret;

	data = talloc_zero(ctx, struct es_data);
	if (!data) {
		return ldb_module_oom(ctx);
	}

	{
		struct ldb_context *ldb = ldb_module_get_ctx(ctx);
		struct ldb_dn *samba_dsdb_dn;
		struct ldb_result *res;
		static const char *samba_dsdb_attrs[] = {
			SAMBA_REQUIRED_FEATURES_ATTR,
			NULL
		};
		TALLOC_CTX *frame = talloc_stackframe();

		samba_dsdb_dn = ldb_dn_new(frame, ldb, "@SAMBA_DSDB");
		if (!samba_dsdb_dn) {
			TALLOC_FREE(frame);
			return ldb_oom(ldb);
		}
		ret = dsdb_module_search_dn(ctx,
					    frame,
					    &res,
					    samba_dsdb_dn,
					    samba_dsdb_attrs,
					    DSDB_FLAG_NEXT_MODULE,
					    NULL);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(frame);
			return ret;
		}
		data->encrypt_secrets =
			ldb_msg_check_string_attribute(
				res->msgs[0],
				SAMBA_REQUIRED_FEATURES_ATTR,
				SAMBA_ENCRYPTED_SECRETS_FEATURE);
		if (data->encrypt_secrets) {
			ret = load_keys(ctx, data);
			if (ret != LDB_SUCCESS) {
				TALLOC_FREE(frame);
				return ret;
			}
		}
		TALLOC_FREE(frame);
	}
	ldb_module_set_private(ctx, data);

	ret = ldb_next_init(ctx);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return LDB_SUCCESS;
}

static const struct ldb_module_ops ldb_encrypted_secrets_module_ops = {
	.name              = "encrypted_secrets",
	.search            = es_search,
	.add		   = es_add,
	.modify		   = es_modify,
	.del		   = es_delete,
	.rename		   = es_rename,
	.init_context	   = es_init
};

int ldb_encrypted_secrets_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_encrypted_secrets_module_ops);
}
