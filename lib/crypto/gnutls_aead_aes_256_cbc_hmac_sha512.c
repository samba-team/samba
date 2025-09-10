/*
 * Copyright (c) 2021-2022 Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "lib/util/data_blob.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "gnutls_helpers.h"

#define SAMR_AES_VERSION_BYTE 0x01
#define SAMR_AES_VERSION_BYTE_LEN 1

static NTSTATUS calculate_enc_key(const DATA_BLOB *cek,
				  const DATA_BLOB *key_salt,
				  uint8_t enc_key[32])
{
	gnutls_mac_algorithm_t hash_algo = GNUTLS_MAC_SHA512;
	size_t hmac_size = gnutls_hmac_get_len(hash_algo);
	uint8_t enc_key_data[hmac_size];
	int rc;

	rc = gnutls_hmac_fast(hash_algo,
			      cek->data,
			      cek->length,
			      key_salt->data,
			      key_salt->length,
			      enc_key_data);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}

	/* The key gets truncated to 32 byte */
	memcpy(enc_key, enc_key_data, 32);
	BURN_DATA(enc_key_data);

	return NT_STATUS_OK;
}

static NTSTATUS calculate_mac_key(const DATA_BLOB *cek,
				  const DATA_BLOB *mac_salt,
				  uint8_t mac_key[64])
{
	int rc;

	rc = gnutls_hmac_fast(GNUTLS_MAC_SHA512,
			      cek->data,
			      cek->length,
			      mac_salt->data,
			      mac_salt->length,
			      mac_key);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}

	return NT_STATUS_OK;
}

/* This is an implementation of [MS-SAMR] 3.2.2.4 AES Cipher Usage */

NTSTATUS
samba_gnutls_aead_aes_256_cbc_hmac_sha512_encrypt(TALLOC_CTX *mem_ctx,
						  const DATA_BLOB *plaintext,
						  const DATA_BLOB *cek,
						  const DATA_BLOB *key_salt,
						  const DATA_BLOB *mac_salt,
						  const DATA_BLOB *iv,
						  DATA_BLOB *pciphertext,
						  uint8_t pauth_tag[64])
{
	gnutls_hmac_hd_t hmac_hnd = NULL;
	gnutls_mac_algorithm_t hmac_algo = GNUTLS_MAC_SHA512;
	size_t hmac_size = gnutls_hmac_get_len(hmac_algo);
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_cipher_algorithm_t cipher_algo = GNUTLS_CIPHER_AES_256_CBC;
	uint32_t aes_block_size = gnutls_cipher_get_block_size(cipher_algo);
	gnutls_datum_t iv_datum = {
		.data = iv->data,
		.size = iv->length,
	};
	uint8_t enc_key_data[32] = {0};
	gnutls_datum_t enc_key = {
		.data = enc_key_data,
		.size = sizeof(enc_key_data),
	};
	uint8_t *cipher_text = NULL;
	size_t cipher_text_len = 0;
	uint8_t mac_key_data[64] = {0};
	gnutls_datum_t mac_key = {
		.data = mac_key_data,
		.size = sizeof(mac_key_data),
	};
	uint8_t version_byte = SAMR_AES_VERSION_BYTE;
	uint8_t version_byte_len = SAMR_AES_VERSION_BYTE_LEN;
	uint8_t auth_data[hmac_size];
#ifndef HAVE_GNUTLS_CIPHER_ENCRYPT3
	DATA_BLOB padded_plaintext;
	size_t padding;
#endif
	NTSTATUS status;
	int rc;

	/*
	 * We don't want to overflow 'pauth_tag', which is 64 bytes in
	 * size.
	 */
	SMB_ASSERT(hmac_size == 64);

	if (plaintext->length == 0 || cek->length == 0 ||
	    key_salt->length == 0 || mac_salt->length == 0 || iv->length == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (plaintext->length + aes_block_size < plaintext->length) {
		return NT_STATUS_INVALID_BUFFER_SIZE;
	}

	status = calculate_enc_key(cek, key_salt, enc_key_data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	rc = gnutls_cipher_init(&cipher_hnd, cipher_algo, &enc_key, &iv_datum);
	if (rc < 0) {
		BURN_DATA(enc_key_data);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}

#ifdef HAVE_GNUTLS_CIPHER_ENCRYPT3
	/* Figure out the size for the cipher text */
	rc = gnutls_cipher_encrypt3(cipher_hnd,
				    plaintext->data,
				    plaintext->length,
				    NULL,
				    &cipher_text_len,
				    GNUTLS_CIPHER_PADDING_PKCS7);
	if (rc < 0) {
		BURN_DATA(enc_key_data);
		gnutls_cipher_deinit(cipher_hnd);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}

	cipher_text = talloc_size(mem_ctx, cipher_text_len);
	if (cipher_text == NULL) {
		BURN_DATA(enc_key_data);
		gnutls_cipher_deinit(cipher_hnd);
		return NT_STATUS_NO_MEMORY;
	}

	rc = gnutls_cipher_encrypt3(cipher_hnd,
				    plaintext->data,
				    plaintext->length,
				    cipher_text,
				    &cipher_text_len,
				    GNUTLS_CIPHER_PADDING_PKCS7);
	gnutls_cipher_deinit(cipher_hnd);
	BURN_DATA(enc_key_data);
	if (rc < 0) {
		TALLOC_FREE(cipher_text);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}
#else /* HAVE_GNUTLS_CIPHER_ENCRYPT3 */
	/*
	 * PKCS#7 padding
	 */
	padded_plaintext.length =
		aes_block_size * (plaintext->length / aes_block_size) +
		aes_block_size;

	padding = padded_plaintext.length - plaintext->length;

	padded_plaintext =
		data_blob_talloc(mem_ctx, NULL, padded_plaintext.length);
	if (padded_plaintext.data == NULL) {
		BURN_DATA(enc_key_data);
		gnutls_cipher_deinit(cipher_hnd);
		return NT_STATUS_NO_MEMORY;
	}

	/* Allocate buffer for cipher text */
	cipher_text_len = padded_plaintext.length;
	cipher_text = talloc_size(mem_ctx, cipher_text_len);
	if (cipher_text == NULL) {
		BURN_DATA(enc_key_data);
		gnutls_cipher_deinit(cipher_hnd);
		data_blob_free(&padded_plaintext);
		return NT_STATUS_NO_MEMORY;
	}

	memcpy(padded_plaintext.data, plaintext->data, plaintext->length);
	memset(padded_plaintext.data + plaintext->length, padding, padding);

	rc = gnutls_cipher_encrypt2(cipher_hnd,
				    padded_plaintext.data,
				    padded_plaintext.length,
				    cipher_text,
				    cipher_text_len);
	gnutls_cipher_deinit(cipher_hnd);
	data_blob_clear_free(&padded_plaintext);
	BURN_DATA(enc_key_data);
	if (rc < 0) {
		TALLOC_FREE(cipher_text);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}
#endif /* HAVE_GNUTLS_CIPHER_ENCRYPT3 */

	/* Calculate mac key */
	status = calculate_mac_key(cek, mac_salt, mac_key_data);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(cipher_text);
		return status;
	}

	/* Generate auth tag */
	rc = gnutls_hmac_init(&hmac_hnd, hmac_algo, mac_key.data, mac_key.size);
	BURN_DATA(mac_key_data);
	if (rc < 0) {
		TALLOC_FREE(cipher_text);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}

	rc = gnutls_hmac(hmac_hnd, &version_byte, sizeof(uint8_t));
	if (rc < 0) {
		TALLOC_FREE(cipher_text);
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}

	rc = gnutls_hmac(hmac_hnd, iv->data, iv->length);
	if (rc < 0) {
		TALLOC_FREE(cipher_text);
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}

	rc = gnutls_hmac(hmac_hnd, cipher_text, cipher_text_len);
	if (rc < 0) {
		TALLOC_FREE(cipher_text);
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}

	rc = gnutls_hmac(hmac_hnd, &version_byte_len, sizeof(uint8_t));
	if (rc < 0) {
		TALLOC_FREE(cipher_text);
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_ENCRYPTION_FAILED);
	}
	gnutls_hmac_deinit(hmac_hnd, auth_data);

	if (pciphertext != NULL) {
		pciphertext->length = cipher_text_len;
		pciphertext->data = cipher_text;
	}
	(void)memcpy(pauth_tag, auth_data, hmac_size);

	return NT_STATUS_OK;
}

NTSTATUS
samba_gnutls_aead_aes_256_cbc_hmac_sha512_decrypt(TALLOC_CTX *mem_ctx,
						  const DATA_BLOB *ciphertext,
						  const DATA_BLOB *cdk,
						  const DATA_BLOB *key_salt,
						  const DATA_BLOB *mac_salt,
						  const DATA_BLOB *iv,
						  const uint8_t auth_tag[64],
						  DATA_BLOB *pplaintext)
{
	gnutls_hmac_hd_t hmac_hnd = NULL;
	gnutls_mac_algorithm_t hash_algo = GNUTLS_MAC_SHA512;
	size_t hmac_size = gnutls_hmac_get_len(hash_algo);
	uint8_t dec_key_data[32];
	uint8_t mac_key_data[64];
	gnutls_datum_t mac_key = {
		.data = mac_key_data,
		.size = sizeof(mac_key_data),
	};
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_cipher_algorithm_t cipher_algo = GNUTLS_CIPHER_AES_256_CBC;
	gnutls_datum_t dec_key = {
		.data = dec_key_data,
		.size = sizeof(dec_key_data),
	};
	gnutls_datum_t iv_datum = {
		.data = iv->data,
		.size = iv->length,
	};
	uint8_t version_byte = SAMR_AES_VERSION_BYTE;
	uint8_t version_byte_len = SAMR_AES_VERSION_BYTE_LEN;
	uint8_t auth_data[hmac_size];
	uint8_t padding;
	size_t i;
	NTSTATUS status;
	bool equal;
	int rc;

	if (cdk->length == 0 || ciphertext->length == 0 ||
	    key_salt->length == 0 || mac_salt->length == 0 || iv->length == 0 ||
	    pplaintext == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Calculate mac key */
	status = calculate_mac_key(cdk, mac_salt, mac_key_data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	rc = gnutls_hmac_init(&hmac_hnd, hash_algo, mac_key.data, mac_key.size);
	BURN_DATA(mac_key_data);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_DECRYPTION_FAILED);
	}

	rc = gnutls_hmac(hmac_hnd, &version_byte, sizeof(uint8_t));
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_DECRYPTION_FAILED);
	}

	rc = gnutls_hmac(hmac_hnd, iv->data, iv->length);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_DECRYPTION_FAILED);
	}

	rc = gnutls_hmac(hmac_hnd, ciphertext->data, ciphertext->length);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_DECRYPTION_FAILED);
	}

	rc = gnutls_hmac(hmac_hnd, &version_byte_len, sizeof(uint8_t));
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_DECRYPTION_FAILED);
	}
	gnutls_hmac_deinit(hmac_hnd, auth_data);

	equal = mem_equal_const_time(auth_data, auth_tag, sizeof(auth_data));
	if (!equal) {
		return NT_STATUS_DECRYPTION_FAILED;
	}

	*pplaintext = data_blob_talloc_zero(mem_ctx, ciphertext->length);
	if (pplaintext->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Calculate decryption key */
	status = calculate_enc_key(cdk, key_salt, dec_key_data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	rc = gnutls_cipher_init(&cipher_hnd, cipher_algo, &dec_key, &iv_datum);
	BURN_DATA(dec_key_data);
	if (rc < 0) {
		data_blob_free(pplaintext);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_DECRYPTION_FAILED);
	}

	rc = gnutls_cipher_decrypt2(cipher_hnd,
				    ciphertext->data,
				    ciphertext->length,
				    pplaintext->data,
				    pplaintext->length);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc < 0) {
		data_blob_clear_free(pplaintext);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_DECRYPTION_FAILED);
	}

	/*
	 * PKCS#7 padding
	 *
	 * TODO: Use gnutls_cipher_decrypt3()
	 */

	/*
	 * The plaintext is always padded.
	 *
	 * We already checked for ciphertext->length == 0 above and the
	 * pplaintext->length is equal to ciphertext->length here. We need to
	 * remove the padding from the plaintext size.
	 */
	padding = pplaintext->data[pplaintext->length - 1];
	if (padding == 0 || padding > 16) {
		data_blob_clear_free(pplaintext);
		return NT_STATUS_DECRYPTION_FAILED;
	}

	for (i = pplaintext->length - padding; i < pplaintext->length; i++) {
		if (pplaintext->data[i] != padding) {
			data_blob_clear_free(pplaintext);
			return NT_STATUS_DECRYPTION_FAILED;
		}
	}

	pplaintext->length -= padding;

	return NT_STATUS_OK;
}
