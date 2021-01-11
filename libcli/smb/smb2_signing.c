/*
   Unix SMB/CIFS implementation.
   SMB2 signing

   Copyright (C) Stefan Metzmacher 2009

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
#include "system/filesys.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#define SMB2_SIGNING_KEY_GNUTLS_TYPES 1
#include "../libcli/smb/smb_common.h"
#include "../lib/crypto/crypto.h"
#include "lib/util/iov_buf.h"

#ifndef HAVE_GNUTLS_AES_CMAC
#include "lib/crypto/aes.h"
#include "lib/crypto/aes_cmac_128.h"
#endif

#include "lib/crypto/gnutls_helpers.h"

int smb2_signing_key_destructor(struct smb2_signing_key *key)
{
	if (key->hmac_hnd != NULL) {
		gnutls_hmac_deinit(key->hmac_hnd, NULL);
		key->hmac_hnd = NULL;
	}

	if (key->cipher_hnd != NULL) {
		gnutls_aead_cipher_deinit(key->cipher_hnd);
		key->cipher_hnd = NULL;
	}

	return 0;
}

bool smb2_signing_key_valid(const struct smb2_signing_key *key)
{
	if (key == NULL) {
		return false;
	}

	if (key->blob.length == 0 || key->blob.data == NULL) {
		return false;
	}

	return true;
}

NTSTATUS smb2_signing_sign_pdu(struct smb2_signing_key *signing_key,
			       enum protocol_types protocol,
			       struct iovec *vector,
			       int count)
{
	uint8_t *hdr;
	uint64_t session_id;
	uint8_t res[16];
	int i;

	if (count < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (vector[0].iov_len != SMB2_HDR_BODY) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	hdr = (uint8_t *)vector[0].iov_base;

	session_id = BVAL(hdr, SMB2_HDR_SESSION_ID);
	if (session_id == 0) {
		/*
		 * do not sign messages with a zero session_id.
		 * See MS-SMB2 3.2.4.1.1
		 */
		return NT_STATUS_OK;
	}

	if (!smb2_signing_key_valid(signing_key)) {
		DBG_WARNING("No signing key for SMB2 signing\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	memset(hdr + SMB2_HDR_SIGNATURE, 0, 16);

	SIVAL(hdr, SMB2_HDR_FLAGS, IVAL(hdr, SMB2_HDR_FLAGS) | SMB2_HDR_FLAG_SIGNED);

	if (protocol >= PROTOCOL_SMB2_24) {
#ifdef HAVE_GNUTLS_AES_CMAC
		gnutls_datum_t key = {
			.data = signing_key->blob.data,
			.size = MIN(signing_key->blob.length, 16),
		};
		int rc;

		if (signing_key->hmac_hnd == NULL) {
			rc = gnutls_hmac_init(&signing_key->hmac_hnd,
					      GNUTLS_MAC_AES_CMAC_128,
					      key.data,
					      key.size);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}

		for (i = 0; i < count; i++) {
			rc = gnutls_hmac(signing_key->hmac_hnd,
					 vector[i].iov_base,
					 vector[i].iov_len);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}
		gnutls_hmac_output(signing_key->hmac_hnd, res);
#else /* NOT HAVE_GNUTLS_AES_CMAC */
		struct aes_cmac_128_context ctx;
		uint8_t key[AES_BLOCK_SIZE] = {0};

		memcpy(key,
		       signing_key->blob.data,
		       MIN(signing_key->blob.length, 16));

		aes_cmac_128_init(&ctx, key);
		for (i=0; i < count; i++) {
			aes_cmac_128_update(&ctx,
					(const uint8_t *)vector[i].iov_base,
					vector[i].iov_len);
		}
		aes_cmac_128_final(&ctx, res);

		ZERO_ARRAY(key);
#endif /* HAVE_GNUTLS_AES_CMAC */
	} else {
		uint8_t digest[gnutls_hmac_get_len(GNUTLS_MAC_SHA256)];
		int rc;

		if (signing_key->hmac_hnd == NULL) {
			rc = gnutls_hmac_init(&signing_key->hmac_hnd,
					      GNUTLS_MAC_SHA256,
					      signing_key->blob.data,
					      MIN(signing_key->blob.length, 16));
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}

		for (i = 0; i < count; i++) {
			rc = gnutls_hmac(signing_key->hmac_hnd,
					 vector[i].iov_base,
					 vector[i].iov_len);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}
		gnutls_hmac_output(signing_key->hmac_hnd, digest);
		memcpy(res, digest, sizeof(res));
	}
	DEBUG(5,("signed SMB2 message\n"));

	memcpy(hdr + SMB2_HDR_SIGNATURE, res, 16);

	return NT_STATUS_OK;
}

NTSTATUS smb2_signing_check_pdu(struct smb2_signing_key *signing_key,
				enum protocol_types protocol,
				const struct iovec *vector,
				int count)
{
	const uint8_t *hdr;
	const uint8_t *sig;
	uint64_t session_id;
	uint8_t res[16];
	static const uint8_t zero_sig[16] = { 0, };
	int i;

	SMB_ASSERT(count >= 2);
	SMB_ASSERT(vector[0].iov_len == SMB2_HDR_BODY);

	hdr = (const uint8_t *)vector[0].iov_base;

	session_id = BVAL(hdr, SMB2_HDR_SESSION_ID);
	if (session_id == 0) {
		/*
		 * do not sign messages with a zero session_id.
		 * See MS-SMB2 3.2.4.1.1
		 */
		return NT_STATUS_OK;
	}

	if (!smb2_signing_key_valid(signing_key)) {
		/* we don't have the session key yet */
		return NT_STATUS_OK;
	}

	sig = hdr+SMB2_HDR_SIGNATURE;

	if (protocol >= PROTOCOL_SMB2_24) {
#ifdef HAVE_GNUTLS_AES_CMAC
		gnutls_datum_t key = {
			.data = signing_key->blob.data,
			.size = MIN(signing_key->blob.length, 16),
		};
		int rc;

		if (signing_key->hmac_hnd == NULL) {
			rc = gnutls_hmac_init(&signing_key->hmac_hnd,
					      GNUTLS_MAC_AES_CMAC_128,
					      key.data,
					      key.size);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}

		rc = gnutls_hmac(signing_key->hmac_hnd, hdr, SMB2_HDR_SIGNATURE);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		rc = gnutls_hmac(signing_key->hmac_hnd, zero_sig, 16);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		for (i = 1; i < count; i++) {
			rc = gnutls_hmac(signing_key->hmac_hnd,
					 vector[i].iov_base,
					 vector[i].iov_len);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}
		gnutls_hmac_output(signing_key->hmac_hnd, res);
#else /* NOT HAVE_GNUTLS_AES_CMAC */
		struct aes_cmac_128_context ctx;
		uint8_t key[AES_BLOCK_SIZE] = {0};

		memcpy(key,
		       signing_key->blob.data,
		       MIN(signing_key->blob.length, 16));

		aes_cmac_128_init(&ctx, key);
		aes_cmac_128_update(&ctx, hdr, SMB2_HDR_SIGNATURE);
		aes_cmac_128_update(&ctx, zero_sig, 16);
		for (i=1; i < count; i++) {
			aes_cmac_128_update(&ctx,
					(const uint8_t *)vector[i].iov_base,
					vector[i].iov_len);
		}
		aes_cmac_128_final(&ctx, res);

		ZERO_ARRAY(key);
#endif
	} else {
		uint8_t digest[gnutls_hash_get_len(GNUTLS_MAC_SHA256)];
		int rc;

		if (signing_key->hmac_hnd == NULL) {
			rc = gnutls_hmac_init(&signing_key->hmac_hnd,
					      GNUTLS_MAC_SHA256,
					      signing_key->blob.data,
					      MIN(signing_key->blob.length, 16));
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}

		rc = gnutls_hmac(signing_key->hmac_hnd, hdr, SMB2_HDR_SIGNATURE);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
		rc = gnutls_hmac(signing_key->hmac_hnd, zero_sig, 16);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		for (i = 1; i < count; i++) {
			rc = gnutls_hmac(signing_key->hmac_hnd,
					 vector[i].iov_base,
					 vector[i].iov_len);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}
		gnutls_hmac_output(signing_key->hmac_hnd, digest);
		memcpy(res, digest, 16);
		ZERO_ARRAY(digest);
	}

	if (memcmp_const_time(res, sig, 16) != 0) {
		DEBUG(0,("Bad SMB2 signature for message\n"));
		dump_data(0, sig, 16);
		dump_data(0, res, 16);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

NTSTATUS smb2_key_derivation(const uint8_t *KI, size_t KI_len,
			     const uint8_t *Label, size_t Label_len,
			     const uint8_t *Context, size_t Context_len,
			     uint8_t KO[16])
{
	gnutls_hmac_hd_t hmac_hnd = NULL;
	uint8_t buf[4];
	static const uint8_t zero = 0;
	uint8_t digest[gnutls_hash_get_len(GNUTLS_MAC_SHA256)];
	uint32_t i = 1;
	uint32_t L = 128;
	int rc;

	/*
	 * a simplified version of
	 * "NIST Special Publication 800-108" section 5.1
	 * using hmac-sha256.
	 */
	rc = gnutls_hmac_init(&hmac_hnd,
			      GNUTLS_MAC_SHA256,
			      KI,
			      KI_len);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}

	RSIVAL(buf, 0, i);
	rc = gnutls_hmac(hmac_hnd, buf, sizeof(buf));
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	rc = gnutls_hmac(hmac_hnd, Label, Label_len);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	rc = gnutls_hmac(hmac_hnd, &zero, 1);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	rc = gnutls_hmac(hmac_hnd, Context, Context_len);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	RSIVAL(buf, 0, L);
	rc = gnutls_hmac(hmac_hnd, buf, sizeof(buf));
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}

	gnutls_hmac_deinit(hmac_hnd, digest);

	memcpy(KO, digest, 16);

	ZERO_ARRAY(digest);

	return NT_STATUS_OK;
}

NTSTATUS smb2_signing_encrypt_pdu(struct smb2_signing_key *encryption_key,
				  uint16_t cipher_id,
				  struct iovec *vector,
				  int count)
{
	uint8_t *tf;
	size_t a_total;
	ssize_t m_total;
	uint32_t iv_size = 0;
	uint32_t key_size = 0;
	size_t tag_size = 0;
	uint8_t _key[16] = {0};
	gnutls_cipher_algorithm_t algo = 0;
	gnutls_datum_t key;
	gnutls_datum_t iv;
	NTSTATUS status;
	int rc;

	if (count < 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (vector[0].iov_len != SMB2_TF_HDR_SIZE) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	tf = (uint8_t *)vector[0].iov_base;

	if (!smb2_signing_key_valid(encryption_key)) {
		DBG_WARNING("No encryption key for SMB2 signing\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	a_total = SMB2_TF_HDR_SIZE - SMB2_TF_NONCE;

	m_total = iov_buflen(&vector[1], count-1);
	if (m_total == -1) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	SSVAL(tf, SMB2_TF_FLAGS, SMB2_TF_FLAGS_ENCRYPTED);
	SIVAL(tf, SMB2_TF_MSG_SIZE, m_total);

	switch (cipher_id) {
	case SMB2_ENCRYPTION_AES128_CCM:
		algo = GNUTLS_CIPHER_AES_128_CCM;
		iv_size = SMB2_AES_128_CCM_NONCE_SIZE;
		break;
	case SMB2_ENCRYPTION_AES128_GCM:
		algo = GNUTLS_CIPHER_AES_128_GCM;
		iv_size = gnutls_cipher_get_iv_size(algo);
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	key_size = gnutls_cipher_get_key_size(algo);
	tag_size = gnutls_cipher_get_tag_size(algo);

	if (key_size > sizeof(_key)) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	key = (gnutls_datum_t) {
		.data = _key,
		.size = key_size,
	};

	memcpy(key.data,
	       encryption_key->blob.data,
	       MIN(encryption_key->blob.length, key.size));

	iv = (gnutls_datum_t) {
		.data = tf + SMB2_TF_NONCE,
		.size = iv_size,
	};

	if (encryption_key->cipher_hnd == NULL) {
		rc = gnutls_aead_cipher_init(&encryption_key->cipher_hnd,
					algo,
					&key);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}
	}

	memset(tf + SMB2_TF_NONCE + iv_size,
	       0,
	       16 - iv_size);

#if defined(HAVE_GNUTLS_AEAD_CIPHER_ENCRYPTV2)
	{
		uint8_t tag[tag_size];
		giovec_t auth_iov[1];

		auth_iov[0] = (giovec_t) {
			.iov_base = tf + SMB2_TF_NONCE,
			.iov_len  = a_total,
		};

		rc = gnutls_aead_cipher_encryptv2(encryption_key->cipher_hnd,
						  iv.data,
						  iv.size,
						  auth_iov,
						  1,
						  &vector[1],
						  count - 1,
						  tag,
						  &tag_size);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}

		memcpy(tf + SMB2_TF_SIGNATURE, tag, tag_size);
	}
#else /* HAVE_GNUTLS_AEAD_CIPHER_ENCRYPTV2 */
	{
		size_t ptext_size = m_total;
		uint8_t *ptext = NULL;
		size_t ctext_size = m_total + tag_size;
		uint8_t *ctext = NULL;
		size_t len = 0;
		int i;

		ptext = talloc_size(talloc_tos(), ptext_size);
		if (ptext == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		ctext = talloc_size(talloc_tos(), ctext_size);
		if (ctext == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		for (i = 1; i < count; i++) {
			memcpy(ptext + len,
			       vector[i].iov_base,
			       vector[i].iov_len);

			len += vector[i].iov_len;
			if (len > ptext_size) {
				TALLOC_FREE(ptext);
				TALLOC_FREE(ctext);
				status = NT_STATUS_INTERNAL_ERROR;
				goto out;
			}
		}

		rc = gnutls_aead_cipher_encrypt(encryption_key->cipher_hnd,
						iv.data,
						iv.size,
						tf + SMB2_TF_NONCE,
						a_total,
						tag_size,
						ptext,
						ptext_size,
						ctext,
						&ctext_size);
		if (rc < 0 || ctext_size != m_total + tag_size) {
			TALLOC_FREE(ptext);
			TALLOC_FREE(ctext);
			status = gnutls_error_to_ntstatus(rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}

		len = 0;
		for (i = 1; i < count; i++) {
			memcpy(vector[i].iov_base,
			       ctext + len,
			       vector[i].iov_len);

			len += vector[i].iov_len;
		}

		memcpy(tf + SMB2_TF_SIGNATURE, ctext + m_total, tag_size);

		TALLOC_FREE(ptext);
		TALLOC_FREE(ctext);
	}
#endif /* HAVE_GNUTLS_AEAD_CIPHER_ENCRYPTV2 */

	DBG_INFO("Enencrypted SMB2 message\n");

	status = NT_STATUS_OK;
out:
	ZERO_ARRAY(_key);

	return status;
}

NTSTATUS smb2_signing_decrypt_pdu(struct smb2_signing_key *decryption_key,
				  uint16_t cipher_id,
				  struct iovec *vector,
				  int count)
{
	uint8_t *tf;
	uint16_t flags;
	size_t a_total;
	ssize_t m_total;
	uint32_t msg_size = 0;
	uint32_t iv_size = 0;
	uint32_t key_size = 0;
	size_t tag_size = 0;
	uint8_t _key[16] = {0};
	gnutls_cipher_algorithm_t algo = 0;
	gnutls_datum_t key;
	gnutls_datum_t iv;
	NTSTATUS status;
	int rc;

	if (count < 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (vector[0].iov_len != SMB2_TF_HDR_SIZE) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	tf = (uint8_t *)vector[0].iov_base;

	if (!smb2_signing_key_valid(decryption_key)) {
		DBG_WARNING("No decryption key for SMB2 signing\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	a_total = SMB2_TF_HDR_SIZE - SMB2_TF_NONCE;

	m_total = iov_buflen(&vector[1], count-1);
	if (m_total == -1) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	flags = SVAL(tf, SMB2_TF_FLAGS);
	msg_size = IVAL(tf, SMB2_TF_MSG_SIZE);

	if (flags != SMB2_TF_FLAGS_ENCRYPTED) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (msg_size != m_total) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	switch (cipher_id) {
	case SMB2_ENCRYPTION_AES128_CCM:
		algo = GNUTLS_CIPHER_AES_128_CCM;
		iv_size = SMB2_AES_128_CCM_NONCE_SIZE;
		break;
	case SMB2_ENCRYPTION_AES128_GCM:
		algo = GNUTLS_CIPHER_AES_128_GCM;
		iv_size = gnutls_cipher_get_iv_size(algo);
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	key_size = gnutls_cipher_get_key_size(algo);
	tag_size = gnutls_cipher_get_tag_size(algo);

	if (key_size > sizeof(_key)) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	key = (gnutls_datum_t) {
		.data = _key,
		.size = key_size,
	};

	memcpy(key.data,
	       decryption_key->blob.data,
	       MIN(decryption_key->blob.length, key.size));

	iv = (gnutls_datum_t) {
		.data = tf + SMB2_TF_NONCE,
		.size = iv_size,
	};

	if (decryption_key->cipher_hnd == NULL) {
		rc = gnutls_aead_cipher_init(&decryption_key->cipher_hnd,
					     algo,
					     &key);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}
	}

/* gnutls_aead_cipher_encryptv2() has a bug in version 3.6.10 */
#if defined(HAVE_GNUTLS_AEAD_CIPHER_ENCRYPTV2)
	{
		giovec_t auth_iov[1];

		auth_iov[0] = (giovec_t) {
			.iov_base = tf + SMB2_TF_NONCE,
			.iov_len  = a_total,
		};

		rc = gnutls_aead_cipher_decryptv2(decryption_key->cipher_hnd,
						  iv.data,
						  iv.size,
						  auth_iov,
						  1,
						  &vector[1],
						  count - 1,
						  tf + SMB2_TF_SIGNATURE,
						  tag_size);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}
	}
#else /* HAVE_GNUTLS_AEAD_CIPHER_ENCRYPTV2 */
	{
		size_t ctext_size = m_total + tag_size;
		uint8_t *ctext = NULL;
		size_t ptext_size = m_total;
		uint8_t *ptext = NULL;
		size_t len = 0;
		int i;

		/* GnuTLS doesn't have a iovec API for decryption yet */

		ptext = talloc_size(talloc_tos(), ptext_size);
		if (ptext == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		ctext = talloc_size(talloc_tos(), ctext_size);
		if (ctext == NULL) {
			TALLOC_FREE(ptext);
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}


		for (i = 1; i < count; i++) {
			memcpy(ctext + len,
			       vector[i].iov_base,
			       vector[i].iov_len);

			len += vector[i].iov_len;
		}
		if (len != m_total) {
			TALLOC_FREE(ptext);
			TALLOC_FREE(ctext);
			status = NT_STATUS_INTERNAL_ERROR;
			goto out;
		}

		memcpy(ctext + len,
		       tf + SMB2_TF_SIGNATURE,
		       tag_size);

		/* This function will verify the tag */
		rc = gnutls_aead_cipher_decrypt(decryption_key->cipher_hnd,
						iv.data,
						iv.size,
						tf + SMB2_TF_NONCE,
						a_total,
						tag_size,
						ctext,
						ctext_size,
						ptext,
						&ptext_size);
		if (rc < 0 || ptext_size != m_total) {
			TALLOC_FREE(ptext);
			TALLOC_FREE(ctext);
			status = gnutls_error_to_ntstatus(rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}

		len = 0;
		for (i = 1; i < count; i++) {
			memcpy(vector[i].iov_base,
			       ptext + len,
			       vector[i].iov_len);

			len += vector[i].iov_len;
		}

		TALLOC_FREE(ptext);
		TALLOC_FREE(ctext);
	}
#endif /* HAVE_GNUTLS_AEAD_CIPHER_ENCRYPTV2 */

	DBG_INFO("Decrypted SMB2 message\n");

	status = NT_STATUS_OK;
out:
	ZERO_ARRAY(_key);

	return status;
}
