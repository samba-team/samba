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

#include "lib/crypto/gnutls_helpers.h"

void smb2_signing_derivations_fill_const_stack(struct smb2_signing_derivations *ds,
					       enum protocol_types protocol,
					       const DATA_BLOB preauth_hash)
{
	*ds = (struct smb2_signing_derivations) { .signing = NULL, };

	if (protocol >= PROTOCOL_SMB3_11) {
		struct smb2_signing_derivation *d = NULL;

		SMB_ASSERT(preauth_hash.length != 0);

		d = &ds->__signing;
		ds->signing = d;
		d->label = data_blob_string_const_null("SMBSigningKey");
		d->context = preauth_hash;

		d = &ds->__cipher_c2s;
		ds->cipher_c2s = d;
		d->label = data_blob_string_const_null("SMBC2SCipherKey");
		d->context = preauth_hash;

		d = &ds->__cipher_s2c;
		ds->cipher_s2c = d;
		d->label = data_blob_string_const_null("SMBS2CCipherKey");
		d->context = preauth_hash;

		d = &ds->__application;
		ds->application = d;
		d->label = data_blob_string_const_null("SMBAppKey");
		d->context = preauth_hash;

	} else if (protocol >= PROTOCOL_SMB3_00) {
		struct smb2_signing_derivation *d = NULL;

		d = &ds->__signing;
		ds->signing = d;
		d->label = data_blob_string_const_null("SMB2AESCMAC");
		d->context = data_blob_string_const_null("SmbSign");

		d = &ds->__cipher_c2s;
		ds->cipher_c2s = d;
		d->label = data_blob_string_const_null("SMB2AESCCM");
		d->context = data_blob_string_const_null("ServerIn ");

		d = &ds->__cipher_s2c;
		ds->cipher_s2c = d;
		d->label = data_blob_string_const_null("SMB2AESCCM");
		d->context = data_blob_string_const_null("ServerOut");

		d = &ds->__application;
		ds->application = d;
		d->label = data_blob_string_const_null("SMB2APP");
		d->context = data_blob_string_const_null("SmbRpc");
	}
}

static int smb2_signing_key_destructor(struct smb2_signing_key *key)
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

NTSTATUS smb2_signing_key_copy(TALLOC_CTX *mem_ctx,
			       const struct smb2_signing_key *src,
			       struct smb2_signing_key **_dst)
{
	struct smb2_signing_key *dst = NULL;

	dst = talloc_zero(mem_ctx, struct smb2_signing_key);
	if (dst == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(dst, smb2_signing_key_destructor);

	dst->sign_algo_id = src->sign_algo_id;
	dst->cipher_algo_id = src->cipher_algo_id;

	if (src->blob.length == 0) {
		*_dst = dst;
		return NT_STATUS_OK;
	}

	dst->blob = data_blob_talloc_zero_s(dst, src->blob.length);
	if (dst->blob.length == 0) {
		TALLOC_FREE(dst);
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(dst->blob.data, src->blob.data, dst->blob.length);

	*_dst = dst;
	return NT_STATUS_OK;
}

static NTSTATUS smb2_signing_key_create(TALLOC_CTX *mem_ctx,
					uint16_t sign_algo_id,
					uint16_t cipher_algo_id,
					const DATA_BLOB *master_key,
					const struct smb2_signing_derivation *d,
					struct smb2_signing_key **_key)
{
	struct smb2_signing_key *key = NULL;
	size_t in_key_length = 16;
	size_t out_key_length = 16;
	NTSTATUS status;

	if (sign_algo_id != SMB2_SIGNING_INVALID_ALGO) {
		SMB_ASSERT(cipher_algo_id == SMB2_ENCRYPTION_INVALID_ALGO);
	}
	if (cipher_algo_id != SMB2_ENCRYPTION_INVALID_ALGO) {
		SMB_ASSERT(sign_algo_id == SMB2_SIGNING_INVALID_ALGO);
	}

	key = talloc_zero(mem_ctx, struct smb2_signing_key);
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(key, smb2_signing_key_destructor);

	key->sign_algo_id = sign_algo_id;
	key->cipher_algo_id = cipher_algo_id;

	if (master_key == NULL) {
		SMB_ASSERT(d == NULL);

		*_key = key;
		return NT_STATUS_OK;
	}

	/*
	 * Per default use the full key.
	 */
	in_key_length = out_key_length = master_key->length;
	switch (sign_algo_id) {
	case SMB2_SIGNING_INVALID_ALGO:
		/*
		 * This means we're processing cipher_algo_id below
		 */
		break;
	case SMB2_SIGNING_MD5_SMB1:
		SMB_ASSERT(d == NULL);
		break;
	case SMB2_SIGNING_HMAC_SHA256:
	case SMB2_SIGNING_AES128_CMAC:
	case SMB2_SIGNING_AES128_GMAC:
		/*
		 * signing keys are padded or truncated to
		 * 16 bytes.
		 *
		 * Even with master_key->length = 0,
		 * we need to use 16 zeros.
		 */
		in_key_length = out_key_length = 16;
		break;
	default:
		DBG_ERR("sign_algo_id[%u] not supported\n", sign_algo_id);
		return NT_STATUS_HMAC_NOT_SUPPORTED;
	}
	switch (cipher_algo_id) {
	case SMB2_ENCRYPTION_INVALID_ALGO:
		/*
		 * This means we're processing sign_algo_id above
		 */
		break;
	case SMB2_ENCRYPTION_NONE:
		/*
		 * No encryption negotiated.
		 */
		break;
	case SMB2_ENCRYPTION_AES128_CCM:
	case SMB2_ENCRYPTION_AES128_GCM:
		/*
		 * encryption keys are padded or truncated to
		 * 16 bytes.
		 */
		if (master_key->length == 0) {
			DBG_ERR("cipher_algo_id[%u] without key\n",
				cipher_algo_id);
			return NT_STATUS_NO_USER_SESSION_KEY;
		}
		in_key_length = out_key_length = 16;
		break;
	case SMB2_ENCRYPTION_AES256_CCM:
	case SMB2_ENCRYPTION_AES256_GCM:
		/*
		 * AES256 uses the available input and
		 * generated a 32 byte encryption key.
		 */
		if (master_key->length == 0) {
			DBG_ERR("cipher_algo_id[%u] without key\n",
				cipher_algo_id);
			return NT_STATUS_NO_USER_SESSION_KEY;
		}
		out_key_length = 32;
		break;
	default:
		DBG_ERR("cipher_algo_id[%u] not supported\n", cipher_algo_id);
		return NT_STATUS_FWP_INCOMPATIBLE_CIPHER_CONFIG;
	}

	if (out_key_length == 0) {
		*_key = key;
		return NT_STATUS_OK;
	}

	key->blob = data_blob_talloc_zero_s(key, out_key_length);
	if (key->blob.length == 0) {
		TALLOC_FREE(key);
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(key->blob.data,
	       master_key->data,
	       MIN(key->blob.length, master_key->length));

	if (d == NULL) {
		*_key = key;
		return NT_STATUS_OK;
	}

	status = samba_gnutls_sp800_108_derive_key(key->blob.data,
						   in_key_length,
						   NULL,
						   0,
						   d->label.data,
						   d->label.length,
						   d->context.data,
						   d->context.length,
						   GNUTLS_MAC_SHA256,
						   key->blob.data,
						   out_key_length);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(key);
		return status;
	}

	*_key = key;
	return NT_STATUS_OK;
}

NTSTATUS smb2_signing_key_sign_create(TALLOC_CTX *mem_ctx,
				      uint16_t sign_algo_id,
				      const DATA_BLOB *master_key,
				      const struct smb2_signing_derivation *d,
				      struct smb2_signing_key **_key)
{
	return smb2_signing_key_create(mem_ctx,
				       sign_algo_id,
				       SMB2_ENCRYPTION_INVALID_ALGO,
				       master_key,
				       d,
				       _key);
}

NTSTATUS smb2_signing_key_cipher_create(TALLOC_CTX *mem_ctx,
					uint16_t cipher_algo_id,
					const DATA_BLOB *master_key,
					const struct smb2_signing_derivation *d,
					struct smb2_signing_key **_key)
{
	return smb2_signing_key_create(mem_ctx,
				       SMB2_SIGNING_INVALID_ALGO,
				       cipher_algo_id,
				       master_key,
				       d,
				       _key);
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

static NTSTATUS smb2_signing_gmac(gnutls_aead_cipher_hd_t cipher_hnd,
				  const uint8_t *iv, size_t iv_size,
				  const giovec_t *auth_iov, uint8_t auth_iovcnt,
				  uint8_t *tag, size_t _tag_size)
{
	size_t tag_size = _tag_size;
	int rc;

	rc = gnutls_aead_cipher_encryptv2(cipher_hnd,
					  iv, iv_size,
					  auth_iov, auth_iovcnt,
					  NULL, 0,
					  tag, &tag_size);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
	}

	return NT_STATUS_OK;
}

static NTSTATUS smb2_signing_calc_signature(struct smb2_signing_key *signing_key,
					    uint16_t sign_algo_id,
					    const struct iovec *vector,
					    int count,
					    uint8_t signature[16])
{
	const uint8_t *hdr = (uint8_t *)vector[0].iov_base;
	uint16_t opcode;
	uint32_t flags;
	uint64_t msg_id;
	static const uint8_t zero_sig[16] = { 0, };
	gnutls_mac_algorithm_t hmac_algo = GNUTLS_MAC_UNKNOWN;
	int i;

	/*
	 * We expect
	 * - SMB2 HDR
	 * - SMB2 BODY FIXED
	 * - (optional) SMB2 BODY DYN
	 * - (optional) PADDING
	 */
	SMB_ASSERT(count >= 2);
	SMB_ASSERT(vector[0].iov_len == SMB2_HDR_BODY);
	SMB_ASSERT(count <= 4);

	opcode = SVAL(hdr, SMB2_HDR_OPCODE);
	flags = IVAL(hdr, SMB2_HDR_FLAGS);
	if (flags & SMB2_HDR_FLAG_REDIRECT) {
		NTSTATUS pdu_status = NT_STATUS(IVAL(hdr, SMB2_HDR_STATUS));
		if (NT_STATUS_EQUAL(pdu_status, NT_STATUS_PENDING)) {
			DBG_ERR("opcode[%u] NT_STATUS_PENDING\n", opcode);
			return NT_STATUS_INTERNAL_ERROR;
		}
		if (opcode == SMB2_OP_CANCEL) {
			DBG_ERR("SMB2_OP_CANCEL response should not be signed\n");
			return NT_STATUS_INTERNAL_ERROR;
		}
	}
	msg_id = BVAL(hdr, SMB2_HDR_MESSAGE_ID);
	if (msg_id == 0) {
		if (opcode != SMB2_OP_CANCEL ||
		    sign_algo_id >= SMB2_SIGNING_AES128_GMAC)
		{
			DBG_ERR("opcode[%u] msg_id == 0\n", opcode);
			return NT_STATUS_INTERNAL_ERROR;
		}
		/*
		 * Legacy algorithms allow MID 0
		 * for cancel requests
		 */
	}
	if (msg_id == UINT64_MAX) {
		DBG_ERR("opcode[%u] msg_id == UINT64_MAX\n", opcode);
		return NT_STATUS_INTERNAL_ERROR;
	}

	switch (sign_algo_id) {
	case SMB2_SIGNING_AES128_GMAC: {
		gnutls_cipher_algorithm_t algo = GNUTLS_CIPHER_AES_128_GCM;
		uint32_t key_size = gnutls_cipher_get_key_size(algo);
		uint32_t iv_size = gnutls_cipher_get_iv_size(algo);
		size_t tag_size = gnutls_cipher_get_tag_size(algo);
		gnutls_datum_t key = {
			.data = signing_key->blob.data,
			.size = MIN(signing_key->blob.length, key_size),
		};
		uint64_t high_bits = 0;
		uint8_t iv[AES_BLOCK_SIZE] = {0};
		giovec_t auth_iov[count+1];
		size_t auth_iovcnt = 0;
		NTSTATUS status;
		int rc;

		high_bits = flags & SMB2_HDR_FLAG_REDIRECT;
		if (opcode == SMB2_OP_CANCEL) {
			high_bits |= SMB2_HDR_FLAG_ASYNC;
		}
		SBVAL(iv, 0, msg_id);
		SBVAL(iv, 8, high_bits);

		if (signing_key->cipher_hnd == NULL) {
			rc = gnutls_aead_cipher_init(&signing_key->cipher_hnd,
						     algo,
					             &key);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}

		SMB_ASSERT(key_size == 16);
		SMB_ASSERT(iv_size == 12);
		SMB_ASSERT(tag_size == 16);

		auth_iov[auth_iovcnt++] = (giovec_t) {
			.iov_base = discard_const_p(uint8_t, hdr),
			.iov_len  = SMB2_HDR_SIGNATURE,
		};
		auth_iov[auth_iovcnt++] = (giovec_t) {
			.iov_base = discard_const_p(uint8_t, zero_sig),
			.iov_len  = 16,
		};
		for (i=1; i < count; i++) {
			auth_iov[auth_iovcnt++] = (giovec_t) {
				.iov_base = discard_const_p(uint8_t, vector[i].iov_base),
				.iov_len  = vector[i].iov_len,
			};
		}

		status = smb2_signing_gmac(signing_key->cipher_hnd,
					   iv,
					   iv_size,
					   auth_iov,
					   auth_iovcnt,
					   signature,
					   tag_size);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		return NT_STATUS_OK;
	}	break;

	case SMB2_SIGNING_AES128_CMAC:
		hmac_algo = GNUTLS_MAC_AES_CMAC_128;
		break;
	case SMB2_SIGNING_HMAC_SHA256:
		hmac_algo = GNUTLS_MAC_SHA256;
		break;

	default:
		return NT_STATUS_HMAC_NOT_SUPPORTED;
	}

	if (hmac_algo != GNUTLS_MAC_UNKNOWN) {
		uint8_t digest[gnutls_hmac_get_len(hmac_algo)];
		gnutls_datum_t key = {
			.data = signing_key->blob.data,
			.size = MIN(signing_key->blob.length, 16),
		};
		int rc;

		if (signing_key->hmac_hnd == NULL) {
			rc = gnutls_hmac_init(&signing_key->hmac_hnd,
					      hmac_algo,
					      key.data,
					      key.size);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}

		rc = gnutls_hmac(signing_key->hmac_hnd, hdr, SMB2_HDR_SIGNATURE);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
		}
		rc = gnutls_hmac(signing_key->hmac_hnd, zero_sig, 16);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		for (i = 1; i < count; i++) {
			rc = gnutls_hmac(signing_key->hmac_hnd,
					 vector[i].iov_base,
					 vector[i].iov_len);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}
		gnutls_hmac_output(signing_key->hmac_hnd, digest);
		memcpy(signature, digest, 16);
		ZERO_ARRAY(digest);
		return NT_STATUS_OK;
	}

	return NT_STATUS_HMAC_NOT_SUPPORTED;
}

NTSTATUS smb2_signing_sign_pdu(struct smb2_signing_key *signing_key,
			       struct iovec *vector,
			       int count)
{
	uint16_t sign_algo_id;
	uint8_t *hdr;
	uint64_t session_id;
	uint8_t res[16];
	NTSTATUS status;

	/*
	 * We expect
	 * - SMB2 HDR
	 * - SMB2 BODY FIXED
	 * - (optional) SMB2 BODY DYN
	 * - (optional) PADDING
	 */
	SMB_ASSERT(count >= 2);
	SMB_ASSERT(vector[0].iov_len == SMB2_HDR_BODY);
	SMB_ASSERT(count <= 4);

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

	sign_algo_id = signing_key->sign_algo_id;

	status = smb2_signing_calc_signature(signing_key,
					     sign_algo_id,
					     vector,
					     count,
					     res);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smb2_signing_calc_signature(sign_algo_id=%u) - %s\n",
			(unsigned)sign_algo_id, nt_errstr(status));
		if (NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR)) {
			smb_panic(__location__);
		}
		return status;
	}

	DEBUG(5,("signed SMB2 message (sign_algo_id=%u)\n",
		 (unsigned)sign_algo_id));

	memcpy(hdr + SMB2_HDR_SIGNATURE, res, 16);

	return NT_STATUS_OK;
}

NTSTATUS smb2_signing_check_pdu(struct smb2_signing_key *signing_key,
				const struct iovec *vector,
				int count)
{
	uint16_t sign_algo_id;
	const uint8_t *hdr;
	const uint8_t *sig;
	uint64_t session_id;
	uint8_t res[16];
	NTSTATUS status;

	/*
	 * We expect
	 * - SMB2 HDR
	 * - SMB2 BODY FIXED
	 * - (optional) SMB2 BODY DYN
	 * - (optional) PADDING
	 */
	SMB_ASSERT(count >= 2);
	SMB_ASSERT(vector[0].iov_len == SMB2_HDR_BODY);
	SMB_ASSERT(count <= 4);

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

	sign_algo_id = signing_key->sign_algo_id;

	status = smb2_signing_calc_signature(signing_key,
					     sign_algo_id,
					     vector,
					     count,
					     res);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smb2_signing_calc_signature(sign_algo_id=%u) - %s\n",
			(unsigned)sign_algo_id, nt_errstr(status));
		if (NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR)) {
			status = NT_STATUS_ACCESS_DENIED;
		}
		return status;
	}

	if (!mem_equal_const_time(res, sig, 16)) {
		DEBUG(0,("Bad SMB2 (sign_algo_id=%u) signature for message\n",
			 (unsigned)sign_algo_id));
		dump_data(0, sig, 16);
		dump_data(0, res, 16);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

NTSTATUS smb2_signing_encrypt_pdu(struct smb2_signing_key *encryption_key,
				  struct iovec *vector,
				  int count)
{
	bool use_encryptv2 = false;
	uint16_t cipher_id;
	uint8_t *tf;
	size_t a_total;
	ssize_t m_total;
	uint32_t iv_size = 0;
	uint32_t key_size = 0;
	size_t tag_size = 0;
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
	cipher_id = encryption_key->cipher_algo_id;

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
#ifdef ALLOW_GNUTLS_AEAD_CIPHER_ENCRYPTV2_AES_CCM
		use_encryptv2 = true;
#endif
		break;
	case SMB2_ENCRYPTION_AES128_GCM:
		algo = GNUTLS_CIPHER_AES_128_GCM;
		iv_size = gnutls_cipher_get_iv_size(algo);
		use_encryptv2 = true;
		break;
	case SMB2_ENCRYPTION_AES256_CCM:
		algo = GNUTLS_CIPHER_AES_256_CCM;
		iv_size = SMB2_AES_128_CCM_NONCE_SIZE;
#ifdef ALLOW_GNUTLS_AEAD_CIPHER_ENCRYPTV2_AES_CCM
		use_encryptv2 = true;
#endif
		break;
	case SMB2_ENCRYPTION_AES256_GCM:
		algo = GNUTLS_CIPHER_AES_256_GCM;
		iv_size = gnutls_cipher_get_iv_size(algo);
		use_encryptv2 = true;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	key_size = gnutls_cipher_get_key_size(algo);
	tag_size = gnutls_cipher_get_tag_size(algo);

	if (key_size != encryption_key->blob.length) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (tag_size != 16) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = (gnutls_datum_t) {
		.data = encryption_key->blob.data,
		.size = key_size,
	};

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

	if (use_encryptv2) {
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
	} else
	{
		size_t ptext_size = m_total;
		uint8_t *ptext = NULL;
		size_t ctext_size = m_total + tag_size;
		uint8_t *ctext = NULL;
		size_t len = 0;
		int i;
		TALLOC_CTX *tmp_ctx = NULL;

		/*
		 * If we come from python bindings, we don't have a stackframe
		 * around, so use the NULL context.
		 *
		 * This is fine as we make sure we free the memory.
		 */
		if (talloc_stackframe_exists()) {
			tmp_ctx = talloc_tos();
		}

		ptext = talloc_size(tmp_ctx, ptext_size);
		if (ptext == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		ctext = talloc_size(tmp_ctx, ctext_size);
		if (ctext == NULL) {
			TALLOC_FREE(ptext);
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		for (i = 1; i < count; i++) {
			if (vector[i].iov_base != NULL) {
				memcpy(ptext + len,
				       vector[i].iov_base,
				       vector[i].iov_len);
			}

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
			if (vector[i].iov_base != NULL) {
				memcpy(vector[i].iov_base,
				       ctext + len,
				       vector[i].iov_len);
			}

			len += vector[i].iov_len;
		}

		memcpy(tf + SMB2_TF_SIGNATURE, ctext + m_total, tag_size);

		TALLOC_FREE(ptext);
		TALLOC_FREE(ctext);
	}

	DBG_INFO("Encrypted SMB2 message\n");

	status = NT_STATUS_OK;
out:
	return status;
}

NTSTATUS smb2_signing_decrypt_pdu(struct smb2_signing_key *decryption_key,
				  struct iovec *vector,
				  int count)
{
	bool use_encryptv2 = false;
	uint16_t cipher_id;
	uint8_t *tf;
	uint16_t flags;
	size_t a_total;
	ssize_t m_total;
	uint32_t msg_size = 0;
	uint32_t iv_size = 0;
	uint32_t key_size = 0;
	size_t tag_size = 0;
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
	cipher_id = decryption_key->cipher_algo_id;

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
#ifdef ALLOW_GNUTLS_AEAD_CIPHER_ENCRYPTV2_AES_CCM
		use_encryptv2 = true;
#endif
		break;
	case SMB2_ENCRYPTION_AES128_GCM:
		algo = GNUTLS_CIPHER_AES_128_GCM;
		iv_size = gnutls_cipher_get_iv_size(algo);
		use_encryptv2 = true;
		break;
	case SMB2_ENCRYPTION_AES256_CCM:
		algo = GNUTLS_CIPHER_AES_256_CCM;
		iv_size = SMB2_AES_128_CCM_NONCE_SIZE;
#ifdef ALLOW_GNUTLS_AEAD_CIPHER_ENCRYPTV2_AES_CCM
		use_encryptv2 = true;
#endif
		break;
	case SMB2_ENCRYPTION_AES256_GCM:
		algo = GNUTLS_CIPHER_AES_256_GCM;
		iv_size = gnutls_cipher_get_iv_size(algo);
		use_encryptv2 = true;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	key_size = gnutls_cipher_get_key_size(algo);
	tag_size = gnutls_cipher_get_tag_size(algo);

	if (key_size != decryption_key->blob.length) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (tag_size != 16) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = (gnutls_datum_t) {
		.data = decryption_key->blob.data,
		.size = key_size,
	};

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

	if (use_encryptv2) {
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
	} else
	{
		size_t ctext_size = m_total + tag_size;
		uint8_t *ctext = NULL;
		size_t ptext_size = m_total;
		uint8_t *ptext = NULL;
		size_t len = 0;
		int i;
		TALLOC_CTX *tmp_ctx = NULL;

		/*
		 * If we come from python bindings, we don't have a stackframe
		 * around, so use the NULL context.
		 *
		 * This is fine as we make sure we free the memory.
		 */
		if (talloc_stackframe_exists()) {
			tmp_ctx = talloc_tos();
		}

		/* GnuTLS doesn't have a iovec API for decryption yet */

		ptext = talloc_size(tmp_ctx, ptext_size);
		if (ptext == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		ctext = talloc_size(tmp_ctx, ctext_size);
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
		if (rc < 0) {
			TALLOC_FREE(ptext);
			TALLOC_FREE(ctext);
			status = gnutls_error_to_ntstatus(rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}
		if (ptext_size != m_total) {
			TALLOC_FREE(ptext);
			TALLOC_FREE(ctext);
			rc = GNUTLS_E_SHORT_MEMORY_BUFFER;
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

	DBG_INFO("Decrypted SMB2 message\n");

	status = NT_STATUS_OK;
out:
	return status;
}
