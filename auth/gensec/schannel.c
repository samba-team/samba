/*
   Unix SMB/CIFS implementation.

   dcerpc schannel operations

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005

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
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "librpc/gen_ndr/ndr_schannel.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/gensec/gensec_proto.h"
#include "../libcli/auth/schannel.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "param/param.h"
#include "auth/gensec/gensec_toplevel_proto.h"
#include "libds/common/roles.h"

#ifndef HAVE_GNUTLS_AES_CFB8
#include "lib/crypto/aes.h"
#endif

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

struct schannel_state {
	struct gensec_security *gensec;
	uint64_t seq_num;
	bool initiator;
	struct netlogon_creds_CredentialState *creds;
	struct auth_user_info_dc *user_info_dc;
};

#define SETUP_SEQNUM(state, buf, initiator) do { \
	uint8_t *_buf = buf; \
	uint32_t _seq_num_low = (state)->seq_num & UINT32_MAX; \
	uint32_t _seq_num_high = (state)->seq_num >> 32; \
	if (initiator) { \
		_seq_num_high |= 0x80000000; \
	} \
	RSIVAL(_buf, 0, _seq_num_low); \
	RSIVAL(_buf, 4, _seq_num_high); \
} while(0)

static struct schannel_state *netsec_create_state(
				struct gensec_security *gensec,
				struct netlogon_creds_CredentialState *creds,
				bool initiator)
{
	struct schannel_state *state;

	state = talloc_zero(gensec, struct schannel_state);
	if (state == NULL) {
		return NULL;
	}

	state->gensec = gensec;
	state->initiator = initiator;
	state->creds = netlogon_creds_copy(state, creds);
	if (state->creds == NULL) {
		talloc_free(state);
		return NULL;
	}

	gensec->private_data = state;

	return state;
}

static void netsec_offset_and_sizes(struct schannel_state *state,
				    bool do_seal,
				    uint32_t *_min_sig_size,
				    uint32_t *_used_sig_size,
				    uint32_t *_checksum_length,
				    uint32_t *_confounder_ofs)
{
	uint32_t min_sig_size;
	uint32_t used_sig_size;
	uint32_t checksum_length;
	uint32_t confounder_ofs;

	if (state->creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		min_sig_size = 48;
		used_sig_size = 56;
		/*
		 * Note: windows has a bug here and uses the old values...
		 *
		 * checksum_length = 32;
		 * confounder_ofs = 48;
		 */
		checksum_length = 8;
		confounder_ofs = 24;
	} else {
		min_sig_size = 24;
		used_sig_size = 32;
		checksum_length = 8;
		confounder_ofs = 24;
	}

	if (do_seal) {
		min_sig_size += 8;
	}

	if (_min_sig_size) {
		*_min_sig_size = min_sig_size;
	}

	if (_used_sig_size) {
		*_used_sig_size = used_sig_size;
	}

	if (_checksum_length) {
		*_checksum_length = checksum_length;
	}

	if (_confounder_ofs) {
		*_confounder_ofs = confounder_ofs;
	}
}

/*******************************************************************
 Encode or Decode the sequence number (which is symmetric)
 ********************************************************************/
static NTSTATUS netsec_do_seq_num(struct schannel_state *state,
				  const uint8_t *checksum,
				  uint32_t checksum_length,
				  uint8_t seq_num[8])
{
	if (state->creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
#ifdef HAVE_GNUTLS_AES_CFB8
		gnutls_cipher_hd_t cipher_hnd = NULL;
		gnutls_datum_t key = {
			.data = state->creds->session_key,
			.size = sizeof(state->creds->session_key),
		};
		uint32_t iv_size =
			gnutls_cipher_get_iv_size(GNUTLS_CIPHER_AES_128_CFB8);
		uint8_t _iv[iv_size];
		gnutls_datum_t iv = {
			.data = _iv,
			.size = iv_size,
		};
		int rc;

		ZERO_ARRAY(_iv);

		memcpy(iv.data + 0, checksum, 8);
		memcpy(iv.data + 8, checksum, 8);

		rc = gnutls_cipher_init(&cipher_hnd,
					GNUTLS_CIPHER_AES_128_CFB8,
					&key,
					&iv);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc,
							NT_STATUS_CRYPTO_SYSTEM_INVALID);
		}

		rc = gnutls_cipher_encrypt(cipher_hnd, seq_num, 8);
		gnutls_cipher_deinit(cipher_hnd);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc,
							NT_STATUS_CRYPTO_SYSTEM_INVALID);
		}

#else /* NOT HAVE_GNUTLS_AES_CFB8 */
		AES_KEY key;
		uint8_t iv[AES_BLOCK_SIZE];

		AES_set_encrypt_key(state->creds->session_key, 128, &key);
		ZERO_STRUCT(iv);
		memcpy(iv+0, checksum, 8);
		memcpy(iv+8, checksum, 8);

		aes_cfb8_encrypt(seq_num, seq_num, 8, &key, iv, AES_ENCRYPT);
#endif /* HAVE_GNUTLS_AES_CFB8 */
	} else {
		static const uint8_t zeros[4];
		uint8_t _sequence_key[16];
		gnutls_cipher_hd_t cipher_hnd;
		gnutls_datum_t sequence_key = {
			.data = _sequence_key,
			.size = sizeof(_sequence_key),
		};
		uint8_t digest1[16];
		int rc;

		rc = gnutls_hmac_fast(GNUTLS_MAC_MD5,
				      state->creds->session_key,
				      sizeof(state->creds->session_key),
				      zeros,
				      sizeof(zeros),
				      digest1);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		rc = gnutls_hmac_fast(GNUTLS_MAC_MD5,
				      digest1,
				      sizeof(digest1),
				      checksum,
				      checksum_length,
				      _sequence_key);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		ZERO_ARRAY(digest1);

		rc = gnutls_cipher_init(&cipher_hnd,
					GNUTLS_CIPHER_ARCFOUR_128,
					&sequence_key,
					NULL);
		if (rc < 0) {
			ZERO_ARRAY(_sequence_key);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		rc = gnutls_cipher_encrypt(cipher_hnd,
					   seq_num,
					   8);
		gnutls_cipher_deinit(cipher_hnd);
		ZERO_ARRAY(_sequence_key);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
	}

	state->seq_num++;

	return NT_STATUS_OK;
}

static NTSTATUS netsec_do_seal(struct schannel_state *state,
			       const uint8_t seq_num[8],
			       uint8_t confounder[8],
			       uint8_t *data, uint32_t length,
			       bool forward)
{
	if (state->creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
#ifdef HAVE_GNUTLS_AES_CFB8
		gnutls_cipher_hd_t cipher_hnd = NULL;
		uint8_t sess_kf0[16] = {0};
		gnutls_datum_t key = {
			.data = sess_kf0,
			.size = sizeof(sess_kf0),
		};
		uint32_t iv_size =
			gnutls_cipher_get_iv_size(GNUTLS_CIPHER_AES_128_CFB8);
		uint8_t _iv[iv_size];
		gnutls_datum_t iv = {
			.data = _iv,
			.size = iv_size,
		};
		uint32_t i;
		int rc;

		for (i = 0; i < key.size; i++) {
			key.data[i] = state->creds->session_key[i] ^ 0xf0;
		}

		ZERO_ARRAY(_iv);

		memcpy(iv.data + 0, seq_num, 8);
		memcpy(iv.data + 8, seq_num, 8);

		rc = gnutls_cipher_init(&cipher_hnd,
					GNUTLS_CIPHER_AES_128_CFB8,
					&key,
					&iv);
		if (rc < 0) {
			DBG_ERR("ERROR: gnutls_cipher_init: %s\n",
				gnutls_strerror(rc));
			return NT_STATUS_NO_MEMORY;
		}

		if (forward) {
			rc = gnutls_cipher_encrypt(cipher_hnd,
						   confounder,
						   8);
			if (rc < 0) {
				gnutls_cipher_deinit(cipher_hnd);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
			}

			rc = gnutls_cipher_encrypt(cipher_hnd,
						   data,
						   length);
			if (rc < 0) {
				gnutls_cipher_deinit(cipher_hnd);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
			}
		} else {

			/*
			 * Workaround bug present in gnutls 3.6.8:
			 *
			 * gnutls_cipher_decrypt() uses an optimization
			 * internally that breaks decryption when processing
			 * buffers with their length not being a multiple
			 * of the blocksize.
			 */

			uint8_t tmp[16] = { 0, };
			uint32_t tmp_dlength = MIN(length, sizeof(tmp) - 8);

			memcpy(tmp, confounder, 8);
			memcpy(tmp + 8, data, tmp_dlength);

			rc = gnutls_cipher_decrypt(cipher_hnd,
						   tmp,
						   8 + tmp_dlength);
			if (rc < 0) {
				ZERO_STRUCT(tmp);
				gnutls_cipher_deinit(cipher_hnd);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
			}

			memcpy(confounder, tmp, 8);
			memcpy(data, tmp + 8, tmp_dlength);
			ZERO_STRUCT(tmp);

			if (length > tmp_dlength) {
				rc = gnutls_cipher_decrypt(cipher_hnd,
							   data + tmp_dlength,
							   length - tmp_dlength);
				if (rc < 0) {
					gnutls_cipher_deinit(cipher_hnd);
					return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
				}
			}
		}
		gnutls_cipher_deinit(cipher_hnd);
#else /* NOT HAVE_GNUTLS_AES_CFB8 */
		AES_KEY key;
		uint8_t iv[AES_BLOCK_SIZE];
		uint8_t sess_kf0[16];
		int i;

		for (i = 0; i < 16; i++) {
			sess_kf0[i] = state->creds->session_key[i] ^ 0xf0;
		}

		AES_set_encrypt_key(sess_kf0, 128, &key);
		ZERO_STRUCT(iv);
		memcpy(iv+0, seq_num, 8);
		memcpy(iv+8, seq_num, 8);

		if (forward) {
			aes_cfb8_encrypt(confounder, confounder, 8, &key, iv, AES_ENCRYPT);
			aes_cfb8_encrypt(data, data, length, &key, iv, AES_ENCRYPT);
		} else {
			aes_cfb8_encrypt(confounder, confounder, 8, &key, iv, AES_DECRYPT);
			aes_cfb8_encrypt(data, data, length, &key, iv, AES_DECRYPT);
		}
#endif /* HAVE_GNUTLS_AES_CFB8 */
	} else {
		gnutls_cipher_hd_t cipher_hnd;
		uint8_t _sealing_key[16];
		gnutls_datum_t sealing_key = {
			.data = _sealing_key,
			.size = sizeof(_sealing_key),
		};
		static const uint8_t zeros[4];
		uint8_t digest2[16];
		uint8_t sess_kf0[16];
		int rc;
		int i;

		for (i = 0; i < 16; i++) {
			sess_kf0[i] = state->creds->session_key[i] ^ 0xf0;
		}

		rc = gnutls_hmac_fast(GNUTLS_MAC_MD5,
				      sess_kf0,
				      sizeof(sess_kf0),
				      zeros,
				      4,
				      digest2);
		if (rc < 0) {
			ZERO_ARRAY(digest2);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		rc = gnutls_hmac_fast(GNUTLS_MAC_MD5,
				      digest2,
				      sizeof(digest2),
				      seq_num,
				      8,
				      _sealing_key);

		ZERO_ARRAY(digest2);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		rc = gnutls_cipher_init(&cipher_hnd,
					GNUTLS_CIPHER_ARCFOUR_128,
					&sealing_key,
					NULL);
		if (rc < 0) {
			ZERO_ARRAY(_sealing_key);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		}
		rc = gnutls_cipher_encrypt(cipher_hnd,
					   confounder,
					   8);
		if (rc < 0) {
			ZERO_ARRAY(_sealing_key);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		}
		gnutls_cipher_deinit(cipher_hnd);
		rc = gnutls_cipher_init(&cipher_hnd,
					GNUTLS_CIPHER_ARCFOUR_128,
					&sealing_key,
					NULL);
		if (rc < 0) {
			ZERO_ARRAY(_sealing_key);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		}
		rc = gnutls_cipher_encrypt(cipher_hnd,
					   data,
					   length);
		gnutls_cipher_deinit(cipher_hnd);
		ZERO_ARRAY(_sealing_key);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		}
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Create a digest over the entire packet (including the data), and
 MD5 it with the session key.
 ********************************************************************/
static NTSTATUS netsec_do_sign(struct schannel_state *state,
			       const uint8_t *confounder,
			       const uint8_t *data, size_t length,
			       uint8_t header[8],
			       uint8_t *checksum)
{
	if (state->creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		gnutls_hmac_hd_t hmac_hnd = NULL;
		int rc;

		rc = gnutls_hmac_init(&hmac_hnd,
				      GNUTLS_MAC_SHA256,
				      state->creds->session_key,
				      sizeof(state->creds->session_key));
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		if (confounder) {
			SSVAL(header, 0, NL_SIGN_HMAC_SHA256);
			SSVAL(header, 2, NL_SEAL_AES128);
			SSVAL(header, 4, 0xFFFF);
			SSVAL(header, 6, 0x0000);

			rc = gnutls_hmac(hmac_hnd, header, 8);
			if (rc < 0) {
				gnutls_hmac_deinit(hmac_hnd, NULL);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
			rc = gnutls_hmac(hmac_hnd, confounder, 8);
			if (rc < 0) {
				gnutls_hmac_deinit(hmac_hnd, NULL);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		} else {
			SSVAL(header, 0, NL_SIGN_HMAC_SHA256);
			SSVAL(header, 2, NL_SEAL_NONE);
			SSVAL(header, 4, 0xFFFF);
			SSVAL(header, 6, 0x0000);

			rc = gnutls_hmac(hmac_hnd, header, 8);
			if (rc < 0) {
				gnutls_hmac_deinit(hmac_hnd, NULL);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}

		rc = gnutls_hmac(hmac_hnd, data, length);
		if (rc < 0) {
			gnutls_hmac_deinit(hmac_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		gnutls_hmac_deinit(hmac_hnd, checksum);
	} else {
		uint8_t packet_digest[16];
		static const uint8_t zeros[4];
		gnutls_hash_hd_t hash_hnd = NULL;
		int rc;

		rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_MD5);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}

		rc = gnutls_hash(hash_hnd, zeros, sizeof(zeros));
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
		if (confounder) {
			SSVAL(header, 0, NL_SIGN_HMAC_MD5);
			SSVAL(header, 2, NL_SEAL_RC4);
			SSVAL(header, 4, 0xFFFF);
			SSVAL(header, 6, 0x0000);

			rc = gnutls_hash(hash_hnd, header, 8);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
			rc = gnutls_hash(hash_hnd, confounder, 8);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		} else {
			SSVAL(header, 0, NL_SIGN_HMAC_MD5);
			SSVAL(header, 2, NL_SEAL_NONE);
			SSVAL(header, 4, 0xFFFF);
			SSVAL(header, 6, 0x0000);

			rc = gnutls_hash(hash_hnd, header, 8);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
			}
		}
		rc = gnutls_hash(hash_hnd, data, length);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
		gnutls_hash_deinit(hash_hnd, packet_digest);

		rc = gnutls_hmac_fast(GNUTLS_MAC_MD5,
				      state->creds->session_key,
				      sizeof(state->creds->session_key),
				      packet_digest,
				      sizeof(packet_digest),
				      checksum);
		ZERO_ARRAY(packet_digest);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS netsec_incoming_packet(struct schannel_state *state,
				bool do_unseal,
				uint8_t *data, size_t length,
				const uint8_t *whole_pdu, size_t pdu_length,
				const DATA_BLOB *sig)
{
	uint32_t min_sig_size = 0;
	uint8_t header[8];
	uint8_t checksum[32];
	uint32_t checksum_length = sizeof(checksum_length);
	uint8_t _confounder[8];
	uint8_t *confounder = NULL;
	uint32_t confounder_ofs = 0;
	uint8_t seq_num[8];
	int ret;
	const uint8_t *sign_data = NULL;
	size_t sign_length = 0;
	NTSTATUS status;

	netsec_offset_and_sizes(state,
				do_unseal,
				&min_sig_size,
				NULL,
				&checksum_length,
				&confounder_ofs);

	if (sig->length < min_sig_size) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (do_unseal) {
		confounder = _confounder;
		memcpy(confounder, sig->data+confounder_ofs, 8);
	} else {
		confounder = NULL;
	}

	SETUP_SEQNUM(state, seq_num, !state->initiator);

	if (do_unseal) {
		status = netsec_do_seal(state,
					seq_num,
					confounder,
					data,
					length,
					false);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("netsec_do_seal failed: %s\n", nt_errstr(status));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (state->gensec->want_features & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		sign_data = whole_pdu;
		sign_length = pdu_length;
	} else {
		sign_data = data;
		sign_length = length;
	}

	status = netsec_do_sign(state,
				confounder,
				sign_data,
				sign_length,
				header,
				checksum);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("netsec_do_sign failed: %s\n", nt_errstr(status));
		return NT_STATUS_ACCESS_DENIED;
	}

	ret = memcmp(checksum, sig->data+16, checksum_length);
	if (ret != 0) {
		dump_data_pw("calc digest:", checksum, checksum_length);
		dump_data_pw("wire digest:", sig->data+16, checksum_length);
		return NT_STATUS_ACCESS_DENIED;
	}

	status = netsec_do_seq_num(state, checksum, checksum_length, seq_num);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("netsec_do_seq_num failed: %s\n",
			    nt_errstr(status));
		return status;
	}

	ZERO_ARRAY(checksum);

	ret = memcmp(seq_num, sig->data+8, 8);
	if (ret != 0) {
		dump_data_pw("calc seq num:", seq_num, 8);
		dump_data_pw("wire seq num:", sig->data+8, 8);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

static uint32_t netsec_outgoing_sig_size(struct schannel_state *state)
{
	uint32_t sig_size = 0;

	netsec_offset_and_sizes(state,
				true,
				NULL,
				&sig_size,
				NULL,
				NULL);

	return sig_size;
}

static NTSTATUS netsec_outgoing_packet(struct schannel_state *state,
				TALLOC_CTX *mem_ctx,
				bool do_seal,
				uint8_t *data, size_t length,
				const uint8_t *whole_pdu, size_t pdu_length,
				DATA_BLOB *sig)
{
	uint32_t min_sig_size = 0;
	uint32_t used_sig_size = 0;
	uint8_t header[8];
	uint8_t checksum[32];
	uint32_t checksum_length = sizeof(checksum_length);
	uint8_t _confounder[8];
	uint8_t *confounder = NULL;
	uint32_t confounder_ofs = 0;
	uint8_t seq_num[8];
	const uint8_t *sign_data = NULL;
	size_t sign_length = 0;
	NTSTATUS status;

	netsec_offset_and_sizes(state,
				do_seal,
				&min_sig_size,
				&used_sig_size,
				&checksum_length,
				&confounder_ofs);

	SETUP_SEQNUM(state, seq_num, state->initiator);

	if (do_seal) {
		confounder = _confounder;
		generate_random_buffer(confounder, 8);
	} else {
		confounder = NULL;
	}

	if (state->gensec->want_features & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		sign_data = whole_pdu;
		sign_length = pdu_length;
	} else {
		sign_data = data;
		sign_length = length;
	}

	status = netsec_do_sign(state,
				confounder,
				sign_data,
				sign_length,
				header,
				checksum);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("netsec_do_sign failed: %s\n", nt_errstr(status));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (do_seal) {
		status = netsec_do_seal(state,
					seq_num,
					confounder,
					data,
					length,
					true);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("netsec_do_seal failed: %s\n",
				    nt_errstr(status));
			return status;
		}
	}

	status = netsec_do_seq_num(state, checksum, checksum_length, seq_num);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("netsec_do_seq_num failed: %s\n",
			    nt_errstr(status));
		return status;
	}

	(*sig) = data_blob_talloc_zero(mem_ctx, used_sig_size);

	memcpy(sig->data, header, 8);
	memcpy(sig->data+8, seq_num, 8);
	memcpy(sig->data+16, checksum, checksum_length);

	if (confounder) {
		memcpy(sig->data+confounder_ofs, confounder, 8);
	}

	dump_data_pw("signature:", sig->data+ 0, 8);
	dump_data_pw("seq_num  :", sig->data+ 8, 8);
	dump_data_pw("digest   :", sig->data+16, checksum_length);
	dump_data_pw("confound :", sig->data+confounder_ofs, 8);

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS gensec_schannel_init(TALLOC_CTX *ctx);

static size_t schannel_sig_size(struct gensec_security *gensec_security, size_t data_size)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_outgoing_sig_size(state);
}

struct schannel_update_state {
	NTSTATUS status;
	DATA_BLOB out;
};

static NTSTATUS schannel_update_internal(struct gensec_security *gensec_security,
					 TALLOC_CTX *out_mem_ctx,
					 const DATA_BLOB in, DATA_BLOB *out);

static struct tevent_req *schannel_update_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct gensec_security *gensec_security,
					       const DATA_BLOB in)
{
	struct tevent_req *req;
	struct schannel_update_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct schannel_update_state);
	if (req == NULL) {
		return NULL;
	}

	status = schannel_update_internal(gensec_security,
					  state, in,
					  &state->out);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS schannel_update_internal(struct gensec_security *gensec_security,
					 TALLOC_CTX *out_mem_ctx,
					 const DATA_BLOB in, DATA_BLOB *out)
{
	struct schannel_state *state =
		talloc_get_type(gensec_security->private_data,
		struct schannel_state);
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	struct NL_AUTH_MESSAGE bind_schannel = {
		.Flags = 0,
	};
	struct NL_AUTH_MESSAGE bind_schannel_ack;
	struct netlogon_creds_CredentialState *creds;
	const char *workstation;
	const char *domain;

	*out = data_blob(NULL, 0);

	if (gensec_security->dcerpc_auth_level < DCERPC_AUTH_LEVEL_INTEGRITY) {
		switch (gensec_security->gensec_role) {
		case GENSEC_CLIENT:
			return NT_STATUS_INVALID_PARAMETER_MIX;
		case GENSEC_SERVER:
			return NT_STATUS_INVALID_PARAMETER;
		}
		return NT_STATUS_INTERNAL_ERROR;
	}

	switch (gensec_security->gensec_role) {
	case GENSEC_CLIENT:
		if (state != NULL) {
			/* we could parse the bind ack, but we don't know what it is yet */
			return NT_STATUS_OK;
		}

		creds = cli_credentials_get_netlogon_creds(gensec_security->credentials);
		if (creds == NULL) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}

		state = netsec_create_state(gensec_security,
					    creds, true /* initiator */);
		if (state == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		bind_schannel.MessageType = NL_NEGOTIATE_REQUEST;

		bind_schannel.Flags = NL_FLAG_OEM_NETBIOS_DOMAIN_NAME |
				      NL_FLAG_OEM_NETBIOS_COMPUTER_NAME;
		bind_schannel.oem_netbios_domain.a = cli_credentials_get_domain(gensec_security->credentials);
		bind_schannel.oem_netbios_computer.a = creds->computer_name;

		if (creds->secure_channel_type == SEC_CHAN_DNS_DOMAIN) {
			bind_schannel.Flags |= NL_FLAG_UTF8_DNS_DOMAIN_NAME;
			bind_schannel.utf8_dns_domain.u = cli_credentials_get_realm(gensec_security->credentials);

			bind_schannel.Flags |= NL_FLAG_UTF8_NETBIOS_COMPUTER_NAME;
			bind_schannel.utf8_netbios_computer.u = creds->computer_name;
		}

		ndr_err = ndr_push_struct_blob(out, out_mem_ctx, &bind_schannel,
					       (ndr_push_flags_fn_t)ndr_push_NL_AUTH_MESSAGE);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(3, ("Could not create schannel bind: %s\n",
				  nt_errstr(status)));
			return status;
		}

		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	case GENSEC_SERVER:

		if (state != NULL) {
			/* no third leg on this protocol */
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* parse the schannel startup blob */
		ndr_err = ndr_pull_struct_blob(&in, out_mem_ctx, &bind_schannel,
			(ndr_pull_flags_fn_t)ndr_pull_NL_AUTH_MESSAGE);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(3, ("Could not parse incoming schannel bind: %s\n",
				  nt_errstr(status)));
			return status;
		}

		if (bind_schannel.Flags & NL_FLAG_OEM_NETBIOS_DOMAIN_NAME) {
			domain = bind_schannel.oem_netbios_domain.a;
			if (strcasecmp_m(domain, lpcfg_workgroup(gensec_security->settings->lp_ctx)) != 0) {
				DEBUG(3, ("Request for schannel to incorrect domain: %s != our domain %s\n",
					  domain, lpcfg_workgroup(gensec_security->settings->lp_ctx)));
				return NT_STATUS_LOGON_FAILURE;
			}
		} else if (bind_schannel.Flags & NL_FLAG_UTF8_DNS_DOMAIN_NAME) {
			domain = bind_schannel.utf8_dns_domain.u;
			if (strcasecmp_m(domain, lpcfg_dnsdomain(gensec_security->settings->lp_ctx)) != 0) {
				DEBUG(3, ("Request for schannel to incorrect domain: %s != our domain %s\n",
					  domain, lpcfg_dnsdomain(gensec_security->settings->lp_ctx)));
				return NT_STATUS_LOGON_FAILURE;
			}
		} else {
			DEBUG(3, ("Request for schannel to without domain\n"));
			return NT_STATUS_LOGON_FAILURE;
		}

		if (bind_schannel.Flags & NL_FLAG_OEM_NETBIOS_COMPUTER_NAME) {
			workstation = bind_schannel.oem_netbios_computer.a;
		} else if (bind_schannel.Flags & NL_FLAG_UTF8_NETBIOS_COMPUTER_NAME) {
			workstation = bind_schannel.utf8_netbios_computer.u;
		} else {
			DEBUG(3, ("Request for schannel to without netbios workstation\n"));
			return NT_STATUS_LOGON_FAILURE;
		}

		status = schannel_get_creds_state(out_mem_ctx,
						  gensec_security->settings->lp_ctx,
						  workstation, &creds);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Could not find session key for attempted schannel connection from %s: %s\n",
				  workstation, nt_errstr(status)));
			if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
				return NT_STATUS_LOGON_FAILURE;
			}
			return status;
		}

		state = netsec_create_state(gensec_security,
					    creds, false /* not initiator */);
		if (state == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = auth_anonymous_user_info_dc(state,
				lpcfg_netbios_name(gensec_security->settings->lp_ctx),
				&state->user_info_dc);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		bind_schannel_ack.MessageType = NL_NEGOTIATE_RESPONSE;
		bind_schannel_ack.Flags = 0;
		bind_schannel_ack.Buffer.dummy = 0x6c0000; /* actually I think
							    * this does not have
							    * any meaning here
							    * - gd */

		ndr_err = ndr_push_struct_blob(out, out_mem_ctx, &bind_schannel_ack,
					       (ndr_push_flags_fn_t)ndr_push_NL_AUTH_MESSAGE);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(3, ("Could not return schannel bind ack for client %s: %s\n",
				  workstation, nt_errstr(status)));
			return status;
		}

		return NT_STATUS_OK;
	}
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS schannel_update_recv(struct tevent_req *req,
				     TALLOC_CTX *out_mem_ctx,
				     DATA_BLOB *out)
{
	struct schannel_update_state *state =
		tevent_req_data(req,
		struct schannel_update_state);
	NTSTATUS status;

	*out = data_blob_null;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	status = state->status;
	talloc_steal(out_mem_ctx, state->out.data);
	*out = state->out;
	tevent_req_received(req);
	return status;
}

/**
 * Returns anonymous credentials for schannel, matching Win2k3.
 *
 */

static NTSTATUS schannel_session_info(struct gensec_security *gensec_security,
				      TALLOC_CTX *mem_ctx,
				      struct auth_session_info **_session_info)
{
	struct schannel_state *state =
		talloc_get_type(gensec_security->private_data,
		struct schannel_state);
	struct auth4_context *auth_ctx = gensec_security->auth_context;
	struct auth_session_info *session_info = NULL;
	uint32_t session_info_flags = 0;
	NTSTATUS status;

	if (auth_ctx == NULL) {
		DEBUG(0, ("Cannot generate a session_info without the auth_context\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (auth_ctx->generate_session_info == NULL) {
		DEBUG(0, ("Cannot generate a session_info without the generate_session_info hook\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (gensec_security->want_features & GENSEC_FEATURE_UNIX_TOKEN) {
		session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	}

	session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;

	status = auth_ctx->generate_session_info(
				auth_ctx,
				mem_ctx,
				state->user_info_dc,
				state->user_info_dc->info->account_name,
				session_info_flags,
				&session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_session_info = session_info;
	return NT_STATUS_OK;
}

/*
 * Reduce the attack surface by ensuring schannel is not availble when
 * we are not a DC
 */
static NTSTATUS schannel_server_start(struct gensec_security *gensec_security)
{
	enum server_role server_role
		= lpcfg_server_role(gensec_security->settings->lp_ctx);

	switch (server_role) {
	case ROLE_DOMAIN_BDC:
	case ROLE_DOMAIN_PDC:
	case ROLE_ACTIVE_DIRECTORY_DC:
	case ROLE_IPA_DC:
		return NT_STATUS_OK;
	default:
		return NT_STATUS_NOT_IMPLEMENTED;
	}
}

static NTSTATUS schannel_client_start(struct gensec_security *gensec_security)
{
	return NT_STATUS_OK;
}

static bool schannel_have_feature(struct gensec_security *gensec_security,
					 uint32_t feature)
{
	if (gensec_security->dcerpc_auth_level >= DCERPC_AUTH_LEVEL_INTEGRITY) {
		if (feature & GENSEC_FEATURE_SIGN) {
			return true;
		}
	}
	if (gensec_security->dcerpc_auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		if (feature & GENSEC_FEATURE_SEAL) {
			return true;
		}
	}
	if (feature & GENSEC_FEATURE_DCE_STYLE) {
		return true;
	}
	if (feature & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		return true;
	}
	return false;
}

/*
  unseal a packet
*/
static NTSTATUS schannel_unseal_packet(struct gensec_security *gensec_security,
				       uint8_t *data, size_t length,
				       const uint8_t *whole_pdu, size_t pdu_length,
				       const DATA_BLOB *sig)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_incoming_packet(state, true,
				      discard_const_p(uint8_t, data),
				      length,
				      whole_pdu, pdu_length,
				      sig);
}

/*
  check the signature on a packet
*/
static NTSTATUS schannel_check_packet(struct gensec_security *gensec_security,
				      const uint8_t *data, size_t length,
				      const uint8_t *whole_pdu, size_t pdu_length,
				      const DATA_BLOB *sig)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_incoming_packet(state, false,
				      discard_const_p(uint8_t, data),
				      length,
				      whole_pdu, pdu_length,
				      sig);
}
/*
  seal a packet
*/
static NTSTATUS schannel_seal_packet(struct gensec_security *gensec_security,
				     TALLOC_CTX *mem_ctx,
				     uint8_t *data, size_t length,
				     const uint8_t *whole_pdu, size_t pdu_length,
				     DATA_BLOB *sig)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_outgoing_packet(state, mem_ctx, true,
				      data, length,
				      whole_pdu, pdu_length,
				      sig);
}

/*
  sign a packet
*/
static NTSTATUS schannel_sign_packet(struct gensec_security *gensec_security,
				     TALLOC_CTX *mem_ctx,
				     const uint8_t *data, size_t length,
				     const uint8_t *whole_pdu, size_t pdu_length,
				     DATA_BLOB *sig)
{
	struct schannel_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct schannel_state);

	return netsec_outgoing_packet(state, mem_ctx, false,
				      discard_const_p(uint8_t, data),
				      length,
				      whole_pdu, pdu_length,
				      sig);
}

static const struct gensec_security_ops gensec_schannel_security_ops = {
	.name		= "schannel",
	.auth_type	= DCERPC_AUTH_TYPE_SCHANNEL,
	.client_start   = schannel_client_start,
	.server_start   = schannel_server_start,
	.update_send	= schannel_update_send,
	.update_recv	= schannel_update_recv,
	.seal_packet 	= schannel_seal_packet,
	.sign_packet   	= schannel_sign_packet,
	.check_packet	= schannel_check_packet,
	.unseal_packet 	= schannel_unseal_packet,
	.session_info	= schannel_session_info,
	.sig_size	= schannel_sig_size,
	.have_feature   = schannel_have_feature,
	.enabled        = true,
	.priority       = GENSEC_SCHANNEL
};

_PUBLIC_ NTSTATUS gensec_schannel_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;
	ret = gensec_register(ctx, &gensec_schannel_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_schannel_security_ops.name));
		return ret;
	}

	return ret;
}
