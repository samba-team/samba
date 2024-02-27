/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "librpc/gen_ndr/lsa.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "rpc_client/init_lsa.h"
#include "lib/crypto/gnutls_helpers.h"
#include "librpc/rpc/dcerpc_lsa.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/*******************************************************************
 inits a structure.
********************************************************************/

void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
	name->size = 2 * strlen_m(s);
	name->length = name->size;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_lsa_StringLarge(struct lsa_StringLarge *name, const char *s)
{
	name->string = s;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_lsa_AsciiString(struct lsa_AsciiString *name, const char *s)
{
	name->string = s;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_lsa_AsciiStringLarge(struct lsa_AsciiStringLarge *name, const char *s)
{
	name->string = s;
}

bool rpc_lsa_encrypt_trustdom_info(
	TALLOC_CTX *mem_ctx,
	const char *incoming_old,
	const char *incoming_new,
	const char *outgoing_old,
	const char *outgoing_new,
	DATA_BLOB session_key,
	struct lsa_TrustDomainInfoAuthInfoInternal **_authinfo_internal)
{
	struct timeval tv_now = timeval_current();
	NTTIME now = timeval_to_nttime(&tv_now);

	struct lsa_TrustDomainInfoAuthInfoInternal *authinfo_internal = NULL;
	struct AuthenticationInformation in_cur_td_info = {
		.AuthType = TRUST_AUTH_TYPE_CLEAR,
		.LastUpdateTime = now,
	};
	struct AuthenticationInformation in_prev_td_buf = {
		.AuthType = TRUST_AUTH_TYPE_CLEAR,
		.LastUpdateTime = now,
	};
	struct AuthenticationInformation out_cur_td_info = {
		.AuthType = TRUST_AUTH_TYPE_CLEAR,
		.LastUpdateTime = now,
	};
	struct AuthenticationInformation out_prev_td_buf = {
		.AuthType = TRUST_AUTH_TYPE_CLEAR,
		.LastUpdateTime = now,
	};

	/*
	 * This corresponds to MS-LSAD 2.2.7.16 LSAPR_TRUSTED_DOMAIN_AUTH_BLOB.
	 */
	struct trustDomainPasswords dom_auth_info = {
		.incoming = {
			.count = 1,
			.previous = {
				.count = 1,
				.array = &in_prev_td_buf,

			},
			.current = {
				.count = 1,
				.array = &in_cur_td_info,
			},
		},

		.outgoing = {
			.count = 1,
			.previous = {
				.count = 1,
				.array = &out_prev_td_buf,

			},
			.current = {
				.count = 1,
				.array = &out_cur_td_info,
			},
		}
	};

	size_t converted_size = 0;
	DATA_BLOB dom_auth_blob = data_blob_null;
	enum ndr_err_code ndr_err;
	bool ok;
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t _session_key = {
		.data = session_key.data,
		.size = session_key.length,
	};

	authinfo_internal = talloc_zero(
		mem_ctx, struct lsa_TrustDomainInfoAuthInfoInternal);
	if (authinfo_internal == NULL) {
		return false;
	}

	ok = convert_string_talloc(mem_ctx,
				   CH_UNIX,
				   CH_UTF16,
				   incoming_new,
				   strlen(incoming_new),
				   &in_cur_td_info.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	in_cur_td_info.AuthInfo.clear.size = converted_size;

	ok = convert_string_talloc(mem_ctx,
				   CH_UNIX,
				   CH_UTF16,
				   incoming_old,
				   strlen(incoming_old),
				   &in_prev_td_buf.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	in_prev_td_buf.AuthInfo.clear.size = converted_size;

	ok = convert_string_talloc(mem_ctx,
				   CH_UNIX,
				   CH_UTF16,
				   outgoing_new,
				   strlen(outgoing_new),
				   &out_cur_td_info.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	out_cur_td_info.AuthInfo.clear.size = converted_size;

	ok = convert_string_talloc(mem_ctx,
				   CH_UNIX,
				   CH_UTF16,
				   outgoing_old,
				   strlen(outgoing_old),
				   &out_prev_td_buf.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	out_prev_td_buf.AuthInfo.clear.size = converted_size;

	generate_random_buffer(dom_auth_info.confounder,
			       sizeof(dom_auth_info.confounder));

	ndr_err = ndr_push_struct_blob(
		&dom_auth_blob,
		authinfo_internal,
		&dom_auth_info,
		(ndr_push_flags_fn_t)ndr_push_trustDomainPasswords);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}
	generate_random_buffer(dom_auth_info.confounder,
			       sizeof(dom_auth_info.confounder));

	gnutls_cipher_init(&cipher_hnd,
			   GNUTLS_CIPHER_ARCFOUR_128,
			   &_session_key,
			   NULL);
	gnutls_cipher_encrypt(cipher_hnd,
			      dom_auth_blob.data,
			      dom_auth_blob.length);
	gnutls_cipher_deinit(cipher_hnd);

	authinfo_internal->auth_blob.size = dom_auth_blob.length;
	authinfo_internal->auth_blob.data = dom_auth_blob.data;

	*_authinfo_internal = authinfo_internal;

	return true;
}

bool rpc_lsa_encrypt_trustdom_info_aes(
	TALLOC_CTX *mem_ctx,
	const char *incoming_old,
	const char *incoming_new,
	const char *outgoing_old,
	const char *outgoing_new,
	DATA_BLOB session_key,
	struct lsa_TrustDomainInfoAuthInfoInternalAES **pauthinfo_internal)
{
	struct timeval tv_now = timeval_current();
	NTTIME now = timeval_to_nttime(&tv_now);

	struct AuthenticationInformation in_cur_td_info = {
		.AuthType = TRUST_AUTH_TYPE_CLEAR,
		.LastUpdateTime = now,
	};
	struct AuthenticationInformation in_prev_td_buf = {
		.AuthType = TRUST_AUTH_TYPE_CLEAR,
		.LastUpdateTime = now,
	};
	struct AuthenticationInformation out_cur_td_info = {
		.AuthType = TRUST_AUTH_TYPE_CLEAR,
		.LastUpdateTime = now,
	};
	struct AuthenticationInformation out_prev_td_buf = {
		.AuthType = TRUST_AUTH_TYPE_CLEAR,
		.LastUpdateTime = now,
	};

	/*
	 * This corresponds to MS-LSAD 2.2.7.16 LSAPR_TRUSTED_DOMAIN_AUTH_BLOB.
	 */
	struct trustDomainPasswords dom_auth_info = {
		.incoming = {
			.count = 1,
			.previous = {
				.count = 1,
				.array = &in_prev_td_buf,

			},
			.current = {
				.count = 1,
				.array = &in_cur_td_info,
			},
		},

		.outgoing = {
			.count = 1,
			.previous = {
				.count = 1,
				.array = &out_prev_td_buf,

			},
			.current = {
				.count = 1,
				.array = &out_cur_td_info,
			},
		}
	};

	struct lsa_TrustDomainInfoAuthInfoInternalAES *authinfo_internal = NULL;
	size_t converted_size = 0;
	DATA_BLOB dom_auth_blob = data_blob_null;
	enum ndr_err_code ndr_err;
	bool ok;
	/* Salt */
	DATA_BLOB iv = {
		.length = 0,
	};
	gnutls_datum_t iv_datum = {
		.size = 0,
	};
	/* Encrypted ciphertext */
	DATA_BLOB ciphertext = data_blob_null;
	NTSTATUS status;

	authinfo_internal = talloc_zero(
		mem_ctx, struct lsa_TrustDomainInfoAuthInfoInternalAES);
	if (authinfo_internal == NULL) {
		return false;
	}

	ok = convert_string_talloc(mem_ctx,
				   CH_UNIX,
				   CH_UTF16,
				   incoming_new,
				   strlen(incoming_new),
				   &in_cur_td_info.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	in_cur_td_info.AuthInfo.clear.size = converted_size;

	ok = convert_string_talloc(mem_ctx,
				   CH_UNIX,
				   CH_UTF16,
				   incoming_old,
				   strlen(incoming_old),
				   &in_prev_td_buf.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	in_prev_td_buf.AuthInfo.clear.size = converted_size;

	ok = convert_string_talloc(mem_ctx,
				   CH_UNIX,
				   CH_UTF16,
				   outgoing_new,
				   strlen(outgoing_new),
				   &out_cur_td_info.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	out_cur_td_info.AuthInfo.clear.size = converted_size;

	ok = convert_string_talloc(mem_ctx,
				   CH_UNIX,
				   CH_UTF16,
				   outgoing_old,
				   strlen(outgoing_old),
				   &out_prev_td_buf.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	out_prev_td_buf.AuthInfo.clear.size = converted_size;

	generate_random_buffer(dom_auth_info.confounder,
			       sizeof(dom_auth_info.confounder));

	ndr_err = ndr_push_struct_blob(
		&dom_auth_blob,
		authinfo_internal,
		&dom_auth_info,
		(ndr_push_flags_fn_t)ndr_push_trustDomainPasswords);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	/* Create salt */
	iv.data = iv_datum.data = authinfo_internal->salt;
	iv.length = iv_datum.size = sizeof(authinfo_internal->salt);
	generate_nonce_buffer(authinfo_internal->salt,
			      sizeof(authinfo_internal->salt));

	/* Create encryption key */
	status = samba_gnutls_aead_aes_256_cbc_hmac_sha512_encrypt(
		authinfo_internal,
		&dom_auth_blob,
		&session_key,
		&lsa_aes256_enc_key_salt,
		&lsa_aes256_mac_key_salt,
		&iv,
		&ciphertext,
		authinfo_internal->auth_data);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (ciphertext.length < 520) {
		return false;
	}

	authinfo_internal->cipher.data = ciphertext.data;
	authinfo_internal->cipher.size = ciphertext.length;

	*pauthinfo_internal = authinfo_internal;

	return true;
}
