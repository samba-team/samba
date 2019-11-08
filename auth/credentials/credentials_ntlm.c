/* 
   Unix SMB/CIFS implementation.

   User credentials handling

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2005
   Copyright (C) Stefan Metzmacher 2005
   
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
#include "librpc/gen_ndr/samr.h" /* for struct samrPassword */
#include "../lib/crypto/crypto.h"
#include "libcli/auth/libcli_auth.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

_PUBLIC_ NTSTATUS cli_credentials_get_ntlm_response(struct cli_credentials *cred, TALLOC_CTX *mem_ctx, 
					   int *flags,
					   DATA_BLOB challenge,
					   const NTTIME *server_timestamp,
					   DATA_BLOB target_info,
					   DATA_BLOB *_lm_response, DATA_BLOB *_nt_response, 
					   DATA_BLOB *_lm_session_key, DATA_BLOB *_session_key) 
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *user = NULL;
	const char *domain = NULL;
	DATA_BLOB lm_response = data_blob_null;
	DATA_BLOB nt_response = data_blob_null;
	DATA_BLOB lm_session_key = data_blob_null;
	DATA_BLOB session_key = data_blob_null;
	const struct samr_Password *nt_hash = NULL;
	int rc;

	if (cred->use_kerberos == CRED_MUST_USE_KERBEROS) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	/* We may already have an NTLM response we prepared earlier.
	 * This is used for NTLM pass-though authentication */
	if (cred->nt_response.data || cred->lm_response.data) {
		if (cred->nt_response.length != 0) {
			nt_response = data_blob_dup_talloc(frame,
							   cred->nt_response);
			if (nt_response.data == NULL) {
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}
		}
		if (cred->lm_response.length != 0) {
			lm_response = data_blob_dup_talloc(frame,
							   cred->lm_response);
			if (lm_response.data == NULL) {
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}
		}

		if (cred->lm_response.data == NULL) {
			*flags = *flags & ~CLI_CRED_LANMAN_AUTH;
		}
		goto done;
	}

	nt_hash = cli_credentials_get_nt_hash(cred, frame);

	cli_credentials_get_ntlm_username_domain(cred, frame, &user, &domain);
	if (user == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	if (domain == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* If we are sending a username@realm login (see function
	 * above), then we will not send LM, it will not be
	 * accepted */
	if (cred->principal_obtained > cred->username_obtained) {
		*flags = *flags & ~CLI_CRED_LANMAN_AUTH;
	}

	/* Likewise if we are a machine account (avoid protocol downgrade attacks) */
	if (cred->machine_account) {
		*flags = *flags & ~CLI_CRED_LANMAN_AUTH;
	}

	if (!nt_hash) {
		/* do nothing - blobs are zero length */

		/* session key is all zeros */
		session_key = data_blob_talloc_zero(frame, 16);
		if (session_key.data == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		lm_session_key = data_blob_talloc_zero(frame, 16);
		if (lm_session_key.data == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		/* not doing NTLM2 without a password */
		*flags &= ~CLI_CRED_NTLM2;
	} else if (*flags & CLI_CRED_NTLMv2_AUTH) {

		if (!target_info.length) {
			/* be lazy, match win2k - we can't do NTLMv2 without it */
			DEBUG(1, ("Server did not provide 'target information', required for NTLMv2\n"));
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* TODO: if the remote server is standalone, then we should replace 'domain'
		   with the server name as supplied above */
		
		if (!SMBNTLMv2encrypt_hash(frame,
					   user, 
					   domain, 
					   nt_hash->hash, &challenge, 
					   server_timestamp, &target_info,
					   &lm_response, &nt_response, 
					   NULL, &session_key)) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		/* LM Key is incompatible... */
		*flags &= ~CLI_CRED_LANMAN_AUTH;
		if (lm_response.length != 0) {
			/*
			 * We should not expose the lm key.
			 */
			memset(lm_response.data, 0, lm_response.length);
		}
	} else if (*flags & CLI_CRED_NTLM2) {
		uint8_t session_nonce[16];
		uint8_t session_nonce_hash[16];
		uint8_t user_session_key[16];

		lm_response = data_blob_talloc_zero(frame, 24);
		if (lm_response.data == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		generate_random_buffer(lm_response.data, 8);

		memcpy(session_nonce, challenge.data, 8);
		memcpy(&session_nonce[8], lm_response.data, 8);

		rc = gnutls_hash_fast(GNUTLS_DIG_MD5,
				      session_nonce,
				      sizeof(session_nonce),
				      session_nonce_hash);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		}

		DEBUG(5, ("NTLMSSP challenge set by NTLM2\n"));
		DEBUG(5, ("challenge is: \n"));
		dump_data(5, session_nonce_hash, 8);

		nt_response = data_blob_talloc_zero(frame, 24);
		if (nt_response.data == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		rc = SMBOWFencrypt(nt_hash->hash,
				   session_nonce_hash,
                                   nt_response.data);
		if (rc != 0) {
			TALLOC_FREE(frame);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		}

		ZERO_ARRAY(session_nonce_hash);

		session_key = data_blob_talloc_zero(frame, 16);
		if (session_key.data == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		SMBsesskeygen_ntv1(nt_hash->hash, user_session_key);

		rc = gnutls_hmac_fast(GNUTLS_MAC_MD5,
				      user_session_key,
				      sizeof(user_session_key),
				      session_nonce,
				      sizeof(session_nonce),
				      session_key.data);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		}

		ZERO_ARRAY(user_session_key);

		dump_data_pw("NTLM2 session key:\n", session_key.data, session_key.length);

		/* LM Key is incompatible... */
		*flags &= ~CLI_CRED_LANMAN_AUTH;
	} else {
		const char *password = cli_credentials_get_password(cred);
		uint8_t lm_hash[16];
		bool do_lm = false;

		nt_response = data_blob_talloc_zero(frame, 24);
		if (nt_response.data == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		rc = SMBOWFencrypt(nt_hash->hash, challenge.data,
				   nt_response.data);
		if (rc != 0) {
			TALLOC_FREE(frame);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		}

		session_key = data_blob_talloc_zero(frame, 16);
		if (session_key.data == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		SMBsesskeygen_ntv1(nt_hash->hash, session_key.data);
		dump_data_pw("NT session key:\n", session_key.data, session_key.length);

		/* lanman auth is insecure, it may be disabled.  
		   We may also not have a password */

		if (password != NULL) {
			do_lm = E_deshash(password, lm_hash);
		}

		if (*flags & CLI_CRED_LANMAN_AUTH && do_lm) {
			lm_response = data_blob_talloc_zero(frame, 24);
			if (lm_response.data == NULL) {
				ZERO_STRUCT(lm_hash);
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}

			rc = SMBencrypt_hash(lm_hash,
					     challenge.data,
					     lm_response.data);
			if (rc != 0) {
				ZERO_STRUCT(lm_hash);
				TALLOC_FREE(frame);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
			}
		} else {
			/* just copy the nt_response */
			lm_response = data_blob_dup_talloc(frame, nt_response);
			if (lm_response.data == NULL) {
				ZERO_STRUCT(lm_hash);
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}
		}

		if (do_lm) {
			lm_session_key = data_blob_talloc_zero(frame, 16);
			if (lm_session_key.data == NULL) {
				ZERO_STRUCT(lm_hash);
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}
			memcpy(lm_session_key.data, lm_hash, 8);

			if (!(*flags & CLI_CRED_NTLM_AUTH)) {
				memcpy(session_key.data, lm_session_key.data, 16);
			}
			ZERO_STRUCT(lm_hash);
		}
	}

done:
	if (_lm_response != NULL) {
		talloc_steal(mem_ctx, lm_response.data);
		*_lm_response = lm_response;
	} else {
		data_blob_clear(&lm_response);
	}
	if (_nt_response != NULL) {
		talloc_steal(mem_ctx, nt_response.data);
		*_nt_response = nt_response;
	} else {
		data_blob_clear(&nt_response);
	}
	if (_lm_session_key != NULL) {
		talloc_steal(mem_ctx, lm_session_key.data);
		*_lm_session_key = lm_session_key;
	} else {
		data_blob_clear(&lm_session_key);
	}
	if (_session_key != NULL) {
		talloc_steal(mem_ctx, session_key.data);
		*_session_key = session_key;
	} else {
		data_blob_clear(&session_key);
	}
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/*
 * Set a utf16 password on the credentials context, including an indication
 * of 'how' the password was obtained
 *
 * This is required because the nt_hash is calculated over the raw utf16 blob,
 * which might not be completely valid utf16, which means the conversion
 * from CH_UTF16MUNGED to CH_UTF8 might loose information.
 */
_PUBLIC_ bool cli_credentials_set_utf16_password(struct cli_credentials *cred,
						 const DATA_BLOB *password_utf16,
						 enum credentials_obtained obtained)
{
	cred->password_will_be_nt_hash = false;

	if (password_utf16 == NULL) {
		return cli_credentials_set_password(cred, NULL, obtained);
	}

	if (obtained >= cred->password_obtained) {
		struct samr_Password *nt_hash = NULL;
		char *password_talloc = NULL;
		size_t password_len = 0;
		bool ok;

		nt_hash = talloc(cred, struct samr_Password);
		if (nt_hash == NULL) {
			return false;
		}

		ok = convert_string_talloc(cred,
					   CH_UTF16MUNGED, CH_UTF8,
					   password_utf16->data,
					   password_utf16->length,
					   (void *)&password_talloc,
					   &password_len);
		if (!ok) {
			TALLOC_FREE(nt_hash);
			return false;
		}

		ok = cli_credentials_set_password(cred, password_talloc, obtained);
		TALLOC_FREE(password_talloc);
		if (!ok) {
			TALLOC_FREE(nt_hash);
			return false;
		}

		mdfour(nt_hash->hash, password_utf16->data, password_utf16->length);
		cred->nt_hash = nt_hash;
		return true;
	}

	return false;
}

/*
 * Set a old utf16 password on the credentials context.
 *
 * This is required because the nt_hash is calculated over the raw utf16 blob,
 * which might not be completely valid utf16, which means the conversion
 * from CH_UTF16MUNGED to CH_UTF8 might loose information.
 */
_PUBLIC_ bool cli_credentials_set_old_utf16_password(struct cli_credentials *cred,
						     const DATA_BLOB *password_utf16)
{
	struct samr_Password *nt_hash = NULL;
	char *password_talloc = NULL;
	size_t password_len = 0;
	bool ok;

	if (password_utf16 == NULL) {
		return cli_credentials_set_old_password(cred, NULL, CRED_SPECIFIED);
	}

	nt_hash = talloc(cred, struct samr_Password);
	if (nt_hash == NULL) {
		return false;
	}

	ok = convert_string_talloc(cred,
				   CH_UTF16MUNGED, CH_UTF8,
				   password_utf16->data,
				   password_utf16->length,
				   (void *)&password_talloc,
				   &password_len);
	if (!ok) {
		TALLOC_FREE(nt_hash);
		return false;
	}

	ok = cli_credentials_set_old_password(cred, password_talloc, CRED_SPECIFIED);
	TALLOC_FREE(password_talloc);
	if (!ok) {
		TALLOC_FREE(nt_hash);
		return false;
	}

	mdfour(nt_hash->hash, password_utf16->data, password_utf16->length);
	cred->old_nt_hash = nt_hash;
	return true;
}

_PUBLIC_ void cli_credentials_set_password_will_be_nt_hash(struct cli_credentials *cred,
							   bool val)
{
	/*
	 * We set this here and the next cli_credentials_set_password()
	 * that resets the password or password callback
	 * will pick this up.
	 *
	 * cli_credentials_set_nt_hash() and
	 * cli_credentials_set_utf16_password() will reset this
	 * to false.
	 */
	cred->password_will_be_nt_hash = val;
}

_PUBLIC_ bool cli_credentials_set_nt_hash(struct cli_credentials *cred,
				 const struct samr_Password *nt_hash, 
				 enum credentials_obtained obtained)
{
	cred->password_will_be_nt_hash = false;

	if (obtained >= cred->password_obtained) {
		cli_credentials_set_password(cred, NULL, obtained);
		if (nt_hash) {
			cred->nt_hash = talloc(cred, struct samr_Password);
			if (cred->nt_hash == NULL) {
				return false;
			}
			*cred->nt_hash = *nt_hash;
		} else {
			cred->nt_hash = NULL;
		}
		return true;
	}

	return false;
}

_PUBLIC_ bool cli_credentials_set_old_nt_hash(struct cli_credentials *cred,
					      const struct samr_Password *nt_hash)
{
	cli_credentials_set_old_password(cred, NULL, CRED_SPECIFIED);
	if (nt_hash) {
		cred->old_nt_hash = talloc(cred, struct samr_Password);
		if (cred->old_nt_hash == NULL) {
			return false;
		}
		*cred->old_nt_hash = *nt_hash;
	} else {
		cred->old_nt_hash = NULL;
	}

	return true;
}

_PUBLIC_ bool cli_credentials_set_ntlm_response(struct cli_credentials *cred,
						const DATA_BLOB *lm_response, 
						const DATA_BLOB *nt_response, 
						enum credentials_obtained obtained)
{
	if (obtained >= cred->password_obtained) {
		cli_credentials_set_password(cred, NULL, obtained);
		if (nt_response) {
			cred->nt_response = data_blob_talloc(cred, nt_response->data, nt_response->length);
			talloc_steal(cred, cred->nt_response.data);
		}
		if (nt_response) {
			cred->lm_response = data_blob_talloc(cred, lm_response->data, lm_response->length);
		}
		return true;
	}

	return false;
}

