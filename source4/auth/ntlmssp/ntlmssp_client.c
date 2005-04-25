/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, client server side parsing

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2005
   Copyright (C) Stefan Metzmacher 2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "auth/auth.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "lib/crypto/crypto.h"

/*********************************************************************
 Client side NTLMSSP
*********************************************************************/

/**
 * Next state function for the Initial packet
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param out_mem_ctx The DATA_BLOB *out will be allocated on this context
 * @param in A NULL data blob (input ignored)
 * @param out The initial negotiate request to the server, as an talloc()ed DATA_BLOB, on out_mem_ctx
 * @return Errors or NT_STATUS_OK. 
 */

NTSTATUS ntlmssp_client_initial(struct gensec_security *gensec_security, 
				TALLOC_CTX *out_mem_ctx, 
				DATA_BLOB in, DATA_BLOB *out) 
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;

	if (gensec_ntlmssp_state->unicode) {
		gensec_ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_UNICODE;
	} else {
		gensec_ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_OEM;
	}
	
	if (gensec_ntlmssp_state->use_ntlmv2) {
		gensec_ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_NTLM2;
	}

	/* generate the ntlmssp negotiate packet */
	msrpc_gen(out_mem_ctx, 
		  out, "CddAA",
		  "NTLMSSP",
		  NTLMSSP_NEGOTIATE,
		  gensec_ntlmssp_state->neg_flags,
		  gensec_ntlmssp_state->get_domain(), 
		  cli_credentials_get_workstation(gensec_security->credentials));

	gensec_ntlmssp_state->expected_state = NTLMSSP_CHALLENGE;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

/**
 * Next state function for the Challenge Packet.  Generate an auth packet.
 * 
 * @param gensec_security GENSEC state
 * @param out_mem_ctx Memory context for *out
 * @param in The server challnege, as a DATA_BLOB.  reply.data must be NULL
 * @param out The next request (auth packet) to the server, as an allocated DATA_BLOB, on the out_mem_ctx context
 * @return Errors or NT_STATUS_OK. 
 */

NTSTATUS ntlmssp_client_challenge(struct gensec_security *gensec_security, 
				  TALLOC_CTX *out_mem_ctx,
				  const DATA_BLOB in, DATA_BLOB *out) 
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;
	uint32_t chal_flags, ntlmssp_command, unkn1, unkn2;
	DATA_BLOB server_domain_blob;
	DATA_BLOB challenge_blob;
	DATA_BLOB struct_blob = data_blob(NULL, 0);
	char *server_domain;
	const char *chal_parse_string;
	const char *auth_gen_string;
	uint8_t lm_hash[16];
	DATA_BLOB lm_response = data_blob(NULL, 0);
	DATA_BLOB nt_response = data_blob(NULL, 0);
	DATA_BLOB session_key = data_blob(NULL, 0);
	DATA_BLOB lm_session_key = data_blob(NULL, 0);
	DATA_BLOB encrypted_session_key = data_blob(NULL, 0);
	NTSTATUS nt_status;

	const char *user, *domain, *password;

	if (!msrpc_parse(out_mem_ctx,
			 &in, "CdBd",
			 "NTLMSSP",
			 &ntlmssp_command, 
			 &server_domain_blob,
			 &chal_flags)) {
		DEBUG(1, ("Failed to parse the NTLMSSP Challenge: (#1)\n"));
		dump_data(2, in.data, in.length);

		return NT_STATUS_INVALID_PARAMETER;
	}
	
	data_blob_free(&server_domain_blob);

	DEBUG(3, ("Got challenge flags:\n"));
	debug_ntlmssp_flags(chal_flags);

	ntlmssp_handle_neg_flags(gensec_ntlmssp_state, chal_flags, gensec_ntlmssp_state->allow_lm_key);

	if (gensec_ntlmssp_state->unicode) {
		if (chal_flags & NTLMSSP_CHAL_TARGET_INFO) {
			chal_parse_string = "CdUdbddB";
		} else {
			chal_parse_string = "CdUdbdd";
		}
		auth_gen_string = "CdBBUUUBd";
	} else {
		if (chal_flags & NTLMSSP_CHAL_TARGET_INFO) {
			chal_parse_string = "CdAdbddB";
		} else {
			chal_parse_string = "CdAdbdd";
		}

		auth_gen_string = "CdBBAAABd";
	}

	DEBUG(3, ("NTLMSSP: Set final flags:\n"));
	debug_ntlmssp_flags(gensec_ntlmssp_state->neg_flags);

	if (!msrpc_parse(out_mem_ctx,
			 &in, chal_parse_string,
			 "NTLMSSP",
			 &ntlmssp_command, 
			 &server_domain,
			 &chal_flags,
			 &challenge_blob, 8,
			 &unkn1, &unkn2,
			 &struct_blob)) {
		DEBUG(1, ("Failed to parse the NTLMSSP Challenge: (#2)\n"));
		dump_data(2, in.data, in.length);
		return NT_STATUS_INVALID_PARAMETER;
	}

	gensec_ntlmssp_state->server_domain = server_domain;

	if (challenge_blob.length != 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Correctly handle username in the original form of user@REALM, which is valid */
	if (gensec_security->credentials->realm_obtained
	    > gensec_security->credentials->domain_obtained) {
		user = talloc_asprintf(out_mem_ctx, "%s@%s", 
				       cli_credentials_get_username(gensec_security->credentials), 
				       cli_credentials_get_realm(gensec_security->credentials));
		domain = NULL;
	} else {
		user = cli_credentials_get_username(gensec_security->credentials);
		domain = cli_credentials_get_domain(gensec_security->credentials);
	}

	password = cli_credentials_get_password(gensec_security->credentials);

	if (!password) {
		static const uint8_t zeros[16];
		/* do nothing - blobs are zero length */

		/* session key is all zeros */
		session_key = data_blob_talloc(gensec_ntlmssp_state, zeros, 16);
		lm_session_key = data_blob_talloc(gensec_ntlmssp_state, zeros, 16);

		/* not doing NLTM2 without a password */
		gensec_ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	} else if (gensec_ntlmssp_state->use_ntlmv2) {

		if (!struct_blob.length) {
			/* be lazy, match win2k - we can't do NTLMv2 without it */
			DEBUG(1, ("Server did not provide 'target information', required for NTLMv2\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* TODO: if the remote server is standalone, then we should replace 'domain'
		   with the server name as supplied above */
		
		if (!SMBNTLMv2encrypt(user, 
				      domain, 
				      password, &challenge_blob, 
				      &struct_blob, 
				      &lm_response, &nt_response, 
				      NULL, &session_key)) {
			data_blob_free(&challenge_blob);
			data_blob_free(&struct_blob);
			return NT_STATUS_NO_MEMORY;
		}

		/* LM Key is incompatible... */
		gensec_ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

	} else if (gensec_ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		struct MD5Context md5_session_nonce_ctx;
		uint8_t nt_hash[16];
		uint8_t session_nonce[16];
		uint8_t session_nonce_hash[16];
		uint8_t user_session_key[16];
		E_md4hash(password, nt_hash);
		
		lm_response = data_blob_talloc(gensec_ntlmssp_state, NULL, 24);
		generate_random_buffer(lm_response.data, 8);
		memset(lm_response.data+8, 0, 16);

		memcpy(session_nonce, challenge_blob.data, 8);
		memcpy(&session_nonce[8], lm_response.data, 8);
	
		MD5Init(&md5_session_nonce_ctx);
		MD5Update(&md5_session_nonce_ctx, challenge_blob.data, 8);
		MD5Update(&md5_session_nonce_ctx, lm_response.data, 8);
		MD5Final(session_nonce_hash, &md5_session_nonce_ctx);

		DEBUG(5, ("NTLMSSP challenge set by NTLM2\n"));
		DEBUG(5, ("challenge is: \n"));
		dump_data(5, session_nonce_hash, 8);
		
		nt_response = data_blob_talloc(gensec_ntlmssp_state, NULL, 24);
		SMBNTencrypt(password,
			     session_nonce_hash,
			     nt_response.data);

		session_key = data_blob_talloc(gensec_ntlmssp_state, NULL, 16);

		SMBsesskeygen_ntv1(nt_hash, user_session_key);
		hmac_md5(user_session_key, session_nonce, sizeof(session_nonce), session_key.data);
		dump_data_pw("NTLM2 session key:\n", session_key.data, session_key.length);

		/* LM Key is incompatible... */
		gensec_ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	} else {
		uint8_t nt_hash[16];

		if (gensec_ntlmssp_state->use_nt_response) {
			nt_response = data_blob_talloc(gensec_ntlmssp_state, NULL, 24);
			SMBNTencrypt(password,challenge_blob.data,
				     nt_response.data);
			E_md4hash(password, nt_hash);
			session_key = data_blob_talloc(gensec_ntlmssp_state, NULL, 16);
			SMBsesskeygen_ntv1(nt_hash, session_key.data);
			dump_data_pw("NT session key:\n", session_key.data, session_key.length);
		}

		/* lanman auth is insecure, it may be disabled */
		if (lp_client_lanman_auth()) {
			lm_response = data_blob_talloc(gensec_ntlmssp_state, NULL, 24);
			if (!SMBencrypt(password,challenge_blob.data,
					lm_response.data)) {
				/* If the LM password was too long (and therefore the LM hash being
				   of the first 14 chars only), don't send it */
				data_blob_free(&lm_response);

				/* LM Key is incompatible with 'long' passwords */
				gensec_ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
			} else {
				E_deshash(password, lm_hash);
				lm_session_key = data_blob_talloc(gensec_ntlmssp_state, NULL, 16);
				memcpy(lm_session_key.data, lm_hash, 8);
				memset(&lm_session_key.data[8], '\0', 8);

				if (!gensec_ntlmssp_state->use_nt_response) {
					session_key = lm_session_key;
				}
			}
		} else {
			/* LM Key is incompatible... */
			gensec_ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
		}
	}
	
	if ((gensec_ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) 
	    && lp_client_lanman_auth() && lm_session_key.length == 16) {
		DATA_BLOB new_session_key = data_blob_talloc(gensec_ntlmssp_state, NULL, 16);
		if (lm_response.length == 24) {
			SMBsesskeygen_lm_sess_key(lm_session_key.data, lm_response.data, 
						  new_session_key.data);
		} else {
			static const uint8_t zeros[24];
			SMBsesskeygen_lm_sess_key(lm_session_key.data, zeros,
						  new_session_key.data);
		}
		new_session_key.length = 16;
		session_key = new_session_key;
		dump_data_pw("LM session key\n", session_key.data, session_key.length);
	}


	/* Key exchange encryptes a new client-generated session key with
	   the password-derived key */
	if (gensec_ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		/* Make up a new session key */
		uint8_t client_session_key[16];
		generate_random_buffer(client_session_key, sizeof(client_session_key));

		/* Encrypt the new session key with the old one */
		encrypted_session_key = data_blob_talloc(gensec_ntlmssp_state, 
							 client_session_key, sizeof(client_session_key));
		dump_data_pw("KEY_EXCH session key:\n", encrypted_session_key.data, encrypted_session_key.length);
		arcfour_crypt(encrypted_session_key.data, session_key.data, encrypted_session_key.length);
		dump_data_pw("KEY_EXCH session key (enc):\n", encrypted_session_key.data, encrypted_session_key.length);

		/* Mark the new session key as the 'real' session key */
		session_key = data_blob_talloc(gensec_ntlmssp_state, client_session_key, sizeof(client_session_key));
	}

	/* this generates the actual auth packet */
	if (!msrpc_gen(out_mem_ctx, 
		       out, auth_gen_string, 
		       "NTLMSSP", 
		       NTLMSSP_AUTH, 
		       lm_response.data, lm_response.length,
		       nt_response.data, nt_response.length,
		       domain, 
		       user, 
		       cli_credentials_get_workstation(gensec_security->credentials),
		       encrypted_session_key.data, encrypted_session_key.length,
		       gensec_ntlmssp_state->neg_flags)) {
		
		return NT_STATUS_NO_MEMORY;
	}

	gensec_ntlmssp_state->session_key = session_key;

	/* The client might be using 56 or 40 bit weakened keys */
	ntlmssp_weaken_keys(gensec_ntlmssp_state);

	gensec_ntlmssp_state->chal = challenge_blob;
	gensec_ntlmssp_state->lm_resp = lm_response;
	gensec_ntlmssp_state->nt_resp = nt_response;

	gensec_ntlmssp_state->expected_state = NTLMSSP_DONE;

	nt_status = ntlmssp_sign_init(gensec_ntlmssp_state);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Could not setup NTLMSSP signing/sealing system (error was: %s)\n", 
			  nt_errstr(nt_status)));
		return nt_status;
	}

	return nt_status;
}

NTSTATUS gensec_ntlmssp_client_start(struct gensec_security *gensec_security)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state;
	NTSTATUS nt_status;

	nt_status = gensec_ntlmssp_start(gensec_security);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	gensec_ntlmssp_state = gensec_security->private_data;

	gensec_ntlmssp_state->role = NTLMSSP_CLIENT;

	gensec_ntlmssp_state->get_domain = lp_workgroup;

	gensec_ntlmssp_state->unicode = lp_parm_bool(-1, "ntlmssp_client", "unicode", True);

	gensec_ntlmssp_state->use_nt_response = lp_parm_bool(-1, "ntlmssp_client", "send_nt_reponse", True);

	gensec_ntlmssp_state->allow_lm_key = (lp_lanman_auth() 
					  && lp_parm_bool(-1, "ntlmssp_client", "allow_lm_key", False));

	gensec_ntlmssp_state->use_ntlmv2 = lp_client_ntlmv2_auth();

	gensec_ntlmssp_state->expected_state = NTLMSSP_INITIAL;

	gensec_ntlmssp_state->neg_flags = 
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_REQUEST_TARGET;

	if (lp_parm_bool(-1, "ntlmssp_client", "128bit", True)) {
		gensec_ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_128;		
	}

	if (lp_parm_bool(-1, "ntlmssp_client", "keyexchange", True)) {
		gensec_ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_KEY_EXCH;		
	}

	if (lp_parm_bool(-1, "ntlmssp_client", "ntlm2", True)) {
		gensec_ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_NTLM2;		
	} else {
		/* apparently we can't do ntlmv2 if we don't do ntlm2 */
		gensec_ntlmssp_state->use_ntlmv2 = False;
	}

	if (gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
		/*
		 * We need to set this to allow a later SetPassword
		 * via the SAMR pipe to succeed. Strange.... We could
		 * also add  NTLMSSP_NEGOTIATE_SEAL here. JRA.
		 * 
		 * Without this, Windows will not create the master key
		 * that it thinks is only used for NTLMSSP signing and 
		 * sealing.  (It is actually pulled out and used directly) 
		 */
		gensec_ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		gensec_ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		gensec_ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}

	gensec_security->private_data = gensec_ntlmssp_state;

	return NT_STATUS_OK;
}

