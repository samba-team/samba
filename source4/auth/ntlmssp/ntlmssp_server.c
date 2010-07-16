/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, client server side parsing

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
#include "system/network.h"
#include "lib/tsocket/tsocket.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "../librpc/gen_ndr/ndr_ntlmssp.h"
#include "../libcli/auth/libcli_auth.h"
#include "../lib/crypto/crypto.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_proto.h"
#include "auth/auth.h"
#include "param/param.h"

/**
 * Determine correct target name flags for reply, given server role 
 * and negotiated flags
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param neg_flags The flags from the packet
 * @param chal_flags The flags to be set in the reply packet
 * @return The 'target name' string.
 */

static const char *ntlmssp_target_name(struct ntlmssp_state *ntlmssp_state,
				       uint32_t neg_flags, uint32_t *chal_flags) 
{
	if (neg_flags & NTLMSSP_REQUEST_TARGET) {
		*chal_flags |= NTLMSSP_NEGOTIATE_TARGET_INFO;
		*chal_flags |= NTLMSSP_REQUEST_TARGET;
		if (ntlmssp_state->server.is_standalone) {
			*chal_flags |= NTLMSSP_TARGET_TYPE_SERVER;
			return ntlmssp_state->server.netbios_name;
		} else {
			*chal_flags |= NTLMSSP_TARGET_TYPE_DOMAIN;
			return ntlmssp_state->server.netbios_domain;
		};
	} else {
		return "";
	}
}



/**
 * Next state function for the Negotiate packet
 * 
 * @param gensec_security GENSEC state
 * @param out_mem_ctx Memory context for *out
 * @param in The request, as a DATA_BLOB.  reply.data must be NULL
 * @param out The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors or MORE_PROCESSING_REQUIRED if (normal) a reply is required. 
 */

NTSTATUS ntlmssp_server_negotiate(struct gensec_security *gensec_security, 
				  TALLOC_CTX *out_mem_ctx, 
				  const DATA_BLOB in, DATA_BLOB *out) 
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	DATA_BLOB struct_blob;
	uint32_t neg_flags = 0;
	uint32_t ntlmssp_command, chal_flags;
	uint8_t cryptkey[8];
	const char *target_name;
	NTSTATUS status;

	/* parse the NTLMSSP packet */
#if 0
	file_save("ntlmssp_negotiate.dat", request.data, request.length);
#endif

	if (in.length) {
		if ((in.length < 16) || !msrpc_parse(out_mem_ctx, 
				 			 &in, "Cdd",
							 "NTLMSSP",
							 &ntlmssp_command,
							 &neg_flags)) {
			DEBUG(1, ("ntlmssp_server_negotiate: failed to parse "
				"NTLMSSP Negotiate of length %u:\n",
				(unsigned int)in.length ));
			dump_data(2, in.data, in.length);
			return NT_STATUS_INVALID_PARAMETER;
		}
		debug_ntlmssp_flags(neg_flags);
	}
	
	ntlmssp_handle_neg_flags(ntlmssp_state, neg_flags, ntlmssp_state->allow_lm_key);

	/* Ask our caller what challenge they would like in the packet */
	status = ntlmssp_state->get_challenge(ntlmssp_state, cryptkey);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("ntlmssp_server_negotiate: backend doesn't give a challenge: %s\n",
			  nt_errstr(status)));
		return status;
	}

	/* Check if we may set the challenge */
	if (!ntlmssp_state->may_set_challenge(ntlmssp_state)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	}

	/* The flags we send back are not just the negotiated flags,
	 * they are also 'what is in this packet'.  Therfore, we
	 * operate on 'chal_flags' from here on 
	 */

	chal_flags = ntlmssp_state->neg_flags;

	/* get the right name to fill in as 'target' */
	target_name = ntlmssp_target_name(ntlmssp_state,
					  neg_flags, &chal_flags); 
	if (target_name == NULL) 
		return NT_STATUS_INVALID_PARAMETER;

	ntlmssp_state->chal = data_blob_talloc(ntlmssp_state, cryptkey, 8);
	ntlmssp_state->internal_chal = data_blob_talloc(ntlmssp_state, cryptkey, 8);

	/* This creates the 'blob' of names that appears at the end of the packet */
	if (chal_flags & NTLMSSP_NEGOTIATE_TARGET_INFO) {
		msrpc_gen(out_mem_ctx, 
			  &struct_blob, "aaaaa",
			  MsvAvNbDomainName, target_name,
			  MsvAvNbComputerName, ntlmssp_state->server.netbios_name,
			  MsvAvDnsDomainName, ntlmssp_state->server.dns_domain,
			  MsvAvDnsComputerName, ntlmssp_state->server.dns_name,
			  MsvAvEOL, "");
	} else {
		struct_blob = data_blob(NULL, 0);
	}

	{
		/* Marshal the packet in the right format, be it unicode or ASCII */
		const char *gen_string;
		DATA_BLOB version_blob = data_blob_null;

		if (chal_flags & NTLMSSP_NEGOTIATE_VERSION) {
			enum ndr_err_code err;
			struct VERSION vers;

			/* "What Windows returns" as a version number. */
			ZERO_STRUCT(vers);
			vers.ProductMajorVersion = NTLMSSP_WINDOWS_MAJOR_VERSION_6;
			vers.ProductMinorVersion = NTLMSSP_WINDOWS_MINOR_VERSION_1;
			vers.ProductBuild = 0;
			vers.NTLMRevisionCurrent = NTLMSSP_REVISION_W2K3;

			err = ndr_push_struct_blob(&version_blob,
						out_mem_ctx,
						&vers,
						(ndr_push_flags_fn_t)ndr_push_VERSION);

			if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		if (ntlmssp_state->unicode) {
			gen_string = "CdUdbddBb";
		} else {
			gen_string = "CdAdbddBb";
		}
		
		msrpc_gen(out_mem_ctx, 
			  out, gen_string,
			  "NTLMSSP", 
			  NTLMSSP_CHALLENGE,
			  target_name,
			  chal_flags,
			  cryptkey, 8,
			  0, 0,
			  struct_blob.data, struct_blob.length,
			  version_blob.data, version_blob.length);

		data_blob_free(&version_blob);
	}
		
	ntlmssp_state->expected_state = NTLMSSP_AUTH;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

struct ntlmssp_server_auth_state {
	DATA_BLOB user_session_key;
	DATA_BLOB lm_session_key;
	/* internal variables used by KEY_EXCH (client-supplied user session key */
	DATA_BLOB encrypted_session_key;
	bool doing_ntlm2;
	/* internal variables used by NTLM2 */
	uint8_t session_nonce[16];
};

/**
 * Next state function for the Authenticate packet
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param request The request, as a DATA_BLOB
 * @return Errors or NT_STATUS_OK. 
 */

static NTSTATUS ntlmssp_server_preauth(struct ntlmssp_state *ntlmssp_state,
				       struct ntlmssp_server_auth_state *state,
				       const DATA_BLOB request) 
{
	uint32_t ntlmssp_command, auth_flags;
	NTSTATUS nt_status;

	uint8_t session_nonce_hash[16];

	const char *parse_string;

#if 0
	file_save("ntlmssp_auth.dat", request.data, request.length);
#endif

	if (ntlmssp_state->unicode) {
		parse_string = "CdBBUUUBd";
	} else {
		parse_string = "CdBBAAABd";
	}

	/* zero these out */
	data_blob_free(&ntlmssp_state->session_key);
	data_blob_free(&ntlmssp_state->lm_resp);
	data_blob_free(&ntlmssp_state->nt_resp);

	ntlmssp_state->user = NULL;
	ntlmssp_state->domain = NULL;
	ntlmssp_state->client.netbios_name = NULL;

	/* now the NTLMSSP encoded auth hashes */
	if (!msrpc_parse(ntlmssp_state,
			 &request, parse_string,
			 "NTLMSSP", 
			 &ntlmssp_command, 
			 &ntlmssp_state->lm_resp,
			 &ntlmssp_state->nt_resp,
			 &ntlmssp_state->domain,
			 &ntlmssp_state->user,
			 &ntlmssp_state->client.netbios_name,
			 &state->encrypted_session_key,
			 &auth_flags)) {
		DEBUG(10, ("ntlmssp_server_auth: failed to parse NTLMSSP (nonfatal):\n"));
		dump_data(10, request.data, request.length);

		/* zero this out */
		data_blob_free(&state->encrypted_session_key);
		auth_flags = 0;
		
		/* Try again with a shorter string (Win9X truncates this packet) */
		if (ntlmssp_state->unicode) {
			parse_string = "CdBBUUU";
		} else {
			parse_string = "CdBBAAA";
		}

		/* now the NTLMSSP encoded auth hashes */
		if (!msrpc_parse(ntlmssp_state,
				 &request, parse_string,
				 "NTLMSSP", 
				 &ntlmssp_command, 
				 &ntlmssp_state->lm_resp,
				 &ntlmssp_state->nt_resp,
				 &ntlmssp_state->domain,
				 &ntlmssp_state->user,
				 &ntlmssp_state->client.netbios_name)) {
			DEBUG(1, ("ntlmssp_server_auth: failed to parse NTLMSSP:\n"));
			dump_data(2, request.data, request.length);

			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	talloc_steal(state, state->encrypted_session_key.data);

	if (auth_flags)
		ntlmssp_handle_neg_flags(ntlmssp_state, auth_flags, ntlmssp_state->allow_lm_key);

	DEBUG(3,("Got user=[%s] domain=[%s] workstation=[%s] len1=%lu len2=%lu\n",
		 ntlmssp_state->user, ntlmssp_state->domain, ntlmssp_state->client.netbios_name, (unsigned long)ntlmssp_state->lm_resp.length, (unsigned long)ntlmssp_state->nt_resp.length));

#if 0
	file_save("nthash1.dat",  &ntlmssp_state->nt_resp.data,  &ntlmssp_state->nt_resp.length);
	file_save("lmhash1.dat",  &ntlmssp_state->lm_resp.data,  &ntlmssp_state->lm_resp.length);
#endif

	/* NTLM2 uses a 'challenge' that is made of up both the server challenge, and a 
	   client challenge 
	
	   However, the NTLM2 flag may still be set for the real NTLMv2 logins, be careful.
	*/
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		if (ntlmssp_state->nt_resp.length == 24 && ntlmssp_state->lm_resp.length == 24) {
			struct MD5Context md5_session_nonce_ctx;
			SMB_ASSERT(ntlmssp_state->internal_chal.data
				   && ntlmssp_state->internal_chal.length == 8);
			
			state->doing_ntlm2 = true;

			memcpy(state->session_nonce, ntlmssp_state->internal_chal.data, 8);
			memcpy(&state->session_nonce[8], ntlmssp_state->lm_resp.data, 8);
			
			MD5Init(&md5_session_nonce_ctx);
			MD5Update(&md5_session_nonce_ctx, state->session_nonce, 16);
			MD5Final(session_nonce_hash, &md5_session_nonce_ctx);
			
			ntlmssp_state->chal = data_blob_talloc(ntlmssp_state,
							       session_nonce_hash, 8);

			/* LM response is no longer useful, zero it out */
			data_blob_free(&ntlmssp_state->lm_resp);

			/* We changed the effective challenge - set it */
			if (!NT_STATUS_IS_OK(nt_status = 
					     ntlmssp_state->set_challenge(ntlmssp_state,
										 &ntlmssp_state->chal))) {
				return nt_status;
			}

			/* LM Key is incompatible... */
			ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
		}
	}
	return NT_STATUS_OK;
}

/**
 * Next state function for the Authenticate packet 
 * (after authentication - figures out the session keys etc)
 * 
 * @param ntlmssp_state NTLMSSP State
 * @return Errors or NT_STATUS_OK. 
 */

static NTSTATUS ntlmssp_server_postauth(struct gensec_security *gensec_security, 
					struct ntlmssp_server_auth_state *state)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	DATA_BLOB *user_session_key = &state->user_session_key;
	DATA_BLOB *lm_session_key = &state->lm_session_key;
	NTSTATUS nt_status;
	DATA_BLOB session_key = data_blob(NULL, 0);

	if (!(gensec_security->want_features
	      & (GENSEC_FEATURE_SIGN|GENSEC_FEATURE_SEAL|GENSEC_FEATURE_SESSION_KEY))) {
		return NT_STATUS_OK;
	}

	if (user_session_key)
		dump_data_pw("USER session key:\n", user_session_key->data, user_session_key->length);

	if (lm_session_key) 
		dump_data_pw("LM first-8:\n", lm_session_key->data, lm_session_key->length);

	/* Handle the different session key derivation for NTLM2 */
	if (state->doing_ntlm2) {
		if (user_session_key && user_session_key->data && user_session_key->length == 16) {
			session_key = data_blob_talloc(ntlmssp_state, NULL, 16);
			hmac_md5(user_session_key->data, state->session_nonce,
				 sizeof(state->session_nonce), session_key.data);
			DEBUG(10,("ntlmssp_server_auth: Created NTLM2 session key.\n"));
			dump_data_pw("NTLM2 session key:\n", session_key.data, session_key.length);
			
		} else {
			DEBUG(10,("ntlmssp_server_auth: Failed to create NTLM2 session key.\n"));
			session_key = data_blob(NULL, 0);
		}
	} else if ((ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY)
		/* Ensure we can never get here on NTLMv2 */
		&& (ntlmssp_state->nt_resp.length == 0 || ntlmssp_state->nt_resp.length == 24)) {

		if (lm_session_key && lm_session_key->data && lm_session_key->length >= 8) {
			if (ntlmssp_state->lm_resp.data && ntlmssp_state->lm_resp.length == 24) {
				session_key = data_blob_talloc(ntlmssp_state, NULL, 16);
				SMBsesskeygen_lm_sess_key(lm_session_key->data, ntlmssp_state->lm_resp.data,
							  session_key.data);
				DEBUG(10,("ntlmssp_server_auth: Created NTLM session key.\n"));
				dump_data_pw("LM session key:\n", session_key.data, session_key.length);
  			} else {
				
				/* When there is no LM response, just use zeros */
 				static const uint8_t zeros[24];
				session_key = data_blob_talloc(ntlmssp_state, NULL, 16);
 				SMBsesskeygen_lm_sess_key(zeros, zeros, 
 							  session_key.data);
 				DEBUG(10,("ntlmssp_server_auth: Created NTLM session key.\n"));
 				dump_data_pw("LM session key:\n", session_key.data, session_key.length);
			}
		} else {
 			/* LM Key not selected */
			ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

			DEBUG(10,("ntlmssp_server_auth: Failed to create NTLM session key.\n"));
			session_key = data_blob(NULL, 0);
		}

	} else if (user_session_key && user_session_key->data) {
		session_key = data_blob_talloc(ntlmssp_state, user_session_key->data, user_session_key->length);
		DEBUG(10,("ntlmssp_server_auth: Using unmodified nt session key.\n"));
		dump_data_pw("unmodified session key:\n", session_key.data, session_key.length);

		/* LM Key not selected */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

	} else if (lm_session_key && lm_session_key->data) {
		/* Very weird to have LM key, but no user session key, but anyway.. */
		session_key = data_blob_talloc(ntlmssp_state, lm_session_key->data, lm_session_key->length);
		DEBUG(10,("ntlmssp_server_auth: Using unmodified lm session key.\n"));
		dump_data_pw("unmodified session key:\n", session_key.data, session_key.length);

		/* LM Key not selected */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

	} else {
		DEBUG(10,("ntlmssp_server_auth: Failed to create unmodified session key.\n"));
		session_key = data_blob(NULL, 0);

		/* LM Key not selected */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	/* With KEY_EXCH, the client supplies the proposed session key, 
	   but encrypts it with the long-term key */
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		if (!state->encrypted_session_key.data
		    || state->encrypted_session_key.length != 16) {
			data_blob_free(&state->encrypted_session_key);
			DEBUG(1, ("Client-supplied KEY_EXCH session key was of invalid length (%u)!\n", 
				  (unsigned)state->encrypted_session_key.length));
			return NT_STATUS_INVALID_PARAMETER;
		} else if (!session_key.data || session_key.length != 16) {
			DEBUG(5, ("server session key is invalid (len == %u), cannot do KEY_EXCH!\n", 
				  (unsigned)session_key.length));
			ntlmssp_state->session_key = session_key;
		} else {
			dump_data_pw("KEY_EXCH session key (enc):\n", 
				     state->encrypted_session_key.data,
				     state->encrypted_session_key.length);
			arcfour_crypt(state->encrypted_session_key.data,
				      session_key.data, 
				      state->encrypted_session_key.length);
			ntlmssp_state->session_key = data_blob_talloc(ntlmssp_state,
								      state->encrypted_session_key.data,
								      state->encrypted_session_key.length);
			dump_data_pw("KEY_EXCH session key:\n",
				     state->encrypted_session_key.data,
				     state->encrypted_session_key.length);
			talloc_free(session_key.data);
		}
	} else {
		ntlmssp_state->session_key = session_key;
	}

	if ((gensec_security->want_features & GENSEC_FEATURE_SIGN)
	    || (gensec_security->want_features & GENSEC_FEATURE_SEAL)) {
		nt_status = ntlmssp_sign_init(ntlmssp_state);
	} else {
		nt_status = NT_STATUS_OK;
	}

	ntlmssp_state->expected_state = NTLMSSP_DONE;

	return nt_status;
}


/**
 * Next state function for the Authenticate packet
 * 
 * @param gensec_security GENSEC state
 * @param out_mem_ctx Memory context for *out
 * @param in The request, as a DATA_BLOB.  reply.data must be NULL
 * @param out The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors or NT_STATUS_OK if authentication sucessful
 */

NTSTATUS ntlmssp_server_auth(struct gensec_security *gensec_security, 
			     TALLOC_CTX *out_mem_ctx, 
			     const DATA_BLOB in, DATA_BLOB *out) 
{	
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	struct ntlmssp_server_auth_state *state;
	NTSTATUS nt_status;

	/* zero the outbound NTLMSSP packet */
	*out = data_blob_null;

	state = talloc_zero(ntlmssp_state, struct ntlmssp_server_auth_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = ntlmssp_server_preauth(ntlmssp_state, state, in);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(state);
		return nt_status;
	}

	/*
	 * Note we don't check here for NTLMv2 auth settings. If NTLMv2 auth
	 * is required (by "ntlm auth = no" and "lm auth = no" being set in the
	 * smb.conf file) and no NTLMv2 response was sent then the password check
	 * will fail here. JRA.
	 */

	/* Finally, actually ask if the password is OK */
	nt_status = ntlmssp_state->check_password(ntlmssp_state,
						  &state->user_session_key,
						  &state->lm_session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(state);
		return nt_status;
	}

	nt_status = ntlmssp_server_postauth(gensec_security, state);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(state);
		return nt_status;
	}

	TALLOC_FREE(state);
	return NT_STATUS_OK;
}

/**
 * Return the challenge as determined by the authentication subsystem 
 * @return an 8 byte random challenge
 */

static NTSTATUS auth_ntlmssp_get_challenge(const struct ntlmssp_state *ntlmssp_state,
					   uint8_t chal[8])
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(ntlmssp_state->callback_private,
				      struct gensec_ntlmssp_context);
	struct auth_context *auth_context = gensec_ntlmssp->auth_context;
	NTSTATUS status;

	status = auth_context->get_challenge(auth_context, chal);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("auth_ntlmssp_get_challenge: failed to get challenge: %s\n",
			nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

/**
 * Some authentication methods 'fix' the challenge, so we may not be able to set it
 *
 * @return If the effective challenge used by the auth subsystem may be modified
 */
static bool auth_ntlmssp_may_set_challenge(const struct ntlmssp_state *ntlmssp_state)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(ntlmssp_state->callback_private,
				      struct gensec_ntlmssp_context);
	struct auth_context *auth_context = gensec_ntlmssp->auth_context;

	return auth_context->challenge_may_be_modified(auth_context);
}

/**
 * NTLM2 authentication modifies the effective challenge, 
 * @param challenge The new challenge value
 */
static NTSTATUS auth_ntlmssp_set_challenge(struct ntlmssp_state *ntlmssp_state, DATA_BLOB *challenge)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(ntlmssp_state->callback_private,
				      struct gensec_ntlmssp_context);
	struct auth_context *auth_context = gensec_ntlmssp->auth_context;
	NTSTATUS nt_status;
	const uint8_t *chal;

	if (challenge->length != 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	chal = challenge->data;

	nt_status = auth_context->set_challenge(auth_context,
						chal,
						"NTLMSSP callback (NTLM2)");

	return nt_status;
}

/**
 * Check the password on an NTLMSSP login.  
 *
 * Return the session keys used on the connection.
 */

static NTSTATUS auth_ntlmssp_check_password(struct ntlmssp_state *ntlmssp_state,
					    DATA_BLOB *user_session_key, DATA_BLOB *lm_session_key)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(ntlmssp_state->callback_private,
				      struct gensec_ntlmssp_context);
	struct auth_context *auth_context = gensec_ntlmssp->auth_context;
	NTSTATUS nt_status;
	struct auth_usersupplied_info *user_info;

	user_info = talloc(ntlmssp_state, struct auth_usersupplied_info);
	if (!user_info) {
		return NT_STATUS_NO_MEMORY;
	}

	user_info->logon_parameters = MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT | MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT;
	user_info->flags = 0;
	user_info->mapped_state = false;
	user_info->client.account_name = ntlmssp_state->user;
	user_info->client.domain_name = ntlmssp_state->domain;
	user_info->workstation_name = ntlmssp_state->client.netbios_name;
	user_info->remote_host = gensec_get_remote_address(gensec_ntlmssp->gensec_security);

	user_info->password_state = AUTH_PASSWORD_RESPONSE;
	user_info->password.response.lanman = ntlmssp_state->lm_resp;
	user_info->password.response.lanman.data = talloc_steal(user_info, ntlmssp_state->lm_resp.data);
	user_info->password.response.nt = ntlmssp_state->nt_resp;
	user_info->password.response.nt.data = talloc_steal(user_info, ntlmssp_state->nt_resp.data);

	nt_status = auth_context->check_password(auth_context,
						 gensec_ntlmssp,
						 user_info,
						 &gensec_ntlmssp->server_info);
	talloc_free(user_info);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	if (gensec_ntlmssp->server_info->user_session_key.length) {
		DEBUG(10, ("Got NT session key of length %u\n",
			   (unsigned)gensec_ntlmssp->server_info->user_session_key.length));
		*user_session_key = gensec_ntlmssp->server_info->user_session_key;
	}
	if (gensec_ntlmssp->server_info->lm_session_key.length) {
		DEBUG(10, ("Got LM session key of length %u\n",
			   (unsigned)gensec_ntlmssp->server_info->lm_session_key.length));
		*lm_session_key = gensec_ntlmssp->server_info->lm_session_key;
	}
	return nt_status;
}

/** 
 * Return the credentials of a logged on user, including session keys
 * etc.
 *
 * Only valid after a successful authentication
 *
 * May only be called once per authentication.
 *
 */

NTSTATUS gensec_ntlmssp_session_info(struct gensec_security *gensec_security,
				     struct auth_session_info **session_info) 
{
	NTSTATUS nt_status;
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;

	nt_status = gensec_generate_session_info(ntlmssp_state,
						 gensec_security,
						 gensec_ntlmssp->server_info,
						 session_info);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	(*session_info)->session_key = data_blob_talloc(*session_info, 
							ntlmssp_state->session_key.data,
							ntlmssp_state->session_key.length);

	return NT_STATUS_OK;
}

/**
 * Start NTLMSSP on the server side 
 *
 */
NTSTATUS gensec_ntlmssp_server_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	struct ntlmssp_state *ntlmssp_state;
	struct gensec_ntlmssp_context *gensec_ntlmssp;

	nt_status = gensec_ntlmssp_start(gensec_security);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	gensec_ntlmssp = talloc_get_type_abort(gensec_security->private_data,
					       struct gensec_ntlmssp_context);
	ntlmssp_state = gensec_ntlmssp->ntlmssp_state;

	ntlmssp_state->role = NTLMSSP_SERVER;

	ntlmssp_state->expected_state = NTLMSSP_NEGOTIATE;

	ntlmssp_state->allow_lm_key = (lpcfg_lanman_auth(gensec_security->settings->lp_ctx)
					  && gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "allow_lm_key", false));

	ntlmssp_state->neg_flags =
		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_VERSION;

	ntlmssp_state->lm_resp = data_blob(NULL, 0);
	ntlmssp_state->nt_resp = data_blob(NULL, 0);

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "128bit", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_128;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "56bit", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_56;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "keyexchange", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_KEY_EXCH;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "alwayssign", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "ntlm2", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_NTLM2;
	}

	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}

	gensec_ntlmssp->auth_context = gensec_security->auth_context;

	ntlmssp_state->get_challenge = auth_ntlmssp_get_challenge;
	ntlmssp_state->may_set_challenge = auth_ntlmssp_may_set_challenge;
	ntlmssp_state->set_challenge = auth_ntlmssp_set_challenge;
	ntlmssp_state->check_password = auth_ntlmssp_check_password;
	if (lpcfg_server_role(gensec_security->settings->lp_ctx) == ROLE_STANDALONE) {
		ntlmssp_state->server.is_standalone = true;
	} else {
		ntlmssp_state->server.is_standalone = false;
	}

	ntlmssp_state->server.netbios_name = lpcfg_netbios_name(gensec_security->settings->lp_ctx);

	ntlmssp_state->server.netbios_domain = lpcfg_workgroup(gensec_security->settings->lp_ctx);

	{
		char dnsdomname[MAXHOSTNAMELEN], dnsname[MAXHOSTNAMELEN];

		/* Find out the DNS domain name */
		dnsdomname[0] = '\0';
		safe_strcpy(dnsdomname, lpcfg_dnsdomain(gensec_security->settings->lp_ctx), sizeof(dnsdomname) - 1);

		/* Find out the DNS host name */
		safe_strcpy(dnsname, ntlmssp_state->server.netbios_name, sizeof(dnsname) - 1);
		if (dnsdomname[0] != '\0') {
			safe_strcat(dnsname, ".", sizeof(dnsname) - 1);
			safe_strcat(dnsname, dnsdomname, sizeof(dnsname) - 1);
		}
		strlower_m(dnsname);

		ntlmssp_state->server.dns_name = talloc_strdup(ntlmssp_state,
								      dnsname);
		NT_STATUS_HAVE_NO_MEMORY(ntlmssp_state->server.dns_name);

		ntlmssp_state->server.dns_domain = talloc_strdup(ntlmssp_state,
								        dnsdomname);
		NT_STATUS_HAVE_NO_MEMORY(ntlmssp_state->server.dns_domain);
	}

	return NT_STATUS_OK;
}

