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

struct auth_session_info;

#include "includes.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "../libcli/auth/libcli_auth.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "param/param.h"
#include "auth/ntlmssp/ntlmssp_private.h"
#include "../librpc/gen_ndr/ndr_ntlmssp.h"
#include "../auth/ntlmssp/ntlmssp_ndr.h"
#include "../nsswitch/libwbclient/wbclient.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

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
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	NTSTATUS status;
	const DATA_BLOB version_blob = ntlmssp_version_blob();

	/* generate the ntlmssp negotiate packet */
	status = msrpc_gen(out_mem_ctx,
		  out, "CddAAb",
		  "NTLMSSP",
		  NTLMSSP_NEGOTIATE,
		  ntlmssp_state->neg_flags,
		  "", /* domain */
		  "", /* workstation */
		  version_blob.data, version_blob.length);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("ntlmssp_client_initial: failed to generate "
			  "ntlmssp negotiate packet\n"));
		return status;
	}

	if (DEBUGLEVEL >= 10) {
		struct NEGOTIATE_MESSAGE *negotiate = talloc(
			ntlmssp_state, struct NEGOTIATE_MESSAGE);
		if (negotiate != NULL) {
			status = ntlmssp_pull_NEGOTIATE_MESSAGE(
				out, negotiate, negotiate);
			if (NT_STATUS_IS_OK(status)) {
				NDR_PRINT_DEBUG(NEGOTIATE_MESSAGE,
						negotiate);
			}
			TALLOC_FREE(negotiate);
		}
	}

	ntlmssp_state->negotiate_blob = data_blob_dup_talloc(ntlmssp_state,
							     *out);
	if (ntlmssp_state->negotiate_blob.length != out->length) {
		return NT_STATUS_NO_MEMORY;
	}

	ntlmssp_state->expected_state = NTLMSSP_CHALLENGE;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS gensec_ntlmssp_resume_ccache(struct gensec_security *gensec_security,
				TALLOC_CTX *out_mem_ctx,
				DATA_BLOB in, DATA_BLOB *out)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	uint32_t neg_flags = 0;
	uint32_t ntlmssp_command;
	NTSTATUS status;
	bool ok;

	*out = data_blob_null;

	if (in.length == 0) {
		/*
		 * This is compat code for older callers
		 * which were missing the "initial_blob"/"negotiate_blob".
		 *
		 * That means we can't calculate the NTLMSSP_MIC
		 * field correctly and need to force the
		 * old_spnego behaviour.
		 */
		DEBUG(10, ("%s: in.length==%u force_old_spnego!\n",
			   __func__, (unsigned int)in.length));
		ntlmssp_state->force_old_spnego = true;
		ntlmssp_state->neg_flags |= ntlmssp_state->required_flags;
		ntlmssp_state->required_flags = 0;
		ntlmssp_state->expected_state = NTLMSSP_CHALLENGE;
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

	/* parse the NTLMSSP packet */

	if (in.length > UINT16_MAX) {
		DEBUG(1, ("%s: reject large request of length %u\n",
			__func__, (unsigned int)in.length));
		return NT_STATUS_INVALID_PARAMETER;
	}

	ok = msrpc_parse(ntlmssp_state, &in, "Cdd",
			 "NTLMSSP",
			 &ntlmssp_command,
			 &neg_flags);
	if (!ok) {
		DEBUG(1, ("%s: failed to parse NTLMSSP Negotiate of length %u\n",
			__func__, (unsigned int)in.length));
		dump_data(2, in.data, in.length);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (ntlmssp_command != NTLMSSP_NEGOTIATE) {
		DEBUG(1, ("%s: no NTLMSSP Negotiate message (length %u)\n",
			__func__, (unsigned int)in.length));
		dump_data(2, in.data, in.length);
		return NT_STATUS_INVALID_PARAMETER;
	}

	ntlmssp_state->neg_flags = neg_flags;
	DEBUG(3, ("Imported Negotiate flags:\n"));
	debug_ntlmssp_flags(neg_flags);

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		ntlmssp_state->unicode = true;
	} else {
		ntlmssp_state->unicode = false;
	}

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SIGN) {
		gensec_security->want_features |= GENSEC_FEATURE_SIGN;
	}

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SEAL) {
		gensec_security->want_features |= GENSEC_FEATURE_SEAL;
	}

	ntlmssp_state->conf_flags = ntlmssp_state->neg_flags;
	ntlmssp_state->required_flags = 0;

	if (DEBUGLEVEL >= 10) {
		struct NEGOTIATE_MESSAGE *negotiate = talloc(
			ntlmssp_state, struct NEGOTIATE_MESSAGE);
		if (negotiate != NULL) {
			status = ntlmssp_pull_NEGOTIATE_MESSAGE(
				&in, negotiate, negotiate);
			if (NT_STATUS_IS_OK(status)) {
				NDR_PRINT_DEBUG(NEGOTIATE_MESSAGE,
						negotiate);
			}
			TALLOC_FREE(negotiate);
		}
	}

	ntlmssp_state->negotiate_blob = data_blob_dup_talloc(ntlmssp_state,
							     in);
	if (ntlmssp_state->negotiate_blob.length != in.length) {
		return NT_STATUS_NO_MEMORY;
	}

	ntlmssp_state->expected_state = NTLMSSP_CHALLENGE;

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
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	uint32_t chal_flags, ntlmssp_command, unkn1 = 0, unkn2 = 0;
	DATA_BLOB server_domain_blob;
	DATA_BLOB challenge_blob;
	DATA_BLOB target_info = data_blob(NULL, 0);
	char *server_domain;
	const char *chal_parse_string;
	const char *chal_parse_string_short = NULL;
	const char *auth_gen_string;
	DATA_BLOB lm_response = data_blob(NULL, 0);
	DATA_BLOB nt_response = data_blob(NULL, 0);
	DATA_BLOB session_key = data_blob(NULL, 0);
	DATA_BLOB lm_session_key = data_blob(NULL, 0);
	DATA_BLOB encrypted_session_key = data_blob(NULL, 0);
	NTSTATUS nt_status;
	int flags = 0;
	const char *user = NULL, *domain = NULL, *workstation = NULL;
	bool is_anonymous = false;
	const DATA_BLOB version_blob = ntlmssp_version_blob();
	const NTTIME *server_timestamp = NULL;
	uint8_t mic_buffer[NTLMSSP_MIC_SIZE] = { 0, };
	DATA_BLOB mic_blob = data_blob_const(mic_buffer, sizeof(mic_buffer));
	gnutls_hmac_hd_t hmac_hnd = NULL;
	int rc;

	TALLOC_CTX *mem_ctx = talloc_new(out_mem_ctx);
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!msrpc_parse(mem_ctx,
			 &in, "CdBd",
			 "NTLMSSP",
			 &ntlmssp_command,
			 &server_domain_blob,
			 &chal_flags)) {
		DEBUG(1, ("Failed to parse the NTLMSSP Challenge: (#1)\n"));
		dump_data(2, in.data, in.length);
		talloc_free(mem_ctx);

		return NT_STATUS_INVALID_PARAMETER;
	}

	data_blob_free(&server_domain_blob);

	DEBUG(3, ("Got challenge flags:\n"));
	debug_ntlmssp_flags(chal_flags);

	nt_status = ntlmssp_handle_neg_flags(ntlmssp_state,
					     chal_flags, "challenge");
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (ntlmssp_state->unicode) {
		if (chal_flags & NTLMSSP_NEGOTIATE_TARGET_INFO) {
			chal_parse_string = "CdUdbddB";
		} else {
			chal_parse_string = "CdUdbdd";
			chal_parse_string_short = "CdUdb";
		}
		auth_gen_string = "CdBBUUUBdbb";
	} else {
		if (chal_flags & NTLMSSP_NEGOTIATE_TARGET_INFO) {
			chal_parse_string = "CdAdbddB";
		} else {
			chal_parse_string = "CdAdbdd";
			chal_parse_string_short = "CdAdb";
		}

		auth_gen_string = "CdBBAAABdbb";
	}

	if (!msrpc_parse(mem_ctx,
			 &in, chal_parse_string,
			 "NTLMSSP",
			 &ntlmssp_command,
			 &server_domain,
			 &chal_flags,
			 &challenge_blob, 8,
			 &unkn1, &unkn2,
			 &target_info)) {

		bool ok = false;

		DEBUG(1, ("Failed to parse the NTLMSSP Challenge: (#2)\n"));

		if (chal_parse_string_short != NULL) {
			/*
			 * In the case where NTLMSSP_NEGOTIATE_TARGET_INFO
			 * is not used, some NTLMSSP servers don't return
			 * the unused unkn1 and unkn2 fields.
			 * See bug:
			 * https://bugzilla.samba.org/show_bug.cgi?id=10016
			 * for packet traces.
			 * Try and parse again without them.
			 */
			ok = msrpc_parse(mem_ctx,
				&in, chal_parse_string_short,
				"NTLMSSP",
				&ntlmssp_command,
				&server_domain,
				&chal_flags,
				&challenge_blob, 8);
			if (!ok) {
				DEBUG(1, ("Failed to short parse "
					"the NTLMSSP Challenge: (#2)\n"));
			}
		}

		if (!ok) {
			dump_data(2, in.data, in.length);
			talloc_free(mem_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	if (DEBUGLEVEL >= 10) {
		struct CHALLENGE_MESSAGE *challenge =
			talloc(ntlmssp_state, struct CHALLENGE_MESSAGE);
		if (challenge != NULL) {
			NTSTATUS status;
			challenge->NegotiateFlags = chal_flags;
			status = ntlmssp_pull_CHALLENGE_MESSAGE(
					&in, challenge, challenge);
			if (NT_STATUS_IS_OK(status)) {
				NDR_PRINT_DEBUG(CHALLENGE_MESSAGE,
						challenge);
			}
			TALLOC_FREE(challenge);
		}
	}

	if (chal_flags & NTLMSSP_TARGET_TYPE_SERVER) {
		ntlmssp_state->server.is_standalone = true;
	} else {
		ntlmssp_state->server.is_standalone = false;
	}
	/* TODO: parse struct_blob and fill in the rest */
	ntlmssp_state->server.netbios_name = "";
	ntlmssp_state->server.netbios_domain = talloc_move(ntlmssp_state, &server_domain);
	ntlmssp_state->server.dns_name = "";
	ntlmssp_state->server.dns_domain = "";

	if (challenge_blob.length != 8) {
		talloc_free(mem_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	is_anonymous = cli_credentials_is_anonymous(gensec_security->credentials);
	cli_credentials_get_ntlm_username_domain(gensec_security->credentials, mem_ctx,
						 &user, &domain);

	workstation = cli_credentials_get_workstation(gensec_security->credentials);

	if (user == NULL) {
		DEBUG(10, ("User is NULL, returning INVALID_PARAMETER\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (domain == NULL) {
		DEBUG(10, ("Domain is NULL, returning INVALID_PARAMETER\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (workstation == NULL) {
		DEBUG(10, ("Workstation is NULL, returning INVALID_PARAMETER\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (is_anonymous) {
		ntlmssp_state->neg_flags |= NTLMSSP_ANONYMOUS;
		/*
		 * don't use the ccache for anonymous auth
		 */
		ntlmssp_state->use_ccache = false;
	}
	if (ntlmssp_state->use_ccache) {
		struct samr_Password *nt_hash = NULL;

		/*
		 * If we have a password given we don't
		 * use the ccache
		 */
		nt_hash = cli_credentials_get_nt_hash(gensec_security->credentials,
						      mem_ctx);
		if (nt_hash != NULL) {
			ZERO_STRUCTP(nt_hash);
			TALLOC_FREE(nt_hash);
			ntlmssp_state->use_ccache = false;
		}
	}

	if (ntlmssp_state->use_ccache) {
		struct wbcCredentialCacheParams params;
		struct wbcCredentialCacheInfo *info = NULL;
		struct wbcAuthErrorInfo *error = NULL;
		struct wbcNamedBlob auth_blobs[2];
		const struct wbcBlob *wbc_auth_blob = NULL;
		const struct wbcBlob *wbc_session_key = NULL;
		wbcErr wbc_status;
		int i;
		bool new_spnego = false;

		params.account_name = user;
		params.domain_name = domain;
		params.level = WBC_CREDENTIAL_CACHE_LEVEL_NTLMSSP;

		auth_blobs[0].name = "challenge_blob";
		auth_blobs[0].flags = 0;
		auth_blobs[0].blob.data = in.data;
		auth_blobs[0].blob.length = in.length;
		auth_blobs[1].name = "negotiate_blob";
		auth_blobs[1].flags = 0;
		auth_blobs[1].blob.data = ntlmssp_state->negotiate_blob.data;
		auth_blobs[1].blob.length = ntlmssp_state->negotiate_blob.length;
		params.num_blobs = ARRAY_SIZE(auth_blobs);
		params.blobs = auth_blobs;

		wbc_status = wbcCredentialCache(&params, &info, &error);
		wbcFreeMemory(error);
		if (!WBC_ERROR_IS_OK(wbc_status)) {
			return NT_STATUS_WRONG_CREDENTIAL_HANDLE;
		}

		for (i=0; i<info->num_blobs; i++) {
			if (strequal(info->blobs[i].name, "auth_blob")) {
				wbc_auth_blob = &info->blobs[i].blob;
			}
			if (strequal(info->blobs[i].name, "session_key")) {
				wbc_session_key = &info->blobs[i].blob;
			}
			if (strequal(info->blobs[i].name, "new_spnego")) {
				new_spnego = true;
			}
		}
		if ((wbc_auth_blob == NULL) || (wbc_session_key == NULL)) {
			wbcFreeMemory(info);
			return NT_STATUS_WRONG_CREDENTIAL_HANDLE;
		}

		session_key = data_blob_talloc(mem_ctx,
					       wbc_session_key->data,
					       wbc_session_key->length);
		if (session_key.length != wbc_session_key->length) {
			wbcFreeMemory(info);
			return NT_STATUS_NO_MEMORY;
		}
		*out = data_blob_talloc(mem_ctx,
					wbc_auth_blob->data,
					wbc_auth_blob->length);
		if (out->length != wbc_auth_blob->length) {
			wbcFreeMemory(info);
			return NT_STATUS_NO_MEMORY;
		}
		ntlmssp_state->new_spnego = new_spnego;

		wbcFreeMemory(info);
		goto done;
	}

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		flags |= CLI_CRED_NTLM2;
	}
	if (ntlmssp_state->use_ntlmv2) {
		flags |= CLI_CRED_NTLMv2_AUTH;
	}
	if (ntlmssp_state->use_nt_response) {
		flags |= CLI_CRED_NTLM_AUTH;
	}
	if (ntlmssp_state->allow_lm_response) {
		flags |= CLI_CRED_LANMAN_AUTH;
	}

	if (target_info.length != 0 && !is_anonymous) {
		struct AV_PAIR *pairs = NULL;
		uint32_t count = 0;
		enum ndr_err_code err;
		struct AV_PAIR *timestamp = NULL;
		struct AV_PAIR *eol = NULL;
		uint32_t i = 0;
		const char *service = NULL;
		const char *hostname = NULL;

		err = ndr_pull_struct_blob(&target_info,
					ntlmssp_state,
					&ntlmssp_state->server.av_pair_list,
					(ndr_pull_flags_fn_t)ndr_pull_AV_PAIR_LIST);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			return ndr_map_error2ntstatus(err);
		}

		count = ntlmssp_state->server.av_pair_list.count;
		/*
		 * We need room for Flags, SingleHost,
		 * ChannelBindings and Target
		 */
		pairs = talloc_zero_array(ntlmssp_state, struct AV_PAIR,
					  count + 4);
		if (pairs == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		for (i = 0; i < count; i++) {
			pairs[i] = ntlmssp_state->server.av_pair_list.pair[i];
		}

		ntlmssp_state->client.av_pair_list.count = count;
		ntlmssp_state->client.av_pair_list.pair = pairs;

		eol = ndr_ntlmssp_find_av(&ntlmssp_state->client.av_pair_list,
					  MsvAvEOL);
		if (eol == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		timestamp = ndr_ntlmssp_find_av(&ntlmssp_state->client.av_pair_list,
						MsvAvTimestamp);
		if (timestamp != NULL) {
			uint32_t sign_features =
					GENSEC_FEATURE_SESSION_KEY |
					GENSEC_FEATURE_SIGN |
					GENSEC_FEATURE_SEAL;

			server_timestamp = &timestamp->Value.AvTimestamp;

			if (ntlmssp_state->force_old_spnego) {
				sign_features = 0;
			}

			if (gensec_security->want_features & sign_features) {
				struct AV_PAIR *av_flags = NULL;

				av_flags = ndr_ntlmssp_find_av(&ntlmssp_state->client.av_pair_list,
							       MsvAvFlags);
				if (av_flags == NULL) {
					av_flags = eol;
					eol++;
					count++;
					*eol = *av_flags;
					av_flags->AvId = MsvAvFlags;
					av_flags->Value.AvFlags = 0;
				}

				av_flags->Value.AvFlags |= NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE;
				ntlmssp_state->new_spnego = true;
			}
		}

		{
			struct AV_PAIR *SingleHost = NULL;

			SingleHost = eol;
			eol++;
			count++;
			*eol = *SingleHost;

			/*
			 * This is not really used, but we want to
			 * add some more random bytes and match
			 * Windows.
			 */
			SingleHost->AvId = MsvAvSingleHost;
			SingleHost->Value.AvSingleHost.token_info.Flags = 0;
			SingleHost->Value.AvSingleHost.token_info.TokenIL = 0;
			generate_random_buffer(SingleHost->Value.AvSingleHost.token_info.MachineId,
					sizeof(SingleHost->Value.AvSingleHost.token_info.MachineId));
			SingleHost->Value.AvSingleHost.remaining = data_blob_null;
		}

		{
			struct AV_PAIR *ChannelBindings = NULL;

			ChannelBindings = eol;
			eol++;
			count++;
			*eol = *ChannelBindings;

			/*
			 * gensec doesn't support channel bindings yet,
			 * but we want to match Windows on the wire
			 */
			ChannelBindings->AvId = MsvChannelBindings;
			memset(ChannelBindings->Value.ChannelBindings, 0,
			       sizeof(ChannelBindings->Value.ChannelBindings));
		}

		service = gensec_get_target_service(gensec_security);
		hostname = gensec_get_target_hostname(gensec_security);
		if (service != NULL && hostname != NULL) {
			struct AV_PAIR *target = NULL;

			target = eol;
			eol++;
			count++;
			*eol = *target;

			target->AvId = MsvAvTargetName;
			target->Value.AvTargetName = talloc_asprintf(pairs, "%s/%s",
								     service,
								     hostname);
			if (target->Value.AvTargetName == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		ntlmssp_state->client.av_pair_list.count = count;
		ntlmssp_state->client.av_pair_list.pair = pairs;

		err = ndr_push_struct_blob(&target_info,
					ntlmssp_state,
					&ntlmssp_state->client.av_pair_list,
					(ndr_push_flags_fn_t)ndr_push_AV_PAIR_LIST);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	nt_status = cli_credentials_get_ntlm_response(gensec_security->credentials, mem_ctx,
						      &flags, challenge_blob,
						      server_timestamp, target_info,
						      &lm_response, &nt_response,
						      &lm_session_key, &session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (!(flags & CLI_CRED_LANMAN_AUTH)) {
		/* LM Key is still possible, just silly, so we do not
		 * allow it. Fortunetly all LM crypto is off by
		 * default and we require command line options to end
		 * up here */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	if (!(flags & CLI_CRED_NTLM2)) {
		/* NTLM2 is incompatible... */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	}

	if ((ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY)
	    && ntlmssp_state->allow_lm_key && lm_session_key.length == 16) {
		DATA_BLOB new_session_key = data_blob_talloc(mem_ctx, NULL, 16);
		if (lm_response.length == 24) {
			nt_status = SMBsesskeygen_lm_sess_key(lm_session_key.data,
							      lm_response.data,
							      new_session_key.data);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return nt_status;
			}
		} else {
			static const uint8_t zeros[24];
			nt_status = SMBsesskeygen_lm_sess_key(lm_session_key.data,
                                                              zeros,
                                                              new_session_key.data);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return nt_status;
			}
		}
		session_key = new_session_key;
		dump_data_pw("LM session key\n", session_key.data, session_key.length);
	}


	/* Key exchange encryptes a new client-generated session key with
	   the password-derived key */
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		/* Make up a new session key */
		uint8_t client_session_key[16];
		gnutls_cipher_hd_t cipher_hnd;
		gnutls_datum_t enc_session_key = {
			.data = session_key.data,
			.size = session_key.length,
		};

		generate_random_buffer(client_session_key, sizeof(client_session_key));

		/* Encrypt the new session key with the old one */
		encrypted_session_key = data_blob_talloc(ntlmssp_state,
							 client_session_key, sizeof(client_session_key));
		dump_data_pw("KEY_EXCH session key:\n", encrypted_session_key.data, encrypted_session_key.length);

		rc = gnutls_cipher_init(&cipher_hnd,
					GNUTLS_CIPHER_ARCFOUR_128,
					&enc_session_key,
					NULL);
		if (rc < 0) {
			nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
			ZERO_ARRAY(client_session_key);
			goto done;
		}
		rc = gnutls_cipher_encrypt(cipher_hnd,
					   encrypted_session_key.data,
					   encrypted_session_key.length);
		gnutls_cipher_deinit(cipher_hnd);
		if (rc < 0) {
			nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
			ZERO_ARRAY(client_session_key);
			goto done;
		}

		dump_data_pw("KEY_EXCH session key (enc):\n", encrypted_session_key.data, encrypted_session_key.length);

		/* Mark the new session key as the 'real' session key */
		session_key = data_blob_talloc(mem_ctx, client_session_key, sizeof(client_session_key));
		ZERO_ARRAY(client_session_key);
	}

	/* this generates the actual auth packet */
	nt_status = msrpc_gen(mem_ctx,
		       out, auth_gen_string,
		       "NTLMSSP",
		       NTLMSSP_AUTH,
		       lm_response.data, lm_response.length,
		       nt_response.data, nt_response.length,
		       domain,
		       user,
		       workstation,
		       encrypted_session_key.data, encrypted_session_key.length,
		       ntlmssp_state->neg_flags,
		       version_blob.data, version_blob.length,
		       mic_blob.data, mic_blob.length);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return nt_status;
	}

	if (DEBUGLEVEL >= 10) {
		struct AUTHENTICATE_MESSAGE *authenticate =
			talloc(ntlmssp_state, struct AUTHENTICATE_MESSAGE);
		if (authenticate != NULL) {
			NTSTATUS status;
			authenticate->NegotiateFlags = ntlmssp_state->neg_flags;
			status = ntlmssp_pull_AUTHENTICATE_MESSAGE(
				out, authenticate, authenticate);
			if (NT_STATUS_IS_OK(status)) {
				NDR_PRINT_DEBUG(AUTHENTICATE_MESSAGE,
						authenticate);
			}
			TALLOC_FREE(authenticate);
		}
	}

	/*
	 * We always include the MIC, even without:
	 * av_flags->Value.AvFlags |= NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE;
	 * ntlmssp_state->new_spnego = true;
	 *
	 * This matches a Windows client.
	 */
	rc = gnutls_hmac_init(&hmac_hnd,
			      GNUTLS_MAC_MD5,
			 session_key.data,
			 MIN(session_key.length, 64));
	if (rc < 0) {
		nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		goto done;
	}

	rc = gnutls_hmac(hmac_hnd,
			 ntlmssp_state->negotiate_blob.data,
			 ntlmssp_state->negotiate_blob.length);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		goto done;
	}
	rc = gnutls_hmac(hmac_hnd, in.data, in.length);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		goto done;
	}
	rc = gnutls_hmac(hmac_hnd, out->data, out->length);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		goto done;
	}

	gnutls_hmac_deinit(hmac_hnd, mic_buffer);

	memcpy(out->data + NTLMSSP_MIC_OFFSET, mic_buffer, NTLMSSP_MIC_SIZE);
	ZERO_ARRAY(mic_buffer);

	nt_status = NT_STATUS_OK;
done:
	ZERO_ARRAY_LEN(ntlmssp_state->negotiate_blob.data,
		       ntlmssp_state->negotiate_blob.length);
	data_blob_free(&ntlmssp_state->negotiate_blob);

	ntlmssp_state->session_key = session_key;
	talloc_steal(ntlmssp_state, session_key.data);

	DEBUG(3, ("NTLMSSP: Set final flags:\n"));
	debug_ntlmssp_flags(ntlmssp_state->neg_flags);

	talloc_steal(out_mem_ctx, out->data);

	ntlmssp_state->expected_state = NTLMSSP_DONE;

	if (gensec_ntlmssp_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		nt_status = ntlmssp_sign_init(ntlmssp_state);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1, ("Could not setup NTLMSSP signing/sealing system (error was: %s)\n",
				  nt_errstr(nt_status)));
			talloc_free(mem_ctx);
			return nt_status;
		}
	}

	talloc_free(mem_ctx);
	return nt_status;
}

NTSTATUS gensec_ntlmssp_client_start(struct gensec_security *gensec_security)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp;
	struct ntlmssp_state *ntlmssp_state;
	NTSTATUS nt_status;

	nt_status = gensec_ntlmssp_start(gensec_security);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);

	ntlmssp_state = talloc_zero(gensec_ntlmssp,
				    struct ntlmssp_state);
	if (!ntlmssp_state) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_ntlmssp->ntlmssp_state = ntlmssp_state;

	ntlmssp_state = gensec_ntlmssp->ntlmssp_state;

	ntlmssp_state->role = NTLMSSP_CLIENT;

	ntlmssp_state->client.netbios_domain = lpcfg_workgroup(gensec_security->settings->lp_ctx);
	ntlmssp_state->client.netbios_name = cli_credentials_get_workstation(gensec_security->credentials);

	ntlmssp_state->unicode = gensec_setting_bool(gensec_security->settings, "ntlmssp_client", "unicode", true);

	ntlmssp_state->use_nt_response = \
		gensec_setting_bool(gensec_security->settings,
				    "ntlmssp_client",
				    "send_nt_response",
				    true);

	ntlmssp_state->allow_lm_response = lpcfg_client_lanman_auth(gensec_security->settings->lp_ctx);

	ntlmssp_state->allow_lm_key = (ntlmssp_state->allow_lm_response
					      && (gensec_setting_bool(gensec_security->settings, "ntlmssp_client", "allow_lm_key", false)
						  || gensec_setting_bool(gensec_security->settings, "ntlmssp_client", "lm_key", false)));

	ntlmssp_state->use_ntlmv2 = lpcfg_client_ntlmv2_auth(gensec_security->settings->lp_ctx);

	ntlmssp_state->force_old_spnego = gensec_setting_bool(gensec_security->settings,
						"ntlmssp_client", "force_old_spnego", false);

	ntlmssp_state->expected_state = NTLMSSP_INITIAL;

	ntlmssp_state->neg_flags =
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_NEGOTIATE_VERSION |
		NTLMSSP_REQUEST_TARGET;

	if (ntlmssp_state->unicode) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_UNICODE;
	} else {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_OEM;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_client", "128bit", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_128;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_client", "56bit", false)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_56;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_client", "lm_key", false)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_LM_KEY;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_client", "keyexchange", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_KEY_EXCH;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_client", "alwayssign", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_client", "ntlm2", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_NTLM2;
	} else {
		/* apparently we can't do ntlmv2 if we don't do ntlm2 */
		ntlmssp_state->use_ntlmv2 = false;
	}

	if (ntlmssp_state->use_ntlmv2) {
		ntlmssp_state->required_flags |= NTLMSSP_NEGOTIATE_NTLM2;
		ntlmssp_state->allow_lm_response = false;
		ntlmssp_state->allow_lm_key = false;
	}

	if (ntlmssp_state->allow_lm_key) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_LM_KEY;
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
		 *
		 * We don't require this here as some servers (e.g. NetAPP)
		 * doesn't support this.
		 */
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		ntlmssp_state->required_flags |= NTLMSSP_NEGOTIATE_SIGN;

		if (gensec_security->want_features & GENSEC_FEATURE_LDAP_STYLE) {
			/*
			 * We need to handle NTLMSSP_NEGOTIATE_SIGN as
			 * NTLMSSP_NEGOTIATE_SEAL if GENSEC_FEATURE_LDAP_STYLE
			 * is requested.
			 */
			ntlmssp_state->force_wrap_seal = true;
		}
	}
	if (ntlmssp_state->force_wrap_seal) {
		bool ret;

		/*
		 * We want also work against old Samba servers
		 * which didn't had GENSEC_FEATURE_LDAP_STYLE
		 * we negotiate SEAL too. We may remove this
		 * in a few years. As all servers should have
		 * GENSEC_FEATURE_LDAP_STYLE by then.
		 */
		ret = gensec_setting_bool(gensec_security->settings,
					  "ntlmssp_client",
					  "ldap_style_send_seal",
					  true);
		if (ret) {
			ntlmssp_state->required_flags |= NTLMSSP_NEGOTIATE_SEAL;
		}
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		ntlmssp_state->required_flags |= NTLMSSP_NEGOTIATE_SIGN;
		ntlmssp_state->required_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_NTLM_CCACHE) {
		ntlmssp_state->use_ccache = true;
	}

	ntlmssp_state->neg_flags |= ntlmssp_state->required_flags;
	ntlmssp_state->conf_flags = ntlmssp_state->neg_flags;

	return NT_STATUS_OK;
}

NTSTATUS gensec_ntlmssp_resume_ccache_start(struct gensec_security *gensec_security)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp = NULL;
	NTSTATUS status;

	status = gensec_ntlmssp_client_start(gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	gensec_ntlmssp = talloc_get_type_abort(gensec_security->private_data,
					       struct gensec_ntlmssp_context);
	gensec_ntlmssp->ntlmssp_state->use_ccache = false;
	gensec_ntlmssp->ntlmssp_state->resume_ccache = true;
	gensec_ntlmssp->ntlmssp_state->expected_state = NTLMSSP_NEGOTIATE;

	return NT_STATUS_OK;
}
