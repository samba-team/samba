/*
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NTLMSSP, server side

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2010

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
#include "lib/util/time_basic.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "auth/ntlmssp/ntlmssp_private.h"
#include "../librpc/gen_ndr/ndr_ntlmssp.h"
#include "auth/ntlmssp/ntlmssp_ndr.h"
#include "../libcli/auth/libcli_auth.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/common_auth.h"
#include "param/param.h"
#include "param/loadparm.h"
#include "libcli/security/session.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/**
 * Determine correct target name flags for reply, given server role
 * and negotiated flags
 *
 * @param ntlmssp_state NTLMSSP State
 * @param neg_flags The flags from the packet
 * @param chal_flags The flags to be set in the reply packet
 * @return The 'target name' string.
 */

const char *ntlmssp_target_name(struct ntlmssp_state *ntlmssp_state,
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
 * Next state function for the NTLMSSP Negotiate packet
 *
 * @param gensec_security GENSEC state
 * @param out_mem_ctx Memory context for *out
 * @param in The request, as a DATA_BLOB.  reply.data must be NULL
 * @param out The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors or MORE_PROCESSING_REQUIRED if (normal) a reply is required.
 */

NTSTATUS gensec_ntlmssp_server_negotiate(struct gensec_security *gensec_security,
					 TALLOC_CTX *out_mem_ctx,
					 const DATA_BLOB request, DATA_BLOB *reply)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	struct auth4_context *auth_context = gensec_security->auth_context;
	DATA_BLOB struct_blob;
	uint32_t neg_flags = 0;
	uint32_t ntlmssp_command, chal_flags;
	uint8_t cryptkey[8];
	const char *target_name;
	NTSTATUS status;
	struct timeval tv_now = timeval_current();
	/*
	 * See [MS-NLMP]
	 *
	 * Windows NT 4.0, windows_2000: use 30 minutes,
	 * Windows XP, Windows Server 2003, Windows Vista,
	 * Windows Server 2008, Windows 7, and Windows Server 2008 R2
	 * use 36 hours.
	 *
	 * Newer systems doesn't check this, likely because the
	 * connectionless NTLMSSP is no longer supported.
	 *
	 * As we expect the AUTHENTICATION_MESSAGE to arrive
	 * directly after the NEGOTIATE_MESSAGE (typically less than
	 * as 1 second later). We use a hard timeout of 30 Minutes.
	 *
	 * We don't look at AUTHENTICATE_MESSAGE.NtChallengeResponse.TimeStamp
	 * instead we just remember our own time.
	 */
	uint32_t max_lifetime = 30 * 60;
	struct timeval tv_end = timeval_add(&tv_now, max_lifetime, 0);

	/* parse the NTLMSSP packet */
#if 0
	file_save("ntlmssp_negotiate.dat", request.data, request.length);
#endif

	if (request.length) {
		if (request.length > UINT16_MAX) {
			DEBUG(1, ("ntlmssp_server_negotiate: reject large request of length %u\n",
				(unsigned int)request.length));
			return NT_STATUS_INVALID_PARAMETER;
		}

		if ((request.length < 16) || !msrpc_parse(ntlmssp_state, &request, "Cdd",
							  "NTLMSSP",
							  &ntlmssp_command,
							  &neg_flags)) {
			DEBUG(1, ("ntlmssp_server_negotiate: failed to parse NTLMSSP Negotiate of length %u\n",
				(unsigned int)request.length));
			dump_data(2, request.data, request.length);
			return NT_STATUS_INVALID_PARAMETER;
		}
		debug_ntlmssp_flags(neg_flags);

		if (DEBUGLEVEL >= 10) {
			struct NEGOTIATE_MESSAGE *negotiate = talloc(
				ntlmssp_state, struct NEGOTIATE_MESSAGE);
			if (negotiate != NULL) {
				status = ntlmssp_pull_NEGOTIATE_MESSAGE(
					&request, negotiate, negotiate);
				if (NT_STATUS_IS_OK(status)) {
					NDR_PRINT_DEBUG(NEGOTIATE_MESSAGE,
							negotiate);
				}
				TALLOC_FREE(negotiate);
			}
		}
	}

	status = ntlmssp_handle_neg_flags(ntlmssp_state, neg_flags, "negotiate");
	if (!NT_STATUS_IS_OK(status)){
		return status;
	}

	/* Ask our caller what challenge they would like in the packet */
	if (auth_context->get_ntlm_challenge) {
		status = auth_context->get_ntlm_challenge(auth_context, cryptkey);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("gensec_ntlmssp_server_negotiate: failed to get challenge: %s\n",
				  nt_errstr(status)));
			return status;
		}
	} else {
		DEBUG(1, ("gensec_ntlmssp_server_negotiate: backend doesn't give a challenge\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/* The flags we send back are not just the negotiated flags,
	 * they are also 'what is in this packet'.  Therfore, we
	 * operate on 'chal_flags' from here on
	 */

	chal_flags = ntlmssp_state->neg_flags;
	ntlmssp_state->server.challenge_endtime = timeval_to_nttime(&tv_end);

	/* get the right name to fill in as 'target' */
	target_name = ntlmssp_target_name(ntlmssp_state,
					  neg_flags, &chal_flags);
	if (target_name == NULL)
		return NT_STATUS_INVALID_PARAMETER;

	ntlmssp_state->chal = data_blob_talloc(ntlmssp_state, cryptkey, 8);
	ntlmssp_state->internal_chal = data_blob_talloc(ntlmssp_state,
							cryptkey, 8);

	/* This creates the 'blob' of names that appears at the end of the packet */
	if (chal_flags & NTLMSSP_NEGOTIATE_TARGET_INFO) {
		enum ndr_err_code err;
		struct AV_PAIR *pairs = NULL;
		uint32_t count = 5;

		pairs = talloc_zero_array(ntlmssp_state, struct AV_PAIR, count + 1);
		if (pairs == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		pairs[0].AvId			= MsvAvNbDomainName;
		pairs[0].Value.AvNbDomainName	= target_name;

		pairs[1].AvId			= MsvAvNbComputerName;
		pairs[1].Value.AvNbComputerName	= ntlmssp_state->server.netbios_name;

		pairs[2].AvId			= MsvAvDnsDomainName;
		pairs[2].Value.AvDnsDomainName	= ntlmssp_state->server.dns_domain;

		pairs[3].AvId			= MsvAvDnsComputerName;
		pairs[3].Value.AvDnsComputerName= ntlmssp_state->server.dns_name;

		if (!ntlmssp_state->force_old_spnego) {
			pairs[4].AvId			= MsvAvTimestamp;
			pairs[4].Value.AvTimestamp	=
						timeval_to_nttime(&tv_now);
			count += 1;

			pairs[5].AvId			= MsvAvEOL;
		} else {
			pairs[4].AvId			= MsvAvEOL;
		}

		ntlmssp_state->server.av_pair_list.count = count;
		ntlmssp_state->server.av_pair_list.pair = pairs;

		err = ndr_push_struct_blob(&struct_blob,
					ntlmssp_state,
					&ntlmssp_state->server.av_pair_list,
					(ndr_push_flags_fn_t)ndr_push_AV_PAIR_LIST);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		struct_blob = data_blob_null;
	}

	{
		/* Marshal the packet in the right format, be it unicode or ASCII */
		const char *gen_string;
		const DATA_BLOB version_blob = ntlmssp_version_blob();

		if (ntlmssp_state->unicode) {
			gen_string = "CdUdbddBb";
		} else {
			gen_string = "CdAdbddBb";
		}

		status = msrpc_gen(out_mem_ctx, reply, gen_string,
			"NTLMSSP",
			NTLMSSP_CHALLENGE,
			target_name,
			chal_flags,
			cryptkey, 8,
			0, 0,
			struct_blob.data, struct_blob.length,
			version_blob.data, version_blob.length);

		if (!NT_STATUS_IS_OK(status)) {
			data_blob_free(&struct_blob);
			return status;
		}

		if (DEBUGLEVEL >= 10) {
			struct CHALLENGE_MESSAGE *challenge = talloc(
				ntlmssp_state, struct CHALLENGE_MESSAGE);
			if (challenge != NULL) {
				challenge->NegotiateFlags = chal_flags;
				status = ntlmssp_pull_CHALLENGE_MESSAGE(
					reply, challenge, challenge);
				if (NT_STATUS_IS_OK(status)) {
					NDR_PRINT_DEBUG(CHALLENGE_MESSAGE,
							challenge);
				}
				TALLOC_FREE(challenge);
			}
		}
	}

	data_blob_free(&struct_blob);

	ntlmssp_state->negotiate_blob = data_blob_dup_talloc(ntlmssp_state,
							     request);
	if (ntlmssp_state->negotiate_blob.length != request.length) {
		return NT_STATUS_NO_MEMORY;
	}

	ntlmssp_state->challenge_blob = data_blob_dup_talloc(ntlmssp_state,
							     *reply);
	if (ntlmssp_state->challenge_blob.length != reply->length) {
		return NT_STATUS_NO_MEMORY;
	}

	ntlmssp_state->expected_state = NTLMSSP_AUTH;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

struct ntlmssp_server_auth_state {
	struct gensec_security *gensec_security;
	struct gensec_ntlmssp_context *gensec_ntlmssp;
	DATA_BLOB in;
	struct auth_usersupplied_info *user_info;
	DATA_BLOB user_session_key;
	DATA_BLOB lm_session_key;
	/* internal variables used by KEY_EXCH (client-supplied user session key */
	DATA_BLOB encrypted_session_key;
	bool doing_ntlm2;
	/* internal variables used by NTLM2 */
	uint8_t session_nonce[16];
};

static NTSTATUS ntlmssp_server_preauth(struct gensec_security *gensec_security,
				       struct gensec_ntlmssp_context *gensec_ntlmssp,
				       struct ntlmssp_server_auth_state *state,
				       const DATA_BLOB request);
static void ntlmssp_server_auth_done(struct tevent_req *subreq);
static NTSTATUS ntlmssp_server_postauth(struct gensec_security *gensec_security,
					struct gensec_ntlmssp_context *gensec_ntlmssp,
					struct ntlmssp_server_auth_state *state,
					DATA_BLOB request);

struct tevent_req *ntlmssp_server_auth_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct gensec_security *gensec_security,
					    const DATA_BLOB in)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct auth4_context *auth_context = gensec_security->auth_context;
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct ntlmssp_server_auth_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct ntlmssp_server_auth_state);
	if (req == NULL) {
		return NULL;
	}
	state->gensec_security = gensec_security;
	state->gensec_ntlmssp = gensec_ntlmssp;
	state->in = in;

	status = ntlmssp_server_preauth(gensec_security,
					gensec_ntlmssp,
					state, in);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = auth_context->check_ntlm_password_send(
		state, ev, auth_context, state->user_info);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,	ntlmssp_server_auth_done, req);
	return req;
}

/**
 * Next state function for the Authenticate packet
 *
 * @param ntlmssp_state NTLMSSP State
 * @param request The request, as a DATA_BLOB
 * @return Errors or NT_STATUS_OK.
 */

static NTSTATUS ntlmssp_server_preauth(struct gensec_security *gensec_security,
				       struct gensec_ntlmssp_context *gensec_ntlmssp,
				       struct ntlmssp_server_auth_state *state,
				       const DATA_BLOB request)
{
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	struct auth4_context *auth_context = gensec_security->auth_context;
	struct auth_usersupplied_info *user_info = NULL;
	uint32_t ntlmssp_command, auth_flags;
	NTSTATUS nt_status;
	const unsigned int version_len = 8;
	DATA_BLOB version_blob = data_blob_null;
	const unsigned int mic_len = NTLMSSP_MIC_SIZE;
	DATA_BLOB mic_blob = data_blob_null;
	const char *parse_string;
	bool ok;
	struct timeval endtime;
	bool expired = false;

#if 0
	file_save("ntlmssp_auth.dat", request.data, request.length);
#endif

	if (ntlmssp_state->unicode) {
		parse_string = "CdBBUUUBdbb";
	} else {
		parse_string = "CdBBAAABdbb";
	}

	/* zero these out */
	data_blob_free(&ntlmssp_state->session_key);
	data_blob_free(&ntlmssp_state->lm_resp);
	data_blob_free(&ntlmssp_state->nt_resp);

	ntlmssp_state->user = NULL;
	ntlmssp_state->domain = NULL;
	ntlmssp_state->client.netbios_name = NULL;

	/* now the NTLMSSP encoded auth hashes */
	ok = msrpc_parse(ntlmssp_state, &request, parse_string,
			 "NTLMSSP",
			 &ntlmssp_command,
			 &ntlmssp_state->lm_resp,
			 &ntlmssp_state->nt_resp,
			 &ntlmssp_state->domain,
			 &ntlmssp_state->user,
			 &ntlmssp_state->client.netbios_name,
			 &state->encrypted_session_key,
			 &auth_flags,
			 &version_blob, version_len,
			 &mic_blob, mic_len);
	if (!ok) {
		DEBUG(10, ("ntlmssp_server_auth: failed to parse NTLMSSP (nonfatal):\n"));
		dump_data(10, request.data, request.length);

		data_blob_free(&version_blob);
		data_blob_free(&mic_blob);

		if (ntlmssp_state->unicode) {
			parse_string = "CdBBUUUBd";
		} else {
			parse_string = "CdBBAAABd";
		}

		ok = msrpc_parse(ntlmssp_state, &request, parse_string,
				 "NTLMSSP",
				 &ntlmssp_command,
				 &ntlmssp_state->lm_resp,
				 &ntlmssp_state->nt_resp,
				 &ntlmssp_state->domain,
				 &ntlmssp_state->user,
				 &ntlmssp_state->client.netbios_name,
				 &state->encrypted_session_key,
				 &auth_flags);
	}

	if (!ok) {
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
		if (!msrpc_parse(ntlmssp_state, &request, parse_string,
				 "NTLMSSP",
				 &ntlmssp_command,
				 &ntlmssp_state->lm_resp,
				 &ntlmssp_state->nt_resp,
				 &ntlmssp_state->domain,
				 &ntlmssp_state->user,
				 &ntlmssp_state->client.netbios_name)) {
			DEBUG(1, ("ntlmssp_server_auth: failed to parse NTLMSSP (tried both formats):\n"));
			dump_data(2, request.data, request.length);

			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	talloc_steal(state, state->encrypted_session_key.data);

	if (auth_flags != 0) {
		nt_status = ntlmssp_handle_neg_flags(ntlmssp_state,
						     auth_flags,
						     "authenticate");
		if (!NT_STATUS_IS_OK(nt_status)){
			return nt_status;
		}
	}

	if (DEBUGLEVEL >= 10) {
		struct AUTHENTICATE_MESSAGE *authenticate = talloc(
			ntlmssp_state, struct AUTHENTICATE_MESSAGE);
		if (authenticate != NULL) {
			NTSTATUS status;
			authenticate->NegotiateFlags = auth_flags;
			status = ntlmssp_pull_AUTHENTICATE_MESSAGE(
				&request, authenticate, authenticate);
			if (NT_STATUS_IS_OK(status)) {
				NDR_PRINT_DEBUG(AUTHENTICATE_MESSAGE,
						authenticate);
			}
			TALLOC_FREE(authenticate);
		}
	}

	DEBUG(3,("Got user=[%s] domain=[%s] workstation=[%s] len1=%lu len2=%lu\n",
		 ntlmssp_state->user, ntlmssp_state->domain,
		 ntlmssp_state->client.netbios_name,
		 (unsigned long)ntlmssp_state->lm_resp.length,
		 (unsigned long)ntlmssp_state->nt_resp.length));

#if 0
	file_save("nthash1.dat",  &ntlmssp_state->nt_resp.data,  &ntlmssp_state->nt_resp.length);
	file_save("lmhash1.dat",  &ntlmssp_state->lm_resp.data,  &ntlmssp_state->lm_resp.length);
#endif

	if (ntlmssp_state->nt_resp.length > 24) {
		struct NTLMv2_RESPONSE v2_resp;
		enum ndr_err_code err;
		uint32_t i = 0;
		uint32_t count = 0;
		const struct AV_PAIR *flags = NULL;
		const struct AV_PAIR *eol = NULL;
		uint32_t av_flags = 0;

		err = ndr_pull_struct_blob(&ntlmssp_state->nt_resp,
					ntlmssp_state,
					&v2_resp,
					(ndr_pull_flags_fn_t)ndr_pull_NTLMv2_RESPONSE);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			nt_status = ndr_map_error2ntstatus(err);
			DEBUG(1,("%s: failed to parse NTLMv2_RESPONSE of length %zu for "
				 "user=[%s] domain=[%s] workstation=[%s] - %s %s\n",
				 __func__, ntlmssp_state->nt_resp.length,
				 ntlmssp_state->user, ntlmssp_state->domain,
				 ntlmssp_state->client.netbios_name,
				 ndr_errstr(err), nt_errstr(nt_status)));
			return nt_status;
		}

		if (DEBUGLVL(10)) {
			NDR_PRINT_DEBUG(NTLMv2_RESPONSE, &v2_resp);
		}

		eol = ndr_ntlmssp_find_av(&v2_resp.Challenge.AvPairs,
					  MsvAvEOL);
		if (eol == NULL) {
			DEBUG(1,("%s: missing MsvAvEOL for "
				 "user=[%s] domain=[%s] workstation=[%s]\n",
				 __func__, ntlmssp_state->user, ntlmssp_state->domain,
				 ntlmssp_state->client.netbios_name));
			return NT_STATUS_INVALID_PARAMETER;
		}

		flags = ndr_ntlmssp_find_av(&v2_resp.Challenge.AvPairs,
					    MsvAvFlags);
		if (flags != NULL) {
			av_flags = flags->Value.AvFlags;
		}

		if (av_flags & NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE) {
			if (mic_blob.length != NTLMSSP_MIC_SIZE) {
				DEBUG(1,("%s: mic_blob.length[%u] for "
					 "user=[%s] domain=[%s] workstation=[%s]\n",
					 __func__,
					 (unsigned)mic_blob.length,
					 ntlmssp_state->user,
					 ntlmssp_state->domain,
					 ntlmssp_state->client.netbios_name));
				return NT_STATUS_INVALID_PARAMETER;
			}

			if (request.length <
			    (NTLMSSP_MIC_OFFSET + NTLMSSP_MIC_SIZE))
			{
				DEBUG(1,("%s: missing MIC "
					 "request.length[%u] for "
					 "user=[%s] domain=[%s] workstation=[%s]\n",
					 __func__,
					 (unsigned)request.length,
					 ntlmssp_state->user,
					 ntlmssp_state->domain,
					 ntlmssp_state->client.netbios_name));
				return NT_STATUS_INVALID_PARAMETER;
			}

			ntlmssp_state->new_spnego = true;
		}

		count = ntlmssp_state->server.av_pair_list.count;
		if (v2_resp.Challenge.AvPairs.count < count) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		for (i = 0; i < count; i++) {
			const struct AV_PAIR *sp =
				&ntlmssp_state->server.av_pair_list.pair[i];
			const struct AV_PAIR *cp = NULL;

			if (sp->AvId == MsvAvEOL) {
				continue;
			}

			cp = ndr_ntlmssp_find_av(&v2_resp.Challenge.AvPairs,
						 sp->AvId);
			if (cp == NULL) {
				DEBUG(1,("%s: AvId 0x%x missing for"
					 "user=[%s] domain=[%s] "
					 "workstation=[%s]\n",
					 __func__,
					 (unsigned)sp->AvId,
					 ntlmssp_state->user,
					 ntlmssp_state->domain,
					 ntlmssp_state->client.netbios_name));
				return NT_STATUS_INVALID_PARAMETER;
			}

			switch (cp->AvId) {
#define CASE_STRING(v) case Msv ## v: do { \
	int cmp; \
	if (sp->Value.v == NULL) { \
		return NT_STATUS_INTERNAL_ERROR; \
	} \
	if (cp->Value.v == NULL) { \
		DEBUG(1,("%s: invalid %s " \
			 "got[%s] expect[%s] for " \
			 "user=[%s] domain=[%s] workstation=[%s]\n", \
			 __func__, #v, \
			 cp->Value.v, \
			 sp->Value.v, \
			 ntlmssp_state->user, \
			 ntlmssp_state->domain, \
			 ntlmssp_state->client.netbios_name)); \
		return NT_STATUS_INVALID_PARAMETER; \
	} \
	cmp = strcmp(cp->Value.v, sp->Value.v); \
	if (cmp != 0) { \
		DEBUG(1,("%s: invalid %s " \
			 "got[%s] expect[%s] for " \
			 "user=[%s] domain=[%s] workstation=[%s]\n", \
			 __func__, #v, \
			 cp->Value.v, \
			 sp->Value.v, \
			 ntlmssp_state->user, \
			 ntlmssp_state->domain, \
			 ntlmssp_state->client.netbios_name)); \
		return NT_STATUS_INVALID_PARAMETER; \
	} \
} while(0); break
			CASE_STRING(AvNbComputerName);
			CASE_STRING(AvNbDomainName);
			CASE_STRING(AvDnsComputerName);
			CASE_STRING(AvDnsDomainName);
			CASE_STRING(AvDnsTreeName);
			case MsvAvTimestamp:
				if (cp->Value.AvTimestamp != sp->Value.AvTimestamp) {
					struct timeval ct;
					struct timeval st;
					struct timeval_buf tmp1;
					struct timeval_buf tmp2;

					nttime_to_timeval(&ct,
							  cp->Value.AvTimestamp);
					nttime_to_timeval(&st,
							  sp->Value.AvTimestamp);

					DEBUG(1,("%s: invalid AvTimestamp "
						 "got[%s] expect[%s] for "
						 "user=[%s] domain=[%s] "
						 "workstation=[%s]\n",
						 __func__,
						 timeval_str_buf(&ct, false,
								 true, &tmp1),
						 timeval_str_buf(&st, false,
								 true, &tmp2),
						 ntlmssp_state->user,
						 ntlmssp_state->domain,
						 ntlmssp_state->client.netbios_name));
					return NT_STATUS_INVALID_PARAMETER;
				}
				break;
			default:
				/*
				 * This can't happen as we control
				 * ntlmssp_state->server.av_pair_list
				 */
				return NT_STATUS_INTERNAL_ERROR;
			}
		}
	}

	nttime_to_timeval(&endtime, ntlmssp_state->server.challenge_endtime);
	expired = timeval_expired(&endtime);
	if (expired) {
		struct timeval_buf tmp;
		DEBUG(1,("%s: challenge invalid (expired %s) for "
			 "user=[%s] domain=[%s] workstation=[%s]\n",
			 __func__,
			 timeval_str_buf(&endtime, false, true, &tmp),
			 ntlmssp_state->user, ntlmssp_state->domain,
			 ntlmssp_state->client.netbios_name));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* NTLM2 uses a 'challenge' that is made of up both the server challenge, and a
	   client challenge

	   However, the NTLM2 flag may still be set for the real NTLMv2 logins, be careful.
	*/
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		if (ntlmssp_state->nt_resp.length == 24 && ntlmssp_state->lm_resp.length == 24) {
			state->doing_ntlm2 = true;

			memcpy(state->session_nonce, ntlmssp_state->internal_chal.data, 8);
			memcpy(&state->session_nonce[8], ntlmssp_state->lm_resp.data, 8);

			SMB_ASSERT(ntlmssp_state->internal_chal.data && ntlmssp_state->internal_chal.length == 8);

			/* LM response is no longer useful */
			data_blob_free(&ntlmssp_state->lm_resp);

			/* We changed the effective challenge - set it */
			if (auth_context->set_ntlm_challenge) {
				uint8_t session_nonce_hash[16];
				int rc;

				rc = gnutls_hash_fast(GNUTLS_DIG_MD5,
						      state->session_nonce,
						      16,
						      session_nonce_hash);
				if (rc < 0) {
					return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
				}


				nt_status = auth_context->set_ntlm_challenge(auth_context,
									     session_nonce_hash,
									     "NTLMSSP callback (NTLM2)");
				ZERO_ARRAY(session_nonce_hash);
				if (!NT_STATUS_IS_OK(nt_status)) {
					DEBUG(1, ("gensec_ntlmssp_server_negotiate: failed to get challenge: %s\n",
						  nt_errstr(nt_status)));
					return nt_status;
				}
			} else {
				DEBUG(1, ("gensec_ntlmssp_server_negotiate: backend doesn't have facility for challenge to be set\n"));

				return NT_STATUS_NOT_IMPLEMENTED;
			}

			/* LM Key is incompatible. */
			ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
		}
	}

	user_info = talloc_zero(state, struct auth_usersupplied_info);
	if (!user_info) {
		return NT_STATUS_NO_MEMORY;
	}

	user_info->logon_parameters = MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT | MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT;
	user_info->flags = 0;
	user_info->mapped_state = false;
	user_info->client.account_name = ntlmssp_state->user;
	user_info->client.domain_name = ntlmssp_state->domain;
	user_info->workstation_name = ntlmssp_state->client.netbios_name;
	user_info->remote_host = gensec_get_remote_address(gensec_security);
	user_info->local_host = gensec_get_local_address(gensec_security);
	user_info->service_description
		= gensec_get_target_service_description(gensec_security);

	/*
	 * This will just be the string "NTLMSSP" from
	 * gensec_ntlmssp_final_auth_type, but ensures it stays in sync
	 * with the same use in the authorization logging triggered by
	 * gensec_session_info() later
	 */
	user_info->auth_description = gensec_final_auth_type(gensec_security);

	user_info->password_state = AUTH_PASSWORD_RESPONSE;
	user_info->password.response.lanman = ntlmssp_state->lm_resp;
	user_info->password.response.nt = ntlmssp_state->nt_resp;

	state->user_info = user_info;
	return NT_STATUS_OK;
}

static void ntlmssp_server_auth_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct ntlmssp_server_auth_state *state =
		tevent_req_data(req,
		struct ntlmssp_server_auth_state);
	struct gensec_security *gensec_security = state->gensec_security;
	struct gensec_ntlmssp_context *gensec_ntlmssp = state->gensec_ntlmssp;
	struct auth4_context *auth_context = gensec_security->auth_context;
	uint8_t authoritative = 1;
	NTSTATUS status;

	status = auth_context->check_ntlm_password_recv(subreq,
						gensec_ntlmssp,
						&authoritative,
						&gensec_ntlmssp->server_returned_info,
						&state->user_session_key,
						&state->lm_session_key);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("Checking NTLMSSP password for %s\\%s failed: %s\n",
			 state->user_info->client.domain_name,
			 state->user_info->client.account_name,
			 nt_errstr(status));
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}
	talloc_steal(state, state->user_session_key.data);
	talloc_steal(state, state->lm_session_key.data);

	status = ntlmssp_server_postauth(state->gensec_security,
					 state->gensec_ntlmssp,
					 state, state->in);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

/**
 * Next state function for the Authenticate packet
 * (after authentication - figures out the session keys etc)
 *
 * @param ntlmssp_state NTLMSSP State
 * @return Errors or NT_STATUS_OK.
 */

static NTSTATUS ntlmssp_server_postauth(struct gensec_security *gensec_security,
					struct gensec_ntlmssp_context *gensec_ntlmssp,
					struct ntlmssp_server_auth_state *state,
					DATA_BLOB request)
{
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	struct auth4_context *auth_context = gensec_security->auth_context;
	DATA_BLOB user_session_key = state->user_session_key;
	DATA_BLOB lm_session_key = state->lm_session_key;
	NTSTATUS nt_status = NT_STATUS_OK;
	DATA_BLOB session_key = data_blob(NULL, 0);
	struct auth_session_info *session_info = NULL;

	TALLOC_FREE(state->user_info);

	if (lpcfg_map_to_guest(gensec_security->settings->lp_ctx) != NEVER_MAP_TO_GUEST
	    && auth_context->generate_session_info != NULL)
	{
		NTSTATUS tmp_status;

		/*
		 * We need to check if the auth is anonymous or mapped to guest
		 */
		tmp_status = auth_context->generate_session_info(auth_context, state,
								 gensec_ntlmssp->server_returned_info,
								 gensec_ntlmssp->ntlmssp_state->user,
								 AUTH_SESSION_INFO_SIMPLE_PRIVILEGES,
								 &session_info);
		if (!NT_STATUS_IS_OK(tmp_status)) {
			/*
			 * We don't care about failures,
			 * the worst result is that we try MIC checking
			 * for a map to guest authentication.
			 */
			TALLOC_FREE(session_info);
		}
	}

	if (session_info != NULL) {
		if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
			/*
			 * Anonymous and GUEST are not secure anyway.
			 * avoid new_spnego and MIC checking.
			 */
			ntlmssp_state->new_spnego = false;
			ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_SIGN;
			ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_SEAL;
		}
		TALLOC_FREE(session_info);
	}

	dump_data_pw("NT session key:\n", user_session_key.data, user_session_key.length);
	dump_data_pw("LM first-8:\n", lm_session_key.data, lm_session_key.length);

	/* Handle the different session key derivation for NTLM2 */
	if (state->doing_ntlm2) {
		if (user_session_key.data && user_session_key.length == 16) {
			int rc;

			session_key = data_blob_talloc(ntlmssp_state,
						       NULL, 16);

			rc = gnutls_hmac_fast(GNUTLS_MAC_MD5,
					      user_session_key.data,
					      user_session_key.length,
					      state->session_nonce,
					      sizeof(state->session_nonce),
					      session_key.data);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
			}

			DEBUG(10,("ntlmssp_server_auth: Created NTLM2 session key.\n"));
			dump_data_pw("NTLM2 session key:\n", session_key.data, session_key.length);

		} else {
			DEBUG(10,("ntlmssp_server_auth: Failed to create NTLM2 session key.\n"));
			session_key = data_blob_null;
		}
	} else if ((ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY)
		/* Ensure we can never get here on NTLMv2 */
		&& (ntlmssp_state->nt_resp.length == 0 || ntlmssp_state->nt_resp.length == 24)) {

		if (lm_session_key.data && lm_session_key.length >= 8) {
			if (ntlmssp_state->lm_resp.data && ntlmssp_state->lm_resp.length == 24) {
				session_key = data_blob_talloc(ntlmssp_state,
							       NULL, 16);
				if (session_key.data == NULL) {
					return NT_STATUS_NO_MEMORY;
				}
				nt_status = SMBsesskeygen_lm_sess_key(lm_session_key.data,
								      ntlmssp_state->lm_resp.data,
								      session_key.data);
				if (!NT_STATUS_IS_OK(nt_status)) {
					return nt_status;
				}
				DEBUG(10,("ntlmssp_server_auth: Created NTLM session key.\n"));
			} else {
				static const uint8_t zeros[24] = {0, };
				session_key = data_blob_talloc(
					ntlmssp_state, NULL, 16);
				if (session_key.data == NULL) {
					return NT_STATUS_NO_MEMORY;
				}
				nt_status = SMBsesskeygen_lm_sess_key(zeros, zeros,
								      session_key.data);
				if (!NT_STATUS_IS_OK(nt_status)) {
					return nt_status;
				}
				DEBUG(10,("ntlmssp_server_auth: Created NTLM session key.\n"));
			}
			dump_data_pw("LM session key:\n", session_key.data,
				     session_key.length);
		} else {
			/* LM Key not selected */
			ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

			DEBUG(10,("ntlmssp_server_auth: Failed to create NTLM session key.\n"));
			session_key = data_blob_null;
		}

	} else if (user_session_key.data) {
		session_key = user_session_key;
		DEBUG(10,("ntlmssp_server_auth: Using unmodified nt session key.\n"));
		dump_data_pw("unmodified session key:\n", session_key.data, session_key.length);

		/* LM Key not selected */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

	} else if (lm_session_key.data) {
		/* Very weird to have LM key, but no user session key, but anyway.. */
		session_key = lm_session_key;
		DEBUG(10,("ntlmssp_server_auth: Using unmodified lm session key.\n"));
		dump_data_pw("unmodified session key:\n", session_key.data, session_key.length);

		/* LM Key not selected */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

	} else {
		DEBUG(10,("ntlmssp_server_auth: Failed to create unmodified session key.\n"));
		session_key = data_blob_null;

		/* LM Key not selected */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	/* With KEY_EXCH, the client supplies the proposed session key,
	   but encrypts it with the long-term key */
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		if (!state->encrypted_session_key.data
		    || state->encrypted_session_key.length != 16) {
			DEBUG(1, ("Client-supplied KEY_EXCH session key was of invalid length (%u)!\n",
				  (unsigned)state->encrypted_session_key.length));
			return NT_STATUS_INVALID_PARAMETER;
		} else if (!session_key.data || session_key.length != 16) {
			DEBUG(5, ("server session key is invalid (len == %u), cannot do KEY_EXCH!\n",
				  (unsigned int)session_key.length));
			ntlmssp_state->session_key = session_key;
			talloc_steal(ntlmssp_state, session_key.data);
		} else {
			gnutls_cipher_hd_t cipher_hnd;
			gnutls_datum_t enc_session_key = {
				.data = session_key.data,
				.size = session_key.length,
			};
			int rc;

			dump_data_pw("KEY_EXCH session key (enc):\n",
				     state->encrypted_session_key.data,
				     state->encrypted_session_key.length);

			rc = gnutls_cipher_init(&cipher_hnd,
						GNUTLS_CIPHER_ARCFOUR_128,
						&enc_session_key,
						NULL);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
			}
			rc = gnutls_cipher_encrypt(cipher_hnd,
						   state->encrypted_session_key.data,
						   state->encrypted_session_key.length);
			gnutls_cipher_deinit(cipher_hnd);
			if (rc < 0) {
				return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
			}

			ntlmssp_state->session_key = data_blob_talloc(ntlmssp_state,
								      state->encrypted_session_key.data,
								      state->encrypted_session_key.length);
			dump_data_pw("KEY_EXCH session key:\n",
				     state->encrypted_session_key.data,
				     state->encrypted_session_key.length);
		}
	} else {
		ntlmssp_state->session_key = session_key;
		talloc_steal(ntlmssp_state, session_key.data);
	}

	if (ntlmssp_state->new_spnego) {
		gnutls_hmac_hd_t hmac_hnd = NULL;
		uint8_t mic_buffer[NTLMSSP_MIC_SIZE] = { 0, };
		int cmp;
		int rc;

		rc = gnutls_hmac_init(&hmac_hnd,
				 GNUTLS_MAC_MD5,
				 ntlmssp_state->session_key.data,
				 MIN(ntlmssp_state->session_key.length, 64));
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		}
		rc = gnutls_hmac(hmac_hnd,
				 ntlmssp_state->negotiate_blob.data,
				 ntlmssp_state->negotiate_blob.length);
		if (rc < 0) {
			gnutls_hmac_deinit(hmac_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		}
		rc = gnutls_hmac(hmac_hnd,
				  ntlmssp_state->challenge_blob.data,
				  ntlmssp_state->challenge_blob.length);
		if (rc < 0) {
			gnutls_hmac_deinit(hmac_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		}

		/* checked were we set ntlmssp_state->new_spnego */
		SMB_ASSERT(request.length >
			   (NTLMSSP_MIC_OFFSET + NTLMSSP_MIC_SIZE));

		rc = gnutls_hmac(hmac_hnd, request.data, NTLMSSP_MIC_OFFSET);
		if (rc < 0) {
			gnutls_hmac_deinit(hmac_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		}
		rc = gnutls_hmac(hmac_hnd, mic_buffer, NTLMSSP_MIC_SIZE);
		if (rc < 0) {
			gnutls_hmac_deinit(hmac_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		}
		rc = gnutls_hmac(hmac_hnd,
				 request.data + (NTLMSSP_MIC_OFFSET + NTLMSSP_MIC_SIZE),
				 request.length - (NTLMSSP_MIC_OFFSET + NTLMSSP_MIC_SIZE));
		if (rc < 0) {
			gnutls_hmac_deinit(hmac_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_NTLM_BLOCKED);
		}
		gnutls_hmac_deinit(hmac_hnd, mic_buffer);

		cmp = memcmp(request.data + NTLMSSP_MIC_OFFSET,
			     mic_buffer, NTLMSSP_MIC_SIZE);
		if (cmp != 0) {
			DEBUG(1,("%s: invalid NTLMSSP_MIC for "
				 "user=[%s] domain=[%s] workstation=[%s]\n",
				 __func__,
				 ntlmssp_state->user,
				 ntlmssp_state->domain,
				 ntlmssp_state->client.netbios_name));
			dump_data(11, request.data + NTLMSSP_MIC_OFFSET,
				  NTLMSSP_MIC_SIZE);
			dump_data(11, mic_buffer,
				  NTLMSSP_MIC_SIZE);
		}

		ZERO_ARRAY(mic_buffer);

		if (cmp != 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	data_blob_free(&ntlmssp_state->negotiate_blob);
	data_blob_free(&ntlmssp_state->challenge_blob);

	if (gensec_ntlmssp_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		if (gensec_security->want_features & GENSEC_FEATURE_LDAP_STYLE) {
			/*
			 * We need to handle NTLMSSP_NEGOTIATE_SIGN as
			 * NTLMSSP_NEGOTIATE_SEAL if GENSEC_FEATURE_LDAP_STYLE
			 * is requested.
			 */
			ntlmssp_state->force_wrap_seal = true;
		}
		nt_status = ntlmssp_sign_init(ntlmssp_state);
	}

	data_blob_clear_free(&ntlmssp_state->internal_chal);
	data_blob_clear_free(&ntlmssp_state->chal);
	data_blob_clear_free(&ntlmssp_state->lm_resp);
	data_blob_clear_free(&ntlmssp_state->nt_resp);

	ntlmssp_state->expected_state = NTLMSSP_DONE;

	return nt_status;
}

NTSTATUS ntlmssp_server_auth_recv(struct tevent_req *req,
				  TALLOC_CTX *out_mem_ctx,
				  DATA_BLOB *out)
{
	NTSTATUS status;

	*out = data_blob_null;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}
