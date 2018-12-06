/*
 *  Unix SMB/CIFS implementation.
 *  Version 3.0
 *  NTLMSSP Signing routines
 *  Copyright (C) Andrew Bartlett 2003-2005
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

/* For structures internal to the NTLMSSP implementation that should not be exposed */

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

struct auth_session_info;

struct ntlmssp_crypt_direction {
	uint32_t seq_num;
	uint8_t sign_key[16];
	gnutls_cipher_hd_t seal_state;
};

union ntlmssp_crypt_state {
	/* NTLM */
	struct ntlmssp_crypt_direction ntlm;

	/* NTLM2 */
	struct {
		struct ntlmssp_crypt_direction sending;
		struct ntlmssp_crypt_direction receiving;
	} ntlm2;
};

struct gensec_ntlmssp_context {
	/* For GENSEC users */
	void *server_returned_info;

	/* used by both client and server implementation */
	struct ntlmssp_state *ntlmssp_state;
};

/* The following definitions come from auth/ntlmssp_util.c  */

void debug_ntlmssp_flags(uint32_t neg_flags);
NTSTATUS ntlmssp_handle_neg_flags(struct ntlmssp_state *ntlmssp_state,
				  uint32_t neg_flags, const char *name);
const DATA_BLOB ntlmssp_version_blob(void);

/* The following definitions come from auth/ntlmssp_server.c  */

const char *ntlmssp_target_name(struct ntlmssp_state *ntlmssp_state,
				uint32_t neg_flags, uint32_t *chal_flags);
NTSTATUS ntlmssp_server_negotiate(struct ntlmssp_state *ntlmssp_state,
				  TALLOC_CTX *out_mem_ctx,
				  const DATA_BLOB in, DATA_BLOB *out);
NTSTATUS ntlmssp_server_auth(struct ntlmssp_state *ntlmssp_state,
			     TALLOC_CTX *out_mem_ctx,
			     const DATA_BLOB request, DATA_BLOB *reply);
/* The following definitions come from auth/ntlmssp/ntlmssp_client.c  */


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
				DATA_BLOB in, DATA_BLOB *out) ;

NTSTATUS gensec_ntlmssp_resume_ccache(struct gensec_security *gensec_security,
				TALLOC_CTX *out_mem_ctx,
				DATA_BLOB in, DATA_BLOB *out);

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
				  const DATA_BLOB in, DATA_BLOB *out) ;
NTSTATUS gensec_ntlmssp_client_start(struct gensec_security *gensec_security);
NTSTATUS gensec_ntlmssp_resume_ccache_start(struct gensec_security *gensec_security);

/* The following definitions come from auth/ntlmssp/gensec_ntlmssp_server.c  */


/**
 * Next state function for the Negotiate packet (GENSEC wrapper)
 *
 * @param gensec_security GENSEC state
 * @param out_mem_ctx Memory context for *out
 * @param in The request, as a DATA_BLOB.  reply.data must be NULL
 * @param out The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors or MORE_PROCESSING_REQUIRED if (normal) a reply is required.
 */
NTSTATUS gensec_ntlmssp_server_negotiate(struct gensec_security *gensec_security,
					 TALLOC_CTX *out_mem_ctx,
					 const DATA_BLOB request, DATA_BLOB *reply);

struct tevent_req *ntlmssp_server_auth_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct gensec_security *gensec_security,
					    const DATA_BLOB in);
NTSTATUS ntlmssp_server_auth_recv(struct tevent_req *req,
				  TALLOC_CTX *out_mem_ctx,
				  DATA_BLOB *out);


/**
 * Start NTLMSSP on the server side
 *
 */
NTSTATUS gensec_ntlmssp_server_start(struct gensec_security *gensec_security);

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
				     TALLOC_CTX *mem_ctx,
				     struct auth_session_info **session_info) ;

/* The following definitions come from auth/ntlmssp/gensec_ntlmssp.c  */

NTSTATUS gensec_ntlmssp_sign_packet(struct gensec_security *gensec_security,
				    TALLOC_CTX *sig_mem_ctx,
				    const uint8_t *data, size_t length,
				    const uint8_t *whole_pdu, size_t pdu_length,
				    DATA_BLOB *sig);
NTSTATUS gensec_ntlmssp_check_packet(struct gensec_security *gensec_security,
				     const uint8_t *data, size_t length,
				     const uint8_t *whole_pdu, size_t pdu_length,
				     const DATA_BLOB *sig);
NTSTATUS gensec_ntlmssp_seal_packet(struct gensec_security *gensec_security,
				    TALLOC_CTX *sig_mem_ctx,
				    uint8_t *data, size_t length,
				    const uint8_t *whole_pdu, size_t pdu_length,
				    DATA_BLOB *sig);
NTSTATUS gensec_ntlmssp_unseal_packet(struct gensec_security *gensec_security,
				      uint8_t *data, size_t length,
				      const uint8_t *whole_pdu, size_t pdu_length,
				      const DATA_BLOB *sig);
size_t gensec_ntlmssp_sig_size(struct gensec_security *gensec_security, size_t data_size) ;
NTSTATUS gensec_ntlmssp_wrap(struct gensec_security *gensec_security,
			     TALLOC_CTX *out_mem_ctx,
			     const DATA_BLOB *in,
			     DATA_BLOB *out);
NTSTATUS gensec_ntlmssp_unwrap(struct gensec_security *gensec_security,
			       TALLOC_CTX *out_mem_ctx,
			       const DATA_BLOB *in,
			       DATA_BLOB *out);

/**
 * Return the NTLMSSP master session key
 *
 * @param ntlmssp_state NTLMSSP State
 */
NTSTATUS gensec_ntlmssp_magic(struct gensec_security *gensec_security,
			      const DATA_BLOB *first_packet);
bool gensec_ntlmssp_have_feature(struct gensec_security *gensec_security,
				 uint32_t feature);
NTSTATUS gensec_ntlmssp_session_key(struct gensec_security *gensec_security,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *session_key);
NTSTATUS gensec_ntlmssp_start(struct gensec_security *gensec_security);

