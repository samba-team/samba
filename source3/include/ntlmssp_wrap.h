/*
   NLTMSSP wrappers

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2003

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

#ifndef _NTLMSSP_WRAP_
#define _NTLMSSP_WRAP_

struct gensec_security;

struct auth_ntlmssp_state {
	/* used only by server implementation */
	struct auth_context *auth_context;
	
	/* used only by the client implementation */
	struct cli_credentials *credentials;

	/* used by both */
	struct gensec_security *gensec_security;
};

NTSTATUS auth_ntlmssp_sign_packet(struct auth_ntlmssp_state *ans,
				  TALLOC_CTX *sig_mem_ctx,
				  const uint8_t *data,
				  size_t length,
				  const uint8_t *whole_pdu,
				  size_t pdu_length,
				  DATA_BLOB *sig);
NTSTATUS auth_ntlmssp_check_packet(struct auth_ntlmssp_state *ans,
				   const uint8_t *data,
				   size_t length,
				   const uint8_t *whole_pdu,
				   size_t pdu_length,
				   const DATA_BLOB *sig);
NTSTATUS auth_ntlmssp_seal_packet(struct auth_ntlmssp_state *ans,
				  TALLOC_CTX *sig_mem_ctx,
				  uint8_t *data,
				  size_t length,
				  const uint8_t *whole_pdu,
				  size_t pdu_length,
				  DATA_BLOB *sig);
NTSTATUS auth_ntlmssp_unseal_packet(struct auth_ntlmssp_state *ans,
				    uint8_t *data,
				    size_t length,
				    const uint8_t *whole_pdu,
				    size_t pdu_length,
				    const DATA_BLOB *sig);
NTSTATUS auth_ntlmssp_set_username(struct auth_ntlmssp_state *ans,
				   const char *user);
NTSTATUS auth_ntlmssp_set_domain(struct auth_ntlmssp_state *ans,
				 const char *domain);
NTSTATUS auth_ntlmssp_set_password(struct auth_ntlmssp_state *ans,
				   const char *password);
void auth_ntlmssp_want_feature(struct auth_ntlmssp_state *ans, uint32_t feature);
DATA_BLOB auth_ntlmssp_get_session_key(struct auth_ntlmssp_state *ans, 
				       TALLOC_CTX *mem_ctx);

NTSTATUS auth_ntlmssp_client_prepare(TALLOC_CTX *mem_ctx,
				     struct auth_ntlmssp_state **_ans);
NTSTATUS auth_ntlmssp_client_start(struct auth_ntlmssp_state *ans);

#endif /* _NTLMSSP_WRAP_ */
