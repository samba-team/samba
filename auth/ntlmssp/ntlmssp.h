/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Andrew Bartlett 2010

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

#include "../librpc/gen_ndr/ntlmssp.h"

struct auth_context;
struct auth_serversupplied_info;
struct tsocket_address;
struct auth_user_info_dc;
struct gensec_security;
struct ntlmssp_state;

/* NTLMSSP mode */
enum ntlmssp_role
{
	NTLMSSP_SERVER,
	NTLMSSP_CLIENT
};

/* NTLMSSP message types */
enum ntlmssp_message_type
{
	NTLMSSP_INITIAL = 0 /* samba internal state */,
	NTLMSSP_NEGOTIATE = 1,
	NTLMSSP_CHALLENGE = 2,
	NTLMSSP_AUTH      = 3,
	NTLMSSP_UNKNOWN   = 4,
	NTLMSSP_DONE      = 5 /* samba final state */
};

#define NTLMSSP_FEATURE_SESSION_KEY        0x00000001
#define NTLMSSP_FEATURE_SIGN               0x00000002
#define NTLMSSP_FEATURE_SEAL               0x00000004
#define NTLMSSP_FEATURE_CCACHE		   0x00000008

union ntlmssp_crypt_state;

struct ntlmssp_state
{
	enum ntlmssp_role role;
	uint32_t expected_state;

	bool unicode;
	bool use_ntlmv2;
	bool use_ccache;
	bool resume_ccache;
	bool use_nt_response;  /* Set to 'False' to debug what happens when the NT response is omited */
	bool allow_lm_response;/* The LM_RESPONSE code is not very secure... */
	bool allow_lm_key;     /* The LM_KEY code is not very secure... */

	const char *user;
	const char *domain;
	uint8_t *nt_hash;
	uint8_t *lm_hash;

	DATA_BLOB negotiate_blob;
	DATA_BLOB challenge_blob;
	bool new_spnego;
	bool force_old_spnego;

	struct {
		const char *netbios_name;
		const char *netbios_domain;
		struct AV_PAIR_LIST av_pair_list;
	} client;

	struct {
		bool is_standalone;
		const char *netbios_name;
		const char *netbios_domain;
		const char *dns_name;
		const char *dns_domain;
		NTTIME challenge_endtime;
		struct AV_PAIR_LIST av_pair_list;
	} server;

	DATA_BLOB internal_chal; /* Random challenge as supplied to the client for NTLM authentication */

	DATA_BLOB chal; /* Random challenge as input into the actual NTLM (or NTLM2) authentication */
	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;
	DATA_BLOB session_key;

	uint32_t conf_flags;
	uint32_t required_flags;
	uint32_t neg_flags; /* the current state of negotiation with the NTLMSSP partner */

	bool force_wrap_seal;

	union ntlmssp_crypt_state *crypt;
};

/* The following definitions come from libcli/auth/ntlmssp_sign.c  */

NTSTATUS ntlmssp_sign_packet(struct ntlmssp_state *ntlmssp_state,
			     TALLOC_CTX *sig_mem_ctx,
			     const uint8_t *data, size_t length,
			     const uint8_t *whole_pdu, size_t pdu_length,
			     DATA_BLOB *sig);
NTSTATUS ntlmssp_check_packet(struct ntlmssp_state *ntlmssp_state,
			      const uint8_t *data, size_t length,
			      const uint8_t *whole_pdu, size_t pdu_length,
			      const DATA_BLOB *sig) ;
NTSTATUS ntlmssp_seal_packet(struct ntlmssp_state *ntlmssp_state,
			     TALLOC_CTX *sig_mem_ctx,
			     uint8_t *data, size_t length,
			     const uint8_t *whole_pdu, size_t pdu_length,
			     DATA_BLOB *sig);
NTSTATUS ntlmssp_unseal_packet(struct ntlmssp_state *ntlmssp_state,
			       uint8_t *data, size_t length,
			       const uint8_t *whole_pdu, size_t pdu_length,
			       const DATA_BLOB *sig);
NTSTATUS ntlmssp_wrap(struct ntlmssp_state *ntlmssp_state,
		      TALLOC_CTX *out_mem_ctx,
		      const DATA_BLOB *in,
		      DATA_BLOB *out);
NTSTATUS ntlmssp_unwrap(struct ntlmssp_state *ntlmssp_stae,
			TALLOC_CTX *out_mem_ctx,
			const DATA_BLOB *in,
			DATA_BLOB *out);
NTSTATUS ntlmssp_sign_reset(struct ntlmssp_state *ntlmssp_state,
			    bool reset_seqnums);
NTSTATUS ntlmssp_sign_init(struct ntlmssp_state *ntlmssp_state);

bool ntlmssp_blob_matches_magic(const DATA_BLOB *blob);

/* The following definitions come from auth/ntlmssp/gensec_ntlmssp.c  */

NTSTATUS gensec_ntlmssp_init(TALLOC_CTX *ctx);

uint32_t gensec_ntlmssp_neg_flags(struct gensec_security *gensec_security);
const char *gensec_ntlmssp_server_domain(struct gensec_security *gensec_security);
