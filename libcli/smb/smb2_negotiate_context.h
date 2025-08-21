/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2014

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

#ifndef _LIBCLI_SMB_SMB2_NEGOTIATE_BLOB_H_
#define _LIBCLI_SMB_SMB2_NEGOTIATE_BLOB_H_

struct smb2_negotiate_context {
	uint16_t type;
	DATA_BLOB data;
};

struct smb2_negotiate_contexts {
	uint16_t num_contexts;
	struct smb2_negotiate_context *contexts;
};

/*
  parse a set of SMB2 negotiate contexts
*/
NTSTATUS smb2_negotiate_context_parse(TALLOC_CTX *mem_ctx, const DATA_BLOB buffer,
				      uint16_t expected_count,
				      struct smb2_negotiate_contexts *contexts);

/*
  negotiate a buffer of a set of negotiate contexts
*/
NTSTATUS smb2_negotiate_context_push(TALLOC_CTX *mem_ctx, DATA_BLOB *buffer,
			       const struct smb2_negotiate_contexts contexts);

NTSTATUS smb2_negotiate_context_add(TALLOC_CTX *mem_ctx,
				    struct smb2_negotiate_contexts *c,
				    uint16_t type,
				    const uint8_t *buf,
				    size_t buflen);

/*
 * return the first context with the given tag
 */
struct smb2_negotiate_context *smb2_negotiate_context_find(const struct smb2_negotiate_contexts *b,
							   uint16_t type);
#define WINDOWS_CLIENT_PURE_SMB2_NEGPROT_INITIAL_CREDIT_ASK	31

struct smb3_signing_capabilities {
#define SMB3_SIGNING_CAPABILITIES_MAX_ALGOS 3
	uint16_t num_algos;
	uint16_t algos[SMB3_SIGNING_CAPABILITIES_MAX_ALGOS];
};

struct smb3_encryption_capabilities {
#define SMB3_ENCRYTION_CAPABILITIES_MAX_ALGOS 4
	uint16_t num_algos;
	uint16_t algos[SMB3_ENCRYTION_CAPABILITIES_MAX_ALGOS];
};

struct smb311_capabilities {
	struct smb3_signing_capabilities signing;
	struct smb3_encryption_capabilities encryption;
	bool smb_encryption_over_quic;
};

const char *smb3_signing_algorithm_name(uint16_t algo);
const char *smb3_encryption_algorithm_name(uint16_t algo);

struct smb311_capabilities smb311_capabilities_parse(
	const char *role,
	const char *const *signing_algos,
	const char *const *encryption_algos,
	bool smb_encryption_over_quic);

NTSTATUS smb311_capabilities_check(const struct smb311_capabilities *c,
				   const char *debug_prefix,
				   int debug_lvl,
				   NTSTATUS error_status,
				   const char *role,
				   enum protocol_types protocol,
				   uint16_t sign_algo,
				   uint16_t cipher_algo);

#endif /* _LIBCLI_SMB_SMB2_NEGOTIATE_BLOB_H_ */
