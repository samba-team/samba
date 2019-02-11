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
	uint32_t num_contexts;
	struct smb2_negotiate_context *contexts;
};

/*
  parse a set of SMB2 negotiate contexts
*/
NTSTATUS smb2_negotiate_context_parse(TALLOC_CTX *mem_ctx, const DATA_BLOB buffer,
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

#endif /* _LIBCLI_SMB_SMB2_NEGOTIATE_BLOB_H_ */
