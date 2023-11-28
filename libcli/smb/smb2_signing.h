/*
   Unix SMB/CIFS implementation.
   SMB2 signing

   Copyright (C) Stefan Metzmacher 2009

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

#ifndef _LIBCLI_SMB_SMB2_SIGNING_H_
#define _LIBCLI_SMB_SMB2_SIGNING_H_

#include <gnutls/gnutls.h>

#include "lib/util/data_blob.h"

#include "libcli/smb/smb_constants.h"
#include "libcli/util/ntstatus.h"

struct iovec;

struct smb2_signing_derivation {
	DATA_BLOB label;
	DATA_BLOB context;
};

struct smb2_signing_derivations {
	struct smb2_signing_derivation __signing;
	const struct smb2_signing_derivation *signing;
	struct smb2_signing_derivation __cipher_c2s;
	const struct smb2_signing_derivation *cipher_c2s;
	struct smb2_signing_derivation __cipher_s2c;
	const struct smb2_signing_derivation *cipher_s2c;
	struct smb2_signing_derivation __application;
	const struct smb2_signing_derivation *application;
};

void smb2_signing_derivations_fill_const_stack(struct smb2_signing_derivations *ds,
					       enum protocol_types protocol,
					       const DATA_BLOB preauth_hash);

struct smb2_signing_key {
	DATA_BLOB blob;
	uint16_t sign_algo_id;
	union {
#ifdef SMB2_SIGNING_KEY_GNUTLS_TYPES
		gnutls_hmac_hd_t hmac_hnd;
#endif
		void *__hmac_hnd;
	};
	uint16_t cipher_algo_id;
	union {
#ifdef SMB2_SIGNING_KEY_GNUTLS_TYPES
		gnutls_aead_cipher_hd_t cipher_hnd;
#endif
		void *__cipher_hnd;
	};
};

NTSTATUS smb2_signing_key_copy(TALLOC_CTX *mem_ctx,
			       const struct smb2_signing_key *src,
			       struct smb2_signing_key **_dst);
NTSTATUS smb2_signing_key_sign_create(TALLOC_CTX *mem_ctx,
				      uint16_t sign_algo_id,
				      const DATA_BLOB *master_key,
				      const struct smb2_signing_derivation *d,
				      struct smb2_signing_key **_key);
NTSTATUS smb2_signing_key_cipher_create(TALLOC_CTX *mem_ctx,
					uint16_t cipher_algo_id,
					const DATA_BLOB *master_key,
					const struct smb2_signing_derivation *d,
					struct smb2_signing_key **_key);

bool smb2_signing_key_valid(const struct smb2_signing_key *key);

NTSTATUS smb2_signing_sign_pdu(struct smb2_signing_key *signing_key,
			       struct iovec *vector,
			       int count);

NTSTATUS smb2_signing_check_pdu(struct smb2_signing_key *signing_key,
				const struct iovec *vector,
				int count);

NTSTATUS smb2_signing_encrypt_pdu(struct smb2_signing_key *encryption_key,
				  struct iovec *vector,
				  int count);
NTSTATUS smb2_signing_decrypt_pdu(struct smb2_signing_key *decryption_key,
				  struct iovec *vector,
				  int count);

#endif /* _LIBCLI_SMB_SMB2_SIGNING_H_ */
