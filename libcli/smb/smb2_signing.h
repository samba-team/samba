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

struct iovec;

NTSTATUS smb2_signing_sign_pdu(DATA_BLOB signing_key,
			       enum protocol_types protocol,
			       struct iovec *vector,
			       int count);

NTSTATUS smb2_signing_check_pdu(DATA_BLOB signing_key,
				enum protocol_types protocol,
				const struct iovec *vector,
				int count);

void smb2_key_derivation(const uint8_t *KI, size_t KI_len,
			 const uint8_t *Label, size_t Label_len,
			 const uint8_t *Context, size_t Context_len,
			 uint8_t KO[16]);

NTSTATUS smb2_signing_encrypt_pdu(DATA_BLOB encryption_key,
				  enum protocol_types protocol,
				  struct iovec *vector,
				  int count);
NTSTATUS smb2_signing_decrypt_pdu(DATA_BLOB decryption_key,
				  enum protocol_types protocol,
				  struct iovec *vector,
				  int count);

#endif /* _LIBCLI_SMB_SMB2_SIGNING_H_ */
