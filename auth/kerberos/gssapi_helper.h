/*
   Unix SMB/CIFS implementation.
   GSSAPI helper functions

   Copyright (C) Stefan Metzmacher 2008,2015

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

#ifndef AUTH_KERBEROS_GSSAPI_HELPER_H
#define AUTH_KERBEROS_GSSAPI_HELPER_H 1

size_t gssapi_get_sig_size(gss_ctx_id_t gssapi_context,
			   const gss_OID mech,
			   uint32_t gss_want_flags,
			   size_t data_size);
NTSTATUS gssapi_seal_packet(gss_ctx_id_t gssapi_context,
			    const gss_OID mech,
			    bool hdr_signing, size_t sig_size,
			    uint8_t *data, size_t length,
			    const uint8_t *whole_pdu, size_t pdu_length,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *sig);
NTSTATUS gssapi_unseal_packet(gss_ctx_id_t gssapi_context,
			      const gss_OID mech,
			      bool hdr_signing,
			      uint8_t *data, size_t length,
			      const uint8_t *whole_pdu, size_t pdu_length,
			      const DATA_BLOB *sig);
NTSTATUS gssapi_sign_packet(gss_ctx_id_t gssapi_context,
			    const gss_OID mech,
			    bool hdr_signing,
			    const uint8_t *data, size_t length,
			    const uint8_t *whole_pdu, size_t pdu_length,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *sig);
NTSTATUS gssapi_check_packet(gss_ctx_id_t gssapi_context,
			     const gss_OID mech,
			     bool hdr_signing,
			     const uint8_t *data, size_t length,
			     const uint8_t *whole_pdu, size_t pdu_length,
			     const DATA_BLOB *sig);

#endif /* AUTH_KERBEROS_GSSAPI_HELPER_H */
