/*
   Unix SMB/CIFS implementation.

   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2006

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
#include "auth/gensec/gensec.h"
#include "auth/common_auth.h"
#include "../lib/util/asn1.h"

NTSTATUS gensec_generate_session_info_pac(TALLOC_CTX *mem_ctx,
					  struct gensec_security *gensec_security,
					  struct smb_krb5_context *smb_krb5_context,
					  DATA_BLOB *pac_blob,
					  const char *principal_string,
					  const struct tsocket_address *remote_address,
					  struct auth_session_info **session_info)
{
	uint32_t session_info_flags = 0;

	if (gensec_security->want_features & GENSEC_FEATURE_UNIX_TOKEN) {
		session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	}

	session_info_flags |= AUTH_SESSION_INFO_DEFAULT_GROUPS;

	if (!pac_blob) {
		if (gensec_setting_bool(gensec_security->settings, "gensec", "require_pac", false)) {
			DEBUG(1, ("Unable to find PAC in ticket from %s, failing to allow access\n",
				  principal_string));
			return NT_STATUS_ACCESS_DENIED;
		}
		DEBUG(1, ("Unable to find PAC for %s, resorting to local user lookup\n",
			  principal_string));
	}

	if (gensec_security->auth_context && gensec_security->auth_context->generate_session_info_pac) {
		return gensec_security->auth_context->generate_session_info_pac(gensec_security->auth_context,
										mem_ctx,
										smb_krb5_context,
										pac_blob,
										principal_string,
										remote_address,
										session_info_flags,
										session_info);
	} else {
		DEBUG(0, ("Cannot generate a session_info without the auth_context\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}
}

/*
 * These functions are for use in the deprecated
 * gensec_socket code (public because SPNEGO must
 * use them for recursion)
 */
_PUBLIC_ NTSTATUS gensec_wrap_packets(struct gensec_security *gensec_security,
			     TALLOC_CTX *mem_ctx,
			     const DATA_BLOB *in,
			     DATA_BLOB *out,
			     size_t *len_processed)
{
	if (!gensec_security->ops->wrap_packets) {
		NTSTATUS nt_status;
		size_t max_input_size;
		DATA_BLOB unwrapped, wrapped;
		max_input_size = gensec_max_input_size(gensec_security);
		unwrapped = data_blob_const(in->data, MIN(max_input_size, (size_t)in->length));

		nt_status = gensec_wrap(gensec_security,
					mem_ctx,
					&unwrapped, &wrapped);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		*out = data_blob_talloc(mem_ctx, NULL, 4);
		if (!out->data) {
			return NT_STATUS_NO_MEMORY;
		}
		RSIVAL(out->data, 0, wrapped.length);

		if (!data_blob_append(mem_ctx, out, wrapped.data, wrapped.length)) {
			return NT_STATUS_NO_MEMORY;
		}
		*len_processed = unwrapped.length;
		return NT_STATUS_OK;
	}
	return gensec_security->ops->wrap_packets(gensec_security, mem_ctx, in, out,
						  len_processed);
}

/*
 * These functions are for use in the deprecated
 * gensec_socket code (public because SPNEGO must
 * use them for recursion)
 */
NTSTATUS gensec_unwrap_packets(struct gensec_security *gensec_security,
					TALLOC_CTX *mem_ctx,
					const DATA_BLOB *in,
					DATA_BLOB *out,
					size_t *len_processed)
{
	if (!gensec_security->ops->unwrap_packets) {
		DATA_BLOB wrapped;
		NTSTATUS nt_status;
		size_t packet_size;
		if (in->length < 4) {
			/* Missing the header we already had! */
			DEBUG(0, ("Asked to unwrap packet of bogus length!  How did we get the short packet?!\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}

		packet_size = RIVAL(in->data, 0);

		wrapped = data_blob_const(in->data + 4, packet_size);

		if (wrapped.length > (in->length - 4)) {
			DEBUG(0, ("Asked to unwrap packed of bogus length %d > %d!  How did we get this?!\n",
				  (int)wrapped.length, (int)(in->length - 4)));
			return NT_STATUS_INTERNAL_ERROR;
		}

		nt_status = gensec_unwrap(gensec_security,
					  mem_ctx,
					  &wrapped, out);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		*len_processed = packet_size + 4;
		return nt_status;
	}
	return gensec_security->ops->unwrap_packets(gensec_security, mem_ctx, in, out,
						    len_processed);
}

/*
 * These functions are for use in the deprecated
 * gensec_socket code (public because SPNEGO must
 * use them for recursion)
 */
NTSTATUS gensec_packet_full_request(struct gensec_security *gensec_security,
				    DATA_BLOB blob, size_t *size)
{
	if (gensec_security->ops->packet_full_request) {
		return gensec_security->ops->packet_full_request(gensec_security,
								 blob, size);
	}
	if (gensec_security->ops->unwrap_packets) {
		if (blob.length) {
			*size = blob.length;
			return NT_STATUS_OK;
		}
		return STATUS_MORE_ENTRIES;
	}

	if (blob.length < 4) {
		return STATUS_MORE_ENTRIES;
	}
	*size = 4 + RIVAL(blob.data, 0);
	if (*size > blob.length) {
		return STATUS_MORE_ENTRIES;
	}
	return NT_STATUS_OK;
}

/*
  magic check a GSS-API wrapper packet for an Kerberos OID
*/
static bool gensec_gssapi_check_oid(const DATA_BLOB *blob, const char *oid)
{
	bool ret;
	struct asn1_data *data = asn1_init(NULL);

	if (!data) return false;

	asn1_load(data, *blob);
	asn1_start_tag(data, ASN1_APPLICATION(0));
	asn1_check_OID(data, oid);

	ret = !data->has_error;

	asn1_free(data);

	return ret;
}

/**
 * Check if the packet is one for the KRB5 mechansim
 *
 * NOTE: This is a helper that can be employed by multiple mechanisms, do
 * not make assumptions about the private_data
 *
 * @param gensec_security GENSEC state, unused
 * @param in The request, as a DATA_BLOB
 * @return Error, INVALID_PARAMETER if it's not a packet for us
 *                or NT_STATUS_OK if the packet is ok.
 */

NTSTATUS gensec_magic_check_krb5_oid(struct gensec_security *unused,
					const DATA_BLOB *blob)
{
	if (gensec_gssapi_check_oid(blob, GENSEC_OID_KERBEROS5)) {
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}
