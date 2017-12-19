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
#include "auth/gensec/gensec_internal.h"
#include "auth/common_auth.h"
#include "../lib/util/asn1.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

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
		DBG_NOTICE("Unable to find PAC for %s, resorting to local "
			   "user lookup\n", principal_string);
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
  magic check a GSS-API wrapper packet for an Kerberos OID
*/
static bool gensec_gssapi_check_oid(const DATA_BLOB *blob, const char *oid)
{
	bool ret = false;
	struct asn1_data *data = asn1_init(NULL);

	if (!data) return false;

	if (!asn1_load(data, *blob)) goto err;
	if (!asn1_start_tag(data, ASN1_APPLICATION(0))) goto err;
	if (!asn1_check_OID(data, oid)) goto err;

	ret = !asn1_has_error(data);

  err:

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

void gensec_child_want_feature(struct gensec_security *gensec_security,
			       uint32_t feature)
{
	struct gensec_security *child_security = gensec_security->child_security;

	gensec_security->want_features |= feature;
	if (child_security == NULL) {
		return;
	}
	gensec_want_feature(child_security, feature);
}

bool gensec_child_have_feature(struct gensec_security *gensec_security,
			       uint32_t feature)
{
	struct gensec_security *child_security = gensec_security->child_security;

	if (feature & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		/*
		 * All mechs with sub (child) mechs need to provide DCERPC
		 * header signing! This is required because the negotiation
		 * of header signing is done before the authentication
		 * is completed.
		 */
		return true;
	}

	if (child_security == NULL) {
		return false;
	}

	return gensec_have_feature(child_security, feature);
}

NTSTATUS gensec_child_unseal_packet(struct gensec_security *gensec_security,
				    uint8_t *data, size_t length,
				    const uint8_t *whole_pdu, size_t pdu_length,
				    const DATA_BLOB *sig)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_unseal_packet(gensec_security->child_security,
				    data, length,
				    whole_pdu, pdu_length,
				    sig);
}

NTSTATUS gensec_child_check_packet(struct gensec_security *gensec_security,
				   const uint8_t *data, size_t length,
				   const uint8_t *whole_pdu, size_t pdu_length,
				   const DATA_BLOB *sig)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_check_packet(gensec_security->child_security,
				   data, length,
				   whole_pdu, pdu_length,
				   sig);
}

NTSTATUS gensec_child_seal_packet(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  uint8_t *data, size_t length,
				  const uint8_t *whole_pdu, size_t pdu_length,
				  DATA_BLOB *sig)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_seal_packet(gensec_security->child_security,
				  mem_ctx,
				  data, length,
				  whole_pdu, pdu_length,
				  sig);
}

NTSTATUS gensec_child_sign_packet(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  const uint8_t *data, size_t length,
				  const uint8_t *whole_pdu, size_t pdu_length,
				  DATA_BLOB *sig)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_sign_packet(gensec_security->child_security,
				  mem_ctx,
				  data, length,
				  whole_pdu, pdu_length,
				  sig);
}

NTSTATUS gensec_child_wrap(struct gensec_security *gensec_security,
			   TALLOC_CTX *mem_ctx,
			   const DATA_BLOB *in,
			   DATA_BLOB *out)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_wrap(gensec_security->child_security,
			   mem_ctx, in, out);
}

NTSTATUS gensec_child_unwrap(struct gensec_security *gensec_security,
			     TALLOC_CTX *mem_ctx,
			     const DATA_BLOB *in,
			     DATA_BLOB *out)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_unwrap(gensec_security->child_security,
			     mem_ctx, in, out);
}

size_t gensec_child_sig_size(struct gensec_security *gensec_security,
			     size_t data_size)
{
	if (gensec_security->child_security == NULL) {
		return 0;
	}

	return gensec_sig_size(gensec_security->child_security, data_size);
}

size_t gensec_child_max_input_size(struct gensec_security *gensec_security)
{
	if (gensec_security->child_security == NULL) {
		return 0;
	}

	return gensec_max_input_size(gensec_security->child_security);
}

size_t gensec_child_max_wrapped_size(struct gensec_security *gensec_security)
{
	if (gensec_security->child_security == NULL) {
		return 0;
	}

	return gensec_max_wrapped_size(gensec_security->child_security);
}

NTSTATUS gensec_child_session_key(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *session_key)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_session_key(gensec_security->child_security,
				  mem_ctx,
				  session_key);
}

NTSTATUS gensec_child_session_info(struct gensec_security *gensec_security,
				   TALLOC_CTX *mem_ctx,
				   struct auth_session_info **session_info)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_session_info(gensec_security->child_security,
				   mem_ctx,
				   session_info);
}

NTTIME gensec_child_expire_time(struct gensec_security *gensec_security)
{
	if (gensec_security->child_security == NULL) {
		return GENSEC_EXPIRE_TIME_INFINITY;
	}

	return gensec_expire_time(gensec_security->child_security);
}

const char *gensec_child_final_auth_type(struct gensec_security *gensec_security)
{
	if (gensec_security->child_security == NULL) {
		return "NONE";
	}

	return gensec_final_auth_type(gensec_security->child_security);
}
