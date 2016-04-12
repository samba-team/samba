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
