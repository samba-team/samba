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
#include "auth/gensec/gensec_proto.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "auth/system_session_proto.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "auth/kerberos/kerberos_util.h"

NTSTATUS gensec_generate_session_info(TALLOC_CTX *mem_ctx,
				      struct gensec_security *gensec_security,
				      struct auth_user_info_dc *user_info_dc,
				      struct auth_session_info **session_info)
{
	NTSTATUS nt_status;
	uint32_t session_info_flags = 0;

	if (gensec_security->want_features & GENSEC_FEATURE_UNIX_TOKEN) {
		session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	}

	session_info_flags |= AUTH_SESSION_INFO_DEFAULT_GROUPS;
	if (user_info_dc->info->authenticated) {
		session_info_flags |= AUTH_SESSION_INFO_AUTHENTICATED;
	}

	if (gensec_security->auth_context) {
		nt_status = gensec_security->auth_context->generate_session_info(mem_ctx, gensec_security->auth_context,
										 user_info_dc,
										 session_info_flags,
										 session_info);
	} else {
		session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;
		nt_status = auth_generate_session_info(mem_ctx,
						       NULL,
						       NULL,
						       user_info_dc, session_info_flags,
						       session_info);
	}
	return nt_status;
}

NTSTATUS gensec_generate_session_info_pac(TALLOC_CTX *mem_ctx_out,
					  struct gensec_security *gensec_security,
					  struct smb_krb5_context *smb_krb5_context,
					  DATA_BLOB *pac_blob,
					  const char *principal_string,
					  const struct tsocket_address *remote_address,
					  struct auth_session_info **session_info)
{
	NTSTATUS nt_status;
	uint32_t session_info_flags = 0;
	TALLOC_CTX *mem_ctx;
	struct auth_user_info_dc *user_info_dc;
	struct PAC_SIGNATURE_DATA *pac_srv_sig = NULL;
	struct PAC_SIGNATURE_DATA *pac_kdc_sig = NULL;

	if (gensec_security->want_features & GENSEC_FEATURE_UNIX_TOKEN) {
		session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	}

	session_info_flags |= AUTH_SESSION_INFO_DEFAULT_GROUPS;

	if (!pac_blob) {
		if (!gensec_setting_bool(gensec_security->settings, "gensec", "require_pac", false)) {
			DEBUG(1, ("Unable to find PAC in ticket from %s, failing to allow access\n",
				  principal_string));
			return NT_STATUS_ACCESS_DENIED;
		}
		DEBUG(1, ("Unable to find PAC for %s, resorting to local user lookup\n",
			  principal_string));
	}

	if (gensec_security->auth_context) {
		return gensec_security->auth_context->generate_session_info_pac(gensec_security->auth_context,
										mem_ctx_out,
										smb_krb5_context,
										pac_blob,
										principal_string,
										remote_address,
										session_info_flags,
										session_info);
	} else if (!pac_blob) {
		DEBUG(0, ("Cannot generate a session_info without either the PAC or the auth_context\n"));
		return NT_STATUS_NO_SUCH_USER;
	}

	mem_ctx = talloc_named(mem_ctx_out, 0, "gensec_gssapi_session_info context");
	NT_STATUS_HAVE_NO_MEMORY(mem_ctx);

	pac_srv_sig = talloc(mem_ctx, struct PAC_SIGNATURE_DATA);
	if (!pac_srv_sig) {
		talloc_free(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	pac_kdc_sig = talloc(mem_ctx, struct PAC_SIGNATURE_DATA);
	if (!pac_kdc_sig) {
		talloc_free(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = kerberos_pac_blob_to_user_info_dc(mem_ctx,
						      *pac_blob,
						      smb_krb5_context->krb5_context,
						      &user_info_dc,
						      pac_srv_sig,
						      pac_kdc_sig);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return nt_status;
	}

	session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;
	nt_status = auth_generate_session_info(mem_ctx_out,
					       NULL,
					       NULL,
					       user_info_dc, session_info_flags,
					       session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return nt_status;
	}

	if ((*session_info)->torture) {
		(*session_info)->torture->pac_srv_sig
			= talloc_steal((*session_info)->torture, pac_srv_sig);
		(*session_info)->torture->pac_kdc_sig
			= talloc_steal((*session_info)->torture, pac_kdc_sig);
	}

	talloc_free(mem_ctx);
	return nt_status;
}
