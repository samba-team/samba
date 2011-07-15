/*
 *  GSSAPI Acceptor
 *  DCERPC Server functions
 *  Copyright (C) Simo Sorce 2010.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "includes.h"
#include "rpc_server/dcesrv_gssapi.h"
#include "../librpc/gen_ndr/ndr_krb5pac.h"
#include "../lib/tsocket/tsocket.h"
#include "librpc/crypto/gse.h"
#include "auth.h"
#ifdef HAVE_KRB5
#include "libcli/auth/krb5_wrap.h"
#endif
NTSTATUS gssapi_server_auth_start(TALLOC_CTX *mem_ctx,
				  bool do_sign,
				  bool do_seal,
				  bool is_dcerpc,
				  DATA_BLOB *token_in,
				  DATA_BLOB *token_out,
				  struct gse_context **ctx)
{
	struct gse_context *gse_ctx = NULL;
	uint32_t add_flags = 0;
        NTSTATUS status;

	if (is_dcerpc) {
		add_flags = GSS_C_DCE_STYLE;
	}

	/* Let's init the gssapi machinery for this connection */
	/* passing a NULL server name means the server will try
	 * to accept any connection regardless of the name used as
	 * long as it can find a decryption key */
	/* by passing NULL, the code will attempt to set a default
	 * keytab based on configuration options */
	status = gse_init_server(mem_ctx, do_sign, do_seal,
				 add_flags, &gse_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to init dcerpc gssapi server (%s)\n",
			  nt_errstr(status)));
		return status;
	}

	status = gse_get_server_auth_token(mem_ctx, gse_ctx,
					   token_in, token_out);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to parse initial client token (%s)\n",
			  nt_errstr(status)));
		goto done;
	}

	*ctx = gse_ctx;
	status = NT_STATUS_OK;

done:
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(gse_ctx);
	}

	return status;
}

NTSTATUS gssapi_server_step(struct gse_context *gse_ctx,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *token_in,
			    DATA_BLOB *token_out)
{
	NTSTATUS status;

	status = gse_get_server_auth_token(mem_ctx, gse_ctx,
					   token_in, token_out);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (gse_require_more_processing(gse_ctx)) {
		/* ask for next leg */
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

	return NT_STATUS_OK;
}

NTSTATUS gssapi_server_check_flags(struct gse_context *gse_ctx)
{
	return gse_verify_server_auth_flags(gse_ctx);
}

NTSTATUS gssapi_server_get_user_info(struct gse_context *gse_ctx,
				     TALLOC_CTX *mem_ctx,
				     const struct tsocket_address *remote_address,
				     struct auth3_session_info **session_info)
{
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB pac_blob;
	struct PAC_DATA *pac_data = NULL;
	struct PAC_LOGON_INFO *logon_info = NULL;
	unsigned int i;
	bool is_mapped;
	bool is_guest;
	char *princ_name;
	char *ntuser;
	char *ntdomain;
	char *username;
	char *rhost;
	struct passwd *pw;
	NTSTATUS status;
	int rc;

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gse_get_pac_blob(gse_ctx, tmp_ctx, &pac_blob);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/* TODO: Fetch user by principal name ? */
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

#ifdef HAVE_KRB5
	status = kerberos_decode_pac(tmp_ctx,
				     pac_blob,
				     NULL, NULL, NULL, NULL, 0, &pac_data);
#else
	status = NT_STATUS_ACCESS_DENIED;
#endif
	data_blob_free(&pac_blob);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = gse_get_client_name(gse_ctx, tmp_ctx, &princ_name);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* get logon name and logon info */
	for (i = 0; i < pac_data->num_buffers; i++) {
		struct PAC_BUFFER *data_buf = &pac_data->buffers[i];

		switch (data_buf->type) {
		case PAC_TYPE_LOGON_INFO:
			if (!data_buf->info) {
				break;
			}
			logon_info = data_buf->info->logon_info.info;
			break;
		default:
			break;
		}
	}
	if (!logon_info) {
		DEBUG(1, ("Invalid PAC data, missing logon info!\n"));
		status = NT_STATUS_NOT_FOUND;
		goto done;
	}

	rc = get_remote_hostname(remote_address,
				 &rhost,
				 tmp_ctx);
	if (rc < 0) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	if (strequal(rhost, "UNKNOWN")) {
		rhost = tsocket_address_inet_addr_string(remote_address,
							 tmp_ctx);
		if (rhost == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	status = get_user_from_kerberos_info(tmp_ctx, rhost,
					     princ_name, logon_info,
					     &is_mapped, &is_guest,
					     &ntuser, &ntdomain,
					     &username, &pw);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to map kerberos principal to system user "
			  "(%s)\n", nt_errstr(status)));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	/* TODO: save PAC data in netsamlogon cache ? */

	status = make_session_info_krb5(mem_ctx,
					ntuser, ntdomain, username, pw,
					logon_info, is_guest, is_mapped, NULL /* No session key for now */,
					session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to map kerberos pac to server info (%s)\n",
			  nt_errstr(status)));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	DEBUG(5, (__location__ "OK: user: %s domain: %s client: %s\n",
		  ntuser, ntdomain, rhost));

	status = NT_STATUS_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}
