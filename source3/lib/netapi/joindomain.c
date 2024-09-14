/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Join Support
 *  Copyright (C) Guenther Deschner 2007-2008
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
#include "ads.h"
#include "librpc/gen_ndr/libnetapi.h"
#include "libcli/auth/libcli_auth.h"
#include "lib/netapi/netapi.h"
#include "lib/netapi/netapi_private.h"
#include "lib/netapi/libnetapi.h"
#include "librpc/gen_ndr/libnet_join.h"
#include "libnet/libnet_join.h"
#include "../librpc/gen_ndr/ndr_wkssvc_c.h"
#include "rpc_client/cli_pipe.h"
#include "secrets.h"
#include "libsmb/dsgetdcname.h"
#include "../librpc/gen_ndr/ndr_ODJ.h"
#include "lib/util/base64.h"
#include "libnet/libnet_join_offline.h"
#include "libcli/security/dom_sid.h"

/****************************************************************
****************************************************************/

WERROR NetJoinDomain_l(struct libnetapi_ctx *mem_ctx,
		       struct NetJoinDomain *r)
{
	struct libnet_JoinCtx *j = NULL;
	struct libnetapi_private_ctx *priv;
	WERROR werr;

	priv = talloc_get_type_abort(mem_ctx->private_data,
		struct libnetapi_private_ctx);

	if (!r->in.domain) {
		return WERR_INVALID_PARAMETER;
	}

	werr = libnet_init_JoinCtx(mem_ctx, &j);
	W_ERROR_NOT_OK_RETURN(werr);

	j->in.domain_name = talloc_strdup(mem_ctx, r->in.domain);
	W_ERROR_HAVE_NO_MEMORY(j->in.domain_name);

	if (r->in.join_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE) {
		NTSTATUS status;
		struct netr_DsRGetDCNameInfo *info = NULL;
		const char *dc = NULL;
		uint32_t flags = DS_DIRECTORY_SERVICE_REQUIRED |
				 DS_WRITABLE_REQUIRED |
				 DS_RETURN_DNS_NAME;
		status = dsgetdcname(mem_ctx, priv->msg_ctx, r->in.domain,
				     NULL, NULL, flags, &info);
		if (!NT_STATUS_IS_OK(status)) {
			libnetapi_set_error_string(mem_ctx,
				"%s", get_friendly_nt_error_msg(status));
			return ntstatus_to_werror(status);
		}

		dc = strip_hostname(info->dc_unc);
		j->in.dc_name = talloc_strdup(mem_ctx, dc);
		W_ERROR_HAVE_NO_MEMORY(j->in.dc_name);
	}

	if (r->in.account_ou) {
		j->in.account_ou = talloc_strdup(mem_ctx, r->in.account_ou);
		W_ERROR_HAVE_NO_MEMORY(j->in.account_ou);
	}

	if (r->in.account != NULL) {
		NTSTATUS status;

		status = ads_simple_creds(j,
					  r->in.domain,
					  r->in.account,
					  r->in.password,
					  &j->in.admin_credentials);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(j);
			return WERR_NERR_BADUSERNAME;
		}
	} else {
		libnetapi_get_creds(mem_ctx, &j->in.admin_credentials);
		if (j->in.admin_credentials == NULL) {
			TALLOC_FREE(j);
			return WERR_NERR_BADUSERNAME;
		}
	}

	j->in.join_flags = r->in.join_flags;
	j->in.modify_config = true;
	j->in.debug = true;

	werr = libnet_Join(mem_ctx, j);
	if (!W_ERROR_IS_OK(werr) && j->out.error_string) {
		libnetapi_set_error_string(mem_ctx, "%s", j->out.error_string);
	}
	TALLOC_FREE(j);

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetJoinDomain_r(struct libnetapi_ctx *ctx,
		       struct NetJoinDomain *r)
{
	struct rpc_pipe_client *pipe_cli = NULL;
	struct wkssvc_PasswordBuffer *encrypted_password = NULL;
	NTSTATUS status;
	WERROR werr;
	unsigned int old_timeout = 0;
	struct dcerpc_binding_handle *b;
	DATA_BLOB session_key;

	if (IS_DC) {
		return WERR_NERR_SETUPDOMAINCONTROLLER;
	}

	werr = libnetapi_open_pipe(ctx, r->in.server,
				   &ndr_table_wkssvc,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	b = pipe_cli->binding_handle;

	if (r->in.password) {

		status = dcerpc_binding_handle_transport_session_key(
				b, talloc_tos(), &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			werr = ntstatus_to_werror(status);
			goto done;
		}

		werr = encode_wkssvc_join_password_buffer(ctx,
							  r->in.password,
							  &session_key,
							  &encrypted_password);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}

	old_timeout = rpccli_set_timeout(pipe_cli, 600000);

	status = dcerpc_wkssvc_NetrJoinDomain2(b, talloc_tos(),
					       r->in.server,
					       r->in.domain,
					       r->in.account_ou,
					       r->in.account,
					       encrypted_password,
					       r->in.join_flags,
					       &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (pipe_cli && old_timeout) {
		rpccli_set_timeout(pipe_cli, old_timeout);
	}

	return werr;
}
/****************************************************************
****************************************************************/

WERROR NetUnjoinDomain_l(struct libnetapi_ctx *mem_ctx,
			 struct NetUnjoinDomain *r)
{
	struct libnet_UnjoinCtx *u = NULL;
	struct dom_sid domain_sid;
	const char *domain = NULL;
	WERROR werr;
	struct libnetapi_private_ctx *priv;
	const char *realm = lp_realm();

	priv = talloc_get_type_abort(mem_ctx->private_data,
		struct libnetapi_private_ctx);

	if (!secrets_fetch_domain_sid(lp_workgroup(), &domain_sid)) {
		return WERR_NERR_SETUPNOTJOINED;
	}

	werr = libnet_init_UnjoinCtx(mem_ctx, &u);
	W_ERROR_NOT_OK_RETURN(werr);

	if (realm[0] != '\0') {
		domain = realm;
	} else {
		domain = lp_workgroup();
	}

	if (r->in.server_name) {
		u->in.dc_name = talloc_strdup(mem_ctx, r->in.server_name);
		W_ERROR_HAVE_NO_MEMORY(u->in.dc_name);
	} else {
		NTSTATUS status;
		struct netr_DsRGetDCNameInfo *info = NULL;
		const char *dc = NULL;
		uint32_t flags = DS_DIRECTORY_SERVICE_REQUIRED |
				 DS_WRITABLE_REQUIRED |
				 DS_RETURN_DNS_NAME;
		status = dsgetdcname(mem_ctx, priv->msg_ctx, domain,
				     NULL, NULL, flags, &info);
		if (!NT_STATUS_IS_OK(status)) {
			libnetapi_set_error_string(mem_ctx,
				"failed to find DC for domain %s: %s",
				domain,
				get_friendly_nt_error_msg(status));
			return ntstatus_to_werror(status);
		}

		dc = strip_hostname(info->dc_unc);
		u->in.dc_name = talloc_strdup(mem_ctx, dc);
		W_ERROR_HAVE_NO_MEMORY(u->in.dc_name);

		u->in.domain_name = domain;
	}

	if (r->in.account != NULL) {
		NTSTATUS status;

		status = ads_simple_creds(u,
					  domain,
					  r->in.account,
					  r->in.password,
					  &u->in.admin_credentials);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(u);
			return WERR_NERR_BADUSERNAME;
		}
	} else {
		libnetapi_get_creds(mem_ctx, &u->in.admin_credentials);
		if (u->in.admin_credentials == NULL) {
			TALLOC_FREE(u);
			return WERR_NERR_BADUSERNAME;
		}
	}

	u->in.domain_name = domain;
	u->in.unjoin_flags = r->in.unjoin_flags;
	u->in.delete_machine_account = false;
	u->in.modify_config = true;
	u->in.debug = true;

	u->in.domain_sid = &domain_sid;

	werr = libnet_Unjoin(mem_ctx, u);
	if (!W_ERROR_IS_OK(werr) && u->out.error_string) {
		libnetapi_set_error_string(mem_ctx, "%s", u->out.error_string);
	}
	TALLOC_FREE(u);

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetUnjoinDomain_r(struct libnetapi_ctx *ctx,
			 struct NetUnjoinDomain *r)
{
	struct rpc_pipe_client *pipe_cli = NULL;
	struct wkssvc_PasswordBuffer *encrypted_password = NULL;
	NTSTATUS status;
	WERROR werr;
	unsigned int old_timeout = 0;
	struct dcerpc_binding_handle *b;
	DATA_BLOB session_key;

	werr = libnetapi_open_pipe(ctx, r->in.server_name,
				   &ndr_table_wkssvc,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	b = pipe_cli->binding_handle;

	if (r->in.password) {

		status = dcerpc_binding_handle_transport_session_key(
				b, talloc_tos(), &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			werr = ntstatus_to_werror(status);
			goto done;
		}

		werr = encode_wkssvc_join_password_buffer(ctx,
							  r->in.password,
							  &session_key,
							  &encrypted_password);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}

	old_timeout = rpccli_set_timeout(pipe_cli, 60000);

	status = dcerpc_wkssvc_NetrUnjoinDomain2(b, talloc_tos(),
						 r->in.server_name,
						 r->in.account,
						 encrypted_password,
						 r->in.unjoin_flags,
						 &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (pipe_cli && old_timeout) {
		rpccli_set_timeout(pipe_cli, old_timeout);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetGetJoinInformation_r(struct libnetapi_ctx *ctx,
			       struct NetGetJoinInformation *r)
{
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	const char *buffer = NULL;
	struct dcerpc_binding_handle *b;

	werr = libnetapi_open_pipe(ctx, r->in.server_name,
				   &ndr_table_wkssvc,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	b = pipe_cli->binding_handle;

	status = dcerpc_wkssvc_NetrGetJoinInformation(b, talloc_tos(),
						      r->in.server_name,
						      &buffer,
						      (enum wkssvc_NetJoinStatus *)r->out.name_type,
						      &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	*r->out.name_buffer = talloc_strdup(ctx, buffer);
	W_ERROR_HAVE_NO_MEMORY(*r->out.name_buffer);

 done:
	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetGetJoinInformation_l(struct libnetapi_ctx *ctx,
			       struct NetGetJoinInformation *r)
{
	const char *realm = lp_realm();

	if ((lp_security() == SEC_ADS) && realm[0] != '\0') {
		*r->out.name_buffer = talloc_strdup(ctx, realm);
	} else {
		*r->out.name_buffer = talloc_strdup(ctx, lp_workgroup());
	}
	if (!*r->out.name_buffer) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	switch (lp_server_role()) {
		case ROLE_DOMAIN_MEMBER:
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
		case ROLE_IPA_DC:
			*r->out.name_type = NetSetupDomainName;
			break;
		case ROLE_STANDALONE:
		default:
			*r->out.name_type = NetSetupWorkgroupName;
			break;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

WERROR NetGetJoinableOUs_l(struct libnetapi_ctx *ctx,
			   struct NetGetJoinableOUs *r)
{
#ifdef HAVE_ADS
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	WERROR ret;
	NTSTATUS status;
	ADS_STATUS ads_status;
	ADS_STRUCT *ads = NULL;
	struct cli_credentials *creds = NULL;
	struct netr_DsRGetDCNameInfo *info = NULL;
	const char *dc = NULL;
	uint32_t flags = DS_DIRECTORY_SERVICE_REQUIRED |
			 DS_RETURN_DNS_NAME;
	struct libnetapi_private_ctx *priv;
	char **p;
	size_t s;

	priv = talloc_get_type_abort(ctx->private_data,
		struct libnetapi_private_ctx);

	status = dsgetdcname(tmp_ctx, priv->msg_ctx, r->in.domain,
			     NULL, NULL, flags, &info);
	if (!NT_STATUS_IS_OK(status)) {
		libnetapi_set_error_string(ctx, "%s",
			get_friendly_nt_error_msg(status));
		ret = ntstatus_to_werror(status);
		goto out;
	}

	dc = strip_hostname(info->dc_unc);

	ads = ads_init(tmp_ctx,
		       info->domain_name,
		       info->domain_name,
		       dc,
		       ADS_SASL_PLAIN);
	if (!ads) {
		ret = WERR_GEN_FAILURE;
		goto out;
	}

	if (r->in.account != NULL) {
		status = ads_simple_creds(ads,
					  r->in.domain,
					  r->in.account,
					  r->in.password,
					  &creds);
		if (!NT_STATUS_IS_OK(status)) {
			ret = WERR_NERR_DEFAULTJOINREQUIRED;
			goto out;
		}
	} else {
		libnetapi_get_creds(ctx, &creds);
	}

	ads_status = ads_connect_creds(ads, creds);
	if (!ADS_ERR_OK(ads_status)) {
		ret = WERR_NERR_DEFAULTJOINREQUIRED;
		goto out;
	}

	ads_status = ads_get_joinable_ous(ads, ctx, &p, &s);
	if (!ADS_ERR_OK(ads_status)) {
		ret = WERR_NERR_DEFAULTJOINREQUIRED;
		goto out;
	}
	*r->out.ous = discard_const_p(const char *, p);
	*r->out.ou_count = s;

	ret = WERR_OK;
out:
	TALLOC_FREE(tmp_ctx);

	return ret;
#else
	return WERR_NOT_SUPPORTED;
#endif
}

/****************************************************************
****************************************************************/

WERROR NetGetJoinableOUs_r(struct libnetapi_ctx *ctx,
			   struct NetGetJoinableOUs *r)
{
	struct rpc_pipe_client *pipe_cli = NULL;
	struct wkssvc_PasswordBuffer *encrypted_password = NULL;
	NTSTATUS status;
	WERROR werr;
	struct dcerpc_binding_handle *b;
	DATA_BLOB session_key;

	werr = libnetapi_open_pipe(ctx, r->in.server_name,
				   &ndr_table_wkssvc,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	b = pipe_cli->binding_handle;

	if (r->in.password) {

		status = dcerpc_binding_handle_transport_session_key(
				b, talloc_tos(), &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			werr = ntstatus_to_werror(status);
			goto done;
		}

		werr = encode_wkssvc_join_password_buffer(ctx,
							  r->in.password,
							  &session_key,
							  &encrypted_password);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}

	status = dcerpc_wkssvc_NetrGetJoinableOus2(b, talloc_tos(),
						   r->in.server_name,
						   r->in.domain,
						   r->in.account,
						   encrypted_password,
						   r->out.ou_count,
						   r->out.ous,
						   &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetRenameMachineInDomain_r(struct libnetapi_ctx *ctx,
				  struct NetRenameMachineInDomain *r)
{
	struct rpc_pipe_client *pipe_cli = NULL;
	struct wkssvc_PasswordBuffer *encrypted_password = NULL;
	NTSTATUS status;
	WERROR werr;
	struct dcerpc_binding_handle *b;
	DATA_BLOB session_key;

	werr = libnetapi_open_pipe(ctx, r->in.server_name,
				   &ndr_table_wkssvc,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	b = pipe_cli->binding_handle;

	if (r->in.password) {

		status = dcerpc_binding_handle_transport_session_key(
				b, talloc_tos(), &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			werr = ntstatus_to_werror(status);
			goto done;
		}

		werr = encode_wkssvc_join_password_buffer(ctx,
							  r->in.password,
							  &session_key,
							  &encrypted_password);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}

	status = dcerpc_wkssvc_NetrRenameMachineInDomain2(b, talloc_tos(),
							  r->in.server_name,
							  r->in.new_machine_name,
							  r->in.account,
							  encrypted_password,
							  r->in.rename_options,
							  &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetRenameMachineInDomain_l(struct libnetapi_ctx *ctx,
				  struct NetRenameMachineInDomain *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetRenameMachineInDomain);
}

/****************************************************************
****************************************************************/

WERROR NetProvisionComputerAccount_r(struct libnetapi_ctx *ctx,
				     struct NetProvisionComputerAccount *r)
{
	return NetProvisionComputerAccount_l(ctx, r);
}

/****************************************************************
****************************************************************/

static WERROR NetProvisionComputerAccount_backend(struct libnetapi_ctx *ctx,
						  struct NetProvisionComputerAccount *r,
						  TALLOC_CTX *mem_ctx,
						  struct ODJ_PROVISION_DATA **p)
{
	WERROR werr;
	struct libnet_JoinCtx *j = NULL;

	werr = libnet_init_JoinCtx(mem_ctx, &j);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	j->in.domain_name = talloc_strdup(j, r->in.domain);
	if (j->in.domain_name == NULL) {
		talloc_free(j);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	talloc_free(discard_const_p(char *, j->in.machine_name));
	j->in.machine_name = talloc_strdup(j, r->in.machine_name);
	if (j->in.machine_name == NULL) {
		talloc_free(j);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (r->in.dcname) {
		j->in.dc_name = talloc_strdup(j, r->in.dcname);
		if (j->in.dc_name == NULL) {
			talloc_free(j);
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	if (r->in.machine_account_ou) {
		j->in.account_ou = talloc_strdup(j, r->in.machine_account_ou);
		if (j->in.account_ou == NULL) {
			talloc_free(j);
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	libnetapi_get_creds(ctx, &j->in.admin_credentials);
	if (j->in.admin_credentials == NULL) {
		talloc_free(j);
		return WERR_NERR_BADUSERNAME;
	}

	j->in.debug = true;
	j->in.join_flags	= WKSSVC_JOIN_FLAGS_JOIN_TYPE |
				  WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE;

	if (r->in.options & NETSETUP_PROVISION_REUSE_ACCOUNT) {
		j->in.join_flags |= WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED;
	}

	if (r->in.options & NETSETUP_PROVISION_USE_DEFAULT_PASSWORD) {
		j->in.join_flags |= WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED;
		j->in.machine_password = talloc_strdup(j, r->in.machine_name);
		if (j->in.machine_password == NULL) {
			talloc_free(j);
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	j->in.provision_computer_account_only = true;

	werr = libnet_Join(mem_ctx, j);
	if (!W_ERROR_IS_OK(werr) && j->out.error_string) {
		libnetapi_set_error_string(ctx, "%s", j->out.error_string);
		talloc_free(j);
		return werr;
	}

	werr = libnet_odj_compose_ODJ_PROVISION_DATA(mem_ctx, j, p);
	if (!W_ERROR_IS_OK(werr)) {
		talloc_free(j);
		return werr;
	}

	TALLOC_FREE(j);

	return WERR_OK;
}

WERROR NetProvisionComputerAccount_l(struct libnetapi_ctx *ctx,
				     struct NetProvisionComputerAccount *r)
{
	WERROR werr;
	enum ndr_err_code ndr_err;
	const char *b64_bin_data_str;
	DATA_BLOB blob;
	struct ODJ_PROVISION_DATA_serialized_ptr odj_provision_data;
	struct ODJ_PROVISION_DATA *p;
	TALLOC_CTX *mem_ctx = talloc_new(ctx);

	if (r->in.provision_bin_data == NULL &&
	    r->in.provision_text_data == NULL) {
		return WERR_INVALID_PARAMETER;
	}
	if (r->in.provision_bin_data != NULL &&
	    r->in.provision_text_data != NULL) {
		return WERR_INVALID_PARAMETER;
	}
	if (r->in.provision_bin_data == NULL &&
	    r->in.provision_bin_data_size != NULL) {
		return WERR_INVALID_PARAMETER;
	}
	if (r->in.provision_bin_data != NULL &&
	   r->in.provision_bin_data_size == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	if (r->in.domain == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	if (r->in.machine_name == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	werr = NetProvisionComputerAccount_backend(ctx, r, mem_ctx, &p);
	if (!W_ERROR_IS_OK(werr)) {
		talloc_free(mem_ctx);
		return werr;
	}

	ZERO_STRUCT(odj_provision_data);

	odj_provision_data.s.p = p;

	ndr_err = ndr_push_struct_blob(&blob, ctx, &odj_provision_data,
		(ndr_push_flags_fn_t)ndr_push_ODJ_PROVISION_DATA_serialized_ptr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(mem_ctx);
		return W_ERROR(NERR_BadOfflineJoinInfo);
	}

	talloc_free(mem_ctx);

	if (r->out.provision_text_data != NULL) {
		b64_bin_data_str = base64_encode_data_blob(ctx, blob);
		if (b64_bin_data_str == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		*r->out.provision_text_data = b64_bin_data_str;
	}

	if (r->out.provision_bin_data != NULL &&
	    r->out.provision_bin_data_size != NULL) {
		*r->out.provision_bin_data = blob.data;
		*r->out.provision_bin_data_size = blob.length;
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetRequestOfflineDomainJoin_r(struct libnetapi_ctx *ctx,
				     struct NetRequestOfflineDomainJoin *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

static WERROR NetRequestOfflineDomainJoin_backend(struct libnetapi_ctx *ctx,
						  const struct ODJ_WIN7BLOB *win7blob,
						  const struct ODJ_PROVISION_DATA *odj_provision_data)
{
	struct libnet_JoinCtx *j = NULL;
	WERROR werr;

	werr = libnet_init_JoinCtx(ctx, &j);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	j->in.domain_name = talloc_strdup(j, win7blob->lpDomain);
	if (j->in.domain_name == NULL) {
		talloc_free(j);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	talloc_free(discard_const_p(char *, j->in.machine_name));
	j->in.machine_name = talloc_strdup(j, win7blob->lpMachineName);
	if (j->in.machine_name == NULL) {
		talloc_free(j);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	j->in.machine_password = talloc_strdup(j, win7blob->lpMachinePassword);
	if (j->in.machine_password == NULL) {
		talloc_free(j);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	j->in.request_offline_join = true;
	j->in.odj_provision_data = discard_const(odj_provision_data);
	j->in.debug = true;
	j->in.join_flags	= WKSSVC_JOIN_FLAGS_JOIN_TYPE |
				  WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED;

	werr = libnet_Join(j, j);
	if (!W_ERROR_IS_OK(werr)) {
		if (j->out.error_string != NULL) {
			libnetapi_set_error_string(ctx, "%s", j->out.error_string);
		}
		talloc_free(j);
		return werr;
	}

	TALLOC_FREE(j);

	return WERR_OK;
}

WERROR NetRequestOfflineDomainJoin_l(struct libnetapi_ctx *ctx,
				     struct NetRequestOfflineDomainJoin *r)
{
	DATA_BLOB blob, blob_base64;
	enum ndr_err_code ndr_err;
	struct ODJ_PROVISION_DATA_serialized_ptr odj_provision_data;
	bool ok;
	struct ODJ_WIN7BLOB win7blob = { 0 };
	WERROR werr;

	if (r->in.provision_bin_data == NULL ||
	    r->in.provision_bin_data_size == 0) {
		return W_ERROR(NERR_NoOfflineJoinInfo);
	}

	if (r->in.provision_bin_data_size < 2) {
		return W_ERROR(NERR_BadOfflineJoinInfo);
	}

	/*
	 * Windows produces and consumes UTF16/UCS2 encoded blobs. Check for the
	 * unicode BOM mark and convert back to UNIX charset if necessary.
	 */
	if (r->in.provision_bin_data[0] == 0xff &&
	    r->in.provision_bin_data[1] == 0xfe) {
		ok = convert_string_talloc(ctx, CH_UTF16LE, CH_UNIX,
					   r->in.provision_bin_data+2,
					   r->in.provision_bin_data_size-2,
					   &blob_base64.data,
					   &blob_base64.length);
		if (!ok) {
			return W_ERROR(NERR_BadOfflineJoinInfo);
		}
	} else {
		blob_base64 = data_blob(r->in.provision_bin_data,
					r->in.provision_bin_data_size);
	}

	blob = base64_decode_data_blob_talloc(ctx, (const char *)blob_base64.data);

	ndr_err = ndr_pull_struct_blob(&blob, ctx, &odj_provision_data,
		(ndr_pull_flags_fn_t)ndr_pull_ODJ_PROVISION_DATA_serialized_ptr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return W_ERROR(NERR_BadOfflineJoinInfo);
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(ODJ_PROVISION_DATA_serialized_ptr, &odj_provision_data);
	}

	if (odj_provision_data.s.p->ulVersion != 1) {
		return W_ERROR(NERR_ProvisioningBlobUnsupported);
	}

	werr = libnet_odj_find_win7blob(odj_provision_data.s.p, &win7blob);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	if (!(r->in.options & NETSETUP_PROVISION_ONLINE_CALLER)) {
		return WERR_NERR_SETUPNOTJOINED;
	}

	werr = NetRequestOfflineDomainJoin_backend(ctx,
						   &win7blob,
						   odj_provision_data.s.p);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	return W_ERROR(NERR_JoinPerformedMustRestart);
}

/****************************************************************
****************************************************************/

WERROR NetComposeOfflineDomainJoin_r(struct libnetapi_ctx *ctx,
				     struct NetComposeOfflineDomainJoin *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

static WERROR NetComposeOfflineDomainJoin_backend(struct libnetapi_ctx *ctx,
						  struct NetComposeOfflineDomainJoin *r,
						  TALLOC_CTX *mem_ctx,
						  struct ODJ_PROVISION_DATA **p)
{
	struct libnet_JoinCtx *j = NULL;
	WERROR werr;

	werr = libnet_init_JoinCtx(ctx, &j);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	j->in.domain_name = talloc_strdup(j, r->in.dns_domain_name);
	if (j->in.domain_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	j->in.dc_name = talloc_strdup(j, r->in.dc_name);
	W_ERROR_HAVE_NO_MEMORY(j->in.dc_name);

	j->in.machine_password = talloc_strdup(j, r->in.machine_account_password);
	W_ERROR_HAVE_NO_MEMORY(j->in.machine_password);

	j->out.account_name = talloc_strdup(j, r->in.machine_account_name);
	W_ERROR_HAVE_NO_MEMORY(j->out.account_name);

	j->out.dns_domain_name = talloc_strdup(j, r->in.dns_domain_name);
	W_ERROR_HAVE_NO_MEMORY(j->out.dns_domain_name);

	j->out.netbios_domain_name = talloc_strdup(j, r->in.netbios_domain_name);
	W_ERROR_HAVE_NO_MEMORY(j->out.netbios_domain_name);

	j->out.domain_sid = dom_sid_dup(j, (struct dom_sid *)r->in.domain_sid);
	W_ERROR_HAVE_NO_MEMORY(j->out.domain_sid);

	j->out.domain_guid = *r->in.domain_guid;

	j->out.forest_name = talloc_strdup(j, r->in.forest_name);
	W_ERROR_HAVE_NO_MEMORY(j->out.forest_name);

	j->out.domain_is_ad = r->in.domain_is_ad;

	j->out.dcinfo = talloc_zero(j, struct netr_DsRGetDCNameInfo);
	W_ERROR_HAVE_NO_MEMORY(j->out.dcinfo);

	j->out.dcinfo->dc_unc = talloc_asprintf(j->out.dcinfo, "\\\\%s", r->in.dc_name);
	W_ERROR_HAVE_NO_MEMORY(j->out.dcinfo->dc_unc);

	j->out.dcinfo->dc_address = talloc_asprintf(j->out.dcinfo, "\\\\%s", r->in.dc_address);
	W_ERROR_HAVE_NO_MEMORY(j->out.dcinfo->dc_address);

	j->out.dcinfo->dc_address_type = DS_ADDRESS_TYPE_INET;

	j->out.dcinfo->domain_guid = *r->in.domain_guid;

	j->out.dcinfo->domain_name = talloc_strdup(j->out.dcinfo, r->in.dns_domain_name);
	W_ERROR_HAVE_NO_MEMORY(j->out.dcinfo->domain_name);

	j->out.dcinfo->forest_name = talloc_strdup(j->out.dcinfo, r->in.forest_name);
	W_ERROR_HAVE_NO_MEMORY(j->out.dcinfo->forest_name);

	werr = libnet_odj_compose_ODJ_PROVISION_DATA(mem_ctx, j, p);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	return WERR_OK;
}

WERROR NetComposeOfflineDomainJoin_l(struct libnetapi_ctx *ctx,
				     struct NetComposeOfflineDomainJoin *r)
{
	WERROR werr;
	enum ndr_err_code ndr_err;
	const char *b64_bin_data_str;
	DATA_BLOB blob;
	struct ODJ_PROVISION_DATA_serialized_ptr odj_compose_data;
	struct ODJ_PROVISION_DATA *p;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	if (r->in.compose_bin_data == NULL &&
	    r->in.compose_text_data == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}
	if (r->in.compose_bin_data != NULL &&
	    r->in.compose_text_data != NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}
	if (r->in.compose_bin_data == NULL &&
	    r->in.compose_bin_data_size != NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}
	if (r->in.compose_bin_data != NULL &&
	    r->in.compose_bin_data_size == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	if (r->in.dns_domain_name == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	if (r->in.netbios_domain_name == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	if (r->in.domain_sid == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	if (r->in.domain_guid == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	if (r->in.forest_name == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	if (r->in.machine_account_name == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	if (r->in.machine_account_password == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	if (r->in.dc_name == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	if (r->in.dc_address == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto out;
	}

	werr = NetComposeOfflineDomainJoin_backend(ctx, r, tmp_ctx, &p);
	if (!W_ERROR_IS_OK(werr)) {
		goto out;
	}

	ZERO_STRUCT(odj_compose_data);

	odj_compose_data.s.p = p;

	ndr_err = ndr_push_struct_blob(&blob, ctx, &odj_compose_data,
		(ndr_push_flags_fn_t)ndr_push_ODJ_PROVISION_DATA_serialized_ptr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		werr = W_ERROR(NERR_BadOfflineJoinInfo);
		goto out;
	}

	if (r->out.compose_text_data != NULL) {
		b64_bin_data_str = base64_encode_data_blob(ctx, blob);
		if (b64_bin_data_str == NULL) {
			werr = WERR_NOT_ENOUGH_MEMORY;
		}
		*r->out.compose_text_data = b64_bin_data_str;
	}

	if (r->out.compose_bin_data != NULL &&
	    r->out.compose_bin_data_size != NULL) {
		*r->out.compose_bin_data = blob.data;
		*r->out.compose_bin_data_size = blob.length;
	}

	werr = WERR_OK;
out:
	talloc_free(tmp_ctx);
	return werr;
}
