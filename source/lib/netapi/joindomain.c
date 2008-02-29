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

#include "lib/netapi/netapi.h"
#include "libnet/libnet.h"

/****************************************************************
****************************************************************/

static WERROR NetJoinDomainLocal(struct libnetapi_ctx *mem_ctx,
				 const char *server_name,
				 const char *domain_name,
				 const char *account_ou,
				 const char *Account,
				 const char *password,
				 uint32_t join_flags)
{
	struct libnet_JoinCtx *r = NULL;
	WERROR werr;

	if (!domain_name) {
		return WERR_INVALID_PARAM;
	}

	werr = libnet_init_JoinCtx(mem_ctx, &r);
	W_ERROR_NOT_OK_RETURN(werr);

	r->in.domain_name = talloc_strdup(mem_ctx, domain_name);
	W_ERROR_HAVE_NO_MEMORY(r->in.domain_name);

	if (join_flags & WKSSVC_JOIN_FLAGS_JOIN_TYPE) {
		NTSTATUS status;
		struct netr_DsRGetDCNameInfo *info = NULL;
		uint32_t flags = DS_DIRECTORY_SERVICE_REQUIRED |
				 DS_WRITABLE_REQUIRED |
				 DS_RETURN_DNS_NAME;
		status = dsgetdcname(mem_ctx, domain_name,
				     NULL, NULL, flags, &info);
		if (!NT_STATUS_IS_OK(status)) {
			libnetapi_set_error_string(mem_ctx,
				"%s", get_friendly_nt_error_msg(status));
			return ntstatus_to_werror(status);
		}
		r->in.dc_name = talloc_strdup(mem_ctx,
					      info->dc_unc);
		W_ERROR_HAVE_NO_MEMORY(r->in.dc_name);
	}

	if (account_ou) {
		r->in.account_ou = talloc_strdup(mem_ctx, account_ou);
		W_ERROR_HAVE_NO_MEMORY(r->in.account_ou);
	}

	if (Account) {
		r->in.admin_account = talloc_strdup(mem_ctx, Account);
		W_ERROR_HAVE_NO_MEMORY(r->in.admin_account);
	}

	if (password) {
		r->in.admin_password = talloc_strdup(mem_ctx, password);
		W_ERROR_HAVE_NO_MEMORY(r->in.admin_password);
	}

	r->in.join_flags = join_flags;
	r->in.modify_config = true;

	werr = libnet_Join(mem_ctx, r);
	if (!W_ERROR_IS_OK(werr) && r->out.error_string) {
		libnetapi_set_error_string(mem_ctx, "%s", r->out.error_string);
	}
	TALLOC_FREE(r);

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR NetJoinDomainRemote(struct libnetapi_ctx *ctx,
				  const char *server_name,
				  const char *domain_name,
				  const char *account_ou,
				  const char *Account,
				  const char *password,
				  uint32_t join_flags)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	struct wkssvc_PasswordBuffer *encrypted_password = NULL;
	NTSTATUS status;
	WERROR werr;
	unsigned int old_timeout = 0;

	status = cli_full_connection(&cli, NULL, server_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     ctx->username,
				     ctx->workgroup,
				     ctx->password,
				     0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_WKSSVC,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (password) {
		encode_wkssvc_join_password_buffer(ctx,
						   password,
						   &cli->user_session_key,
						   &encrypted_password);
	}

	old_timeout = cli_set_timeout(cli, 60000);

	status = rpccli_wkssvc_NetrJoinDomain2(pipe_cli, ctx,
					       server_name, domain_name,
					       account_ou, Account,
					       encrypted_password,
					       join_flags, &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (cli) {
		cli_set_timeout(cli, old_timeout);
		cli_shutdown(cli);
	}

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR libnetapi_NetJoinDomain(struct libnetapi_ctx *ctx,
				      const char *server_name,
				      const char *domain_name,
				      const char *account_ou,
				      const char *Account,
				      const char *password,
				      uint32_t join_flags)
{
	if (!domain_name) {
		return WERR_INVALID_PARAM;
	}

	if (!server_name || is_myname_or_ipaddr(server_name)) {

		return NetJoinDomainLocal(ctx,
					  server_name,
					  domain_name,
					  account_ou,
					  Account,
					  password,
					  join_flags);
	}

	return NetJoinDomainRemote(ctx,
				   server_name,
				   domain_name,
				   account_ou,
				   Account,
				   password,
				   join_flags);
}

/****************************************************************
 NetJoinDomain
****************************************************************/

NET_API_STATUS NetJoinDomain(const char *server_name,
			     const char *domain_name,
			     const char *account_ou,
			     const char *Account,
			     const char *password,
			     uint32_t join_flags)
{
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	werr = libnetapi_NetJoinDomain(ctx,
				       server_name,
				       domain_name,
				       account_ou,
				       Account,
				       password,
				       join_flags);
	if (!W_ERROR_IS_OK(werr)) {
		return W_ERROR_V(werr);
	}

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

static WERROR NetUnjoinDomainLocal(struct libnetapi_ctx *mem_ctx,
				   const char *server_name,
				   const char *account,
				   const char *password,
				   uint32_t unjoin_flags)
{
	struct libnet_UnjoinCtx *r = NULL;
	struct dom_sid domain_sid;
	WERROR werr;

	if (!secrets_fetch_domain_sid(lp_workgroup(), &domain_sid)) {
		return WERR_SETUP_NOT_JOINED;
	}

	werr = libnet_init_UnjoinCtx(mem_ctx, &r);
	W_ERROR_NOT_OK_RETURN(werr);

	if (server_name) {
		r->in.dc_name = talloc_strdup(mem_ctx, server_name);
		W_ERROR_HAVE_NO_MEMORY(r->in.dc_name);
	} else {
		NTSTATUS status;
		const char *domain = NULL;
		struct netr_DsRGetDCNameInfo *info = NULL;
		uint32_t flags = DS_DIRECTORY_SERVICE_REQUIRED |
				 DS_WRITABLE_REQUIRED |
				 DS_RETURN_DNS_NAME;
		if (lp_realm()) {
			domain = lp_realm();
		} else {
			domain = lp_workgroup();
		}
		status = dsgetdcname(mem_ctx, domain,
				     NULL, NULL, flags, &info);
		if (!NT_STATUS_IS_OK(status)) {
			libnetapi_set_error_string(mem_ctx,
				"%s", get_friendly_nt_error_msg(status));
			return ntstatus_to_werror(status);
		}
		r->in.dc_name = talloc_strdup(mem_ctx,
					      info->dc_unc);
		W_ERROR_HAVE_NO_MEMORY(r->in.dc_name);
	}

	if (account) {
		r->in.admin_account = talloc_strdup(mem_ctx, account);
		W_ERROR_HAVE_NO_MEMORY(r->in.admin_account);
	}

	if (password) {
		r->in.admin_password = talloc_strdup(mem_ctx, password);
		W_ERROR_HAVE_NO_MEMORY(r->in.admin_password);
	}

	r->in.unjoin_flags = unjoin_flags;
	r->in.modify_config = true;
	r->in.debug = true;

	r->in.domain_sid = &domain_sid;

	werr = libnet_Unjoin(mem_ctx, r);
	if (!W_ERROR_IS_OK(werr) && r->out.error_string) {
		libnetapi_set_error_string(mem_ctx, "%s", r->out.error_string);
	}
	TALLOC_FREE(r);

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR NetUnjoinDomainRemote(struct libnetapi_ctx *ctx,
				    const char *server_name,
				    const char *account,
				    const char *password,
				    uint32_t unjoin_flags)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	struct wkssvc_PasswordBuffer *encrypted_password = NULL;
	NTSTATUS status;
	WERROR werr;
	unsigned int old_timeout = 0;

	status = cli_full_connection(&cli, NULL, server_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     ctx->username,
				     ctx->workgroup,
				     ctx->password,
				     0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_WKSSVC,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (password) {
		encode_wkssvc_join_password_buffer(ctx,
						   password,
						   &cli->user_session_key,
						   &encrypted_password);
	}

	old_timeout = cli_set_timeout(cli, 60000);

	status = rpccli_wkssvc_NetrUnjoinDomain2(pipe_cli, ctx,
						 server_name,
						 account,
						 encrypted_password,
						 unjoin_flags,
						 &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (cli) {
		cli_set_timeout(cli, old_timeout);
		cli_shutdown(cli);
	}

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR libnetapi_NetUnjoinDomain(struct libnetapi_ctx *ctx,
					const char *server_name,
					const char *account,
					const char *password,
					uint32_t unjoin_flags)
{
	if (!server_name || is_myname_or_ipaddr(server_name)) {

		return NetUnjoinDomainLocal(ctx,
					    server_name,
					    account,
					    password,
					    unjoin_flags);
	}

	return NetUnjoinDomainRemote(ctx,
				     server_name,
				     account,
				     password,
				     unjoin_flags);
}

/****************************************************************
 NetUnjoinDomain
****************************************************************/

NET_API_STATUS NetUnjoinDomain(const char *server_name,
			       const char *account,
			       const char *password,
			       uint32_t unjoin_flags)
{
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	werr = libnetapi_NetUnjoinDomain(ctx,
					 server_name,
					 account,
					 password,
					 unjoin_flags);
	if (!W_ERROR_IS_OK(werr)) {
		return W_ERROR_V(werr);
	}

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

static WERROR NetGetJoinInformationRemote(struct libnetapi_ctx *ctx,
					  const char *server_name,
					  const char **name_buffer,
					  uint16_t *name_type)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;

	status = cli_full_connection(&cli, NULL, server_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     ctx->username,
				     ctx->workgroup,
				     ctx->password,
				     0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_WKSSVC,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_wkssvc_NetrGetJoinInformation(pipe_cli, ctx,
						      server_name,
						      name_buffer,
						      (enum wkssvc_NetJoinStatus *)name_type,
						      &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR NetGetJoinInformationLocal(struct libnetapi_ctx *ctx,
					 const char *server_name,
					 const char **name_buffer,
					 uint16_t *name_type)
{
	if ((lp_security() == SEC_ADS) && lp_realm()) {
		*name_buffer = talloc_strdup(ctx, lp_realm());
	} else {
		*name_buffer = talloc_strdup(ctx, lp_workgroup());
	}
	if (!*name_buffer) {
		return WERR_NOMEM;
	}

	switch (lp_server_role()) {
		case ROLE_DOMAIN_MEMBER:
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
			*name_type = NetSetupDomainName;
			break;
		case ROLE_STANDALONE:
		default:
			*name_type = NetSetupWorkgroupName;
			break;
	}

	return WERR_OK;
}

static WERROR libnetapi_NetGetJoinInformation(struct libnetapi_ctx *ctx,
					      const char *server_name,
					      const char **name_buffer,
					      uint16_t *name_type)
{
	if (!server_name || is_myname_or_ipaddr(server_name)) {
		return NetGetJoinInformationLocal(ctx,
						  server_name,
						  name_buffer,
						  name_type);
	}

	return NetGetJoinInformationRemote(ctx,
					   server_name,
					   name_buffer,
					   name_type);
}

/****************************************************************
 NetGetJoinInformation
****************************************************************/

NET_API_STATUS NetGetJoinInformation(const char *server_name,
				     const char **name_buffer,
				     uint16_t *name_type)
{
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	werr = libnetapi_NetGetJoinInformation(ctx,
					       server_name,
					       name_buffer,
					       name_type);
	if (!W_ERROR_IS_OK(werr)) {
		return W_ERROR_V(werr);
	}

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

static WERROR NetGetJoinableOUsLocal(struct libnetapi_ctx *ctx,
				     const char *server_name,
				     const char *domain,
				     const char *account,
				     const char *password,
				     uint32_t *ou_count,
				     const char ***ous)
{
#ifdef WITH_ADS
	NTSTATUS status;
	ADS_STATUS ads_status;
	ADS_STRUCT *ads = NULL;
	struct netr_DsRGetDCNameInfo *info = NULL;
	uint32_t flags = DS_DIRECTORY_SERVICE_REQUIRED |
			 DS_RETURN_DNS_NAME;

	status = dsgetdcname(ctx, domain,
			     NULL, NULL, flags, &info);
	if (!NT_STATUS_IS_OK(status)) {
		libnetapi_set_error_string(ctx, "%s",
			get_friendly_nt_error_msg(status));
		return ntstatus_to_werror(status);
	}

	ads = ads_init(domain, domain, info->dc_unc);
	if (!ads) {
		return WERR_GENERAL_FAILURE;
	}

	SAFE_FREE(ads->auth.user_name);
	if (account) {
		ads->auth.user_name = SMB_STRDUP(account);
	} else if (ctx->username) {
		ads->auth.user_name = SMB_STRDUP(ctx->username);
	}

	SAFE_FREE(ads->auth.password);
	if (password) {
		ads->auth.password = SMB_STRDUP(password);
	} else if (ctx->password) {
		ads->auth.password = SMB_STRDUP(ctx->password);
	}

	ads_status = ads_connect(ads);
	if (!ADS_ERR_OK(ads_status)) {
		ads_destroy(&ads);
		return WERR_DEFAULT_JOIN_REQUIRED;
	}

	ads_status = ads_get_joinable_ous(ads, ctx,
					  (char ***)ous,
					  (size_t *)ou_count);
	if (!ADS_ERR_OK(ads_status)) {
		ads_destroy(&ads);
		return WERR_DEFAULT_JOIN_REQUIRED;
	}

	ads_destroy(&ads);
	return WERR_OK;
#else
	return WERR_NOT_SUPPORTED;
#endif
}

/****************************************************************
****************************************************************/

static WERROR NetGetJoinableOUsRemote(struct libnetapi_ctx *ctx,
				      const char *server_name,
				      const char *domain,
				      const char *account,
				      const char *password,
				      uint32_t *ou_count,
				      const char ***ous)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	struct wkssvc_PasswordBuffer *encrypted_password = NULL;
	NTSTATUS status;
	WERROR werr;

	status = cli_full_connection(&cli, NULL, server_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     ctx->username,
				     ctx->workgroup,
				     ctx->password,
				     0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_WKSSVC,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (password) {
		encode_wkssvc_join_password_buffer(ctx,
						   password,
						   &cli->user_session_key,
						   &encrypted_password);
	}

	status = rpccli_wkssvc_NetrGetJoinableOus2(pipe_cli, ctx,
						   server_name,
						   domain,
						   account,
						   encrypted_password,
						   ou_count,
						   ous,
						   &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR libnetapi_NetGetJoinableOUs(struct libnetapi_ctx *ctx,
					  const char *server_name,
					  const char *domain,
					  const char *account,
					  const char *password,
					  uint32_t *ou_count,
					  const char ***ous)
{
	if (!server_name || is_myname_or_ipaddr(server_name)) {
		return NetGetJoinableOUsLocal(ctx,
					      server_name,
					      domain,
					      account,
					      password,
					      ou_count,
					      ous);
	}

	return NetGetJoinableOUsRemote(ctx,
				       server_name,
				       domain,
				       account,
				       password,
				       ou_count,
				       ous);
}

/****************************************************************
 NetGetJoinableOUs
****************************************************************/

NET_API_STATUS NetGetJoinableOUs(const char *server_name,
				 const char *domain,
				 const char *account,
				 const char *password,
				 uint32_t *ou_count,
				 const char ***ous)
{
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	werr = libnetapi_NetGetJoinableOUs(ctx,
					   server_name,
					   domain,
					   account,
					   password,
					   ou_count,
					   ous);
	if (!W_ERROR_IS_OK(werr)) {
		return W_ERROR_V(werr);
	}

	return NET_API_STATUS_SUCCESS;
}
