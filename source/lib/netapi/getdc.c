/*
 *  Unix SMB/CIFS implementation.
 *  NetApi GetDC Support
 *  Copyright (C) Guenther Deschner 2007
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

/********************************************************************
********************************************************************/

static WERROR NetGetDCNameLocal(struct libnetapi_ctx *ctx,
				const char *server_name,
				const char *domain_name,
				uint8_t **buffer)
{
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
********************************************************************/

static WERROR NetGetDCNameRemote(struct libnetapi_ctx *ctx,
				 const char *server_name,
				 const char *domain_name,
				 uint8_t **buffer)
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

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_NETLOGON,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	};

	status = rpccli_netr_GetDcName(pipe_cli, ctx,
				       server_name,
				       domain_name,
				       (const char **)buffer,
				       &werr);
 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return werr;
}

/********************************************************************
********************************************************************/

static WERROR libnetapi_NetGetDCName(struct libnetapi_ctx *ctx,
				     const char *server_name,
				     const char *domain_name,
				     uint8_t **buffer)
{
	if (!server_name || is_myname_or_ipaddr(server_name)) {
		return NetGetDCNameLocal(ctx,
					 server_name,
					 domain_name,
					 buffer);
	}

	return NetGetDCNameRemote(ctx,
				  server_name,
				  domain_name,
				  buffer);
}

/****************************************************************
 NetGetDCName
****************************************************************/

NET_API_STATUS NetGetDCName(const char *server_name,
			    const char *domain_name,
			    uint8_t **buffer)
{
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	werr = libnetapi_NetGetDCName(ctx,
				      server_name,
				      domain_name,
				      buffer);
	if (!W_ERROR_IS_OK(werr)) {
		return W_ERROR_V(werr);
	}

	return NET_API_STATUS_SUCCESS;
}

/********************************************************************
********************************************************************/

static WERROR NetGetAnyDCNameLocal(struct libnetapi_ctx *ctx,
				   const char *server_name,
				   const char *domain_name,
				   uint8_t **buffer)
{
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
********************************************************************/

static WERROR NetGetAnyDCNameRemote(struct libnetapi_ctx *ctx,
				    const char *server_name,
				    const char *domain_name,
				    uint8_t **buffer)
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

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_NETLOGON,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	};

	status = rpccli_netr_GetAnyDCName(pipe_cli, ctx,
					  server_name,
					  domain_name,
					  (const char **)buffer,
					  &werr);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return werr;

}

/********************************************************************
********************************************************************/

static WERROR libnetapi_NetGetAnyDCName(struct libnetapi_ctx *ctx,
					const char *server_name,
					const char *domain_name,
					uint8_t **buffer)
{
	if (!server_name || is_myname_or_ipaddr(server_name)) {
		return NetGetAnyDCNameLocal(ctx,
					    server_name,
					    domain_name,
					    buffer);
	}

	return NetGetAnyDCNameRemote(ctx,
				     server_name,
				     domain_name,
				     buffer);
}

/****************************************************************
 NetGetAnyDCName
****************************************************************/

NET_API_STATUS NetGetAnyDCName(const char *server_name,
			       const char *domain_name,
			       uint8_t **buffer)
{
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	werr = libnetapi_NetGetAnyDCName(ctx,
					 server_name,
					 domain_name,
					 buffer);
	if (!W_ERROR_IS_OK(werr)) {
		return W_ERROR_V(werr);
	}

	return NET_API_STATUS_SUCCESS;
}
