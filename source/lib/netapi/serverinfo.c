/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Server Support
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

/****************************************************************
****************************************************************/

static WERROR NetServerGetInfoLocal_1005(struct libnetapi_ctx *ctx,
					 uint8_t **buffer)
{
	struct srvsvc_NetSrvInfo1005 info1005;

	info1005.comment = lp_serverstring();
	*buffer = (uint8_t *)talloc_memdup(ctx, &info1005, sizeof(info1005));
	if (!*buffer) {
		return WERR_NOMEM;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static WERROR NetServerGetInfoLocal(struct libnetapi_ctx *ctx,
				    const char *server_name,
				    uint32_t level,
				    uint8_t **buffer)
{
	switch (level) {
		case 1005:
			return NetServerGetInfoLocal_1005(ctx, buffer);
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}

/****************************************************************
****************************************************************/

static WERROR NetServerGetInfoRemote(struct libnetapi_ctx *ctx,
				     const char *server_name,
				     uint32_t level,
				     uint8_t **buffer)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	union srvsvc_NetSrvInfo info;

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

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_SRVSVC,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	};

	status = rpccli_srvsvc_NetSrvGetInfo(pipe_cli, ctx,
					     server_name,
					     level,
					     &info,
					     &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	*buffer = (uint8_t *)&info;

 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR libnetapi_NetServerGetInfo(struct libnetapi_ctx *ctx,
					 const char *server_name,
					 uint32_t level,
					 uint8_t **buffer)
{
	if (!server_name || is_myname_or_ipaddr(server_name)) {
		return NetServerGetInfoLocal(ctx,
					     server_name,
					     level,
					     buffer);
	}

	return NetServerGetInfoRemote(ctx,
				      server_name,
				      level,
				      buffer);

}

/****************************************************************
 NetServerGetInfo
****************************************************************/

NET_API_STATUS NetServerGetInfo(const char *server_name,
				uint32_t level,
				uint8_t **buffer)
{
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	werr = libnetapi_NetServerGetInfo(ctx,
					  server_name,
					  level,
					  buffer);
	if (!W_ERROR_IS_OK(werr)) {
		return W_ERROR_V(werr);
	}

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

static WERROR NetServerSetInfoLocal_1005(struct libnetapi_ctx *ctx,
					 uint8_t *buffer,
					 uint32_t *parm_error)
{
	WERROR werr;
	struct smbconf_ctx *conf_ctx;
	struct srvsvc_NetSrvInfo1005 *info1005;

	if (!buffer) {
		*parm_error = 1005; /* sure here ? */
		return WERR_INVALID_PARAM;
	}

	info1005 = (struct srvsvc_NetSrvInfo1005 *)buffer;

	if (!info1005->comment) {
		*parm_error = 1005;
		return WERR_INVALID_PARAM;
	}

	if (!lp_config_backend_is_registry()) {
		libnetapi_set_error_string(ctx,
			"Configuration manipulation requested but not "
			"supported by backend");
		return WERR_NOT_SUPPORTED;
	}

	werr = smbconf_open(ctx, &conf_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = smbconf_set_global_parameter(conf_ctx, "server string",
					    info1005->comment);

 done:
	smbconf_close(conf_ctx);
	return werr;
}

/****************************************************************
****************************************************************/

static WERROR NetServerSetInfoLocal(struct libnetapi_ctx *ctx,
				    const char *server_name,
				    uint32_t level,
				    uint8_t *buffer,
				    uint32_t *parm_error)
{
	switch (level) {
		case 1005:
			return NetServerSetInfoLocal_1005(ctx, buffer, parm_error);
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}

/****************************************************************
****************************************************************/

static WERROR NetServerSetInfoRemote(struct libnetapi_ctx *ctx,
				     const char *server_name,
				     uint32_t level,
				     uint8_t *buffer,
				     uint32_t *parm_error)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	union srvsvc_NetSrvInfo info;

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

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_SRVSVC,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	};

	switch (level) {
		case 1005:
			info.info1005 = (struct srvsvc_NetSrvInfo1005 *)buffer;
			break;
		default:
			werr = WERR_NOT_SUPPORTED;
			goto done;
	}

	status = rpccli_srvsvc_NetSrvSetInfo(pipe_cli, ctx,
					     server_name,
					     level,
					     info,
					     parm_error,
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

static WERROR libnetapi_NetServerSetInfo(struct libnetapi_ctx *ctx,
					 const char *server_name,
					 uint32_t level,
					 uint8_t *buffer,
					 uint32_t *parm_error)
{
	if (!server_name || is_myname_or_ipaddr(server_name)) {
		return NetServerSetInfoLocal(ctx,
					     server_name,
					     level,
					     buffer,
					     parm_error);
	}

	return NetServerSetInfoRemote(ctx,
				      server_name,
				      level,
				      buffer,
				      parm_error);
}

/****************************************************************
 NetServerSetInfo
****************************************************************/

NET_API_STATUS NetServerSetInfo(const char *server_name,
				uint32_t level,
				uint8_t *buffer,
				uint32_t *parm_error)
{
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	werr = libnetapi_NetServerSetInfo(ctx,
					  server_name,
					  level,
					  buffer,
					  parm_error);
	if (!W_ERROR_IS_OK(werr)) {
		return W_ERROR_V(werr);
	}

	return NET_API_STATUS_SUCCESS;
}
