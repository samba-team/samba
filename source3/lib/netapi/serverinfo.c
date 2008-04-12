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

#include "librpc/gen_ndr/libnetapi.h"
#include "lib/netapi/netapi.h"
#include "lib/netapi/netapi_private.h"
#include "lib/netapi/libnetapi.h"
#include "libnet/libnet.h"

/****************************************************************
****************************************************************/

static WERROR NetServerGetInfo_l_1005(struct libnetapi_ctx *ctx,
				      uint8_t **buffer)
{
	struct SERVER_INFO_1005 info1005;

	info1005.sv1005_comment = lp_serverstring();
	*buffer = (uint8_t *)talloc_memdup(ctx, &info1005, sizeof(info1005));
	if (!*buffer) {
		return WERR_NOMEM;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

WERROR NetServerGetInfo_l(struct libnetapi_ctx *ctx,
			  struct NetServerGetInfo *r)
{
	switch (r->in.level) {
		case 1005:
			return NetServerGetInfo_l_1005(ctx, r->out.buffer);
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}

/****************************************************************
****************************************************************/

WERROR NetServerGetInfo_r(struct libnetapi_ctx *ctx,
			  struct NetServerGetInfo *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	union srvsvc_NetSrvInfo info;

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SRVSVC, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = rpccli_srvsvc_NetSrvGetInfo(pipe_cli, ctx,
					     r->in.server_name,
					     r->in.level,
					     &info,
					     &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	*r->out.buffer = (uint8_t *)talloc_memdup(ctx, &info, sizeof(info));
	if (!*r->out.buffer) {
		werr = WERR_NOMEM;
		goto done;
	}

 done:
	return werr;
}

/****************************************************************
****************************************************************/

static WERROR NetServerSetInfo_l_1005(struct libnetapi_ctx *ctx,
				      struct NetServerSetInfo *r)
{
	WERROR werr;
	struct smbconf_ctx *conf_ctx;
	struct srvsvc_NetSrvInfo1005 *info1005;

	if (!r->in.buffer) {
		*r->out.parm_error = 1005; /* sure here ? */
		return WERR_INVALID_PARAM;
	}

	info1005 = (struct srvsvc_NetSrvInfo1005 *)r->in.buffer;

	if (!info1005->comment) {
		*r->out.parm_error = 1005;
		return WERR_INVALID_PARAM;
	}

	if (!lp_config_backend_is_registry()) {
		libnetapi_set_error_string(ctx,
			"Configuration manipulation requested but not "
			"supported by backend");
		return WERR_NOT_SUPPORTED;
	}

	werr = smbconf_init_reg(ctx, &conf_ctx, NULL);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = smbconf_set_global_parameter(conf_ctx, "server string",
					    info1005->comment);

 done:
	smbconf_shutdown(conf_ctx);
	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetServerSetInfo_l(struct libnetapi_ctx *ctx,
			  struct NetServerSetInfo *r)
{
	switch (r->in.level) {
		case 1005:
			return NetServerSetInfo_l_1005(ctx, r);
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}

/****************************************************************
****************************************************************/

WERROR NetServerSetInfo_r(struct libnetapi_ctx *ctx,
			  struct NetServerSetInfo *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	union srvsvc_NetSrvInfo info;

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SRVSVC, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	switch (r->in.level) {
		case 1005:
			info.info1005 = (struct srvsvc_NetSrvInfo1005 *)r->in.buffer;
			break;
		default:
			werr = WERR_NOT_SUPPORTED;
			goto done;
	}

	status = rpccli_srvsvc_NetSrvSetInfo(pipe_cli, ctx,
					     r->in.server_name,
					     r->in.level,
					     &info,
					     r->out.parm_error,
					     &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	return werr;
}
