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

#include "librpc/gen_ndr/libnetapi.h"
#include "lib/netapi/netapi.h"
#include "lib/netapi/libnetapi.h"
#include "libnet/libnet.h"

/********************************************************************
********************************************************************/

WERROR NetGetDCName_l(struct libnetapi_ctx *ctx,
		      struct NetGetDCName *r)
{
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
********************************************************************/

WERROR NetGetDCName_r(struct libnetapi_ctx *ctx,
		      struct NetGetDCName *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;

	status = cli_full_connection(&cli, NULL, r->in.server_name,
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
	}

	status = rpccli_netr_GetDcName(pipe_cli, ctx,
				       r->in.server_name,
				       r->in.domain_name,
				       (const char **)r->out.buffer,
				       &werr);
 done:
	if (cli) {
		cli_shutdown(cli);
	}

	return werr;
}

/********************************************************************
********************************************************************/

WERROR NetGetAnyDCName_l(struct libnetapi_ctx *ctx,
			 struct NetGetAnyDCName *r)
{
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
********************************************************************/

WERROR NetGetAnyDCName_r(struct libnetapi_ctx *ctx,
			 struct NetGetAnyDCName *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;

	status = cli_full_connection(&cli, NULL, r->in.server_name,
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
					  r->in.server_name,
					  r->in.domain_name,
					  (const char **)r->out.buffer,
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
