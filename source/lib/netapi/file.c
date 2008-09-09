/*
 *  Unix SMB/CIFS implementation.
 *  NetApi File Support
 *  Copyright (C) Guenther Deschner 2008
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

/****************************************************************
****************************************************************/

WERROR NetFileClose_r(struct libnetapi_ctx *ctx,
		      struct NetFileClose *r)
{
	WERROR werr;
	NTSTATUS status;
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;

	werr = libnetapi_open_pipe(ctx, r->in.server_name,
				   &ndr_table_srvsvc.syntax_id,
				   &cli,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = rpccli_srvsvc_NetFileClose(pipe_cli, ctx,
					    r->in.server_name,
					    r->in.fileid,
					    &werr);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

 done:
	if (!cli) {
		return werr;
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetFileClose_l(struct libnetapi_ctx *ctx,
		      struct NetFileClose *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetFileClose);
}

/****************************************************************
****************************************************************/

WERROR NetFileGetInfo_r(struct libnetapi_ctx *ctx,
			struct NetFileGetInfo *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetFileGetInfo_l(struct libnetapi_ctx *ctx,
			struct NetFileGetInfo *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetFileGetInfo);
}
