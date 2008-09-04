/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Share Support
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

static NTSTATUS map_SHARE_INFO_buffer_to_srvsvc_share_info(TALLOC_CTX *mem_ctx,
							   uint8_t *buffer,
							   uint32_t level,
							   union srvsvc_NetShareInfo *info)
{
	struct SHARE_INFO_2 *i2 = NULL;
	struct srvsvc_NetShareInfo2 *s2 = NULL;

	if (!buffer) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (level) {
		case 2:
			i2 = (struct SHARE_INFO_2 *)buffer;

			s2 = TALLOC_P(mem_ctx, struct srvsvc_NetShareInfo2);
			NT_STATUS_HAVE_NO_MEMORY(s2);

			s2->name		= i2->shi2_netname;
			s2->type		= i2->shi2_type;
			s2->comment		= i2->shi2_remark;
			s2->permissions		= i2->shi2_permissions;
			s2->max_users		= i2->shi2_max_uses;
			s2->current_users	= i2->shi2_current_uses;
			s2->path		= i2->shi2_path;
			s2->password		= i2->shi2_passwd;

			info->info2 = s2;

			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

WERROR NetShareAdd_r(struct libnetapi_ctx *ctx,
		     struct NetShareAdd *r)
{
	WERROR werr;
	NTSTATUS status;
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	union srvsvc_NetShareInfo info;

	if (!r->in.buffer) {
		return WERR_INVALID_PARAM;
	}

	switch (r->in.level) {
		case 2:
			break;
		case 502:
		case 503:
			return WERR_NOT_SUPPORTED;
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	werr = libnetapi_open_pipe(ctx, r->in.server_name,
				   &ndr_table_srvsvc.syntax_id,
				   &cli,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = map_SHARE_INFO_buffer_to_srvsvc_share_info(ctx,
							    r->in.buffer,
							    r->in.level,
							    &info);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_srvsvc_NetShareAdd(pipe_cli, ctx,
					   r->in.server_name,
					   r->in.level,
					   &info,
					   r->out.parm_err,
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

WERROR NetShareAdd_l(struct libnetapi_ctx *ctx,
		     struct NetShareAdd *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetShareAdd);
}

/****************************************************************
****************************************************************/

WERROR NetShareDel_r(struct libnetapi_ctx *ctx,
		     struct NetShareDel *r)
{
	WERROR werr;
	NTSTATUS status;
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;

	if (!r->in.net_name) {
		return WERR_INVALID_PARAM;
	}

	werr = libnetapi_open_pipe(ctx, r->in.server_name,
				   &ndr_table_srvsvc.syntax_id,
				   &cli,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = rpccli_srvsvc_NetShareDel(pipe_cli, ctx,
					   r->in.server_name,
					   r->in.net_name,
					   r->in.reserved,
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

WERROR NetShareDel_l(struct libnetapi_ctx *ctx,
		     struct NetShareDel *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetShareDel);
}

/****************************************************************
****************************************************************/

WERROR NetShareEnum_r(struct libnetapi_ctx *ctx,
		      struct NetShareEnum *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetShareEnum_l(struct libnetapi_ctx *ctx,
		      struct NetShareEnum *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetShareEnum);
}

/****************************************************************
****************************************************************/

WERROR NetShareGetInfo_r(struct libnetapi_ctx *ctx,
			 struct NetShareGetInfo *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetShareGetInfo_l(struct libnetapi_ctx *ctx,
			 struct NetShareGetInfo *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetShareGetInfo);
}
