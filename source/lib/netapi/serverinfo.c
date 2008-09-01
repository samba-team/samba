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

static WERROR NetServerGetInfo_l_101(struct libnetapi_ctx *ctx,
				     uint8_t **buffer)
{
	struct SERVER_INFO_101 i;

	i.sv101_platform_id	= PLATFORM_ID_NT;
	i.sv101_name		= global_myname();
	i.sv101_version_major	= lp_major_announce_version();
	i.sv101_version_minor	= lp_minor_announce_version();
	i.sv101_type		= lp_default_server_announce();
	i.sv101_comment		= lp_serverstring();

	*buffer = (uint8_t *)talloc_memdup(ctx, &i, sizeof(i));
	if (!*buffer) {
		return WERR_NOMEM;
	}

	return WERR_OK;
}

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
		case 101:
			return NetServerGetInfo_l_101(ctx, r->out.buffer);
		case 1005:
			return NetServerGetInfo_l_1005(ctx, r->out.buffer);
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}

/****************************************************************
****************************************************************/

static NTSTATUS map_server_info_to_SERVER_INFO_buffer(TALLOC_CTX *mem_ctx,
						      uint32_t level,
						      union srvsvc_NetSrvInfo *i,
						      uint8_t **buffer)
{
	struct SERVER_INFO_100 i100;
	struct SERVER_INFO_101 i101;
	struct SERVER_INFO_102 i102;
	struct SERVER_INFO_1005 i1005;

	uint32_t num_info = 0;

	switch (level) {
		case 100:
			i100.sv100_platform_id		= i->info100->platform_id;
			i100.sv100_name			= talloc_strdup(mem_ctx, i->info100->server_name);

			ADD_TO_ARRAY(mem_ctx, struct SERVER_INFO_100, i100,
				     (struct SERVER_INFO_100 **)buffer,
				     &num_info);
			break;

		case 101:
			i101.sv101_platform_id		= i->info101->platform_id;
			i101.sv101_name			= talloc_strdup(mem_ctx, i->info101->server_name);
			i101.sv101_version_major	= i->info101->version_major;
			i101.sv101_version_minor	= i->info101->version_minor;
			i101.sv101_type			= i->info101->server_type;
			i101.sv101_comment		= talloc_strdup(mem_ctx, i->info101->comment);

			ADD_TO_ARRAY(mem_ctx, struct SERVER_INFO_101, i101,
				     (struct SERVER_INFO_101 **)buffer,
				     &num_info);
			break;

		case 102:
			i102.sv102_platform_id		= i->info102->platform_id;
			i102.sv102_name			= talloc_strdup(mem_ctx, i->info102->server_name);
			i102.sv102_version_major	= i->info102->version_major;
			i102.sv102_version_minor	= i->info102->version_minor;
			i102.sv102_type			= i->info102->server_type;
			i102.sv102_comment		= talloc_strdup(mem_ctx, i->info102->comment);
			i102.sv102_users		= i->info102->users;
			i102.sv102_disc			= i->info102->disc;
			i102.sv102_hidden		= i->info102->hidden;
			i102.sv102_announce		= i->info102->announce;
			i102.sv102_anndelta		= i->info102->anndelta;
			i102.sv102_licenses		= i->info102->licenses;
			i102.sv102_userpath		= talloc_strdup(mem_ctx, i->info102->userpath);

			ADD_TO_ARRAY(mem_ctx, struct SERVER_INFO_102, i102,
				     (struct SERVER_INFO_102 **)buffer,
				     &num_info);
			break;

		case 1005:
			i1005.sv1005_comment		= talloc_strdup(mem_ctx, i->info1005->comment);

			ADD_TO_ARRAY(mem_ctx, struct SERVER_INFO_1005, i1005,
				     (struct SERVER_INFO_1005 **)buffer,
				     &num_info);
			break;
		default:
			return NT_STATUS_NOT_SUPPORTED;
	}

	return NT_STATUS_OK;
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

	if (!r->out.buffer) {
		return WERR_INVALID_PARAM;
	}

	switch (r->in.level) {
		case 100:
		case 101:
		case 102:
		case 1005:
			break;
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

	status = rpccli_srvsvc_NetSrvGetInfo(pipe_cli, ctx,
					     r->in.server_name,
					     r->in.level,
					     &info,
					     &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = map_server_info_to_SERVER_INFO_buffer(ctx, r->in.level, &info,
						       r->out.buffer);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
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

	werr = libnetapi_open_pipe(ctx, r->in.server_name,
				   &ndr_table_srvsvc.syntax_id,
				   &cli,
				   &pipe_cli);
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

/****************************************************************
****************************************************************/

WERROR NetRemoteTOD_r(struct libnetapi_ctx *ctx,
		      struct NetRemoteTOD *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	struct srvsvc_NetRemoteTODInfo *info = NULL;

	werr = libnetapi_open_pipe(ctx, r->in.server_name,
				   &ndr_table_srvsvc.syntax_id,
				   &cli,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = rpccli_srvsvc_NetRemoteTOD(pipe_cli, ctx,
					    r->in.server_name,
					    &info,
					    &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	*r->out.buffer = (uint8_t *)talloc_memdup(ctx, info,
			  sizeof(struct srvsvc_NetRemoteTODInfo));
	W_ERROR_HAVE_NO_MEMORY(*r->out.buffer);

 done:
	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetRemoteTOD_l(struct libnetapi_ctx *ctx,
		      struct NetRemoteTOD *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetRemoteTOD);
}

