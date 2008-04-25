/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Support
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

#include "lib/netapi/netapi.h"
#include "lib/netapi/netapi_private.h"

/********************************************************************
********************************************************************/

WERROR libnetapi_open_ipc_connection(struct libnetapi_ctx *ctx,
				     const char *server_name,
				     struct cli_state **cli)
{
	struct cli_state *cli_ipc = NULL;

	if (!ctx || !cli || !server_name) {
		return WERR_INVALID_PARAM;
	}

	cli_cm_set_signing_state(Undefined);

	if (ctx->use_kerberos) {
		cli_cm_set_use_kerberos();
	}

	if (ctx->password) {
		cli_cm_set_password(ctx->password);
	}
	if (ctx->username) {
		cli_cm_set_username(ctx->username);
	}

	if (ctx->username && ctx->username[0] &&
	    ctx->password && ctx->password[0] &&
	    ctx->use_kerberos) {
		cli_cm_set_fallback_after_kerberos();
	}

	cli_ipc = cli_cm_open(ctx, NULL,
			      server_name, "IPC$",
			      false, false);
	if (!cli_ipc) {
		libnetapi_set_error_string(ctx,
			"Failed to connect to IPC$ share on %s", server_name);
		return WERR_CAN_NOT_COMPLETE;
	}

	*cli = cli_ipc;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR libnetapi_shutdown_cm(struct libnetapi_ctx *ctx)
{
	cli_cm_shutdown();

	return WERR_OK;
}

/********************************************************************
********************************************************************/

struct client_pipe_connection {
	struct client_pipe_connection *prev, *next;
	struct rpc_pipe_client *pipe;
};

static struct client_pipe_connection *pipe_connections;

/********************************************************************
********************************************************************/

static struct rpc_pipe_client *pipe_cm_find(struct cli_state *cli,
					    int pipe_idx,
					    NTSTATUS *status)
{
	struct client_pipe_connection *p;

	for (p = pipe_connections; p; p = p->next) {

		if (!p->pipe->cli) {
			*status = NT_STATUS_PIPE_EMPTY;
			return NULL;
		}

		if (strequal(cli->desthost, p->pipe->cli->desthost) &&
		    pipe_idx == p->pipe->pipe_idx) {
			*status = NT_STATUS_OK;
			return p->pipe;
		}
	}

	*status = NT_STATUS_PIPE_NOT_AVAILABLE;

	return NULL;
}

/********************************************************************
********************************************************************/

static struct rpc_pipe_client *pipe_cm_connect(TALLOC_CTX *mem_ctx,
					       struct cli_state *cli,
					       int pipe_idx,
					       NTSTATUS *status)
{
	struct client_pipe_connection *p;

	p = TALLOC_ZERO_ARRAY(mem_ctx, struct client_pipe_connection, 1);
	if (!p) {
		*status = NT_STATUS_NO_MEMORY;
		return NULL;
	}

	p->pipe = cli_rpc_pipe_open_noauth(cli, pipe_idx, status);
	if (!p->pipe) {
		TALLOC_FREE(p);
		return NULL;
	}

	DLIST_ADD(pipe_connections, p);

	return p->pipe;
}

/********************************************************************
********************************************************************/

static struct rpc_pipe_client *pipe_cm_open(TALLOC_CTX *ctx,
					    struct cli_state *cli,
					    int pipe_idx,
					    NTSTATUS *status)
{
	struct rpc_pipe_client *p;

	p = pipe_cm_find(cli, pipe_idx, status);
	if (!p) {
		p = pipe_cm_connect(ctx, cli, pipe_idx, status);
	}

	return p;
}

/********************************************************************
********************************************************************/

WERROR libnetapi_open_pipe(struct libnetapi_ctx *ctx,
			   struct cli_state *cli,
			   int pipe_idx,
			   struct rpc_pipe_client **pipe_cli)
{
	NTSTATUS status;

	if (!cli || !pipe_cli) {
		return WERR_INVALID_PARAM;
	}

	*pipe_cli = pipe_cm_open(ctx, cli, pipe_idx, &status);
	if (!*pipe_cli) {
		libnetapi_set_error_string(ctx, "failed to open PIPE %s: %s",
			cli_get_pipe_name(pipe_idx),
			get_friendly_nt_error_msg(status));
		return WERR_DEST_NOT_FOUND;
	}

	return WERR_OK;
}


