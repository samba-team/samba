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
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "rpc_client/cli_pipe.h"
#include "../libcli/smb/smbXcli_base.h"

/********************************************************************
********************************************************************/

struct client_ipc_connection {
	struct client_ipc_connection *prev, *next;
	struct cli_state *cli;
	struct client_pipe_connection *pipe_connections;
};

struct client_pipe_connection {
	struct client_pipe_connection *prev, *next;
	struct rpc_pipe_client *pipe;
};

/********************************************************************
********************************************************************/

static struct client_ipc_connection *ipc_cm_find(
	struct libnetapi_private_ctx *priv_ctx, const char *server_name)
{
	struct client_ipc_connection *p;

	for (p = priv_ctx->ipc_connections; p; p = p->next) {
		const char *remote_name = smbXcli_conn_remote_name(p->cli->conn);

		if (strequal(remote_name, server_name)) {
			return p;
		}
	}

	return NULL;
}

/********************************************************************
********************************************************************/

static WERROR libnetapi_open_ipc_connection(struct libnetapi_ctx *ctx,
					    const char *server_name,
					    struct client_ipc_connection **pp)
{
	struct libnetapi_private_ctx *priv_ctx;
	struct cli_state *cli_ipc = NULL;
	struct client_ipc_connection *p;
	NTSTATUS status;
	const char *username = NULL;
	const char *password = NULL;
	NET_API_STATUS rc;
	enum credentials_use_kerberos krb5_state;
	struct smb_transports ts =
		smb_transports_parse("client smb transports",
				     lp_client_smb_transports());

	if (!ctx || !pp || !server_name) {
		return WERR_INVALID_PARAMETER;
	}

	priv_ctx = (struct libnetapi_private_ctx *)ctx->private_data;

	p = ipc_cm_find(priv_ctx, server_name);
	if (p) {
		*pp = p;
		return WERR_OK;
	}

	rc = libnetapi_get_username(ctx, &username);
	if (rc != 0) {
		return WERR_INTERNAL_ERROR;
	}

	rc = libnetapi_get_password(ctx, &password);
	if (rc != 0) {
		return WERR_INTERNAL_ERROR;
	}

	if (password == NULL) {
		cli_credentials_set_cmdline_callbacks(ctx->creds);
	}

	krb5_state = cli_credentials_get_kerberos_state(ctx->creds);

	if (username != NULL && username[0] != '\0' &&
	    password != NULL && password[0] != '\0' &&
	    krb5_state == CRED_USE_KERBEROS_REQUIRED) {
		cli_credentials_set_kerberos_state(ctx->creds,
						   CRED_USE_KERBEROS_DESIRED,
						   CRED_SPECIFIED);
	}

	status = cli_cm_open(ctx, NULL,
			     server_name, "IPC$",
			     ctx->creds,
			     NULL, &ts, 0x20, &cli_ipc);
	if (!NT_STATUS_IS_OK(status)) {
		cli_ipc = NULL;
	}

	if (!cli_ipc) {
		libnetapi_set_error_string(ctx,
			"Failed to connect to IPC$ share on %s", server_name);
		return WERR_CAN_NOT_COMPLETE;
	}

	p = talloc_zero(ctx, struct client_ipc_connection);
	if (p == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	p->cli = cli_ipc;
	DLIST_ADD(priv_ctx->ipc_connections, p);

	*pp = p;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR libnetapi_shutdown_cm(struct libnetapi_ctx *ctx)
{
	struct libnetapi_private_ctx *priv_ctx =
		(struct libnetapi_private_ctx *)ctx->private_data;
	struct client_ipc_connection *p;

	for (p = priv_ctx->ipc_connections; p; p = p->next) {
		cli_shutdown(p->cli);
	}

	return WERR_OK;
}

/********************************************************************
********************************************************************/

static NTSTATUS pipe_cm_find(struct client_ipc_connection *ipc,
			     const struct ndr_interface_table *table,
			     struct rpc_pipe_client **presult)
{
	struct client_pipe_connection *p;

	for (p = ipc->pipe_connections; p; p = p->next) {
		struct dcerpc_binding_handle *bh = NULL;
		const struct dcerpc_binding *bd = NULL;
		const char *ipc_remote_name;
		struct ndr_syntax_id syntax;

		if (!rpccli_is_connected(p->pipe)) {
			return NT_STATUS_PIPE_EMPTY;
		}

		ipc_remote_name = smbXcli_conn_remote_name(ipc->cli->conn);

		if (!strequal(ipc_remote_name, p->pipe->desthost)) {
			continue;
		}

		bh = p->pipe->binding_handle;
		bd = dcerpc_binding_handle_get_binding(bh);
		syntax = dcerpc_binding_get_abstract_syntax(bd);

		if (ndr_syntax_id_equal(&syntax, &table->syntax_id)) {
			*presult = p->pipe;
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_PIPE_NOT_AVAILABLE;
}

/********************************************************************
********************************************************************/

static NTSTATUS pipe_cm_connect(TALLOC_CTX *mem_ctx,
				struct client_ipc_connection *ipc,
				const struct ndr_interface_table *table,
				struct rpc_pipe_client **presult)
{
	struct client_pipe_connection *p;
	NTSTATUS status;

	p = talloc_zero_array(mem_ctx, struct client_pipe_connection, 1);
	if (!p) {
		return NT_STATUS_NO_MEMORY;
	}

	status = cli_rpc_pipe_open_noauth(ipc->cli, table, &p->pipe);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(p);
		return status;
	}

	DLIST_ADD(ipc->pipe_connections, p);

	*presult = p->pipe;
	return NT_STATUS_OK;
}

/********************************************************************
********************************************************************/

static NTSTATUS pipe_cm_open(TALLOC_CTX *ctx,
			     struct client_ipc_connection *ipc,
			     const struct ndr_interface_table *table,
			     struct rpc_pipe_client **presult)
{
	if (NT_STATUS_IS_OK(pipe_cm_find(ipc, table, presult))) {
		return NT_STATUS_OK;
	}

	return pipe_cm_connect(ctx, ipc, table, presult);
}

/********************************************************************
********************************************************************/

WERROR libnetapi_open_pipe(struct libnetapi_ctx *ctx,
			   const char *server_name,
			   const struct ndr_interface_table *table,
			   struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result = NULL;
	NTSTATUS status;
	WERROR werr;
	struct client_ipc_connection *ipc = NULL;

	if (!presult) {
		return WERR_INVALID_PARAMETER;
	}

	werr = libnetapi_open_ipc_connection(ctx, server_name, &ipc);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	status = pipe_cm_open(ctx, ipc, table, &result);
	if (!NT_STATUS_IS_OK(status)) {
		libnetapi_set_error_string(ctx, "failed to open PIPE %s: %s",
			table->name,
			get_friendly_nt_error_msg(status));
		return WERR_NERR_DESTNOTFOUND;
	}

	*presult = result;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR libnetapi_get_binding_handle(struct libnetapi_ctx *ctx,
				    const char *server_name,
				    const struct ndr_interface_table *table,
				    struct dcerpc_binding_handle **binding_handle)
{
	struct rpc_pipe_client *pipe_cli;
	WERROR result;

	*binding_handle = NULL;

	result = libnetapi_open_pipe(ctx, server_name, table, &pipe_cli);
	if (!W_ERROR_IS_OK(result)) {
		return result;
	}

	*binding_handle = pipe_cli->binding_handle;

	return WERR_OK;
}
