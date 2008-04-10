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
	cli_cm_set_use_kerberos();

	if (ctx->password) {
		cli_cm_set_password(ctx->password);
	}
	if (ctx->username) {
		cli_cm_set_username(ctx->username);
	}

	if (ctx->username && ctx->username[0] &&
	    ctx->password && ctx->password[0]) {
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
