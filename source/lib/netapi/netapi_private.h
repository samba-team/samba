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

#ifndef __LIB_NETAPI_PRIVATE_H__
#define __LIB_NETAPI_PRIVATE_H__

NET_API_STATUS libnetapi_get_password(struct libnetapi_ctx *ctx, char **password);
NET_API_STATUS libnetapi_get_username(struct libnetapi_ctx *ctx, char **username);
NET_API_STATUS libnetapi_set_error_string(struct libnetapi_ctx *ctx, const char *format, ...);
NET_API_STATUS libnetapi_get_debuglevel(struct libnetapi_ctx *ctx, char **debuglevel);

WERROR libnetapi_open_ipc_connection(struct libnetapi_ctx *ctx,
				     const char *server_name,
				     struct cli_state **cli);
WERROR libnetapi_shutdown_cm(struct libnetapi_ctx *ctx);
WERROR libnetapi_open_pipe(struct libnetapi_ctx *ctx,
			   struct cli_state *cli,
			   int pipe_idx,
			   struct rpc_pipe_client **pipe_cli);
#endif
