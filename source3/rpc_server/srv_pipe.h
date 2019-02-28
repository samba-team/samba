/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Almost completely rewritten by (C) Jeremy Allison 2005 - 2010
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

#ifndef _RPC_SERVER_SRV_PIPE_H_
#define _RPC_SERVER_SRV_PIPE_H_

struct dcesrv_context;
struct dcesrv_endpoint;

/* The following definitions come from rpc_server/srv_pipe.c  */

NTSTATUS is_known_pipename(struct dcesrv_context *dce_ctx,
			   const char *pipename,
			   struct dcesrv_endpoint **ep);

#endif /* _RPC_SERVER_SRV_PIPE_H_ */
