/* 
   Unix SMB/CIFS implementation.

   server side dcerpc defines

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Stefan (metze) Metzmacher 2004-2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SAMBA_DCERPC_SERVER_H
#define SAMBA_DCERPC_SERVER_H

#include "librpc/rpc/dcesrv_core.h"

struct model_ops;

NTSTATUS dcesrv_add_ep(struct dcesrv_context *dce_ctx,
		       struct loadparm_context *lp_ctx,
		       struct dcesrv_endpoint *e,
		       struct tevent_context *event_ctx,
		       const struct model_ops *model_ops,
		       void *process_context);

_PUBLIC_ struct imessaging_context *dcesrv_imessaging_context(
                                       struct dcesrv_connection *conn);
_PUBLIC_ struct server_id dcesrv_server_id(struct dcesrv_connection *conn);

#endif /* SAMBA_DCERPC_SERVER_H */
