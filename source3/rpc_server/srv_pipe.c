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

/*  this module apparently provides an implementation of DCE/RPC over a
 *  named pipe (IPC$ connection using SMBtrans).  details of DCE/RPC
 *  documentation are available (in on-line form) from the X-Open group.
 *
 *  this module should provide a level of abstraction between SMB
 *  and DCE/RPC, while minimising the amount of mallocs, unnecessary
 *  data copies, and network traffic.
 *
 */

#include "includes.h"
#include "rpc_server.h"
#include "rpc_server/srv_pipe.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/**
 * Is a named pipe known?
 * @param[in] dce_ctx		The rpc server context
 * @param[in] pipename		Just the filename
 * @param[out] endpoint		The DCERPC endpoint serving the pipe name
 * @result			NT error code
 */
NTSTATUS is_known_pipename(struct dcesrv_context *dce_ctx,
			   const char *pipename,
			   struct dcesrv_endpoint **ep)
{
	NTSTATUS status;

	if (strchr(pipename, '/')) {
		DBG_WARNING("Refusing open on pipe %s\n", pipename);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (lp_disable_spoolss() && strequal(pipename, "spoolss")) {
		DBG_DEBUG("refusing spoolss access\n");
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	status = dcesrv_endpoint_by_ncacn_np_name(dce_ctx, pipename, ep);
	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}

	status = smb_probe_module("rpc", pipename);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Unknown pipe '%s'\n", pipename);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	DBG_DEBUG("'%s' loaded dynamically\n", pipename);

	/*
	 * Scan the list again for the interface id
	 */
	status = dcesrv_endpoint_by_ncacn_np_name(dce_ctx, pipename, ep);
	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}

	DBG_DEBUG("pipe %s did not register itself!\n", pipename);

	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}
