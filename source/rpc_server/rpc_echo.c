/* 
   Unix SMB/CIFS implementation.

   endpoint server for the echo pipe

   Copyright (C) Andrew Tridgell 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"



/**************************************************************************
  all the code below this point is boilerplate that will be auto-generated
***************************************************************************/


/*
  return True if we want to handle the given endpoint
*/
static BOOL op_query(const struct dcesrv_endpoint *ep)
{
	return dcesrv_table_query(&dcerpc_table_rpcecho, ep);
}


/* op_connect is called when a connection is made to an endpoint */
static NTSTATUS op_connect(struct dcesrv_state *dce)
{
	return NT_STATUS_OK;
}

static void op_disconnect(struct dcesrv_state *dce)
{
	/* nothing to do */
}


static const struct dcesrv_endpoint_ops rpc_echo_ops = {
	op_query,
	op_connect,
	op_disconnect
};

/*
  register with the dcerpc server
*/
void rpc_echo_init(struct server_context *smb)
{
	if (!dcesrv_endpoint_register(smb, &rpc_echo_ops)) {
		DEBUG(1,("Failed to register rpcecho endpoint\n"));
	}
}
