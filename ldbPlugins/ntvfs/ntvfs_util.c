/* 
   Unix SMB/CIFS implementation.
   NTVFS utility code
   Copyright (C) Stefan Metzmacher 2004

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
/*
  this implements common utility functions that many NTVFS backends may wish to use
*/

#include "includes.h"
#include "dlinklist.h"
#include "smb_server/smb_server.h"


NTSTATUS ntvfs_async_state_push(struct smbsrv_request *req,
				void *private_data,
				void (*send_fn)(struct smbsrv_request *),
				struct ntvfs_module_context *ntvfs)
{
	struct ntvfs_async_state *async;

	async = talloc_p(req, struct ntvfs_async_state);
	if (!async) {
		return NT_STATUS_NO_MEMORY;
	}

	async->state		= req->async_states->state;
	async->private_data	= private_data;
	async->send_fn		= send_fn;
	async->status		= NT_STATUS_INTERNAL_ERROR;

	async->ntvfs		= ntvfs;

	DLIST_ADD(req->async_states, async);

	return NT_STATUS_OK;
}

void ntvfs_async_state_pop(struct smbsrv_request *req)
{
	struct ntvfs_async_state *async;

	async = req->async_states;

	DLIST_REMOVE(req->async_states, async);

	req->async_states->state	= async->state;
	req->async_states->status	= async->status;

	talloc_free(async);
}
