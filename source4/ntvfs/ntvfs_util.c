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
#include "ntvfs/ntvfs.h"


_PUBLIC_ struct ntvfs_request *ntvfs_request_create(struct ntvfs_context *ctx, TALLOC_CTX *mem_ctx,
						    struct auth_session_info *session_info,
						    uint16_t smbpid, uint16_t smbmid,
						    struct timeval request_time,
						    void *private_data,
						    void (*send_fn)(struct ntvfs_request *),
						    uint32_t state)
{
	struct ntvfs_request *req;
	struct ntvfs_async_state *async;

	req = talloc(mem_ctx, struct ntvfs_request);
	if (!req) return NULL;
	req->ctx			= ctx;
	req->async_states		= NULL;
	req->session_info		= session_info;
	req->smbpid			= smbpid;
	req->smbmid			= smbmid;
	req->statistics.request_time	= request_time;

	async = talloc(req, struct ntvfs_async_state);
	if (!async) goto failed;

	async->state		= state;
	async->private_data	= private_data;
	async->send_fn		= send_fn;
	async->status		= NT_STATUS_INTERNAL_ERROR;
	async->ntvfs		= NULL;

	DLIST_ADD(req->async_states, async);

	return req;

failed:
	return NULL;
}

_PUBLIC_ NTSTATUS ntvfs_async_state_push(struct ntvfs_module_context *ntvfs,
					 struct ntvfs_request *req,
					 void *private_data,
					 void (*send_fn)(struct ntvfs_request *))
{
	struct ntvfs_async_state *async;

	async = talloc(req, struct ntvfs_async_state);
	NT_STATUS_HAVE_NO_MEMORY(async);

	async->state		= req->async_states->state;
	async->private_data	= private_data;
	async->send_fn		= send_fn;
	async->status		= NT_STATUS_INTERNAL_ERROR;

	async->ntvfs		= ntvfs;

	DLIST_ADD(req->async_states, async);

	return NT_STATUS_OK;
}

_PUBLIC_ void ntvfs_async_state_pop(struct ntvfs_request *req)
{
	struct ntvfs_async_state *async;

	async = req->async_states;

	DLIST_REMOVE(req->async_states, async);

	req->async_states->state	= async->state;
	req->async_states->status	= async->status;

	talloc_free(async);
}
