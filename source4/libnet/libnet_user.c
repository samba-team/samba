/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Rafal Szczesniak <mimir@samba.org> 2005
   
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
#include "libnet/libnet.h"
#include "libnet/composite.h"


NTSTATUS libnet_CreateUser(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_CreateUser *r)
{
	NTSTATUS status;
	struct libnet_RpcConnect cn;
	struct libnet_Lookup fp;
	struct libnet_rpc_domain_open dom_io;
	struct libnet_rpc_useradd user_io;
	const char *address;
	
	address = talloc_array(mem_ctx, const char, 8);

	/* find domain pdc */
	fp.in.hostname    = r->in.domain_name;
	fp.in.methods     = NULL;
	fp.out.address    = &address;

	status = libnet_LookupPdc(ctx, mem_ctx, &fp);
	if (!NT_STATUS_IS_OK(status)) return status;

	/* connect rpc service of remote server */
	cn.level                      = LIBNET_RPC_CONNECT_PDC;
	cn.in.domain_name             = talloc_strdup(mem_ctx, *fp.out.address);
	cn.in.dcerpc_iface_name       = DCERPC_SAMR_NAME;
	cn.in.dcerpc_iface_uuid       = DCERPC_SAMR_UUID;
	cn.in.dcerpc_iface_version    = DCERPC_SAMR_VERSION;

	status = libnet_RpcConnect(ctx, mem_ctx, &cn);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "Connection to SAMR pipe domain '%s' PDC failed: %s\n",
						      r->in.domain_name, nt_errstr(status));
		return status;
	}

	ctx->pipe = cn.out.dcerpc_pipe;

	/* open connected domain */
	dom_io.in.domain_name   = r->in.domain_name;
	dom_io.in.access_mask   = SEC_FLAG_MAXIMUM_ALLOWED;
	
	status = libnet_rpc_domain_open(ctx->pipe, mem_ctx, &dom_io);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "Creating user account failed: %s\n",
						      nt_errstr(status));
		return status;
	}

	ctx->domain_handle = dom_io.out.domain_handle;

	/* create user */
	user_io.in.username       = r->in.user_name;
	user_io.in.domain_handle  = dom_io.out.domain_handle;

	status = libnet_rpc_useradd(ctx->pipe, mem_ctx, &user_io);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "Creating user account failed: %s\n",
						      nt_errstr(status));
		return status;
	}

	ctx->user_handle = user_io.out.user_handle;

	return status;
}
