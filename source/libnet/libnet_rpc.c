/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher  2004
   Copyright (C) Rafal Szczesniak   2005
   
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
#include "libcli/libcli.h"

/**
 * Connects rpc pipe on remote server
 * 
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r data structure containing necessary parameters and return values
 * @return nt status of the call
 **/

static NTSTATUS libnet_RpcConnectSrv(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_RpcConnect *r)
{
	NTSTATUS status;
	const char *binding = NULL;

	/* prepare binding string */
	switch (r->level) {
	case LIBNET_RPC_CONNECT_DC:
	case LIBNET_RPC_CONNECT_PDC:
	case LIBNET_RPC_CONNECT_SERVER:
		binding = talloc_asprintf(mem_ctx, "ncacn_np:%s", r->in.name);
		break;

	case LIBNET_RPC_CONNECT_BINDING:
		binding = r->in.binding;
		break;
	}

	/* connect to remote dcerpc pipe */
	status = dcerpc_pipe_connect(mem_ctx, &r->out.dcerpc_pipe,
				     binding, r->in.dcerpc_iface,
				     ctx->cred, ctx->event_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "dcerpc_pipe_connect to pipe %s[%s] failed with %s\n",
						      r->in.dcerpc_iface->name, binding, nt_errstr(status));
		return status;
	}

	r->out.error_string = NULL;
	ctx->pipe = r->out.dcerpc_pipe;

	return status;
}


/**
 * Connects rpc pipe on domain pdc
 * 
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r data structure containing necessary parameters and return values
 * @return nt status of the call
 **/

static NTSTATUS libnet_RpcConnectPdc(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_RpcConnect *r)
{
	NTSTATUS status;
	struct libnet_RpcConnect r2;
	struct libnet_LookupDCs f;
	const char *connect_name;

	f.in.domain_name  = r->in.name;
	switch (r->level) {
	case LIBNET_RPC_CONNECT_PDC:
		f.in.name_type = NBT_NAME_PDC;
		break;
	case LIBNET_RPC_CONNECT_DC:
		f.in.name_type = NBT_NAME_LOGON;
		break;
	default:
		break;
	}
	f.out.num_dcs = 0;
	f.out.dcs  = NULL;

	/* find the domain pdc first */
	status = libnet_LookupDCs(ctx, mem_ctx, &f);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx, "libnet_LookupDCs failed: %s",
						      nt_errstr(status));
		return status;
	}

	/* we might not have got back a name.  Fall back to the IP */
	if (f.out.dcs[0].name) {
		connect_name = f.out.dcs[0].name;
	} else {
		connect_name = f.out.dcs[0].address;
	}

	/* ok, pdc has been found so do attempt to rpc connect */
	r2.level	    = LIBNET_RPC_CONNECT_SERVER;

	/* This will cause yet another name resolution, but at least
	 * we pass the right name down the stack now */
	r2.in.name	    = talloc_strdup(mem_ctx, connect_name);
	r2.in.dcerpc_iface  = r->in.dcerpc_iface;
	
	status = libnet_RpcConnect(ctx, mem_ctx, &r2);

	r->out.dcerpc_pipe          = r2.out.dcerpc_pipe;
	r->out.error_string	    = r2.out.error_string;

	ctx->pipe = r->out.dcerpc_pipe;

	return status;
}


/**
 * Connects to rpc pipe on remote server or pdc
 * 
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r data structure containing necessary parameters and return values
 * @return nt status of the call
 **/

NTSTATUS libnet_RpcConnect(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_RpcConnect *r)
{
	switch (r->level) {
		case LIBNET_RPC_CONNECT_SERVER:
			return libnet_RpcConnectSrv(ctx, mem_ctx, r);

		case LIBNET_RPC_CONNECT_BINDING:
			return libnet_RpcConnectSrv(ctx, mem_ctx, r);

		case LIBNET_RPC_CONNECT_PDC:
		case LIBNET_RPC_CONNECT_DC:
			return libnet_RpcConnectPdc(ctx, mem_ctx, r);
	}

	return NT_STATUS_INVALID_LEVEL;
}
