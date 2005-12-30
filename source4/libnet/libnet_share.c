/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Grégory LEOCADIE <gleocadie@idealx.com>
   
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


NTSTATUS libnet_ListShares(struct libnet_context *ctx, 
			   TALLOC_CTX *mem_ctx, struct libnet_ListShares *r)
{
	NTSTATUS status;
	struct libnet_RpcConnect c;
	struct srvsvc_NetShareEnumAll s;
	uint32_t resume_handle;
	struct srvsvc_NetShareCtr0 ctr0;

	c.level                      = LIBNET_RPC_CONNECT_SERVER;
	c.in.domain_name             = r->in.server_name;
	c.in.dcerpc_iface       	 = &dcerpc_table_srvsvc;

	status = libnet_RpcConnect(ctx, mem_ctx, &c);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "Connection to SRVSVC pipe of server %s "
						      "failed: %s\n",
						      r->in.server_name,
						      nt_errstr(status));
		return status;
	}

	s.in.level = r->in.level;
	s.in.ctr.ctr0 = &ctr0;
	s.in.max_buffer = ~0;
	s.in.resume_handle = &resume_handle;

	ZERO_STRUCT(ctr0);

	status = dcerpc_srvsvc_NetShareEnumAll(c.out.dcerpc_pipe, mem_ctx, &s);
	
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "srvsvc_NetShareEnumAll on server '%s' failed"
						      ": %s\n",
						      r->in.server_name, nt_errstr(status));
		goto disconnect;
	}

	if (!W_ERROR_IS_OK(s.out.result) && !W_ERROR_EQUAL(s.out.result, WERR_MORE_DATA)) {
		goto disconnect;
	}

	r->out.ctr = s.out.ctr;

disconnect:
	talloc_free(c.out.dcerpc_pipe);

	return status;	
}


NTSTATUS libnet_AddShare(struct libnet_context *ctx,
			 TALLOC_CTX *mem_ctx, struct libnet_AddShare *r)
{
	NTSTATUS status;
	struct libnet_RpcConnect c;
	struct srvsvc_NetShareAdd s;

	c.level                     = LIBNET_RPC_CONNECT_SERVER;
	c.in.domain_name            = r->in.server_name;
	c.in.dcerpc_iface      		= &dcerpc_table_srvsvc;

	status = libnet_RpcConnect(ctx, mem_ctx, &c);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "Connection to SRVSVC pipe of server %s "
						      "failed: %s\n",
						      r->in.server_name, nt_errstr(status));
		return status;
	}

	s.in.level 		= r->in.level;
	s.in.info.info2 	= &r->in.share;
	s.in.server_unc		= talloc_asprintf(mem_ctx, "\\\\%s", r->in.server_name);
 
	status = dcerpc_srvsvc_NetShareAdd(c.out.dcerpc_pipe, mem_ctx,&s);	

	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "srvsvc_NetShareAdd on server '%s' failed"
						      ": %s\n",
						      r->in.server_name, nt_errstr(status));
	}

	talloc_free(c.out.dcerpc_pipe);
	
	return status;
}


NTSTATUS libnet_DelShare(struct libnet_context *ctx,
			 TALLOC_CTX *mem_ctx, struct libnet_DelShare *r)
{
	NTSTATUS status;
	struct libnet_RpcConnect c;
	struct srvsvc_NetShareDel s;

	c.level                      = LIBNET_RPC_CONNECT_SERVER;
	c.in.domain_name             = r->in.server_name;
	c.in.dcerpc_iface       	 = &dcerpc_table_srvsvc;

	status = libnet_RpcConnect(ctx, mem_ctx, &c);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "Connection to SRVSVC pipe of server %s "
						      "failed: %s\n",
						      r->in.server_name, nt_errstr(status));
		return status;
	} 
		
	s.in.server_unc = talloc_asprintf(mem_ctx, "\\\\%s", r->in.server_name);
	s.in.share_name = r->in.share_name;

	status = dcerpc_srvsvc_NetShareDel(c.out.dcerpc_pipe, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "srvsvc_NetShareDel on server '%s' failed"
						      ": %s\n",
						      r->in.server_name, nt_errstr(status));
	}

	talloc_free(c.out.dcerpc_pipe);

	return status;
}
