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
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"

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

static NTSTATUS libnet_RpcConnectDC(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_RpcConnect *r)
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
			return libnet_RpcConnectDC(ctx, mem_ctx, r);
	}

	return NT_STATUS_INVALID_LEVEL;
}

/**
 * Connects to rpc pipe on remote server or pdc, and returns info on the domain name, domain sid and realm
 * 
 * @param ctx initialised libnet context
 * @param r data structure containing necessary parameters and return values.  Must be a talloc context
 * @return nt status of the call
 **/

NTSTATUS libnet_RpcConnectDCInfo(struct libnet_context *ctx, 
				 struct libnet_RpcConnectDCInfo *r)
{
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;

	struct libnet_RpcConnect *c;
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 lsa_open_policy;
	struct policy_handle lsa_p_handle;
	struct lsa_QueryInfoPolicy2 lsa_query_info2;
	struct lsa_QueryInfoPolicy lsa_query_info;

	struct dcerpc_pipe *lsa_pipe;

	struct dcerpc_binding *final_binding;
	struct dcerpc_pipe *final_pipe;

	tmp_ctx = talloc_new(r);
	if (!tmp_ctx) {
		r->out.error_string = NULL;
		return NT_STATUS_NO_MEMORY;
	}
	
	c = talloc(tmp_ctx, struct libnet_RpcConnect);
	if (!c) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	c->level              = r->level;

	if (r->level != LIBNET_RPC_CONNECT_BINDING) {
		c->in.name    = r->in.name;
	} else {
		c->in.binding = r->in.binding;
	}
	
	c->in.dcerpc_iface    = &dcerpc_table_lsarpc;
	
	/* connect to the LSA pipe of the PDC */

	status = libnet_RpcConnect(ctx, c, c);
	if (!NT_STATUS_IS_OK(status)) {
		if (r->level != LIBNET_RPC_CONNECT_BINDING) {
			r->out.error_string = talloc_asprintf(r,
							      "Connection to LSA pipe of DC failed: %s",
							      c->out.error_string);
		} else {
			r->out.error_string = talloc_asprintf(r,
							      "Connection to LSA pipe with binding '%s' failed: %s",
							      r->in.binding, c->out.error_string);
		}
		talloc_free(tmp_ctx);
		return status;
	}			
	lsa_pipe = c->out.dcerpc_pipe;
	
	/* Get an LSA policy handle */

	ZERO_STRUCT(lsa_p_handle);
	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	lsa_open_policy.in.attr = &attr;
	
	lsa_open_policy.in.system_name = talloc_asprintf(tmp_ctx, "\\"); 
	if (!lsa_open_policy.in.system_name) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	lsa_open_policy.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	lsa_open_policy.out.handle = &lsa_p_handle;

	status = dcerpc_lsa_OpenPolicy2(lsa_pipe, tmp_ctx, &lsa_open_policy); 

	/* This now fails on ncacn_ip_tcp against Win2k3 SP1 */
	if (NT_STATUS_IS_OK(status)) {
		/* Look to see if this is ADS (a fault indicates NT4 or Samba 3.0) */
		
		lsa_query_info2.in.handle = &lsa_p_handle;
		lsa_query_info2.in.level = LSA_POLICY_INFO_DNS;
		
		status = dcerpc_lsa_QueryInfoPolicy2(lsa_pipe, tmp_ctx, 		
						     &lsa_query_info2);
		
		if (!NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			if (!NT_STATUS_IS_OK(status)) {
				r->out.error_string = talloc_asprintf(r,
								      "lsa_QueryInfoPolicy2 failed: %s",
								      nt_errstr(status));
				talloc_free(tmp_ctx);
				return status;
			}
			r->out.realm = lsa_query_info2.out.info->dns.dns_domain.string;
			r->out.guid = talloc(r, struct GUID);
			if (!r->out.guid) {
				r->out.error_string = NULL;
				return NT_STATUS_NO_MEMORY;
			}
			*r->out.guid = lsa_query_info2.out.info->dns.domain_guid;
		} else {
			r->out.realm = NULL;
			r->out.guid = NULL;
		}
		
		/* Grab the domain SID (regardless of the result of the previous call */
		
		lsa_query_info.in.handle = &lsa_p_handle;
		lsa_query_info.in.level = LSA_POLICY_INFO_DOMAIN;
		
		status = dcerpc_lsa_QueryInfoPolicy(lsa_pipe, tmp_ctx, 
						    &lsa_query_info);
		
		if (!NT_STATUS_IS_OK(status)) {
			r->out.error_string = talloc_asprintf(r,
							      "lsa_QueryInfoPolicy2 failed: %s",
							      nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
		
		r->out.domain_sid = lsa_query_info.out.info->domain.sid;
		r->out.domain_name = lsa_query_info.out.info->domain.name.string;
	} else {
		/* Cause the code further down to try this with just SAMR */
		r->out.domain_sid = NULL;
		r->out.domain_name = NULL;
		r->out.realm = NULL;
	}

	/* Find the original binding string */
	final_binding = talloc(tmp_ctx, struct dcerpc_binding);
	if (!final_binding) {
		return NT_STATUS_NO_MEMORY;
	}
	*final_binding = *lsa_pipe->binding;
	/* Ensure we keep hold of the member elements */
	talloc_reference(final_binding, lsa_pipe->binding);

	/* Make binding string for samr, not the other pipe */
	status = dcerpc_epm_map_binding(tmp_ctx, final_binding, 					
					r->in.dcerpc_iface,
					lsa_pipe->conn->event_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(r,
						      "Failed to map pipe with endpoint mapper - %s",
						      nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	/* Now that we have the info setup a final connection to the pipe they wanted */
	status = dcerpc_secondary_connection(lsa_pipe, &final_pipe, final_binding);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(r,
						      "secondary connection failed: %s",
						      nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}
	r->out.dcerpc_pipe = final_pipe;

	talloc_steal(r, r->out.realm);
	talloc_steal(r, r->out.domain_sid);
	talloc_steal(r, r->out.domain_name);
	talloc_steal(r, r->out.dcerpc_pipe);

	/* This should close the LSA pipe, which we don't need now we have the info */
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

