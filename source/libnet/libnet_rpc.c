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
#include "libcli/composite/composite.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"


struct rpc_connect_srv_state {
	struct libnet_RpcConnect r;
	const char *binding;
};


static void continue_pipe_connect(struct composite_context *ctx);


/**
 * Initiates connection to rpc pipe on remote server
 * 
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r data structure containing necessary parameters and return values
 * @return nt status of the call
 **/

static struct composite_context* libnet_RpcConnectSrv_send(struct libnet_context *ctx,
							   TALLOC_CTX *mem_ctx,
							   struct libnet_RpcConnect *r)
{
	struct composite_context *c;	
	struct rpc_connect_srv_state *s;
	struct composite_context *pipe_connect_req;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct rpc_connect_srv_state);
	if (composite_nomem(s, c)) return c;

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = ctx->event_ctx;

	s->r = *r;

	/* prepare binding string */
	switch (r->level) {
	case LIBNET_RPC_CONNECT_DC:
	case LIBNET_RPC_CONNECT_PDC:
	case LIBNET_RPC_CONNECT_SERVER:
		s->binding = talloc_asprintf(s, "ncacn_np:%s", r->in.name);
		break;

	case LIBNET_RPC_CONNECT_BINDING:
		s->binding = talloc_strdup(s, r->in.binding);
		break;
	}

	/* connect to remote dcerpc pipe */
	pipe_connect_req = dcerpc_pipe_connect_send(c, &s->r.out.dcerpc_pipe,
						    s->binding, r->in.dcerpc_iface,
						    ctx->cred, c->event_ctx);
	if (composite_nomem(pipe_connect_req, c)) return c;

	composite_continue(c, pipe_connect_req, continue_pipe_connect, c);
	return c;
}


static void continue_pipe_connect(struct composite_context *ctx)
{
	struct composite_context *c;
	struct rpc_connect_srv_state *s;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct rpc_connect_srv_state);

	c->status = dcerpc_pipe_connect_recv(ctx, c, &s->r.out.dcerpc_pipe);
	if (!composite_is_ok(c)) return;

	s->r.out.error_string = NULL;
	composite_done(c);
}


/**
 * Receives result of connection to rpc pipe on remote server
 *
 * @param c composite context
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r data structure containing necessary parameters and return values
 * @return nt status of rpc connection
 **/

static NTSTATUS libnet_RpcConnectSrv_recv(struct composite_context *c,
					  struct libnet_context *ctx,
					  TALLOC_CTX *mem_ctx,
					  struct libnet_RpcConnect *r)
{
	struct rpc_connect_srv_state *s;
	NTSTATUS status = composite_wait(c);

	if (NT_STATUS_IS_OK(status) && ctx && mem_ctx && r) {
		s = talloc_get_type(c->private_data, struct rpc_connect_srv_state);
		r->out.dcerpc_pipe = talloc_steal(mem_ctx, s->r.out.dcerpc_pipe);
		ctx->pipe = r->out.dcerpc_pipe;
	}

	talloc_free(c);
	return status;
}


static NTSTATUS libnet_RpcConnectSrv(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
				     struct libnet_RpcConnect *r)
{
	struct composite_context *c;

	c = libnet_RpcConnectSrv_send(ctx, mem_ctx, r);
	return libnet_RpcConnectSrv_recv(c, ctx, mem_ctx, r);
}


struct rpc_connect_dc_state {
	struct libnet_context *ctx;
	struct libnet_RpcConnect r;
	struct libnet_RpcConnect r2;
	struct libnet_LookupDCs f;
	const char *connect_name;
};


static void continue_lookup_dc(struct composite_context *ctx);
static void continue_rpc_connect(struct composite_context *ctx);


/**
 * Initiates connection to rpc pipe on domain pdc
 * 
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r data structure containing necessary parameters and return values
 * @return composite context of this call
 **/

static struct composite_context* libnet_RpcConnectDC_send(struct libnet_context *ctx,
							  TALLOC_CTX *mem_ctx,
							  struct libnet_RpcConnect *r)
{
	struct composite_context *c;
	struct rpc_connect_dc_state *s;
	struct composite_context *lookup_dc_req;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct rpc_connect_dc_state);
	if (composite_nomem(s, c)) return c;

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = ctx->event_ctx;

	s->r   = *r;
	s->ctx = ctx;

	switch (r->level) {
	case LIBNET_RPC_CONNECT_PDC:
		s->f.in.name_type = NBT_NAME_PDC;
		break;

	case LIBNET_RPC_CONNECT_DC:
		s->f.in.name_type = NBT_NAME_LOGON;
		break;

	default:
		break;
	}
	s->f.in.domain_name = r->in.name;
	s->f.out.num_dcs    = 0;
	s->f.out.dcs        = NULL;

	/* find the domain pdc first */
	lookup_dc_req = libnet_LookupDCs_send(ctx, c, &s->f);
	if (composite_nomem(lookup_dc_req, c)) return c;

	composite_continue(c, lookup_dc_req, continue_lookup_dc, c);
	return c;
}


static void continue_lookup_dc(struct composite_context *ctx)
{
	struct composite_context *c;
	struct rpc_connect_dc_state *s;
	struct composite_context *rpc_connect_req;
	
	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct rpc_connect_dc_state);
	
	c->status = libnet_LookupDCs_recv(ctx, c, &s->f);
	if (!composite_is_ok(c)) return;

	/* we might not have got back a name.  Fall back to the IP */
	if (s->f.out.dcs[0].name) {
		s->connect_name = s->f.out.dcs[0].name;
	} else {
		s->connect_name = s->f.out.dcs[0].address;
	}

	/* ok, pdc has been found so do attempt to rpc connect */
	s->r2.level	       = LIBNET_RPC_CONNECT_SERVER;

	/* this will cause yet another name resolution, but at least
	 * we pass the right name down the stack now */
	s->r2.in.name          = talloc_strdup(c, s->connect_name);
	s->r2.in.dcerpc_iface  = s->r.in.dcerpc_iface;	

	rpc_connect_req = libnet_RpcConnect_send(s->ctx, c, &s->r2);
	if (composite_nomem(rpc_connect_req, c)) return;

	composite_continue(c, rpc_connect_req, continue_rpc_connect, c);
}


static void continue_rpc_connect(struct composite_context *ctx)
{
	struct composite_context *c;
	struct rpc_connect_dc_state *s;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct rpc_connect_dc_state);

	c->status = libnet_RpcConnect_recv(ctx, s->ctx, c, &s->r2);

	/* error string is to be passed anyway */
	s->r.out.error_string  = s->r2.out.error_string;
	if (!composite_is_ok(c)) return;

	s->r.out.dcerpc_pipe = s->r2.out.dcerpc_pipe;

	composite_done(c);
}


/**
 * Receives result of connection to rpc pipe on domain pdc
 *
 * @param c composite context
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r data structure containing necessary parameters and return values
 * @return nt status of rpc connection
 **/

static NTSTATUS libnet_RpcConnectDC_recv(struct composite_context *c,
					 struct libnet_context *ctx,
					 TALLOC_CTX *mem_ctx,
					 struct libnet_RpcConnect *r)
{
	NTSTATUS status;
	struct rpc_connect_dc_state *s;
	
	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status) && ctx && mem_ctx && r) {
		s = talloc_get_type(c->private_data, struct rpc_connect_dc_state);
		r->out.dcerpc_pipe = talloc_steal(mem_ctx, s->r.out.dcerpc_pipe);
		ctx->pipe = r->out.dcerpc_pipe;
	}

	talloc_free(c);
	return status;
}



/**
 * Initiates connection to rpc pipe on remote server or pdc
 * 
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r data structure containing necessary parameters and return values
 * @return composite context of this call
 **/

struct composite_context* libnet_RpcConnect_send(struct libnet_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 struct libnet_RpcConnect *r)
{
	struct composite_context *c;

	switch (r->level) {
	case LIBNET_RPC_CONNECT_SERVER:
		c = libnet_RpcConnectSrv_send(ctx, mem_ctx, r);
		break;

	case LIBNET_RPC_CONNECT_BINDING:
		c = libnet_RpcConnectSrv_send(ctx, mem_ctx, r);
		break;
			
	case LIBNET_RPC_CONNECT_PDC:
	case LIBNET_RPC_CONNECT_DC:
		c = libnet_RpcConnectDC_send(ctx, mem_ctx, r);
		break;

	default:
		c = talloc_zero(mem_ctx, struct composite_context);
		composite_error(c, NT_STATUS_INVALID_LEVEL);
	}

	return c;
}


/**
 * Receives result of connection to rpc pipe on remote server or pdc
 *
 * @param c composite context
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r data structure containing necessary parameters and return values
 * @return nt status of rpc connection
 **/

NTSTATUS libnet_RpcConnect_recv(struct composite_context *c, struct libnet_context *ctx,
				TALLOC_CTX *mem_ctx, struct libnet_RpcConnect *r)
{
	switch (r->level) {
	case LIBNET_RPC_CONNECT_SERVER:
	case LIBNET_RPC_CONNECT_BINDING:
		return libnet_RpcConnectSrv_recv(c, ctx, mem_ctx, r);

	case LIBNET_RPC_CONNECT_PDC:
	case LIBNET_RPC_CONNECT_DC:
		return libnet_RpcConnectDC_recv(c, ctx, mem_ctx, r);

	default:
		return NT_STATUS_INVALID_LEVEL;
	}
}


NTSTATUS libnet_RpcConnect(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			   struct libnet_RpcConnect *r)
{
	struct composite_context *c;
	
	c = libnet_RpcConnect_send(ctx, mem_ctx, r);
	return libnet_RpcConnect_recv(c, ctx, mem_ctx, r);
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

