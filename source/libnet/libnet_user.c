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
#include "libcli/composite/composite.h"
#include "auth/credentials/credentials.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_samr.h"


struct create_user_state {
	struct libnet_CreateUser r;
	struct libnet_DomainOpen domain_open;
	struct libnet_rpc_useradd user_add;
	struct libnet_context *ctx;

	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg *);
};


static void continue_rpc_useradd(struct composite_context *ctx);
static void continue_domain_open_create(struct composite_context *ctx);


struct composite_context* libnet_CreateUser_send(struct libnet_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 struct libnet_CreateUser *r,
						 void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct create_user_state *s;
	struct composite_context *create_req;
	struct composite_context *domopen_req;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct create_user_state);
	if (composite_nomem(s, c)) return c;

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = ctx->event_ctx;

	s->ctx = ctx;
	s->r   = *r;
	ZERO_STRUCT(s->r.out);

	if (s->r.in.domain_name == NULL) {
		
		if (policy_handle_empty(&ctx->domain.handle)) {
			s->domain_open.in.domain_name = cli_credentials_get_domain(ctx->cred);
			s->domain_open.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
			
			domopen_req = libnet_DomainOpen_send(ctx, &s->domain_open, monitor);
			if (composite_nomem(domopen_req, c)) return c;
			
			composite_continue(c, domopen_req, continue_domain_open_create, c);
			return c;
		} else {
			/* no domain name provided - neither in io structure nor default
			   stored in libnet context - report an error */
			composite_error(c, NT_STATUS_INVALID_PARAMETER);
			return c;
		}

	} else {
		
		if (policy_handle_empty(&ctx->domain.handle) ||
		    !strequal(s->r.in.domain_name, ctx->domain.name)) {
			s->domain_open.in.domain_name = s->r.in.domain_name;
			s->domain_open.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;

			domopen_req = libnet_DomainOpen_send(ctx, &s->domain_open, monitor);
			if (composite_nomem(domopen_req, c)) return c;
			
			composite_continue(c, domopen_req, continue_domain_open_create, c);
			return c;
		}
	}
	
	s->user_add.in.username       = r->in.user_name;
	s->user_add.in.domain_handle  = ctx->domain.handle;

	create_req = libnet_rpc_useradd_send(ctx->samr_pipe, &s->user_add, monitor);
	if (composite_nomem(create_req, c)) return c;

	composite_continue(c, create_req, continue_rpc_useradd, c);
	return c;
}


static void continue_domain_open_create(struct composite_context *ctx)
{
	struct composite_context *c;
	struct create_user_state *s;
	struct composite_context *create_req;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct create_user_state);

	c->status = libnet_DomainOpen_recv(ctx, s->ctx, c, &s->domain_open);
	if (!composite_is_ok(c)) return;

	if (s->monitor_fn) s->monitor_fn(&msg);
	
	s->user_add.in.username       = s->r.in.user_name;
	s->user_add.in.domain_handle  = s->ctx->domain.handle;

	create_req = libnet_rpc_useradd_send(s->ctx->samr_pipe, &s->user_add, s->monitor_fn);
	if (composite_nomem(create_req, c)) return;
	
	composite_continue(c, create_req, continue_rpc_useradd, c);
}


static void continue_rpc_useradd(struct composite_context *ctx)
{
	struct composite_context *c;
	struct create_user_state *s;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct create_user_state);

	c->status = libnet_rpc_useradd_recv(ctx, c, &s->user_add);
	if (!composite_is_ok(c)) return;

	if (s->monitor_fn) s->monitor_fn(&msg);
	composite_done(c);
}


NTSTATUS libnet_CreateUser_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				struct libnet_CreateUser *r)
{
	NTSTATUS status;
	struct create_user_state *s;

	status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		r->out.error_string = NULL;
	} else {
		s = talloc_get_type(c->private_data, struct create_user_state);
		r->out.error_string = talloc_steal(mem_ctx, s->r.out.error_string);
	}

	return status;
}


NTSTATUS libnet_CreateUser(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			   struct libnet_CreateUser *r)
{
	struct composite_context *c;

	c = libnet_CreateUser_send(ctx, mem_ctx, r, NULL);
	return libnet_CreateUser_recv(c, mem_ctx, r);
}



struct delete_user_state {
	struct libnet_DeleteUser r;
	struct libnet_context *ctx;
	struct libnet_DomainOpen domain_open;
	struct libnet_rpc_userdel user_del;

	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg *);
};


static void continue_rpc_userdel(struct composite_context *ctx);
static void continue_domain_open_delete(struct composite_context *ctx);


struct composite_context *libnet_DeleteUser_send(struct libnet_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 struct libnet_DeleteUser *r,
						 void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct delete_user_state *s;
	struct composite_context *domopen_req;
	struct composite_context *delete_req;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct delete_user_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;
	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->event_ctx = ctx->event_ctx;

	s->ctx = ctx;
	s->r = *r;
	ZERO_STRUCT(s->r.out);
	
	if (s->r.in.domain_name == NULL) {
		
		if (policy_handle_empty(&ctx->domain.handle)) {
			s->domain_open.in.domain_name = cli_credentials_get_domain(ctx->cred);
			s->domain_open.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
			
			domopen_req = libnet_DomainOpen_send(ctx, &s->domain_open, monitor);
			if (composite_nomem(domopen_req, c)) return c;
			
			composite_continue(c, domopen_req, continue_domain_open_delete, c);
			return c;
		}

	} else {

		if (policy_handle_empty(&ctx->domain.handle) ||
		    !strequal(s->r.in.domain_name, ctx->domain.name)) {
			s->domain_open.in.domain_name = s->r.in.domain_name;
			s->domain_open.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
			
			domopen_req = libnet_DomainOpen_send(ctx, &s->domain_open, monitor);
			if (composite_nomem(domopen_req, c)) return c;

			composite_continue(c, domopen_req, continue_domain_open_delete, c);
			return c;
		}
	}

	s->user_del.in.username       = r->in.user_name;
	s->user_del.in.domain_handle  = ctx->domain.handle;
	
	delete_req = libnet_rpc_userdel_send(ctx->samr_pipe, &s->user_del, monitor);
	if (composite_nomem(delete_req, c)) return c;
	
	composite_continue(c, delete_req, continue_rpc_userdel, c);
	return c;
}


static void continue_domain_open_delete(struct composite_context *ctx)
{
	struct composite_context *c;
	struct delete_user_state *s;
	struct composite_context *delete_req;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct delete_user_state);

	c->status = libnet_DomainOpen_recv(ctx, s->ctx, c, &s->domain_open);
	if (!composite_is_ok(c)) return;

	if (s->monitor_fn) s->monitor_fn(&msg);
	
	s->user_del.in.username       = s->r.in.user_name;
	s->user_del.in.domain_handle  = s->ctx->domain.handle;

	delete_req = libnet_rpc_userdel_send(s->ctx->samr_pipe, &s->user_del, s->monitor_fn);
	if (composite_nomem(delete_req, c)) return;
	
	composite_continue(c, delete_req, continue_rpc_userdel, c);
}


static void continue_rpc_userdel(struct composite_context *ctx)
{
	struct composite_context *c;
	struct delete_user_state *s;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct delete_user_state);

	c->status = libnet_rpc_userdel_recv(ctx, c, &s->user_del);
	if (!composite_is_ok(c)) return;

	if (s->monitor_fn) s->monitor_fn(&msg);
	composite_done(c);
}


NTSTATUS libnet_DeleteUser_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				struct libnet_DeleteUser *r)
{
	NTSTATUS status;
	struct delete_user_state *s;

	status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		r->out.error_string = NULL;
	} else {
		s = talloc_get_type(c->private_data, struct delete_user_state);
		r->out.error_string = talloc_steal(mem_ctx, s->r.out.error_string);
	}
	
	return status;
}


NTSTATUS libnet_DeleteUser(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			   struct libnet_DeleteUser *r)
{
	struct composite_context *c;
	
	c = libnet_DeleteUser_send(ctx, mem_ctx, r, NULL);
	return libnet_DeleteUser_recv(c, mem_ctx, r);
}
