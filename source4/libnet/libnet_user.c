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
#include "librpc/gen_ndr/samr.h"
#include "librpc/gen_ndr/ndr_samr.h"


/**
 * Verify, before actually doing anything with user accounts, whether
 * required domain is already opened and thus ready for operation.
 * If it is not, or if the opened domain is not the one requested, open
 * the requested domain.
 */
static struct composite_context* domain_opened(struct libnet_context *ctx,
					       const char *domain_name,
					       struct composite_context *parent_ctx,
					       struct libnet_DomainOpen *domain_open,
					       void (*continue_fn)(struct composite_context*),
					       void (*monitor)(struct monitor_msg*))
{
	struct composite_context *domopen_req;

	if (domain_name == NULL) {
		/*
		 * Try to guess the domain name from credentials,
		 * if it's not been explicitly specified.
		 */

		if (policy_handle_empty(&ctx->samr.handle)) {
			domain_open->in.domain_name = cli_credentials_get_domain(ctx->cred);
			domain_open->in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;

		} else {
			composite_error(parent_ctx, NT_STATUS_INVALID_PARAMETER);
			return parent_ctx;
		}

	} else {
		/*
		 * The domain name has been specified, so check whether the same
		 * domain is already opened. If it is - just return NULL. Start
		 * opening a new domain otherwise.
		 */

		if (policy_handle_empty(&ctx->samr.handle) ||
		    !strequal(domain_name, ctx->samr.name)) {
			domain_open->in.domain_name = domain_name;
			domain_open->in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;			

		} else {
			/* domain has already been opened and it's the same domain
			   as requested */
			return NULL;
		}
	}

	/* send request to open the domain */
	domopen_req = libnet_DomainOpen_send(ctx, domain_open, monitor);
	if (composite_nomem(domopen_req, parent_ctx)) return parent_ctx;
	
	composite_continue(parent_ctx, domopen_req, continue_fn, parent_ctx);
	return parent_ctx;
}


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


/**
 * Sends request to create user account
 *
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r pointer to a structure containing arguments and results of this call
 * @param monitor function pointer for receiving monitor messages
 * @return compostite context of this request
 */
struct composite_context* libnet_CreateUser_send(struct libnet_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 struct libnet_CreateUser *r,
						 void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct create_user_state *s;
	struct composite_context *create_req;
	struct composite_context *prereq_ctx;

	/* composite context allocation and setup */
	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct create_user_state);
	if (composite_nomem(s, c)) return c;

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = ctx->event_ctx;

	/* store arguments in the state structure */
	s->ctx = ctx;
	s->r   = *r;
	ZERO_STRUCT(s->r.out);

	/* prerequisite: make sure the domain is opened */
	prereq_ctx = domain_opened(ctx, s->r.in.domain_name, c, &s->domain_open,
				   continue_domain_open_create, monitor);
	if (prereq_ctx) return prereq_ctx;

	/* prepare arguments for useradd call */
	s->user_add.in.username       = r->in.user_name;
	s->user_add.in.domain_handle  = ctx->samr.handle;

	/* send the request */
	create_req = libnet_rpc_useradd_send(ctx->samr.pipe, &s->user_add, monitor);
	if (composite_nomem(create_req, c)) return c;

	/* set the next stage */
	composite_continue(c, create_req, continue_rpc_useradd, c);
	return c;
}


/*
 * Stage 0.5 (optional): receive result of domain open request
 * and send useradd request
 */
static void continue_domain_open_create(struct composite_context *ctx)
{
	struct composite_context *c;
	struct create_user_state *s;
	struct composite_context *create_req;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct create_user_state);

	/* receive result of DomainOpen call */
	c->status = libnet_DomainOpen_recv(ctx, s->ctx, c, &s->domain_open);
	if (!composite_is_ok(c)) return;

	/* send monitor message */
	if (s->monitor_fn) s->monitor_fn(&msg);
	
	/* prepare arguments for useradd call */
	s->user_add.in.username       = s->r.in.user_name;
	s->user_add.in.domain_handle  = s->ctx->samr.handle;

	/* send the request */
	create_req = libnet_rpc_useradd_send(s->ctx->samr.pipe, &s->user_add, s->monitor_fn);
	if (composite_nomem(create_req, c)) return;

	/* set the next stage */
	composite_continue(c, create_req, continue_rpc_useradd, c);
}


/*
 * Stage 1: receive result of useradd call
 */
static void continue_rpc_useradd(struct composite_context *ctx)
{
	struct composite_context *c;
	struct create_user_state *s;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct create_user_state);
	
	/* receive result of the call */
	c->status = libnet_rpc_useradd_recv(ctx, c, &s->user_add);
	if (!composite_is_ok(c)) return;

	/* send monitor message */
	if (s->monitor_fn) s->monitor_fn(&msg);

	/* we're done */
	composite_done(c);
}


/**
 * Receive result of CreateUser call
 *
 * @param c composite context returned by send request routine
 * @param mem_ctx memory context of this call
 * @param r pointer to a structure containing arguments and result of this call
 * @return nt status
 */
NTSTATUS libnet_CreateUser_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				struct libnet_CreateUser *r)
{
	NTSTATUS status;
	struct create_user_state *s;

	r->out.error_string = NULL;

	/* wait for result of async request and check status code */
	status = composite_wait(c);
	if (!NT_STATUS_IS_OK(status)) {
		s = talloc_get_type(c->private_data, struct create_user_state);
		r->out.error_string = talloc_strdup(mem_ctx, nt_errstr(status));
	}

	return status;
}


/**
 * Synchronous version of CreateUser call
 *
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r pointer to a structure containing arguments and result of this call
 * @return nt status
 */
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


/**
 * Sends request to delete user account
 *
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r pointer to structure containing arguments and result of this call
 * @param monitor function pointer for receiving monitor messages
 */
struct composite_context *libnet_DeleteUser_send(struct libnet_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 struct libnet_DeleteUser *r,
						 void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct delete_user_state *s;
	struct composite_context *delete_req;
	struct composite_context *prereq_ctx;

	/* composite context allocation and setup */
	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct delete_user_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;
	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->event_ctx = ctx->event_ctx;

	/* store arguments in state structure */
	s->ctx = ctx;
	s->r   = *r;
	ZERO_STRUCT(s->r.out);
	
	/* prerequisite: make sure the domain is opened before proceeding */
	prereq_ctx = domain_opened(ctx, s->r.in.domain_name, c, &s->domain_open,
				   continue_domain_open_delete, monitor);
	if (prereq_ctx) return prereq_ctx;

	/* prepare arguments for userdel call */
	s->user_del.in.username       = r->in.user_name;
	s->user_del.in.domain_handle  = ctx->samr.handle;

	/* send request */
	delete_req = libnet_rpc_userdel_send(ctx->samr.pipe, &s->user_del, monitor);
	if (composite_nomem(delete_req, c)) return c;
	
	/* set the next stage */
	composite_continue(c, delete_req, continue_rpc_userdel, c);
	return c;
}


/*
 * Stage 0.5 (optional): receive result of domain open request
 * and send useradd request
 */
static void continue_domain_open_delete(struct composite_context *ctx)
{
	struct composite_context *c;
	struct delete_user_state *s;
	struct composite_context *delete_req;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct delete_user_state);

	/* receive result of DomainOpen call */
	c->status = libnet_DomainOpen_recv(ctx, s->ctx, c, &s->domain_open);
	if (!composite_is_ok(c)) return;
	
	/* send monitor message */
	if (s->monitor_fn) s->monitor_fn(&msg);

	/* prepare arguments for userdel call */
	s->user_del.in.username       = s->r.in.user_name;
	s->user_del.in.domain_handle  = s->ctx->samr.handle;

	/* send request */
	delete_req = libnet_rpc_userdel_send(s->ctx->samr.pipe, &s->user_del, s->monitor_fn);
	if (composite_nomem(delete_req, c)) return;

	/* set the next stage */
	composite_continue(c, delete_req, continue_rpc_userdel, c);
}


static void continue_rpc_userdel(struct composite_context *ctx)
{
	struct composite_context *c;
	struct delete_user_state *s;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct delete_user_state);

	/* receive result of userdel call */
	c->status = libnet_rpc_userdel_recv(ctx, c, &s->user_del);
	if (!composite_is_ok(c)) return;

	/* send monitor message */
	if (s->monitor_fn) s->monitor_fn(&msg);

	/* we're done */
	composite_done(c);
}


/**
 * Receives result of asynchronous DeleteUser call
 *
 * @param c composite context returned by async DeleteUser call
 * @param mem_ctx memory context of this call
 * @param r pointer to structure containing arguments and result
 */
NTSTATUS libnet_DeleteUser_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				struct libnet_DeleteUser *r)
{
	NTSTATUS status;
	struct delete_user_state *s;

	r->out.error_string = NULL;

	/* wait for result of async request and check status code */
	status = composite_wait(c);
	if (!NT_STATUS_IS_OK(status)) {
		s = talloc_get_type(c->private_data, struct delete_user_state);
		r->out.error_string = talloc_steal(mem_ctx, s->r.out.error_string);
	}
	
	return status;
}


/**
 * Synchronous version of DeleteUser call
 *
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r pointer to structure containing arguments and result
 */
NTSTATUS libnet_DeleteUser(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			   struct libnet_DeleteUser *r)
{
	struct composite_context *c;
	
	c = libnet_DeleteUser_send(ctx, mem_ctx, r, NULL);
	return libnet_DeleteUser_recv(c, mem_ctx, r);
}


struct modify_user_state {
	struct libnet_ModifyUser r;
	struct libnet_context *ctx;
	struct libnet_DomainOpen domain_open;
	struct libnet_rpc_userinfo user_info;
	struct libnet_rpc_usermod user_mod;

	void (*monitor_fn)(struct monitor_msg *);
};


static void continue_rpc_usermod(struct composite_context *ctx);
static void continue_domain_open_modify(struct composite_context *ctx);
static NTSTATUS set_user_changes(TALLOC_CTX *mem_ctx, struct usermod_change *mod,
				 struct libnet_rpc_userinfo *info, struct libnet_ModifyUser *r);
static void continue_rpc_userinfo(struct composite_context *ctx);


struct composite_context *libnet_ModifyUser_send(struct libnet_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 struct libnet_ModifyUser *r,
						 void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct modify_user_state *s;
	struct composite_context *prereq_ctx;
	struct composite_context *userinfo_req;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct modify_user_state);
	if (composite_nomem(s, c)) return c;

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = ctx->event_ctx;

	s->ctx = ctx;
	s->r = *r;

	prereq_ctx = domain_opened(ctx, s->r.in.domain_name, c, &s->domain_open,
				   continue_domain_open_modify, monitor);
	if (prereq_ctx) return prereq_ctx;

	s->user_mod.in.username      = r->in.user_name;
	s->user_mod.in.domain_handle = ctx->samr.handle;

	userinfo_req = libnet_rpc_userinfo_send(ctx->samr.pipe, &s->user_info, monitor);
	if (composite_nomem(userinfo_req, c)) return c;

	composite_continue(c, userinfo_req, continue_rpc_userinfo, c);
	return c;
}


static void continue_domain_open_modify(struct composite_context *ctx)
{
	const uint16_t level = 21;
	struct composite_context *c;
	struct modify_user_state *s;
	struct composite_context *userinfo_req;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct modify_user_state);

	c->status = libnet_DomainOpen_recv(ctx, s->ctx, c, &s->domain_open);
	if (!composite_is_ok(c)) return;

	if (s->monitor_fn) s->monitor_fn(&msg);
	
	s->user_info.in.domain_handle  = s->ctx->samr.handle;
	s->user_info.in.username       = s->r.in.user_name;
	s->user_info.in.level          = level;

	userinfo_req = libnet_rpc_userinfo_send(s->ctx->samr.pipe, &s->user_info, s->monitor_fn);
	if (composite_nomem(userinfo_req, c)) return;
	
	composite_continue(c, userinfo_req, continue_rpc_userinfo, c);
}


static void continue_rpc_userinfo(struct composite_context *ctx)
{
	struct composite_context *c;
	struct modify_user_state *s;
	struct composite_context *usermod_req;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct modify_user_state);

	c->status = libnet_rpc_userinfo_recv(ctx, c, &s->user_info);
	if (!composite_is_ok(c)) return;

	s->user_mod.in.domain_handle = s->ctx->samr.handle;
	s->user_mod.in.username      = s->r.in.user_name;

	c->status = set_user_changes(c, &s->user_mod.in.change, &s->user_info, &s->r);

	usermod_req = libnet_rpc_usermod_send(s->ctx->samr.pipe, &s->user_mod, s->monitor_fn);
	if (composite_nomem(usermod_req, c)) return;

	composite_continue(c, usermod_req, continue_rpc_usermod, c);
}


static NTSTATUS set_user_changes(TALLOC_CTX *mem_ctx, struct usermod_change *mod,
				 struct libnet_rpc_userinfo *info, struct libnet_ModifyUser *r)
{
	struct samr_UserInfo21 *user;

	if (mod == NULL || info == NULL || r == NULL || info->in.level != 21) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	user = &info->out.info.info21;
	mod->fields = 0;        /* reset flag field before setting individual flags */

	/* account name change */
	SET_FIELD_LSA_STRING(r->in, user, mod, account_name, USERMOD_FIELD_ACCOUNT_NAME);

	/* full name change */
	SET_FIELD_LSA_STRING(r->in, user, mod, full_name, USERMOD_FIELD_FULL_NAME);

	/* description change */
	SET_FIELD_LSA_STRING(r->in, user, mod, comment, USERMOD_FIELD_DESCRIPTION);

	/* comment change */
	SET_FIELD_LSA_STRING(r->in, user, mod, comment, USERMOD_FIELD_COMMENT);

	/* home directory change */
	SET_FIELD_LSA_STRING(r->in, user, mod, home_directory, USERMOD_FIELD_HOME_DIRECTORY);

	/* home drive change */
	SET_FIELD_LSA_STRING(r->in, user, mod, home_drive, USERMOD_FIELD_HOME_DRIVE);

	/* logon script change */
	SET_FIELD_LSA_STRING(r->in, user, mod, logon_script, USERMOD_FIELD_LOGON_SCRIPT);

	/* profile path change */
	SET_FIELD_LSA_STRING(r->in, user, mod, profile_path, USERMOD_FIELD_PROFILE_PATH);

	/* allow password change time */
	SET_FIELD_NTTIME(r->in, user, mod, allow_password_change, USERMOD_FIELD_ALLOW_PASS_CHG);

	/* force password change time */
	SET_FIELD_NTTIME(r->in, user, mod, force_password_change, USERMOD_FIELD_FORCE_PASS_CHG);

	/* account expiry change */
	SET_FIELD_NTTIME(r->in, user, mod, acct_expiry, USERMOD_FIELD_ACCT_EXPIRY);

	return NT_STATUS_OK;
}


static void continue_rpc_usermod(struct composite_context *ctx)
{
	struct composite_context *c;
	struct modify_user_state *s;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct modify_user_state);
	
	c->status = libnet_rpc_usermod_recv(ctx, c, &s->user_mod);
	if (!composite_is_ok(c)) return;
	
	if (s->monitor_fn) s->monitor_fn(&msg);
	composite_done(c);
}


NTSTATUS libnet_ModifyUser_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				struct libnet_ModifyUser *r)
{
	NTSTATUS status = composite_wait(c);
	return status;
}


NTSTATUS libnet_ModifyUser(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			   struct libnet_ModifyUser *r)
{
	struct composite_context *c;

	c = libnet_ModifyUser_send(ctx, mem_ctx, r, NULL);
	return libnet_ModifyUser_recv(c, mem_ctx, r);
}
