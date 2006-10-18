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


/*
 * Stage 1: receive result of userdel call and finish the composite function
 */
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


/**
 * Sends request to modify user account
 *
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r pointer to structure containing arguments and result of this call
 * @param monitor function pointer for receiving monitor messages
 */
struct composite_context *libnet_ModifyUser_send(struct libnet_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 struct libnet_ModifyUser *r,
						 void (*monitor)(struct monitor_msg*))
{
	const uint16_t level = 21;
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

	s->user_info.in.username      = r->in.user_name;
	s->user_info.in.domain_handle = ctx->samr.handle;
	s->user_info.in.level         = level;

	userinfo_req = libnet_rpc_userinfo_send(ctx->samr.pipe, &s->user_info, monitor);
	if (composite_nomem(userinfo_req, c)) return c;

	composite_continue(c, userinfo_req, continue_rpc_userinfo, c);
	return c;
}


/*
 * Stage 0.5 (optional): receive result of domain open request
 * and send userinfo request
 */
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


/*
 * Stage 1: receive result of userinfo call, prepare user changes
 * (set the fields a caller required to change) and send usermod request
 */
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


/*
 * Prepare user changes: compare userinfo result to requested changes and
 * set the field values and flags accordingly for user modify call
 */
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
	SET_FIELD_LSA_STRING(r->in, user, mod, description, USERMOD_FIELD_DESCRIPTION);

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

	/* account expiry change */
	SET_FIELD_NTTIME(r->in, user, mod, acct_expiry, USERMOD_FIELD_ACCT_EXPIRY);

	return NT_STATUS_OK;
}


/*
 * Stage 2: receive result of usermod request and finish the composite function
 */
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


/**
 * Receive result of ModifyUser call
 *
 * @param c composite context returned by send request routine
 * @param mem_ctx memory context of this call
 * @param r pointer to a structure containing arguments and result of this call
 * @return nt status
 */
NTSTATUS libnet_ModifyUser_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				struct libnet_ModifyUser *r)
{
	NTSTATUS status = composite_wait(c);
	return status;
}


/**
 * Synchronous version of ModifyUser call
 *
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r pointer to a structure containing arguments and result of this call
 * @return nt status
 */
NTSTATUS libnet_ModifyUser(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			   struct libnet_ModifyUser *r)
{
	struct composite_context *c;

	c = libnet_ModifyUser_send(ctx, mem_ctx, r, NULL);
	return libnet_ModifyUser_recv(c, mem_ctx, r);
}


struct user_info_state {
	struct libnet_context *ctx;
	const char *domain_name;
	const char *user_name;
	struct libnet_LookupName lookup;
	struct libnet_DomainOpen domopen;
	struct libnet_rpc_userinfo userinfo;

	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg *);
};


static void continue_name_found(struct composite_context *ctx);
static void continue_domain_open_info(struct composite_context *ctx);
static void continue_info_received(struct composite_context *ctx);


/**
 * Sends request to get user account information
 *
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r pointer to a structure containing arguments and results of this call
 * @param monitor function pointer for receiving monitor messages
 * @return compostite context of this request
 */
struct composite_context* libnet_UserInfo_send(struct libnet_context *ctx,
					       TALLOC_CTX *mem_ctx,
					       struct libnet_UserInfo *r,
					       void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct user_info_state *s;
	struct composite_context *prereq_ctx;
	struct composite_context *lookup_req;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, ctx->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct user_info_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;

	/* store arguments in the state structure */
	s->monitor_fn = monitor;
	s->ctx = ctx;
	s->domain_name = talloc_strdup(c, r->in.domain_name);
	s->user_name = talloc_strdup(c, r->in.user_name);

	/* prerequisite: make sure the domain is opened */
	prereq_ctx = domain_opened(ctx, s->domain_name, c, &s->domopen,
				   continue_domain_open_info, monitor);
	if (prereq_ctx) return prereq_ctx;

	/* prepare arguments for LookupName call */
	s->lookup.in.domain_name = s->domain_name;
	s->lookup.in.name        = s->user_name;

	/* send the request */
	lookup_req = libnet_LookupName_send(ctx, c, &s->lookup, s->monitor_fn);
	if (composite_nomem(lookup_req, c)) return c;

	/* set the next stage */
	composite_continue(c, lookup_req, continue_name_found, c);
	return c;
}


/*
 * Stage 0.5 (optional): receive result of domain open request
 * and send LookupName request
 */
static void continue_domain_open_info(struct composite_context *ctx)
{
	struct composite_context *c;
	struct user_info_state *s;
	struct composite_context *lookup_req;
	struct monitor_msg msg;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct user_info_state);

	/* receive result of DomainOpen call */
	c->status = libnet_DomainOpen_recv(ctx, s->ctx, c, &s->domopen);
	if (!composite_is_ok(c)) return;

	/* send monitor message */
	if (s->monitor_fn) s->monitor_fn(&msg);

	/* prepare arguments for LookupName call */
	s->lookup.in.domain_name = s->domain_name;
	s->lookup.in.name        = s->user_name;
	
	/* send the request */
	lookup_req = libnet_LookupName_send(s->ctx, c, &s->lookup, s->monitor_fn);
	if (composite_nomem(lookup_req, c)) return;

	/* set the next stage */
	composite_continue(c, lookup_req, continue_rpc_userinfo, c);
}


/*
 * Stage 1: receive the name (if found) and send userinfo request
 */
static void continue_name_found(struct composite_context *ctx)
{
	struct composite_context *c;
	struct user_info_state *s;
	struct composite_context *info_req;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct user_info_state);

	/* receive result of LookupName call */
	c->status = libnet_LookupName_recv(ctx, c, &s->lookup);
	if (!composite_is_ok(c)) return;

	/* we're only interested in user accounts this time */
	if (s->lookup.out.sid_type != SID_NAME_USER) {
		composite_error(c, NT_STATUS_NO_SUCH_USER);
		return;
	}

	/* prepare arguments for UserInfo call */
	s->userinfo.in.domain_handle = s->ctx->samr.handle;
	s->userinfo.in.sid = s->lookup.out.sidstr;
	s->userinfo.in.level = 21;

	/* send the request */
	info_req = libnet_rpc_userinfo_send(s->ctx->samr.pipe, &s->userinfo, s->monitor_fn);
	if (composite_nomem(info_req, c)) return;

	/* set the next stage */
	composite_continue(c, info_req, continue_info_received, c);
}


/*
 * Stage 2: receive user account information and finish the composite function
 */
static void continue_info_received(struct composite_context *ctx)
{
	struct composite_context *c;
	struct user_info_state *s;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct user_info_state);
	
	/* receive result of userinfo call */
	c->status = libnet_rpc_userinfo_recv(ctx, c, &s->userinfo);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/**
 * Receive result of UserInfo call
 *
 * @param c composite context returned by send request routine
 * @param mem_ctx memory context of this call
 * @param r pointer to a structure containing arguments and result of this call
 * @return nt status
 */
NTSTATUS libnet_UserInfo_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
			      struct libnet_UserInfo *r)
{
	NTSTATUS status;
	struct user_info_state *s;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status) && r != NULL) {
		struct samr_UserInfo21 *info;

		s = talloc_get_type(c->private_data, struct user_info_state);
		info = &s->userinfo.out.info.info21;

		/* string fields */
		r->out.account_name   = talloc_steal(mem_ctx, info->account_name.string);
		r->out.full_name      = talloc_steal(mem_ctx, info->full_name.string);
		r->out.description    = talloc_steal(mem_ctx, info->description.string);
		r->out.home_directory = talloc_steal(mem_ctx, info->home_directory.string);
		r->out.home_drive     = talloc_steal(mem_ctx, info->home_drive.string);
		r->out.comment        = talloc_steal(mem_ctx, info->comment.string);
		r->out.logon_script   = talloc_steal(mem_ctx, info->logon_script.string);
		r->out.profile_path   = talloc_steal(mem_ctx, info->profile_path.string);

		/* time fields (allocation) */
		r->out.acct_expiry           = talloc(mem_ctx, struct timeval);
		r->out.allow_password_change = talloc(mem_ctx, struct timeval);
		r->out.force_password_change = talloc(mem_ctx, struct timeval);
		r->out.last_logon            = talloc(mem_ctx, struct timeval);
		r->out.last_logoff           = talloc(mem_ctx, struct timeval);
		r->out.last_password_change  = talloc(mem_ctx, struct timeval);
		
		/* time fields (converting) */
		nttime_to_timeval(r->out.acct_expiry, info->acct_expiry);
		nttime_to_timeval(r->out.allow_password_change, info->allow_password_change);
		nttime_to_timeval(r->out.force_password_change, info->force_password_change);
		nttime_to_timeval(r->out.last_logon, info->last_logon);
		nttime_to_timeval(r->out.last_logoff, info->last_logoff);
		nttime_to_timeval(r->out.last_password_change, info->last_password_change);

		/* flag and number fields */
		r->out.acct_flags = info->acct_flags;

		r->out.error_string = talloc_strdup(mem_ctx, "Success");
	}

	talloc_free(c);
	
	return status;
}


/**
 * Synchronous version of UserInfo call
 *
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of this call
 * @param r pointer to a structure containing arguments and result of this call
 * @return nt status
 */
NTSTATUS libnet_UserInfo(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			 struct libnet_UserInfo *r)
{
	struct composite_context *c;
	
	c = libnet_UserInfo_send(ctx, mem_ctx, r, NULL);
	return libnet_UserInfo_recv(c, mem_ctx, r);
}
