/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Rafal Szczesniak 2005
   
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
  a composite functions for user management operations (add/del/chg)
*/

#include "includes.h"
#include "libcli/composite/composite.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "libnet/composite.h"
#include "libnet/userman.h"
#include "libnet/userinfo.h"

/*
 * Composite USER ADD functionality
 */

static void useradd_handler(struct rpc_request*);

enum useradd_stage { USERADD_CREATE };

struct useradd_state {
	enum useradd_stage       stage;
	struct dcerpc_pipe       *pipe;
	struct rpc_request       *req;
	struct policy_handle     domain_handle;
	struct samr_CreateUser   createuser;
	struct policy_handle     user_handle;
	uint32_t                 user_rid;

	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg *);
};


/**
 * Stage 1 (and the only one for now): Create user account.
 */
static NTSTATUS useradd_create(struct composite_context *c,
			       struct useradd_state *s)
{
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	
	c->state = COMPOSITE_STATE_DONE;
	return NT_STATUS_OK;
}


/**
 * Event handler for asynchronous request. Handles transition through
 * intermediate stages of the call.
 *
 * @param req rpc call context
 */
static void useradd_handler(struct rpc_request *req)
{
	struct composite_context *c = req->async.private;
	struct useradd_state *s = talloc_get_type(c->private_data, struct useradd_state);
	struct monitor_msg msg;
	struct msg_rpc_create_user *rpc_create;
	
	switch (s->stage) {
	case USERADD_CREATE:
		c->status = useradd_create(c, s);

		msg.type = rpc_create_user;
		rpc_create = talloc(s, struct msg_rpc_create_user);
		rpc_create->rid = *s->createuser.out.rid;
		msg.data = (void*)rpc_create;
		msg.data_size = sizeof(*rpc_create);
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}

	if (s->monitor_fn) {
		s->monitor_fn(&msg);
	}

	if (c->state >= COMPOSITE_STATE_DONE &&
	    c->async.fn) {
		c->async.fn(c);
	}
}


/**
 * Sends asynchronous useradd request
 *
 * @param p dce/rpc call pipe 
 * @param io arguments and results of the call
 */

struct composite_context *libnet_rpc_useradd_send(struct dcerpc_pipe *p,
						  struct libnet_rpc_useradd *io,
						  void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct useradd_state *s;
	
	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;
	
	s = talloc_zero(c, struct useradd_state);
	if (s == NULL) goto failure;
	
	s->domain_handle = io->in.domain_handle;
	s->pipe          = p;
	s->monitor_fn    = monitor;
	
	c->state        = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx    = dcerpc_event_context(p);

	/* preparing parameters to send rpc request */
	s->createuser.in.domain_handle         = &io->in.domain_handle;
	s->createuser.in.account_name          = talloc_zero(c, struct lsa_String);
	s->createuser.in.account_name->string  = talloc_strdup(c, io->in.username);
	s->createuser.out.user_handle          = &s->user_handle;
	s->createuser.out.rid                  = &s->user_rid;

	/* send request */
	s->req = dcerpc_samr_CreateUser_send(p, c, &s->createuser);

	/* callback handler */
	s->req->async.callback = useradd_handler;
	s->req->async.private  = c;
	s->stage = USERADD_CREATE;

	return c;
	
failure:
	talloc_free(c);
	return NULL;
}


/**
 * Waits for and receives result of asynchronous useradd call
 * 
 * @param c composite context returned by asynchronous useradd call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_rpc_useradd_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				 struct libnet_rpc_useradd *io)
{
	NTSTATUS status;
	struct useradd_state *s;
	
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status) && io) {
		/* get and return result of the call */
		s = talloc_get_type(c->private_data, struct useradd_state);
		io->out.user_handle = s->user_handle;
	}

	talloc_free(c);
	return status;
}


/**
 * Synchronous version of useradd call
 *
 * @param pipe dce/rpc call pipe
 * @param mem_ctx memory context for the call
 * @param io arguments and results of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_rpc_useradd(struct dcerpc_pipe *pipe,
			    TALLOC_CTX *mem_ctx,
			    struct libnet_rpc_useradd *io)
{
	struct composite_context *c = libnet_rpc_useradd_send(pipe, io, NULL);
	return libnet_rpc_useradd_recv(c, mem_ctx, io);
}



/*
 * Composite USER DELETE functionality
 */

static void userdel_handler(struct rpc_request*);

enum userdel_stage { USERDEL_LOOKUP, USERDEL_OPEN, USERDEL_DELETE };

struct userdel_state {
	enum userdel_stage        stage;
	struct dcerpc_pipe        *pipe;
	struct rpc_request        *req;
	struct policy_handle      domain_handle;
	struct policy_handle      user_handle;
	struct samr_LookupNames   lookupname;
	struct samr_OpenUser      openuser;
	struct samr_DeleteUser    deleteuser;

	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg *);
};


/**
 * Stage 1: Lookup the user name and resolve it to rid
 */
static NTSTATUS userdel_lookup(struct composite_context *c,
			       struct userdel_state *s)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	
	if (!s->lookupname.out.rids.count) {
		/* TODO: no such user */
		status = NT_STATUS_NO_SUCH_USER;

	} else if (!s->lookupname.out.rids.count > 1) {
		/* TODO: ambiguous username */
		status = NT_STATUS_INVALID_ACCOUNT_NAME;
	}
	
	s->openuser.in.domain_handle = &s->domain_handle;
	s->openuser.in.rid           = s->lookupname.out.rids.ids[0];
	s->openuser.in.access_mask   = SEC_FLAG_MAXIMUM_ALLOWED;
	s->openuser.out.user_handle  = &s->user_handle;

	s->req = dcerpc_samr_OpenUser_send(s->pipe, c, &s->openuser);
	
	s->req->async.callback = userdel_handler;
	s->req->async.private  = c;
	s->stage = USERDEL_OPEN;
	
	return NT_STATUS_OK;
}


/**
 * Stage 2: Open user account.
 */
static NTSTATUS userdel_open(struct composite_context *c,
			     struct userdel_state *s)
{
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	
	s->deleteuser.in.user_handle   = &s->user_handle;
	s->deleteuser.out.user_handle  = &s->user_handle;
	
	s->req = dcerpc_samr_DeleteUser_send(s->pipe, c, &s->deleteuser);
	
	s->req->async.callback = userdel_handler;
	s->req->async.private  = c;
	s->stage = USERDEL_DELETE;
	
	return NT_STATUS_OK;
}


/**
 * Stage 3: Delete user account
 */
static NTSTATUS userdel_delete(struct composite_context *c,
			       struct userdel_state *s)
{
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	
	c->state = COMPOSITE_STATE_DONE;

	return NT_STATUS_OK;
}


/**
 * Event handler for asynchronous request. Handles transition through
 * intermediate stages of the call.
 *
 * @param req rpc call context
 */
static void userdel_handler(struct rpc_request *req)
{
	struct composite_context *c = req->async.private;
	struct userdel_state *s = talloc_get_type(c->private_data, struct userdel_state);
	struct monitor_msg msg;
	struct msg_rpc_lookup_name *msg_lookup;
	struct msg_rpc_open_user *msg_open;
	
	switch (s->stage) {
	case USERDEL_LOOKUP:
		c->status = userdel_lookup(c, s);

		msg.type = rpc_lookup_name;
		msg_lookup = talloc(s, struct msg_rpc_lookup_name);

		msg_lookup->rid   = s->lookupname.out.rids.ids;
		msg_lookup->count = s->lookupname.out.rids.count;
		msg.data = (void*)msg_lookup;
		msg.data_size = sizeof(*msg_lookup);
		break;

	case USERDEL_OPEN:
		c->status = userdel_open(c, s);

		msg.type = rpc_open_user;
		msg_open = talloc(s, struct msg_rpc_open_user);

		msg_open->rid         = s->openuser.in.rid;
		msg_open->access_mask = s->openuser.in.rid;
		msg.data = (void*)msg_open;
		msg.data_size = sizeof(*msg_open);
		break;

	case USERDEL_DELETE:
		c->status = userdel_delete(c, s);
		
		msg.type = rpc_delete_user;
		msg.data = NULL;
		msg.data_size = 0;
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}

	if (s->monitor_fn) {
		s->monitor_fn(&msg);
	}

	if (c->state >= COMPOSITE_STATE_DONE &&
	    c->async.fn) {
		c->async.fn(c);
	}
}


/**
 * Sends asynchronous userdel request
 *
 * @param p dce/rpc call pipe
 * @param io arguments and results of the call
 */

struct composite_context *libnet_rpc_userdel_send(struct dcerpc_pipe *p,
						  struct libnet_rpc_userdel *io)
{
	struct composite_context *c;
	struct userdel_state *s;
	
	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;

	s = talloc_zero(c, struct userdel_state);
	if (s == NULL) goto failure;

	c->state         = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data  = s;
	c->event_ctx     = dcerpc_event_context(p);

	s->pipe          = p;
	s->domain_handle = io->in.domain_handle;
	
	/* preparing parameters to send rpc request */
	s->lookupname.in.domain_handle = &io->in.domain_handle;
	s->lookupname.in.num_names     = 1;
	s->lookupname.in.names         = talloc_zero(s, struct lsa_String);
	s->lookupname.in.names->string = io->in.username;

	/* send the request */
	s->req = dcerpc_samr_LookupNames_send(p, c, &s->lookupname);

	/* callback handler */
	s->req->async.callback = userdel_handler;
	s->req->async.private  = c;
	s->stage = USERDEL_LOOKUP;

	return c;

failure:
	talloc_free(c);
	return NULL;
}


/**
 * Waits for and receives results of asynchronous userdel call
 *
 * @param c composite context returned by asynchronous userdel call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_rpc_userdel_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				 struct libnet_rpc_userdel *io)
{
	NTSTATUS status;
	struct userdel_state *s;
	
	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status) && io) {
		s  = talloc_get_type(c->private_data, struct userdel_state);
		io->out.user_handle = s->user_handle;
	}

	talloc_free(c);
	return status;
}


/**
 * Synchronous version of userdel call
 *
 * @param pipe dce/rpc call pipe
 * @param mem_ctx memory context for the call
 * @param io arguments and results of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_rpc_userdel(struct dcerpc_pipe *pipe,
			    TALLOC_CTX *mem_ctx,
			    struct libnet_rpc_userdel *io)
{
	struct composite_context *c = libnet_rpc_userdel_send(pipe, io);
	return libnet_rpc_userdel_recv(c, mem_ctx, io);
}


/*
 * USER MODIFY functionality
 */

static void usermod_handler(struct rpc_request*);

enum usermod_stage { USERMOD_LOOKUP, USERMOD_OPEN, USERMOD_QUERY, USERMOD_MODIFY };

struct usermod_state {
	enum usermod_stage         stage;
	struct dcerpc_pipe         *pipe;
	struct rpc_request         *req;
	struct policy_handle       domain_handle;
	struct policy_handle       user_handle;
	struct usermod_change      change;
	union  samr_UserInfo       info;
	struct samr_LookupNames    lookupname;
	struct samr_OpenUser       openuser;
	struct samr_SetUserInfo    setuser;
	struct samr_QueryUserInfo  queryuser;

	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg *);
};


/**
 * Step 1: Lookup user name
 */
static NTSTATUS usermod_lookup(struct composite_context *c,
			       struct usermod_state *s)
{
	NTSTATUS status;

	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	if (!s->lookupname.out.rids.count) {
		/* TODO: no such user */
		status = NT_STATUS_NO_SUCH_USER;

	} else if (!s->lookupname.out.rids.count > 1) {
		/* TODO: ambiguous username */
		status = NT_STATUS_INVALID_ACCOUNT_NAME;
	}

	s->openuser.in.domain_handle = &s->domain_handle;
	s->openuser.in.rid           = s->lookupname.out.rids.ids[0];
	s->openuser.in.access_mask   = SEC_FLAG_MAXIMUM_ALLOWED;
	s->openuser.out.user_handle  = &s->user_handle;

	s->req = dcerpc_samr_OpenUser_send(s->pipe, c, &s->openuser);

	s->req->async.callback = usermod_handler;
	s->req->async.private  = c;
	s->stage = USERMOD_OPEN;
	
	return NT_STATUS_OK;
}


static uint32_t usermod_setfields(struct usermod_state *s, uint16_t *level,
				  union samr_UserInfo *i)
{
	if (s->change.fields) {
		if (s->change.fields & USERMOD_FIELD_ACCOUNT_NAME) {
			*level = 7;
			i->info7.account_name.string = s->change.account_name;

			s->change.fields ^= USERMOD_FIELD_ACCOUNT_NAME;

		} else if (s->change.fields & USERMOD_FIELD_FULL_NAME) {
			*level = 8;
			i->info8.full_name.string = s->change.full_name;
			
			s->change.fields ^= USERMOD_FIELD_FULL_NAME;

		} else if (s->change.fields & USERMOD_FIELD_DESCRIPTION) {
			*level = 13;
			i->info13.description.string = s->change.description;
			
			s->change.fields ^= USERMOD_FIELD_DESCRIPTION;

		} else if (s->change.fields & USERMOD_FIELD_COMMENT) {
			*level = 2;

			if (s->stage == USERMOD_QUERY) {
				/* the user info is obtained, so now set the required field */
				i->info2.comment.string = s->change.comment;
				s->change.fields ^= USERMOD_FIELD_COMMENT;

			} else {
				/* we need to query the user info before setting one field in it */
				s->stage = USERMOD_QUERY;
				return s->change.fields;
			}

		} else if (s->change.fields & USERMOD_FIELD_ALLOW_PASS_CHG) {
			*level = 3;
			
			if (s->stage == USERMOD_QUERY) {
				i->info3.allow_password_change = timeval_to_nttime(s->change.allow_password_change);
				s->change.fields ^= USERMOD_FIELD_ALLOW_PASS_CHG;

			} else {
				s->stage = USERMOD_QUERY;
				return s->change.fields;
			}

		} else if (s->change.fields & USERMOD_FIELD_FORCE_PASS_CHG) {
			*level = 3;

			if (s->stage == USERMOD_QUERY) {
				i->info3.force_password_change = timeval_to_nttime(s->change.force_password_change);
				s->change.fields ^= USERMOD_FIELD_FORCE_PASS_CHG;

			} else {
				s->stage = USERMOD_QUERY;
				return s->change.fields;
			}

		} else if (s->change.fields & USERMOD_FIELD_LOGON_SCRIPT) {
			*level = 11;
			i->info11.logon_script.string = s->change.logon_script;
			
			s->change.fields ^= USERMOD_FIELD_LOGON_SCRIPT;

		} else if (s->change.fields & USERMOD_FIELD_PROFILE_PATH) {
			*level = 12;
			i->info12.profile_path.string = s->change.profile_path;

			s->change.fields ^= USERMOD_FIELD_PROFILE_PATH;

		} else if (s->change.fields & USERMOD_FIELD_ACCT_EXPIRY) {
			*level = 17;
			i->info17.acct_expiry = timeval_to_nttime(s->change.acct_expiry);

			s->change.fields ^= USERMOD_FIELD_ACCT_EXPIRY;

		} else if (s->change.fields & USERMOD_FIELD_ACCT_FLAGS) {
			*level = 16;
			i->info16.acct_flags = s->change.acct_flags;

			s->change.fields ^= USERMOD_FIELD_ACCT_FLAGS;
		}
	}

	/* We're going to be back here again soon unless all fields have been set */
	if (s->change.fields) {
		s->stage = USERMOD_OPEN;
	} else {
		s->stage = USERMOD_MODIFY;
	}

	return s->change.fields;
}


/**
 * Stage 2: Open user account
 */
static NTSTATUS usermod_open(struct composite_context *c,
			     struct usermod_state *s)
{
	union samr_UserInfo *i = &s->info;
	uint16_t level;

	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	/* Prepare UserInfo level and data based on bitmask field */
	s->change.fields = usermod_setfields(s, &level, i);

	if (s->stage == USERMOD_QUERY) {
		s->queryuser.in.user_handle = &s->user_handle;
		s->queryuser.in.level       = level;

		s->req = dcerpc_samr_QueryUserInfo_send(s->pipe, c, &s->queryuser);

	} else {
		s->setuser.in.user_handle  = &s->user_handle;
		s->setuser.in.level        = level;
		s->setuser.in.info         = i;

		s->req = dcerpc_samr_SetUserInfo_send(s->pipe, c, &s->setuser);
	}

	s->req->async.callback = usermod_handler;
	s->req->async.private  = c;

	return NT_STATUS_OK;
}


/**
 * Stage 2a (optional): Query the user information
 */
static NTSTATUS usermod_query(struct composite_context *c,
			      struct usermod_state *s)
{
	union samr_UserInfo *i = &s->info;
	uint16_t level;

	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	s->info = *s->queryuser.out.info;

	s->change.fields = usermod_setfields(s, &level, i);

	s->setuser.in.user_handle  = &s->user_handle;
	s->setuser.in.level        = level;
	s->setuser.in.info         = i;
	
	s->req = dcerpc_samr_SetUserInfo_send(s->pipe, c, &s->setuser);

	s->req->async.callback = usermod_handler;
	s->req->async.private  = c;

	return NT_STATUS_OK;
}


/**
 * Stage 3: Set new user account data
 */
static NTSTATUS usermod_modify(struct composite_context *c,
			       struct usermod_state *s)
{
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	c->state = COMPOSITE_STATE_DONE;

	return NT_STATUS_OK;
}


/**
 * Event handler for asynchronous request. Handles transition through
 * intermediate stages of the call.
 *
 * @param req rpc call context
 */

static void usermod_handler(struct rpc_request *req)
{
	struct composite_context *c = req->async.private;
	struct usermod_state *s = talloc_get_type(c->private_data, struct usermod_state);
	struct monitor_msg msg;
	struct msg_rpc_lookup_name *msg_lookup;
	struct msg_rpc_open_user *msg_open;

	switch (s->stage) {
	case USERMOD_LOOKUP:
		c->status = usermod_lookup(c, s);

		msg.type = rpc_lookup_name;
		msg_lookup = talloc(s, struct msg_rpc_lookup_name);

		msg_lookup->rid   = s->lookupname.out.rids.ids;
		msg_lookup->count = s->lookupname.out.rids.count;
		msg.data = (void*)msg_lookup;
		msg.data_size = sizeof(*msg_lookup);
		break;

	case USERMOD_OPEN:
		c->status = usermod_open(c, s);

		msg.type = rpc_open_user;
		msg_open = talloc(s, struct msg_rpc_open_user);

		msg_open->rid         = s->openuser.in.rid;
		msg_open->access_mask = s->openuser.in.rid;
		msg.data = (void*)msg_open;
		msg.data_size = sizeof(*msg_open);
		break;

	case USERMOD_QUERY:
		c->status = usermod_query(c, s);

		msg.type = rpc_query_user;
		msg.data = NULL;
		msg.data_size = 0;
		break;

	case USERMOD_MODIFY:
		c->status = usermod_modify(c, s);

		msg.type = rpc_set_user;
		msg.data = NULL;
		msg.data_size = 0;
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}

	if (s->monitor_fn) {
		s->monitor_fn(&msg);
	}

	if (c->state >= COMPOSITE_STATE_DONE &&
	    c->async.fn) {
		c->async.fn(c);
	}
}


/**
 * Sends asynchronous usermod request
 *
 * @param p dce/rpc call pipe
 * @param io arguments and results of the call
 */

struct composite_context *libnet_rpc_usermod_send(struct dcerpc_pipe *p,
						  struct libnet_rpc_usermod *io)
{
	struct composite_context *c;
	struct usermod_state *s;
	
	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;

	s = talloc_zero(c, struct usermod_state);
	if (s == NULL) goto failure;

	c->state        = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx    = dcerpc_event_context(p);

	s->pipe          = p;
	s->domain_handle = io->in.domain_handle;
	s->change        = io->in.change;
	
	s->lookupname.in.domain_handle = &io->in.domain_handle;
	s->lookupname.in.num_names     = 1;
	s->lookupname.in.names         = talloc_zero(s, struct lsa_String);
	s->lookupname.in.names->string = io->in.username;
	
	s->req = dcerpc_samr_LookupNames_send(p, c, &s->lookupname);
	
	s->req->async.callback = usermod_handler;
	s->req->async.private  = c;
	s->stage = USERMOD_LOOKUP;

	return c;

failure:
	talloc_free(c);
	return NULL;
}


/**
 * Waits for and receives results of asynchronous usermod call
 *
 * @param c composite context returned by asynchronous usermod call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_rpc_usermod_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				 struct libnet_rpc_usermod *io)
{
	NTSTATUS status;
	
	status = composite_wait(c);

	talloc_free(c);
	return status;
}


/**
 * Synchronous version of usermod call
 *
 * @param pipe dce/rpc call pipe
 * @param mem_ctx memory context for the call
 * @param io arguments and results of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_rpc_usermod(struct dcerpc_pipe *pipe,
			    TALLOC_CTX *mem_ctx,
			    struct libnet_rpc_usermod *io)
{
	struct composite_context *c = libnet_rpc_usermod_send(pipe, io);
	return libnet_rpc_usermod_recv(c, mem_ctx, io);
}
