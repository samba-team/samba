/* 
   ldb database library - ildap backend

   Copyright (C) Andrew Tridgell  2005
   Copyright (C) Simo Sorce       2006

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb_ildap
 *
 *  Component: ldb ildap backend
 *
 *  Description: This is a ldb backend for the internal ldap
 *  client library in Samba4. By using this backend we are
 *  independent of a system ldap library
 *
 *  Author: Andrew Tridgell
 *
 *  Modifications:
 *
 *  - description: make the module use asyncronous calls
 *    date: Feb 2006
 *    author: Simo Sorce
 */


#include "includes.h"
#include "ldb/include/includes.h"

#include "lib/events/events.h"
#include "libcli/ldap/ldap.h"
#include "libcli/ldap/ldap_client.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"

struct ildb_private {
	struct ldap_connection *ldap;
	struct ldb_context *ldb;
	struct ldb_module *module;
};

struct ildb_context {
	struct ldb_module *module;
	struct ildb_private *ildb;
	struct ldb_handle *handle;
	struct ldap_request *req;
	void *context;
	int (*callback)(struct ldb_context *, void *, struct ldb_reply *);
};

/*
  convert a ldb_message structure to a list of ldap_mod structures
  ready for ildap_add() or ildap_modify()
*/
static struct ldap_mod **ildb_msg_to_mods(void *mem_ctx, int *num_mods,
					  const struct ldb_message *msg, int use_flags)
{
	struct ldap_mod **mods;
	unsigned int i;
	int n = 0;

	/* allocate maximum number of elements needed */
	mods = talloc_array(mem_ctx, struct ldap_mod *, msg->num_elements+1);
	if (!mods) {
		errno = ENOMEM;
		return NULL;
	}
	mods[0] = NULL;

	for (i = 0; i < msg->num_elements; i++) {
		const struct ldb_message_element *el = &msg->elements[i];

		mods[n] = talloc(mods, struct ldap_mod);
		if (!mods[n]) {
			goto failed;
		}
		mods[n + 1] = NULL;
		mods[n]->type = 0;
		mods[n]->attrib = *el;
		if (use_flags) {
			switch (el->flags & LDB_FLAG_MOD_MASK) {
			case LDB_FLAG_MOD_ADD:
				mods[n]->type = LDAP_MODIFY_ADD;
				break;
			case LDB_FLAG_MOD_DELETE:
				mods[n]->type = LDAP_MODIFY_DELETE;
				break;
			case LDB_FLAG_MOD_REPLACE:
				mods[n]->type = LDAP_MODIFY_REPLACE;
				break;
			}
		}
		n++;
	}

	*num_mods = n;
	return mods;

failed:
	talloc_free(mods);
	return NULL;
}


/*
  map an ildap NTSTATUS to a ldb error code
*/
static int ildb_map_error(struct ildb_private *ildb, NTSTATUS status)
{
	if (NT_STATUS_IS_OK(status)) {
		return LDB_SUCCESS;
	}
	ldb_set_errstring(ildb->ldb, ldap_errstr(ildb->ldap, status));
	if (NT_STATUS_IS_LDAP(status)) {
		return NT_STATUS_LDAP_CODE(status);
	}
	return LDB_ERR_OPERATIONS_ERROR;
}

static void ildb_request_timeout(struct event_context *ev, struct timed_event *te,
				 struct timeval t, void *private_data)
{
	struct ildb_context *ac = talloc_get_type(private_data, struct ildb_context);
	struct ldb_handle *handle = ac->handle;

	if (ac->req->state == LDAP_REQUEST_PENDING) {
		DLIST_REMOVE(ac->req->conn->pending, ac->req);
	}

	handle->status = LDB_ERR_TIME_LIMIT_EXCEEDED;

	return;
}

static void ildb_callback(struct ldap_request *req)
{
	struct ildb_context *ac = talloc_get_type(req->async.private_data, struct ildb_context);
	struct ldb_handle *handle = ac->handle;
	struct ildb_private *ildb = ac->ildb;
	NTSTATUS status;
	int i;

	handle->status = LDB_SUCCESS;

	if (!NT_STATUS_IS_OK(req->status)) {
		handle->status = ildb_map_error(ildb, req->status);
		return;
	}

	if (req->num_replies < 1) {
		handle->status = LDB_ERR_OPERATIONS_ERROR;
		return;
	} 
		
	switch (req->type) {

	case LDAP_TAG_ModifyRequest:
		if (req->replies[0]->type != LDAP_TAG_ModifyResponse) {
			handle->status = LDB_ERR_PROTOCOL_ERROR;
			return;
		}
		status = ldap_check_response(req->conn, &req->replies[0]->r.GeneralResult);
		handle->status = ildb_map_error(ildb, status);
		if (ac->callback && handle->status == LDB_SUCCESS) {
			/* FIXME: build a corresponding ares to pass on */
			handle->status = ac->callback(ac->module->ldb, ac->context, NULL);
		}
		handle->state = LDB_ASYNC_DONE;
		break;

	case LDAP_TAG_AddRequest:
		if (req->replies[0]->type != LDAP_TAG_AddResponse) {
			handle->status = LDB_ERR_PROTOCOL_ERROR;
			return;
		}
		status = ldap_check_response(req->conn, &req->replies[0]->r.GeneralResult);
		handle->status = ildb_map_error(ildb, status);
		if (ac->callback && handle->status == LDB_SUCCESS) {
			/* FIXME: build a corresponding ares to pass on */
			handle->status = ac->callback(ac->module->ldb, ac->context, NULL);
		}
		handle->state = LDB_ASYNC_DONE;
		break;

	case LDAP_TAG_DelRequest:
		if (req->replies[0]->type != LDAP_TAG_DelResponse) {
			handle->status = LDB_ERR_PROTOCOL_ERROR;
			return;
		}
		status = ldap_check_response(req->conn, &req->replies[0]->r.GeneralResult);
		handle->status = ildb_map_error(ildb, status);
		if (ac->callback && handle->status == LDB_SUCCESS) {
			/* FIXME: build a corresponding ares to pass on */
			handle->status = ac->callback(ac->module->ldb, ac->context, NULL);
		}
		handle->state = LDB_ASYNC_DONE;
		break;

	case LDAP_TAG_ModifyDNRequest:
		if (req->replies[0]->type != LDAP_TAG_ModifyDNResponse) {
			handle->status = LDB_ERR_PROTOCOL_ERROR;
			return;
		}
		status = ldap_check_response(req->conn, &req->replies[0]->r.GeneralResult);
		handle->status = ildb_map_error(ildb, status);
		if (ac->callback && handle->status == LDB_SUCCESS) {
			/* FIXME: build a corresponding ares to pass on */
			handle->status = ac->callback(ac->module->ldb, ac->context, NULL);
		}
		handle->state = LDB_ASYNC_DONE;
		break;

	case LDAP_TAG_SearchRequest:
		/* loop over all messages */
		for (i = 0; i < req->num_replies; i++) {
			struct ldap_SearchResEntry *search;
			struct ldb_reply *ares = NULL;
			struct ldap_message *msg;
			int ret;

			ares = talloc_zero(ac, struct ldb_reply);
			if (!ares) {
				handle->status = LDB_ERR_OPERATIONS_ERROR;
				return;
			}

			msg = req->replies[i];
			switch (msg->type) {

			case LDAP_TAG_SearchResultDone:

				status = ldap_check_response(req->conn, &msg->r.GeneralResult);
				if (!NT_STATUS_IS_OK(status)) {
					handle->status = ildb_map_error(ildb, status);
					return;
				}
				
				ares->controls = talloc_move(ares, &msg->controls);
				if (msg->r.SearchResultDone.resultcode) {
					if (msg->r.SearchResultDone.errormessage) {
						ldb_set_errstring(ac->module->ldb, msg->r.SearchResultDone.errormessage);
					}
				}

				handle->status = msg->r.SearchResultDone.resultcode;
				handle->state = LDB_ASYNC_DONE;
				ares->type = LDB_REPLY_DONE;
				break;

			case LDAP_TAG_SearchResultEntry:


				ares->message = ldb_msg_new(ares);
				if (!ares->message) {
					handle->status = LDB_ERR_OPERATIONS_ERROR;
					return;
				}

				search = &(msg->r.SearchResultEntry);
		
				ares->message->dn = ldb_dn_new(ares->message, ac->module->ldb, search->dn);
				if ( ! ldb_dn_validate(ares->message->dn)) {
					handle->status = LDB_ERR_OPERATIONS_ERROR;
					return;
				}
				ares->message->num_elements = search->num_attributes;
				ares->message->elements = talloc_move(ares->message,
								      &search->attributes);

				handle->status = LDB_SUCCESS;
				handle->state = LDB_ASYNC_PENDING;
				ares->type = LDB_REPLY_ENTRY;
				break;

			case LDAP_TAG_SearchResultReference:

				ares->referral = talloc_strdup(ares, msg->r.SearchResultReference.referral);
				
				handle->status = LDB_SUCCESS;
				handle->state = LDB_ASYNC_PENDING;
				ares->type = LDB_REPLY_REFERRAL;
				break;

			default:
				/* TAG not handled, fail ! */
				handle->status = LDB_ERR_PROTOCOL_ERROR;
				return;
			}

			ret = ac->callback(ac->module->ldb, ac->context, ares);
			if (ret) {
				handle->status = ret;
			}
		}

		talloc_free(req->replies);
		req->replies = NULL;
		req->num_replies = 0;

		break;
		
	default:
		handle->status = LDB_ERR_PROTOCOL_ERROR;
		return;
	}
}

static struct ildb_context *init_ildb_handle(struct ildb_private *ildb,
					     struct ldb_request *req)
{
	struct ildb_context *ildb_ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(ildb->module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = ildb->module;

	ildb_ac = talloc(h, struct ildb_context);
	if (ildb_ac == NULL) {
		ldb_set_errstring(ildb->module->ldb, "Out of Memory");
		talloc_free(h);
		return NULL;
	}

	h->private_data = ildb_ac;

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ildb_ac->module = ildb->module;
	ildb_ac->ildb = ildb;
	ildb_ac->handle = h;
	ildb_ac->context = req->context;
	ildb_ac->callback = req->callback;

	req->handle = h;
	return ildb_ac;
}

static int ildb_request_send(struct ildb_private *ildb, struct ldap_message *msg, struct ldb_request *r)
{
	struct ildb_context *ildb_ac = init_ildb_handle(ildb, r);
	struct ldap_request *req;

	if (!ildb_ac) {
		return LDB_ERR_OPERATIONS_ERROR;		
	}

	req = ldap_request_send(ildb->ldap, msg);
	if (req == NULL) {
		ldb_set_errstring(ildb->module->ldb, "async send request failed");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ildb_ac->req = talloc_steal(ildb_ac, req);

	if (!req->conn) {
		ldb_set_errstring(ildb->module->ldb, "connection to remote LDAP server dropped?");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_free(req->time_event);
	req->time_event = NULL;
	if (r->timeout) {
		req->time_event = event_add_timed(req->conn->event.event_ctx, ildb_ac, 
						  timeval_current_ofs(r->timeout, 0),
						  ildb_request_timeout, ildb_ac);
	}

	req->async.fn = ildb_callback;
	req->async.private_data = ildb_ac;

	return LDB_SUCCESS;
}

static int ildb_request_noop(struct ildb_private *ildb, struct ldb_request *req) 
{
	struct ildb_context *ildb_ac = init_ildb_handle(ildb, req);
	int ret = LDB_SUCCESS;

	if (!ildb_ac) {
		return LDB_ERR_OPERATIONS_ERROR;		
	}

	if (ildb_ac->callback) {
		ret = ildb_ac->callback(ildb->module->ldb, ildb_ac->context, NULL);
	}
	ildb_ac->handle->state = LDB_ASYNC_DONE;
	return ret;
}

/*
  search for matching records using an asynchronous function
 */
static int ildb_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;
	int n;

	req->handle = NULL;

	if (!req->callback || !req->context) {
		ldb_set_errstring(module->ldb, "Async interface called with NULL callback function or NULL context");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	if (req->op.search.tree == NULL) {
		ldb_set_errstring(module->ldb, "Invalid expression parse tree");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg = new_ldap_message(req);
	if (msg == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_SearchRequest;

	if (req->op.search.base == NULL) {
		msg->r.SearchRequest.basedn = talloc_strdup(msg, "");
	} else {
		msg->r.SearchRequest.basedn  = ldb_dn_alloc_linearized(msg, req->op.search.base);
	}
	if (msg->r.SearchRequest.basedn == NULL) {
		ldb_set_errstring(module->ldb, "Unable to determine baseDN");
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (req->op.search.scope == LDB_SCOPE_DEFAULT) {
		msg->r.SearchRequest.scope = LDB_SCOPE_SUBTREE;
	} else {
		msg->r.SearchRequest.scope = req->op.search.scope;
	}
	
	msg->r.SearchRequest.deref  = LDAP_DEREFERENCE_NEVER;
	msg->r.SearchRequest.timelimit = 0;
	msg->r.SearchRequest.sizelimit = 0;
	msg->r.SearchRequest.attributesonly = 0;
	msg->r.SearchRequest.tree = discard_const(req->op.search.tree);
	
	for (n = 0; req->op.search.attrs && req->op.search.attrs[n]; n++) /* noop */ ;
	msg->r.SearchRequest.num_attributes = n;
	msg->r.SearchRequest.attributes = discard_const(req->op.search.attrs);
	msg->controls = req->controls;

	return ildb_request_send(ildb, msg, req);
}

/*
  add a record
*/
static int ildb_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;
	struct ldap_mod **mods;
	int i,n;

	req->handle = NULL;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ildb_request_noop(ildb, req);
	}

	msg = new_ldap_message(req);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_AddRequest;

	msg->r.AddRequest.dn = ldb_dn_alloc_linearized(msg, req->op.add.message->dn);
	if (msg->r.AddRequest.dn == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	mods = ildb_msg_to_mods(msg, &n, req->op.add.message, 0);
	if (mods == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->r.AddRequest.num_attributes = n;
	msg->r.AddRequest.attributes = talloc_array(msg, struct ldb_message_element, n);
	if (msg->r.AddRequest.attributes == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i = 0; i < n; i++) {
		msg->r.AddRequest.attributes[i] = mods[i]->attrib;
	}

	return ildb_request_send(ildb, msg, req);
}

/*
  modify a record
*/
static int ildb_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;
	struct ldap_mod **mods;
	int i,n;

	req->handle = NULL;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ildb_request_noop(ildb, req);
	}

	msg = new_ldap_message(req);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_ModifyRequest;

	msg->r.ModifyRequest.dn = ldb_dn_alloc_linearized(msg, req->op.mod.message->dn);
	if (msg->r.ModifyRequest.dn == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	mods = ildb_msg_to_mods(msg, &n, req->op.mod.message, 1);
	if (mods == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->r.ModifyRequest.num_mods = n;
	msg->r.ModifyRequest.mods = talloc_array(msg, struct ldap_mod, n);
	if (msg->r.ModifyRequest.mods == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i = 0; i < n; i++) {
		msg->r.ModifyRequest.mods[i] = *mods[i];
	}

	return ildb_request_send(ildb, msg, req);
}

/*
  delete a record
*/
static int ildb_delete(struct ldb_module *module, struct ldb_request *req)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;

	req->handle = NULL;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(req->op.del.dn)) {
		return ildb_request_noop(ildb, req);
	}

	msg = new_ldap_message(req);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_DelRequest;
	
	msg->r.DelRequest.dn = ldb_dn_alloc_linearized(msg, req->op.del.dn);
	if (msg->r.DelRequest.dn == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	return ildb_request_send(ildb, msg, req);
}

/*
  rename a record
*/
static int ildb_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;

	req->handle = NULL;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(req->op.rename.olddn) || ldb_dn_is_special(req->op.rename.newdn)) {
		return ildb_request_noop(ildb, req);
	}

	msg = new_ldap_message(req);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_ModifyDNRequest;
	msg->r.ModifyDNRequest.dn = ldb_dn_alloc_linearized(msg, req->op.rename.olddn);
	if (msg->r.ModifyDNRequest.dn == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	msg->r.ModifyDNRequest.newrdn = 
		talloc_asprintf(msg, "%s=%s",
				ldb_dn_get_rdn_name(req->op.rename.newdn),
				ldb_dn_escape_value(msg, *ldb_dn_get_rdn_val(req->op.rename.newdn)));
	if (msg->r.ModifyDNRequest.newrdn == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->r.ModifyDNRequest.newsuperior =
		ldb_dn_alloc_linearized(msg, ldb_dn_get_parent(msg, req->op.rename.newdn));
	if (msg->r.ModifyDNRequest.newsuperior == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	msg->r.ModifyDNRequest.deleteolddn = True;

	return ildb_request_send(ildb, msg, req);
}

static int ildb_start_trans(struct ldb_module *module)
{
	/* TODO implement a local locking mechanism here */

	return LDB_SUCCESS;
}

static int ildb_end_trans(struct ldb_module *module)
{
	/* TODO implement a local transaction mechanism here */

	return LDB_SUCCESS;
}

static int ildb_del_trans(struct ldb_module *module)
{
	/* TODO implement a local locking mechanism here */

	return LDB_SUCCESS;
}

static int ildb_request(struct ldb_module *module, struct ldb_request *req)
{
	return LDB_ERR_OPERATIONS_ERROR;
}

static int ildb_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	struct ildb_context *ac = talloc_get_type(handle->private_data, struct ildb_context);

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	handle->state = LDB_ASYNC_INIT;

	switch(type) {
	case LDB_WAIT_NONE:
		if (event_loop_once(ac->req->conn->event.event_ctx) != 0) {
			return LDB_ERR_OTHER;
		}
		break;
	case LDB_WAIT_ALL:
		while (handle->status == LDB_SUCCESS && handle->state != LDB_ASYNC_DONE) {
			if (event_loop_once(ac->req->conn->event.event_ctx) != 0) {
				return LDB_ERR_OTHER;
			}
		}
		break;
	default:
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	return handle->status;
}

static const struct ldb_module_ops ildb_ops = {
	.name              = "ldap",
	.search            = ildb_search,
	.add               = ildb_add,
	.modify            = ildb_modify,
	.del               = ildb_delete,
	.rename            = ildb_rename,
	.request           = ildb_request,
	.start_transaction = ildb_start_trans,
	.end_transaction   = ildb_end_trans,
	.del_transaction   = ildb_del_trans,
	.wait              = ildb_wait
};

/*
  connect to the database
*/
static int ildb_connect(struct ldb_context *ldb, const char *url, 
			unsigned int flags, const char *options[],
			struct ldb_module **_module)
{
	struct ldb_module *module;
	struct ildb_private *ildb;
	NTSTATUS status;
	struct cli_credentials *creds;

	module = talloc(ldb, struct ldb_module);
	if (!module) {
		ldb_oom(ldb);
		return -1;
	}
	talloc_set_name_const(module, "ldb_ildap backend");
	module->ldb		= ldb;
	module->prev		= module->next = NULL;
	module->private_data	= NULL;
	module->ops		= &ildb_ops;

	ildb = talloc(module, struct ildb_private);
	if (!ildb) {
		ldb_oom(ldb);
		goto failed;
	}
	module->private_data	= ildb;
	ildb->ldb		= ldb;
	ildb->module		= module;
	ildb->ldap = ldap4_new_connection(ildb, ldb_get_opaque(ldb, "EventContext"));
	if (!ildb->ldap) {
		ldb_oom(ldb);
		goto failed;
	}

	if (flags & LDB_FLG_RECONNECT) {
		ldap_set_reconn_params(ildb->ldap, 10);
	}

	status = ldap_connect(ildb->ldap, url);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Failed to connect to ldap URL '%s' - %s\n",
			  url, ldap_errstr(ildb->ldap, status));
		goto failed;
	}

	/* caller can optionally setup credentials using the opaque token 'credentials' */
	creds = talloc_get_type(ldb_get_opaque(ldb, "credentials"), struct cli_credentials);
	if (creds == NULL) {
		struct auth_session_info *session_info = talloc_get_type(ldb_get_opaque(ldb, "sessionInfo"), struct auth_session_info);
		if (session_info) {
			creds = session_info->credentials;
		}
	}

	if (creds != NULL && cli_credentials_authentication_requested(creds)) {
		const char *bind_dn = cli_credentials_get_bind_dn(creds);
		if (bind_dn) {
			const char *password = cli_credentials_get_password(creds);
			status = ldap_bind_simple(ildb->ldap, bind_dn, password);
			if (!NT_STATUS_IS_OK(status)) {
				ldb_debug(ldb, LDB_DEBUG_ERROR, "Failed to bind - %s\n",
					  ldap_errstr(ildb->ldap, status));
				goto failed;
			}
		} else {
			status = ldap_bind_sasl(ildb->ldap, creds);
			if (!NT_STATUS_IS_OK(status)) {
				ldb_debug(ldb, LDB_DEBUG_ERROR, "Failed to bind - %s\n",
					  ldap_errstr(ildb->ldap, status));
				goto failed;
			}
		}
	}

	*_module = module;
	return 0;

failed:
	talloc_free(module);
	return -1;
}

int ldb_ildap_init(void)
{
	return ldb_register_backend("ldap", ildb_connect) + 
		   ldb_register_backend("ldapi", ildb_connect) + 
		   ldb_register_backend("ldaps", ildb_connect);
}
