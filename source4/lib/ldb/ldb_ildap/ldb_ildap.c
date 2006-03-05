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
#include "lib/cmdline/popt_common.h"
#include "auth/auth.h"

struct ildb_private {
	struct ldap_connection *ldap;
	struct ldb_message *rootDSE;
	struct ldb_context *ldb;
};

struct ildb_async_context {
	struct ldb_module *module;
	struct ldap_request *req;
	void *context;
	int (*callback)(struct ldb_context *, void *, struct ldb_async_result *);
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
	talloc_free(ildb->ldb->err_string);
	ildb->ldb->err_string = talloc_strdup(ildb, ldap_errstr(ildb->ldap, status));
	if (NT_STATUS_IS_LDAP(status)) {
		return NT_STATUS_LDAP_CODE(status);
	}
	return LDB_ERR_OPERATIONS_ERROR;
}

static void ildb_request_timeout(struct event_context *ev, struct timed_event *te,
				 struct timeval t, void *private_data)
{
	struct ldb_async_handle *handle = talloc_get_type(private_data, struct ldb_async_handle);
	struct ildb_async_context *ac = talloc_get_type(handle->private_data, struct ildb_async_context);

	if (ac->req->state == LDAP_REQUEST_PENDING) {
		DLIST_REMOVE(ac->req->conn->pending, ac->req);
	}

	handle->status = LDB_ERR_OPERATIONS_ERROR;

	return;
}

static void ildb_async_callback(struct ldap_request *req)
{
	struct ldb_async_handle *handle = talloc_get_type(req->async.private_data, struct ldb_async_handle);
	struct ildb_async_context *ac = talloc_get_type(handle->private_data, struct ildb_async_context);
	struct ildb_private *ildb = talloc_get_type(ac->module->private_data, struct ildb_private);
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
			struct ldb_async_result *ares = NULL;
			struct ldap_message *msg;
			int ret;

			ares = talloc_zero(ac, struct ldb_async_result);
			if (!ares) {
				handle->status = LDB_ERR_OPERATIONS_ERROR;
				return;
			}

			msg = req->replies[i];
			switch (msg->type) {

			case LDAP_TAG_SearchResultDone:

				status = ldap_check_response(req->conn, &msg->r.GeneralResult);
				if (!NT_STATUS_IS_OK(status)) {
					ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Error: %s\n" ,ldap_errstr(req->conn, status));
					handle->status = ildb_map_error(ildb, status);
					return;
				}
				
				if (msg->controls) {
					ares->controls = talloc_steal(ares, msg->controls);
				}
				if (msg->r.SearchResultDone.resultcode) {
					if (msg->r.SearchResultDone.errormessage) {
						ldb_set_errstring(ac->module->ldb, talloc_strdup(ac->module, msg->r.SearchResultDone.errormessage));
					}
				}

				handle->status = msg->r.SearchResultDone.resultcode;
				handle->state = LDB_ASYNC_DONE;
				ares->type = LDB_REPLY_DONE;
				break;

			case LDAP_TAG_SearchResultEntry:


				ares->message = ldb_msg_new(ares);
				if (!ares->message) {
					handle->status = LDB_ERR_OPERATIONS_ERROR;;
					return;
				}

				search = &(msg->r.SearchResultEntry);
		
				ares->message->dn = ldb_dn_explode_or_special(ares->message, search->dn);
				if (ares->message->dn == NULL) {
					handle->status = LDB_ERR_OPERATIONS_ERROR;
					return;
				}
				ares->message->num_elements = search->num_attributes;
				ares->message->elements = talloc_steal(ares->message, search->attributes);

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

static int ildb_request_send(struct ldb_module *module, struct ldap_message *msg,
			     void *context,
			     int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			     int timeout,
			     struct ldb_async_handle **handle)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ildb_async_context *ildb_ac;
	struct ldb_async_handle *h;
	struct ldap_request *req;

	h = talloc_zero(ildb->ldap, struct ldb_async_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ildb_ac = talloc(h, struct ildb_async_context);
	if (ildb_ac == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		talloc_free(h);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	h->private_data = (void *)ildb_ac;

	req = ldap_request_send(ildb->ldap, msg);
	if (req == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "async send request failed"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ildb_ac->req = talloc_steal(ildb_ac, req);
	ildb_ac->module = module;
	ildb_ac->context = context;
	ildb_ac->callback = callback;

	req->async.fn = ildb_async_callback;
	req->async.private_data = (void *)h;

	talloc_free(req->time_event);
	req->time_event = NULL;
	if (timeout) {
		req->time_event = event_add_timed(req->conn->event.event_ctx, h, 
						  timeval_current_ofs(timeout, 0),
						  ildb_request_timeout, ildb_ac);
	}

	*handle = h;

	return LDB_SUCCESS;

}

/*
  search for matching records using an asynchronous function
 */
static int ildb_search_async(struct ldb_module *module, const struct ldb_dn *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs,
			      struct ldb_control **control_req,
			      void *context,
			      int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			      int timeout,
			      struct ldb_async_handle **handle)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;
	int n;

	*handle = NULL;

	if (!callback || !context) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Async interface called with NULL callback function or NULL context"));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	if (tree == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Invalid expression parse tree"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg = new_ldap_message(ildb);
	if (msg == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_SearchRequest;

	if (base == NULL) {
		if (ildb->rootDSE != NULL) {
			msg->r.SearchRequest.basedn =
				talloc_strdup(msg, ldb_msg_find_string(ildb->rootDSE, "defaultNamingContext", ""));
		} else {
			msg->r.SearchRequest.basedn = talloc_strdup(msg, "");
		}
	} else {
		msg->r.SearchRequest.basedn  = ldb_dn_linearize(msg, base);
	}
	if (msg->r.SearchRequest.basedn == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Unable to determine baseDN"));
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (scope == LDB_SCOPE_DEFAULT) {
		msg->r.SearchRequest.scope = LDB_SCOPE_SUBTREE;
	} else {
		msg->r.SearchRequest.scope = scope;
	}
	
	msg->r.SearchRequest.deref  = LDAP_DEREFERENCE_NEVER;
	msg->r.SearchRequest.timelimit = 0;
	msg->r.SearchRequest.sizelimit = 0;
	msg->r.SearchRequest.attributesonly = 0;
	msg->r.SearchRequest.tree = tree;
	
	for (n = 0; attrs && attrs[n]; n++) /* noop */ ;
	msg->r.SearchRequest.num_attributes = n;
	msg->r.SearchRequest.attributes = discard_const(attrs);
	msg->controls = control_req;

	return ildb_request_send(module, msg, context, callback, timeout, handle);
}

static int ildb_search_sync_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
{
	struct ldb_result *res;
	int n;
	
 	if (!context) {
		ldb_set_errstring(ldb, talloc_asprintf(ldb, "NULL Context in callback"));
		return LDB_ERR_OPERATIONS_ERROR;
	}	

	res = *((struct ldb_result **)context);

	if (!res || !ares) {
		goto error;
	}

	if (ares->type == LDB_REPLY_ENTRY) {
		res->msgs = talloc_realloc(res, res->msgs, struct ldb_message *, res->count + 2);
		if (! res->msgs) {
			goto error;
		}

		res->msgs[res->count + 1] = NULL;

		res->msgs[res->count] = talloc_steal(res->msgs, ares->message);
		if (! res->msgs[res->count]) {
			goto error;
		}

		res->count++;
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		if (res->refs) {
			for (n = 0; res->refs[n]; n++) /*noop*/ ;
		} else {
			n = 0;
		}

		res->refs = talloc_realloc(res, res->refs, char *, n + 2);
		if (! res->refs) {
			goto error;
		}

		res->refs[n] = talloc_steal(res->refs, ares->referral);
		res->refs[n + 1] = NULL;
	}

	if (ares->controls) {
		res->controls = talloc_steal(res, ares->controls);
		if (! res->controls) {
			goto error;
		}
	}

	talloc_free(ares);
	return LDB_SUCCESS;

error:
	talloc_free(ares);
	talloc_free(res);
	*((struct ldb_result **)context) = NULL;
	return LDB_ERR_OPERATIONS_ERROR;
}

/*
  search for matching records using a synchronous function
 */
static int ildb_search_bytree(struct ldb_module *module, const struct ldb_dn *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs,
			      struct ldb_control **control_req,
			      struct ldb_result **res)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldb_async_handle *handle;
	int ret;

	*res = talloc_zero(ildb, struct ldb_result);
	if (! *res) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ildb_search_async(module, base, scope, tree, attrs, control_req,
				res, &ildb_search_sync_callback, ildb->ldap->timeout, &handle);

	if (ret == LDB_SUCCESS) {
		ret = ldb_async_wait(module->ldb, handle, LDB_WAIT_ALL);
		talloc_free(handle);
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(*res);
	}

	return ret;
}

/*
  add a record
*/
static int ildb_add_async(struct ldb_module *module, const struct ldb_message *ldb_msg,
			  void *context,
			  int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			  int timeout,
			  struct ldb_async_handle **handle)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;
	struct ldap_mod **mods;
	int i,n;

	*handle = NULL;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(ldb_msg->dn)) {
		return LDB_SUCCESS;
	}

	msg = new_ldap_message(ildb->ldap);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_AddRequest;

	msg->r.AddRequest.dn = ldb_dn_linearize(msg, ldb_msg->dn);
	if (msg->r.AddRequest.dn == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	mods = ildb_msg_to_mods(msg, &n, ldb_msg, 0);
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

	return ildb_request_send(module, msg, context, callback, timeout, handle);
}

static int ildb_add(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldb_async_handle *handle;
	int ret;

	ret = ildb_add_async(module, msg,
				NULL, NULL, ildb->ldap->timeout, &handle);

	if (ret != LDB_SUCCESS)
		return ret;

	ret = ldb_async_wait(module->ldb, handle, LDB_WAIT_ALL);

	talloc_free(handle);
	return ret;
}

/*
  modify a record
*/
static int ildb_modify_async(struct ldb_module *module, const struct ldb_message *ldb_msg,
			     void *context,
			     int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			     int timeout,
			     struct ldb_async_handle **handle)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;
	struct ldap_mod **mods;
	int i,n;

	*handle = NULL;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(ldb_msg->dn)) {
		return LDB_SUCCESS;
	}

	msg = new_ldap_message(ildb->ldap);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_ModifyRequest;

	msg->r.ModifyRequest.dn = ldb_dn_linearize(msg, ldb_msg->dn);
	if (msg->r.ModifyRequest.dn == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	mods = ildb_msg_to_mods(msg, &n, ldb_msg, 1);
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

	return ildb_request_send(module, msg, context, callback, timeout, handle);
}

static int ildb_modify(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldb_async_handle *handle;
	int ret;

	ret = ildb_modify_async(module, msg,
				NULL, NULL, ildb->ldap->timeout, &handle);

	if (ret != LDB_SUCCESS)
		return ret;

	ret = ldb_async_wait(module->ldb, handle, LDB_WAIT_ALL);

	talloc_free(handle);
	return ret;
}

/*
  delete a record
*/
static int ildb_delete_async(struct ldb_module *module, const struct ldb_dn *dn,
			     void *context,
			     int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			     int timeout,
			     struct ldb_async_handle **handle)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;

	*handle = NULL;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(dn)) {
		return LDB_SUCCESS;
	}

	msg = new_ldap_message(ildb->ldap);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_DelRequest;
	
	msg->r.DelRequest.dn = ldb_dn_linearize(msg, dn);
	if (msg->r.DelRequest.dn == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	return ildb_request_send(module, msg, context, callback, timeout, handle);
}

static int ildb_delete(struct ldb_module *module, const struct ldb_dn *dn)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldb_async_handle *handle;
	int ret;

	ret = ildb_delete_async(module, dn,
				NULL, NULL, ildb->ldap->timeout, &handle);

	if (ret != LDB_SUCCESS)
		return ret;

	ret = ldb_async_wait(module->ldb, handle, LDB_WAIT_ALL);

	talloc_free(handle);
	return ret;
}

/*
  rename a record
*/
static int ildb_rename_async(struct ldb_module *module,
			     const struct ldb_dn *olddn, const struct ldb_dn *newdn,
			     void *context,
			     int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			     int timeout,
			     struct ldb_async_handle **handle)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldap_message *msg;

	*handle = NULL;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(olddn) || ldb_dn_is_special(newdn)) {
		return LDB_SUCCESS;
	}

	msg = new_ldap_message(ildb->ldap);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->type = LDAP_TAG_ModifyDNRequest;
	msg->r.ModifyDNRequest.dn = ldb_dn_linearize(msg, olddn);
	if (msg->r.ModifyDNRequest.dn == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	msg->r.ModifyDNRequest.newrdn = 
		talloc_asprintf(msg, "%s=%s",
				newdn->components[0].name,
				ldb_dn_escape_value(msg, newdn->components[0].value));
	if (msg->r.ModifyDNRequest.newrdn == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->r.ModifyDNRequest.newsuperior =
		ldb_dn_linearize(msg,
				 ldb_dn_get_parent(msg, newdn));
	if (msg->r.ModifyDNRequest.newsuperior == NULL) {
		talloc_free(msg);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	msg->r.ModifyDNRequest.deleteolddn = True;

	return ildb_request_send(module, msg, context, callback, timeout, handle);
}

static int ildb_rename(struct ldb_module *module, const struct ldb_dn *olddn, const struct ldb_dn *newdn)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldb_async_handle *handle;
	int ret;

	ret = ildb_rename_async(module, olddn, newdn,
				NULL, NULL, ildb->ldap->timeout, &handle);

	if (ret != LDB_SUCCESS)
		return ret;

	ret = ldb_async_wait(module->ldb, handle, LDB_WAIT_ALL);

	talloc_free(handle);
	return ret;
}

static int ildb_start_trans(struct ldb_module *module)
{
	/* TODO implement a local locking mechanism here */

	return 0;
}

static int ildb_end_trans(struct ldb_module *module)
{
	/* TODO implement a local transaction mechanism here */

	return 0;
}

static int ildb_del_trans(struct ldb_module *module)
{
	/* TODO implement a local locking mechanism here */

	return 0;
}

static int ildb_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return ildb_search_bytree(module,
					  req->op.search.base,
					  req->op.search.scope, 
					  req->op.search.tree, 
					  req->op.search.attrs, 
					  req->controls,
					  &req->op.search.res);

	case LDB_REQ_ADD:
		return ildb_add(module, req->op.add.message);

	case LDB_REQ_MODIFY:
		return ildb_modify(module, req->op.mod.message);

	case LDB_REQ_DELETE:
		return ildb_delete(module, req->op.del.dn);

	case LDB_REQ_RENAME:
		return ildb_rename(module,
					req->op.rename.olddn,
					req->op.rename.newdn);

	case LDB_ASYNC_SEARCH:
		return ildb_search_async(module,
					req->op.search.base,
					req->op.search.scope, 
					req->op.search.tree, 
					req->op.search.attrs,
				 	req->controls,
					req->async.context,
					req->async.callback,
					req->async.timeout,
					&req->async.handle);

	case LDB_ASYNC_ADD:
		return ildb_add_async(module,
					req->op.add.message,
					req->async.context,
					req->async.callback,
					req->async.timeout,
					&req->async.handle);

	case LDB_ASYNC_MODIFY:
		return ildb_modify_async(module,
					req->op.mod.message,
					req->async.context,
					req->async.callback,
					req->async.timeout,
					&req->async.handle);

	case LDB_ASYNC_DELETE:
		return ildb_delete_async(module,
					req->op.del.dn,
					req->async.context,
					req->async.callback,
					req->async.timeout,
					&req->async.handle);

	case LDB_ASYNC_RENAME:
		return ildb_rename_async(module,
					req->op.rename.olddn,
					req->op.rename.newdn,
					req->async.context,
					req->async.callback,
					req->async.timeout,
					&req->async.handle);

	default:
		return -1;

	}
}

static int ildb_async_wait(struct ldb_module *module, struct ldb_async_handle *handle, enum ldb_async_wait_type type)
{
	struct ildb_async_context *ac = talloc_get_type(handle->private_data, struct ildb_async_context);

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
	case LDB_WAIT_ONCE:
		while (handle->status == LDB_SUCCESS && handle->state == LDB_ASYNC_INIT) {
		       if (event_loop_once(ac->req->conn->event.event_ctx) != 0) {
				return LDB_ERR_OTHER;
			}
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

/*
  fetch the rootDSE for later use
*/
static int ildb_init(struct ldb_module *module)
{
	struct ildb_private *ildb = talloc_get_type(module->private_data, struct ildb_private);
	struct ldb_result *res = NULL;
	struct ldb_dn *empty_dn = ldb_dn_new(ildb);
	int ret;
	ret = ildb_search_bytree(module, empty_dn, LDB_SCOPE_BASE, 
				 ldb_parse_tree(empty_dn, "dn=dc=rootDSE"), 
				 NULL, NULL, &res);
	if (ret == LDB_SUCCESS && res->count == 1) {
		ildb->rootDSE = talloc_steal(ildb, res->msgs[0]);
	}
	if (ret == LDB_SUCCESS) talloc_free(res);
	talloc_free(empty_dn);

	return LDB_SUCCESS;
}

static const struct ldb_module_ops ildb_ops = {
	.name              = "ldap",
	.request           = ildb_request,
	.start_transaction = ildb_start_trans,
	.end_transaction   = ildb_end_trans,
	.del_transaction   = ildb_del_trans,
	.async_wait        = ildb_async_wait,
	.init_context	   = ildb_init
};

/*
  connect to the database
*/
static int ildb_connect(struct ldb_context *ldb, const char *url, 
		 unsigned int flags, const char *options[])
{
	struct ildb_private *ildb = NULL;
	NTSTATUS status;
	struct cli_credentials *creds;

	ildb = talloc(ldb, struct ildb_private);
	if (!ildb) {
		ldb_oom(ldb);
		goto failed;
	}

	ildb->rootDSE = NULL;
	ildb->ldb     = ldb;

	ildb->ldap = ldap_new_connection(ildb, ldb_get_opaque(ldb, "EventContext"));
	if (!ildb->ldap) {
		ldb_oom(ldb);
		goto failed;
	}

	status = ldap_connect(ildb->ldap, url);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Failed to connect to ldap URL '%s' - %s\n",
			  url, ldap_errstr(ildb->ldap, status));
		goto failed;
	}

	ldb->modules = talloc(ldb, struct ldb_module);
	if (!ldb->modules) {
		ldb_oom(ldb);
		goto failed;
	}
	ldb->modules->ldb = ldb;
	ldb->modules->prev = ldb->modules->next = NULL;
	ldb->modules->private_data = ildb;
	ldb->modules->ops = &ildb_ops;

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

	return 0;

failed:
	if (ldb->modules) {
		ldb->modules->private_data = NULL;
	}
	talloc_free(ildb);
	return -1;
}

int ldb_ildap_init(void)
{
	return ldb_register_backend("ldap", ildb_connect);
}
