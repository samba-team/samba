/* 
   ldb database module

   Copyright (C) Simo Sorce  2004-2006
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2006
   Copyright (C) Andrew Tridgell 2004

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
 *  Name: ldb
 *
 *  Component: ldb local_password module
 *
 *  Description: correctly update hash values based on changes to sambaPassword and friends
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "libcli/ldap/ldap.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/ndr/libndr.h"
#include "dsdb/samdb/ldb_modules/password_modules.h"

#define PASSWORD_GUID_ATTR "masterGUID"

/* This module maintains a local password database, seperate from the main LDAP server.

   This allows the password database to be syncronised in a multi-master
   fashion, seperate to the more difficult concerns of the main
   database.  (With passwords, the last writer always wins)
   
   Each incoming add/modify is split into a remote, and a local request, done in that order.

   We maintain a list of attributes that are kept locally:
 */

static const char * const password_attrs[] = {
	"sambaPassword",
	"krb5Key",
	"ntPwdHash",
	"lmPwdHash",
	"sambaLMPwdHistory", 
	"sambaNTPwdHistory", 
	"msDS-KeyVersionNumber",
	"pwdLastSet"
};

/* And we merge them back into search requests when asked to do so */

struct lpdb_context {

	enum lpdb_type {LPDB_ADD, LPDB_MOD, LPDB_SEARCH} type;
	enum lpdb_step {LPDB_ADD_REMOTE, LPDB_MOD_REMOTE, LPDB_MOD_SEARCH_SELF, LPDB_LOCAL, LPDB_SEARCH_REMOTE} step;

	struct ldb_module *module;
	struct ldb_request *orig_req;
	struct ldb_request *remote_req;
	struct ldb_request *search_req;
	struct ldb_request *local_req;

	struct ldb_message *local_message;

	BOOL added_objectGUID;
	BOOL added_objectClass;

	struct ldb_reply *search_res;
};

struct lpdb_local_search_context {
	struct lpdb_context *ac;
	struct ldb_reply *remote_res;
	struct ldb_reply *local_res;
};

static struct ldb_handle *lpdb_init_handle(struct ldb_request *req, struct ldb_module *module, enum lpdb_type type)
{
	struct lpdb_context *ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct lpdb_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)ac;

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->type = type;
	ac->module = module;
	ac->orig_req = req;

	return h;
}

/* Add a record, splitting password attributes from the user's main
 * record */

static int local_password_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_handle *h;
	struct lpdb_context *ac;
	struct ldb_message *remote_message;
	struct ldb_message *local_message;
	struct GUID objectGUID;
	int i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "local_password_add\n");

	if (ldb_dn_is_special(req->op.add.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* If the caller is manipulating the local passwords directly, let them pass */
	if (ldb_dn_compare_base(ldb_dn_new(req, module->ldb, LOCAL_BASE),
				req->op.add.message->dn) == 0) {
		return ldb_next_request(module, req);
	}

	for (i=0; i < ARRAY_SIZE(password_attrs); i++) {
		if (ldb_msg_find_element(req->op.add.message, password_attrs[i])) {
			break;
		}
	}

	/* It didn't match any of our password attributes, go on */
	if (i == ARRAY_SIZE(password_attrs)) {
		return ldb_next_request(module, req);
	}

	/* TODO: remove this when sambaPassword will be in schema */
	if (!ldb_msg_check_string_attribute(req->op.add.message, "objectClass", "person")) {
		ldb_asprintf_errstring(module->ldb,
					"Cannot relocate a password on entry: %s, does not have objectClass 'person'",
					ldb_dn_get_linearized(req->op.add.message->dn));
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	/* From here, we assume we have password attributes to split off */
	h = lpdb_init_handle(req, module, LPDB_ADD);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct lpdb_context);

	ac->orig_req = req;

	ac->remote_req = talloc(ac, struct ldb_request);
	if (ac->remote_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->remote_req) = *(ac->orig_req);

	remote_message = ldb_msg_copy_shallow(ac->remote_req, ac->orig_req->op.add.message);
	if (remote_message == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Remove any password attributes from the remote message */
	for (i=0; i < ARRAY_SIZE(password_attrs); i++) {
		ldb_msg_remove_attr(remote_message, password_attrs[i]);
	}

	ac->remote_req->op.add.message = remote_message;

	ac->remote_req->context = NULL;
	ac->remote_req->callback = NULL;

	ac->local_req = talloc(ac, struct ldb_request);
	if (ac->local_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->local_req) = *(ac->orig_req);
	local_message = ldb_msg_copy_shallow(ac->local_req, ac->orig_req->op.add.message);
	if (local_message == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Remove anything seen in the remote message from the local
	 * message (leaving only password attributes) */
	for (i=0;i<ac->remote_req->op.add.message->num_elements;i++) {
		ldb_msg_remove_attr(local_message, ac->remote_req->op.add.message->elements[i].name);
	}

	/* We must have an objectGUID already, or we don't know where
	 * to add the password.  This may be changed to an 'add and
	 * search', to allow the directory to create the objectGUID */
	if (ldb_msg_find_ldb_val(ac->orig_req->op.add.message, "objectGUID") == NULL) {
		ldb_set_errstring(module->ldb, 
				  "no objectGUID found in search: local_password module must be configured below objectGUID module!\n");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* Find the objectGUID to use as the key */
	objectGUID = samdb_result_guid(ac->orig_req->op.add.message, "objectGUID");
	
	local_message->dn = ldb_dn_new(local_message, module->ldb, LOCAL_BASE);
	ldb_dn_add_child_fmt(local_message->dn, PASSWORD_GUID_ATTR "=%s", GUID_string(local_message, &objectGUID));

	ac->local_req->op.add.message = local_message;

	ac->local_req->context = NULL;
	ac->local_req->callback = NULL;

	ac->step = LPDB_ADD_REMOTE;

	/* Return our own handle do deal with this call */
	req->handle = h;

	return ldb_next_request(module, ac->remote_req);
}

/* After adding the remote entry, add the local one */
static int local_password_add_local(struct ldb_handle *h) {

	struct lpdb_context *ac;
	ac = talloc_get_type(h->private_data, struct lpdb_context);

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = LPDB_LOCAL;

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->local_req);

	/* perform the local add */
	return ldb_next_request(ac->module, ac->local_req);
}

static int local_password_mod_search_self(struct ldb_handle *h);

static int local_password_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_handle *h;
	struct lpdb_context *ac;
	struct ldb_message *remote_message;
	struct ldb_message *local_message;
	int i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "local_password_modify\n");

	if (ldb_dn_is_special(req->op.mod.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* If the caller is manipulating the local passwords directly, let them pass */
	if (ldb_dn_compare_base(ldb_dn_new(req, module->ldb, LOCAL_BASE),
				req->op.mod.message->dn) == 0) {
		return ldb_next_request(module, req);
	}

	for (i=0; i < ARRAY_SIZE(password_attrs); i++) {
		if (ldb_msg_find_element(req->op.add.message, password_attrs[i])) {
			break;
		}
	}

	/* It didn't match any of our password attributes, then we have nothing to do here */
	if (i == ARRAY_SIZE(password_attrs)) {
		return ldb_next_request(module, req);
	}

	/* From here, we assume we have password attributes to split off */
	h = lpdb_init_handle(req, module, LPDB_MOD);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct lpdb_context);

	ac->orig_req = req;

	ac->remote_req = talloc(ac, struct ldb_request);
	if (ac->remote_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->remote_req) = *(ac->orig_req);
	remote_message = ldb_msg_copy_shallow(ac->remote_req, ac->orig_req->op.mod.message);
	if (remote_message == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	/* Remove any password attributes from the remote message */
	for (i=0; i < ARRAY_SIZE(password_attrs); i++) {
		ldb_msg_remove_attr(remote_message, password_attrs[i]);
	}

	ac->remote_req->op.mod.message = remote_message;

	ac->remote_req->context = NULL;
	ac->remote_req->callback = NULL;

	ac->local_req = talloc(ac, struct ldb_request);
	if (ac->local_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(ac->local_req) = *(ac->orig_req);
	local_message = ldb_msg_copy_shallow(ac->local_req, ac->orig_req->op.mod.message);
	if (local_message == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Remove anything seen in the remote message from the local
	 * message (leaving only password attributes) */
	for (i=0;i<ac->remote_req->op.mod.message->num_elements;i++) {
		ldb_msg_remove_attr(local_message, ac->remote_req->op.mod.message->elements[i].name);
	}

	ac->local_req->op.mod.message = local_message;
	ac->local_message = local_message;

	ac->local_req->context = NULL;
	ac->local_req->callback = NULL;

	ac->step = LPDB_MOD_REMOTE;

	/* Return our own handle do deal with this call */
	req->handle = h;

	return ldb_next_request(module, ac->remote_req);
}

/* Called when we search for our oen entry.  Stores the one entry we
 * expect (as it is a base search) on the context pointer */
static int get_self_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct lpdb_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac = talloc_get_type(context, struct lpdb_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		if (ac->search_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ac->search_res = talloc_steal(ac, ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
}

/* On a modify, we don't have the objectGUID handy, so we need to
 * search our DN for it */
static int local_password_mod_search_self(struct ldb_handle *h) {

	struct lpdb_context *ac;
	static const char * const attrs[] = { "objectGUID", "objectClass", NULL };

	ac = talloc_get_type(h->private_data, struct lpdb_context);

	/* prepare the search operation */
	ac->search_req = talloc_zero(ac, struct ldb_request);
	if (ac->search_req == NULL) {
		ldb_debug(ac->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->search_req->operation = LDB_SEARCH;
	ac->search_req->op.search.base = ac->orig_req->op.mod.message->dn;
	ac->search_req->op.search.scope = LDB_SCOPE_BASE;
	ac->search_req->op.search.tree = ldb_parse_tree(ac->orig_req, NULL);
	if (ac->search_req->op.search.tree == NULL) {
		ldb_set_errstring(ac->module->ldb, "Invalid search filter");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->search_req->op.search.attrs = attrs;
	ac->search_req->controls = NULL;
	ac->search_req->context = ac;
	ac->search_req->callback = get_self_callback;
	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->search_req);

	ac->step = LPDB_MOD_SEARCH_SELF;

	return ldb_next_request(ac->module, ac->search_req);
}

/* After we find out the objectGUID for the entry, modify the local
 * password database as required */
static int local_password_mod_local(struct ldb_handle *h) {

	struct lpdb_context *ac;
	struct GUID objectGUID;
	ac = talloc_get_type(h->private_data, struct lpdb_context);

	/* if it is not an entry of type person this is an error */
	/* TODO: remove this when sambaPassword will be in schema */
	if (!ac->search_res) {
		ldb_asprintf_errstring(ac->module->ldb, 
					"entry just modified (%s) not found!",
					ldb_dn_get_linearized(ac->remote_req->op.mod.message->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (!ldb_msg_check_string_attribute(ac->search_res->message, "objectClass", "person")) {
		/* Not relevent to us */
		return LDB_SUCCESS;
	}
	
	if (ldb_msg_find_ldb_val(ac->search_res->message, "objectGUID") == NULL) {
		ldb_set_errstring(ac->module->ldb, 
				  "no objectGUID found in search: local_password module must be configured below objectGUID module!\n");
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}
	
	objectGUID = samdb_result_guid(ac->search_res->message, "objectGUID");

	ac->local_message->dn = ldb_dn_new(ac, ac->module->ldb, LOCAL_BASE);
	ldb_dn_add_child_fmt(ac->local_message->dn, PASSWORD_GUID_ATTR "=%s", GUID_string(ac, &objectGUID));

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = LPDB_LOCAL;

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->local_req);

	/* perform the local update */
	return ldb_next_request(ac->module, ac->local_req);
}


static int lpdb_local_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct lpdb_local_search_context *local_context;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	local_context = talloc_get_type(context, struct lpdb_local_search_context);

	/* we are interested only in the single reply (base search) we receive here */
	switch (ares->type) {
	case LDB_REPLY_ENTRY:
	{
		int i;
		if (local_context->local_res != NULL) {
			ldb_set_errstring(ldb, "Too many results to base search for password entry!");
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		local_context->local_res = ares;

		/* Make sure never to return the internal key attribute to the caller */
		ldb_msg_remove_attr(ares->message, PASSWORD_GUID_ATTR);

		talloc_steal(local_context->remote_res->message->elements, ares->message->elements);
		for (i=0; i < ares->message->num_elements; i++) {
			struct ldb_message_element *el;
			
			el = ldb_msg_find_element(local_context->remote_res->message, 
						  ares->message->elements[i].name);
			if (!el) {
				if (ldb_msg_add_empty(local_context->remote_res->message, 
						      ares->message->elements[i].name, 0, &el) != LDB_SUCCESS) {
					talloc_free(ares);
					return LDB_ERR_OPERATIONS_ERROR;
				}
				*el = ares->message->elements[i];
			}
		}
		return local_context->ac->orig_req->callback(ldb, 
								   local_context->ac->orig_req->context,
								   local_context->remote_res);
	} 
	case LDB_REPLY_DONE:
	{
		/* Fire off the callback if there was no local entry, so we get the rest returned */
		if (local_context->local_res == NULL) {
			return local_context->ac->orig_req->callback(ldb, 
									   local_context->ac->orig_req->context,
									   local_context->remote_res);
		}
		return LDB_SUCCESS;
		break;
	}
	default:
	{
		talloc_free(ares);
		ldb_set_errstring(ldb, "Unexpected result type in base search for password entry!");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	}
}

/* For each entry returned in a remote search, do a local base search,
 * based on the objectGUID we asked for as an additional attribute */
static int lpdb_remote_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct lpdb_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		goto error;
	}

	ac = talloc_get_type(context, struct lpdb_context);

	if (ares->type == LDB_REPLY_ENTRY) {
		struct ldb_request *req;
		struct lpdb_local_search_context *local_context;
		struct GUID objectGUID;

		/* No point searching further if it's not a 'person' entry */
		if (!ldb_msg_check_string_attribute(ares->message, "objectClass", "person")) {

			/* Make sure to remove anything we added */
			if (ac->added_objectGUID) {
				ldb_msg_remove_attr(ares->message, "objectGUID");
			}
			
			if (ac->added_objectClass) {
				ldb_msg_remove_attr(ares->message, "objectClass");
			}
			
			return ac->orig_req->callback(ldb, ac->orig_req->context, ares);
		}

		if (ldb_msg_find_ldb_val(ares->message, "objectGUID") == NULL) {
			ldb_set_errstring(ac->module->ldb, 
					  "no objectGUID found in search: local_password module must be configured below objectGUID module!\n");
			return LDB_ERR_OPERATIONS_ERROR;
		}
	
		objectGUID = samdb_result_guid(ares->message, "objectGUID");

		if (ac->added_objectGUID) {
			ldb_msg_remove_attr(ares->message, "objectGUID");
		}

		if (ac->added_objectClass) {
			ldb_msg_remove_attr(ares->message, "objectClass");
		}

		req = talloc_zero(ac, struct ldb_request);
		if (!req) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		local_context = talloc(ac, struct lpdb_local_search_context);
		if (!local_context) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		local_context->ac = ac;
		local_context->remote_res = ares;
		local_context->local_res = NULL;

		req->op.search.base = ldb_dn_new(ac, ac->module->ldb, LOCAL_BASE);
		if ( ! ldb_dn_add_child_fmt(req->op.search.base, PASSWORD_GUID_ATTR "=%s", GUID_string(ac, &objectGUID))) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		req->operation = LDB_SEARCH;
		req->op.search.scope = LDB_SCOPE_BASE;
		req->op.search.tree = ldb_parse_tree(req, NULL);
		if (req->op.search.tree == NULL) {
			ldb_set_errstring(ac->module->ldb, "Out of Memory");
			return LDB_ERR_OPERATIONS_ERROR;
		}
		req->op.search.attrs = ac->orig_req->op.search.attrs;
		req->controls = NULL;
		req->context = ac;
		req->callback = get_self_callback;

		ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, req);
		
		req->context = local_context;
		req->callback = lpdb_local_search_callback;

		return ldb_next_request(ac->module, req);
	} else {
		return ac->orig_req->callback(ldb, ac->orig_req->context, ares);
	}
error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

/* Search for passwords and other attributes.  The passwords are
 * local, but the other attributes are remote, and we need to glue the
 * two search spaces back togeather */

static int local_password_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_handle *h;
	struct lpdb_context *ac;
	int i;
	int ret;
	const char * const *search_attrs = NULL;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "local_password_search\n");

	if (ldb_dn_is_special(req->op.search.base)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* If the caller is searching for the local passwords directly, let them pass */
	if (ldb_dn_compare_base(ldb_dn_new(req, module->ldb, LOCAL_BASE),
				req->op.search.base) == 0) {
		return ldb_next_request(module, req);
	}

	if (req->op.search.attrs && (!ldb_attr_in_list(req->op.search.attrs, "*"))) {
		for (i=0; i < ARRAY_SIZE(password_attrs); i++) {
			if (ldb_attr_in_list(req->op.search.attrs, password_attrs[i])) {
				break;
			}
		}
		
		/* It didn't match any of our password attributes, go on */
		if (i == ARRAY_SIZE(password_attrs)) {
			return ldb_next_request(module, req);
		}
	}

	h = lpdb_init_handle(req, module, LPDB_SEARCH);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	ac = talloc_get_type(h->private_data, struct lpdb_context);

	ac->orig_req = req;

	ac->remote_req = talloc(ac, struct ldb_request);
	if (ac->remote_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Remote search is for all attributes: if the remote LDAP server has these attributes, then it overrides the local database */
	*(ac->remote_req) = *(ac->orig_req);

	/* Return our own handle do deal with this call */
	ac->remote_req->handle = h;
	
	ac->remote_req->context = ac;
	ac->remote_req->callback = lpdb_remote_search_callback;

	if (req->op.search.attrs && !ldb_attr_in_list(req->op.search.attrs, "*")) {
		if (!ldb_attr_in_list(req->op.search.attrs, "objectGUID")) {
			search_attrs = ldb_attr_list_copy_add(req, req->op.search.attrs, "objectGUID");
			ac->added_objectGUID = True;
			if (!search_attrs) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		} else {
			search_attrs = req->op.search.attrs;
		}
		if (!ldb_attr_in_list(search_attrs, "objectClass")) {
			search_attrs = ldb_attr_list_copy_add(req, search_attrs, "objectClass");
			ac->added_objectClass = True;
			if (!search_attrs) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
	} else {
		search_attrs = req->op.search.attrs;
	}

	ac->remote_req->op.search.attrs = search_attrs;

	ldb_set_timeout_from_prev_req(module->ldb, ac->orig_req, ac->remote_req);

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = LPDB_SEARCH_REMOTE;

	/* perform the search */
	ret = ldb_next_request(module, ac->remote_req);

	if (ret == LDB_SUCCESS) {
		req->handle = ac->remote_req->handle;
	}

	return ret;
}

static int lpdb_wait(struct ldb_handle *handle) {
	struct lpdb_context *ac;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	ac = talloc_get_type(handle->private_data, struct lpdb_context);

	switch (ac->step) {
	case LPDB_ADD_REMOTE:
		ret = ldb_wait(ac->remote_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->remote_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->remote_req->handle->status;
			goto done;
		}

		if (ac->remote_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* original request done, go on */
		return local_password_add_local(handle);
		
	case LPDB_MOD_REMOTE:
		ret = ldb_wait(ac->remote_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->remote_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->remote_req->handle->status;
			goto done;
		}

		if (ac->remote_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* original request done, go on */
		return local_password_mod_search_self(handle);
		
	case LPDB_MOD_SEARCH_SELF:
		ret = ldb_wait(ac->search_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->search_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->search_req->handle->status;
			goto done;
		}

		if (ac->search_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* original request done, go on */
		return local_password_mod_local(handle);
		
	case LPDB_LOCAL:
		ret = ldb_wait(ac->local_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->local_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->local_req->handle->status;
			goto done;
		}

		if (ac->local_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	case LPDB_SEARCH_REMOTE:
		ret = ldb_wait(ac->remote_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->remote_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->remote_req->handle->status;
			goto done;
		}

		if (ac->remote_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	default:
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = LDB_SUCCESS;

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;
}

static int lpdb_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = lpdb_wait(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int local_password_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return lpdb_wait_all(handle);
	} else {
		return lpdb_wait(handle);
	}
}

static const struct ldb_module_ops local_password_ops = {
	.name          = "local_password",
	.add           = local_password_add,
	.modify        = local_password_modify,
	.search        = local_password_search,
	.wait          = local_password_wait
};


int local_password_module_init(void)
{
	return ldb_register_module(&local_password_ops);
}
