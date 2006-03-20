/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004
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
 *  Name: ldb_ldap
 *
 *  Component: ldb ldap backend
 *
 *  Description: core files for LDAP backend
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

#include <ldap.h>

struct lldb_private {
	LDAP *ldap;
	int timeout;
};

struct lldb_async_context {
	struct ldb_module *module;
	int msgid;
	int timeout;
	void *context;
	int (*callback)(struct ldb_context *, void *, struct ldb_async_result *);
};

static int lldb_ldap_to_ldb(int err) {
	/* Ldap errors and ldb errors are defined to the same values */
	return err;
}

static struct ldb_async_handle *init_handle(struct lldb_private *lldb, struct ldb_module *module,
					    void *context,
					    int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
					    int timeout)
{
	struct lldb_async_context *ac;
	struct ldb_async_handle *h;

	h = talloc_zero(lldb, struct ldb_async_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		return NULL;
	}

	h->module = module;

	ac = talloc(h, struct lldb_async_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)ac;

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->module = module;
	ac->context = context;
	ac->callback = callback;
	ac->timeout = timeout;
	ac->msgid = 0;

	return h;
}
/*
  convert a ldb_message structure to a list of LDAPMod structures
  ready for ldap_add() or ldap_modify()
*/
static LDAPMod **lldb_msg_to_mods(void *mem_ctx, const struct ldb_message *msg, int use_flags)
{
	LDAPMod **mods;
	unsigned int i, j;
	int num_mods = 0;

	/* allocate maximum number of elements needed */
	mods = talloc_array(mem_ctx, LDAPMod *, msg->num_elements+1);
	if (!mods) {
		errno = ENOMEM;
		return NULL;
	}
	mods[0] = NULL;

	for (i=0;i<msg->num_elements;i++) {
		const struct ldb_message_element *el = &msg->elements[i];

		mods[num_mods] = talloc(mods, LDAPMod);
		if (!mods[num_mods]) {
			goto failed;
		}
		mods[num_mods+1] = NULL;
		mods[num_mods]->mod_op = LDAP_MOD_BVALUES;
		if (use_flags) {
			switch (el->flags & LDB_FLAG_MOD_MASK) {
			case LDB_FLAG_MOD_ADD:
				mods[num_mods]->mod_op |= LDAP_MOD_ADD;
				break;
			case LDB_FLAG_MOD_DELETE:
				mods[num_mods]->mod_op |= LDAP_MOD_DELETE;
				break;
			case LDB_FLAG_MOD_REPLACE:
				mods[num_mods]->mod_op |= LDAP_MOD_REPLACE;
				break;
			}
		}
		mods[num_mods]->mod_type = discard_const_p(char, el->name);
		mods[num_mods]->mod_vals.modv_bvals = talloc_array(mods[num_mods], 
								   struct berval *,
								   1+el->num_values);
		if (!mods[num_mods]->mod_vals.modv_bvals) {
			goto failed;
		}

		for (j=0;j<el->num_values;j++) {
			mods[num_mods]->mod_vals.modv_bvals[j] = talloc(mods[num_mods]->mod_vals.modv_bvals,
									struct berval);
			if (!mods[num_mods]->mod_vals.modv_bvals[j]) {
				goto failed;
			}
			mods[num_mods]->mod_vals.modv_bvals[j]->bv_val = el->values[j].data;
			mods[num_mods]->mod_vals.modv_bvals[j]->bv_len = el->values[j].length;
		}
		mods[num_mods]->mod_vals.modv_bvals[j] = NULL;
		num_mods++;
	}

	return mods;

failed:
	talloc_free(mods);
	return NULL;
}

/*
  add a single set of ldap message values to a ldb_message
*/
static int lldb_add_msg_attr(struct ldb_context *ldb,
			     struct ldb_message *msg, 
			     const char *attr, struct berval **bval)
{
	int count, i;
	struct ldb_message_element *el;

	count = ldap_count_values_len(bval);

	if (count <= 0) {
		return -1;
	}

	el = talloc_realloc(msg, msg->elements, struct ldb_message_element, 
			      msg->num_elements + 1);
	if (!el) {
		errno = ENOMEM;
		return -1;
	}

	msg->elements = el;

	el = &msg->elements[msg->num_elements];

	el->name = talloc_strdup(msg->elements, attr);
	if (!el->name) {
		errno = ENOMEM;
		return -1;
	}
	el->flags = 0;

	el->num_values = 0;
	el->values = talloc_array(msg->elements, struct ldb_val, count);
	if (!el->values) {
		errno = ENOMEM;
		return -1;
	}

	for (i=0;i<count;i++) {
		el->values[i].data = talloc_memdup(el->values, bval[i]->bv_val, bval[i]->bv_len);
		if (!el->values[i].data) {
			return -1;
		}
		el->values[i].length = bval[i]->bv_len;
		el->num_values++;
	}

	msg->num_elements++;

	return 0;
}

/*
  search for matching records
*/
static int lldb_search_async(struct ldb_module *module, const struct ldb_dn *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs,
			      struct ldb_control **control_req,
			      void *context,
			      int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			      int timeout,
			      struct ldb_async_handle **handle)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct lldb_async_context *lldb_ac;
	struct timeval tv;
	int ldap_scope;
	char *search_base;
	char *expression;
	int ret;

	if (!callback || !context) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Async interface called with NULL callback function or NULL context"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (tree == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Invalid expression parse tree"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (control_req != NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "Controls are not yet supported by ldb_ldap backend!\n");
	}

	*handle = init_handle(lldb, module, context, callback, timeout);
	if (*handle == NULL) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lldb_ac = talloc_get_type((*handle)->private_data, struct lldb_async_context);

	search_base = ldb_dn_linearize(lldb_ac, base);
	if (base == NULL) {
		search_base = talloc_strdup(lldb_ac, "");
	}
	if (search_base == NULL) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	expression = ldb_filter_from_tree(lldb_ac, tree);
	if (expression == NULL) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	switch (scope) {
	case LDB_SCOPE_BASE:
		ldap_scope = LDAP_SCOPE_BASE;
		break;
	case LDB_SCOPE_ONELEVEL:
		ldap_scope = LDAP_SCOPE_ONELEVEL;
		break;
	default:
		ldap_scope = LDAP_SCOPE_SUBTREE;
		break;
	}

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	ret = ldap_search_ext(lldb->ldap, search_base, ldap_scope, 
			    expression, 
			    discard_const_p(char *, attrs), 
			    0,
			    NULL,
			    NULL,
			    &tv,
			    LDAP_NO_LIMIT,
			    &lldb_ac->msgid);

	if (ret != LDAP_SUCCESS) {
		ldb_set_errstring(module->ldb, talloc_strdup(module, ldap_err2string(ret)));
		talloc_free(*handle);
		*handle = NULL;
	}

	return lldb_ldap_to_ldb(ret);
}

static int lldb_search_sync_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
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

	if (ares->type == LDB_REPLY_DONE) {
		if (ares->controls) {
			res->controls = talloc_steal(res, ares->controls);
			if (! res->controls) {
				goto error;
			}
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
static int lldb_search_bytree(struct ldb_module *module, const struct ldb_dn *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs,
			      struct ldb_control **control_req,
			      struct ldb_result **res)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct ldb_async_handle *handle;
	int ret;

	*res = talloc_zero(lldb, struct ldb_result);
	if (! *res) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = lldb_search_async(module, base, scope, tree, attrs, control_req,
				res, &lldb_search_sync_callback, lldb->timeout, &handle);

	if (ret == LDB_SUCCESS) {
		ret = ldb_async_wait(handle, LDB_WAIT_ALL);
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
static int lldb_add_async(struct ldb_module *module, const struct ldb_message *msg,
			  void *context,
			  int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			  int timeout,
			  struct ldb_async_handle **handle)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct lldb_async_context *lldb_ac;
	LDAPMod **mods;
	char *dn;
	int ret;

	/* ltdb specials should not reach this point */
	if (ldb_dn_is_special(msg->dn)) {
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	*handle = init_handle(lldb, module, context, callback, timeout);
	if (*handle == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lldb_ac = talloc_get_type((*handle)->private_data, struct lldb_async_context);

	mods = lldb_msg_to_mods(lldb_ac, msg, 0);
	if (mods == NULL) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dn = ldb_dn_linearize(lldb_ac, msg->dn);
	if (dn == NULL) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldap_add_ext(lldb->ldap, dn, mods,
			   NULL,
			   NULL,
			   &lldb_ac->msgid);

	if (ret != LDAP_SUCCESS) {
		ldb_set_errstring(module->ldb, talloc_strdup(module, ldap_err2string(ret)));
		talloc_free(*handle);
	}

	return lldb_ldap_to_ldb(ret);
}

static int lldb_add(struct ldb_module *module, const struct ldb_message *msg)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct ldb_async_handle *handle;
	int ret;

	/* ldap does not understand ltdb specials */
	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	ret = lldb_add_async(module, msg, NULL, NULL, lldb->timeout, &handle);

	if (ret != LDB_SUCCESS)
		return ret;

	ret = ldb_async_wait(handle, LDB_WAIT_ALL);

	talloc_free(handle);
	return ret;
}


/*
  modify a record
*/
static int lldb_modify_async(struct ldb_module *module, const struct ldb_message *msg,
			     void *context,
			     int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			     int timeout,
			     struct ldb_async_handle **handle)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct lldb_async_context *lldb_ac;
	LDAPMod **mods;
	char *dn;
	int ret;

	/* ltdb specials should not reach this point */
	if (ldb_dn_is_special(msg->dn)) {
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	*handle = init_handle(lldb, module, context, callback, timeout);
	if (*handle == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lldb_ac = talloc_get_type((*handle)->private_data, struct lldb_async_context);

	mods = lldb_msg_to_mods(lldb_ac, msg, 1);
	if (mods == NULL) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dn = ldb_dn_linearize(lldb_ac, msg->dn);
	if (dn == NULL) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldap_modify_ext(lldb->ldap, dn, mods,
			      NULL,
			      NULL,
			      &lldb_ac->msgid);

	if (ret != LDAP_SUCCESS) {
		ldb_set_errstring(module->ldb, talloc_strdup(module, ldap_err2string(ret)));
		talloc_free(*handle);
	}

	return lldb_ldap_to_ldb(ret);
}

static int lldb_modify(struct ldb_module *module, const struct ldb_message *msg)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct ldb_async_handle *handle;
	int ret;

	/* ldap does not understand ltdb specials */
	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	ret = lldb_modify_async(module, msg, NULL, NULL, lldb->timeout, &handle);

	if (ret != LDB_SUCCESS)
		return ret;

	ret = ldb_async_wait(handle, LDB_WAIT_ALL);

	talloc_free(handle);
	return ret;
}

/*
  delete a record
*/
static int lldb_delete_async(struct ldb_module *module, const struct ldb_dn *dn,
			     void *context,
			     int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			     int timeout,
			     struct ldb_async_handle **handle)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct lldb_async_context *lldb_ac;
	char *dnstr;
	int ret;
	
	/* ltdb specials should not reach this point */
	if (ldb_dn_is_special(dn)) {
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	*handle = init_handle(lldb, module, context, callback, timeout);
	if (*handle == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lldb_ac = talloc_get_type((*handle)->private_data, struct lldb_async_context);

	dnstr = ldb_dn_linearize(lldb_ac, dn);

	ret = ldap_delete_ext(lldb->ldap, dnstr,
			      NULL,
			      NULL,
			      &lldb_ac->msgid);

	if (ret != LDAP_SUCCESS) {
		ldb_set_errstring(module->ldb, talloc_strdup(module, ldap_err2string(ret)));
		talloc_free(*handle);
	}

	return lldb_ldap_to_ldb(ret);
}

static int lldb_delete(struct ldb_module *module, const struct ldb_dn *dn)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct ldb_async_handle *handle;
	int ret;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(dn)) {
		return LDB_SUCCESS;
	}

	ret = lldb_delete_async(module, dn, NULL, NULL, lldb->timeout, &handle);

	if (ret != LDB_SUCCESS)
		return ret;

	ret = ldb_async_wait(handle, LDB_WAIT_ALL);

	talloc_free(handle);
	return ret;
}

/*
  rename a record
*/
static int lldb_rename_async(struct ldb_module *module,
			     const struct ldb_dn *olddn, const struct ldb_dn *newdn,
			     void *context,
			     int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
			     int timeout,
			     struct ldb_async_handle **handle)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct lldb_async_context *lldb_ac;
	char *old_dn;
       	char *newrdn;
	char *parentdn;
	int ret;
	
	/* ltdb specials should not reach this point */
	if (ldb_dn_is_special(olddn) || ldb_dn_is_special(newdn)) {
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	*handle = init_handle(lldb, module, context, callback, timeout);
	if (*handle == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lldb_ac = talloc_get_type((*handle)->private_data, struct lldb_async_context);

	old_dn = ldb_dn_linearize(lldb_ac, olddn);
	if (old_dn == NULL) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	newrdn = talloc_asprintf(lldb_ac, "%s=%s",
				      newdn->components[0].name,
				      ldb_dn_escape_value(lldb, newdn->components[0].value));
	if (!newrdn) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	parentdn = ldb_dn_linearize(lldb_ac, ldb_dn_get_parent(lldb_ac, newdn));
	if (!parentdn) {
		talloc_free(*handle);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldap_rename(lldb->ldap, old_dn, newrdn, parentdn,
			  1, NULL, NULL,
			  &lldb_ac->msgid);

	if (ret != LDAP_SUCCESS) {
		ldb_set_errstring(module->ldb, talloc_strdup(module, ldap_err2string(ret)));
		talloc_free(*handle);
	}

	return lldb_ldap_to_ldb(ret);
}

static int lldb_rename(struct ldb_module *module, const struct ldb_dn *olddn, const struct ldb_dn *newdn)
{
	struct lldb_private *lldb = talloc_get_type(module->private_data, struct lldb_private);
	struct ldb_async_handle *handle;
	int ret;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(olddn) || ldb_dn_is_special(newdn)) {
		return LDB_SUCCESS;
	}

	ret = lldb_rename_async(module, olddn, newdn, NULL, NULL, lldb->timeout, &handle);

	if (ret != LDB_SUCCESS)
		return ret;

	ret = ldb_async_wait(handle, LDB_WAIT_ALL);

	talloc_free(handle);
	return ret;
}

static int lldb_parse_result(struct ldb_async_handle *handle, LDAPMessage *result)
{
	struct lldb_async_context *ac = talloc_get_type(handle->private_data, struct lldb_async_context);
	struct lldb_private *lldb = talloc_get_type(ac->module->private_data, struct lldb_private);
	struct ldb_async_result *ares = NULL;
	LDAPMessage *msg;
	int type;
	char *matcheddnp = NULL;
	char *errmsgp = NULL;
	char **referralsp = NULL;
	LDAPControl **serverctrlsp = NULL;
	int ret;

	type = ldap_msgtype(result);

	switch (type) {

	case LDAP_RES_SEARCH_ENTRY:
		msg = ldap_first_entry(lldb->ldap, result);
	       	if (msg != NULL) {
			BerElement *berptr = NULL;
			char *attr, *dn;

			ares = talloc_zero(ac, struct ldb_async_result);
			if (!ares) {
				handle->status = LDB_ERR_OPERATIONS_ERROR;
				goto error;
			}

			ares->message = ldb_msg_new(ares);
			if (!ares->message) {
				handle->status = LDB_ERR_OPERATIONS_ERROR;
				goto error;
			}

			dn = ldap_get_dn(lldb->ldap, msg);
			if (!dn) {
				handle->status = LDB_ERR_OPERATIONS_ERROR;
				goto error;
			}
			ares->message->dn = ldb_dn_explode_or_special(ares->message, dn);
			if (ares->message->dn == NULL) {
				handle->status = LDB_ERR_OPERATIONS_ERROR;
				goto error;
			}
			ldap_memfree(dn);

			ares->message->num_elements = 0;
			ares->message->elements = NULL;
			ares->message->private_data = NULL;

			/* loop over all attributes */
			for (attr=ldap_first_attribute(lldb->ldap, msg, &berptr);
			     attr;
			     attr=ldap_next_attribute(lldb->ldap, msg, berptr)) {
				struct berval **bval;
				bval = ldap_get_values_len(lldb->ldap, msg, attr);

				if (bval) {
					lldb_add_msg_attr(ac->module->ldb, ares->message, attr, bval);
					ldap_value_free_len(bval);
				}					  
			}
			if (berptr) ber_free(berptr, 0);


			ares->type = LDB_REPLY_ENTRY;
			handle->state = LDB_ASYNC_PENDING;
			ret = ac->callback(ac->module->ldb, ac->context, ares);
			if (ret != LDB_SUCCESS) {
				handle->status = ret;
			}
		} else {
			handle->status = LDB_ERR_PROTOCOL_ERROR;
			handle->state = LDB_ASYNC_DONE;
		}
		break;

	case LDAP_RES_SEARCH_REFERENCE:
		if (ldap_parse_result(lldb->ldap, result, &handle->status,
					&matcheddnp, &errmsgp,
					&referralsp, &serverctrlsp, 1) != LDAP_SUCCESS) {
			handle->status = LDB_ERR_OPERATIONS_ERROR;
			goto error;
		}
		if (referralsp == NULL) {
			handle->status = LDB_ERR_PROTOCOL_ERROR;
			goto error;
		}

		ares = talloc_zero(ac, struct ldb_async_result);
		if (!ares) {
			handle->status = LDB_ERR_OPERATIONS_ERROR;
			goto error;
		}

		ares->referral = talloc_strdup(ares, *referralsp);
		ares->type = LDB_REPLY_REFERRAL;
		handle->state = LDB_ASYNC_PENDING;
		ret = ac->callback(ac->module->ldb, ac->context, ares);
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
		}

		break;

	case LDAP_RES_SEARCH_RESULT:
		if (ldap_parse_result(lldb->ldap, result, &handle->status,
					&matcheddnp, &errmsgp,
					&referralsp, &serverctrlsp, 1) != LDAP_SUCCESS) {
			handle->status = LDB_ERR_OPERATIONS_ERROR;
			goto error;
		}

		ares = talloc_zero(ac, struct ldb_async_result);
		if (!ares) {
			handle->status = LDB_ERR_OPERATIONS_ERROR;
			goto error;
		}

		if (serverctrlsp != NULL) {
			/* FIXME: transform the LDAPControl list into an ldb_control one */
			ares->controls = NULL;
		}
		
		ares->type = LDB_REPLY_DONE;
		handle->state = LDB_ASYNC_DONE;
		ret = ac->callback(ac->module->ldb, ac->context, ares);
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
		}

		break;

	case LDAP_RES_MODIFY:
	case LDAP_RES_ADD:
	case LDAP_RES_DELETE:
	case LDAP_RES_MODDN:
		if (ldap_parse_result(lldb->ldap, result, &handle->status,
					&matcheddnp, &errmsgp,
					&referralsp, &serverctrlsp, 1) != LDAP_SUCCESS) {
			handle->status = LDB_ERR_OPERATIONS_ERROR;
			goto error;
		}
		if (ac->callback && handle->status == LDB_SUCCESS) {
			ares = NULL; /* FIXME: build a corresponding ares to pass on */
			handle->status = ac->callback(ac->module->ldb, ac->context, ares);
		}
		handle->state = LDB_ASYNC_DONE;
		break;

	default:
		handle->status = LDB_ERR_PROTOCOL_ERROR;
		goto error;
	}

	if (matcheddnp) ldap_memfree(matcheddnp);
	if (errmsgp) {
		ldb_set_errstring(ac->module->ldb, talloc_strdup(ac->module, errmsgp));
		ldap_memfree(errmsgp);
	}
	if (referralsp) ldap_value_free(referralsp);
	if (serverctrlsp) ldap_controls_free(serverctrlsp);

	ldap_msgfree(result);
	return handle->status;

error:
	handle->state = LDB_ASYNC_DONE;
	ldap_msgfree(result);
	return handle->status;
}

static int lldb_async_wait(struct ldb_async_handle *handle, enum ldb_async_wait_type type)
{
	struct lldb_async_context *ac = talloc_get_type(handle->private_data, struct lldb_async_context);
	struct lldb_private *lldb = talloc_get_type(handle->module->private_data, struct lldb_private);
	struct timeval timeout;
	LDAPMessage *result;
	int ret = LDB_ERR_OPERATIONS_ERROR;

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	if (!ac || !ac->msgid) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	handle->status = LDB_SUCCESS;

	switch(type) {
	case LDB_WAIT_NONE:
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;
		ret = ldap_result(lldb->ldap, ac->msgid, 0, &timeout, &result);
		if (ret == -1) {
			handle->status = LDB_ERR_OPERATIONS_ERROR;
			return handle->status;
		}
		if (ret == 0) {
			handle->status = LDB_SUCCESS;
			return handle->status;
		}
		ret = lldb_parse_result(handle, result);
		break;
	case LDB_WAIT_ALL:
		timeout.tv_sec = ac->timeout;
		timeout.tv_usec = 0;
		while (handle->status == LDB_SUCCESS && handle->state != LDB_ASYNC_DONE) {
			ret = ldap_result(lldb->ldap, ac->msgid, 0, &timeout, &result);
			if (ret == -1 || ret == 0) {
				handle->status = LDB_ERR_OPERATIONS_ERROR;
				return handle->status;
			}
			ret = lldb_parse_result(handle, result);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
		break;
	}

	return ret;
}

static int lldb_start_trans(struct ldb_module *module)
{
	/* TODO implement a local transaction mechanism here */

	return 0;
}

static int lldb_end_trans(struct ldb_module *module)
{
	/* TODO implement a local transaction mechanism here */

	return 0;
}

static int lldb_del_trans(struct ldb_module *module)
{
	/* TODO implement a local transaction mechanism here */

	return 0;
}

static int lldb_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return lldb_search_bytree(module,
					  req->op.search.base,
					  req->op.search.scope, 
					  req->op.search.tree, 
					  req->op.search.attrs, 
					  req->controls,
					  &req->op.search.res);

	case LDB_REQ_ADD:
		return lldb_add(module, req->op.add.message);

	case LDB_REQ_MODIFY:
		return lldb_modify(module, req->op.mod.message);

	case LDB_REQ_DELETE:
		return lldb_delete(module, req->op.del.dn);

	case LDB_REQ_RENAME:
		return lldb_rename(module,
					req->op.rename.olddn,
					req->op.rename.newdn);

	case LDB_ASYNC_SEARCH:
		return lldb_search_async(module,
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
		return lldb_add_async(module,
					req->op.add.message,
					req->async.context,
					req->async.callback,
					req->async.timeout,
					&req->async.handle);

	case LDB_ASYNC_MODIFY:
		return lldb_modify_async(module,
					req->op.mod.message,
					req->async.context,
					req->async.callback,
					req->async.timeout,
					&req->async.handle);

	case LDB_ASYNC_DELETE:
		return lldb_delete_async(module,
					req->op.del.dn,
					req->async.context,
					req->async.callback,
					req->async.timeout,
					&req->async.handle);

	case LDB_ASYNC_RENAME:
		return lldb_rename_async(module,
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

static const struct ldb_module_ops lldb_ops = {
	.name              = "ldap",
	.request           = lldb_request,
	.start_transaction = lldb_start_trans,
	.end_transaction   = lldb_end_trans,
	.del_transaction   = lldb_del_trans,
	.async_wait        = lldb_async_wait
};


static int lldb_destructor(void *p)
{
	struct lldb_private *lldb = p;
	ldap_unbind(lldb->ldap);
	return 0;
}

/*
  connect to the database
*/
static int lldb_connect(struct ldb_context *ldb,
		 const char *url, 
		 unsigned int flags, 
		 const char *options[])
{
	struct lldb_private *lldb = NULL;
	int version = 3;
	int ret;

	lldb = talloc(ldb, struct lldb_private);
	if (!lldb) {
		ldb_oom(ldb);
		goto failed;
	}

	lldb->ldap = NULL;
	lldb->timeout = 120; /* TODO: get timeout from options ? */

	ret = ldap_initialize(&lldb->ldap, url);
	if (ret != LDAP_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "ldap_initialize failed for URL '%s' - %s\n",
			  url, ldap_err2string(ret));
		goto failed;
	}

	talloc_set_destructor(lldb, lldb_destructor);

	ret = ldap_set_option(lldb->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (ret != LDAP_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "ldap_set_option failed - %s\n",
			  ldap_err2string(ret));
		goto failed;
	}

	ldb->modules = talloc(ldb, struct ldb_module);
	if (!ldb->modules) {
		ldb_oom(ldb);
		goto failed;
	}
	ldb->modules->ldb = ldb;
	ldb->modules->prev = ldb->modules->next = NULL;
	ldb->modules->private_data = lldb;
	ldb->modules->ops = &lldb_ops;

	return 0;

failed:
	talloc_free(lldb);
	return -1;
}

int ldb_ldap_init(void)
{
	return ldb_register_backend("ldap", lldb_connect) +
		   ldb_register_backend("ldapi", lldb_connect) + 
		   ldb_register_backend("ldaps", lldb_connect);
}
