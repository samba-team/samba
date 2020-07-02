/*
   ldb database library

   Copyright (C) Simo Sorce  2005-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: paged_result
 *
 *  Component: ldb paged results control module
 *
 *  Description: this module caches a complete search and sends back
 *  		 results in chunks as asked by the client
 *
 *  Author: Garming Sam and Aaron Haslett
 *
 *  Note: Based on the original paged_results.c by Simo Sorce and
 *        vlv_pagination.c by Douglas Bagnall and Garming Sam.
 */

#include "includes.h"
#include "auth/auth.h"
#include <ldb.h>
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "libcli/ldap/ldap_errors.h"
#include "replace.h"
#include "system/filesys.h"
#include "system/time.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"

#include "dsdb/common/util.h"
#include "lib/util/dlinklist.h"

/* Referrals are temporarily stored in a linked list */
struct referral_store {
	char *ref;
	struct referral_store *next;
};

struct private_data;

struct results_store {
	struct results_store *prev, *next;

	struct private_data *priv;

	char *cookie;
	time_t timestamp;

	struct referral_store *first_ref;
	struct referral_store *last_ref;

	struct ldb_control **controls;

	/* from VLV */
	struct GUID *results;
	size_t num_entries;
	size_t result_array_size;

	struct ldb_control **down_controls;
	const char * const *attrs;

	unsigned last_i;
	struct ldb_parse_tree *expr;
	char *expr_str;
};

struct private_data {
	uint32_t next_free_id;
	size_t num_stores;
	struct results_store *store;
};

static int store_destructor(struct results_store *del)
{
	struct private_data *priv = del->priv;
	DLIST_REMOVE(priv->store, del);

	priv->num_stores -= 1;

	return 0;
}

static struct results_store *new_store(struct private_data *priv)
{
	struct results_store *newr;
	uint32_t new_id = priv->next_free_id++;

	/* TODO: we should have a limit on the number of
	 * outstanding paged searches
	 */

	newr = talloc_zero(priv, struct results_store);
	if (!newr) return NULL;

	newr->priv = priv;

	newr->cookie = talloc_asprintf(newr, "%d", new_id);
	if (!newr->cookie) {
		talloc_free(newr);
		return NULL;
	}

	newr->timestamp = time(NULL);

	DLIST_ADD(priv->store, newr);

	priv->num_stores += 1;

	talloc_set_destructor(newr, store_destructor);

	if (priv->num_stores > 10) {
		struct results_store *last;
		/*
		 * 10 is the default for MaxResultSetsPerConn --
		 * possibly need to parameterize it.
		 */
		last = DLIST_TAIL(priv->store);
		TALLOC_FREE(last);
	}

	return newr;
}

struct paged_context {
	struct ldb_module *module;
	struct ldb_request *req;

	struct results_store *store;
	int size;
	struct ldb_control **controls;
};

static int send_referrals(struct results_store *store,
			  struct ldb_request *req)
{
	int ret;
	struct referral_store *node;
	while (store->first_ref != NULL) {
		node = store->first_ref;
		ret = ldb_module_send_referral(req, node->ref);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		store->first_ref = node->next;
		talloc_free(node);
	}
	return LDB_SUCCESS;
}

/* Start an ldb request for a single object by GUID */
static int paged_search_by_dn_guid(struct ldb_module *module,
				 struct paged_context *ac,
				 struct ldb_result **result,
				 const struct GUID *guid,
				 const char * const *attrs,
				 struct ldb_parse_tree *expr)
{
	struct ldb_dn *dn;
	struct ldb_request *req;
	struct ldb_result *res;
	int ret;
	struct GUID_txt_buf guid_str;

	/* Use controls passed in on the downreq */
	struct ldb_control **controls = ac->store->down_controls;

	struct ldb_context *ldb = ldb_module_get_ctx(module);

	dn = ldb_dn_new_fmt(ac, ldb, "<GUID=%s>",
			    GUID_buf_string(guid, &guid_str));
	if (dn == NULL) {
		return ldb_oom(ldb);
	}

	res = talloc_zero(ac, struct ldb_result);
	if (res == NULL) {
		TALLOC_FREE(dn);
		return ldb_oom(ldb);
	}

	ret = ldb_build_search_req_ex(&req, ldb, ac,
				   dn,
				   LDB_SCOPE_BASE,
				   expr,
				   attrs,
				   controls,
				   res,
				   ldb_search_default_callback,
				   ac->req);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(dn);
		TALLOC_FREE(res);
		return ret;
	}

	/*
	 * Ensure the dn lasts only as long as the request,
	 * as we will have a lot of these (one per object
	 * being returned)
	 */

	talloc_steal(req, dn);

	ret = ldb_request(ldb, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	talloc_free(req);
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		return ret;
	}

	*result = res;
	return ret;
}

static int paged_results(struct paged_context *ac, struct ldb_reply *ares)
{
	struct ldb_paged_control *paged;
	unsigned int i, num_ctrls;
	int ret;

	if (ac->store == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}

	while (ac->store->last_i < ac->store->num_entries && ac->size > 0) {
		struct GUID *guid = &ac->store->results[ac->store->last_i++];
		struct ldb_result *result = NULL;

		ac->size--;

		/*
		 * Note: In the case that an object has been moved to a
		 * different place in the LDAP tree, we might expect the object
		 * to disappear from paged results.  If we were going to
		 * implement that behaviour, we would do it here by passing
		 * down the original container DN to the search.
		 * However, testing shows that, on Windows, the moved object
		 * remains in the paged results. So, we are matching Windows
		 * behaviour here by leaving out the scope.
		 */
		ret = paged_search_by_dn_guid(ac->module, ac, &result, guid,
					    ac->req->op.search.attrs,
					    ac->store->expr);
		if (ret == LDAP_NO_SUCH_OBJECT ||
		    (ret == LDB_SUCCESS && result->count == 0)) {
			/* The thing isn't there TODO, which we quietly
			   ignore and go on to send an extra one
			   instead. */
			continue;
		} else if (ret != LDB_SUCCESS) {
			return ldb_module_done(
				ac->req, ac->controls, ares->response, ret);
		}

		ret = ldb_module_send_entry(ac->req, result->msgs[0],
					    NULL);
		if (ret != LDB_SUCCESS) {
			/*
			 * ldb_module_send_entry will have called
			 * ldb_module_done if an error occurred.
			 */
			return ret;
		}
	}

	if (ac->store->first_ref) {
		/* There is no right place to put references in the sorted
		   results, so we send them as soon as possible.
		*/
		ret = send_referrals(ac->store, ac->req);
		if (ret != LDB_SUCCESS) {
			/*
			 * send_referrals will have called ldb_module_done
			 * if an error occurred.
			 */
			return ret;
		}
	}

	/* return result done */
	num_ctrls = 1;
	i = 0;

	if (ac->store->controls != NULL) {
		while (ac->store->controls[i]) i++; /* counting */

		num_ctrls += i;
	}

	ac->controls = talloc_array(ac, struct ldb_control *, num_ctrls +1);
	if (ac->controls == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}
	ac->controls[num_ctrls] = NULL;

	for (i = 0; i < (num_ctrls -1); i++) {
		ac->controls[i] = talloc_reference(ac->controls,
						   ac->store->controls[i]);
	}

	ac->controls[i] = talloc(ac->controls, struct ldb_control);
	if (ac->controls[i] == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}

	ac->controls[i]->oid = talloc_strdup(ac->controls[i],
						LDB_CONTROL_PAGED_RESULTS_OID);
	if (ac->controls[i]->oid == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}

	ac->controls[i]->critical = 0;

	paged = talloc(ac->controls[i], struct ldb_paged_control);
	if (paged == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}

	ac->controls[i]->data = paged;

	if (ac->size > 0) {
		paged->size = 0;
		paged->cookie = NULL;
		paged->cookie_len = 0;
	} else {
		paged->size = ac->store->num_entries;
		paged->cookie = talloc_strdup(paged, ac->store->cookie);
		paged->cookie_len = strlen(paged->cookie) + 1;
	}

	return LDB_SUCCESS;
}

static int save_referral(struct results_store *store, char *ref)
{
	struct referral_store *node = talloc(store,
					     struct referral_store);
	if (node == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	node->next = NULL;
	node->ref = talloc_steal(node, ref);

	if (store->first_ref == NULL) {
		store->first_ref = node;
	} else {
		store->last_ref->next = node;
	}
	store->last_ref = node;
	return LDB_SUCCESS;
}

static int paged_search_callback(struct ldb_request *req,
				 struct ldb_reply *ares)
{
	struct paged_context *ac;
	struct results_store *store;
	int ret;
	const struct ldb_val *guid_blob;
	struct GUID guid;
	NTSTATUS status;

	ac = talloc_get_type(req->context, struct paged_context);
	store = ac->store;

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (store->results == NULL) {
			store->num_entries = 0;
			store->result_array_size = 16;
			store->results = talloc_array(store, struct GUID,
						     store->result_array_size);
			if (store->results == NULL) {
				return ldb_module_done(ac->req, NULL, NULL,
						     LDB_ERR_OPERATIONS_ERROR);
			}
		} else if (store->num_entries == store->result_array_size) {
			if (store->result_array_size > INT_MAX/2) {
				return ldb_module_done(ac->req, NULL, NULL,
						     LDB_ERR_OPERATIONS_ERROR);
			}
			store->result_array_size *= 2;
			store->results = talloc_realloc(store, store->results,
							struct GUID,
						store->result_array_size);
			if (store->results == NULL) {
				return ldb_module_done(ac->req, NULL, NULL,
						     LDB_ERR_OPERATIONS_ERROR);
			}
		}

		guid_blob = ldb_dn_get_extended_component(ares->message->dn,
							  "GUID");
		if (guid_blob == NULL) {
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_OPERATIONS_ERROR);
		}
		status = GUID_from_ndr_blob(guid_blob, &guid);
		if (!NT_STATUS_IS_OK(status)) {
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_OPERATIONS_ERROR);
		}

		/* Redundant paranoid check */
		if (store->num_entries > store->result_array_size) {
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_OPERATIONS_ERROR);
		}

		store->results[store->num_entries] = guid;
		store->num_entries++;
		break;

	case LDB_REPLY_REFERRAL:
		ret = save_referral(store, ares->referral);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		break;

	case LDB_REPLY_DONE:
		if (store->num_entries != 0) {
			store->results = talloc_realloc(store, store->results,
							struct GUID,
							store->num_entries);
			if (store->results == NULL) {
				return ldb_module_done(ac->req, NULL, NULL,
						     LDB_ERR_OPERATIONS_ERROR);
			}
		}
		store->result_array_size = store->num_entries;

		ac->store->controls = talloc_move(ac->store, &ares->controls);
		ret = paged_results(ac, ares);
		if (ret != LDB_SUCCESS) {
			/* paged_results will have called ldb_module_done
			 * if an error occurred
			 */
			return ret;
		}
		return ldb_module_done(ac->req, ac->controls,
					ares->response, ret);
	}

	return LDB_SUCCESS;
}

static struct ldb_control **
paged_results_copy_down_controls(TALLOC_CTX *mem_ctx,
				 struct ldb_control **controls)
{

	struct ldb_control **new_controls;
	unsigned int i, j, num_ctrls;
	if (controls == NULL) {
		return NULL;
	}

	for (num_ctrls = 0; controls[num_ctrls]; num_ctrls++);

	new_controls = talloc_array(mem_ctx, struct ldb_control *, num_ctrls);
	if (new_controls == NULL) {
		return NULL;
	}

	for (j = 0, i = 0; i < (num_ctrls); i++) {
		struct ldb_control *control = controls[i];
		if (control->oid == NULL) {
			continue;
		}
		if (strcmp(control->oid, LDB_CONTROL_PAGED_RESULTS_OID) == 0) {
			continue;
		}
		/*
		 * ASQ changes everything, do not copy it down for the
		 * per-GUID search
		 */
		if (strcmp(control->oid, LDB_CONTROL_ASQ_OID) == 0) {
			continue;
		}
		new_controls[j] = talloc_steal(new_controls, control);

		/*
		 * Sadly the caller is not obliged to make this a
		 * proper talloc tree, so we do so here.
		 */
		if (control->data) {
			talloc_steal(control, control->data);
		}
		j++;
	}
	new_controls[j] = NULL;
	return new_controls;
}

static const char * const *paged_copy_attrs(TALLOC_CTX *mem_ctx,
					    const char * const *attrs) {
	int i;
	const char **new_attrs;
	if (attrs == NULL) {
		return NULL;
	}
	new_attrs = ldb_attr_list_copy(mem_ctx, attrs);

	for (i=0; attrs[i] != NULL; i++) {
		new_attrs[i] = talloc_strdup(mem_ctx, attrs[i]);
	}
	new_attrs[i] = NULL;
	return new_attrs;
}

/*
 * Check if two sets of controls are the same except for the paged results
 * control in the request controls.  This function is messy because request
 * control lists can contain controls that were NULL'd by the rootdse.  We
 * must ignore those entries.  This function is not portable.
 */
static bool paged_controls_same(struct ldb_request *req,
				struct ldb_control **down_controls) {
	int i;
	unsigned int num_down_controls, num_non_null_req_controls;
	struct ldb_control *ctrl;

	num_down_controls = 0;
	for (i=0; down_controls[i] != NULL; i++) {
		num_down_controls++;

		ctrl = ldb_request_get_control(req, down_controls[i]->oid);
		if (ctrl == NULL) {
			return false;
		}
	}

	num_non_null_req_controls = 0;
	for (i=0; req->controls[i] != NULL; i++) {
		if (req->controls[i]->oid != NULL &&
		    strcmp(req->controls[i]->oid,
			   LDB_CONTROL_ASQ_OID) != 0) {
			num_non_null_req_controls++;
		}
	}

	/* At this point we have the number of non-null entries for both
	 * control lists and we know that:
	 * 1. down_controls does not contain the paged control or ASQ
	 * 	(because paged_results_copy_down_controls excludes it)
	 * 2. req->controls does contain the paged control
	 * 	(because this function is only called if this is true)
	 * 3. down_controls is a subset of non-null controls in req->controls
	 * 	(checked above)
	 * So to confirm that the two lists are identical except for the paged
	 * control and possibly ASQ, all we need to check is: */
	if (num_non_null_req_controls == num_down_controls + 1) {
		return true;
	}
	return false;
}

static bool paged_attrs_same(const char * const *attrs_1,
			     const char * const *attrs_2) {
	int i;
	if (attrs_1 == NULL || attrs_2 == NULL) {
		if (attrs_1 == NULL && attrs_2 == NULL) {
			return true;
		}
		return false;
	}

	for (i=0; attrs_1[i] != NULL; i++) {
	       if (!ldb_attr_in_list(attrs_2, attrs_1[i])) {
		       return false;
	       }
	}
	return true;
}

static int paged_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_control *control;
	struct ldb_control *vlv_control;
	struct private_data *private_data;
	struct ldb_paged_control *paged_ctrl;
	struct ldb_request *search_req;
	struct paged_context *ac;
	int ret;

	ldb = ldb_module_get_ctx(module);

	/* check if there's a paged request control */
	control = ldb_request_get_control(req, LDB_CONTROL_PAGED_RESULTS_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	paged_ctrl = talloc_get_type(control->data, struct ldb_paged_control);
	if (!paged_ctrl) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

	private_data = talloc_get_type(ldb_module_get_private(module),
					struct private_data);

	vlv_control = ldb_request_get_control(req, LDB_CONTROL_VLV_REQ_OID);
	if (vlv_control != NULL) {
		/*
		 * VLV and paged_results are not allowed at the same
		 * time
		 */
		return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
	}

	ac = talloc_zero(req, struct paged_context);
	if (ac == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;
	ac->size = paged_ctrl->size;
	if (ac->size < 0) {
		/*
		 * Apparently some clients send more than 2^31. This
		 * violates the ldap standard, but we need to cope.
		 * In the future, if maximum result sizes are implemented in
		 * Samba, we should also clamp the page size to the maximum
		 * result size.
		 */
		ac->size = 0x7FFFFFFF;
	}

	/* check if it is a continuation search the store */
	if (paged_ctrl->cookie_len == 0) {
		struct ldb_control *ext_ctrl;
		struct ldb_control **controls;
		static const char * const attrs[1] = { NULL };

		if (paged_ctrl->size == 0) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ac->store = new_store(private_data);
		if (ac->store == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		controls = req->controls;
		ext_ctrl = ldb_request_get_control(req,
					LDB_CONTROL_EXTENDED_DN_OID);
		if (ext_ctrl == NULL) {
			/*
			 * Add extended_dn control to the request if there
			 * isn't already one.  We'll get the GUID out of it in
			 * the callback.  This is a workaround for the case
			 * where ntsecuritydescriptor forbids fetching GUIDs
			 * for the current user.
			 */
			struct ldb_request *req_extended_dn;
			struct ldb_extended_dn_control *ext_ctrl_data;
			req_extended_dn = talloc_zero(req, struct ldb_request);
			req_extended_dn->controls = req->controls;
			ext_ctrl_data = talloc_zero(req,
					struct ldb_extended_dn_control);
			ext_ctrl_data->type = 1;

			ret = ldb_request_add_control(req_extended_dn,
					      LDB_CONTROL_EXTENDED_DN_OID,
						      true,
						      ext_ctrl_data);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			controls = req_extended_dn->controls;
		}

		ret = ldb_build_search_req_ex(&search_req, ldb, ac,
						req->op.search.base,
						req->op.search.scope,
						req->op.search.tree,
						attrs,
						controls,
						ac,
						paged_search_callback,
						req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ac->store->expr = talloc_steal(ac->store, req->op.search.tree);
		ac->store->expr_str = ldb_filter_from_tree(ac->store,
							  req->op.search.tree);
		ac->store->attrs = paged_copy_attrs(ac->store,
						    req->op.search.attrs);

		/* save it locally and remove it from the list */
		/* we do not need to replace them later as we
		 * are keeping the original req intact */
		if (!ldb_save_controls(control, search_req, NULL)) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ac->store->down_controls =
		    paged_results_copy_down_controls(ac->store, req->controls);
		if (ac->store->down_controls == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		return ldb_next_request(module, search_req);

	} else {
		struct results_store *current = NULL;
		char *expr_str;
		bool bool_ret;

		/* TODO: age out old outstanding requests */
		for (current = private_data->store; current != NULL;
		     current = current->next) {
			if (strcmp(current->cookie, paged_ctrl->cookie) == 0) {
				current->timestamp = time(NULL);
				break;
			}
		}
		if (current == NULL) {
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		/* Get the expression string and make sure it didn't change */
		expr_str = ldb_filter_from_tree(ac, req->op.search.tree);
		if (expr_str == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = strcmp(current->expr_str, expr_str);
		if (ret != 0) {
			return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
		}

		bool_ret = paged_controls_same(req, current->down_controls);
		if (bool_ret == false) {
			return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
		}

		bool_ret = paged_attrs_same(req->op.search.attrs,
					    current->attrs);
		if (bool_ret == false) {
			return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
		}

		DLIST_PROMOTE(private_data->store, current);

		ac->store = current;

		/* check if it is an abandon */
		if (ac->size == 0) {
			return ldb_module_done(req, NULL, NULL,
								LDB_SUCCESS);
		}

		ret = paged_results(ac, NULL);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(req, NULL, NULL, ret);
		}
		return ldb_module_done(req, ac->controls, NULL, LDB_SUCCESS);
	}
}

static int paged_request_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct private_data *data;
	int ret;

	ldb = ldb_module_get_ctx(module);

	data = talloc(module, struct private_data);
	if (data == NULL) {
		return LDB_ERR_OTHER;
	}

	data->next_free_id = 1;
	data->num_stores = 0;
	data->store = NULL;
	ldb_module_set_private(module, data);

	ret = ldb_mod_register_control(module, LDB_CONTROL_PAGED_RESULTS_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			"paged_results:"
			"Unable to register control with rootdse!");
	}

	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_paged_results_module_ops = {
	.name           = "dsdb_paged_results",
	.search         = paged_search,
	.init_context 	= paged_request_init
};

int ldb_dsdb_paged_results_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_paged_results_module_ops);
}
