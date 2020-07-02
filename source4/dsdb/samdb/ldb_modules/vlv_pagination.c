/*
   ldb database library

   Copyright (C) Simo Sorce  2005-2008
   Copyright (C) Catalyst IT 2016

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
 *  Name: vlv_pagination
 *
 *  Component: ldb vlv pagination control module
 *
 *  Description: this module caches a complete search and sends back
 *  		 results in chunks as asked by the client
 *
 *  Originally based on paged_results.c by Simo Sorce
 *  Modified by Douglas Bagnall and Garming Sam for Catalyst.
 */

#include "includes.h"
#include "auth/auth.h"
#include <ldb.h>
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "libcli/ldap/ldap_errors.h"
#include <ldb.h>
#include "replace.h"
#include "system/filesys.h"
#include "system/time.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"

#include "dsdb/common/util.h"
#include "lib/util/binsearch.h"

/* This is the number of concurrent searches per connection to cache. */
#define VLV_N_SEARCHES 5


struct results_store {
	uint32_t contextId;
	time_t timestamp;

	struct GUID *results;
	size_t num_entries;
	size_t result_array_size;

	struct referral_store *first_ref;
	struct referral_store *last_ref;

	struct ldb_control **controls;
	struct ldb_control **down_controls;
	struct ldb_vlv_req_control *vlv_details;
	struct ldb_server_sort_control *sort_details;
};

struct private_data {
	uint32_t next_free_id;
	struct results_store **store;
	int n_stores;
};


struct vlv_context {
	struct ldb_module *module;
	struct ldb_request *req;
	struct results_store *store;
	struct ldb_control **controls;
	struct private_data *priv;
};


static struct results_store *new_store(struct private_data *priv)
{
	struct results_store *store;
	int i;
	int best = 0;
	time_t oldest = TIME_T_MAX;
	for (i = 0; i < priv->n_stores; i++) {
		if (priv->store[i] == NULL) {
			best = i;
			break;
		} else if (priv->store[i]->timestamp < oldest){
			best = i;
			oldest = priv->store[i]->timestamp;
		}
	}

	store = talloc_zero(priv, struct results_store);
	if (store == NULL) {
		return NULL;
	}
	if (priv->store[best] != NULL) {
		TALLOC_FREE(priv->store[best]);
	}
	priv->store[best] = store;
	store->timestamp = time(NULL);
	return store;
}


struct vlv_sort_context {
	struct ldb_context *ldb;
	ldb_attr_comparison_t comparison_fn;
	const char *attr;
	struct vlv_context *ac;
	int status;
	struct ldb_val value;
};


/* Referrals are temporarily stored in a linked list */
struct referral_store {
	char *ref;
	struct referral_store *next;
};

/*
  search for attrs on one DN, by the GUID of the DN, with true
  LDB controls
 */

static int vlv_search_by_dn_guid(struct ldb_module *module,
				 struct vlv_context *ac,
				 struct ldb_result **result,
				 const struct GUID *guid,
				 const char * const *attrs)
{
	struct ldb_dn *dn;
	struct ldb_request *req;
	struct ldb_result *res;
	int ret;
	struct GUID_txt_buf guid_str;
	struct ldb_control **controls = ac->store->down_controls;
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	dn = ldb_dn_new_fmt(ac, ldb, "<GUID=%s>",
			    GUID_buf_string(guid, &guid_str));
	if (dn == NULL) {
		return ldb_oom(ldb);
	}

	res = talloc_zero(ac, struct ldb_result);
	if (res == NULL) {
		return ldb_oom(ldb);
	}

	ret = ldb_build_search_req(&req, ldb, ac,
				   dn,
				   LDB_SCOPE_BASE,
				   NULL,
				   attrs,
				   controls,
				   res,
				   ldb_search_default_callback,
				   ac->req);
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		return ret;
	}

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


/* vlv_value_compare() is used in a binary search */

static int vlv_value_compare(struct vlv_sort_context *target,
			     struct GUID *guid)
{
	struct ldb_result *result = NULL;
	struct ldb_message_element *el = NULL;
	struct vlv_context *ac = target->ac;
	int ret;
	const char *attrs[2] = {
		target->attr,
		NULL
	};

	ret = vlv_search_by_dn_guid(ac->module, ac, &result, guid, attrs);

	if (ret != LDB_SUCCESS) {
		target->status = ret;
		/* returning 0 ends the search. */
		return 0;
	}

	el = ldb_msg_find_element(result->msgs[0], target->attr);
	return target->comparison_fn(target->ldb, ac,
				     &target->value, &el->values[0]);

}

/* The same as vlv_value_compare() but sorting in the opposite direction. */
static int vlv_value_compare_rev(struct vlv_sort_context *target,
			     struct GUID *guid)
{
	return -vlv_value_compare(target, guid);
}



/* Convert a "greater than or equal to" VLV query into an index. This is
   zero-based, so one less than the equivalent VLV offset query.

   If the query value is greater than (or less than in the reverse case) all
   the items, An index just beyond the last position is used.

   If an error occurs during the search for the index, we stash it in the
   status argument.
 */

static int vlv_gt_eq_to_index(struct vlv_context *ac,
			      struct GUID *guid_array,
			      struct ldb_vlv_req_control *vlv_details,
			      struct ldb_server_sort_control *sort_details,
			      int *status)
{
	/* this has a >= comparison string, which needs to be
	 * converted into indices.
	 */
	size_t len = ac->store->num_entries;
	struct ldb_context *ldb;
	const struct ldb_schema_attribute *a;
	struct GUID *result = NULL;
	struct vlv_sort_context context;
	struct ldb_val value = {
		.data = (uint8_t *)vlv_details->match.gtOrEq.value,
		.length = vlv_details->match.gtOrEq.value_len
	};
	ldb = ldb_module_get_ctx(ac->module);
	a = ldb_schema_attribute_by_name(ldb, sort_details->attributeName);

	context = (struct vlv_sort_context){
		.ldb = ldb,
		.comparison_fn = a->syntax->comparison_fn,
		.attr = sort_details->attributeName,
		.ac = ac,
		.status = LDB_SUCCESS,
		.value = value
	};

	if (sort_details->reverse) {
		/* when the sort is reversed, "gtOrEq" means
		   "less than or equal" */
		BINARY_ARRAY_SEARCH_GTE(guid_array, len, &context,
					vlv_value_compare_rev,
					result, result);
	} else {
		BINARY_ARRAY_SEARCH_GTE(guid_array, len, &context,
					vlv_value_compare,
					result, result);
	}
	if (context.status != LDB_SUCCESS) {
		*status = context.status;
		return len;
	}
	*status = LDB_SUCCESS;

	if (result == NULL) {
		/* the target is beyond the end of the array */
		return len;
	}
	return result - guid_array;

}

/* return the zero-based index into the sorted results, or -1 on error.

   The VLV index is one-base, so one greater than this.
 */

static int vlv_calc_real_offset(int offset, int denominator, int n_entries)
{
	double fraction;

	/* An offset of 0 (or less) is an error, unless the denominator is
	   also zero. */
	if (offset <= 0 && denominator != 0) {
		return -1;
	}

	/* a denominator of zero means the server should use the estimated
	   number of entries. */
	if (denominator == 0) {
		if (offset == 0) {
                        /* 0/0 means the last one */
			return n_entries - 1;
		}
		denominator = n_entries;
	}

	if (denominator == 1) {
		/* The 1/1 case means the LAST index.
		   Strangely, for n > 1, n/1 means the FIRST index.
		*/
		if (offset == 1) {
			return n_entries - 1;
		}
		return 0;
	}

	if (offset >= denominator) {
		/* we want the last one */
		return n_entries - 1;
	}
	/* if the denominator is exactly the number of entries, the offset is
	   already correct. */

	if (denominator == n_entries) {
		return offset - 1;
	}

	/* The following formula was discovered by probing Windows. */
	fraction = (offset - 1.0) / (denominator - 1.0);
	return (int)(fraction * (n_entries - 1.0) + 0.5);
}


/* vlv_results() is called when there is a valid contextID -- meaning the search
   has been prepared earlier and saved -- or by vlv_search_callback() when a
   search has just been completed. */

static int vlv_results(struct vlv_context *ac, struct ldb_reply *ares)
{
	struct ldb_vlv_resp_control *vlv;
	unsigned int num_ctrls;
	int ret, i, first_i, last_i;
	struct ldb_vlv_req_control *vlv_details;
	struct ldb_server_sort_control *sort_details;
	int target = 0;

	if (ac->store == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}

	if (ac->store->first_ref) {
		/* There is no right place to put references in the sorted
		   results, so we send them as soon as possible.
		*/
		ret = send_referrals(ac->store, ac->req);
		if (ret != LDB_SUCCESS) {
			/*
			 * send_referrals will have called ldb_module_done
			 * if there was an error.
			 */
			return ret;
		}
	}

	vlv_details = ac->store->vlv_details;
	sort_details = ac->store->sort_details;

	if (ac->store->num_entries != 0) {
		if (vlv_details->type == 1) {
			target = vlv_gt_eq_to_index(ac, ac->store->results,
						    vlv_details,
						    sort_details, &ret);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(
					ac->req,
					ac->controls,
					ares->response,
					ret);
			}
		} else {
			target = vlv_calc_real_offset(vlv_details->match.byOffset.offset,
						      vlv_details->match.byOffset.contentCount,
						      ac->store->num_entries);
			if (target == -1) {
				ret = LDB_ERR_OPERATIONS_ERROR;
				return ldb_module_done(
					ac->req,
					ac->controls,
					ares->response,
					ret);
			}
		}

		/* send the results */
		first_i = MAX(target - vlv_details->beforeCount, 0);
		last_i = MIN(target + vlv_details->afterCount,
			     ac->store->num_entries - 1);

		for (i = first_i; i <= last_i; i++) {
			struct ldb_result *result = NULL;
			struct GUID *guid = &ac->store->results[i];

			ret = vlv_search_by_dn_guid(ac->module, ac, &result, guid,
						    ac->req->op.search.attrs);

			if (ret == LDAP_NO_SUCH_OBJECT
			    || result->count != 1) {
				/*
				 * The thing isn't there, which we quietly
				 * ignore and go on to send an extra one
				 * instead.
				 *
				 * result->count == 0 or > 1 can only
				 * happen if ASQ (which breaks all the
				 * rules) is somehow invoked (as this
				 * is a BASE search).
				 *
				 * (We skip the ASQ cookie for the
				 * GUID searches)
				 */
				if (last_i < ac->store->num_entries - 1) {
					last_i++;
				}
				continue;
			} else if (ret != LDB_SUCCESS) {
				return ldb_module_done(
					ac->req,
					ac->controls,
					ares->response,
					ret);
			}

			ret = ldb_module_send_entry(ac->req, result->msgs[0],
						    NULL);
			if (ret != LDB_SUCCESS) {
				/*
				 * ldb_module_send_entry will have called
				 * ldb_module_done if there was an error
				 */
				return ret;
			}
		}
	} else {
		target = -1;
	}

	/* return result done */
	num_ctrls = 1;
	i = 0;

	if (ac->store->controls != NULL) {
		while (ac->store->controls[i]){
			i++; /* counting */
		}
		num_ctrls += i;
	}

	ac->controls = talloc_array(ac, struct ldb_control *, num_ctrls + 1);
	if (ac->controls == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}
	ac->controls[num_ctrls] = NULL;

	for (i = 0; i < (num_ctrls -1); i++) {
		ac->controls[i] = talloc_reference(ac->controls, ac->store->controls[i]);
	}

	ac->controls[i] = talloc(ac->controls, struct ldb_control);
	if (ac->controls[i] == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}

	ac->controls[i]->oid = talloc_strdup(ac->controls[i],
					     LDB_CONTROL_VLV_RESP_OID);
	if (ac->controls[i]->oid == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}

	ac->controls[i]->critical = 0;

	vlv = talloc(ac->controls[i], struct ldb_vlv_resp_control);
	if (vlv == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		return ldb_module_done(
			ac->req, ac->controls, ares->response, ret);
	}
	ac->controls[i]->data = vlv;

	ac->store->timestamp = time(NULL);

	ac->store->contextId = ac->priv->next_free_id;
	ac->priv->next_free_id++;
	vlv->contextId = talloc_memdup(vlv, &ac->store->contextId, sizeof(uint32_t));
	vlv->ctxid_len = sizeof(uint32_t);
	vlv->vlv_result = 0;
	vlv->contentCount = ac->store->num_entries;
	if (target >= 0) {
		vlv->targetPosition = target + 1;
	} else if (vlv_details->type == 1) {
		vlv->targetPosition = ac->store->num_entries + 1;
	} else {
		vlv->targetPosition = 0;
	}
	return LDB_SUCCESS;
}


/* vlv_search_callback() collects GUIDs found by the original search */

static int vlv_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct vlv_context *ac;
	struct results_store *store;
	int ret;

	ac = talloc_get_type(req->context, struct vlv_context);
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
			store->result_array_size *= 2;
			store->results = talloc_realloc(store, store->results,
							struct GUID,
							store->result_array_size);
			if (store->results == NULL) {
				return ldb_module_done(ac->req, NULL, NULL,
						       LDB_ERR_OPERATIONS_ERROR);
			}
		}
		store->results[store->num_entries] = \
			samdb_result_guid(ares->message, "objectGUID");
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
		ret = vlv_results(ac, ares);
		if (ret != LDB_SUCCESS) {
			/* vlv_results will have called ldb_module_done
			 * if there was an error.
			 */
			return ret;
		}
		return ldb_module_done(ac->req, ac->controls,
					ares->response, ret);
	}

	return LDB_SUCCESS;
}

static int copy_search_details(struct results_store *store,
			       struct ldb_vlv_req_control *vlv_ctrl,
			       struct ldb_server_sort_control *sort_ctrl)
{
	/* free the old details which are no longer going to be reachable. */
	if (store->vlv_details != NULL){
		TALLOC_FREE(store->vlv_details);
	}

	if (store->sort_details != NULL){
		TALLOC_FREE(store->sort_details);
	}

	store->vlv_details = talloc(store, struct ldb_vlv_req_control);
	if (store->vlv_details == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	*store->vlv_details = *vlv_ctrl;
	store->vlv_details->contextId = talloc_memdup(store, vlv_ctrl->contextId,
						      vlv_ctrl->ctxid_len);
	if (store->vlv_details->contextId == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (vlv_ctrl->type == 1) {
		char *v = talloc_array(store, char,
				       vlv_ctrl->match.gtOrEq.value_len + 1);

		if (v == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		memcpy(v, vlv_ctrl->match.gtOrEq.value, vlv_ctrl->match.gtOrEq.value_len);
		v[vlv_ctrl->match.gtOrEq.value_len] = '\0';

		store->vlv_details->match.gtOrEq.value = v;
	}

	store->sort_details = talloc(store, struct ldb_server_sort_control);
	if (store->sort_details == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	store->sort_details->attributeName = talloc_strdup(store,
							   sort_ctrl->attributeName);
	if (store->sort_details->attributeName == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (sort_ctrl->orderingRule == NULL) {
		store->sort_details->orderingRule = NULL;
	} else {
		store->sort_details->orderingRule = talloc_strdup(store,
								  sort_ctrl->orderingRule);
		if (store->sort_details->orderingRule == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}
	store->sort_details->reverse = sort_ctrl->reverse;

	return LDB_SUCCESS;
}


static struct ldb_control **
vlv_copy_down_controls(TALLOC_CTX *mem_ctx, struct ldb_control **controls)
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
			break;
		}
		/*
		 * Do not re-use VLV, nor the server-sort, both are
		 * already handled here.
		 */
		if (strcmp(control->oid, LDB_CONTROL_VLV_REQ_OID) == 0 ||
		    strcmp(control->oid, LDB_CONTROL_SERVER_SORT_OID) == 0) {
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

static int vlv_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_control *control;
	struct ldb_control *sort_control;
	struct private_data *priv;
	struct ldb_vlv_req_control *vlv_ctrl;
	struct ldb_server_sort_control **sort_ctrl;
	struct ldb_request *search_req;
	struct vlv_context *ac;
	int ret, i, critical;

	ldb = ldb_module_get_ctx(module);

	control = ldb_request_get_control(req, LDB_CONTROL_VLV_REQ_OID);
	if (control == NULL) {
		/* There is no VLV. go on */
		return ldb_next_request(module, req);
	}
	critical = control->critical;
	control->critical = 0;

	sort_control = ldb_request_get_control(req, LDB_CONTROL_SERVER_SORT_OID);
	if (sort_control == NULL) {
		/* VLV needs sort */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	vlv_ctrl = talloc_get_type(control->data, struct ldb_vlv_req_control);
	if (vlv_ctrl == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	sort_ctrl = talloc_get_type(sort_control->data, struct ldb_server_sort_control *);
	if (sort_ctrl == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	priv = talloc_get_type(ldb_module_get_private(module),
			       struct private_data);

	ac = talloc_zero(req, struct vlv_context);
	if (ac == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;
	ac->priv = priv;
	/* If there is no cookie, this is a new request, and we need to do the
	 * search in the database. Otherwise we try to refer to a previously
	 * saved search.
	 */
	if (vlv_ctrl->ctxid_len == 0) {
		static const char * const attrs[2] = {
			"objectGUID", NULL
		};

		ac->store = new_store(priv);
		if (ac->store == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = copy_search_details(ac->store, vlv_ctrl, sort_ctrl[0]);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ret = ldb_build_search_req_ex(&search_req, ldb, ac,
					      req->op.search.base,
					      req->op.search.scope,
					      req->op.search.tree,
					      attrs,
					      req->controls,
					      ac,
					      vlv_search_callback,
					      req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		/* save it locally and remove it from the list */
		/* we do not need to replace them later as we
		 * are keeping the original req intact */
		if (!ldb_save_controls(control, search_req, NULL)) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ac->store->down_controls = vlv_copy_down_controls(ac->store,
								  req->controls);

		if (ac->store->down_controls == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		return ldb_next_request(module, search_req);

	} else {
		struct results_store *current = NULL;
		uint8_t *id = vlv_ctrl->contextId;

		if (vlv_ctrl->ctxid_len != sizeof(uint32_t)){
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		for (i = 0; i < priv->n_stores; i++) {
			current = priv->store[i];
			if (current == NULL) {
				continue;
			}
			if (memcmp(&current->contextId, id, sizeof(uint32_t)) == 0) {
				current->timestamp = time(NULL);
				break;
			}
		}
		if (i == priv->n_stores) {
			/* We were given a context id that we don't know about. */
			if (critical) {
				return LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
			} else {
				return ldb_next_request(module, req);
			}
		}

		ac->store = current;
		ret = copy_search_details(ac->store, vlv_ctrl, sort_ctrl[0]);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ret = vlv_results(ac, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		return ldb_module_done(req, ac->controls, NULL,
				       LDB_SUCCESS);
	}
}


static int vlv_request_init(struct ldb_module *module)
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
	data->n_stores = VLV_N_SEARCHES;
	data->store = talloc_zero_array(data, struct results_store *, data->n_stores);

	ldb_module_set_private(module, data);

	ret = ldb_mod_register_control(module, LDB_CONTROL_VLV_REQ_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "vlv:"
			  "Unable to register control with rootdse!");
	}

	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_vlv_module_ops = {
	.name           = "vlv",
	.search         = vlv_search,
	.init_context 	= vlv_request_init
};

int ldb_vlv_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_vlv_module_ops);
}
