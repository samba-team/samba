/* 
   ldb database library

   Copyright (C) Simo Sorce  2005-2008

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
 *  Name: paged_searches
 *
 *  Component: ldb paged searches module
 *
 *  Description: this module detects if the remote ldap server supports
 *               paged results and use them to transparently access all objects
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb_module.h"

#define PS_DEFAULT_PAGE_SIZE 500
/* 500 objects per query seem to be a decent compromise
 * the default AD limit per request is 1000 entries */

struct private_data {

	bool paged_supported;
};

struct ps_context {
	struct ldb_module *module;
	struct ldb_request *req;

	bool pending;

	char **saved_referrals;
	int num_referrals;
};

static int check_ps_continuation(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ps_context *ac;
	struct ldb_paged_control *rep_control, *req_control;

	ac = talloc_get_type(req->context, struct ps_context);

	/* look up our paged control */
	if (!ares->controls || strcmp(LDB_CONTROL_PAGED_RESULTS_OID, ares->controls[0]->oid) != 0) {
		/* something wrong here */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	rep_control = talloc_get_type(ares->controls[0]->data, struct ldb_paged_control);
	if (rep_control->cookie_len == 0) {
		/* we are done */
		ac->pending = false;
		return LDB_SUCCESS;
	}

	/* more processing required */
	/* let's fill in the request control with the new cookie */
	/* if there's a reply control we must find a request
	 * control matching it */

	if (strcmp(LDB_CONTROL_PAGED_RESULTS_OID, req->controls[0]->oid) != 0) {
		/* something wrong here */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req_control = talloc_get_type(req->controls[0]->data, struct ldb_paged_control);

	if (req_control->cookie) {
		talloc_free(req_control->cookie);
	}

	req_control->cookie = talloc_memdup(req_control,
					    rep_control->cookie,
					    rep_control->cookie_len);
	req_control->cookie_len = rep_control->cookie_len;

	ac->pending = true;
	return LDB_SUCCESS;
}

static int store_referral(struct ps_context *ac, char *referral)
{
	ac->saved_referrals = talloc_realloc(ac, ac->saved_referrals, char *, ac->num_referrals + 2);
	if (!ac->saved_referrals) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->saved_referrals[ac->num_referrals] = talloc_strdup(ac->saved_referrals, referral);
	if (!ac->saved_referrals[ac->num_referrals]) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->num_referrals++;
	ac->saved_referrals[ac->num_referrals] = NULL;

	return LDB_SUCCESS;
}

static int send_referrals(struct ps_context *ac)
{
	struct ldb_reply *ares;
	int ret;
	int i;

	for (i = 0; i < ac->num_referrals; i++) {
		ares = talloc_zero(ac->req, struct ldb_reply);
		if (!ares) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ares->type = LDB_REPLY_REFERRAL;
		ares->referral = ac->saved_referrals[i];

		ret = ldb_module_send_referral(ac->req, ares->referral);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

static int ps_next_request(struct ps_context *ac);

static int ps_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ps_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct ps_context);

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
		ret = ldb_module_send_entry(ac->req, ares->message, ares->controls);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		break;

	case LDB_REPLY_REFERRAL:
		ret = store_referral(ac, ares->referral);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		break;

	case LDB_REPLY_DONE:

		ret = check_ps_continuation(req, ares);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}

		if (ac->pending) {

			ret = ps_next_request(ac);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req,
							NULL, NULL, ret);
			}

		} else {

			/* send referrals */
			ret = send_referrals(ac);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req,
							NULL, NULL, ret);
			}

			/* send REPLY_DONE */
			return ldb_module_done(ac->req, ares->controls,
						ares->response, LDB_SUCCESS);
		}
		break;
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

static int ps_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct private_data *private_data;
	struct ps_context *ac;

	private_data = talloc_get_type(ldb_module_get_private(module), struct private_data);
	ldb = ldb_module_get_ctx(module);

	/* check if paging is supported and if there is a any control */
	if (!private_data || !private_data->paged_supported || req->controls) {
		/* do not touch this request paged controls not
		 * supported or explicit controls have been set or we
		 * are just not setup yet */
		return ldb_next_request(module, req);
	}

	ac = talloc_zero(req, struct ps_context);
	if (ac == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;
	ac->pending = false;
	ac->saved_referrals = NULL;
	ac->num_referrals = 0;

	return ps_next_request(ac);
}

static int ps_next_request(struct ps_context *ac) {

	struct ldb_context *ldb;
	struct ldb_paged_control *control;
	struct ldb_control **controls;
	struct ldb_request *new_req;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	controls = talloc_array(ac, struct ldb_control *, 2);
	if (!controls) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	controls[0] = talloc(controls, struct ldb_control);
	if (!controls[0]) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	control = talloc(controls[0], struct ldb_paged_control);
	if (!control) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	control->size = PS_DEFAULT_PAGE_SIZE;
	control->cookie = NULL;
	control->cookie_len = 0;

	controls[0]->oid = LDB_CONTROL_PAGED_RESULTS_OID;
	controls[0]->critical = 1;
	controls[0]->data = control;
	controls[1] = NULL;

	ret = ldb_build_search_req_ex(&new_req, ldb, ac,
					ac->req->op.search.base,
					ac->req->op.search.scope,
					ac->req->op.search.tree,
					ac->req->op.search.attrs,
					controls,
					ac,
					ps_callback,
					ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	talloc_steal(new_req, controls);

	return ldb_next_request(ac->module, new_req);
}

static int check_supported_paged(struct ldb_request *req,
				 struct ldb_reply *ares)
{
	struct private_data *data;

	data = talloc_get_type(req->context, struct private_data);

	if (!ares) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (ldb_msg_check_string_attribute(ares->message,
						   "supportedControl",
						   LDB_CONTROL_PAGED_RESULTS_OID)) {
			data->paged_supported = true;
		}
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		break;

	case LDB_REPLY_DONE:
		return ldb_request_done(req, LDB_SUCCESS);
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

static int ps_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	static const char *attrs[] = { "supportedControl", NULL };
	struct private_data *data;
	struct ldb_dn *base;
	int ret;
	struct ldb_request *req;

	ldb = ldb_module_get_ctx(module);

	data = talloc(module, struct private_data);
	if (data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	data->paged_supported = false;

	ldb_module_set_private(module, data);

	base = ldb_dn_new(module, ldb, "");
	if (base == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_build_search_req(&req, ldb, module,
				   base, LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL,
				   data, check_supported_paged,
				   NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_next_request(module, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_free(base);
	talloc_free(req);

	return ldb_next_init(module);
}

_PUBLIC_ const struct ldb_module_ops ldb_paged_searches_module_ops = {
	.name           = "paged_searches",
	.search         = ps_search,
	.init_context 	= ps_init
};
