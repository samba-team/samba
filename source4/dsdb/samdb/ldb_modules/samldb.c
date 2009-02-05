/*
   SAM ldb module

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Simo Sorce  2004-2008

   * NOTICE: this module is NOT released under the GNU LGPL license as
   * other ldb code. This module is release under the GNU GPL v3 or
   * later license.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb samldb module
 *
 *  Description: add embedded user/group creation functionality
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "libcli/ldap/ldap_ndr.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "../lib/util/util_ldb.h"
#include "ldb_wrap.h"

struct samldb_ctx;

typedef int (*samldb_step_fn_t)(struct samldb_ctx *);

struct samldb_step {
	struct samldb_step *next;
	samldb_step_fn_t fn;
};

struct samldb_ctx {
	struct ldb_module *module;
	struct ldb_request *req;

	/* the resulting message */
	struct ldb_message *msg;

	/* used to apply templates */
	const char *type;

	/* used to find parent domain */
	struct ldb_dn *check_dn;
	struct ldb_dn *domain_dn;
	struct dom_sid *domain_sid;
	uint32_t next_rid;

	/* generic storage, remember to zero it before use */
	struct ldb_reply *ares;

	/* holds the entry SID */
	struct dom_sid *sid;

	/* all the async steps necessary to complete the operation */
	struct samldb_step *steps;
	struct samldb_step *curstep;
};

static struct samldb_ctx *samldb_ctx_init(struct ldb_module *module,
					  struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct samldb_ctx);
	if (ac == NULL) {
		ldb_oom(ldb);
		return NULL;
	}

	ac->module = module;
	ac->req = req;

	return ac;
}

static int samldb_add_step(struct samldb_ctx *ac, samldb_step_fn_t fn)
{
	struct samldb_step *step;

	step = talloc_zero(ac, struct samldb_step);
	if (step == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ac->steps == NULL) {
		ac->steps = step;
		ac->curstep = step;
	} else {
		ac->curstep->next = step;
		ac->curstep = step;
	}

	step->fn = fn;

	return LDB_SUCCESS;
}

static int samldb_first_step(struct samldb_ctx *ac)
{
	if (ac->steps == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->curstep = ac->steps;
	return ac->curstep->fn(ac);
}

static int samldb_next_step(struct samldb_ctx *ac)
{
	if (ac->curstep->next) {
		ac->curstep = ac->curstep->next;
		return ac->curstep->fn(ac);
	}

	/* it is an error if the last step does not properly
	 * return to the upper module by itself */
	return LDB_ERR_OPERATIONS_ERROR;
}

static int samldb_search_template_callback(struct ldb_request *req,
					   struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	int ret;

	ac = talloc_get_type(req->context, struct samldb_ctx);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		/* save entry */
		if (ac->ares != NULL) {
			/* one too many! */
			ldb_set_errstring(ldb,
				"Invalid number of results while searching "
				"for template objects");
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto done;
		}

		ac->ares = talloc_steal(ac, ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:

		talloc_free(ares);
		ret = samldb_next_step(ac);
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

static int samldb_search_template(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct tevent_context *ev;
	struct loadparm_context *lparm_ctx;
	struct ldb_context *templates_ldb;
	char *templates_ldb_path;
	struct ldb_request *req;
	struct ldb_dn *basedn;
	void *opaque;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	opaque = ldb_get_opaque(ldb, "loadparm");
	lparm_ctx = talloc_get_type(opaque, struct loadparm_context);
	if (lparm_ctx == NULL) {
		ldb_set_errstring(ldb,
			"Unable to find loadparm context\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	opaque = ldb_get_opaque(ldb, "templates_ldb");
	templates_ldb = talloc_get_type(opaque,	struct ldb_context);

	/* make sure we have the templates ldb */
	if (!templates_ldb) {
		templates_ldb_path = samdb_relative_path(ldb, ac,
							 "templates.ldb");
		if (!templates_ldb_path) {
			ldb_set_errstring(ldb,
					"samldb_init_template: ERROR: Failed "
					"to contruct path for template db");
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ev = ldb_get_event_context(ldb);

		templates_ldb = ldb_wrap_connect(ldb, ev,
						lparm_ctx, templates_ldb_path,
						NULL, NULL, 0, NULL);
		talloc_free(templates_ldb_path);

		if (!templates_ldb) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (!talloc_reference(templates_ldb, ev)) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = ldb_set_opaque(ldb,
					"templates_ldb", templates_ldb);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* search template */
	basedn = ldb_dn_new_fmt(ac, templates_ldb,
			    "cn=Template%s,cn=Templates", ac->type);
	if (basedn == NULL) {
		ldb_set_errstring(ldb,
			"samldb_init_template: ERROR: Failed "
			"to contruct DN for template");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* pull the template record */
	ret = ldb_build_search_req(&req, templates_ldb, ac,
				   basedn, LDB_SCOPE_BASE,
				  "(distinguishedName=*)", NULL,
				  NULL,
				  ac, samldb_search_template_callback,
				  ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_steal(req, basedn);
	ac->ares = NULL;

	return ldb_request(templates_ldb, req);
}

static int samldb_apply_template(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_message_element *el;
	struct ldb_message *msg;
	int i, j;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);
	msg = ac->ares->message;

	for (i = 0; i < msg->num_elements; i++) {
		el = &msg->elements[i];
		/* some elements should not be copied */
		if (ldb_attr_cmp(el->name, "cn") == 0 ||
		    ldb_attr_cmp(el->name, "name") == 0 ||
		    ldb_attr_cmp(el->name, "objectClass") == 0 ||
		    ldb_attr_cmp(el->name, "sAMAccountName") == 0 ||
		    ldb_attr_cmp(el->name, "sAMAccountName") == 0 ||
		    ldb_attr_cmp(el->name, "distinguishedName") == 0 ||
		    ldb_attr_cmp(el->name, "objectGUID") == 0) {
			continue;
		}
		for (j = 0; j < el->num_values; j++) {
			ret = samdb_find_or_add_attribute(
					ldb, ac->msg, el->name,
					(char *)el->values[j].data);
			if (ret != LDB_SUCCESS) {
				ldb_set_errstring(ldb,
					  "Failed adding template attribute\n");
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
	}

	return samldb_next_step(ac);
}

static int samldb_get_parent_domain(struct samldb_ctx *ac);

static int samldb_get_parent_domain_callback(struct ldb_request *req,
					     struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	const char *nextRid;
	int ret;

	ac = talloc_get_type(req->context, struct samldb_ctx);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		/* save entry */
		if (ac->domain_dn != NULL) {
			/* one too many! */
			ldb_set_errstring(ldb,
				"Invalid number of results while searching "
				"for domain object");
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}

		nextRid = ldb_msg_find_attr_as_string(ares->message,
						      "nextRid", NULL);
		if (nextRid == NULL) {
			ldb_asprintf_errstring(ldb,
				"while looking for domain above %s attribute nextRid not found in %s\n",
					       ldb_dn_get_linearized(ac->req->op.add.message->dn), 
					       ldb_dn_get_linearized(ares->message->dn));
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}

		ac->next_rid = strtol(nextRid, NULL, 0);

		ac->domain_sid = samdb_result_dom_sid(ac, ares->message,
								"objectSid");
		if (ac->domain_sid == NULL) {
			ldb_set_errstring(ldb,
				"error retrieving parent domain domain sid!\n");
			ret = LDB_ERR_CONSTRAINT_VIOLATION;
			break;
		}
		ac->domain_dn = talloc_steal(ac, ares->message->dn);

		talloc_free(ares);
		ret = LDB_SUCCESS;
		ldb_reset_err_string(ldb);
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:

		talloc_free(ares);
		if (ac->domain_dn == NULL) {
			/* search again */
			ret = samldb_get_parent_domain(ac);
		} else {
			/* found, go on */
			ret = samldb_next_step(ac);
		}
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

/* Find a domain object in the parents of a particular DN.  */
static int samldb_get_parent_domain(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	static const char * const attrs[3] = { "objectSid", "nextRid", NULL };
	struct ldb_request *req;
	struct ldb_dn *dn;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->check_dn == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dn = ldb_dn_get_parent(ac, ac->check_dn);
	if (dn == NULL) {
		ldb_set_errstring(ldb,
			"Unable to find parent domain object");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	ac->check_dn = dn;

	ret = ldb_build_search_req(&req, ldb, ac,
				   dn, LDB_SCOPE_BASE,
				   "(|(objectClass=domain)"
				     "(objectClass=builtinDomain)"
				     "(objectClass=samba4LocalDomain))",
				   attrs,
				   NULL,
				   ac, samldb_get_parent_domain_callback,
				   ac->req);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, req);
}

static int samldb_generate_samAccountName(struct ldb_message *msg)
{
	char *name;

	/* Format: $000000-000000000000 */

	name = talloc_asprintf(msg, "$%.6X-%.6X%.6X",
				(unsigned int)generate_random(),
				(unsigned int)generate_random(),
				(unsigned int)generate_random());
	if (name == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return ldb_msg_add_steal_string(msg, "samAccountName", name);
}

static int samldb_check_samAccountName_callback(struct ldb_request *req,
						struct ldb_reply *ares)
{
	struct samldb_ctx *ac;
	int ret;

	ac = talloc_get_type(req->context, struct samldb_ctx);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:

		/* if we get an entry it means this samAccountName
		 * already exists */
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_ENTRY_ALREADY_EXISTS);

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:

		/* not found, go on */
		talloc_free(ares);
		ret = samldb_next_step(ac);
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

static int samldb_check_samAccountName(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	const char *name;
	char *filter;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if (ldb_msg_find_element(ac->msg, "samAccountName") == NULL) {
		ret = samldb_generate_samAccountName(ac->msg);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	name = ldb_msg_find_attr_as_string(ac->msg, "samAccountName", NULL);
	if (name == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	filter = talloc_asprintf(ac, "samAccountName=%s", name);
	if (filter == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb, ac,
				ac->domain_dn, LDB_SCOPE_SUBTREE,
				filter, NULL,
				NULL,
				ac, samldb_check_samAccountName_callback,
				ac->req);
	talloc_free(filter);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ac->ares = NULL;
	return ldb_next_request(ac->module, req);
}

static int samldb_check_samAccountType(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	unsigned int account_type;
	unsigned int group_type;
	unsigned int uac;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	/* make sure sAMAccountType is not specified */
	if (ldb_msg_find_element(ac->msg, "sAMAccountType") != NULL) {
		ldb_asprintf_errstring(ldb,
					"sAMAccountType must not be specified");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if (strcmp("user", ac->type) == 0) {
		uac = samdb_result_uint(ac->msg, "userAccountControl", 0);
		if (uac == 0) {
			ldb_asprintf_errstring(ldb,
						"userAccountControl invalid");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		} else {
			account_type = samdb_uf2atype(uac);
			ret = samdb_msg_add_uint(ldb,
						 ac->msg, ac->msg,
						 "sAMAccountType",
						 account_type);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	} else
	if (strcmp("group", ac->type) == 0) {

		group_type = samdb_result_uint(ac->msg, "groupType", 0);
		if (group_type == 0) {
			ldb_asprintf_errstring(ldb,
						"groupType invalid");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		} else {
			account_type = samdb_gtype2atype(group_type);
			ret = samdb_msg_add_uint(ldb,
						 ac->msg, ac->msg,
						 "sAMAccountType",
						 account_type);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}

	return samldb_next_step(ac);
}

static int samldb_get_sid_domain_callback(struct ldb_request *req,
					  struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	const char *nextRid;
	int ret;

	ac = talloc_get_type(req->context, struct samldb_ctx);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		/* save entry */
		if (ac->next_rid != 0) {
			/* one too many! */
			ldb_set_errstring(ldb,
				"Invalid number of results while searching "
				"for domain object");
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}

		nextRid = ldb_msg_find_attr_as_string(ares->message,
							"nextRid", NULL);
		if (nextRid == NULL) {
			ldb_asprintf_errstring(ldb,
				"attribute nextRid not found in %s\n",
				ldb_dn_get_linearized(ares->message->dn));
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}

		ac->next_rid = strtol(nextRid, NULL, 0);

		ac->domain_dn = talloc_steal(ac, ares->message->dn);

		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:

		if (ac->next_rid == 0) {
			ldb_asprintf_errstring(ldb,
				"Unable to get nextRid from domain entry\n");
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}

		/* found, go on */
		ret = samldb_next_step(ac);
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

/* Find a domain object in the parents of a particular DN.  */
static int samldb_get_sid_domain(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	static const char * const attrs[2] = { "nextRid", NULL };
	struct ldb_request *req;
	char *filter;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->sid == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->domain_sid = dom_sid_dup(ac, ac->sid);
	if (!ac->domain_sid) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* get the domain component part of the provided SID */
	ac->domain_sid->num_auths--;

	filter = talloc_asprintf(ac, "(&(objectSid=%s)"
				       "(|(objectClass=domain)"
				         "(objectClass=builtinDomain)"
				         "(objectClass=samba4LocalDomain)))",
				 ldap_encode_ndr_dom_sid(ac, ac->domain_sid));
	if (filter == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb, ac,
				   ldb_get_default_basedn(ldb),
				   LDB_SCOPE_SUBTREE,
				   filter, attrs,
				   NULL,
				   ac, samldb_get_sid_domain_callback,
				   ac->req);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->next_rid = 0;
	return ldb_next_request(ac->module, req);
}

static bool samldb_msg_add_sid(struct ldb_message *msg,
				const char *name,
				const struct dom_sid *sid)
{
	struct ldb_val v;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_blob(&v, msg, NULL, sid,
				       (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}
	return (ldb_msg_add_value(msg, name, &v, NULL) == 0);
}

static int samldb_new_sid(struct samldb_ctx *ac)
{

	if (ac->domain_sid == NULL || ac->next_rid == 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->sid = dom_sid_add_rid(ac, ac->domain_sid, ac->next_rid + 1);
	if (ac->sid == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if ( ! samldb_msg_add_sid(ac->msg, "objectSid", ac->sid)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return samldb_next_step(ac);
}

static int samldb_check_sid_callback(struct ldb_request *req,
				     struct ldb_reply *ares)
{
	struct samldb_ctx *ac;
	int ret;

	ac = talloc_get_type(req->context, struct samldb_ctx);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:

		/* if we get an entry it means an object with the
		 * requested sid exists */
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_CONSTRAINT_VIOLATION);

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		break;

	case LDB_REPLY_DONE:

		/* not found, go on */
		talloc_free(ares);
		ret = samldb_next_step(ac);
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

static int samldb_check_sid(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	const char *const attrs[2] = { "objectSid", NULL };
	struct ldb_request *req;
	char *filter;
	int ret;

	if (ac->sid == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb = ldb_module_get_ctx(ac->module);

	filter = talloc_asprintf(ac, "(objectSid=%s)",
				 ldap_encode_ndr_dom_sid(ac, ac->sid));
	if (filter == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb, ac,
				   ldb_get_default_basedn(ldb),
				   LDB_SCOPE_SUBTREE,
				   filter, attrs,
				   NULL,
				   ac, samldb_check_sid_callback,
				   ac->req);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, req);
}

static int samldb_notice_sid_callback(struct ldb_request *req,
					struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	int ret;

	ac = talloc_get_type(req->context, struct samldb_ctx);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}
	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb,
			"Invalid reply type!\n");
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = samldb_next_step(ac);

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

/* If we are adding new users/groups, we need to update the nextRid
 * attribute to be 'above' the new/incoming RID. Attempt to do it
 *atomically. */
static int samldb_notice_sid(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	uint32_t old_id, new_id;
	struct ldb_request *req;
	struct ldb_message *msg;
	struct ldb_message_element *els;
	struct ldb_val *vals;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);
	old_id = ac->next_rid;
	new_id = ac->sid->sub_auths[ac->sid->num_auths - 1];

	if (old_id >= new_id) {
		/* no need to update the domain nextRid attribute */
		return samldb_next_step(ac);
	}

	/* we do a delete and add as a single operation. That prevents
	   a race, in case we are not actually on a transaction db */
	msg = talloc_zero(ac, struct ldb_message);
	if (msg == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	els = talloc_array(msg, struct ldb_message_element, 2);
	if (els == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	vals = talloc_array(msg, struct ldb_val, 2);
	if (vals == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	msg->dn = ac->domain_dn;
	msg->num_elements = 2;
	msg->elements = els;

	els[0].num_values = 1;
	els[0].values = &vals[0];
	els[0].flags = LDB_FLAG_MOD_DELETE;
	els[0].name = talloc_strdup(msg, "nextRid");
	if (!els[0].name) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	els[1].num_values = 1;
	els[1].values = &vals[1];
	els[1].flags = LDB_FLAG_MOD_ADD;
	els[1].name = els[0].name;

	vals[0].data = (uint8_t *)talloc_asprintf(vals, "%u", old_id);
	if (!vals[0].data) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	vals[0].length = strlen((char *)vals[0].data);

	vals[1].data = (uint8_t *)talloc_asprintf(vals, "%u", new_id);
	if (!vals[1].data) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	vals[1].length = strlen((char *)vals[1].data);

	ret = ldb_build_mod_req(&req, ldb, ac,
				msg, NULL,
				ac, samldb_notice_sid_callback,
				ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, req);
}

static int samldb_add_entry_callback(struct ldb_request *req,
					struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;

	ac = talloc_get_type(req->context, struct samldb_ctx);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}
	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb,
			"Invalid reply type!\n");
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	/* we exit the samldb module here */
	return ldb_module_done(ac->req, ares->controls,
				ares->response, LDB_SUCCESS);
}

static int samldb_add_entry(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	ret = ldb_build_add_req(&req, ldb, ac,
				ac->msg,
				ac->req->controls,
				ac, samldb_add_entry_callback,
				ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, req);
}

static int samldb_fill_object(struct samldb_ctx *ac, const char *type)
{
	int ret;

	/* first look for the template */
	ac->type = type;
	ret = samldb_add_step(ac, samldb_search_template);
	if (ret != LDB_SUCCESS) return ret;

	/* then apply it */
	ret = samldb_add_step(ac, samldb_apply_template);
	if (ret != LDB_SUCCESS) return ret;

	/* search for a parent domain objet */
	ac->check_dn = ac->req->op.add.message->dn;
	ret = samldb_add_step(ac, samldb_get_parent_domain);
	if (ret != LDB_SUCCESS) return ret;

	/* check if we have a valid samAccountName */
	ret = samldb_add_step(ac, samldb_check_samAccountName);
	if (ret != LDB_SUCCESS) return ret;

	/* check account_type/group_type */
	ret = samldb_add_step(ac, samldb_check_samAccountType);
	if (ret != LDB_SUCCESS) return ret;

	/* check if we have a valid SID */
	ac->sid = samdb_result_dom_sid(ac, ac->msg, "objectSid");
	if ( ! ac->sid) {
		ret = samldb_add_step(ac, samldb_new_sid);
		if (ret != LDB_SUCCESS) return ret;
	} else {
		ret = samldb_add_step(ac, samldb_get_sid_domain);
		if (ret != LDB_SUCCESS) return ret;
	}

	ret = samldb_add_step(ac, samldb_check_sid);
	if (ret != LDB_SUCCESS) return ret;

	ret = samldb_add_step(ac, samldb_notice_sid);
	if (ret != LDB_SUCCESS) return ret;

	/* finally proceed with adding the entry */
	ret = samldb_add_step(ac, samldb_add_entry);
	if (ret != LDB_SUCCESS) return ret;

	return samldb_first_step(ac);

	/* TODO: userAccountControl, badPwdCount, codePage,
	 *	 countryCode, badPasswordTime, lastLogoff, lastLogon,
	 *	 pwdLastSet, primaryGroupID, accountExpires, logonCount */

}

static int samldb_foreign_notice_sid_callback(struct ldb_request *req,
						struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	const char *nextRid;
	const char *name;
	int ret;

	ac = talloc_get_type(req->context, struct samldb_ctx);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		/* save entry */
		if (ac->next_rid != 0) {
			/* one too many! */
			ldb_set_errstring(ldb,
				"Invalid number of results while searching "
				"for domain object");
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}

		nextRid = ldb_msg_find_attr_as_string(ares->message,
							"nextRid", NULL);
		if (nextRid == NULL) {
			ldb_asprintf_errstring(ldb,
				"while looking for forign sid %s attribute nextRid not found in %s\n",
					       dom_sid_string(ares, ac->sid), ldb_dn_get_linearized(ares->message->dn));
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}

		ac->next_rid = strtol(nextRid, NULL, 0);

		ac->domain_dn = talloc_steal(ac, ares->message->dn);

		name = samdb_result_string(ares->message, "name", NULL);
		ldb_debug(ldb, LDB_DEBUG_TRACE,
			 "NOTE (strange but valid): Adding foreign SID "
			 "record with SID %s, but this domain (%s) is "
			 "not foreign in the database",
			 dom_sid_string(ares, ac->sid), name);

		talloc_free(ares);
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		break;

	case LDB_REPLY_DONE:

		/* if this is a fake foreign SID, notice the SID */
		if (ac->domain_dn) {
			ret = samldb_notice_sid(ac);
			break;
		}

		/* found, go on */
		ret = samldb_next_step(ac);
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

/* Find a domain object in the parents of a particular DN. */
static int samldb_foreign_notice_sid(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	static const char * const attrs[3] = { "nextRid", "name", NULL };
	struct ldb_request *req;
	NTSTATUS status;
	char *filter;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->sid == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	status = dom_sid_split_rid(ac, ac->sid, &ac->domain_sid, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	filter = talloc_asprintf(ac, "(&(objectSid=%s)(objectclass=domain))",
				 ldap_encode_ndr_dom_sid(ac, ac->domain_sid));
	if (filter == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb, ac,
				   ldb_get_default_basedn(ldb),
				   LDB_SCOPE_SUBTREE,
				   filter, attrs,
				   NULL,
				   ac, samldb_foreign_notice_sid_callback,
				   ac->req);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->next_rid = 0;
	return ldb_next_request(ac->module, req);
}

static int samldb_fill_foreignSecurityPrincipal_object(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	ac->sid = samdb_result_dom_sid(ac->msg, ac->msg, "objectSid");
	if (ac->sid == NULL) {
		ac->sid = dom_sid_parse_talloc(ac->msg,
			   (const char *)ldb_dn_get_rdn_val(ac->msg->dn)->data);
		if (!ac->sid) {
			ldb_set_errstring(ldb,
					"No valid found SID in "
					"ForeignSecurityPrincipal CN!");
			talloc_free(ac);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ( ! samldb_msg_add_sid(ac->msg, "objectSid", ac->sid)) {
			talloc_free(ac);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/* first look for the template */
	ac->type = "foreignSecurityPrincipal";
	ret = samldb_add_step(ac, samldb_search_template);
	if (ret != LDB_SUCCESS) return ret;

	/* then apply it */
	ret = samldb_add_step(ac, samldb_apply_template);
	if (ret != LDB_SUCCESS) return ret;

	/* check we do not already have this SID */
	ret = samldb_add_step(ac, samldb_check_sid);
	if (ret != LDB_SUCCESS) return ret;

	/* check if we need to notice this SID */
	ret = samldb_add_step(ac, samldb_foreign_notice_sid);
	if (ret != LDB_SUCCESS) return ret;

	/* finally proceed with adding the entry */
	ret = samldb_add_step(ac, samldb_add_entry);
	if (ret != LDB_SUCCESS) return ret;

	return samldb_first_step(ac);
}

static int samldb_check_rdn(struct ldb_module *module, struct ldb_dn *dn)
{
	struct ldb_context *ldb;
	const char *rdn_name;

	ldb = ldb_module_get_ctx(module);
	rdn_name = ldb_dn_get_rdn_name(dn);

	if (strcasecmp(rdn_name, "cn") != 0) {
		ldb_asprintf_errstring(ldb,
					"Bad RDN (%s=) for samldb object, "
					"should be CN=!\n", rdn_name);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	return LDB_SUCCESS;
}

/* add_record */
static int samldb_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	int ret;

	ldb = ldb_module_get_ctx(module);
	ldb_debug(ldb, LDB_DEBUG_TRACE, "samldb_add_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	ac = samldb_ctx_init(module, req);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* build the new msg */
	ac->msg = ldb_msg_copy(ac, ac->req->op.add.message);
	if (!ac->msg) {
		talloc_free(ac);
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "samldb_add: ldb_msg_copy failed!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "computer") != NULL) {

		/* make sure the computer object also has the 'user'
		 * objectclass so it will be handled by the next call */
		ret = samdb_find_or_add_value(ldb, ac->msg,
						"objectclass", "user");
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "user") != NULL) {

		ret = samldb_check_rdn(module, ac->req->op.add.message->dn);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}

		return samldb_fill_object(ac, "user");
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "group") != NULL) {

		ret = samldb_check_rdn(module, ac->req->op.add.message->dn);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}

		return samldb_fill_object(ac, "group");
	}

	/* perhaps a foreignSecurityPrincipal? */
	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass",
				 "foreignSecurityPrincipal") != NULL) {

		ret = samldb_check_rdn(module, ac->req->op.add.message->dn);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}

		return samldb_fill_foreignSecurityPrincipal_object(ac);
	}

	talloc_free(ac);

	/* nothing matched, go on */
	return ldb_next_request(module, req);
}

/* modify */
static int samldb_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_message *msg;
	struct ldb_message_element *el, *el2;
	int ret;
	unsigned int group_type, user_account_control, account_type;
	if (ldb_dn_is_special(req->op.mod.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	if (ldb_msg_find_element(req->op.mod.message, "sAMAccountType") != NULL) {
		ldb_asprintf_errstring(ldb, "sAMAccountType must not be specified");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* TODO: do not modify original request, create a new one */

	el = ldb_msg_find_element(req->op.mod.message, "groupType");
	if (el && el->flags & (LDB_FLAG_MOD_ADD|LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		req->op.mod.message = msg = ldb_msg_copy_shallow(req, req->op.mod.message);

		group_type = strtoul((const char *)el->values[0].data, NULL, 0);
		account_type =  samdb_gtype2atype(group_type);
		ret = samdb_msg_add_uint(ldb, msg, msg,
					 "sAMAccountType",
					 account_type);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el2 = ldb_msg_find_element(msg, "sAMAccountType");
		el2->flags = LDB_FLAG_MOD_REPLACE;
	}

	el = ldb_msg_find_element(req->op.mod.message, "userAccountControl");
	if (el && el->flags & (LDB_FLAG_MOD_ADD|LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		req->op.mod.message = msg = ldb_msg_copy_shallow(req, req->op.mod.message);

		user_account_control = strtoul((const char *)el->values[0].data, NULL, 0);
		account_type = samdb_uf2atype(user_account_control);
		ret = samdb_msg_add_uint(ldb, msg, msg,
					 "sAMAccountType",
					 account_type);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el2 = ldb_msg_find_element(msg, "sAMAccountType");
		el2->flags = LDB_FLAG_MOD_REPLACE;
	}
	return ldb_next_request(module, req);
}


static int samldb_init(struct ldb_module *module)
{
	return ldb_next_init(module);
}

_PUBLIC_ const struct ldb_module_ops ldb_samldb_module_ops = {
	.name          = "samldb",
	.init_context  = samldb_init,
	.add           = samldb_add,
	.modify        = samldb_modify
};
