/*
   SAM ldb module

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Simo Sorce  2004-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009

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
#include "dsdb/samdb/ldb_modules/util.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "../lib/util/util_ldb.h"
#include "ldb_wrap.h"
#include "param/param.h"

struct samldb_ctx;

typedef int (*samldb_step_fn_t)(struct samldb_ctx *);

struct samldb_step {
	struct samldb_step *next;
	samldb_step_fn_t fn;
};

struct samldb_ctx {
	struct ldb_module *module;
	struct ldb_request *req;

	/* used for add operations */
	const char *type;

	/* the resulting message */
	struct ldb_message *msg;

	/* holds the entry SID */
	struct dom_sid *sid;

	/* holds a generic dn */
	struct ldb_dn *dn;

	/* used in conjunction with "sid" in "samldb_dn_from_sid" */
	struct ldb_dn *res_dn;

	/* used in conjunction with "dn" in "samldb_sid_from_dn" */
	struct dom_sid *res_sid;

	/* used in "samldb_user_dn_to_prim_group_rid" */
	uint32_t prim_group_rid;

	/* used in conjunction with "prim_group_rid" in
	 * "samldb_prim_group_rid_to_users_cnt" */
	unsigned int users_cnt;

	/* used in "samldb_group_add_member" and "samldb_group_del_member" */
	struct ldb_dn *group_dn;
	struct ldb_dn *member_dn;

	/* used in "samldb_primary_group_change" */
	struct ldb_dn *user_dn;
	struct ldb_dn *old_prim_group_dn, *new_prim_group_dn;

	/* generic counter - used in "samldb_member_check" */
	unsigned int cnt;

	/* all the async steps necessary to complete the operation */
	struct samldb_step *steps;
	struct samldb_step *curstep;

	/* If someone set an ares to forward controls and response back to the caller */
	struct ldb_reply *ares;
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
	struct samldb_step *step, *stepper;

	step = talloc_zero(ac, struct samldb_step);
	if (step == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	step->fn = fn;

	if (ac->steps == NULL) {
		ac->steps = step;
		ac->curstep = step;
	} else {
		if (ac->curstep == NULL)
			return LDB_ERR_OPERATIONS_ERROR;
		for (stepper = ac->curstep; stepper->next != NULL;
			stepper = stepper->next);
		stepper->next = step;
	}

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

	/* we exit the samldb module here */
	/* If someone set an ares to forward controls and response back to the caller, use them */
	if (ac->ares) {
		return ldb_module_done(ac->req, ac->ares->controls,
				       ac->ares->response, LDB_SUCCESS);
	} else {
		return ldb_module_done(ac->req, NULL, NULL, LDB_SUCCESS);
	}
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

/*
 * samldb_check_samAccountName (async)
 */

static int samldb_check_samAccountName_callback(struct ldb_request *req,
						struct ldb_reply *ares)
{
	struct samldb_ctx *ac;
	int ret;

	ac = talloc_get_type(req->context, struct samldb_ctx);

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
	filter = talloc_asprintf(ac, "samAccountName=%s",
				 ldb_binary_encode_string(ac, name));
	if (filter == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb, ac,
				   samdb_base_dn(ldb), LDB_SCOPE_SUBTREE,
				   filter, NULL,
				   NULL,
				   ac, samldb_check_samAccountName_callback,
				   ac->req);
	talloc_free(filter);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
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
			"sAMAccountType must not be specified!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if (strcmp("user", ac->type) == 0) {
		uac = samdb_result_uint(ac->msg, "userAccountControl", 0);
		if (uac == 0) {
			ldb_asprintf_errstring(ldb,
				"userAccountControl invalid!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		} else {
			account_type = ds_uf2atype(uac);
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
				"groupType invalid!\n");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		} else {
			account_type = ds_gtype2atype(group_type);
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


/* allocate a SID using our RID Set */
static int samldb_allocate_sid(struct samldb_ctx *ac)
{
	uint32_t rid;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);

	ret = ridalloc_allocate_rid(ac->module, &rid);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), rid);
	if (ac->sid == NULL) {
		ldb_module_oom(ac->module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if ( ! samldb_msg_add_sid(ac->msg, "objectSid", ac->sid)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return samldb_next_step(ac);
}

/*
 * samldb_dn_from_sid (async)
 */

static int samldb_dn_from_sid(struct samldb_ctx *ac);

static int samldb_dn_from_sid_callback(struct ldb_request *req,
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
		if (ac->res_dn != NULL) {
			/* one too many! */
			ldb_set_errstring(ldb,
				"Invalid number of results while searching "
				"for domain objects!");
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}
		ac->res_dn = ldb_dn_copy(ac, ares->message->dn);

		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);

		/* found or not found, go on */
		ret = samldb_next_step(ac);
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

/* Finds the DN "res_dn" of an object with a given SID "sid" */
static int samldb_dn_from_sid(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	static const char * const attrs[] = { NULL };
	struct ldb_request *req;
	char *filter;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->sid == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	filter = talloc_asprintf(ac, "(objectSid=%s)",
		ldap_encode_ndr_dom_sid(ac, ac->sid));
	if (filter == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	ret = ldb_build_search_req(&req, ldb, ac,
				ldb_get_default_basedn(ldb),
				LDB_SCOPE_SUBTREE,
				filter, attrs,
				NULL,
				ac, samldb_dn_from_sid_callback,
				ac->req);
	if (ret != LDB_SUCCESS)
		return ret;

	return ldb_next_request(ac->module, req);
}


static int samldb_check_primaryGroupID_1(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	uint32_t rid;

	ldb = ldb_module_get_ctx(ac->module);

	rid = samdb_result_uint(ac->msg, "primaryGroupID", ~0);
	ac->sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), rid);
	if (ac->sid == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	ac->res_dn = NULL;

	return samldb_next_step(ac);
}

static int samldb_check_primaryGroupID_2(struct samldb_ctx *ac)
{
	if (ac->res_dn == NULL) {
		struct ldb_context *ldb;
		ldb = ldb_module_get_ctx(ac->module);
		ldb_asprintf_errstring(ldb,
				       "Failed to find group sid %s!",
				       dom_sid_string(ac->sid, ac->sid));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	return samldb_next_step(ac);
}


/*
 * samldb_set_defaultObjectCategory_callback (async)
 */

static int samldb_set_defaultObjectCategory_callback(struct ldb_request *req,
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
			"Invalid reply type!");
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

static int samldb_set_defaultObjectCategory(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_message *msg;
	struct ldb_request *req;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	/* (Re)set the default object category to have it set to the DN in the
	 * storage format */
	msg = ldb_msg_new(ac);
	msg->dn = ac->msg->dn;
	ldb_msg_add_empty(msg, "defaultObjectCategory",
			  LDB_FLAG_MOD_REPLACE, NULL);
	ldb_msg_add_steal_string(msg, "defaultObjectCategory",
				 ldb_dn_alloc_linearized(msg, ac->dn));

	ret = ldb_build_mod_req(&req, ldb, ac,
				msg, NULL,
				ac,
				samldb_set_defaultObjectCategory_callback,
				ac->req);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}

	return ldb_next_request(ac->module, req);
}

/*
 * samldb_find_for_defaultObjectCategory (async)
 */

static int samldb_find_for_defaultObjectCategory_callback(struct ldb_request *req,
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
		if (ares->error == LDB_ERR_NO_SUCH_OBJECT) {
			if (ldb_request_get_control(ac->req,
						    LDB_CONTROL_RELAX_OID) != NULL) {
				/* Don't be pricky when the DN doesn't exist */
				/* if we have the RELAX control specified */
				ac->dn = req->op.search.base;
				return samldb_next_step(ac);
			} else {
				ldb_set_errstring(ldb,
					"samldb_find_defaultObjectCategory: "
					"Invalid DN for 'defaultObjectCategory'!");
				ares->error = LDB_ERR_CONSTRAINT_VIOLATION;
			}
		}

		return ldb_module_done(ac->req, ares->controls,
                                       ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		ac->dn = talloc_steal(ac, ares->message->dn);

		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);

		if (ac->dn != NULL) {
			/* when found go on */
			ret = samldb_next_step(ac);
		} else {
			ret = LDB_ERR_OPERATIONS_ERROR;
		}
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

static int samldb_find_for_defaultObjectCategory(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	static const char *no_attrs[] = { NULL };
        int ret;
	const struct ldb_val *val;
	struct ldb_dn *def_obj_cat_dn;

	ldb = ldb_module_get_ctx(ac->module);

	ac->dn = NULL;

	val = ldb_msg_find_ldb_val(ac->msg, "defaultObjectCategory");
	if (val != NULL) {
		/* "defaultObjectCategory" has been set by the caller. Do some
		 * checks for consistency.
		 * NOTE: The real constraint check (that 'defaultObjectCategory'
		 * is the DN of the new objectclass or any parent of it) is
		 * still incomplete.
		 * For now we say that 'defaultObjectCategory' is valid if it
		 * exists and it is of objectclass "classSchema". */
		def_obj_cat_dn = ldb_dn_from_ldb_val(ac, ldb, val);
		if (def_obj_cat_dn == NULL) {
			ldb_set_errstring(ldb,
				"samldb_find_defaultObjectCategory: Invalid DN "
				"for 'defaultObjectCategory'!");
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	} else {
		/* "defaultObjectCategory" has not been set by the caller. Use
		 * the entry DN for it. */
		def_obj_cat_dn = ac->msg->dn;
	}

	ret = ldb_build_search_req(&req, ldb, ac,
				   def_obj_cat_dn, LDB_SCOPE_BASE,
				   "objectClass=classSchema", no_attrs,
				   NULL,
				   ac, samldb_find_for_defaultObjectCategory_callback,
				   ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_request_add_controls(req,
					DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, req);
}

/**
 * msDS-IntId attributeSchema attribute handling
 * during LDB_ADD request processing
 */
static int samldb_add_handle_msDS_IntId(struct samldb_ctx *ac)
{
	int ret;
	bool id_exists;
	uint32_t msds_intid;
	uint32_t system_flags;
	struct ldb_context *ldb;
	struct ldb_result *ldb_res;
	struct ldb_dn *schema_dn;

	ldb = ldb_module_get_ctx(ac->module);
	schema_dn = ldb_get_schema_basedn(ldb);

	/* replicated update should always go through */
	if (ldb_request_get_control(ac->req, DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
		return LDB_SUCCESS;
	}

	/* msDS-IntId is handled by system and should never be
	 * passed by clients */
	if (ldb_msg_find_element(ac->msg, "msDS-IntId")) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* do not generate msDS-IntId if Relax control is passed */
	if (ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID)) {
		return LDB_SUCCESS;
	}

	/* check Functional Level */
	if (dsdb_functional_level(ldb) < DS_DOMAIN_FUNCTION_2003) {
		return LDB_SUCCESS;
	}

	/* check systemFlags for SCHEMA_BASE_OBJECT flag */
	system_flags = ldb_msg_find_attr_as_uint(ac->msg, "systemFlags", 0);
	if (system_flags & SYSTEM_FLAG_SCHEMA_BASE_OBJECT) {
		return LDB_SUCCESS;
	}

	/* Generate new value for msDs-IntId
	 * Value should be in 0x80000000..0xBFFFFFFF range */
	msds_intid = generate_random() % 0X3FFFFFFF;
	msds_intid += 0x80000000;

	/* probe id values until unique one is found */
	do {
		msds_intid++;
		if (msds_intid > 0xBFFFFFFF) {
			msds_intid = 0x80000001;
		}

		ret = dsdb_module_search(ac->module, ac,
		                         &ldb_res,
		                         schema_dn, LDB_SCOPE_ONELEVEL, NULL, 0,
		                         "(msDS-IntId=%d)", msds_intid);
		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_ERROR,
				      __location__": Searching for msDS-IntId=%d failed - %s\n",
				      msds_intid,
				      ldb_errstring(ldb));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		id_exists = (ldb_res->count > 0);

		talloc_free(ldb_res);
	} while(id_exists);

	return ldb_msg_add_fmt(ac->msg, "msDS-IntId", "%d", msds_intid);
}


/*
 * samldb_add_entry (async)
 */

static int samldb_add_entry_callback(struct ldb_request *req,
					struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	int ret;

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

	/* The caller may wish to get controls back from the add */
	ac->ares = talloc_steal(ac, ares);

	ret = samldb_next_step(ac);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}
	return ret;
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
	struct ldb_context *ldb;
	struct loadparm_context *lp_ctx;
	enum sid_generator sid_generator;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	/* Add informations for the different account types */
	ac->type = type;
	if (strcmp(ac->type, "user") == 0) {
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"userAccountControl", "546");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"badPwdCount", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"codePage", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"countryCode", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"badPasswordTime", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"lastLogoff", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"lastLogon", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"pwdLastSet", "0");
		if (ret != LDB_SUCCESS) return ret;
		if (!ldb_msg_find_element(ac->msg, "primaryGroupID")) {
			ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
						 "primaryGroupID", DOMAIN_RID_USERS);
			if (ret != LDB_SUCCESS) return ret;
		}
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"accountExpires", "9223372036854775807");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"logonCount", "0");
		if (ret != LDB_SUCCESS) return ret;
	} else if (strcmp(ac->type, "group") == 0) {
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"groupType", "-2147483646");
		if (ret != LDB_SUCCESS) return ret;
	} else if (strcmp(ac->type, "classSchema") == 0) {
		const struct ldb_val *rdn_value;

		ret = samdb_find_or_add_attribute(ldb, ac->msg,
						  "rdnAttId", "cn");
		if (ret != LDB_SUCCESS) return ret;

		rdn_value = ldb_dn_get_rdn_val(ac->msg->dn);
		if (!ldb_msg_find_element(ac->msg, "lDAPDisplayName")) {
			/* the RDN has prefix "CN" */
			ret = ldb_msg_add_string(ac->msg, "lDAPDisplayName",
				samdb_cn_to_lDAPDisplayName(ac,
					(const char *) rdn_value->data));
			if (ret != LDB_SUCCESS) {
				ldb_oom(ldb);
				return ret;
			}
		}

		if (!ldb_msg_find_element(ac->msg, "schemaIDGUID")) {
			struct GUID guid;
			/* a new GUID */
			guid = GUID_random();
			ret = dsdb_msg_add_guid(ac->msg, &guid, "schemaIDGUID");
			if (ret != LDB_SUCCESS) {
				ldb_oom(ldb);
				return ret;
			}
		}

		ret = samldb_add_step(ac, samldb_add_entry);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_find_for_defaultObjectCategory);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_set_defaultObjectCategory);
		if (ret != LDB_SUCCESS) return ret;

		return samldb_first_step(ac);
	} else if (strcmp(ac->type, "attributeSchema") == 0) {
		const struct ldb_val *rdn_value;
		rdn_value = ldb_dn_get_rdn_val(ac->msg->dn);
		if (!ldb_msg_find_element(ac->msg, "lDAPDisplayName")) {
			/* the RDN has prefix "CN" */
			ret = ldb_msg_add_string(ac->msg, "lDAPDisplayName",
				samdb_cn_to_lDAPDisplayName(ac,
					(const char *) rdn_value->data));
			if (ret != LDB_SUCCESS) {
				ldb_oom(ldb);
				return ret;
			}
		}

		ret = samdb_find_or_add_attribute(ldb, ac->msg,
						  "isSingleValued", "FALSE");
		if (ret != LDB_SUCCESS) return ret;

		if (!ldb_msg_find_element(ac->msg, "schemaIDGUID")) {
			struct GUID guid;
			/* a new GUID */
			guid = GUID_random();
			ret = dsdb_msg_add_guid(ac->msg, &guid, "schemaIDGUID");
			if (ret != LDB_SUCCESS) {
				ldb_oom(ldb);
				return ret;
			}
		}

		/* handle msDS-IntID attribute */
		ret = samldb_add_handle_msDS_IntId(ac);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_add_entry);
		if (ret != LDB_SUCCESS) return ret;

		return samldb_first_step(ac);
	} else {
		ldb_asprintf_errstring(ldb,
			"Invalid entry type!");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* check if we have a valid samAccountName */
	ret = samldb_add_step(ac, samldb_check_samAccountName);
	if (ret != LDB_SUCCESS) return ret;

	/* check account_type/group_type */
	ret = samldb_add_step(ac, samldb_check_samAccountType);
	if (ret != LDB_SUCCESS) return ret;

	/* check if we have a valid primary group ID */
	if (strcmp(ac->type, "user") == 0) {
		ret = samldb_add_step(ac, samldb_check_primaryGroupID_1);
		if (ret != LDB_SUCCESS) return ret;
		ret = samldb_add_step(ac, samldb_dn_from_sid);
		if (ret != LDB_SUCCESS) return ret;
		ret = samldb_add_step(ac, samldb_check_primaryGroupID_2);
		if (ret != LDB_SUCCESS) return ret;
	}

	lp_ctx = talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
		 struct loadparm_context);

	/* don't allow objectSID to be specified without the RELAX control */
	ac->sid = samdb_result_dom_sid(ac, ac->msg, "objectSid");
	if (ac->sid && !ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID) &&
	    !dsdb_module_am_system(ac->module)) {
		ldb_asprintf_errstring(ldb, "No SID may be specified in user/group creation for %s",
				       ldb_dn_get_linearized(ac->msg->dn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if ( ! ac->sid) {
		sid_generator = lp_sid_generator(lp_ctx);
		if (sid_generator == SID_GENERATOR_INTERNAL) {
			ret = samldb_add_step(ac, samldb_allocate_sid);
			if (ret != LDB_SUCCESS) return ret;
		}
	}

	/* finally proceed with adding the entry */
	ret = samldb_add_step(ac, samldb_add_entry);
	if (ret != LDB_SUCCESS) return ret;

	return samldb_first_step(ac);
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
					"No valid SID found in "
					"ForeignSecurityPrincipal CN!");
			talloc_free(ac);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ( ! samldb_msg_add_sid(ac->msg, "objectSid", ac->sid)) {
			talloc_free(ac);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

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
					"should be CN=!", rdn_name);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	return LDB_SUCCESS;
}

/*
 * samldb_sid_from_dn (async)
 */

static int samldb_sid_from_dn(struct samldb_ctx *ac);

static int samldb_sid_from_dn_callback(struct ldb_request *req,
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
		if (ac->res_sid != NULL) {
			/* one too many! */
			ldb_set_errstring(ldb,
				"Invalid number of results while searching "
				"for domain objects!");
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}
		ac->res_sid = samdb_result_dom_sid(ac, ares->message,
			"objectSid");

		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);

		/* found or not found, go on */
		ret = samldb_next_step(ac);
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

/* Finds the SID "res_sid" of an object with a given DN "dn" */
static int samldb_sid_from_dn(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	static const char * const attrs[] = { "objectSid", NULL };
	struct ldb_request *req;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->dn == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	ret = ldb_build_search_req(&req, ldb, ac,
				ac->dn,
				LDB_SCOPE_BASE,
				NULL, attrs,
				NULL,
				ac, samldb_sid_from_dn_callback,
				ac->req);
	if (ret != LDB_SUCCESS)
		return ret;

	return ldb_next_request(ac->module, req);
}

/*
 * samldb_user_dn_to_prim_group_rid (async)
 */

static int samldb_user_dn_to_prim_group_rid(struct samldb_ctx *ac);

static int samldb_user_dn_to_prim_group_rid_callback(struct ldb_request *req,
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
		if (ac->prim_group_rid != 0) {
			/* one too many! */
			ldb_set_errstring(ldb,
				"Invalid number of results while searching "
				"for domain objects!");
			ret = LDB_ERR_OPERATIONS_ERROR;
			break;
		}
		ac->prim_group_rid = samdb_result_uint(ares->message,
			"primaryGroupID", ~0);

		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);
		if (ac->prim_group_rid == 0) {
			ldb_asprintf_errstring(ldb,
				"Unable to get the primary group RID!");
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

/* Locates the "primaryGroupID" attribute from a certain user specified as
 * "user_dn". Saves the result in "prim_group_rid". */
static int samldb_user_dn_to_prim_group_rid(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	static const char * const attrs[] = { "primaryGroupID", NULL };
	struct ldb_request *req;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->user_dn == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	ret = ldb_build_search_req(&req, ldb, ac,
				ac->user_dn,
				LDB_SCOPE_BASE,
				NULL, attrs,
				NULL,
				ac, samldb_user_dn_to_prim_group_rid_callback,
				ac->req);
	if (ret != LDB_SUCCESS)
		return ret;

	return ldb_next_request(ac->module, req);
}

/*
 * samldb_prim_group_rid_to_users_cnt (async)
 */

static int samldb_prim_group_rid_to_users_cnt(struct samldb_ctx *ac);

static int samldb_prim_group_rid_to_users_cnt_callback(struct ldb_request *req,
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
		++(ac->users_cnt);

		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		ret = LDB_SUCCESS;
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);

		/* found or not found, go on */
		ret = samldb_next_step(ac);
		break;
	}

done:
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

/* Finds the amount of users which have the primary group "prim_group_rid" and
 * save the result in "users_cnt" */
static int samldb_prim_group_rid_to_users_cnt(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	static const char * const attrs[] = { NULL };
	struct ldb_request *req;
	char *filter;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if ((ac->prim_group_rid == 0) || (ac->users_cnt != 0))
		return LDB_ERR_OPERATIONS_ERROR;

	filter = talloc_asprintf(ac, "(&(primaryGroupID=%u)(objectclass=user))",
		ac->prim_group_rid);
	if (filter == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	ret = ldb_build_search_req(&req, ldb, ac,
				ldb_get_default_basedn(ldb),
				LDB_SCOPE_SUBTREE,
				filter, attrs,
				NULL,
				ac,
				samldb_prim_group_rid_to_users_cnt_callback,
				ac->req);
	if (ret != LDB_SUCCESS)
		return ret;

	return ldb_next_request(ac->module, req);
}

/*
 * samldb_group_add_member (async)
 * samldb_group_del_member (async)
 */

static int samldb_group_add_del_member_callback(struct ldb_request *req,
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
		if (ares->error == LDB_ERR_NO_SUCH_ATTRIBUTE) {
			/* On error "NO_SUCH_ATTRIBUTE" (delete of an invalid
			 * "member" attribute) return "UNWILLING_TO_PERFORM" */
			ares->error = LDB_ERR_UNWILLING_TO_PERFORM;
		}
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}
	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb,
			"Invalid reply type!");
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

/* Adds a member with DN "member_dn" to a group with DN "group_dn" */
static int samldb_group_add_member(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	struct ldb_message *msg;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if ((ac->group_dn == NULL) || (ac->member_dn == NULL))
		return LDB_ERR_OPERATIONS_ERROR;

	msg = ldb_msg_new(ac);
	msg->dn = ac->group_dn;
	samdb_msg_add_addval(ldb, ac, msg, "member",
		ldb_dn_get_linearized(ac->member_dn));

	ret = ldb_build_mod_req(&req, ldb, ac,
				msg, NULL,
				ac, samldb_group_add_del_member_callback,
				ac->req);
	if (ret != LDB_SUCCESS)
		return ret;

	return ldb_next_request(ac->module, req);
}

/* Removes a member with DN "member_dn" from a group with DN "group_dn" */
static int samldb_group_del_member(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	struct ldb_message *msg;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	if ((ac->group_dn == NULL) || (ac->member_dn == NULL))
		return LDB_ERR_OPERATIONS_ERROR;

	msg = ldb_msg_new(ac);
	msg->dn = ac->group_dn;
	samdb_msg_add_delval(ldb, ac, msg, "member",
		ldb_dn_get_linearized(ac->member_dn));

	ret = ldb_build_mod_req(&req, ldb, ac,
				msg, NULL,
				ac, samldb_group_add_del_member_callback,
				ac->req);
	if (ret != LDB_SUCCESS)
		return ret;

	return ldb_next_request(ac->module, req);
}


static int samldb_prim_group_change_1(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	uint32_t rid;

	ldb = ldb_module_get_ctx(ac->module);

	ac->user_dn = ac->msg->dn;

	rid = samdb_result_uint(ac->msg, "primaryGroupID", ~0);
	ac->sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), rid);
	if (ac->sid == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	ac->res_dn = NULL;

	ac->prim_group_rid = 0;

	return samldb_next_step(ac);
}

static int samldb_prim_group_change_2(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->res_dn != NULL)
		ac->new_prim_group_dn = ac->res_dn;
	else
		return LDB_ERR_UNWILLING_TO_PERFORM;

	ac->sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb),
		ac->prim_group_rid);
	if (ac->sid == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	ac->res_dn = NULL;

	return samldb_next_step(ac);
}

static int samldb_prim_group_change_4(struct samldb_ctx *ac);
static int samldb_prim_group_change_5(struct samldb_ctx *ac);
static int samldb_prim_group_change_6(struct samldb_ctx *ac);

static int samldb_prim_group_change_3(struct samldb_ctx *ac)
{
	int ret;

	if (ac->res_dn != NULL)
		ac->old_prim_group_dn = ac->res_dn;
	else
		return LDB_ERR_UNWILLING_TO_PERFORM;

	/* Only update when the primary group changed */
	if (ldb_dn_compare(ac->old_prim_group_dn, ac->new_prim_group_dn) != 0) {
		ac->member_dn = ac->user_dn;
		/* Remove the "member" attribute of the actual (new) primary
		 * group */

		ret = samldb_add_step(ac, samldb_prim_group_change_4);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_group_del_member);
		if (ret != LDB_SUCCESS) return ret;

		/* Add a "member" attribute for the previous primary group */

		ret = samldb_add_step(ac, samldb_prim_group_change_5);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_group_add_member);
		if (ret != LDB_SUCCESS) return ret;
	}

	ret = samldb_add_step(ac, samldb_prim_group_change_6);
	if (ret != LDB_SUCCESS) return ret;

	return samldb_next_step(ac);
}

static int samldb_prim_group_change_4(struct samldb_ctx *ac)
{
	ac->group_dn = ac->new_prim_group_dn;

	return samldb_next_step(ac);
}

static int samldb_prim_group_change_5(struct samldb_ctx *ac)
{
	ac->group_dn = ac->old_prim_group_dn;

	return samldb_next_step(ac);
}

static int samldb_prim_group_change_6(struct samldb_ctx *ac)
{
	return ldb_next_request(ac->module, ac->req);
}

static int samldb_prim_group_change(struct samldb_ctx *ac)
{
	int ret;

	/* Finds out the DN of the new primary group */

	ret = samldb_add_step(ac, samldb_prim_group_change_1);
	if (ret != LDB_SUCCESS) return ret;

	ret = samldb_add_step(ac, samldb_dn_from_sid);
	if (ret != LDB_SUCCESS) return ret;

	ret = samldb_add_step(ac, samldb_user_dn_to_prim_group_rid);
	if (ret != LDB_SUCCESS) return ret;

	/* Finds out the DN of the old primary group */

	ret = samldb_add_step(ac, samldb_prim_group_change_2);
	if (ret != LDB_SUCCESS) return ret;

	ret = samldb_add_step(ac, samldb_dn_from_sid);
	if (ret != LDB_SUCCESS) return ret;

	ret = samldb_add_step(ac, samldb_prim_group_change_3);
	if (ret != LDB_SUCCESS) return ret;

	return samldb_first_step(ac);
}


static int samldb_member_check_1(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_message_element *el;

	ldb = ldb_module_get_ctx(ac->module);

	el = ldb_msg_find_element(ac->msg, "member");

	ac->user_dn = ldb_dn_from_ldb_val(ac, ldb, &el->values[ac->cnt]);
	if (!ldb_dn_validate(ac->user_dn))
		return LDB_ERR_OPERATIONS_ERROR;
	ac->prim_group_rid = 0;

	return samldb_next_step(ac);
}

static int samldb_member_check_2(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;

	ldb = ldb_module_get_ctx(ac->module);

	ac->sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb),
		ac->prim_group_rid);
	if (ac->sid == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	ac->res_dn = NULL;

	return samldb_next_step(ac);
}

static int samldb_member_check_3(struct samldb_ctx *ac)
{
	if (ldb_dn_compare(ac->res_dn, ac->msg->dn) == 0)
		return LDB_ERR_ENTRY_ALREADY_EXISTS;

	++(ac->cnt);

	return samldb_next_step(ac);
}

static int samldb_member_check_4(struct samldb_ctx *ac)
{
	return ldb_next_request(ac->module, ac->req);
}

static int samldb_member_check(struct samldb_ctx *ac)
{
	struct ldb_message_element *el;
	int i, ret;

	el = ldb_msg_find_element(ac->msg, "member");
	ac->cnt = 0;
	for (i = 0; i < el->num_values; i++) {
		/* Denies to add "member"s to groups which are primary ones
		 * for them */
		ret = samldb_add_step(ac, samldb_member_check_1);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_user_dn_to_prim_group_rid);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_member_check_2);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_dn_from_sid);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_member_check_3);
		if (ret != LDB_SUCCESS) return ret;
	}

	ret = samldb_add_step(ac, samldb_member_check_4);
	if (ret != LDB_SUCCESS) return ret;

	return samldb_first_step(ac);
}


static int samldb_prim_group_users_check_1(struct samldb_ctx *ac)
{
	ac->dn = ac->req->op.del.dn;
	ac->res_sid = NULL;

	return samldb_next_step(ac);
}

static int samldb_prim_group_users_check_2(struct samldb_ctx *ac)
{
	NTSTATUS status;
	uint32_t rid;

	if (ac->res_sid == NULL) {
		/* No SID - therefore ok here */
		return ldb_next_request(ac->module, ac->req);
	}
	status = dom_sid_split_rid(ac, ac->res_sid, NULL, &rid);
	if (!NT_STATUS_IS_OK(status))
		return LDB_ERR_OPERATIONS_ERROR;

	if (rid == 0) {
		/* Special object (security principal?) */
		return ldb_next_request(ac->module, ac->req);
	}

	ac->prim_group_rid = rid;
	ac->users_cnt = 0;

	return samldb_next_step(ac);
}

static int samldb_prim_group_users_check_3(struct samldb_ctx *ac)
{
	if (ac->users_cnt > 0)
		return LDB_ERR_ENTRY_ALREADY_EXISTS;

	return ldb_next_request(ac->module, ac->req);
}

static int samldb_prim_group_users_check(struct samldb_ctx *ac)
{
	int ret;

	/* Finds out the SID/RID of the domain object */

	ret = samldb_add_step(ac, samldb_prim_group_users_check_1);
	if (ret != LDB_SUCCESS) return ret;

	ret = samldb_add_step(ac, samldb_sid_from_dn);
	if (ret != LDB_SUCCESS) return ret;

	/* Deny delete requests from groups which are primary ones */

	ret = samldb_add_step(ac, samldb_prim_group_users_check_2);
	if (ret != LDB_SUCCESS) return ret;

	ret = samldb_add_step(ac, samldb_prim_group_rid_to_users_cnt);
	if (ret != LDB_SUCCESS) return ret;

	ret = samldb_add_step(ac, samldb_prim_group_users_check_3);
	if (ret != LDB_SUCCESS) return ret;

	return samldb_first_step(ac);
}


/* add */
static int samldb_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	int ret;

	ldb = ldb_module_get_ctx(module);
	ldb_debug(ldb, LDB_DEBUG_TRACE, "samldb_add\n");

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

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "classSchema") != NULL) {

		ret = samldb_check_rdn(module, ac->req->op.add.message->dn);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}

		return samldb_fill_object(ac, "classSchema");
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "attributeSchema") != NULL) {

		ret = samldb_check_rdn(module, ac->req->op.add.message->dn);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}

		return samldb_fill_object(ac, "attributeSchema");
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
	uint32_t account_type;

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	if (ldb_msg_find_element(req->op.mod.message, "sAMAccountType") != NULL) {
		ldb_asprintf_errstring(ldb,
			"sAMAccountType must not be specified!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* msDS-IntId is not allowed to be modified
	 * except when modification comes from replication */
	if (ldb_msg_find_element(req->op.mod.message, "msDS-IntId")) {
		if (!ldb_request_get_control(req, DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	}

	/* TODO: do not modify original request, create a new one */

	el = ldb_msg_find_element(req->op.mod.message, "groupType");
	if (el && el->flags & (LDB_FLAG_MOD_ADD|LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		uint32_t group_type;

		req->op.mod.message = msg = ldb_msg_copy_shallow(req,
			req->op.mod.message);

		group_type = strtoul((const char *)el->values[0].data, NULL, 0);
		account_type =  ds_gtype2atype(group_type);
		ret = samdb_msg_add_uint(ldb, msg, msg,
					 "sAMAccountType",
					 account_type);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el2 = ldb_msg_find_element(msg, "sAMAccountType");
		el2->flags = LDB_FLAG_MOD_REPLACE;
	}

	el = ldb_msg_find_element(req->op.mod.message, "primaryGroupID");
	if (el && el->flags & (LDB_FLAG_MOD_ADD|LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		struct samldb_ctx *ac;

		ac = samldb_ctx_init(module, req);
		if (ac == NULL)
			return LDB_ERR_OPERATIONS_ERROR;

		req->op.mod.message = ac->msg = ldb_msg_copy_shallow(req,
			req->op.mod.message);

		return samldb_prim_group_change(ac);
	}

	el = ldb_msg_find_element(req->op.mod.message, "userAccountControl");
	if (el && el->flags & (LDB_FLAG_MOD_ADD|LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		uint32_t user_account_control;

		req->op.mod.message = msg = ldb_msg_copy_shallow(req,
			req->op.mod.message);

		user_account_control = strtoul((const char *)el->values[0].data,
			NULL, 0);
		account_type = ds_uf2atype(user_account_control);
		ret = samdb_msg_add_uint(ldb, msg, msg,
					 "sAMAccountType",
					 account_type);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el2 = ldb_msg_find_element(msg, "sAMAccountType");
		el2->flags = LDB_FLAG_MOD_REPLACE;

		if (user_account_control & UF_SERVER_TRUST_ACCOUNT) {
			ret = samdb_msg_add_string(ldb, msg, msg,
						   "isCriticalSystemObject", "TRUE");
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			el2 = ldb_msg_find_element(msg, "isCriticalSystemObject");
			el2->flags = LDB_FLAG_MOD_REPLACE;

			/* DCs have primaryGroupID of DOMAIN_RID_DCS */
			if (!ldb_msg_find_element(msg, "primaryGroupID")) {
				ret = samdb_msg_add_uint(ldb, msg, msg,
							 "primaryGroupID", DOMAIN_RID_DCS);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
				el2 = ldb_msg_find_element(msg, "primaryGroupID");
				el2->flags = LDB_FLAG_MOD_REPLACE;
			}
		}
	}

	el = ldb_msg_find_element(req->op.mod.message, "member");
	if (el && el->flags & (LDB_FLAG_MOD_ADD|LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		struct samldb_ctx *ac;

		ac = samldb_ctx_init(module, req);
		if (ac == NULL)
			return LDB_ERR_OPERATIONS_ERROR;

		req->op.mod.message = ac->msg = ldb_msg_copy_shallow(req,
			req->op.mod.message);

		return samldb_member_check(ac);
	}

	/* nothing matched, go on */
	return ldb_next_request(module, req);
}

/* delete */
static int samldb_delete(struct ldb_module *module, struct ldb_request *req)
{
	struct samldb_ctx *ac;

	if (ldb_dn_is_special(req->op.del.dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ac = samldb_ctx_init(module, req);
	if (ac == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	return samldb_prim_group_users_check(ac);
}

static int samldb_extended_allocate_rid_pool(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_fsmo_extended_op *exop;
	int ret;

	exop = talloc_get_type(req->op.extended.data, struct dsdb_fsmo_extended_op);
	if (!exop) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "samldb_extended_allocate_rid_pool: invalid extended data\n");
		return LDB_ERR_PROTOCOL_ERROR;
	}

	ret = ridalloc_allocate_rid_pool_fsmo(module, exop);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
}

static int samldb_extended(struct ldb_module *module, struct ldb_request *req)
{
	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_ALLOCATE_RID_POOL) == 0) {
		return samldb_extended_allocate_rid_pool(module, req);
	}

	return ldb_next_request(module, req);
}


_PUBLIC_ const struct ldb_module_ops ldb_samldb_module_ops = {
	.name          = "samldb",
	.add           = samldb_add,
	.modify        = samldb_modify,
	.del           = samldb_delete,
	.extended      = samldb_extended
};

