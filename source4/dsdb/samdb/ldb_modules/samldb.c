/*
   SAM ldb module

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Simo Sorce  2004-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009-2010

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
 *  Description: various internal DSDB triggers - most for SAM specific objects
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "libcli/ldap/ldap_ndr.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/ldb_modules/ridalloc.h"
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

	/* used in "samldb_find_for_defaultObjectCategory" */
	struct ldb_dn *dn, *res_dn;

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
		return ldb_oom(ldb_module_get_ctx(ac->module));
	}

	step->fn = fn;

	if (ac->steps == NULL) {
		ac->steps = step;
		ac->curstep = step;
	} else {
		if (ac->curstep == NULL)
			return ldb_operr(ldb_module_get_ctx(ac->module));
		for (stepper = ac->curstep; stepper->next != NULL;
			stepper = stepper->next);
		stepper->next = step;
	}

	return LDB_SUCCESS;
}

static int samldb_first_step(struct samldb_ctx *ac)
{
	if (ac->steps == NULL) {
		return ldb_operr(ldb_module_get_ctx(ac->module));
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


/* sAMAccountName handling */

static int samldb_generate_sAMAccountName(struct ldb_context *ldb, struct ldb_message *msg)
{
	char *name;

	/* Format: $000000-000000000000 */

	name = talloc_asprintf(msg, "$%.6X-%.6X%.6X",
				(unsigned int)generate_random(),
				(unsigned int)generate_random(),
				(unsigned int)generate_random());
	if (name == NULL) {
		return ldb_oom(ldb);
	}
	return ldb_msg_add_steal_string(msg, "sAMAccountName", name);
}

static int samldb_check_sAMAccountName(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	const char *name;
	int ret;

	if (ldb_msg_find_element(ac->msg, "sAMAccountName") == NULL) {
		ret = samldb_generate_sAMAccountName(ldb, ac->msg);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	name = ldb_msg_find_attr_as_string(ac->msg, "sAMAccountName", NULL);
	if (name == NULL) {
		return ldb_operr(ldb);
	}

	ret = samdb_search_count(ldb, NULL, "(sAMAccountName=%s)",
				 ldb_binary_encode_string(ac, name));
	if ((ret < 0) || (ret > 1)) {
		return ldb_operr(ldb);
	}
	if (ret == 1) {
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	}

	return samldb_next_step(ac);
}


static bool samldb_msg_add_sid(struct ldb_message *msg,
				const char *name,
				const struct dom_sid *sid)
{
	struct ldb_val v;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_blob(&v, msg, sid,
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
	struct dom_sid *sid;
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	int ret;

	ret = ridalloc_allocate_rid(ac->module, &rid);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), rid);
	if (sid == NULL) {
		return ldb_module_oom(ac->module);
	}

	if ( ! samldb_msg_add_sid(ac->msg, "objectSid", sid)) {
		return ldb_operr(ldb);
	}

	return samldb_next_step(ac);
}

/*
  see if a krbtgt_number is available
 */
static bool samldb_krbtgtnumber_available(struct samldb_ctx *ac, unsigned krbtgt_number)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ac);
	struct ldb_result *res;
	const char *attrs[] = { NULL };
	int ret;

	ret = dsdb_module_search(ac->module, tmp_ctx, &res, NULL, LDB_SCOPE_SUBTREE,
				 attrs, DSDB_FLAG_NEXT_MODULE,
				 "msDC-SecondaryKrbTgtNumber=%u", krbtgt_number);
	if (ret == LDB_SUCCESS && res->count == 0) {
		talloc_free(tmp_ctx);
		return true;
	}
	talloc_free(tmp_ctx);
	return false;
}

/* special handling for add in RODC join */
static int samldb_rodc_add(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	uint32_t krbtgt_number, i_start, i;
	int ret;
	char *newpass;

	/* find a unused msDC-SecondaryKrbTgtNumber */
	i_start = generate_random() & 0xFFFF;
	if (i_start == 0) {
		i_start = 1;
	}

	for (i=i_start; i<=0xFFFF; i++) {
		if (samldb_krbtgtnumber_available(ac, i)) {
			krbtgt_number = i;
			goto found;
		}
	}
	for (i=1; i<i_start; i++) {
		if (samldb_krbtgtnumber_available(ac, i)) {
			krbtgt_number = i;
			goto found;
		}
	}

	ldb_asprintf_errstring(ldb,
			       "%08X: Unable to find available msDS-SecondaryKrbTgtNumber",
			       W_ERROR_V(WERR_NO_SYSTEM_RESOURCES));
	return LDB_ERR_OTHER;

found:
	ret = ldb_msg_add_empty(ac->msg, "msDS-SecondaryKrbTgtNumber", LDB_FLAG_INTERNAL_DISABLE_VALIDATION, NULL);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
				 "msDS-SecondaryKrbTgtNumber", krbtgt_number);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	ret = ldb_msg_add_fmt(ac->msg, "sAMAccountName", "krbtgt_%u", krbtgt_number);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	newpass = generate_random_password(ac, 128, 255);
	if (newpass == NULL) {
		return ldb_operr(ldb);
	}

	ret = ldb_msg_add_steal_string(ac->msg, "clearTextPassword", newpass);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	return samldb_next_step(ac);
}

static int samldb_find_for_defaultObjectCategory(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_result *res;
	const char *no_attrs[] = { NULL };
	int ret;

	ac->res_dn = NULL;

	ret = dsdb_module_search(ac->module, ac, &res,
				 ac->dn, LDB_SCOPE_BASE, no_attrs,
				 DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT | DSDB_FLAG_NEXT_MODULE,
				 "(objectClass=classSchema)");
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* Don't be pricky when the DN doesn't exist if we have the */
		/* RELAX control specified */
		if (ldb_request_get_control(ac->req,
					    LDB_CONTROL_RELAX_OID) == NULL) {
			ldb_set_errstring(ldb,
					  "samldb_find_defaultObjectCategory: "
					  "Invalid DN for 'defaultObjectCategory'!");
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	}
	if ((ret != LDB_ERR_NO_SUCH_OBJECT) && (ret != LDB_SUCCESS)) {
		return ret;
	}

	ac->res_dn = ac->dn;

	return samldb_next_step(ac);
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
	int32_t system_flags;
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
	system_flags = ldb_msg_find_attr_as_int(ac->msg, "systemFlags", 0);
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
		                         schema_dn, LDB_SCOPE_ONELEVEL, NULL,
		                         DSDB_FLAG_NEXT_MODULE,
		                         "(msDS-IntId=%d)", msds_intid);
		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_ERROR,
				      __location__": Searching for msDS-IntId=%d failed - %s\n",
				      msds_intid,
				      ldb_errstring(ldb));
			return ldb_operr(ldb);
		}
		id_exists = (ldb_res->count > 0);

		talloc_free(ldb_res);
	} while(id_exists);

	return samdb_msg_add_int(ldb, ac->msg, ac->msg, "msDS-IntId",
				 msds_intid);
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

	if (ares->type == LDB_REPLY_REFERRAL) {
		return ldb_module_send_referral(ac->req, ares->referral);
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
	LDB_REQ_SET_LOCATION(req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, req);
}

/*
 * return true if msg carries an attributeSchema that is intended to be RODC
 * filtered but is also a system-critical attribute.
 */
static bool check_rodc_critical_attribute(struct ldb_message *msg)
{
	uint32_t schemaFlagsEx, searchFlags, rodc_filtered_flags;

	schemaFlagsEx = ldb_msg_find_attr_as_uint(msg, "schemaFlagsEx", 0);
	searchFlags = ldb_msg_find_attr_as_uint(msg, "searchFlags", 0);
	rodc_filtered_flags = (SEARCH_FLAG_RODC_ATTRIBUTE | SEARCH_FLAG_CONFIDENTIAL);

	if ((schemaFlagsEx & SCHEMA_FLAG_ATTR_IS_CRITICAL) &&
		((searchFlags & rodc_filtered_flags) == rodc_filtered_flags)) {
		return true;
	} else {
		return false;
	}
}


static int samldb_fill_object(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	int ret;

	/* Add informations for the different account types */
	if (strcmp(ac->type, "user") == 0) {
		struct ldb_control *rodc_control = ldb_request_get_control(ac->req,
									   LDB_CONTROL_RODC_DCPROMO_OID);
		if (rodc_control != NULL) {
			/* see [MS-ADTS] 3.1.1.3.4.1.23 LDAP_SERVER_RODC_DCPROMO_OID */
			rodc_control->critical = false;
			ret = samldb_add_step(ac, samldb_rodc_add);
			if (ret != LDB_SUCCESS) return ret;
		}

		/* check if we have a valid sAMAccountName */
		ret = samldb_add_step(ac, samldb_check_sAMAccountName);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_add_entry);
		if (ret != LDB_SUCCESS) return ret;

	} else if (strcmp(ac->type, "group") == 0) {
		/* check if we have a valid sAMAccountName */
		ret = samldb_add_step(ac, samldb_check_sAMAccountName);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_add_entry);
		if (ret != LDB_SUCCESS) return ret;

	} else if (strcmp(ac->type, "classSchema") == 0) {
		const struct ldb_val *rdn_value, *def_obj_cat_val;

		ret = samdb_find_or_add_attribute(ldb, ac->msg,
						  "rdnAttId", "cn");
		if (ret != LDB_SUCCESS) return ret;

		/* do not allow to mark an attributeSchema as RODC filtered if it
		 * is system-critical */
		if (check_rodc_critical_attribute(ac->msg)) {
			ldb_asprintf_errstring(ldb, "Refusing schema add of %s - cannot combine critical class with RODC filtering",
					       ldb_dn_get_linearized(ac->msg->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

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

		def_obj_cat_val = ldb_msg_find_ldb_val(ac->msg,
						       "defaultObjectCategory");
		if (def_obj_cat_val != NULL) {
			/* "defaultObjectCategory" has been set by the caller.
			 * Do some checks for consistency.
			 * NOTE: The real constraint check (that
			 * 'defaultObjectCategory' is the DN of the new
			 * objectclass or any parent of it) is still incomplete.
			 * For now we say that 'defaultObjectCategory' is valid
			 * if it exists and it is of objectclass "classSchema".
			 */
			ac->dn = ldb_dn_from_ldb_val(ac, ldb, def_obj_cat_val);
			if (ac->dn == NULL) {
				ldb_set_errstring(ldb,
						  "Invalid DN for 'defaultObjectCategory'!");
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		} else {
			/* "defaultObjectCategory" has not been set by the
			 * caller. Use the entry DN for it. */
			ac->dn = ac->msg->dn;

			ret = samdb_msg_add_string(ldb, ac->msg, ac->msg,
						   "defaultObjectCategory",
						   ldb_dn_get_linearized(ac->dn));
			if (ret != LDB_SUCCESS) {
				ldb_oom(ldb);
				return ret;
			}
		}

		ret = samldb_add_step(ac, samldb_add_entry);
		if (ret != LDB_SUCCESS) return ret;

		/* Now perform the checks for the 'defaultObjectCategory'. The
		 * lookup DN was already saved in "ac->dn" */
		ret = samldb_add_step(ac, samldb_find_for_defaultObjectCategory);
		if (ret != LDB_SUCCESS) return ret;

	} else if (strcmp(ac->type, "attributeSchema") == 0) {
		const struct ldb_val *rdn_value;
		rdn_value = ldb_dn_get_rdn_val(ac->msg->dn);
		if (!ldb_msg_find_element(ac->msg, "lDAPDisplayName")) {
			/* the RDN has prefix "CN" */
			ret = ldb_msg_add_string(ac->msg, "lDAPDisplayName",
				samdb_cn_to_lDAPDisplayName(ac->msg,
					(const char *) rdn_value->data));
			if (ret != LDB_SUCCESS) {
				ldb_oom(ldb);
				return ret;
			}
		}

		/* do not allow to mark an attributeSchema as RODC filtered if it
		 * is system-critical */
		if (check_rodc_critical_attribute(ac->msg)) {
			ldb_asprintf_errstring(ldb, "Refusing schema add of %s - cannot combine critical attribute with RODC filtering",
					       ldb_dn_get_linearized(ac->msg->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
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

	} else {
		ldb_asprintf_errstring(ldb,
			"Invalid entry type!");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return samldb_first_step(ac);
}

static int samldb_fill_foreignSecurityPrincipal_object(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct dom_sid *sid;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	sid = samdb_result_dom_sid(ac->msg, ac->msg, "objectSid");
	if (sid == NULL) {
		sid = dom_sid_parse_talloc(ac->msg,
					   (const char *)ldb_dn_get_rdn_val(ac->msg->dn)->data);
		if (sid == NULL) {
			ldb_set_errstring(ldb,
					"No valid SID found in "
					"ForeignSecurityPrincipal CN!");
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if (! samldb_msg_add_sid(ac->msg, "objectSid", sid)) {
			return ldb_operr(ldb);
		}
	}

	/* finally proceed with adding the entry */
	ret = samldb_add_step(ac, samldb_add_entry);
	if (ret != LDB_SUCCESS) return ret;

	return samldb_first_step(ac);
}

static int samldb_schema_info_update(struct samldb_ctx *ac)
{
	WERROR werr;
	struct ldb_context *ldb;
	struct dsdb_schema *schema;

	/* replicated update should always go through */
	if (ldb_request_get_control(ac->req, DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
		return LDB_SUCCESS;
	}

	/* do not update schemaInfo during provisioning */
	if (ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID)) {
		return LDB_SUCCESS;
	}

	ldb = ldb_module_get_ctx(ac->module);
	schema = dsdb_get_schema(ldb, NULL);
	if (!schema) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "samldb_schema_info_update: no dsdb_schema loaded");
		DEBUG(0,(__location__ ": %s\n", ldb_errstring(ldb)));
		return ldb_operr(ldb);
	}

	werr = dsdb_module_schema_info_update(ac->module, schema, DSDB_FLAG_NEXT_MODULE);
	if (!W_ERROR_IS_OK(werr)) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "samldb_schema_info_update: "
		              "dsdb_module_schema_info_update failed with %s",
		              win_errstr(werr));
		DEBUG(0,(__location__ ": %s\n", ldb_errstring(ldb)));
		return ldb_operr(ldb);
	}

	return LDB_SUCCESS;
}

/*
 * "Objectclass" trigger (MS-SAMR 3.1.1.8.1)
 *
 * Has to be invoked on "add" and "modify" operations on "user", "computer" and
 * "group" objects.
 * ac->msg contains the "add"/"modify" message
 * ac->type contains the object type (main objectclass)
 */
static int samldb_objectclass_trigger(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct loadparm_context *lp_ctx = talloc_get_type(ldb_get_opaque(ldb,
					 "loadparm"), struct loadparm_context);
	struct ldb_message_element *el, *el2;
	enum sid_generator sid_generator;
	struct dom_sid *sid;
	const char *tempstr;
	int ret;

	/* make sure that "sAMAccountType" is not specified */
	el = ldb_msg_find_element(ac->msg, "sAMAccountType");
	if (el != NULL) {
		ldb_set_errstring(ldb,
			"samldb: sAMAccountType must not be specified!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* Step 1: objectSid assignment */

	/* Don't allow the objectSid to be changed. But beside the RELAX
	 * control we have also to guarantee that it can always be set with
	 * SYSTEM permissions. This is needed for the "samba3sam" backend. */
	sid = samdb_result_dom_sid(ac, ac->msg, "objectSid");
	if ((sid != NULL) && (!dsdb_module_am_system(ac->module)) &&
	    (ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID) == NULL)) {
		ldb_asprintf_errstring(ldb, "No SID may be specified in user/group modifications for %s",
				       ldb_dn_get_linearized(ac->msg->dn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* but generate a new SID when we do have an add operations */
	if ((sid == NULL) && (ac->req->operation == LDB_ADD)) {
		sid_generator = lpcfg_sid_generator(lp_ctx);
		if (sid_generator == SID_GENERATOR_INTERNAL) {
			ret = samldb_add_step(ac, samldb_allocate_sid);
			if (ret != LDB_SUCCESS) return ret;
		}
	}

	if (strcmp(ac->type, "user") == 0) {
		/* Step 1.2: Default values */
		tempstr = talloc_asprintf(ac->msg, "%d", UF_NORMAL_ACCOUNT);
		if (tempstr == NULL) return ldb_operr(ldb);
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"userAccountControl", tempstr);
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
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"accountExpires", "9223372036854775807");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"logonCount", "0");
		if (ret != LDB_SUCCESS) return ret;

		el = ldb_msg_find_element(ac->msg, "userAccountControl");
		if (el != NULL) {
			uint32_t user_account_control, account_type;

			/* Step 1.3: "userAccountControl" -> "sAMAccountType" mapping */
			user_account_control = ldb_msg_find_attr_as_uint(ac->msg,
									 "userAccountControl",
									 0);

			/* Temporary duplicate accounts aren't allowed */
			if ((user_account_control & UF_TEMP_DUPLICATE_ACCOUNT) != 0) {
				return LDB_ERR_OTHER;
			}

			account_type = ds_uf2atype(user_account_control);
			if (account_type == 0) {
				ldb_set_errstring(ldb, "samldb: Unrecognized account type!");
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
			ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
						 "sAMAccountType",
						 account_type);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			el2 = ldb_msg_find_element(ac->msg, "sAMAccountType");
			el2->flags = LDB_FLAG_MOD_REPLACE;

			if (user_account_control &
			    (UF_SERVER_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT)) {
				ret = samdb_msg_set_string(ldb, ac->msg, ac->msg,
							   "isCriticalSystemObject",
							   "TRUE");
				if (ret != LDB_SUCCESS) {
					return ret;
				}
				el2 = ldb_msg_find_element(ac->msg,
							   "isCriticalSystemObject");
				el2->flags = LDB_FLAG_MOD_REPLACE;
			}

			/* Step 1.4: "userAccountControl" -> "primaryGroupID" mapping */
			if (!ldb_msg_find_element(ac->msg, "primaryGroupID")) {
				uint32_t rid = ds_uf2prim_group_rid(user_account_control);
				ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
							 "primaryGroupID", rid);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
				el2 = ldb_msg_find_element(ac->msg,
							   "primaryGroupID");
				el2->flags = LDB_FLAG_MOD_REPLACE;
			}

			/* Step 1.5: Add additional flags when needed */
			if ((user_account_control & UF_NORMAL_ACCOUNT) &&
			    (ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID) == NULL)) {
				user_account_control |= UF_ACCOUNTDISABLE;
				user_account_control |= UF_PASSWD_NOTREQD;

				ret = samdb_msg_set_uint(ldb, ac->msg, ac->msg,
							 "userAccountControl",
							 user_account_control);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
		}

	} else if (strcmp(ac->type, "group") == 0) {
		/* Step 2.2: Default values */
		tempstr = talloc_asprintf(ac->msg, "%d",
					  GTYPE_SECURITY_GLOBAL_GROUP);
		if (tempstr == NULL) return ldb_operr(ldb);
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"groupType", tempstr);
		if (ret != LDB_SUCCESS) return ret;

		/* Step 2.3: "groupType" -> "sAMAccountType" */
		el = ldb_msg_find_element(ac->msg, "groupType");
		if (el != NULL) {
			uint32_t group_type, account_type;

			group_type = ldb_msg_find_attr_as_uint(ac->msg,
							       "groupType", 0);

			/* The creation of builtin groups requires the
			 * RELAX control */
			if (group_type == GTYPE_SECURITY_BUILTIN_LOCAL_GROUP) {
				if (ldb_request_get_control(ac->req,
							    LDB_CONTROL_RELAX_OID) == NULL) {
					return LDB_ERR_UNWILLING_TO_PERFORM;
				}
			}

			account_type = ds_gtype2atype(group_type);
			if (account_type == 0) {
				ldb_set_errstring(ldb, "samldb: Unrecognized account type!");
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
			ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
						 "sAMAccountType",
						 account_type);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			el2 = ldb_msg_find_element(ac->msg, "sAMAccountType");
			el2->flags = LDB_FLAG_MOD_REPLACE;
		}
	}

	return LDB_SUCCESS;
}

/*
 * "Primary group ID" trigger (MS-SAMR 3.1.1.8.2)
 *
 * Has to be invoked on "add" and "modify" operations on "user" and "computer"
 * objects.
 * ac->msg contains the "add"/"modify" message
 */

static int samldb_prim_group_set(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_dn *prim_group_dn;
	uint32_t rid;
	struct dom_sid *sid;

	rid = ldb_msg_find_attr_as_uint(ac->msg, "primaryGroupID", (uint32_t) -1);
	if (rid == (uint32_t) -1) {
		/* we aren't affected of any primary group set */
		return LDB_SUCCESS;

	} else if (!ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID)) {
		ldb_set_errstring(ldb,
				  "The primary group isn't settable on add operations!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), rid);
	if (sid == NULL) {
		return ldb_operr(ldb);
	}

	prim_group_dn = samdb_search_dn(ldb, ac, NULL, "(objectSid=%s)",
					ldap_encode_ndr_dom_sid(ac, sid));
	if (prim_group_dn == NULL) {
		ldb_asprintf_errstring(ldb,
				       "Failed to find primary group with RID %u!",
				       rid);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	return LDB_SUCCESS;
}

static int samldb_prim_group_change(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	const char * attrs[] = { "primaryGroupID", "memberOf", NULL };
	struct ldb_result *res;
	struct ldb_message_element *el;
	struct ldb_message *msg;
	uint32_t rid;
	struct dom_sid *sid;
	struct ldb_dn *prev_prim_group_dn, *new_prim_group_dn;
	int ret;

	/* Fetch informations from the existing object */

	ret = ldb_search(ldb, ac, &res, ac->msg->dn, LDB_SCOPE_BASE, attrs,
			 NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Finds out the DN of the old primary group */

	rid = ldb_msg_find_attr_as_uint(res->msgs[0], "primaryGroupID", (uint32_t) -1);
	if (rid == (uint32_t) -1) {
		/* User objects do always have a mandatory "primaryGroupID"
		 * attribute. If this doesn't exist then the object is of the
		 * wrong type. This is the exact Windows error code */
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), rid);
	if (sid == NULL) {
		return ldb_operr(ldb);
	}

	prev_prim_group_dn = samdb_search_dn(ldb, ac, NULL, "(objectSid=%s)",
					     ldap_encode_ndr_dom_sid(ac, sid));
	if (prev_prim_group_dn == NULL) {
		return ldb_operr(ldb);
	}

	/* Finds out the DN of the new primary group */

	rid = ldb_msg_find_attr_as_uint(ac->msg, "primaryGroupID", (uint32_t) -1);
	if (rid == (uint32_t) -1) {
		/* we aren't affected of any primary group change */
		return LDB_SUCCESS;
	}

	sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), rid);
	if (sid == NULL) {
		return ldb_operr(ldb);
	}

	new_prim_group_dn = samdb_search_dn(ldb, ac, NULL, "(objectSid=%s)",
					    ldap_encode_ndr_dom_sid(ac, sid));
	if (new_prim_group_dn == NULL) {
		/* Here we know if the specified new primary group candidate is
		 * valid or not. */
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* Only update the "member" attributes when we really do have a change */
	if (ldb_dn_compare(new_prim_group_dn, prev_prim_group_dn) != 0) {
		/* We need to be already a normal member of the new primary
		 * group in order to be successful. */
		el = samdb_find_attribute(ldb, res->msgs[0], "memberOf",
					  ldb_dn_get_linearized(new_prim_group_dn));
		if (el == NULL) {
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		/* Remove the "member" attribute on the new primary group */
		msg = talloc_zero(ac, struct ldb_message);
		msg->dn = new_prim_group_dn;

		ret = samdb_msg_add_delval(ldb, ac, msg, "member",
					   ldb_dn_get_linearized(ac->msg->dn));
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ret = dsdb_module_modify(ac->module, msg, DSDB_FLAG_NEXT_MODULE);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/* Add a "member" attribute for the previous primary group */
		msg = talloc_zero(ac, struct ldb_message);
		msg->dn = prev_prim_group_dn;

		ret = samdb_msg_add_addval(ldb, ac, msg, "member",
					   ldb_dn_get_linearized(ac->msg->dn));
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ret = dsdb_module_modify(ac->module, msg, DSDB_FLAG_NEXT_MODULE);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

static int samldb_prim_group_trigger(struct samldb_ctx *ac)
{
	int ret;

	if (ac->req->operation == LDB_ADD) {
		ret = samldb_prim_group_set(ac);
	} else {
		ret = samldb_prim_group_change(ac);
	}

	return ret;
}

static int samldb_member_check(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_message_element *el;
	struct ldb_dn *member_dn, *group_dn;
	uint32_t prim_group_rid;
	struct dom_sid *sid;
	unsigned int i;

	ldb = ldb_module_get_ctx(ac->module);

	el = ldb_msg_find_element(ac->msg, "member");
	if (el == NULL) {
		/* we aren't affected */
		return LDB_SUCCESS;
	}

	for (i = 0; i < el->num_values; i++) {
		/* Denies to add "member"s to groups which are primary ones
		 * for them */
		member_dn = ldb_dn_from_ldb_val(ac, ldb, &el->values[i]);
		if (!ldb_dn_validate(member_dn)) {
			return ldb_operr(ldb);
		}

		prim_group_rid = samdb_search_uint(ldb, ac, (uint32_t) -1,
						   member_dn, "primaryGroupID",
						   NULL);
		if (prim_group_rid == (uint32_t) -1) {
			/* the member hasn't to be a user account -> therefore
			 * no check needed in this case. */
			continue;
		}

		sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb),
				      prim_group_rid);
		if (sid == NULL) {
			return ldb_operr(ldb);
		}

		group_dn = samdb_search_dn(ldb, ac, NULL, "(objectSid=%s)",
					   ldap_encode_ndr_dom_sid(ac, sid));
		if (group_dn == NULL) {
			return ldb_operr(ldb);
		}

		if (ldb_dn_compare(group_dn, ac->msg->dn) == 0) {
			return LDB_ERR_ENTRY_ALREADY_EXISTS;
		}
	}

	return LDB_SUCCESS;
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
		return ldb_operr(ldb);
	}

	/* build the new msg */
	ac->msg = ldb_msg_copy_shallow(ac, req->op.add.message);
	if (ac->msg == NULL) {
		talloc_free(ac);
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "samldb_add: ldb_msg_copy_shallow failed!\n");
		return ldb_operr(ldb);
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "user") != NULL) {
		ac->type = "user";

		ret = samldb_prim_group_trigger(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ret = samldb_objectclass_trigger(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		return samldb_fill_object(ac);
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "group") != NULL) {
		ac->type = "group";

		ret = samldb_objectclass_trigger(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		return samldb_fill_object(ac);
	}

	/* perhaps a foreignSecurityPrincipal? */
	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass",
				 "foreignSecurityPrincipal") != NULL) {
		return samldb_fill_foreignSecurityPrincipal_object(ac);
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "classSchema") != NULL) {
		ret = samldb_schema_info_update(ac);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}

		ac->type = "classSchema";
		return samldb_fill_object(ac);
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "attributeSchema") != NULL) {
		ret = samldb_schema_info_update(ac);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}

		ac->type = "attributeSchema";
		return samldb_fill_object(ac);
	}

	talloc_free(ac);

	/* nothing matched, go on */
	return ldb_next_request(module, req);
}

/* modify */
static int samldb_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	struct ldb_message_element *el, *el2;
	bool modified = false;
	int ret;
	uint32_t account_type;

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	/* make sure that "sAMAccountType" is not specified */
	el = ldb_msg_find_element(req->op.mod.message, "sAMAccountType");
	if (el != NULL) {
		ldb_set_errstring(ldb,
			"samldb: sAMAccountType must not be specified!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	/* make sure that "isCriticalSystemObject" is not specified */
	el = ldb_msg_find_element(req->op.mod.message, "isCriticalSystemObject");
	if (el != NULL) {
		if (ldb_request_get_control(req, LDB_CONTROL_RELAX_OID) == NULL) {
			ldb_set_errstring(ldb,
				"samldb: isCriticalSystemObject must not be specified!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}

	/* msDS-IntId is not allowed to be modified
	 * except when modification comes from replication */
	if (ldb_msg_find_element(req->op.mod.message, "msDS-IntId")) {
		if (!ldb_request_get_control(req, DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	}

	ac = samldb_ctx_init(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* build the new msg */
	ac->msg = ldb_msg_copy_shallow(ac, req->op.mod.message);
	if (ac->msg == NULL) {
		talloc_free(ac);
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "samldb_modify: ldb_msg_copy_shallow failed!\n");
		return ldb_operr(ldb);
	}

	el = ldb_msg_find_element(ac->msg, "groupType");
	if (el && (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		uint32_t group_type, old_group_type;

		modified = true;

		group_type = ldb_msg_find_attr_as_uint(ac->msg, "groupType", 0);
		old_group_type = samdb_search_uint(ldb, ac, 0, ac->msg->dn,
						   "groupType", NULL);
		if (old_group_type == 0) {
			return ldb_operr(ldb);
		}

		/* Group type switching isn't so easy as it seems: We can only
		 * change in this directions: global <-> universal <-> local
		 * On each step also the group type itself
		 * (security/distribution) is variable. */

		switch (group_type) {
		case GTYPE_SECURITY_GLOBAL_GROUP:
		case GTYPE_DISTRIBUTION_GLOBAL_GROUP:
			/* change to "universal" allowed */
			if ((old_group_type == GTYPE_SECURITY_DOMAIN_LOCAL_GROUP) ||
			    (old_group_type == GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)) {
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
		break;

		case GTYPE_SECURITY_UNIVERSAL_GROUP:
		case GTYPE_DISTRIBUTION_UNIVERSAL_GROUP:
			/* each change allowed */
		break;

		case GTYPE_SECURITY_DOMAIN_LOCAL_GROUP:
		case GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP:
			/* change to "universal" allowed */
			if ((old_group_type == GTYPE_SECURITY_GLOBAL_GROUP) ||
			    (old_group_type == GTYPE_DISTRIBUTION_GLOBAL_GROUP)) {
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
		break;

		case GTYPE_SECURITY_BUILTIN_LOCAL_GROUP:
		default:
			/* we don't allow this "groupType" values */
			return LDB_ERR_UNWILLING_TO_PERFORM;
		break;
		}

		account_type =  ds_gtype2atype(group_type);
		if (account_type == 0) {
			ldb_set_errstring(ldb, "samldb: Unrecognized account type!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
					 "sAMAccountType",
					 account_type);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el2 = ldb_msg_find_element(ac->msg, "sAMAccountType");
		el2->flags = LDB_FLAG_MOD_REPLACE;
	}
	el = ldb_msg_find_element(ac->msg, "groupType");
	if (el && (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE)) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	el = ldb_msg_find_element(ac->msg, "primaryGroupID");
	if (el && (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		modified = true;

		ret = samldb_prim_group_change(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	el = ldb_msg_find_element(ac->msg, "primaryGroupID");
	if (el && (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE)) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	el = ldb_msg_find_element(ac->msg, "userAccountControl");
	if (el && (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		uint32_t user_account_control;

		modified = true;

		user_account_control = ldb_msg_find_attr_as_uint(ac->msg,
								 "userAccountControl",
								 0);

		/* Temporary duplicate accounts aren't allowed */
		if ((user_account_control & UF_TEMP_DUPLICATE_ACCOUNT) != 0) {
			return LDB_ERR_OTHER;
		}

		account_type = ds_uf2atype(user_account_control);
		if (account_type == 0) {
			ldb_set_errstring(ldb, "samldb: Unrecognized account type!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
					 "sAMAccountType",
					 account_type);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el2 = ldb_msg_find_element(ac->msg, "sAMAccountType");
		el2->flags = LDB_FLAG_MOD_REPLACE;

		if (user_account_control & (UF_SERVER_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT)) {
			ret = samdb_msg_add_string(ldb, ac->msg, ac->msg,
						   "isCriticalSystemObject",
						   "TRUE");
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			el2 = ldb_msg_find_element(ac->msg,
						   "isCriticalSystemObject");
			el2->flags = LDB_FLAG_MOD_REPLACE;
		}

		if (!ldb_msg_find_element(ac->msg, "primaryGroupID")) {
			uint32_t rid = ds_uf2prim_group_rid(user_account_control);

			ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
						 "primaryGroupID", rid);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			el2 = ldb_msg_find_element(ac->msg,
						   "primaryGroupID");
			el2->flags = LDB_FLAG_MOD_REPLACE;
		}
	}
	el = ldb_msg_find_element(ac->msg, "userAccountControl");
	if (el && (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE)) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	el = ldb_msg_find_element(ac->msg, "member");
	if (el && el->flags & (LDB_FLAG_MOD_ADD|LDB_FLAG_MOD_REPLACE) && el->num_values == 1) {
		ret = samldb_member_check(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (modified) {
		struct ldb_request *child_req;

		/* Now perform the real modifications as a child request */
		ret = ldb_build_mod_req(&child_req, ldb, ac,
					ac->msg,
					req->controls,
					req, dsdb_next_callback,
					req);
		LDB_REQ_SET_LOCATION(child_req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		return ldb_next_request(module, child_req);
	}

	talloc_free(ac);

	/* no change which interests us, go on */
	return ldb_next_request(module, req);
}

/* delete */

static int samldb_prim_group_users_check(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	struct dom_sid *sid;
	uint32_t rid;
	NTSTATUS status;
	int count;

	ldb = ldb_module_get_ctx(ac->module);

	/* Finds out the SID/RID of the SAM object */
	sid = samdb_search_dom_sid(ldb, ac, ac->req->op.del.dn, "objectSid",
				   NULL);
	if (sid == NULL) {
		/* No SID - it might not be a SAM object - therefore ok */
		return LDB_SUCCESS;
	}
	status = dom_sid_split_rid(ac, sid, NULL, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		return ldb_operr(ldb);
	}
	if (rid == 0) {
		/* Special object (security principal?) */
		return LDB_SUCCESS;
	}

	/* Deny delete requests from groups which are primary ones */
	count = samdb_search_count(ldb, NULL,
				   "(&(primaryGroupID=%u)(objectClass=user))",
				   rid);
	if (count < 0) {
		return ldb_operr(ldb);
	}
	if (count > 0) {
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	}

	return LDB_SUCCESS;
}

static int samldb_delete(struct ldb_module *module, struct ldb_request *req)
{
	struct samldb_ctx *ac;
	int ret;

	if (ldb_dn_is_special(req->op.del.dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ac = samldb_ctx_init(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb_module_get_ctx(module));
	}

	ret = samldb_prim_group_users_check(ac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_free(ac);

	return ldb_next_request(module, req);
}

/* extended */

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

