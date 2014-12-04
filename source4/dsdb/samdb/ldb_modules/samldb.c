/*
   SAM ldb module

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2014
   Copyright (C) Simo Sorce  2004-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009-2011
   Copyright (C) Matthieu Patou 2012

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
#include "auth/auth.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/ldb_modules/ridalloc.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "ldb_wrap.h"
#include "param/param.h"
#include "libds/common/flag_mapping.h"

struct samldb_ctx;
enum samldb_add_type {
	SAMLDB_TYPE_USER,
	SAMLDB_TYPE_GROUP,
	SAMLDB_TYPE_CLASS,
	SAMLDB_TYPE_ATTRIBUTE
};

typedef int (*samldb_step_fn_t)(struct samldb_ctx *);

struct samldb_step {
	struct samldb_step *next;
	samldb_step_fn_t fn;
};

struct samldb_ctx {
	struct ldb_module *module;
	struct ldb_request *req;

	/* used for add operations */
	enum samldb_add_type type;

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

	/* We exit the samldb module here. If someone set an "ares" to forward
	 * controls and response back to the caller, use them. */
	if (ac->ares) {
		return ldb_module_done(ac->req, ac->ares->controls,
				       ac->ares->response, LDB_SUCCESS);
	} else {
		return ldb_module_done(ac->req, NULL, NULL, LDB_SUCCESS);
	}
}


/* sAMAccountName handling */

static int samldb_generate_sAMAccountName(struct ldb_context *ldb,
					  struct ldb_message *msg)
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
	struct ldb_result *res;
	const char * const noattrs[] = { NULL };

	if (ldb_msg_find_element(ac->msg, "sAMAccountName") == NULL) {
		ret = samldb_generate_sAMAccountName(ldb, ac->msg);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	name = ldb_msg_find_attr_as_string(ac->msg, "sAMAccountName", NULL);
	if (name == NULL) {
		/* The "sAMAccountName" cannot be nothing */
		ldb_set_errstring(ldb,
				  "samldb: Empty account names aren't allowed!");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	ret = dsdb_module_search(ac->module, ac, &res,
				 ldb_get_default_basedn(ldb), LDB_SCOPE_SUBTREE, noattrs,
				 DSDB_FLAG_NEXT_MODULE,
				 ac->req,
				 "(sAMAccountName=%s)",
				 ldb_binary_encode_string(ac, name));
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count != 0) {
		ldb_asprintf_errstring(ldb,
				       "samldb: Account name (sAMAccountName) '%s' already in use!",
				       name);
		talloc_free(res);
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	}
	talloc_free(res);

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

	ret = ridalloc_allocate_rid(ac->module, &rid, ac->req);
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
static bool samldb_krbtgtnumber_available(struct samldb_ctx *ac,
					  uint32_t krbtgt_number)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ac);
	struct ldb_result *res;
	const char * const no_attrs[] = { NULL };
	int ret;

	ret = dsdb_module_search(ac->module, tmp_ctx, &res,
				 ldb_get_default_basedn(ldb_module_get_ctx(ac->module)),
				 LDB_SCOPE_SUBTREE, no_attrs,
				 DSDB_FLAG_NEXT_MODULE,
				 ac->req,
				 "(msDC-SecondaryKrbTgtNumber=%u)",
				 krbtgt_number);
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
	struct ldb_val newpass_utf16;

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
	ret = ldb_msg_add_empty(ac->msg, "msDS-SecondaryKrbTgtNumber",
				LDB_FLAG_INTERNAL_DISABLE_VALIDATION, NULL);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
				 "msDS-SecondaryKrbTgtNumber", krbtgt_number);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	ret = ldb_msg_add_fmt(ac->msg, "sAMAccountName", "krbtgt_%u",
			      krbtgt_number);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	newpass = generate_random_password(ac->msg, 128, 255);
	if (newpass == NULL) {
		return ldb_operr(ldb);
	}

	if (!convert_string_talloc(ac,
				   CH_UNIX, CH_UTF16,
				   newpass, strlen(newpass),
				   (void *)&newpass_utf16.data,
				   &newpass_utf16.length)) {
		ldb_asprintf_errstring(ldb,
				       "samldb_rodc_add: "
				       "failed to generate UTF16 password from random password");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_msg_add_steal_value(ac->msg, "clearTextPassword", &newpass_utf16);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	return samldb_next_step(ac);
}

static int samldb_find_for_defaultObjectCategory(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_result *res;
	const char * const no_attrs[] = { NULL };
	int ret;

	ac->res_dn = NULL;

	ret = dsdb_module_search(ac->module, ac, &res,
				 ac->dn, LDB_SCOPE_BASE, no_attrs,
				 DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT
				 | DSDB_FLAG_NEXT_MODULE,
				 ac->req,
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

	if (ret == LDB_SUCCESS) {
		/* ensure the defaultObjectCategory has a full GUID */
		struct ldb_message *m;
		m = ldb_msg_new(ac->msg);
		if (m == NULL) {
			return ldb_oom(ldb);
		}
		m->dn = ac->msg->dn;
		if (ldb_msg_add_string(m, "defaultObjectCategory",
				       ldb_dn_get_extended_linearized(m, res->msgs[0]->dn, 1)) !=
		    LDB_SUCCESS) {
			return ldb_oom(ldb);
		}
		m->elements[0].flags = LDB_FLAG_MOD_REPLACE;

		ret = dsdb_module_modify(ac->module, m,
					 DSDB_FLAG_NEXT_MODULE,
					 ac->req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
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
	struct samldb_msds_intid_persistant *msds_intid_struct;
	struct dsdb_schema *schema;

	ldb = ldb_module_get_ctx(ac->module);
	schema_dn = ldb_get_schema_basedn(ldb);

	/* replicated update should always go through */
	if (ldb_request_get_control(ac->req,
				    DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
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
	schema = dsdb_get_schema(ldb, NULL);
	if (!schema) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "samldb_schema_info_update: no dsdb_schema loaded");
		DEBUG(0,(__location__ ": %s\n", ldb_errstring(ldb)));
		return ldb_operr(ldb);
	}

	msds_intid_struct = (struct samldb_msds_intid_persistant*) ldb_get_opaque(ldb, SAMLDB_MSDS_INTID_OPAQUE);
	if (!msds_intid_struct) {
		msds_intid_struct = talloc(ldb, struct samldb_msds_intid_persistant);
		/* Generate new value for msDs-IntId
		* Value should be in 0x80000000..0xBFFFFFFF range */
		msds_intid = generate_random() % 0X3FFFFFFF;
		msds_intid += 0x80000000;
		msds_intid_struct->msds_intid = msds_intid;
		msds_intid_struct->usn = schema->loaded_usn;
		DEBUG(2, ("No samldb_msds_intid_persistant struct, allocating a new one\n"));
	} else {
		msds_intid = msds_intid_struct->msds_intid;
	}

	/* probe id values until unique one is found */
	do {
		uint64_t current_usn;
		msds_intid++;
		if (msds_intid > 0xBFFFFFFF) {
			msds_intid = 0x80000001;
		}
		/*
		 * Alternative strategy to a costly (even indexed search) to the
		 * database.
		 * We search in the schema if we have already this intid (using dsdb_attribute_by_attributeID_id because
		 * in the range 0x80000000 0xBFFFFFFFF, attributeID is a DSDB_ATTID_TYPE_INTID).
		 * If so generate another random value.
		 * If not check if the highest USN in the database for the schema partition is the
		 * one that we know.
		 * If so it means that's only this ldb context that is touching the schema in the database.
		 * If not it means that's someone else has modified the database while we are doing our changes too
		 * (this case should be very bery rare) in order to be sure do the search in the database.
		 */
		if (dsdb_attribute_by_attributeID_id(schema, msds_intid)) {
			msds_intid = generate_random() % 0X3FFFFFFF;
			msds_intid += 0x80000000;
			continue;
		}

		ret = dsdb_module_load_partition_usn(ac->module, schema_dn,
						     &current_usn, NULL, NULL);
		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_ERROR,
				      __location__": Searching for schema USN failed: %s\n",
				      ldb_errstring(ldb));
			return ldb_operr(ldb);
		}

		/* current_usn can be lesser than msds_intid_struct-> if there is
		 * uncommited changes.
		 */
		if (current_usn > msds_intid_struct->usn) {
			/* oups something has changed, someone/something
			 * else is modifying or has modified the schema
			 * we'd better check this intid is the database directly
			 */

			DEBUG(2, ("Schema has changed, searching the database for the unicity of %d\n",
					msds_intid));

			ret = dsdb_module_search(ac->module, ac,
						&ldb_res,
						schema_dn, LDB_SCOPE_ONELEVEL, NULL,
						DSDB_FLAG_NEXT_MODULE,
						ac->req,
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
		} else {
			id_exists = 0;
		}

	} while(id_exists);
	msds_intid_struct->msds_intid = msds_intid;
	ldb_set_opaque(ldb, SAMLDB_MSDS_INTID_OPAQUE, msds_intid_struct);

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
		ldb_asprintf_errstring(ldb, "Invalid LDB reply type %d", ares->type);
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
	rodc_filtered_flags = (SEARCH_FLAG_RODC_ATTRIBUTE
			      | SEARCH_FLAG_CONFIDENTIAL);

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

	/* Add information for the different account types */
	switch(ac->type) {
	case SAMLDB_TYPE_USER: {
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
		break;
	}

	case SAMLDB_TYPE_GROUP: {
		/* check if we have a valid sAMAccountName */
		ret = samldb_add_step(ac, samldb_check_sAMAccountName);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_add_entry);
		if (ret != LDB_SUCCESS) return ret;
		break;
	}

	case SAMLDB_TYPE_CLASS: {
		const struct ldb_val *rdn_value, *def_obj_cat_val;
		unsigned int v = ldb_msg_find_attr_as_uint(ac->msg, "objectClassCategory", -2);

		/* As discussed with Microsoft through dochelp in April 2012 this is the behavior of windows*/
		if (!ldb_msg_find_element(ac->msg, "subClassOf")) {
			ret = ldb_msg_add_string(ac->msg, "subClassOf", "top");
			if (ret != LDB_SUCCESS) return ret;
		}

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
		if (rdn_value == NULL) {
			return ldb_operr(ldb);
		}
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

			ret = ldb_msg_add_string(ac->msg, "defaultObjectCategory",
						 ldb_dn_alloc_linearized(ac->msg, ac->dn));
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

		/* -2 is not a valid objectClassCategory so it means the attribute wasn't present */
		if (v == -2) {
			/* Windows 2003 does this*/
			ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg, "objectClassCategory", 0);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
		break;
	}

	case SAMLDB_TYPE_ATTRIBUTE: {
		const struct ldb_val *rdn_value;
		struct ldb_message_element *el;
		rdn_value = ldb_dn_get_rdn_val(ac->msg->dn);
		if (rdn_value == NULL) {
			return ldb_operr(ldb);
		}
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
			ldb_asprintf_errstring(ldb,
					       "samldb: refusing schema add of %s - cannot combine critical attribute with RODC filtering",
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

		el = ldb_msg_find_element(ac->msg, "attributeSyntax");
		if (el) {
			/*
			 * No need to scream if there isn't as we have code later on
			 * that will take care of it.
			 */
			const struct dsdb_syntax *syntax = find_syntax_map_by_ad_oid((const char *)el->values[0].data);
			if (!syntax) {
				DEBUG(9, ("Can't find dsdb_syntax object for attributeSyntax %s\n",
						(const char *)el->values[0].data));
			} else {
				unsigned int v = ldb_msg_find_attr_as_uint(ac->msg, "oMSyntax", 0);
				const struct ldb_val *val = ldb_msg_find_ldb_val(ac->msg, "oMObjectClass");

				if (v == 0) {
					ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg, "oMSyntax", syntax->oMSyntax);
					if (ret != LDB_SUCCESS) {
						return ret;
					}
				}
				if (!val) {
					struct ldb_val val2 = ldb_val_dup(ldb, &syntax->oMObjectClass);
					if (val2.length > 0) {
						ret = ldb_msg_add_value(ac->msg, "oMObjectClass", &val2, NULL);
						if (ret != LDB_SUCCESS) {
							return ret;
						}
					}
				}
			}
		}

		/* handle msDS-IntID attribute */
		ret = samldb_add_handle_msDS_IntId(ac);
		if (ret != LDB_SUCCESS) return ret;

		ret = samldb_add_step(ac, samldb_add_entry);
		if (ret != LDB_SUCCESS) return ret;
		break;
	}

	default:
		ldb_asprintf_errstring(ldb, "Invalid entry type!");
		return LDB_ERR_OPERATIONS_ERROR;
		break;
	}

	return samldb_first_step(ac);
}

static int samldb_fill_foreignSecurityPrincipal_object(struct samldb_ctx *ac)
{
	struct ldb_context *ldb;
	const struct ldb_val *rdn_value;
	struct dom_sid *sid;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	sid = samdb_result_dom_sid(ac->msg, ac->msg, "objectSid");
	if (sid == NULL) {
		rdn_value = ldb_dn_get_rdn_val(ac->msg->dn);
		if (rdn_value == NULL) {
			return ldb_operr(ldb);
		}
		sid = dom_sid_parse_talloc(ac->msg,
					   (const char *)rdn_value->data);
		if (sid == NULL) {
			ldb_set_errstring(ldb,
					  "samldb: No valid SID found in ForeignSecurityPrincipal CN!");
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
	int ret;
	struct ldb_context *ldb;
	struct dsdb_schema *schema;

	/* replicated update should always go through */
	if (ldb_request_get_control(ac->req,
				    DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
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

	ret = dsdb_module_schema_info_update(ac->module, schema,
					     DSDB_FLAG_NEXT_MODULE|
					     DSDB_FLAG_AS_SYSTEM,
					     ac->req);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb,
				       "samldb_schema_info_update: dsdb_module_schema_info_update failed with %s",
				       ldb_errstring(ldb));
		return ret;
	}

	return LDB_SUCCESS;
}

static int samldb_prim_group_tester(struct samldb_ctx *ac, uint32_t rid);
static int samldb_check_user_account_control_acl(struct samldb_ctx *ac,
						 struct dom_sid *sid,
						 uint32_t user_account_control,
						 uint32_t user_account_control_old);

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
	void *skip_allocate_sids = ldb_get_opaque(ldb,
						  "skip_allocate_sids");
	struct ldb_message_element *el, *el2;
	struct dom_sid *sid;
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
		ldb_set_errstring(ldb,
				  "samldb: objectSid must not be specified!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* but generate a new SID when we do have an add operations */
	if ((sid == NULL) && (ac->req->operation == LDB_ADD) && !skip_allocate_sids) {
		ret = samldb_add_step(ac, samldb_allocate_sid);
		if (ret != LDB_SUCCESS) return ret;
	}

	switch(ac->type) {
	case SAMLDB_TYPE_USER: {
		bool uac_generated = false, uac_add_flags = false;

		/* Step 1.2: Default values */
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"accountExpires", "9223372036854775807");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"badPasswordTime", "0");
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
			"lastLogoff", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"lastLogon", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"logonCount", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->msg,
			"pwdLastSet", "0");
		if (ret != LDB_SUCCESS) return ret;

		/* On add operations we might need to generate a
		 * "userAccountControl" (if it isn't specified). */
		el = ldb_msg_find_element(ac->msg, "userAccountControl");
		if ((el == NULL) && (ac->req->operation == LDB_ADD)) {
			ret = samdb_msg_set_uint(ldb, ac->msg, ac->msg,
						 "userAccountControl",
						 UF_NORMAL_ACCOUNT);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			uac_generated = true;
			uac_add_flags = true;
		}

		el = ldb_msg_find_element(ac->msg, "userAccountControl");
		if (el != NULL) {
			uint32_t user_account_control, account_type;
			/* Step 1.3: "userAccountControl" -> "sAMAccountType" mapping */
			user_account_control = ldb_msg_find_attr_as_uint(ac->msg,
									 "userAccountControl",
									 0);
			/* "userAccountControl" = 0 means "UF_NORMAL_ACCOUNT" */
			if (user_account_control == 0) {
				user_account_control = UF_NORMAL_ACCOUNT;
				uac_generated = true;
			}

			/*
			 * As per MS-SAMR 3.1.1.8.10 these flags have not to be set
			 */
			if ((user_account_control & UF_LOCKOUT) != 0) {
				user_account_control &= ~UF_LOCKOUT;
				uac_generated = true;
			}
			if ((user_account_control & UF_PASSWORD_EXPIRED) != 0) {
				user_account_control &= ~UF_PASSWORD_EXPIRED;
				uac_generated = true;
			}

			/* Temporary duplicate accounts aren't allowed */
			if ((user_account_control & UF_TEMP_DUPLICATE_ACCOUNT) != 0) {
				return LDB_ERR_OTHER;
			}

			/* Workstation and (read-only) DC objects do need objectclass "computer" */
			if ((samdb_find_attribute(ldb, ac->msg,
						  "objectclass", "computer") == NULL) &&
			    (user_account_control &
			     (UF_SERVER_TRUST_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT))) {
				ldb_set_errstring(ldb,
						  "samldb: Requested account type does need objectclass 'computer'!");
				return LDB_ERR_OBJECT_CLASS_VIOLATION;
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

			/* "isCriticalSystemObject" might be set */
			if (user_account_control &
			    (UF_SERVER_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT)) {
				ret = ldb_msg_add_string(ac->msg, "isCriticalSystemObject",
							 "TRUE");
				if (ret != LDB_SUCCESS) {
					return ret;
				}
				el2 = ldb_msg_find_element(ac->msg,
							   "isCriticalSystemObject");
				el2->flags = LDB_FLAG_MOD_REPLACE;
			} else if (user_account_control & UF_WORKSTATION_TRUST_ACCOUNT) {
				ret = ldb_msg_add_string(ac->msg, "isCriticalSystemObject",
							 "FALSE");
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

				/*
				 * Older AD deployments don't know about the
				 * RODC group
				 */
				if (rid == DOMAIN_RID_READONLY_DCS) {
					ret = samldb_prim_group_tester(ac, rid);
					if (ret != LDB_SUCCESS) {
						return ret;
					}
				}

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
			/* Obviously this is done when the "userAccountControl"
			 * has been generated here (tested against Windows
			 * Server) */
			if (uac_generated) {
				if (uac_add_flags) {
					user_account_control |= UF_ACCOUNTDISABLE;
					user_account_control |= UF_PASSWD_NOTREQD;
				}

				ret = samdb_msg_set_uint(ldb, ac->msg, ac->msg,
							 "userAccountControl",
							 user_account_control);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}

			ret = samldb_check_user_account_control_acl(ac, NULL,
								    user_account_control, 0);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
		break;
	}

	case SAMLDB_TYPE_GROUP: {
		const char *tempstr;

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
		break;
	}

	default:
		ldb_asprintf_errstring(ldb,
				"Invalid entry type!");
		return LDB_ERR_OPERATIONS_ERROR;
		break;
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

static int samldb_prim_group_tester(struct samldb_ctx *ac, uint32_t rid)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct dom_sid *sid;
	struct ldb_result *res;
	int ret;
	const char * const noattrs[] = { NULL };

	sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), rid);
	if (sid == NULL) {
		return ldb_operr(ldb);
	}

	ret = dsdb_module_search(ac->module, ac, &res,
				 ldb_get_default_basedn(ldb),
				 LDB_SCOPE_SUBTREE,
				 noattrs, DSDB_FLAG_NEXT_MODULE,
				 ac->req,
				 "(objectSid=%s)",
				 ldap_encode_ndr_dom_sid(ac, sid));
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count != 1) {
		talloc_free(res);
		ldb_asprintf_errstring(ldb,
				       "Failed to find primary group with RID %u!",
				       rid);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	talloc_free(res);

	return LDB_SUCCESS;
}

static int samldb_prim_group_set(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	uint32_t rid;

	rid = ldb_msg_find_attr_as_uint(ac->msg, "primaryGroupID", (uint32_t) -1);
	if (rid == (uint32_t) -1) {
		/* we aren't affected of any primary group set */
		return LDB_SUCCESS;

	} else if (!ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID)) {
		ldb_set_errstring(ldb,
				  "The primary group isn't settable on add operations!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	return samldb_prim_group_tester(ac, rid);
}

static int samldb_prim_group_change(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	const char * const attrs[] = { "primaryGroupID", "memberOf", NULL };
	struct ldb_result *res, *group_res;
	struct ldb_message_element *el;
	struct ldb_message *msg;
	uint32_t prev_rid, new_rid;
	struct dom_sid *prev_sid, *new_sid;
	struct ldb_dn *prev_prim_group_dn, *new_prim_group_dn;
	int ret;
	const char * const noattrs[] = { NULL };

	el = dsdb_get_single_valued_attr(ac->msg, "primaryGroupID",
					 ac->req->operation);
	if (el == NULL) {
		/* we are not affected */
		return LDB_SUCCESS;
	}

	/* Fetch information from the existing object */

	ret = dsdb_module_search_dn(ac->module, ac, &res, ac->msg->dn, attrs,
				    DSDB_FLAG_NEXT_MODULE, ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Finds out the DN of the old primary group */

	prev_rid = ldb_msg_find_attr_as_uint(res->msgs[0], "primaryGroupID",
					     (uint32_t) -1);
	if (prev_rid == (uint32_t) -1) {
		/* User objects do always have a mandatory "primaryGroupID"
		 * attribute. If this doesn't exist then the object is of the
		 * wrong type. This is the exact Windows error code */
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	prev_sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), prev_rid);
	if (prev_sid == NULL) {
		return ldb_operr(ldb);
	}

	/* Finds out the DN of the new primary group
	 * Notice: in order to parse the primary group ID correctly we create
	 * a temporary message here. */

	msg = ldb_msg_new(ac->msg);
	if (msg == NULL) {
		return ldb_module_oom(ac->module);
	}
	ret = ldb_msg_add(msg, el, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	new_rid = ldb_msg_find_attr_as_uint(msg, "primaryGroupID", (uint32_t) -1);
	talloc_free(msg);
	if (new_rid == (uint32_t) -1) {
		/* we aren't affected of any primary group change */
		return LDB_SUCCESS;
	}

	if (prev_rid == new_rid) {
		return LDB_SUCCESS;
	}

	ret = dsdb_module_search(ac->module, ac, &group_res,
				 ldb_get_default_basedn(ldb),
				 LDB_SCOPE_SUBTREE,
				 noattrs, DSDB_FLAG_NEXT_MODULE,
				 ac->req,
				 "(objectSid=%s)",
				 ldap_encode_ndr_dom_sid(ac, prev_sid));
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (group_res->count != 1) {
		return ldb_operr(ldb);
	}
	prev_prim_group_dn = group_res->msgs[0]->dn;

	new_sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb), new_rid);
	if (new_sid == NULL) {
		return ldb_operr(ldb);
	}

	ret = dsdb_module_search(ac->module, ac, &group_res,
				 ldb_get_default_basedn(ldb),
				 LDB_SCOPE_SUBTREE,
				 noattrs, DSDB_FLAG_NEXT_MODULE,
				 ac->req,
				 "(objectSid=%s)",
				 ldap_encode_ndr_dom_sid(ac, new_sid));
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (group_res->count != 1) {
		/* Here we know if the specified new primary group candidate is
		 * valid or not. */
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	new_prim_group_dn = group_res->msgs[0]->dn;

	/* We need to be already a normal member of the new primary
	 * group in order to be successful. */
	el = samdb_find_attribute(ldb, res->msgs[0], "memberOf",
				  ldb_dn_get_linearized(new_prim_group_dn));
	if (el == NULL) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* Remove the "member" attribute on the new primary group */
	msg = ldb_msg_new(ac->msg);
	if (msg == NULL) {
		return ldb_module_oom(ac->module);
	}
	msg->dn = new_prim_group_dn;

	ret = samdb_msg_add_delval(ldb, msg, msg, "member",
				   ldb_dn_get_linearized(ac->msg->dn));
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_module_modify(ac->module, msg, DSDB_FLAG_NEXT_MODULE, ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	talloc_free(msg);

	/* Add a "member" attribute for the previous primary group */
	msg = ldb_msg_new(ac->msg);
	if (msg == NULL) {
		return ldb_module_oom(ac->module);
	}
	msg->dn = prev_prim_group_dn;

	ret = samdb_msg_add_addval(ldb, msg, msg, "member",
				   ldb_dn_get_linearized(ac->msg->dn));
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_module_modify(ac->module, msg, DSDB_FLAG_NEXT_MODULE, ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	talloc_free(msg);

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

/**
 * Validate that the restriction in point 5 of MS-SAMR 3.1.1.8.10 userAccountControl is honoured
 *
 */
static int samldb_check_user_account_control_acl(struct samldb_ctx *ac,
						 struct dom_sid *sid,
						 uint32_t user_account_control,
						 uint32_t user_account_control_old)
{
	int i, ret = 0;
	bool need_acl_check = false;
	struct ldb_result *res;
	const char * const sd_attrs[] = {"ntSecurityDescriptor", NULL};
	struct security_token *user_token;
	struct security_descriptor *domain_sd;
	struct ldb_dn *domain_dn = ldb_get_default_basedn(ldb_module_get_ctx(ac->module));
	const struct uac_to_guid {
		uint32_t uac;
		const char *oid;
		const char *guid;
		enum sec_privilege privilege;
		bool delete_is_privileged;
		const char *error_string;
	} map[] = {
		{
			.uac = UF_PASSWD_NOTREQD,
			.guid = GUID_DRS_UPDATE_PASSWORD_NOT_REQUIRED_BIT,
			.error_string = "Adding the UF_PASSWD_NOTREQD bit in userAccountControl requires the Update-Password-Not-Required-Bit right that was not given on the Domain object"
		},
		{
			.uac = UF_DONT_EXPIRE_PASSWD,
			.guid = GUID_DRS_UNEXPIRE_PASSWORD,
			.error_string = "Adding the UF_DONT_EXPIRE_PASSWD bit in userAccountControl requires the Unexpire-Password right that was not given on the Domain object"
		},
		{
			.uac = UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,
			.guid = GUID_DRS_ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD,
			.error_string = "Adding the UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED bit in userAccountControl requires the Enable-Per-User-Reversibly-Encrypted-Password right that was not given on the Domain object"
		},
		{
			.uac = UF_SERVER_TRUST_ACCOUNT,
			.guid = GUID_DRS_DS_INSTALL_REPLICA,
			.error_string = "Adding the UF_SERVER_TRUST_ACCOUNT bit in userAccountControl requires the DS-Install-Replica right that was not given on the Domain object"
		},
		{
			.uac = UF_PARTIAL_SECRETS_ACCOUNT,
			.guid = GUID_DRS_DS_INSTALL_REPLICA,
			.error_string = "Adding the UF_PARTIAL_SECRETS_ACCOUNT bit in userAccountControl requires the DS-Install-Replica right that was not given on the Domain object"
		},
		{
			.uac = UF_INTERDOMAIN_TRUST_ACCOUNT,
			.oid = DSDB_CONTROL_PERMIT_INTERDOMAIN_TRUST_UAC_OID,
			.error_string = "Updating the UF_INTERDOMAIN_TRUST_ACCOUNT bit in userAccountControl is not permitted over LDAP.  This bit is restricted to the LSA CreateTrustedDomain interface",
			.delete_is_privileged = true
		},
		{
			.uac = UF_TRUSTED_FOR_DELEGATION,
			.privilege = SEC_PRIV_ENABLE_DELEGATION,
			.delete_is_privileged = true,
			.error_string = "Updating the UF_TRUSTED_FOR_DELEGATION bit in userAccountControl is not permitted without the SeEnableDelegationPrivilege"
		},
		{
			.uac = UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
			.privilege = SEC_PRIV_ENABLE_DELEGATION,
			.delete_is_privileged = true,
			.error_string = "Updating the UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION bit in userAccountControl is not permitted without the SeEnableDelegationPrivilege"
		}

	};

	if (dsdb_module_am_system(ac->module)) {
		return LDB_SUCCESS;
	}

	for (i = 0; i < ARRAY_SIZE(map); i++) {
		if (user_account_control & map[i].uac) {
			need_acl_check = true;
			break;
		}
	}
	if (need_acl_check == false) {
		return LDB_SUCCESS;
	}

	user_token = acl_user_token(ac->module);
	if (user_token == NULL) {
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	ret = dsdb_module_search_dn(ac->module, ac, &res,
				    domain_dn,
				    sd_attrs,
				    DSDB_FLAG_NEXT_MODULE | DSDB_SEARCH_SHOW_DELETED,
				    ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count != 1) {
		return ldb_module_operr(ac->module);
	}

	ret = dsdb_get_sd_from_ldb_message(ldb_module_get_ctx(ac->module),
					   ac, res->msgs[0], &domain_sd);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	for (i = 0; i < ARRAY_SIZE(map); i++) {
		uint32_t this_uac_new = user_account_control & map[i].uac;
		uint32_t this_uac_old = user_account_control_old & map[i].uac;
		if (this_uac_new != this_uac_old) {
			if (this_uac_old != 0) {
				if (map[i].delete_is_privileged == false) {
					continue;
				}
			}
			if (map[i].oid) {
				struct ldb_control *control = ldb_request_get_control(ac->req, map[i].oid);
				if (control == NULL) {
					ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
				}
			} else if (map[i].privilege != SEC_PRIV_INVALID) {
				bool have_priv = security_token_has_privilege(user_token,
									      map[i].privilege);
				if (have_priv == false) {
					ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
				}
			} else {
				ret = acl_check_extended_right(ac, domain_sd,
							       user_token,
							       map[i].guid,
							       SEC_ADS_CONTROL_ACCESS,
							       sid);
			}
			if (ret != LDB_SUCCESS) {
				break;
			}
		}
	}
	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		switch (ac->req->operation) {
		case LDB_ADD:
			ldb_asprintf_errstring(ldb_module_get_ctx(ac->module),
					       "Failed to add %s: %s",
					       ldb_dn_get_linearized(ac->msg->dn),
					       map[i].error_string);
			break;
		case LDB_MODIFY:
			ldb_asprintf_errstring(ldb_module_get_ctx(ac->module),
					       "Failed to modify %s: %s",
					       ldb_dn_get_linearized(ac->msg->dn),
					       map[i].error_string);
			break;
		default:
			return ldb_module_operr(ac->module);
		}
		if (map[i].guid) {
			dsdb_acl_debug(domain_sd, acl_user_token(ac->module),
				       domain_dn,
				       true,
				       10);
		}
	}
	return ret;
}

/**
 * This function is called on LDB modify operations. It performs some additions/
 * replaces on the current LDB message when "userAccountControl" changes.
 */
static int samldb_user_account_control_change(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	uint32_t old_uac;
	uint32_t new_uac;
	uint32_t raw_uac;
	uint32_t old_ufa;
	uint32_t new_ufa;
	uint32_t old_acb;
	uint32_t new_acb;
	uint32_t clear_acb;
	uint32_t old_atype;
	uint32_t new_atype;
	uint32_t old_pgrid;
	uint32_t new_pgrid;
	NTTIME old_lockoutTime;
	struct ldb_message_element *el;
	struct ldb_val *val;
	struct ldb_val computer_val;
	struct ldb_message *tmp_msg;
	struct dom_sid *sid;
	int ret;
	struct ldb_result *res;
	const char * const attrs[] = {
		"objectClass",
		"isCriticalSystemObject",
		"userAccountControl",
		"msDS-User-Account-Control-Computed",
		"lockoutTime",
		"objectSid",
		NULL
	};
	bool is_computer = false;
	bool old_is_critical = false;
	bool new_is_critical = false;

	el = dsdb_get_single_valued_attr(ac->msg, "userAccountControl",
					 ac->req->operation);
	if (el == NULL || el->num_values == 0) {
		ldb_asprintf_errstring(ldb,
			"%08X: samldb: 'userAccountControl' can't be deleted!",
			W_ERROR_V(WERR_DS_ILLEGAL_MOD_OPERATION));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* Create a temporary message for fetching the "userAccountControl" */
	tmp_msg = ldb_msg_new(ac->msg);
	if (tmp_msg == NULL) {
		return ldb_module_oom(ac->module);
	}
	ret = ldb_msg_add(tmp_msg, el, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	raw_uac = ldb_msg_find_attr_as_uint(tmp_msg,
					    "userAccountControl",
					    0);
	new_acb = samdb_result_acct_flags(tmp_msg, NULL);
	talloc_free(tmp_msg);
	/*
	 * UF_LOCKOUT and UF_PASSWORD_EXPIRED are only generated
	 * and not stored. We ignore them almost completely.
	 *
	 * The only exception is the resulting ACB_AUTOLOCK in clear_acb.
	 */
	new_uac = raw_uac & ~(UF_LOCKOUT|UF_PASSWORD_EXPIRED);

	/* Fetch the old "userAccountControl" and "objectClass" */
	ret = dsdb_module_search_dn(ac->module, ac, &res, ac->msg->dn, attrs,
				    DSDB_FLAG_NEXT_MODULE, ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	old_uac = ldb_msg_find_attr_as_uint(res->msgs[0], "userAccountControl", 0);
	if (old_uac == 0) {
		return ldb_operr(ldb);
	}
	old_acb = samdb_result_acct_flags(res->msgs[0],
					  "msDS-User-Account-Control-Computed");
	old_lockoutTime = ldb_msg_find_attr_as_int64(res->msgs[0],
						     "lockoutTime", 0);
	old_is_critical = ldb_msg_find_attr_as_bool(res->msgs[0],
						    "isCriticalSystemObject", 0);
	/* When we do not have objectclass "omputer" we cannot switch to a (read-only) DC */
	el = ldb_msg_find_element(res->msgs[0], "objectClass");
	if (el == NULL) {
		return ldb_operr(ldb);
	}
	computer_val = data_blob_string_const("computer");
	val = ldb_msg_find_val(el, &computer_val);
	if (val != NULL) {
		is_computer = true;
	}

	old_ufa = old_uac & UF_ACCOUNT_TYPE_MASK;
	old_atype = ds_uf2atype(old_ufa);
	old_pgrid = ds_uf2prim_group_rid(old_uac);

	new_ufa = new_uac & UF_ACCOUNT_TYPE_MASK;
	if (new_ufa == 0) {
		/*
		 * When there is no account type embedded in "userAccountControl"
		 * fall back to the old.
		 */
		new_ufa = old_ufa;
		new_uac |= new_ufa;
	}
	new_atype = ds_uf2atype(new_ufa);
	new_pgrid = ds_uf2prim_group_rid(new_uac);

	clear_acb = old_acb & ~new_acb;

	switch (new_ufa) {
	case UF_NORMAL_ACCOUNT:
		new_is_critical = old_is_critical;
		break;

	case UF_INTERDOMAIN_TRUST_ACCOUNT:
		new_is_critical = true;
		break;

	case UF_WORKSTATION_TRUST_ACCOUNT:
		new_is_critical = false;
		break;

	case (UF_WORKSTATION_TRUST_ACCOUNT|UF_PARTIAL_SECRETS_ACCOUNT):
		if (!is_computer) {
			ldb_asprintf_errstring(ldb,
				"%08X: samldb: UF_PARTIAL_SECRETS_ACCOUNT "
				"requires objectclass 'computer'!",
				W_ERROR_V(WERR_DS_MACHINE_ACCOUNT_CREATED_PRENT4));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		new_is_critical = true;
		break;

	case UF_SERVER_TRUST_ACCOUNT:
		if (!is_computer) {
			ldb_asprintf_errstring(ldb,
				"%08X: samldb: UF_SERVER_TRUST_ACCOUNT "
				"requires objectclass 'computer'!",
				W_ERROR_V(WERR_DS_MACHINE_ACCOUNT_CREATED_PRENT4));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		new_is_critical = true;
		break;

	default:
		ldb_asprintf_errstring(ldb,
			"%08X: samldb: invalid userAccountControl[0x%08X]",
			W_ERROR_V(WERR_INVALID_PARAMETER), raw_uac);
		return LDB_ERR_OTHER;
	}

	if (old_atype != new_atype) {
		ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
					 "sAMAccountType", new_atype);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el = ldb_msg_find_element(ac->msg, "sAMAccountType");
		el->flags = LDB_FLAG_MOD_REPLACE;
	}

	/* As per MS-SAMR 3.1.1.8.10 these flags have not to be set */
	if ((clear_acb & ACB_AUTOLOCK) && (old_lockoutTime != 0)) {
		/* "pwdLastSet" reset as password expiration has been forced  */
		ldb_msg_remove_attr(ac->msg, "lockoutTime");
		ret = samdb_msg_add_uint64(ldb, ac->msg, ac->msg, "lockoutTime",
					   (NTTIME)0);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el = ldb_msg_find_element(ac->msg, "lockoutTime");
		el->flags = LDB_FLAG_MOD_REPLACE;
	}

	/* "isCriticalSystemObject" might be set/changed */
	if (old_is_critical != new_is_critical) {
		ret = ldb_msg_add_string(ac->msg, "isCriticalSystemObject",
					 new_is_critical ? "TRUE": "FALSE");
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el = ldb_msg_find_element(ac->msg,
					   "isCriticalSystemObject");
		el->flags = LDB_FLAG_MOD_REPLACE;
	}

	if (!ldb_msg_find_element(ac->msg, "primaryGroupID") &&
	    (old_pgrid != new_pgrid)) {
		/* Older AD deployments don't know about the RODC group */
		if (new_pgrid == DOMAIN_RID_READONLY_DCS) {
			ret = samldb_prim_group_tester(ac, new_pgrid);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}

		ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg,
					 "primaryGroupID", new_pgrid);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el = ldb_msg_find_element(ac->msg,
					   "primaryGroupID");
		el->flags = LDB_FLAG_MOD_REPLACE;
	}

	/* Propagate eventual "userAccountControl" attribute changes */
	if (old_uac != new_uac) {
		char *tempstr = talloc_asprintf(ac->msg, "%d",
						new_uac);
		if (tempstr == NULL) {
			return ldb_module_oom(ac->module);
		}

		/* Overwrite "userAccountControl" correctly */
		el = dsdb_get_single_valued_attr(ac->msg, "userAccountControl",
						 ac->req->operation);
		el->values[0].data = (uint8_t *) tempstr;
		el->values[0].length = strlen(tempstr);
	} else {
		ldb_msg_remove_attr(ac->msg, "userAccountControl");
	}

	sid = samdb_result_dom_sid(res, res->msgs[0], "objectSid");
	if (sid == NULL) {
		return ldb_module_operr(ac->module);
	}

	ret = samldb_check_user_account_control_acl(ac, sid, new_uac, old_uac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

static int samldb_lockout_time(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	NTTIME lockoutTime;
	struct ldb_message_element *el;
	struct ldb_message *tmp_msg;
	int ret;

	el = dsdb_get_single_valued_attr(ac->msg, "lockoutTime",
					 ac->req->operation);
	if (el == NULL || el->num_values == 0) {
		ldb_asprintf_errstring(ldb,
			"%08X: samldb: 'lockoutTime' can't be deleted!",
			W_ERROR_V(WERR_DS_ILLEGAL_MOD_OPERATION));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* Create a temporary message for fetching the "lockoutTime" */
	tmp_msg = ldb_msg_new(ac->msg);
	if (tmp_msg == NULL) {
		return ldb_module_oom(ac->module);
	}
	ret = ldb_msg_add(tmp_msg, el, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	lockoutTime = ldb_msg_find_attr_as_int64(tmp_msg,
						 "lockoutTime",
						 0);
	talloc_free(tmp_msg);

	if (lockoutTime != 0) {
		return LDB_SUCCESS;
	}

	/* lockoutTime == 0 resets badPwdCount */
	ldb_msg_remove_attr(ac->msg, "badPwdCount");
	ret = samdb_msg_add_int(ldb, ac->msg, ac->msg,
				"badPwdCount", 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	el = ldb_msg_find_element(ac->msg, "badPwdCount");
	el->flags = LDB_FLAG_MOD_REPLACE;

	return LDB_SUCCESS;
}

static int samldb_group_type_change(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	uint32_t group_type, old_group_type, account_type;
	struct ldb_message_element *el;
	struct ldb_message *tmp_msg;
	int ret;
	struct ldb_result *res;
	const char * const attrs[] = { "groupType", NULL };

	el = dsdb_get_single_valued_attr(ac->msg, "groupType",
					 ac->req->operation);
	if (el == NULL) {
		/* we are not affected */
		return LDB_SUCCESS;
	}

	/* Create a temporary message for fetching the "groupType" */
	tmp_msg = ldb_msg_new(ac->msg);
	if (tmp_msg == NULL) {
		return ldb_module_oom(ac->module);
	}
	ret = ldb_msg_add(tmp_msg, el, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	group_type = ldb_msg_find_attr_as_uint(tmp_msg, "groupType", 0);
	talloc_free(tmp_msg);

	ret = dsdb_module_search_dn(ac->module, ac, &res, ac->msg->dn, attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_SEARCH_SHOW_DELETED, ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	old_group_type = ldb_msg_find_attr_as_uint(res->msgs[0], "groupType", 0);
	if (old_group_type == 0) {
		return ldb_operr(ldb);
	}

	/* Group type switching isn't so easy as it seems: We can only
	 * change in this directions: global <-> universal <-> local
	 * On each step also the group type itself
	 * (security/distribution) is variable. */

	if (ldb_request_get_control(ac->req, LDB_CONTROL_PROVISION_OID) == NULL) {
		switch (group_type) {
		case GTYPE_SECURITY_GLOBAL_GROUP:
		case GTYPE_DISTRIBUTION_GLOBAL_GROUP:
			/* change to "universal" allowed */
			if ((old_group_type == GTYPE_SECURITY_DOMAIN_LOCAL_GROUP) ||
			(old_group_type == GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)) {
				ldb_set_errstring(ldb,
					"samldb: Change from security/distribution local group forbidden!");
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
				ldb_set_errstring(ldb,
					"samldb: Change from security/distribution global group forbidden!");
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
		break;

		case GTYPE_SECURITY_BUILTIN_LOCAL_GROUP:
		default:
			/* we don't allow this "groupType" values */
			return LDB_ERR_UNWILLING_TO_PERFORM;
		break;
		}
	}

	account_type =  ds_gtype2atype(group_type);
	if (account_type == 0) {
		ldb_set_errstring(ldb, "samldb: Unrecognized account type!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	ret = samdb_msg_add_uint(ldb, ac->msg, ac->msg, "sAMAccountType",
				 account_type);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	el = ldb_msg_find_element(ac->msg, "sAMAccountType");
	el->flags = LDB_FLAG_MOD_REPLACE;

	return LDB_SUCCESS;
}

static int samldb_sam_accountname_check(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	const char * const no_attrs[] = { NULL };
	struct ldb_result *res;
	const char *sam_accountname, *enc_str;
	struct ldb_message_element *el;
	struct ldb_message *tmp_msg;
	int ret;

	el = dsdb_get_single_valued_attr(ac->msg, "sAMAccountName",
					 ac->req->operation);
	if (el == NULL) {
		/* we are not affected */
		return LDB_SUCCESS;
	}

	/* Create a temporary message for fetching the "sAMAccountName" */
	tmp_msg = ldb_msg_new(ac->msg);
	if (tmp_msg == NULL) {
		return ldb_module_oom(ac->module);
	}
	ret = ldb_msg_add(tmp_msg, el, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* We must not steal the original string, it belongs to the caller! */
	sam_accountname = talloc_strdup(ac, 
					ldb_msg_find_attr_as_string(tmp_msg, "sAMAccountName", NULL));
	talloc_free(tmp_msg);

	if (sam_accountname == NULL) {
		/* The "sAMAccountName" cannot be nothing */
		ldb_set_errstring(ldb,
				  "samldb: Empty account names aren't allowed!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	enc_str = ldb_binary_encode_string(ac, sam_accountname);
	if (enc_str == NULL) {
		return ldb_module_oom(ac->module);
	}

	/* Make sure that a "sAMAccountName" is only used once */

	ret = dsdb_module_search(ac->module, ac, &res,
				 ldb_get_default_basedn(ldb),
				 LDB_SCOPE_SUBTREE, no_attrs,
				 DSDB_FLAG_NEXT_MODULE, ac->req,
				 "(sAMAccountName=%s)", enc_str);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count > 1) {
		return ldb_operr(ldb);
	} else if (res->count == 1) {
		if (ldb_dn_compare(res->msgs[0]->dn, ac->msg->dn) != 0) {
			ldb_asprintf_errstring(ldb,
					       "samldb: Account name (sAMAccountName) '%s' already in use!",
					       sam_accountname);
			return LDB_ERR_ENTRY_ALREADY_EXISTS;
		}
	}
	talloc_free(res);

	return LDB_SUCCESS;
}

static int samldb_member_check(struct samldb_ctx *ac)
{
	const char * const attrs[] = { "objectSid", NULL };
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_message_element *el;
	struct ldb_dn *member_dn;
	struct dom_sid *sid;
	struct ldb_result *res;
	struct dom_sid *group_sid;
	unsigned int i, j;
	int ret;

	/* Fetch information from the existing object */

	ret = dsdb_module_search(ac->module, ac, &res, ac->msg->dn, LDB_SCOPE_BASE, attrs,
				 DSDB_FLAG_NEXT_MODULE | DSDB_SEARCH_SHOW_DELETED, ac->req, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count != 1) {
		return ldb_operr(ldb);
	}

	group_sid = samdb_result_dom_sid(res, res->msgs[0], "objectSid");
	if (group_sid == NULL) {
		return ldb_operr(ldb);
	}

	/* We've to walk over all modification entries and consider the "member"
	 * ones. */
	for (i = 0; i < ac->msg->num_elements; i++) {
		if (ldb_attr_cmp(ac->msg->elements[i].name, "member") != 0) {
			continue;
		}

		el = &ac->msg->elements[i];
		for (j = 0; j < el->num_values; j++) {
			struct ldb_result *group_res;
			const char *group_attrs[] = { "primaryGroupID" , NULL };
			uint32_t prim_group_rid;

			if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE) {
				/* Deletes will be handled in
				 * repl_meta_data, and deletes not
				 * matching a member will return
				 * LDB_ERR_UNWILLING_TO_PERFORM
				 * there */
				continue;
			}

			member_dn = ldb_dn_from_ldb_val(ac, ldb,
							&el->values[j]);
			if (!ldb_dn_validate(member_dn)) {
				return ldb_operr(ldb);
			}

			/* Denies to add "member"s to groups which are primary
			 * ones for them - in this case return
			 * ERR_ENTRY_ALREADY_EXISTS. */

			ret = dsdb_module_search_dn(ac->module, ac, &group_res,
						    member_dn, group_attrs,
						    DSDB_FLAG_NEXT_MODULE, ac->req);
			if (ret == LDB_ERR_NO_SUCH_OBJECT) {
				/* member DN doesn't exist yet */
				continue;
			}
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			prim_group_rid = ldb_msg_find_attr_as_uint(group_res->msgs[0], "primaryGroupID", (uint32_t)-1);
			if (prim_group_rid == (uint32_t) -1) {
				/* the member hasn't to be a user account ->
				 * therefore no check needed in this case. */
				continue;
			}

			sid = dom_sid_add_rid(ac, samdb_domain_sid(ldb),
					      prim_group_rid);
			if (sid == NULL) {
				return ldb_operr(ldb);
			}

			if (dom_sid_equal(group_sid, sid)) {
				ldb_asprintf_errstring(ldb,
						       "samldb: member %s already set via primaryGroupID %u",
						       ldb_dn_get_linearized(member_dn), prim_group_rid);
				return LDB_ERR_ENTRY_ALREADY_EXISTS;
			}
		}
	}

	talloc_free(res);

	return LDB_SUCCESS;
}

/* SAM objects have special rules regarding the "description" attribute on
 * modify operations. */
static int samldb_description_check(struct samldb_ctx *ac, bool *modified)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	const char * const attrs[] = { "objectClass", "description", NULL };
	struct ldb_result *res;
	unsigned int i;
	int ret;

	/* Fetch information from the existing object */
	ret = dsdb_module_search(ac->module, ac, &res, ac->msg->dn, LDB_SCOPE_BASE, attrs,
				 DSDB_FLAG_NEXT_MODULE | DSDB_SEARCH_SHOW_DELETED, ac->req,
				 "(|(objectclass=user)(objectclass=group)(objectclass=samDomain)(objectclass=samServer))");
	if (ret != LDB_SUCCESS) {
		/* don't treat it specially ... let normal error codes
		   happen from other places */
		ldb_reset_err_string(ldb);
		return LDB_SUCCESS;
	}
	if (res->count == 0) {
		/* we didn't match the filter */
		talloc_free(res);
		return LDB_SUCCESS;
	}

	/* We've to walk over all modification entries and consider the
	 * "description" ones. */
	for (i = 0; i < ac->msg->num_elements; i++) {
		if (ldb_attr_cmp(ac->msg->elements[i].name, "description") == 0) {
			ac->msg->elements[i].flags |= LDB_FLAG_INTERNAL_FORCE_SINGLE_VALUE_CHECK;
			*modified = true;
		}
	}

	talloc_free(res);

	return LDB_SUCCESS;
}

/* This trigger adapts the "servicePrincipalName" attributes if the
 * "dNSHostName" and/or "sAMAccountName" attribute change(s) */
static int samldb_service_principal_names_change(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_message_element *el = NULL, *el2 = NULL;
	struct ldb_message *msg;
	const char * const attrs[] = { "servicePrincipalName", NULL };
	struct ldb_result *res;
	const char *dns_hostname = NULL, *old_dns_hostname = NULL,
		   *sam_accountname = NULL, *old_sam_accountname = NULL;
	unsigned int i, j;
	int ret;

	el = dsdb_get_single_valued_attr(ac->msg, "dNSHostName",
					 ac->req->operation);
	el2 = dsdb_get_single_valued_attr(ac->msg, "sAMAccountName",
					  ac->req->operation);
	if ((el == NULL) && (el2 == NULL)) {
		/* we are not affected */
		return LDB_SUCCESS;
	}

	/* Create a temporary message for fetching the "dNSHostName" */
	if (el != NULL) {
		const char *dns_attrs[] = { "dNSHostName", NULL };
		msg = ldb_msg_new(ac->msg);
		if (msg == NULL) {
			return ldb_module_oom(ac->module);
		}
		ret = ldb_msg_add(msg, el, 0);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		dns_hostname = talloc_strdup(ac, 
					     ldb_msg_find_attr_as_string(msg, "dNSHostName", NULL));
		if (dns_hostname == NULL) {
			return ldb_module_oom(ac->module);
		}
			
		talloc_free(msg);

		ret = dsdb_module_search_dn(ac->module, ac, &res, ac->msg->dn,
					    dns_attrs, DSDB_FLAG_NEXT_MODULE, ac->req);
		if (ret == LDB_SUCCESS) {
			old_dns_hostname = ldb_msg_find_attr_as_string(res->msgs[0], "dNSHostName", NULL);
		}
	}

	/* Create a temporary message for fetching the "sAMAccountName" */
	if (el2 != NULL) {
		char *tempstr, *tempstr2 = NULL;
		const char *acct_attrs[] = { "sAMAccountName", NULL };

		msg = ldb_msg_new(ac->msg);
		if (msg == NULL) {
			return ldb_module_oom(ac->module);
		}
		ret = ldb_msg_add(msg, el2, 0);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		tempstr = talloc_strdup(ac,
					ldb_msg_find_attr_as_string(msg, "sAMAccountName", NULL));
		talloc_free(msg);

		ret = dsdb_module_search_dn(ac->module, ac, &res, ac->msg->dn, acct_attrs,
					    DSDB_FLAG_NEXT_MODULE, ac->req);
		if (ret == LDB_SUCCESS) {
			tempstr2 = talloc_strdup(ac,
						 ldb_msg_find_attr_as_string(res->msgs[0],
									     "sAMAccountName", NULL));
		}


		/* The "sAMAccountName" needs some additional trimming: we need
		 * to remove the trailing "$"s if they exist. */
		if ((tempstr != NULL) && (tempstr[0] != '\0') &&
		    (tempstr[strlen(tempstr) - 1] == '$')) {
			tempstr[strlen(tempstr) - 1] = '\0';
		}
		if ((tempstr2 != NULL) && (tempstr2[0] != '\0') &&
		    (tempstr2[strlen(tempstr2) - 1] == '$')) {
			tempstr2[strlen(tempstr2) - 1] = '\0';
		}
		sam_accountname = tempstr;
		old_sam_accountname = tempstr2;
	}

	if (old_dns_hostname == NULL) {
		/* we cannot change when the old name is unknown */
		dns_hostname = NULL;
	}
	if ((old_dns_hostname != NULL) && (dns_hostname != NULL) &&
	    (strcasecmp_m(old_dns_hostname, dns_hostname) == 0)) {
		/* The "dNSHostName" didn't change */
		dns_hostname = NULL;
	}

	if (old_sam_accountname == NULL) {
		/* we cannot change when the old name is unknown */
		sam_accountname = NULL;
	}
	if ((old_sam_accountname != NULL) && (sam_accountname != NULL) &&
	    (strcasecmp_m(old_sam_accountname, sam_accountname) == 0)) {
		/* The "sAMAccountName" didn't change */
		sam_accountname = NULL;
	}

	if ((dns_hostname == NULL) && (sam_accountname == NULL)) {
		/* Well, there are information missing (old name(s)) or the
		 * names didn't change. We've nothing to do and can exit here */
		return LDB_SUCCESS;
	}

	/* Potential "servicePrincipalName" changes in the same request have to
	 * be handled before the update (Windows behaviour). */
	el = ldb_msg_find_element(ac->msg, "servicePrincipalName");
	if (el != NULL) {
		msg = ldb_msg_new(ac->msg);
		if (msg == NULL) {
			return ldb_module_oom(ac->module);
		}
		msg->dn = ac->msg->dn;

		do {
			ret = ldb_msg_add(msg, el, el->flags);
			if (ret != LDB_SUCCESS) {
				return ret;
			}

			ldb_msg_remove_element(ac->msg, el);

			el = ldb_msg_find_element(ac->msg,
						  "servicePrincipalName");
		} while (el != NULL);

		ret = dsdb_module_modify(ac->module, msg,
					 DSDB_FLAG_NEXT_MODULE, ac->req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		talloc_free(msg);
	}

	/* Fetch the "servicePrincipalName"s if any */
	ret = dsdb_module_search(ac->module, ac, &res, ac->msg->dn, LDB_SCOPE_BASE, attrs,
				 DSDB_FLAG_NEXT_MODULE, ac->req, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if ((res->count != 1) || (res->msgs[0]->num_elements > 1)) {
		return ldb_operr(ldb);
	}

	if (res->msgs[0]->num_elements == 1) {
		/*
		 * Yes, we do have "servicePrincipalName"s. First we update them
		 * locally, that means we do always substitute the current
		 * "dNSHostName" with the new one and/or "sAMAccountName"
		 * without "$" with the new one and then we append the
		 * modified "servicePrincipalName"s as a message element
		 * replace to the modification request (Windows behaviour). We
		 * need also to make sure that the values remain case-
		 * insensitively unique.
		 */

		ret = ldb_msg_add_empty(ac->msg, "servicePrincipalName",
					LDB_FLAG_MOD_REPLACE, &el);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		for (i = 0; i < res->msgs[0]->elements[0].num_values; i++) {
			char *old_str, *new_str, *pos;
			const char *tok;
			struct ldb_val *vals;
			bool found = false;

			old_str = (char *)
				res->msgs[0]->elements[0].values[i].data;

			new_str = talloc_strdup(ac->msg,
						strtok_r(old_str, "/", &pos));
			if (new_str == NULL) {
				return ldb_module_oom(ac->module);
			}

			while ((tok = strtok_r(NULL, "/", &pos)) != NULL) {
				if ((dns_hostname != NULL) &&
				    (strcasecmp_m(tok, old_dns_hostname) == 0)) {
					tok = dns_hostname;
				}
				if ((sam_accountname != NULL) &&
				    (strcasecmp_m(tok, old_sam_accountname) == 0)) {
					tok = sam_accountname;
				}

				new_str = talloc_asprintf(ac->msg, "%s/%s",
							  new_str, tok);
				if (new_str == NULL) {
					return ldb_module_oom(ac->module);
				}
			}

			/* Uniqueness check */
			for (j = 0; (!found) && (j < el->num_values); j++) {
				if (strcasecmp_m((char *)el->values[j].data,
					       new_str) == 0) {
					found = true;
				}
			}
			if (found) {
				continue;
			}

			/*
			 * append the new "servicePrincipalName" -
			 * code derived from ldb_msg_add_value().
			 *
			 * Open coded to make it clear that we must
			 * append to the MOD_REPLACE el created above.
			 */
			vals = talloc_realloc(ac->msg, el->values,
					      struct ldb_val,
					      el->num_values + 1);
			if (vals == NULL) {
				return ldb_module_oom(ac->module);
			}
			el->values = vals;
			el->values[el->num_values] = data_blob_string_const(new_str);
			++(el->num_values);
		}
	}

	talloc_free(res);

	return LDB_SUCCESS;
}

/* This checks the "fSMORoleOwner" attributes */
static int samldb_fsmo_role_owner_check(struct samldb_ctx *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	const char * const no_attrs[] = { NULL };
	struct ldb_message_element *el;
	struct ldb_message *tmp_msg;
	struct ldb_dn *res_dn;
	struct ldb_result *res;
	int ret;

	el = dsdb_get_single_valued_attr(ac->msg, "fSMORoleOwner",
					 ac->req->operation);
	if (el == NULL) {
		/* we are not affected */
		return LDB_SUCCESS;
	}

	/* Create a temporary message for fetching the "fSMORoleOwner" */
	tmp_msg = ldb_msg_new(ac->msg);
	if (tmp_msg == NULL) {
		return ldb_module_oom(ac->module);
	}
	ret = ldb_msg_add(tmp_msg, el, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	res_dn = ldb_msg_find_attr_as_dn(ldb, ac, tmp_msg, "fSMORoleOwner");
	talloc_free(tmp_msg);

	if (res_dn == NULL) {
		ldb_set_errstring(ldb,
				  "samldb: 'fSMORoleOwner' attributes have to reference 'nTDSDSA' entries!");
		if (ac->req->operation == LDB_ADD) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		} else {
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}

	/* Fetched DN has to reference a "nTDSDSA" entry */
	ret = dsdb_module_search(ac->module, ac, &res, res_dn, LDB_SCOPE_BASE,
				 no_attrs,
				 DSDB_FLAG_NEXT_MODULE | DSDB_SEARCH_SHOW_DELETED,
				 ac->req, "(objectClass=nTDSDSA)");
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count != 1) {
		ldb_set_errstring(ldb,
				  "samldb: 'fSMORoleOwner' attributes have to reference 'nTDSDSA' entries!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	talloc_free(res);

	return LDB_SUCCESS;
}


/* add */
static int samldb_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct samldb_ctx *ac;
	struct ldb_message_element *el;
	int ret;

	ldb = ldb_module_get_ctx(module);
	ldb_debug(ldb, LDB_DEBUG_TRACE, "samldb_add\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	el = ldb_msg_find_element(req->op.add.message, "userParameters");
	if (el != NULL && ldb_req_is_untrusted(req)) {
		const char *reason = "samldb_add: "
			"setting userParameters is not supported over LDAP, "
			"see https://bugzilla.samba.org/show_bug.cgi?id=8077";
		ldb_debug(ldb, LDB_DEBUG_WARNING, "%s", reason);
		return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION, reason);
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

	el = ldb_msg_find_element(ac->msg, "fSMORoleOwner");
	if (el != NULL) {
		ret = samldb_fsmo_role_owner_check(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "user") != NULL) {
		ac->type = SAMLDB_TYPE_USER;

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
		ac->type = SAMLDB_TYPE_GROUP;

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

		ac->type = SAMLDB_TYPE_CLASS;
		return samldb_fill_object(ac);
	}

	if (samdb_find_attribute(ldb, ac->msg,
				 "objectclass", "attributeSchema") != NULL) {
		ret = samldb_schema_info_update(ac);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}

		ac->type = SAMLDB_TYPE_ATTRIBUTE;
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

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	/* make sure that "objectSid" is not specified */
	el = ldb_msg_find_element(req->op.mod.message, "objectSid");
	if (el != NULL) {
		if (ldb_request_get_control(req, LDB_CONTROL_PROVISION_OID) == NULL) {
			ldb_set_errstring(ldb,
					  "samldb: objectSid must not be specified!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}
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
		if (!ldb_request_get_control(req,
					     DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	}

	el = ldb_msg_find_element(req->op.mod.message, "userParameters");
	if (el != NULL && ldb_req_is_untrusted(req)) {
		const char *reason = "samldb: "
			"setting userParameters is not supported over LDAP, "
			"see https://bugzilla.samba.org/show_bug.cgi?id=8077";
		ldb_debug(ldb, LDB_DEBUG_WARNING, "%s", reason);
		return ldb_error(ldb, LDB_ERR_CONSTRAINT_VIOLATION, reason);
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

	el = ldb_msg_find_element(ac->msg, "primaryGroupID");
	if (el != NULL) {
		ret = samldb_prim_group_trigger(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	el = ldb_msg_find_element(ac->msg, "userAccountControl");
	if (el != NULL) {
		modified = true;
		ret = samldb_user_account_control_change(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	el = ldb_msg_find_element(ac->msg, "lockoutTime");
	if (el != NULL) {
		modified = true;
		ret = samldb_lockout_time(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	el = ldb_msg_find_element(ac->msg, "groupType");
	if (el != NULL) {
		modified = true;
		ret = samldb_group_type_change(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	el = ldb_msg_find_element(ac->msg, "sAMAccountName");
	if (el != NULL) {
		ret = samldb_sam_accountname_check(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	el = ldb_msg_find_element(ac->msg, "member");
	if (el != NULL) {
		ret = samldb_member_check(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	el = ldb_msg_find_element(ac->msg, "description");
	if (el != NULL) {
		ret = samldb_description_check(ac, &modified);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	el = ldb_msg_find_element(ac->msg, "dNSHostName");
	el2 = ldb_msg_find_element(ac->msg, "sAMAccountName");
	if ((el != NULL) || (el2 != NULL)) {
		modified = true;
		ret = samldb_service_principal_names_change(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	el = ldb_msg_find_element(ac->msg, "fSMORoleOwner");
	if (el != NULL) {
		ret = samldb_fsmo_role_owner_check(ac);
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
	int ret;
	struct ldb_result *res;
	const char * const attrs[] = { "objectSid", "isDeleted", NULL };
	const char * const noattrs[] = { NULL };

	ldb = ldb_module_get_ctx(ac->module);

	/* Finds out the SID/RID of the SAM object */
	ret = dsdb_module_search_dn(ac->module, ac, &res, ac->req->op.del.dn,
					attrs,
					DSDB_FLAG_NEXT_MODULE | DSDB_SEARCH_SHOW_DELETED,
					ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (ldb_msg_check_string_attribute(res->msgs[0], "isDeleted", "TRUE")) {
		return LDB_SUCCESS;
	}

	sid = samdb_result_dom_sid(ac, res->msgs[0], "objectSid");
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
	/* do not allow deletion of well-known sids */
	if (rid < DSDB_SAMDB_MINIMUM_ALLOWED_RID &&
	    (ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID) == NULL)) {
		return LDB_ERR_OTHER;
	}

	/* Deny delete requests from groups which are primary ones */
	ret = dsdb_module_search(ac->module, ac, &res,
				 ldb_get_default_basedn(ldb),
				 LDB_SCOPE_SUBTREE, noattrs,
				 DSDB_FLAG_NEXT_MODULE,
				 ac->req,
				 "(&(primaryGroupID=%u)(objectClass=user))", rid);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count > 0) {
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

/* rename */

static int check_rename_constraints(struct ldb_message *msg,
				    struct samldb_ctx *ac,
				    struct ldb_dn *olddn, struct ldb_dn *newdn)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_dn *dn1, *dn2, *nc_root;
	int32_t systemFlags;
	bool move_op = false;
	bool rename_op = false;
	int ret;

	/* Skip the checks if old and new DN are the same, or if we have the
	 * relax control specified or if the returned objects is already
	 * deleted and needs only to be moved for consistency. */

	if (ldb_dn_compare(olddn, newdn) == 0) {
		return LDB_SUCCESS;
	}
	if (ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID) != NULL) {
		return LDB_SUCCESS;
	}
	if (ldb_msg_find_attr_as_bool(msg, "isDeleted", false)) {
		return LDB_SUCCESS;
	}

	/* Objects under CN=System */

	dn1 = ldb_dn_copy(ac, ldb_get_default_basedn(ldb));
	if (dn1 == NULL) return ldb_oom(ldb);

	if ( ! ldb_dn_add_child_fmt(dn1, "CN=System")) {
		talloc_free(dn1);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if ((ldb_dn_compare_base(dn1, olddn) == 0) &&
	    (ldb_dn_compare_base(dn1, newdn) != 0)) {
		talloc_free(dn1);
		ldb_asprintf_errstring(ldb,
				       "subtree_rename: Cannot move/rename %s. Objects under CN=System have to stay under it!",
				       ldb_dn_get_linearized(olddn));
		return LDB_ERR_OTHER;
	}

	talloc_free(dn1);

	/* LSA objects */

	if ((samdb_find_attribute(ldb, msg, "objectClass", "secret") != NULL) ||
	    (samdb_find_attribute(ldb, msg, "objectClass", "trustedDomain") != NULL)) {
		ldb_asprintf_errstring(ldb,
				       "subtree_rename: Cannot move/rename %s. It's an LSA-specific object!",
				       ldb_dn_get_linearized(olddn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* systemFlags */

	dn1 = ldb_dn_get_parent(ac, olddn);
	if (dn1 == NULL) return ldb_oom(ldb);
	dn2 = ldb_dn_get_parent(ac, newdn);
	if (dn2 == NULL) return ldb_oom(ldb);

	if (ldb_dn_compare(dn1, dn2) == 0) {
		rename_op = true;
	} else {
		move_op = true;
	}

	talloc_free(dn1);
	talloc_free(dn2);

	systemFlags = ldb_msg_find_attr_as_int(msg, "systemFlags", 0);

	/* Fetch name context */

	ret = dsdb_find_nc_root(ldb, ac, olddn, &nc_root);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (ldb_dn_compare(nc_root, ldb_get_schema_basedn(ldb)) == 0) {
		if (move_op) {
			ldb_asprintf_errstring(ldb,
					       "subtree_rename: Cannot move %s within schema partition",
					       ldb_dn_get_linearized(olddn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		if (rename_op &&
		    (systemFlags & SYSTEM_FLAG_SCHEMA_BASE_OBJECT) != 0) {
			ldb_asprintf_errstring(ldb,
					       "subtree_rename: Cannot rename %s within schema partition",
					       ldb_dn_get_linearized(olddn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	} else if (ldb_dn_compare(nc_root, ldb_get_config_basedn(ldb)) == 0) {
		if (move_op &&
		    (systemFlags & SYSTEM_FLAG_CONFIG_ALLOW_MOVE) == 0) {
			/* Here we have to do more: control the
			 * "ALLOW_LIMITED_MOVE" flag. This means that the
			 * grand-grand-parents of two objects have to be equal
			 * in order to perform the move (this is used for
			 * moving "server" objects in the "sites" container). */
			bool limited_move =
				systemFlags & SYSTEM_FLAG_CONFIG_ALLOW_LIMITED_MOVE;

			if (limited_move) {
				dn1 = ldb_dn_copy(ac, olddn);
				if (dn1 == NULL) return ldb_oom(ldb);
				dn2 = ldb_dn_copy(ac, newdn);
				if (dn2 == NULL) return ldb_oom(ldb);

				limited_move &= ldb_dn_remove_child_components(dn1, 3);
				limited_move &= ldb_dn_remove_child_components(dn2, 3);
				limited_move &= ldb_dn_compare(dn1, dn2) == 0;

				talloc_free(dn1);
				talloc_free(dn2);
			}

			if (!limited_move) {
				ldb_asprintf_errstring(ldb,
						       "subtree_rename: Cannot move %s to %s in config partition",
						       ldb_dn_get_linearized(olddn), ldb_dn_get_linearized(newdn));
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
		}
		if (rename_op &&
		    (systemFlags & SYSTEM_FLAG_CONFIG_ALLOW_RENAME) == 0) {
			ldb_asprintf_errstring(ldb,
					       "subtree_rename: Cannot rename %s to %s within config partition",
					       ldb_dn_get_linearized(olddn), ldb_dn_get_linearized(newdn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	} else if (ldb_dn_compare(nc_root, ldb_get_default_basedn(ldb)) == 0) {
		if (move_op &&
		    (systemFlags & SYSTEM_FLAG_DOMAIN_DISALLOW_MOVE) != 0) {
			ldb_asprintf_errstring(ldb,
					       "subtree_rename: Cannot move %s to %s - DISALLOW_MOVE set",
					       ldb_dn_get_linearized(olddn), ldb_dn_get_linearized(newdn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		if (rename_op &&
		    (systemFlags & SYSTEM_FLAG_DOMAIN_DISALLOW_RENAME) != 0) {
			ldb_asprintf_errstring(ldb,
						       "subtree_rename: Cannot rename %s to %s - DISALLOW_RENAME set",
					       ldb_dn_get_linearized(olddn), ldb_dn_get_linearized(newdn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}

	talloc_free(nc_root);

	return LDB_SUCCESS;
}


static int samldb_rename_search_base_callback(struct ldb_request *req,
					       struct ldb_reply *ares)
{
	struct samldb_ctx *ac;
	int ret;

	ac = talloc_get_type(req->context, struct samldb_ctx);

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
		/*
		 * This is the root entry of the originating move
		 * respectively rename request. It has been already
		 * stored in the list using "subtree_rename_search()".
		 * Only this one is subject to constraint checking.
		 */
		ret = check_rename_constraints(ares->message, ac,
					       ac->req->op.rename.olddn,
					       ac->req->op.rename.newdn);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL,
					       ret);
		}
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		break;

	case LDB_REPLY_DONE:

		/*
		 * Great, no problem with the rename, so go ahead as
		 * if we never were here
		 */
		ret = ldb_next_request(ac->module, ac->req);
		talloc_free(ares);
		return ret;
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}


/* rename */
static int samldb_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	static const char * const attrs[] = { "objectClass", "systemFlags",
					      "isDeleted", NULL };
	struct ldb_request *search_req;
	struct samldb_ctx *ac;
	int ret;

	if (ldb_dn_is_special(req->op.rename.olddn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	ac = samldb_ctx_init(module, req);
	if (!ac) {
		return ldb_oom(ldb);
	}

	ret = ldb_build_search_req(&search_req, ldb, ac,
				   req->op.rename.olddn,
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs,
				   NULL,
				   ac,
				   samldb_rename_search_base_callback,
				   req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_request_add_control(search_req, LDB_CONTROL_SHOW_RECYCLED_OID,
				      true, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, search_req);
}

/* extended */

static int samldb_extended_allocate_rid_pool(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_fsmo_extended_op *exop;
	int ret;

	exop = talloc_get_type(req->op.extended.data,
			       struct dsdb_fsmo_extended_op);
	if (!exop) {
		ldb_set_errstring(ldb,
				  "samldb_extended_allocate_rid_pool: invalid extended data");
		return LDB_ERR_PROTOCOL_ERROR;
	}

	ret = ridalloc_allocate_rid_pool_fsmo(module, exop, req);
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


static const struct ldb_module_ops ldb_samldb_module_ops = {
	.name          = "samldb",
	.add           = samldb_add,
	.modify        = samldb_modify,
	.del           = samldb_delete,
	.rename        = samldb_rename,
	.extended      = samldb_extended
};


int ldb_samldb_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_samldb_module_ops);
}
