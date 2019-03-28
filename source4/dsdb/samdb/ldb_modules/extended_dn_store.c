/* 
   ldb database library

   Copyright (C) Simo Sorce 2005-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2007-2009

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
 *  Component: ldb extended dn control module
 *
 *  Description: this module builds a special dn for returned search
 *  results nad creates the special DN in the backend store for new
 *  values.
 *
 *  This also has the curious result that we convert <SID=S-1-2-345>
 *  in an attribute value into a normal DN for the rest of the stack
 *  to process
 *
 *  Authors: Simo Sorce
 *           Andrew Bartlett
 */

#include "includes.h"
#include <ldb.h>
#include <ldb_errors.h>
#include <ldb_module.h>
#include "librpc/gen_ndr/ndr_misc.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include <time.h>

struct extended_dn_replace_list {
	struct extended_dn_replace_list *next;
	struct dsdb_dn *dsdb_dn;
	TALLOC_CTX *mem_ctx;
	struct ldb_val *replace_dn;
	struct extended_dn_context *ac;
	struct ldb_request *search_req;
	bool fpo_enabled;
	bool require_object;
	bool got_entry;
};


struct extended_dn_context {
	const struct dsdb_schema *schema;
	struct ldb_module *module;
	struct ldb_context *ldb;
	struct ldb_request *req;
	struct ldb_request *new_req;

	struct extended_dn_replace_list *ops;
	struct extended_dn_replace_list *cur;

	/*
	 * Used by the FPO-enabled attribute validation.
	 */
	struct dsdb_trust_routing_table *routing_table;
};


static struct extended_dn_context *extended_dn_context_init(struct ldb_module *module,
							    struct ldb_request *req)
{
	struct extended_dn_context *ac;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	ac = talloc_zero(req, struct extended_dn_context);
	if (ac == NULL) {
		ldb_oom(ldb);
		return NULL;
	}

	ac->schema = dsdb_get_schema(ldb, ac);
	ac->module = module;
	ac->ldb = ldb;
	ac->req = req;

	return ac;
}

static int extended_replace_dn(struct extended_dn_replace_list *os,
			       struct ldb_dn *dn)
{
	struct dsdb_dn *dsdb_dn = NULL;
	const char *str = NULL;

	/*
	 * Rebuild with the string or binary 'extra part' the
	 * DN may have had as a prefix
	 */
	dsdb_dn = dsdb_dn_construct(os, dn,
				    os->dsdb_dn->extra_part,
				    os->dsdb_dn->oid);
	if (dsdb_dn == NULL) {
		return ldb_module_operr(os->ac->module);
	}

	str = dsdb_dn_get_extended_linearized(os->mem_ctx,
					      dsdb_dn, 1);
	if (str == NULL) {
		return ldb_module_operr(os->ac->module);
	}

	/*
	 * Replace the DN with the extended version of the DN
	 * (ie, add SID and GUID)
	 */
	*os->replace_dn = data_blob_string_const(str);
	os->got_entry = true;
	return LDB_SUCCESS;
}

static int extended_dn_handle_fpo_attr(struct extended_dn_replace_list *os)
{
	struct dom_sid target_sid = { 0, };
	struct dom_sid target_domain = { 0, };
	struct ldb_message *fmsg = NULL;
	char *fsid = NULL;
	const struct dom_sid *domain_sid = NULL;
	struct ldb_dn *domain_dn = NULL;
	const struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	uint32_t trust_attributes = 0;
	const char *no_attrs[] = { NULL, };
	struct ldb_result *res = NULL;
	NTSTATUS status;
	bool match;
	bool ok;
	int ret;

	/*
	 * DN doesn't exist yet
	 *
	 * Check if a foreign SID is specified,
	 * which would trigger the creation
	 * of a foreignSecurityPrincipal.
	 */
	status = dsdb_get_extended_dn_sid(os->dsdb_dn->dn,
					  &target_sid,
					  "SID");
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * No SID specified
		 */
		return dsdb_module_werror(os->ac->module,
					  LDB_ERR_NO_SUCH_OBJECT,
					  WERR_NO_SUCH_USER,
					  "specified dn doesn't exist");
	}
	if (!NT_STATUS_IS_OK(status)) {
		return ldb_module_operr(os->ac->module);
	}
	if (ldb_dn_get_extended_comp_num(os->dsdb_dn->dn) != 1) {
		return dsdb_module_werror(os->ac->module,
					  LDB_ERR_NO_SUCH_OBJECT,
					  WERR_NO_SUCH_USER,
					  "specified extended component other than SID");
	}
	if (ldb_dn_get_comp_num(os->dsdb_dn->dn) != 0) {
		return dsdb_module_werror(os->ac->module,
					  LDB_ERR_NO_SUCH_OBJECT,
					  WERR_NO_SUCH_USER,
					  "specified more the SID");
	}

	target_domain = target_sid;
	sid_split_rid(&target_domain, NULL);

	match = dom_sid_equal(&global_sid_Builtin, &target_domain);
	if (match) {
		/*
		 * Non existing BUILTIN sid
		 */
		return dsdb_module_werror(os->ac->module,
				LDB_ERR_NO_SUCH_OBJECT,
				WERR_NO_SUCH_MEMBER,
				"specified sid doesn't exist in BUILTIN");
	}

	domain_sid = samdb_domain_sid(os->ac->ldb);
	if (domain_sid == NULL) {
		return ldb_module_operr(os->ac->module);
	}
	match = dom_sid_equal(domain_sid, &target_domain);
	if (match) {
		/*
		 * Non existing SID in our domain.
		 */
		return dsdb_module_werror(os->ac->module,
				LDB_ERR_UNWILLING_TO_PERFORM,
				WERR_DS_INVALID_GROUP_TYPE,
				"specified sid doesn't exist in domain");
	}

	if (os->ac->routing_table == NULL) {
		status = dsdb_trust_routing_table_load(os->ac->ldb, os->ac,
						       &os->ac->routing_table);
		if (!NT_STATUS_IS_OK(status)) {
			return ldb_module_operr(os->ac->module);
		}
	}

	tdo = dsdb_trust_domain_by_sid(os->ac->routing_table,
				       &target_domain, NULL);
	if (tdo != NULL) {
		trust_attributes = tdo->trust_attributes;
	}

	if (trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
		return dsdb_module_werror(os->ac->module,
				LDB_ERR_UNWILLING_TO_PERFORM,
				WERR_DS_INVALID_GROUP_TYPE,
				"specified sid doesn't exist in forest");
	}

	fmsg = ldb_msg_new(os);
	if (fmsg == NULL) {
		return ldb_module_oom(os->ac->module);
	}

	fsid = dom_sid_string(fmsg, &target_sid);
	if (fsid == NULL) {
		return ldb_module_oom(os->ac->module);
	}

	domain_dn = ldb_get_default_basedn(os->ac->ldb);
	if (domain_dn == NULL) {
		return ldb_module_operr(os->ac->module);
	}

	fmsg->dn = ldb_dn_copy(fmsg, domain_dn);
	if (fmsg->dn == NULL) {
		return ldb_module_oom(os->ac->module);
	}

	ok = ldb_dn_add_child_fmt(fmsg->dn,
				  "CN=%s,CN=ForeignSecurityPrincipals",
				  fsid);
	if (!ok) {
		return ldb_module_oom(os->ac->module);
	}

	ret = ldb_msg_add_string(fmsg, "objectClass", "foreignSecurityPrincipal");
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_module_add(os->ac->module, fmsg,
			      DSDB_FLAG_AS_SYSTEM |
			      DSDB_FLAG_NEXT_MODULE,
			      os->ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_module_search_dn(os->ac->module, fmsg, &res,
				    fmsg->dn, no_attrs,
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
				    os->ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/*
	 * dsdb_module_search_dn() garantees exactly one result message
	 * on success.
	 */
	ret = extended_replace_dn(os, res->msgs[0]->dn);
	TALLOC_FREE(fmsg);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

/* An extra layer of indirection because LDB does not allow the original request to be altered */

static int extended_final_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	int ret = LDB_ERR_OPERATIONS_ERROR;
	struct extended_dn_context *ac;
	ac = talloc_get_type(req->context, struct extended_dn_context);

	if (ares->error != LDB_SUCCESS) {
		ret = ldb_module_done(ac->req, ares->controls,
				      ares->response, ares->error);
	} else {
		switch (ares->type) {
		case LDB_REPLY_ENTRY:
			
			ret = ldb_module_send_entry(ac->req, ares->message, ares->controls);
			break;
		case LDB_REPLY_REFERRAL:
			
			ret = ldb_module_send_referral(ac->req, ares->referral);
			break;
		case LDB_REPLY_DONE:
			
			ret = ldb_module_done(ac->req, ares->controls,
					      ares->response, ares->error);
			break;
		}
	}
	return ret;
}

static int extended_replace_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct extended_dn_replace_list *os = talloc_get_type(req->context, 
							   struct extended_dn_replace_list);

	if (!ares) {
		return ldb_module_done(os->ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error == LDB_ERR_NO_SUCH_OBJECT) {
		if (os->got_entry) {
			/* This is in internal error... */
			int ret = ldb_module_operr(os->ac->module);
			return ldb_module_done(os->ac->req, NULL, NULL, ret);
		}

		if (os->require_object && os->fpo_enabled) {
			int ret;

			ret = extended_dn_handle_fpo_attr(os);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(os->ac->req, NULL, NULL,
						       ret);
			}
			/* os->got_entry is true at this point... */
		}

		if (!os->got_entry && os->require_object) {
			/*
			 * It's an error if the target doesn't exist,
			 * unless it's a delete.
			 */
			int ret = dsdb_module_werror(os->ac->module,
						LDB_ERR_CONSTRAINT_VIOLATION,
						WERR_DS_NAME_REFERENCE_INVALID,
						"Referenced object not found");
			return ldb_module_done(os->ac->req, NULL, NULL, ret);
		}

		/* Don't worry too much about dangling references */

		ldb_reset_err_string(os->ac->ldb);
		if (os->next) {
			struct extended_dn_replace_list *next;

			next = os->next;

			talloc_free(os);

			os = next;
			return ldb_next_request(os->ac->module, next->search_req);
		} else {
			/* Otherwise, we are done - let's run the
			 * request now we have swapped the DNs for the
			 * full versions */
			return ldb_next_request(os->ac->module, os->ac->new_req);
		}
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(os->ac->req, ares->controls,
					ares->response, ares->error);
	}

	/* Only entries are interesting, and we only want the olddn */
	switch (ares->type) {
	case LDB_REPLY_ENTRY:
	{
		/* This *must* be the right DN, as this is a base
		 * search.  We can't check, as it could be an extended
		 * DN, so a module below will resolve it */
		int ret;

		ret = extended_replace_dn(os, ares->message->dn);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(os->ac->req, NULL, NULL, ret);
		}
		/* os->got_entry is true at this point */
		break;
	}
	case LDB_REPLY_REFERRAL:
		/* ignore */
		break;

	case LDB_REPLY_DONE:

		talloc_free(ares);

		if (!os->got_entry && os->require_object && os->fpo_enabled) {
			int ret;

			ret = extended_dn_handle_fpo_attr(os);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(os->ac->req, NULL, NULL,
						       ret);
			}
			/* os->got_entry is true at this point... */
		}

		if (!os->got_entry && os->require_object) {
			/*
			 * It's an error if the target doesn't exist,
			 * unless it's a delete.
			 */
			int ret = dsdb_module_werror(os->ac->module,
						 LDB_ERR_CONSTRAINT_VIOLATION,
						 WERR_DS_NAME_REFERENCE_INVALID,
						 "Referenced object not found");
			return ldb_module_done(os->ac->req, NULL, NULL, ret);
		}

		/* Run the next search */

		if (os->next) {
			struct extended_dn_replace_list *next;

			next = os->next;

			talloc_free(os);

			os = next;
			return ldb_next_request(os->ac->module, next->search_req);
		} else {
			/* Otherwise, we are done - let's run the
			 * request now we have swapped the DNs for the
			 * full versions */
			return ldb_next_request(os->ac->module, os->ac->new_req);
		}
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

/* We have a 'normal' DN in the inbound request.  We need to find out
 * what the GUID and SID are on the DN it points to, so we can
 * construct an extended DN for storage.
 *
 * This creates a list of DNs to look up, and the plain DN to replace
 */

static int extended_store_replace(struct extended_dn_context *ac,
				  TALLOC_CTX *callback_mem_ctx,
				  struct ldb_dn *self_dn,
				  struct ldb_val *plain_dn,
				  bool is_delete, 
				  const struct dsdb_attribute *schema_attr)
{
	const char *oid = schema_attr->syntax->ldap_oid;
	int ret;
	struct extended_dn_replace_list *os;
	static const char *attrs[] = {
		"objectSid",
		"objectGUID",
		NULL
	};
	uint32_t ctrl_flags = 0;
	bool is_untrusted = ldb_req_is_untrusted(ac->req);

	os = talloc_zero(ac, struct extended_dn_replace_list);
	if (!os) {
		return ldb_oom(ac->ldb);
	}

	os->ac = ac;
	
	os->mem_ctx = callback_mem_ctx;

	os->dsdb_dn = dsdb_dn_parse(os, ac->ldb, plain_dn, oid);
	if (!os->dsdb_dn || !ldb_dn_validate(os->dsdb_dn->dn)) {
		talloc_free(os);
		ldb_asprintf_errstring(ac->ldb,
				       "could not parse %.*s as a %s DN", (int)plain_dn->length, plain_dn->data,
				       oid);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	if (self_dn != NULL) {
		ret = ldb_dn_compare(self_dn, os->dsdb_dn->dn);
		if (ret == 0) {
			/*
			 * If this is a reference to the object
			 * itself during an 'add', we won't
			 * be able to find the object.
			 */
			talloc_free(os);
			return LDB_SUCCESS;
		}
	}

	if (is_delete && !ldb_dn_has_extended(os->dsdb_dn->dn)) {
		/* NO need to figure this DN out, this element is
		 * going to be deleted anyway, and becuase it's not
		 * extended, we have enough information to do the
		 * delete */
		talloc_free(os);
		return LDB_SUCCESS;
	}
	
		
	os->replace_dn = plain_dn;

	/* The search request here might happen to be for an
	 * 'extended' style DN, such as <GUID=abced...>.  The next
	 * module in the stack will convert this into a normal DN for
	 * processing */
	ret = ldb_build_search_req(&os->search_req,
				   ac->ldb, os, os->dsdb_dn->dn, LDB_SCOPE_BASE, NULL, 
				   attrs, NULL, os, extended_replace_callback,
				   ac->req);
	LDB_REQ_SET_LOCATION(os->search_req);
	if (ret != LDB_SUCCESS) {
		talloc_free(os);
		return ret;
	}

	/*
	 * By default we require the presence of the target.
	 */
	os->require_object = true;

	/*
	 * Handle FPO-enabled attributes, see
	 * [MS-ADTS] 3.1.1.5.2.3 Special Classes and Attributes:
	 *
	 *   FPO-enabled attributes: member, msDS-MembersForAzRole,
	 *     msDS-NeverRevealGroup, msDS-NonMembers, msDS-RevealOnDemandGroup,
	 *     msDS-ServiceAccount.
	 *
	 * Note there's no msDS-ServiceAccount in any schema (only
	 * msDS-HostServiceAccount and that's not an FPO-enabled attribute
	 * at least not in W2008R2)
	 *
	 * msDS-NonMembers always generates NOT_SUPPORTED against W2008R2.
	 *
	 * See also [MS-SAMR] 3.1.1.8.9 member.
	 */
	switch (schema_attr->attributeID_id) {
	case DRSUAPI_ATTID_member:
	case DRSUAPI_ATTID_msDS_MembersForAzRole:
	case DRSUAPI_ATTID_msDS_NeverRevealGroup:
	case DRSUAPI_ATTID_msDS_RevealOnDemandGroup:
		os->fpo_enabled = true;
		break;

	case DRSUAPI_ATTID_msDS_HostServiceAccount:
		/* This is NOT a FPO-enabled attribute */
		break;

	case DRSUAPI_ATTID_msDS_NonMembers:
		return dsdb_module_werror(os->ac->module,
					  LDB_ERR_UNWILLING_TO_PERFORM,
					  WERR_NOT_SUPPORTED,
					  "msDS-NonMembers is not supported");
	}

	if (schema_attr->linkID == 0) {
		/*
		 * None linked attributes allow references
		 * to deleted objects.
		 */
		ctrl_flags |= DSDB_SEARCH_SHOW_RECYCLED;
	}

	if (is_delete) {
		/*
		 * On delete want to be able to
		 * find a deleted object, but
		 * it's not a problem if they doesn't
		 * exist.
		 */
		ctrl_flags |= DSDB_SEARCH_SHOW_RECYCLED;
		os->require_object = false;
	}

	if (!is_untrusted) {
		struct ldb_control *ctrl = NULL;

		/*
		 * During provision or dbcheck we may not find
		 * an object.
		 */

		ctrl = ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID);
		if (ctrl != NULL) {
			os->require_object = false;
		}
		ctrl = ldb_request_get_control(ac->req, DSDB_CONTROL_DBCHECK);
		if (ctrl != NULL) {
			os->require_object = false;
		}
	}

	ret = dsdb_request_add_controls(os->search_req,
					DSDB_FLAG_AS_SYSTEM |
					ctrl_flags |
					DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT);
	if (ret != LDB_SUCCESS) {
		talloc_free(os);
		return ret;
	}

	if (ac->ops) {
		ac->cur->next = os;
	} else {
		ac->ops = os;
	}
	ac->cur = os;

	return LDB_SUCCESS;
}


/* add */
static int extended_dn_add(struct ldb_module *module, struct ldb_request *req)
{
	struct extended_dn_context *ac;
	int ret;
	unsigned int i, j;

	if (ldb_dn_is_special(req->op.add.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ac = extended_dn_context_init(module, req);
	if (!ac) {
		return ldb_operr(ldb_module_get_ctx(module));
	}

	if (!ac->schema) {
		/* without schema, this doesn't make any sense */
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	for (i=0; i < req->op.add.message->num_elements; i++) {
		const struct ldb_message_element *el = &req->op.add.message->elements[i];
		const struct dsdb_attribute *schema_attr
			= dsdb_attribute_by_lDAPDisplayName(ac->schema, el->name);
		if (!schema_attr) {
			continue;
		}

		/* We only setup an extended DN GUID on DN elements */
		if (schema_attr->dn_format == DSDB_INVALID_DN) {
			continue;
		}

		if (schema_attr->attributeID_id == DRSUAPI_ATTID_distinguishedName) {
			/* distinguishedName values are ignored */
			continue;
		}

		/* Before we setup a procedure to modify the incoming message, we must copy it */
		if (!ac->new_req) {
			struct ldb_message *msg = ldb_msg_copy(ac, req->op.add.message);
			if (!msg) {
				return ldb_oom(ldb_module_get_ctx(module));
			}
		   
			ret = ldb_build_add_req(&ac->new_req, ac->ldb, ac, msg, req->controls, ac, extended_final_callback, req);
			LDB_REQ_SET_LOCATION(ac->new_req);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
		/* Re-calculate el */
		el = &ac->new_req->op.add.message->elements[i];
		for (j = 0; j < el->num_values; j++) {
			ret = extended_store_replace(ac, ac->new_req,
						     req->op.add.message->dn,
						     &el->values[j],
						     false, schema_attr);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}

	/* if no DNs were set continue */
	if (ac->ops == NULL) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	/* start with the searches */
	return ldb_next_request(module, ac->ops->search_req);
}

/* modify */
static int extended_dn_modify(struct ldb_module *module, struct ldb_request *req)
{
	/* Look over list of modifications */
	/* Find if any are for linked attributes */
	/* Determine the effect of the modification */
	/* Apply the modify to the linked entry */

	unsigned int i, j;
	struct extended_dn_context *ac;
	struct ldb_control *fix_links_control = NULL;
	struct ldb_control *fix_link_sid_ctrl = NULL;
	int ret;

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ac = extended_dn_context_init(module, req);
	if (!ac) {
		return ldb_operr(ldb_module_get_ctx(module));
	}

	if (!ac->schema) {
		talloc_free(ac);
		/* without schema, this doesn't make any sense */
		return ldb_next_request(module, req);
	}

	fix_links_control = ldb_request_get_control(req,
					DSDB_CONTROL_DBCHECK_FIX_DUPLICATE_LINKS);
	if (fix_links_control != NULL) {
		return ldb_next_request(module, req);
	}

	fix_link_sid_ctrl = ldb_request_get_control(ac->req,
					DSDB_CONTROL_DBCHECK_FIX_LINK_DN_SID);
	if (fix_link_sid_ctrl != NULL) {
		return ldb_next_request(module, req);
	}

	for (i=0; i < req->op.mod.message->num_elements; i++) {
		const struct ldb_message_element *el = &req->op.mod.message->elements[i];
		const struct dsdb_attribute *schema_attr
			= dsdb_attribute_by_lDAPDisplayName(ac->schema, el->name);
		if (!schema_attr) {
			continue;
		}

		/* We only setup an extended DN GUID on these particular DN objects */
		if (schema_attr->dn_format == DSDB_INVALID_DN) {
			continue;
		}

		if (schema_attr->attributeID_id == DRSUAPI_ATTID_distinguishedName) {
			/* distinguishedName values are ignored */
			continue;
		}

		/* Before we setup a procedure to modify the incoming message, we must copy it */
		if (!ac->new_req) {
			struct ldb_message *msg = ldb_msg_copy(ac, req->op.mod.message);
			if (!msg) {
				talloc_free(ac);
				return ldb_oom(ac->ldb);
			}
		   
			ret = ldb_build_mod_req(&ac->new_req, ac->ldb, ac, msg, req->controls, ac, extended_final_callback, req);
			LDB_REQ_SET_LOCATION(ac->new_req);
			if (ret != LDB_SUCCESS) {
				talloc_free(ac);
				return ret;
			}
		}
		/* Re-calculate el */
		el = &ac->new_req->op.mod.message->elements[i];
		/* For each value being added, we need to setup the lookups to fill in the extended DN */
		for (j = 0; j < el->num_values; j++) {
			/* If we are just going to delete this
			 * element, only do a lookup if
			 * extended_store_replace determines it's an
			 * input of an extended DN */
			bool is_delete = (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE);

			ret = extended_store_replace(ac, ac->new_req,
						     NULL, /* self_dn to be ignored */
						     &el->values[j],
						     is_delete, schema_attr);
			if (ret != LDB_SUCCESS) {
				talloc_free(ac);
				return ret;
			}
		}
	}

	/* if DNs were set continue */
	if (ac->ops == NULL) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	/* start with the searches */
	return ldb_next_request(module, ac->ops->search_req);
}

static const struct ldb_module_ops ldb_extended_dn_store_module_ops = {
	.name		   = "extended_dn_store",
	.add               = extended_dn_add,
	.modify            = extended_dn_modify,
};

int ldb_extended_dn_store_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_extended_dn_store_module_ops);
}
