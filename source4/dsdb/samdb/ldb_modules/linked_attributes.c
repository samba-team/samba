/* 
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2007
   Copyright (C) Simo Sorce <idra@samba.org> 2008

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
 *  Component: ldb linked_attributes module
 *
 *  Description: Module to ensure linked attribute pairs remain in sync
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb_module.h"
#include "dlinklist.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "dsdb/samdb/ldb_modules/util.h"


static int linked_attributes_fix_links(struct ldb_module *module,
				       struct ldb_dn *old_dn, struct ldb_dn *new_dn,
				       struct ldb_message_element *el, struct dsdb_schema *schema,
				       const struct dsdb_attribute *schema_attr)
{
	int i;
	TALLOC_CTX *tmp_ctx = talloc_new(module);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct dsdb_attribute *target;
	const char *attrs[2];

	target = dsdb_attribute_by_linkID(schema, schema_attr->linkID ^ 1);
	if (target == NULL) {
		/* there is no counterpart link to change */
		return LDB_SUCCESS;
	}

	attrs[0] = target->lDAPDisplayName;
	attrs[1] = NULL;

	for (i=0; i<el->num_values; i++) {
		struct dsdb_dn *dsdb_dn;
		int ret, j;
		struct ldb_result *res;
		struct ldb_message *msg;
		struct ldb_message_element *el2;

		dsdb_dn = dsdb_dn_parse(tmp_ctx, ldb, &el->values[i], schema_attr->syntax->ldap_oid);
		if (dsdb_dn == NULL) {
			talloc_free(tmp_ctx);
			return LDB_ERR_INVALID_DN_SYNTAX;
		}

		ret = dsdb_module_search_dn(module, tmp_ctx, &res, dsdb_dn->dn,
					    attrs,
					    DSDB_SEARCH_SHOW_DELETED |
					    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT |
					    DSDB_SEARCH_REVEAL_INTERNALS);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, "Linked attribute %s->%s between %s and %s - remote not found - %s",
					       el->name, target->lDAPDisplayName,
					       ldb_dn_get_linearized(old_dn),
					       ldb_dn_get_linearized(dsdb_dn->dn),
					       ldb_errstring(ldb));
			talloc_free(tmp_ctx);
			return ret;
		}
		msg = res->msgs[0];

		if (msg->num_elements != 1 ||
		    ldb_attr_cmp(msg->elements[0].name, target->lDAPDisplayName) != 0) {
			ldb_set_errstring(ldb, "Bad msg elements in linked_attributes_fix_links");
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		el2 = &msg->elements[0];

		el2->flags = LDB_FLAG_MOD_REPLACE;

		/* find our DN in the values */
		for (j=0; j<el2->num_values; j++) {
			struct dsdb_dn *dsdb_dn2;
			dsdb_dn2 = dsdb_dn_parse(msg, ldb, &el2->values[j], target->syntax->ldap_oid);
			if (dsdb_dn2 == NULL) {
				talloc_free(tmp_ctx);
				return LDB_ERR_INVALID_DN_SYNTAX;
			}
			if (ldb_dn_compare(old_dn, dsdb_dn2->dn) != 0) {
				continue;
			}
			ret = ldb_dn_update_components(dsdb_dn2->dn, new_dn);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}

			el2->values[j] = data_blob_string_const(
				dsdb_dn_get_extended_linearized(el2->values, dsdb_dn2, 1));
		}

		ret = dsdb_check_single_valued_link(target, el2);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}

		ret = dsdb_module_modify(module, msg, DSDB_MODIFY_RELAX);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, "Linked attribute %s->%s between %s and %s - update failed - %s",
					       el->name, target->lDAPDisplayName,
					       ldb_dn_get_linearized(old_dn),
					       ldb_dn_get_linearized(dsdb_dn->dn),
					       ldb_errstring(ldb));
			talloc_free(tmp_ctx);
			return ret;
		}
	}

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}


/* rename */
static int linked_attributes_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_result *res;
	struct ldb_message *msg;
	int ret, i;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_schema *schema = dsdb_get_schema(ldb);
	/*
	   - load the current msg
	   - find any linked attributes
	   - if its a link then find the target object
	   - modify the target linked attributes with the new DN
	*/
	ret = dsdb_module_search_dn(module, req, &res, req->op.rename.olddn,
				    NULL, DSDB_SEARCH_SHOW_DELETED);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	msg = res->msgs[0];

	for (i=0; i<msg->num_elements; i++) {
		struct ldb_message_element *el = &msg->elements[i];
		const struct dsdb_attribute *schema_attr
			= dsdb_attribute_by_lDAPDisplayName(schema, el->name);
		if (!schema_attr || schema_attr->linkID == 0) {
			continue;
		}
		ret = linked_attributes_fix_links(module, msg->dn, req->op.rename.newdn, el,
						  schema, schema_attr);
		if (ret != LDB_SUCCESS) {
			talloc_free(res);
			return ret;
		}
	}

	talloc_free(res);

	return ldb_next_request(module, req);
}


_PUBLIC_ const struct ldb_module_ops ldb_linked_attributes_module_ops = {
	.name		   = "linked_attributes",
	.rename	  	   = linked_attributes_rename,
};
