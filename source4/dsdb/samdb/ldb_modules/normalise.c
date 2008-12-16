/* 
   ldb database library

   Copyright (C) Amdrew Bartlett <abartlet@samba.org> 2007-2008

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
 *  Component: ldb normalisation module
 *
 *  Description: module to ensure all DNs and attribute names are normalised
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"

/* Fix up the DN to be in the standard form, taking particular care to match the parent DN

   This should mean that if the parent is:
    CN=Users,DC=samba,DC=example,DC=com
   and a proposed child is
    cn=Admins ,cn=USERS,dc=Samba,dc=example,dc=COM

   The resulting DN should be:

    CN=Admins,CN=Users,DC=samba,DC=example,DC=com
   
 */

struct norm_context {
	struct ldb_module *module;
	struct ldb_request *req;

	const struct dsdb_schema *schema;
};

static int fix_dn(struct ldb_dn *dn) 
{
	int i, ret;
	char *upper_rdn_attr;

	for (i=0; i < ldb_dn_get_comp_num(dn); i++) {
		/* We need the attribute name in upper case */
		upper_rdn_attr = strupper_talloc(dn,
						 ldb_dn_get_component_name(dn, i));
		if (!upper_rdn_attr) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		/* And replace it with CN=foo (we need the attribute in upper case */
		ret = ldb_dn_set_component(dn, i, upper_rdn_attr,
					   *ldb_dn_get_component_val(dn, i));
		talloc_free(upper_rdn_attr);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	return LDB_SUCCESS;
}

static int normalize_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_message *msg;
	struct norm_context *ac;
	int i, j, ret;

	ac = talloc_get_type(req->context, struct norm_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	/* Only entries are interesting, and we handle the case of the parent seperatly */

	switch (ares->type) {
	case LDB_REPLY_ENTRY:

		/* OK, we have one of *many* search results passing by here,
		 * but we should get them one at a time */
		msg = ares->message;

		ret = fix_dn(msg->dn);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}

		for (i = 0; i < msg->num_elements; i++) {
			const struct dsdb_attribute *attribute = dsdb_attribute_by_lDAPDisplayName(ac->schema, msg->elements[i].name);
			if (!attribute) {
				continue;
			}
			/* Look to see if this attributeSyntax is a DN */
			if (!((strcmp(attribute->attributeSyntax_oid, "2.5.5.1") == 0) ||
			      (strcmp(attribute->attributeSyntax_oid, "2.5.5.7") == 0))) {
				continue;
			}
			for (j = 0; j < msg->elements[i].num_values; j++) {
				const char *dn_str;
				struct ldb_dn *dn = ldb_dn_from_ldb_val(ac, ac->module->ldb, &msg->elements[i].values[j]);
				if (!dn) {
					return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
				}
				ret = fix_dn(dn);
				if (ret != LDB_SUCCESS) {
					return ldb_module_done(ac->req, NULL, NULL, ret);
				}
				dn_str = talloc_steal(msg->elements[i].values, ldb_dn_get_linearized(dn));
				msg->elements[i].values[j] = data_blob_string_const(dn_str);
				talloc_free(dn);
			}
		}

		return ldb_module_send_entry(ac->req, msg, ares->controls);

	case LDB_REPLY_REFERRAL:

		return ldb_module_send_referral(ac->req, ares->referral);

	case LDB_REPLY_DONE:

		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	return LDB_SUCCESS;
}

/* search */
static int normalise_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_request *down_req;
	struct norm_context *ac;
	int ret;

	ac = talloc(req, struct norm_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;

	/* if schema not yet present just skip over */
	ac->schema = dsdb_get_schema(ac->module->ldb);
	if (ac->schema == NULL) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	ret = ldb_build_search_req_ex(&down_req, module->ldb, ac,
					req->op.search.base,
					req->op.search.scope,
					req->op.search.tree,
					req->op.search.attrs,
					req->controls,
					ac, normalize_search_callback,
					req);
	if (ret != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ldb_next_request(module, down_req);
}



_PUBLIC_ const struct ldb_module_ops ldb_normalise_module_ops = {
	.name		   = "normalise",
	.search            = normalise_search,
};
