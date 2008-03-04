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

static int normalise_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares) 
{
	const struct dsdb_schema *schema = dsdb_get_schema(ldb);
	struct ldb_request *orig_req = talloc_get_type(context, struct ldb_request);
	TALLOC_CTX *mem_ctx;
	int i, j, ret;

	/* Only entries are interesting, and we handle the case of the parent seperatly */
	if (ares->type != LDB_REPLY_ENTRY) {
		return orig_req->callback(ldb, orig_req->context, ares);
	}

	if (!schema) {
		return orig_req->callback(ldb, orig_req->context, ares);
	}

	mem_ctx = talloc_new(ares);
	if (!mem_ctx) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* OK, we have one of *many* search results passing by here,
	 * but we should get them one at a time */

	ret = fix_dn(ares->message->dn);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}

	for (i = 0; i < ares->message->num_elements; i++) {
		const struct dsdb_attribute *attribute = dsdb_attribute_by_lDAPDisplayName(schema, ares->message->elements[i].name);
		if (!attribute) {
			continue;
		}
		/* Look to see if this attributeSyntax is a DN */
		if (!((strcmp(attribute->attributeSyntax_oid, "2.5.5.1") == 0) ||
		      (strcmp(attribute->attributeSyntax_oid, "2.5.5.7") == 0))) {
			continue;
		}
		for (j = 0; j < ares->message->elements[i].num_values; j++) {
			const char *dn_str;
			struct ldb_dn *dn = ldb_dn_new(mem_ctx, ldb, (const char *)ares->message->elements[i].values[j].data);
			if (!dn) {
				talloc_free(mem_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			ret = fix_dn(ares->message->dn);
			if (ret != LDB_SUCCESS) {
				talloc_free(mem_ctx);
				return ret;
			}
			dn_str = talloc_steal(ares->message->elements[i].values, ldb_dn_get_linearized(dn));
			ares->message->elements[i].values[j] = data_blob_string_const(dn_str);
			talloc_free(dn);
		}
	}
	talloc_free(mem_ctx);
	return orig_req->callback(ldb, orig_req->context, ares);
}

/* search */
static int normalise_search(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_request *down_req = talloc(req, struct ldb_request);
	if (!down_req) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	*down_req = *req;
	down_req->context = req;
	down_req->callback = normalise_search_callback;

	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->handle = down_req->handle;
	}
	return ret;
}


_PUBLIC_ const struct ldb_module_ops ldb_normalise_module_ops = {
	.name		   = "normalise",
	.search            = normalise_search,
};
