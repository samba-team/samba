/* 
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2007
   Copyright (C) Andrew Tridgell <tridge@samba.org> 2009
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
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
 *  Component: ldb subtree delete (prevention) module
 *
 *  Description: Prevent deletion of a subtree in LDB
 *
 *  Author: Andrew Bartlett
 */

#include "ldb_module.h"
#include "dsdb/samdb/ldb_modules/util.h"


static int subtree_delete(struct ldb_module *module, struct ldb_request *req)
{
	static const char * const attrs[] = { NULL };
	int ret;
	struct ldb_result *res = NULL;

	if (ldb_dn_is_special(req->op.del.dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* see if we have any children */
	ret = dsdb_module_search(module, req, &res, req->op.del.dn, LDB_SCOPE_ONELEVEL, attrs,
				 DSDB_SEARCH_SHOW_DELETED, NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		return ret;
	}
	if (res->count > 0) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Cannot delete %s, not a leaf node "
				       "(has %d children)\n",
				       ldb_dn_get_linearized(req->op.del.dn),
				       res->count);
		talloc_free(res);
		return LDB_ERR_NOT_ALLOWED_ON_NON_LEAF;
	}
	talloc_free(res);

	return ldb_next_request(module, req);
}

const struct ldb_module_ops ldb_subtree_delete_module_ops = {
	.name		   = "subtree_delete",
	.del               = subtree_delete,
};
