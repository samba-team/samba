/*
   notification control module

   Copyright (C) Stefan Metzmacher 2015

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


#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

struct dsdb_notification_cookie {
	uint64_t known_usn;
};

static int dsdb_notification_verify_tree(struct ldb_parse_tree *tree)
{
	unsigned int i;
	int ret;
	unsigned int num_ok = 0;
	/*
	 * these attributes are present on every object
	 * and windows accepts them.
	 *
	 * While [MS-ADTS] says only '(objectClass=*)'
	 * would be allowed.
	 */
	static const char * const attrs_ok[] = {
		"objectClass",
		"objectGUID",
		"distinguishedName",
		"name",
		NULL,
	};

	switch (tree->operation) {
	case LDB_OP_AND:
		for (i = 0; i < tree->u.list.num_elements; i++) {
			/*
			 * all elements need to be valid
			 */
			ret = dsdb_notification_verify_tree(tree->u.list.elements[i]);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			num_ok++;
		}
		break;
	case LDB_OP_OR:
		for (i = 0; i < tree->u.list.num_elements; i++) {
			/*
			 * at least one element needs to be valid
			 */
			ret = dsdb_notification_verify_tree(tree->u.list.elements[i]);
			if (ret == LDB_SUCCESS) {
				num_ok++;
				break;
			}
		}
		break;
	case LDB_OP_NOT:
	case LDB_OP_EQUALITY:
	case LDB_OP_GREATER:
	case LDB_OP_LESS:
	case LDB_OP_APPROX:
	case LDB_OP_SUBSTRING:
	case LDB_OP_EXTENDED:
		break;

	case LDB_OP_PRESENT:
		ret = ldb_attr_in_list(attrs_ok, tree->u.present.attr);
		if (ret == 1) {
			num_ok++;
		}
		break;
	}

	if (num_ok != 0) {
		return LDB_SUCCESS;
	}

	return LDB_ERR_UNWILLING_TO_PERFORM;
}

static int dsdb_notification_filter_search(struct ldb_module *module,
					  struct ldb_request *req,
					  struct ldb_control *control)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	char *filter_usn = NULL;
	struct ldb_parse_tree *down_tree = NULL;
	struct ldb_request *down_req = NULL;
	struct dsdb_notification_cookie *cookie = NULL;
	int ret;

	if (req->op.search.tree == NULL) {
		return dsdb_module_werror(module, LDB_ERR_OTHER,
					  WERR_DS_NOTIFY_FILTER_TOO_COMPLEX,
					  "Search filter missing.");
	}

	ret = dsdb_notification_verify_tree(req->op.search.tree);
	if (ret != LDB_SUCCESS) {
		return dsdb_module_werror(module, ret,
					  WERR_DS_NOTIFY_FILTER_TOO_COMPLEX,
					  "Search filter too complex.");
	}

	/*
	 * For now we use a very simple design:
	 *
	 * - We don't do fully async ldb_requests,
	 *   the caller needs to retry periodically!
	 * - The only useful caller is the LDAP server, which is a long
	 *   running task that can do periodic retries.
	 * - We use a cookie in order to transfer state between the
	 *   retries.
	 * - We just search the available new objects each time we're
	 *   called.
	 *
	 * As the only valid search filter is '(objectClass=*)' or
	 * something similar that matches every object, we simply
	 * replace it with (uSNChanged >= ) filter.
	 * We could improve this later if required...
	 */

	/*
	 * The ldap_control_handler() decode_flag_request for
	 * LDB_CONTROL_NOTIFICATION_OID. This makes sure
	 * notification_control->data is NULL when comming from
	 * the client.
	 */
	if (control->data == NULL) {
		cookie = talloc_zero(control, struct dsdb_notification_cookie);
		if (cookie == NULL) {
			return ldb_module_oom(module);
		}
		control->data = (uint8_t *)cookie;

		/* mark the control as done */
		control->critical = 0;
	}

	cookie = talloc_get_type_abort(control->data,
				       struct dsdb_notification_cookie);

	if (cookie->known_usn != 0) {
		filter_usn = talloc_asprintf(req, "%llu",
				(unsigned long long)(cookie->known_usn)+1);
		if (filter_usn == NULL) {
			return ldb_module_oom(module);
		}
	}

	ret = ldb_sequence_number(ldb, LDB_SEQ_HIGHEST_SEQ,
				  &cookie->known_usn);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (filter_usn == NULL) {
		/*
		 * It's the first time, let the caller comeback later
		 * as we won't find any new objects.
		 */
		return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
	}

	down_tree = talloc_zero(req, struct ldb_parse_tree);
	if (down_tree == NULL) {
		return ldb_module_oom(module);
	}
	down_tree->operation = LDB_OP_GREATER;
	down_tree->u.equality.attr = "uSNChanged";
	down_tree->u.equality.value = data_blob_string_const(filter_usn);
	(void)talloc_move(down_req, &filter_usn);

	ret = ldb_build_search_req_ex(&down_req, ldb, req,
				      req->op.search.base,
				      req->op.search.scope,
				      down_tree,
				      req->op.search.attrs,
				      req->controls,
				      req, dsdb_next_callback,
				      req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* perform the search */
	return ldb_next_request(module, down_req);
}

static int dsdb_notification_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control = NULL;

	if (ldb_dn_is_special(req->op.search.base)) {
		return ldb_next_request(module, req);
	}

	/*
	 * check if there's an extended dn control
	 */
	control = ldb_request_get_control(req, LDB_CONTROL_NOTIFICATION_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	return dsdb_notification_filter_search(module, req, control);
}

static int dsdb_notification_init(struct ldb_module *module)
{
	int ret;

	ret = ldb_mod_register_control(module, LDB_CONTROL_NOTIFICATION_OID);
	if (ret != LDB_SUCCESS) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);

		ldb_debug(ldb, LDB_DEBUG_ERROR,
			"notification: Unable to register control with rootdse!\n");
		return ldb_module_operr(module);
	}

	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_dsdb_notification_module_ops = {
	.name		   = "dsdb_notification",
	.search            = dsdb_notification_search,
	.init_context	   = dsdb_notification_init,
};

/*
  initialise the module
 */
_PUBLIC_ int ldb_dsdb_notification_module_init(const char *version)
{
	int ret;
	LDB_MODULE_CHECK_VERSION(version);
	ret = ldb_register_module(&ldb_dsdb_notification_module_ops);
	return ret;
}
