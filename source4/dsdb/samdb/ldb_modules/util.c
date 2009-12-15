/* 
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 2009
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009

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
#include "ldb.h"
#include "ldb_module.h"
#include "librpc/ndr/libndr.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/samdb.h"
#include "util.h"

/*
  add a set of controls to a ldb_request structure based on a set of
  flags. See util.h for a list of available flags
 */
int dsdb_request_add_controls(struct ldb_module *module, struct ldb_request *req, uint32_t dsdb_flags)
{
	int ret;
	if (dsdb_flags & DSDB_SEARCH_SEARCH_ALL_PARTITIONS) {
		struct ldb_search_options_control *options;
		/* Using the phantom root control allows us to search all partitions */
		options = talloc(req, struct ldb_search_options_control);
		if (options == NULL) {
			ldb_module_oom(module);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		options->search_options = LDB_SEARCH_OPTION_PHANTOM_ROOT;
		
		ret = ldb_request_add_control(req,
					      LDB_CONTROL_SEARCH_OPTIONS_OID,
					      true, options);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_SHOW_DELETED) {
		ret = ldb_request_add_control(req, LDB_CONTROL_SHOW_DELETED_OID, true, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT) {
		ret = ldb_request_add_control(req, DSDB_CONTROL_DN_STORAGE_FORMAT_OID, true, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_SHOW_EXTENDED_DN) {
		struct ldb_extended_dn_control *extended_ctrl = talloc(req, struct ldb_extended_dn_control);
		if (!extended_ctrl) {
			ldb_module_oom(module);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		extended_ctrl->type = 1;
		
		ret = ldb_request_add_control(req, LDB_CONTROL_EXTENDED_DN_OID, true, extended_ctrl);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dsdb_flags & DSDB_SEARCH_REVEAL_INTERNALS) {
		ret = ldb_request_add_control(req, LDB_CONTROL_REVEAL_INTERNALS, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

/*
  search for attrs on one DN, in the modules below
 */
int dsdb_module_search_dn(struct ldb_module *module,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_result **_res,
			  struct ldb_dn *basedn,
			  const char * const *attrs,
			  uint32_t dsdb_flags)
{
	int ret;
	struct ldb_request *req;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;

	tmp_ctx = talloc_new(mem_ctx);

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb_module_get_ctx(module), tmp_ctx,
				   basedn,
				   LDB_SCOPE_BASE,
				   NULL,
				   attrs,
				   NULL,
				   res,
				   ldb_search_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(module, req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = ldb_next_request(module, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	if (res->count != 1) {
		/* we may be reading a DB that does not have the 'check base on search' option... */
		ret = LDB_ERR_NO_SUCH_OBJECT;
		ldb_asprintf_errstring(ldb_module_get_ctx(module), 
				       "dsdb_module_search_dn: did not find base dn %s (%d results)", 
				       ldb_dn_get_linearized(basedn), res->count);
	} else {
		*_res = talloc_steal(mem_ctx, res);
	}
	talloc_free(tmp_ctx);
	return ret;
}

/*
  search for attrs in the modules below
 */
int dsdb_module_search(struct ldb_module *module,
		       TALLOC_CTX *mem_ctx,
		       struct ldb_result **_res,
		       struct ldb_dn *basedn, enum ldb_scope scope, 
		       const char * const *attrs,
		       int dsdb_flags, 
		       const char *expression)
{
	int ret;
	struct ldb_request *req;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;

	tmp_ctx = talloc_new(mem_ctx);

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb_module_get_ctx(module), tmp_ctx,
				   basedn,
				   scope,
				   expression,
				   attrs,
				   NULL,
				   res,
				   ldb_search_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(module, req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = ldb_next_request(module, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	talloc_free(req);
	if (ret == LDB_SUCCESS) {
		*_res = talloc_steal(mem_ctx, res);
	}
	talloc_free(tmp_ctx);
	return ret;
}

/*
  find a DN given a GUID. This searches across all partitions
 */
int dsdb_module_dn_by_guid(struct ldb_module *module, TALLOC_CTX *mem_ctx,
			   const struct GUID *guid, struct ldb_dn **dn)
{
	struct ldb_result *res;
	const char *attrs[] = { NULL };
	char *expression;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	int ret;

	expression = talloc_asprintf(tmp_ctx, "objectGUID=%s", GUID_string(tmp_ctx, guid));
	if (!expression) {
		ldb_module_oom(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = dsdb_module_search(module, tmp_ctx, &res, NULL, LDB_SCOPE_SUBTREE,
				 attrs,
				 DSDB_SEARCH_SHOW_DELETED |
				 DSDB_SEARCH_SEARCH_ALL_PARTITIONS |
				 DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
				 expression);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	if (res->count == 0) {
		talloc_free(tmp_ctx);
		return LDB_ERR_NO_SUCH_OBJECT;
	}
	if (res->count != 1) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module), "More than one object found matching %s\n",
				       expression);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*dn = talloc_steal(mem_ctx, res->msgs[0]->dn);

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

/*
  a ldb_modify request operating on modules below the
  current module
 */
int dsdb_module_modify(struct ldb_module *module,
		       const struct ldb_message *message,
		       uint32_t dsdb_flags)
{
	struct ldb_request *mod_req;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx = talloc_new(module);

	ret = ldb_build_mod_req(&mod_req, ldb, tmp_ctx,
				message,
				NULL,
				NULL,
				ldb_op_default_callback,
				NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(module, mod_req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Run the new request */
	ret = ldb_next_request(module, mod_req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(mod_req->handle, LDB_WAIT_ALL);
	}

	talloc_free(tmp_ctx);
	return ret;
}



/*
  a ldb_rename request operating on modules below the
  current module
 */
int dsdb_module_rename(struct ldb_module *module,
                      struct ldb_dn *olddn, struct ldb_dn *newdn,
                      uint32_t dsdb_flags)
{
	struct ldb_request *req;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx = talloc_new(module);

	ret = ldb_build_rename_req(&req, ldb, tmp_ctx,
				   olddn,
				   newdn,
				   NULL,
				   NULL,
				   ldb_op_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(module, req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Run the new request */
	ret = ldb_next_request(module, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	talloc_free(tmp_ctx);
	return ret;
}

const struct dsdb_class * get_last_structural_class(const struct dsdb_schema *schema,const struct ldb_message_element *element)
{
	const struct dsdb_class *last_class = NULL;
	int i;

	for (i = 0; i < element->num_values; i++){
		const struct dsdb_class *tmp_class = dsdb_class_by_lDAPDisplayName_ldb_val(schema, &element->values[i]);

		if(tmp_class == NULL) {
			continue;
		}

		if(tmp_class->objectClassCategory == 3) {
			continue;
		}

		if (!last_class) {
			last_class = tmp_class;
		} else {
			if (tmp_class->subClass_order > last_class->subClass_order)
				last_class = tmp_class;
		}
	}

	return last_class;
}
