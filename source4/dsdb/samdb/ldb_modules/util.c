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

	if (dsdb_flags & DSDB_MODIFY_RELAX) {
		ret = ldb_request_add_control(req, LDB_CONTROL_RELAX_OID, false, NULL);
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
		       const char *format, ...) _PRINTF_ATTRIBUTE(8, 9)
{
	int ret;
	struct ldb_request *req;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;
	va_list ap;
	char *expression;

	tmp_ctx = talloc_new(mem_ctx);

	va_start(ap, format);
	expression = talloc_vasprintf(tmp_ctx, format, ap);
	va_end(ap);

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

	if (dsdb_flags & DSDB_FLAG_OWN_MODULE) {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		ret = ops->search(module, req);
	} else {
		ret = ldb_next_request(module, req);
	}
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
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	int ret;

	ret = dsdb_module_search(module, tmp_ctx, &res, NULL, LDB_SCOPE_SUBTREE,
				 attrs,
				 DSDB_SEARCH_SHOW_DELETED |
				 DSDB_SEARCH_SEARCH_ALL_PARTITIONS |
				 DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
				 "objectGUID=%s", GUID_string(tmp_ctx, guid));
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	if (res->count == 0) {
		talloc_free(tmp_ctx);
		return LDB_ERR_NO_SUCH_OBJECT;
	}
	if (res->count != 1) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module), "More than one object found matching objectGUID %s\n",
				       GUID_string(tmp_ctx, guid));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*dn = talloc_steal(mem_ctx, res->msgs[0]->dn);

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

/*
  find a GUID given a DN.
 */
int dsdb_module_guid_by_dn(struct ldb_module *module, struct ldb_dn *dn, struct GUID *guid)
{
	const char *attrs[] = { NULL };
	struct ldb_result *res;
	TALLOC_CTX *tmp_ctx = talloc_new(module);
	int ret;
	NTSTATUS status;

	ret = dsdb_module_search_dn(module, tmp_ctx, &res, dn, attrs,
				    DSDB_SEARCH_SHOW_DELETED|
				    DSDB_SEARCH_SHOW_EXTENDED_DN);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module), "Failed to find GUID for %s",
				       ldb_dn_get_linearized(dn));
		talloc_free(tmp_ctx);
		return ret;
	}

	status = dsdb_get_extended_dn_guid(res->msgs[0]->dn, guid, "GUID");
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

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
	if (dsdb_flags & DSDB_FLAG_OWN_MODULE) {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		ret = ops->modify(module, mod_req);
	} else {
		ret = ldb_next_request(module, mod_req);
	}
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
	if (dsdb_flags & DSDB_FLAG_OWN_MODULE) {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		ret = ops->rename(module, req);
	} else {
		ret = ldb_next_request(module, req);
	}
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	talloc_free(tmp_ctx);
	return ret;
}

/*
  a ldb_add request operating on modules below the
  current module
 */
int dsdb_module_add(struct ldb_module *module,
		    const struct ldb_message *message,
		    uint32_t dsdb_flags)
{
	struct ldb_request *req;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx = talloc_new(module);

	ret = ldb_build_add_req(&req, ldb, tmp_ctx,
				message,
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
	if (dsdb_flags & DSDB_FLAG_OWN_MODULE) {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		ret = ops->add(module, req);
	} else {
		ret = ldb_next_request(module, req);
	}
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

/*
  check if a single valued link has multiple non-deleted values

  This is needed when we will be using the RELAX control to stop
  ldb_tdb from checking single valued links
 */
int dsdb_check_single_valued_link(const struct dsdb_attribute *attr,
				  const struct ldb_message_element *el)
{
	bool found_active = false;
	int i;

	if (!(attr->ldb_schema_attribute->flags & LDB_ATTR_FLAG_SINGLE_VALUE) ||
	    el->num_values < 2) {
		return LDB_SUCCESS;
	}

	for (i=0; i<el->num_values; i++) {
		if (!dsdb_dn_is_deleted_val(&el->values[i])) {
			if (found_active) {
				return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
			}
			found_active = true;
		}
	}

	return LDB_SUCCESS;
}


/*
  find a 'reference' DN that points at another object
  (eg. serverReference, rIDManagerReference etc)
 */
int dsdb_module_reference_dn(struct ldb_module *module, TALLOC_CTX *mem_ctx, struct ldb_dn *base,
			     const char *attribute, struct ldb_dn **dn)
{
	const char *attrs[2];
	struct ldb_result *res;
	int ret;

	attrs[0] = attribute;
	attrs[1] = NULL;

	ret = dsdb_module_search_dn(module, mem_ctx, &res, base, attrs, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	*dn = ldb_msg_find_attr_as_dn(ldb_module_get_ctx(module),
				      mem_ctx, res->msgs[0], attribute);
	if (!*dn) {
		talloc_free(res);
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	talloc_free(res);
	return LDB_SUCCESS;
}

/*
  find the RID Manager$ DN via the rIDManagerReference attribute in the
  base DN
 */
int dsdb_module_rid_manager_dn(struct ldb_module *module, TALLOC_CTX *mem_ctx, struct ldb_dn **dn)
{
	return dsdb_module_reference_dn(module, mem_ctx,
					samdb_base_dn(ldb_module_get_ctx(module)),
					"rIDManagerReference", dn);
}


/*
  update an integer attribute safely via a constrained delete/add
 */
int dsdb_module_constrainted_update_integer(struct ldb_module *module, struct ldb_dn *dn,
					    const char *attr, uint64_t old_val, uint64_t new_val)
{
	struct ldb_message *msg;
	struct ldb_message_element *el;
	struct ldb_val v1, v2;
	int ret;
	char *vstring;

	msg = ldb_msg_new(module);
	msg->dn = dn;

	ret = ldb_msg_add_empty(msg, attr, LDB_FLAG_MOD_DELETE, &el);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}
	el->num_values = 1;
	el->values = &v1;
	vstring = talloc_asprintf(msg, "%llu", (unsigned long long)old_val);
	if (!vstring) {
		ldb_module_oom(module);
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	v1 = data_blob_string_const(vstring);

	ret = ldb_msg_add_empty(msg, attr, LDB_FLAG_MOD_ADD, &el);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}
	el->num_values = 1;
	el->values = &v2;
	vstring = talloc_asprintf(msg, "%llu", (unsigned long long)new_val);
	if (!vstring) {
		ldb_module_oom(module);
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	v2 = data_blob_string_const(vstring);

	ret = dsdb_module_modify(module, msg, 0);
	talloc_free(msg);
	return ret;
}

/*
  used to chain to the callers callback
 */
int dsdb_next_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_request *up_req = talloc_get_type(req->context, struct ldb_request);

	talloc_steal(up_req, req);
	return up_req->callback(up_req, ares);
}

