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
#include "libcli/security/security.h"

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
		talloc_free(tmp_ctx);
		return ldb_oom(ldb_module_get_ctx(module));
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

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Run the new request */
	if (dsdb_flags & DSDB_FLAG_NEXT_MODULE) {
		ret = ldb_next_request(module, req);
	} else if (dsdb_flags & DSDB_FLAG_TOP_MODULE) {
		ret = ldb_request(ldb_module_get_ctx(module), req);
	} else {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		SMB_ASSERT(dsdb_flags & DSDB_FLAG_OWN_MODULE);
		ret = ops->modify(module, req);
	}
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

	if (format) {
		va_start(ap, format);
		expression = talloc_vasprintf(tmp_ctx, format, ap);
		va_end(ap);

		if (!expression) {
			talloc_free(tmp_ctx);
			return ldb_oom(ldb_module_get_ctx(module));
		}
	} else {
		expression = NULL;
	}

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb_module_get_ctx(module));
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

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	if (dsdb_flags & DSDB_FLAG_NEXT_MODULE) {
		ret = ldb_next_request(module, req);
	} else if (dsdb_flags & DSDB_FLAG_TOP_MODULE) {
		ret = ldb_request(ldb_module_get_ctx(module), req);
	} else {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		SMB_ASSERT(dsdb_flags & DSDB_FLAG_OWN_MODULE);
		ret = ops->search(module, req);
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
				 DSDB_FLAG_NEXT_MODULE |
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
	                            DSDB_FLAG_NEXT_MODULE |
	                            DSDB_SEARCH_SHOW_DELETED |
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
		return ldb_operr(ldb_module_get_ctx(module));
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
	struct ldb_result *res;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb_module_get_ctx(module));
	}

	ret = ldb_build_mod_req(&mod_req, ldb, tmp_ctx,
				message,
				NULL,
				res,
				ldb_modify_default_callback,
				NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(mod_req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Run the new request */
	if (dsdb_flags & DSDB_FLAG_NEXT_MODULE) {
		ret = ldb_next_request(module, mod_req);
	} else if (dsdb_flags & DSDB_FLAG_TOP_MODULE) {
		ret = ldb_request(ldb_module_get_ctx(module), mod_req);
	} else {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		SMB_ASSERT(dsdb_flags & DSDB_FLAG_OWN_MODULE);
		ret = ops->modify(module, mod_req);
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
	struct ldb_result *res;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb_module_get_ctx(module));
	}

	ret = ldb_build_rename_req(&req, ldb, tmp_ctx,
				   olddn,
				   newdn,
				   NULL,
				   res,
				   ldb_modify_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Run the new request */
	if (dsdb_flags & DSDB_FLAG_NEXT_MODULE) {
		ret = ldb_next_request(module, req);
	} else if (dsdb_flags & DSDB_FLAG_TOP_MODULE) {
		ret = ldb_request(ldb_module_get_ctx(module), req);
	} else {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		SMB_ASSERT(dsdb_flags & DSDB_FLAG_OWN_MODULE);
		ret = ops->rename(module, req);
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
	struct ldb_result *res;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb_module_get_ctx(module));
	}

	ret = ldb_build_add_req(&req, ldb, tmp_ctx,
				message,
				NULL,
				res,
				ldb_modify_default_callback,
				NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Run the new request */
	if (dsdb_flags & DSDB_FLAG_NEXT_MODULE) {
		ret = ldb_next_request(module, req);
	} else if (dsdb_flags & DSDB_FLAG_TOP_MODULE) {
		ret = ldb_request(ldb_module_get_ctx(module), req);
	} else {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		SMB_ASSERT(dsdb_flags & DSDB_FLAG_OWN_MODULE);
		ret = ops->add(module, req);
	}
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	talloc_free(tmp_ctx);
	return ret;
}

/*
  a ldb_delete request operating on modules below the
  current module
 */
int dsdb_module_del(struct ldb_module *module,
		    struct ldb_dn *dn,
		    uint32_t dsdb_flags)
{
	struct ldb_request *req;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx = talloc_new(module);
	struct ldb_result *res;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	ret = ldb_build_del_req(&req, ldb, tmp_ctx,
				dn,
				NULL,
				res,
				ldb_modify_default_callback,
				NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(req, dsdb_flags);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Run the new request */
	if (dsdb_flags & DSDB_FLAG_NEXT_MODULE) {
		ret = ldb_next_request(module, req);
	} else if (dsdb_flags & DSDB_FLAG_TOP_MODULE) {
		ret = ldb_request(ldb_module_get_ctx(module), req);
	} else {
		const struct ldb_module_ops *ops = ldb_module_get_ops(module);
		SMB_ASSERT(dsdb_flags & DSDB_FLAG_OWN_MODULE);
		ret = ops->del(module, req);
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
	unsigned int i;

	for (i = 0; i < element->num_values; i++){
		const struct dsdb_class *tmp_class = dsdb_class_by_lDAPDisplayName_ldb_val(schema, &element->values[i]);

		if(tmp_class == NULL) {
			continue;
		}

		if(tmp_class->objectClassCategory > 1) {
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
	unsigned int i;

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

int dsdb_check_optional_feature(struct ldb_module *module, struct ldb_dn *scope,
					struct GUID op_feature_guid, bool *feature_enabled)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_result *res;
	struct ldb_dn *search_dn;
	struct GUID search_guid;
	const char *attrs[] = {"msDS-EnabledFeature", NULL};
	int ret;
	unsigned int i;
	struct ldb_message_element *el;

	*feature_enabled = false;

	tmp_ctx = talloc_new(ldb);

	ret = ldb_search(ldb, tmp_ctx, &res,
					scope, LDB_SCOPE_BASE, attrs,
					NULL);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb,
				"Could no find the scope object - dn: %s\n",
				ldb_dn_get_linearized(scope));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (res->msgs[0]->num_elements > 0) {

		el = ldb_msg_find_element(res->msgs[0],"msDS-EnabledFeature");

		attrs[0] = "msDS-OptionalFeatureGUID";

		for (i=0; i<el->num_values; i++) {
			search_dn = ldb_dn_from_ldb_val(tmp_ctx, ldb, &el->values[i]);

			ret = ldb_search(ldb, tmp_ctx, &res,
							search_dn, LDB_SCOPE_BASE, attrs,
							NULL);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb,
						"Could no find object dn: %s\n",
						ldb_dn_get_linearized(search_dn));
				talloc_free(tmp_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			search_guid = samdb_result_guid(res->msgs[0], "msDS-OptionalFeatureGUID");

			if (GUID_compare(&search_guid, &op_feature_guid) == 0){
				*feature_enabled = true;
				break;
			}
		}
	}
	talloc_free(tmp_ctx);
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

	ret = dsdb_module_search_dn(module, mem_ctx, &res, base, attrs,
	                            DSDB_FLAG_NEXT_MODULE);
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
					ldb_get_default_basedn(ldb_module_get_ctx(module)),
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
		talloc_free(msg);
		return ldb_module_oom(module);
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
		talloc_free(msg);
		return ldb_module_oom(module);
	}
	v2 = data_blob_string_const(vstring);

	ret = dsdb_module_modify(module, msg, DSDB_FLAG_NEXT_MODULE);
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


/*
  set an integer attribute
 */
int dsdb_module_set_integer(struct ldb_module *module, struct ldb_dn *dn,
			    const char *attr, uint64_t new_val)
{
	struct ldb_message *msg;
	int ret;

	msg = ldb_msg_new(module);
	msg->dn = dn;

	ret = ldb_msg_add_fmt(msg, attr, "%llu", (unsigned long long)new_val);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}
	msg->elements[0].flags = LDB_FLAG_MOD_REPLACE;

	ret = dsdb_module_modify(module, msg, DSDB_FLAG_NEXT_MODULE);
	talloc_free(msg);
	return ret;
}

/*
  load the uSNHighest and the uSNUrgent attributes from the @REPLCHANGED
  object for a partition
 */
int dsdb_module_load_partition_usn(struct ldb_module *module, struct ldb_dn *dn,
				  uint64_t *uSN, uint64_t *urgent_uSN)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *req;
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(module);
	struct dsdb_control_current_partition *p_ctrl;
	struct ldb_result *res;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_module_oom(module);
	}

	ret = ldb_build_search_req(&req, ldb, tmp_ctx,
				   ldb_dn_new(tmp_ctx, ldb, "@REPLCHANGED"),
				   LDB_SCOPE_BASE,
				   NULL, NULL,
				   NULL,
				   res, ldb_search_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	p_ctrl = talloc(req, struct dsdb_control_current_partition);
	if (p_ctrl == NULL) {
		talloc_free(tmp_ctx);
		return ldb_module_oom(module);
	}
	p_ctrl->version = DSDB_CONTROL_CURRENT_PARTITION_VERSION;
	p_ctrl->dn = dn;


	ret = ldb_request_add_control(req,
				      DSDB_CONTROL_CURRENT_PARTITION_OID,
				      false, p_ctrl);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Run the new request */
	ret = ldb_next_request(module, req);

	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret == LDB_ERR_NO_SUCH_OBJECT || ret == LDB_ERR_INVALID_DN_SYNTAX) {
		/* it hasn't been created yet, which means
		   an implicit value of zero */
		*uSN = 0;
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	if (res->count != 1) {
		*uSN = 0;
		if (urgent_uSN) {
			*urgent_uSN = 0;
		}
	} else {
		*uSN = ldb_msg_find_attr_as_uint64(res->msgs[0], "uSNHighest", 0);
		if (urgent_uSN) {
			*urgent_uSN = ldb_msg_find_attr_as_uint64(res->msgs[0], "uSNUrgent", 0);
		}
	}

	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}

/*
  save uSNHighest and uSNUrgent attributes in the @REPLCHANGED object for a
  partition
 */
int dsdb_module_save_partition_usn(struct ldb_module *module, struct ldb_dn *dn,
				   uint64_t uSN, uint64_t urgent_uSN)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *req;
	struct ldb_message *msg;
	struct dsdb_control_current_partition *p_ctrl;
	int ret;
	struct ldb_result *res;

	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return ldb_module_oom(module);
	}

	msg->dn = ldb_dn_new(msg, ldb, "@REPLCHANGED");
	if (msg->dn == NULL) {
		talloc_free(msg);
		return ldb_operr(ldb_module_get_ctx(module));
	}

	res = talloc_zero(msg, struct ldb_result);
	if (!res) {
		talloc_free(msg);
		return ldb_module_oom(module);
	}

	ret = ldb_msg_add_fmt(msg, "uSNHighest", "%llu", (unsigned long long)uSN);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}
	msg->elements[0].flags = LDB_FLAG_MOD_REPLACE;

	/* urgent_uSN is optional so may not be stored */
	if (urgent_uSN) {
		ret = ldb_msg_add_fmt(msg, "uSNUrgent", "%llu", (unsigned long long)urgent_uSN);
		if (ret != LDB_SUCCESS) {
			talloc_free(msg);
			return ret;
		}
		msg->elements[1].flags = LDB_FLAG_MOD_REPLACE;
	}


	p_ctrl = talloc(msg, struct dsdb_control_current_partition);
	if (p_ctrl == NULL) {
		talloc_free(msg);
		return ldb_oom(ldb);
	}
	p_ctrl->version = DSDB_CONTROL_CURRENT_PARTITION_VERSION;
	p_ctrl->dn = dn;
	ret = ldb_build_mod_req(&req, ldb, msg,
				msg,
				NULL,
				res,
				ldb_modify_default_callback,
				NULL);
again:
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}

	ret = ldb_request_add_control(req,
				      DSDB_CONTROL_CURRENT_PARTITION_OID,
				      false, p_ctrl);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}

	/* Run the new request */
	ret = ldb_next_request(module, req);

	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		ret = ldb_build_add_req(&req, ldb, msg,
					msg,
					NULL,
					res,
					ldb_modify_default_callback,
					NULL);
		goto again;
	}

	talloc_free(msg);

	return ret;
}

bool dsdb_module_am_system(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct auth_session_info *session_info
		= (struct auth_session_info *)ldb_get_opaque(ldb, "sessionInfo");
	return security_session_user_level(session_info, NULL) == SECURITY_SYSTEM;
}

/*
  check if the recyclebin is enabled
 */
int dsdb_recyclebin_enabled(struct ldb_module *module, bool *enabled)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *partitions_dn;
	struct GUID recyclebin_guid;
	int ret;

	partitions_dn = samdb_partitions_dn(ldb, module);

	GUID_from_string(DS_GUID_FEATURE_RECYCLE_BIN, &recyclebin_guid);

	ret = dsdb_check_optional_feature(module, partitions_dn, recyclebin_guid, enabled);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Could not verify if Recycle Bin is enabled \n");
		talloc_free(partitions_dn);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	talloc_free(partitions_dn);
	return LDB_SUCCESS;
}

bool is_attr_in_list(const char * const * attrs, const char *attr)
{
	unsigned int i;

	for (i = 0; attrs[i]; i++) {
		if (ldb_attr_cmp(attrs[i], attr) == 0)
			return true;
	}

	return false;
}

int dsdb_msg_constrainted_update_int32(struct ldb_module *module,
				       struct ldb_message *msg,
				       const char *attr,
				       const int32_t *old_val,
				       const int32_t *new_val)
{
	struct ldb_message_element *el;
	struct ldb_val *v1, *v2;
	int ret;
	char *vstring;

	if (old_val) {
		ret = ldb_msg_add_empty(msg, attr, LDB_FLAG_MOD_DELETE, &el);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el->num_values = 1;
		el->values = talloc_array(msg, struct ldb_val, el->num_values);
		if (!el->values) {
			return ldb_module_oom(module);
		}
		vstring = talloc_asprintf(el->values, "%ld", (long)*old_val);
		if (!vstring) {
			return ldb_module_oom(module);
		}
		*el->values = data_blob_string_const(vstring);
	}

	if (new_val) {
		ret = ldb_msg_add_empty(msg, attr, LDB_FLAG_MOD_ADD, &el);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el->num_values = 1;
		el->values = talloc_array(msg, struct ldb_val, el->num_values);
		if (!el->values) {
			return ldb_module_oom(module);
		}
		vstring = talloc_asprintf(el->values, "%ld", (long)*new_val);
		if (!vstring) {
			return ldb_module_oom(module);
		}
		*el->values = data_blob_string_const(vstring);
	}

	return LDB_SUCCESS;
}

int dsdb_msg_constrainted_update_uint32(struct ldb_module *module,
					struct ldb_message *msg,
					const char *attr,
					const uint32_t *old_val,
					const uint32_t *new_val)
{
	return dsdb_msg_constrainted_update_int32(module, msg, attr,
						  (const int32_t *)old_val,
						  (const int32_t *)new_val);
}

int dsdb_msg_constrainted_update_int64(struct ldb_module *module,
				       struct ldb_message *msg,
				       const char *attr,
				       const int64_t *old_val,
				       const int64_t *new_val)
{
	struct ldb_message_element *el;
	struct ldb_val *v1, *v2;
	int ret;
	char *vstring;

	if (old_val) {
		ret = ldb_msg_add_empty(msg, attr, LDB_FLAG_MOD_DELETE, &el);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el->num_values = 1;
		el->values = talloc_array(msg, struct ldb_val, el->num_values);
		if (!el->values) {
			return ldb_module_oom(module);
		}
		vstring = talloc_asprintf(el->values, "%lld", (long long)*old_val);
		if (!vstring) {
			return ldb_module_oom(module);
		}
		*el->values = data_blob_string_const(vstring);
	}

	if (new_val) {
		ret = ldb_msg_add_empty(msg, attr, LDB_FLAG_MOD_ADD, &el);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el->num_values = 1;
		el->values = talloc_array(msg, struct ldb_val, el->num_values);
		if (!el->values) {
			return ldb_module_oom(module);
		}
		vstring = talloc_asprintf(el->values, "%lld", (long long)*new_val);
		if (!vstring) {
			return ldb_module_oom(module);
		}
		*el->values = data_blob_string_const(vstring);
	}

	return LDB_SUCCESS;
}

int dsdb_msg_constrainted_update_uint64(struct ldb_module *module,
					struct ldb_message *msg,
					const char *attr,
					const uint64_t *old_val,
					const uint64_t *new_val)
{
	return dsdb_msg_constrainted_update_int64(module, msg, attr,
						  (const int64_t *)old_val,
						  (const int64_t *)new_val);
}

/*
  update an int32 attribute safely via a constrained delete/add
 */
int dsdb_module_constrainted_update_int32(struct ldb_module *module,
					  struct ldb_dn *dn,
					  const char *attr,
					  const int32_t *old_val,
					  const int32_t *new_val)
{
	struct ldb_message *msg;
	int ret;

	msg = ldb_msg_new(module);
	msg->dn = dn;

	ret = dsdb_msg_constrainted_update_int32(module,
						 msg, attr,
						 old_val,
						 new_val);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}

	ret = dsdb_module_modify(module, msg, DSDB_FLAG_NEXT_MODULE);
	talloc_free(msg);
	return ret;
}

int dsdb_module_constrainted_update_uint32(struct ldb_module *module,
					   struct ldb_dn *dn,
					   const char *attr,
					   const uint32_t *old_val,
					   const uint32_t *new_val)
{
	return dsdb_module_constrainted_update_int32(module, dn, attr,
						     (const int32_t *)old_val,
						     (const int32_t *)new_val);
}

/*
  update an int64 attribute safely via a constrained delete/add
 */
int dsdb_module_constrainted_update_int64(struct ldb_module *module,
					  struct ldb_dn *dn,
					  const char *attr,
					  const int64_t *old_val,
					  const int64_t *new_val)
{
	struct ldb_message *msg;
	int ret;

	msg = ldb_msg_new(module);
	msg->dn = dn;

	ret = dsdb_msg_constrainted_update_int64(module,
						 msg, attr,
						 old_val,
						 new_val);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}

	ret = dsdb_module_modify(module, msg, DSDB_FLAG_NEXT_MODULE);
	talloc_free(msg);
	return ret;
}

int dsdb_module_constrainted_update_uint64(struct ldb_module *module,
					   struct ldb_dn *dn,
					   const char *attr,
					   const uint64_t *old_val,
					   const uint64_t *new_val)
{
	return dsdb_module_constrainted_update_int64(module, dn, attr,
						     (const int64_t *)old_val,
						     (const int64_t *)new_val);
}
