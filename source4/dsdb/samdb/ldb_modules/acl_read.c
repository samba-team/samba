/*
  ldb database library

  Copyright (C) Simo Sorce 2006-2008
  Copyright (C) Nadezhda Ivanova 2010

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
 *  Component: ldb ACL Read module
 *
 *  Description: Module that performs authorisation access checks on read requests
 *               Only DACL checks implemented at this point
 *
 *  Author: Nadezhda Ivanova
 */

#include "includes.h"
#include "ldb_module.h"
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "param/param.h"
#include "dsdb/samdb/ldb_modules/util.h"


struct aclread_context {
	struct ldb_module *module;
	struct ldb_request *req;
	const char * const *attrs;
	const struct dsdb_schema *schema;
	bool sd;
	bool instance_type;
	bool object_sid;
};

struct aclread_private {
	bool enabled;
};

static int aclread_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	 struct ldb_context *ldb;
	 struct aclread_context *ac;
	 int ret;
	 unsigned int i;
	 struct security_descriptor *sd;
	 struct dom_sid *sid = NULL;
	 TALLOC_CTX *tmp_ctx;
	 uint32_t instanceType;

	 ac = talloc_get_type(req->context, struct aclread_context);
	 ldb = ldb_module_get_ctx(ac->module);
	 if (!ares) {
		 return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR );
	 }
	 if (ares->error != LDB_SUCCESS) {
		 return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	 }
	 tmp_ctx = talloc_new(ac);
	 switch (ares->type) {
	 case LDB_REPLY_ENTRY:
		 ret = dsdb_get_sd_from_ldb_message(ldb, tmp_ctx, ares->message, &sd);
		 if (ret != LDB_SUCCESS) {
			 DEBUG(10, ("acl_read: cannot get descriptor\n"));
			 ret = LDB_ERR_OPERATIONS_ERROR;
			 goto fail;
		 }
		 sid = samdb_result_dom_sid(tmp_ctx, ares->message, "objectSid");
		 /* get the object instance type */
		 instanceType = ldb_msg_find_attr_as_uint(ares->message,
							 "instanceType", 0);
		 if (!ldb_dn_is_null(ares->message->dn) && !(instanceType & INSTANCE_TYPE_IS_NC_HEAD))
		 {
			/* the object has a parent, so we have to check for visibility */
			struct ldb_dn *parent_dn = ldb_dn_get_parent(tmp_ctx, ares->message->dn);
			ret = dsdb_module_check_access_on_dn(ac->module,
							     tmp_ctx,
							     parent_dn,
							     SEC_ADS_LIST,
							     NULL);
			if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
				talloc_free(tmp_ctx);
				return LDB_SUCCESS;
			} else if (ret != LDB_SUCCESS) {
				goto fail;
			}
		 }
		 /* for every element in the message check RP */
		 i = 0;
		 while (i < ares->message->num_elements) {
			 const struct dsdb_attribute *attr;
			 attr =  dsdb_attribute_by_lDAPDisplayName(ac->schema,
								   ares->message->elements[i].name);
			 if (!attr) {
				 DEBUG(2, ("acl_read: cannot find attribute %s in schema\n",
					   ares->message->elements[i].name));
				 ret = LDB_ERR_OPERATIONS_ERROR;
				 goto fail;
			 }
			 /* nTSecurityDescriptor is a special case */
			 if (ldb_attr_cmp("nTSecurityDescriptor",
					  ares->message->elements[i].name) == 0) {
				 if (ac->sd) {
					 ldb_msg_remove_attr(ares->message, ares->message->elements[i].name);
					 ret = LDB_SUCCESS;
				 }
				 ret = acl_check_access_on_attribute(ac->module,
								     tmp_ctx,
								     sd,
								     sid,
								     SEC_FLAG_SYSTEM_SECURITY|SEC_STD_READ_CONTROL,
								     attr);
			 } else {
				 ret = acl_check_access_on_attribute(ac->module,
								     tmp_ctx,
								     sd,
								     sid,
								     SEC_ADS_READ_PROP,
								     attr);
			 }
			 if (ret == LDB_SUCCESS) {
				 i++;
			 } else if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
				 /* do not return this entry if attribute is
					    part of the search filter */
				 if (dsdb_attr_in_parse_tree(ac->req->op.search.tree,
							     ares->message->elements[i].name)) {
					 talloc_free(tmp_ctx);
					 return LDB_SUCCESS;
				 }
				 ldb_msg_remove_attr(ares->message, ares->message->elements[i].name);
			 } else {
				 goto fail;
			 }
		 }
		 if (ac->instance_type) {
			 ldb_msg_remove_attr(ares->message, "instanceType");
		 }
		 if (ac->object_sid) {
			 ldb_msg_remove_attr(ares->message, "objectSid");
		 }
		 talloc_free(tmp_ctx);
		 return ldb_module_send_entry(ac->req, ares->message, ares->controls);
	 case LDB_REPLY_REFERRAL:
		 return ldb_module_send_referral(ac->req, ares->referral);
	 case LDB_REPLY_DONE:
		 return ldb_module_done(ac->req, ares->controls,
					ares->response, LDB_SUCCESS);

	 }
	 return LDB_SUCCESS;
fail:
	 talloc_free(tmp_ctx);
	 return ldb_module_done(ac->req, NULL, NULL, ret);
}


static int aclread_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	int ret;
	struct aclread_context *ac;
	struct ldb_request *down_req;
	struct ldb_control *as_system = ldb_request_get_control(req, LDB_CONTROL_AS_SYSTEM_OID);
	struct ldb_result *res;
	struct aclread_private *p;
	bool is_untrusted = ldb_req_is_untrusted(req);
	const char * const *attrs = NULL;
	uint32_t instanceType;
	static const char *acl_attrs[] = {
		 "instanceType",
		 NULL
	};

	ldb = ldb_module_get_ctx(module);
	p = talloc_get_type(ldb_module_get_private(module), struct aclread_private);

	/* skip access checks if we are system or system control is supplied
	 * or this is not LDAP server request */
	if (!p || !p->enabled ||
	    dsdb_module_am_system(module)
	    || as_system || !is_untrusted) {
		return ldb_next_request(module, req);
	}
	/* no checks on special dn */
	if (ldb_dn_is_special(req->op.search.base)) {
		return ldb_next_request(module, req);
	}

	/* check accessibility of base */
	if (!ldb_dn_is_null(req->op.search.base)) {
		ret = dsdb_module_search_dn(module, req, &res, req->op.search.base,
					    acl_attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_SEARCH_SHOW_DELETED);
		if (ret != LDB_SUCCESS) {
			return ldb_error(ldb, ret,
					 "acl_read: Error retrieving instanceType for base.");
		}
		instanceType = ldb_msg_find_attr_as_uint(res->msgs[0],
							 "instanceType", 0);
		if (instanceType != 0 && !(instanceType & INSTANCE_TYPE_IS_NC_HEAD))
		{
			/* the object has a parent, so we have to check for visibility */
			struct ldb_dn *parent_dn = ldb_dn_get_parent(req, req->op.search.base);
			ret = dsdb_module_check_access_on_dn(module,
							     req,
							     parent_dn,
							     SEC_ADS_LIST,
							     NULL);
			if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
				return ldb_module_done(req, NULL, NULL, LDB_ERR_NO_SUCH_OBJECT);
			} else if (ret != LDB_SUCCESS) {
				return ldb_module_done(req, NULL, NULL, ret);
			}
		}
	}
	ac = talloc_zero(req, struct aclread_context);
	if (ac == NULL) {
		return ldb_oom(ldb);
	}
	ac->module = module;
	ac->req = req;
	ac->schema = dsdb_get_schema(ldb, req);
	if (!ac->schema) {
		return ldb_operr(ldb);
	}
	ac->sd = !(ldb_attr_in_list(req->op.search.attrs, "nTSecurityDescriptor"));
	if (req->op.search.attrs && !ldb_attr_in_list(req->op.search.attrs, "*")) {
		if (!ldb_attr_in_list(req->op.search.attrs, "instanceType")) {
			ac->instance_type = true;
			attrs = ldb_attr_list_copy_add(ac, req->op.search.attrs, "instanceType");
		} else {
			attrs = req->op.search.attrs;
		}
		if (!ldb_attr_in_list(req->op.search.attrs, "objectSid")) {
			ac->object_sid = true;
			attrs = ldb_attr_list_copy_add(ac, attrs, "objectSid");
		}
	}

	if (ac->sd) {
		/* avoid replacing all attributes with nTSecurityDescriptor
		 * if attribute list is empty */
		if (!attrs) {
			attrs = ldb_attr_list_copy_add(ac, attrs, "*");
		}
		attrs = ldb_attr_list_copy_add(ac, attrs, "nTSecurityDescriptor");
	}
	ac->attrs = req->op.search.attrs;
	ret = ldb_build_search_req_ex(&down_req,
				      ldb, ac,
				      req->op.search.base,
				      req->op.search.scope,
				      req->op.search.tree,
				      attrs,
				      req->controls,
				      ac, aclread_callback,
				      req);

	if (ret != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ldb_next_request(module, down_req);
}

static int aclread_init(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct aclread_private *p = talloc_zero(module, struct aclread_private);
	if (p == NULL) {
		return ldb_module_oom(module);
	}
	p->enabled = lpcfg_parm_bool(ldb_get_opaque(ldb, "loadparm"), NULL, "acl", "search", false);
	ldb_module_set_private(module, p);
	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_aclread_module_ops = {
	.name		   = "aclread",
	.search            = aclread_search,
	.init_context      = aclread_init
};

int ldb_aclread_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_aclread_module_ops);
}
