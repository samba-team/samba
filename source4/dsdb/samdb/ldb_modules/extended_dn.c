/* 
   ldb database library

   Copyright (C) Simo Sorce 2005-2008

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb extended dn control module
 *
 *  Description: this module builds a special dn
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"

#include <time.h>

static bool is_attr_in_list(const char * const * attrs, const char *attr)
{
	int i;

	for (i = 0; attrs[i]; i++) {
		if (strcasecmp(attrs[i], attr) == 0)
			return true;
	}

	return false;
}

static char **copy_attrs(void *mem_ctx, const char * const * attrs)
{
	char **new;
	int i, num;

	for (num = 0; attrs[num]; num++);

	new = talloc_array(mem_ctx, char *, num + 1);
	if (!new) return NULL;

	for(i = 0; i < num; i++) {
		new[i] = talloc_strdup(new, attrs[i]);
		if (!new[i]) {
			talloc_free(new);
			return NULL;
		}
	}
	new[i] = NULL;

	return new;
}

static bool add_attrs(void *mem_ctx, char ***attrs, const char *attr)
{
	char **new;
	int num;

	for (num = 0; (*attrs)[num]; num++);

	new = talloc_realloc(mem_ctx, *attrs, char *, num + 2);
	if (!new) return false;

	*attrs = new;

	new[num] = talloc_strdup(new, attr);
	if (!new[num]) return false;

	new[num + 1] = NULL;

	return true;
}

static int inject_extended_dn(struct ldb_message *msg,
				struct ldb_context *ldb,
				int type,
				bool remove_guid,
				bool remove_sid)
{
	const struct ldb_val *val;
	struct GUID guid;
	struct dom_sid *sid;
	const DATA_BLOB *guid_blob;
	const DATA_BLOB *sid_blob;
	char *object_guid;
	char *object_sid;
	char *new_dn;

	guid_blob = ldb_msg_find_ldb_val(msg, "objectGUID");
	sid_blob = ldb_msg_find_ldb_val(msg, "objectSID");

	if (!guid_blob) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	switch (type) {
		case 0:
			/* return things in hexadecimal format */
			if (sid_blob) {
				const char *lower_guid_hex = strlower_talloc(msg, data_blob_hex_string(msg, guid_blob));
				const char *lower_sid_hex = strlower_talloc(msg, data_blob_hex_string(msg, sid_blob));
				if (!lower_guid_hex || !lower_sid_hex) {
					return LDB_ERR_OPERATIONS_ERROR;
				}
				new_dn = talloc_asprintf(msg, "<GUID=%s>;<SID=%s>;%s",
							 lower_guid_hex, 
							 lower_sid_hex,
							 ldb_dn_get_linearized(msg->dn));
			} else {
				const char *lower_guid_hex = strlower_talloc(msg, data_blob_hex_string(msg, guid_blob));
				if (!lower_guid_hex) {
					return LDB_ERR_OPERATIONS_ERROR;
				}
				new_dn = talloc_asprintf(msg, "<GUID=%s>;%s",
							 lower_guid_hex, 
							 ldb_dn_get_linearized(msg->dn));
			}

			break;
		case 1:
			/* retrieve object_guid */
			guid = samdb_result_guid(msg, "objectGUID");
			object_guid = GUID_string(msg, &guid);
			
			/* retrieve object_sid */
			object_sid = NULL;
			sid = samdb_result_dom_sid(msg, msg, "objectSID");
			if (sid) {
				object_sid = dom_sid_string(msg, sid);
				if (!object_sid)
					return LDB_ERR_OPERATIONS_ERROR;

			}
			
			/* Normal, sane format */
			if (object_sid) {
				new_dn = talloc_asprintf(msg, "<GUID=%s>;<SID=%s>;%s",
							 object_guid, object_sid,
							 ldb_dn_get_linearized(msg->dn));
			} else {
				new_dn = talloc_asprintf(msg, "<GUID=%s>;%s",
							 object_guid,
							 ldb_dn_get_linearized(msg->dn));
			}
			break;
		default:
			return LDB_ERR_OPERATIONS_ERROR;
	}

	if (!new_dn) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (remove_guid) {
		ldb_msg_remove_attr(msg, "objectGUID");
	}

	if (sid_blob && remove_sid) {
		ldb_msg_remove_attr(msg, "objectSID");
	}

	msg->dn = ldb_dn_new(msg, ldb, new_dn);
	if (! ldb_dn_validate(msg->dn))
		return LDB_ERR_OPERATIONS_ERROR;

	val = ldb_msg_find_ldb_val(msg, "distinguishedName");
	if (val) {
		ldb_msg_remove_attr(msg, "distinguishedName");
		if (ldb_msg_add_steal_string(msg, "distinguishedName", new_dn))
			return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

/* search */
struct extended_context {

	struct ldb_module *module;
	struct ldb_request *req;
	struct ldb_control *control;
	struct ldb_dn *basedn;
	char *wellknown_object;
	bool inject;
	bool remove_guid;
	bool remove_sid;
	int extended_type;
	const char * const *cast_attrs;
};

static int extended_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct extended_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct extended_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (ac->inject) {
			/* for each record returned post-process to add any derived
			   attributes that have been asked for */
			ret = inject_extended_dn(ares->message, ac->module->ldb,
						 ac->extended_type, ac->remove_guid,
						 ac->remove_sid);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		return ldb_module_send_entry(ac->req, ares->message);

	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(ac->req, ares->referral);

	case LDB_REPLY_DONE:
		return ldb_module_done(ac->req, ares->controls,
					ares->response, LDB_SUCCESS);

	}
	return LDB_SUCCESS;
}

static int extended_base_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct extended_context *ac;
	struct ldb_request *down_req;
	struct ldb_control **saved_controls;
	struct ldb_message_element *el;
	int ret;
	size_t i;
	size_t wkn_len = 0;
	char *valstr = NULL;
	const char *found = NULL;

	ac = talloc_get_type(req->context, struct extended_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (!ac->wellknown_object) {
			ac->basedn = ares->message->dn;
			break;
		}

		wkn_len = strlen(ac->wellknown_object);

		el = ldb_msg_find_element(ares->message, "wellKnownObjects");
		if (!el) {
			ac->basedn = NULL;
			break;
		}

		for (i=0; i < el->num_values; i++) {
			valstr = talloc_strndup(ac,
						(const char *)el->values[i].data,
						el->values[i].length);
			if (!valstr) {
				ldb_oom(ac->module->ldb);
				return ldb_module_done(ac->req, NULL, NULL,
						       LDB_ERR_OPERATIONS_ERROR);
			}

			if (strncasecmp(valstr, ac->wellknown_object, wkn_len) != 0) {
				talloc_free(valstr);
				continue;
			}

			found = &valstr[wkn_len];
			break;
		}

		if (!found) {
			break;
		}

		ac->basedn = ldb_dn_new(ac, ac->module->ldb, found);
		talloc_free(valstr);
		if (!ac->basedn) {
			ldb_oom(ac->module->ldb);
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_OPERATIONS_ERROR);
		}

		break;

	case LDB_REPLY_REFERRAL:
		break;

	case LDB_REPLY_DONE:

		if (!ac->basedn) {
			const char *str = talloc_asprintf(req, "Base-DN '%s' not found",
							  ldb_dn_get_linearized(ac->req->op.search.base));
			ldb_set_errstring(ac->module->ldb, str);
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_NO_SUCH_OBJECT);
		}

		ret = ldb_build_search_req_ex(&down_req,
						ac->module->ldb, ac,
						ac->basedn,
						ac->req->op.search.scope,
						ac->req->op.search.tree,
						ac->cast_attrs,
						ac->req->controls,
						ac, extended_callback,
						ac->req);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
		}

		if (ac->control) {
			/* save it locally and remove it from the list */
			/* we do not need to replace them later as we
			 * are keeping the original req intact */
			if (!save_controls(ac->control, down_req, &saved_controls)) {
				return ldb_module_done(ac->req, NULL, NULL,
							LDB_ERR_OPERATIONS_ERROR);
			}
		}

		/* perform the search */
		return ldb_next_request(ac->module, down_req);
	}
	return LDB_SUCCESS;
}

static int extended_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control;
	struct ldb_extended_dn_control *extended_ctrl = NULL;
	struct ldb_control **saved_controls;
	struct extended_context *ac;
	struct ldb_request *down_req;
	char **new_attrs;
	int ret;
	struct ldb_dn *base_dn = NULL;
	enum ldb_scope base_dn_scope = LDB_SCOPE_BASE;
	const char *base_dn_filter = NULL;
	const char * const *base_dn_attrs = NULL;
	char *wellknown_object = NULL;
	static const char *dnattr[] = {
		"distinguishedName",
		NULL
	};
	static const char *wkattr[] = {
		"wellKnownObjects",
		NULL
	};

	if (ldb_dn_is_special(req->op.search.base)) {
		char *dn;

		dn = ldb_dn_alloc_linearized(req, req->op.search.base);
		if (!dn) {
			ldb_oom(module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (strncasecmp(dn, "<SID=", 5) == 0) {
			char *str;
			char *valstr;
			char *p;

			p = strchr(dn, '=');
			if (!p) {
				return LDB_ERR_INVALID_DN_SYNTAX;
			}

			p[0] = '\0';
			p++;

			str = p;

			p = strchr(str, '>');
			if (!p) {
				return LDB_ERR_INVALID_DN_SYNTAX;
			}
			p[0] = '\0';

			if (strncasecmp(str, "S-", 2) == 0) {
				valstr = str;
			} else {
				DATA_BLOB binary;
				binary = strhex_to_data_blob(str);
				if (!binary.data) {
					ldb_oom(module->ldb);
					return LDB_ERR_OPERATIONS_ERROR;
				}
				valstr = ldb_binary_encode(req, binary);
				data_blob_free(&binary);
				if (!valstr) {
					ldb_oom(module->ldb);
					return LDB_ERR_OPERATIONS_ERROR;
				}
			}

			/* TODO: do a search over all partitions */
			base_dn = ldb_get_default_basedn(module->ldb);
			base_dn_filter = talloc_asprintf(req, "(objectSid=%s)", valstr);
			if (!base_dn_filter) {
				ldb_oom(module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			base_dn_scope = LDB_SCOPE_SUBTREE;
			base_dn_attrs = dnattr;
		} else if (strncasecmp(dn, "<GUID=", 6) == 0) {
			char *str;
			char *valstr;
			char *p;

			p = strchr(dn, '=');
			if (!p) {
				return LDB_ERR_INVALID_DN_SYNTAX;
			}

			p[0] = '\0';
			p++;

			str = p;

			p = strchr(str, '>');
			if (!p) {
				return LDB_ERR_INVALID_DN_SYNTAX;
			}
			p[0] = '\0';

			if (strchr(str, '-')) {
				valstr = str;
			} else {
				DATA_BLOB binary;
				binary = strhex_to_data_blob(str);
				if (!binary.data) {
					ldb_oom(module->ldb);
					return LDB_ERR_OPERATIONS_ERROR;
				}
				valstr = ldb_binary_encode(req, binary);
				data_blob_free(&binary);
				if (!valstr) {
					ldb_oom(module->ldb);
					return LDB_ERR_OPERATIONS_ERROR;
				}
			}

			/* TODO: do a search over all partitions */
			base_dn = ldb_get_default_basedn(module->ldb);
			base_dn_filter = talloc_asprintf(req, "(objectGUID=%s)", valstr);
			if (!base_dn_filter) {
				ldb_oom(module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			base_dn_scope = LDB_SCOPE_SUBTREE;
			base_dn_attrs = dnattr;
		} else if (strncasecmp(dn, "<WKGUID=", 8) == 0) {
			char *tail_str;
			char *p;

			p = strchr(dn, ',');
			if (!p) {
				return LDB_ERR_INVALID_DN_SYNTAX;
			}

			p[0] = '\0';
			p++;

			wellknown_object = talloc_asprintf(req, "B:32:%s:", &dn[8]);
			if (!wellknown_object) {
				ldb_oom(module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			tail_str = p;
			p = strchr(tail_str, '>');
			if (!p) {
				return LDB_ERR_INVALID_DN_SYNTAX;
			}
			p[0] = '\0';

			base_dn = ldb_dn_new(req, module->ldb, tail_str);
			if (!base_dn) {
				ldb_oom(module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			base_dn_filter = talloc_strdup(req, "(objectClass=*)");
			if (!base_dn_filter) {
				ldb_oom(module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			base_dn_scope = LDB_SCOPE_BASE;
			base_dn_attrs = wkattr;
		}
		talloc_free(dn);
	}

	/* check if there's an extended dn control */
	control = ldb_request_get_control(req, LDB_CONTROL_EXTENDED_DN_OID);
	if (control == NULL && base_dn_filter == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	if (control && control->data) {
		extended_ctrl = talloc_get_type(control->data, struct ldb_extended_dn_control);
		if (!extended_ctrl) {
			return LDB_ERR_PROTOCOL_ERROR;
		}
	}

	ac = talloc_zero(req, struct extended_context);
	if (ac == NULL) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;
	ac->control = control;
	ac->basedn = NULL;
	ac->wellknown_object = wellknown_object;
	ac->inject = false;
	ac->remove_guid = false;
	ac->remove_sid = false;

	if (control) {
		ac->inject = true;
		if (extended_ctrl) {
			ac->extended_type = extended_ctrl->type;
		} else {
			ac->extended_type = 0;
		}

		/* check if attrs only is specified, in that case check wether we need to modify them */
		if (req->op.search.attrs) {
			if (! is_attr_in_list(req->op.search.attrs, "objectGUID")) {
				ac->remove_guid = true;
			}
			if (! is_attr_in_list(req->op.search.attrs, "objectSID")) {
				ac->remove_sid = true;
			}
			if (ac->remove_guid || ac->remove_sid) {
				new_attrs = copy_attrs(ac, req->op.search.attrs);
				if (new_attrs == NULL) {
					ldb_oom(module->ldb);
					return LDB_ERR_OPERATIONS_ERROR;
				}

				if (ac->remove_guid) {
					if (!add_attrs(ac, &new_attrs, "objectGUID"))
						return LDB_ERR_OPERATIONS_ERROR;
				}
				if (ac->remove_sid) {
					if (!add_attrs(ac, &new_attrs, "objectSID"))
						return LDB_ERR_OPERATIONS_ERROR;
				}
				ac->cast_attrs = (const char * const *)new_attrs;
			} else {
				ac->cast_attrs = req->op.search.attrs;
			}
		}
	}

	if (base_dn) {
		ret = ldb_build_search_req(&down_req,
					   module->ldb, ac,
					   base_dn,
					   base_dn_scope,
					   base_dn_filter,
					   base_dn_attrs,
					   NULL,
					   ac, extended_base_callback,
					   req);
		if (ret != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* perform the search */
		return ldb_next_request(module, down_req);
	}

	ret = ldb_build_search_req_ex(&down_req,
					module->ldb, ac,
					req->op.search.base,
					req->op.search.scope,
					req->op.search.tree,
					ac->cast_attrs,
					req->controls,
					ac, extended_callback,
					req);
	if (ret != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ac->control) {
		/* save it locally and remove it from the list */
		/* we do not need to replace them later as we
		 * are keeping the original req intact */
		if (!save_controls(control, down_req, &saved_controls)) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/* perform the search */
	return ldb_next_request(module, down_req);
}

static int extended_init(struct ldb_module *module)
{
	int ret;

	ret = ldb_mod_register_control(module, LDB_CONTROL_EXTENDED_DN_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR,
			"extended_dn: Unable to register control with rootdse!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ldb_next_init(module);
}

_PUBLIC_ const struct ldb_module_ops ldb_extended_dn_module_ops = {
	.name		   = "extended_dn",
	.search            = extended_search,
	.init_context	   = extended_init
};
