/* 
   ldb database library

   Copyright (C) Simo Sorce 2005-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2007-2009

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
 *  Component: ldb extended dn control module
 *
 *  Description: this module builds a special dn for returned search
 *  results, and fixes some other aspects of the result (returned case issues)
 *  values.
 *
 *  Authors: Simo Sorce
 *           Andrew Bartlett
 */

#include "includes.h"
#include <ldb.h>
#include <ldb_errors.h>
#include <ldb_module.h>
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/ndr/libndr.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

struct extended_dn_out_private {
	bool dereference;
	bool normalise;
	const char **attrs;
};

static char **copy_attrs(void *mem_ctx, const char * const * attrs)
{
	char **nattrs;
	unsigned int i, num;

	for (num = 0; attrs[num]; num++);

	nattrs = talloc_array(mem_ctx, char *, num + 1);
	if (!nattrs) return NULL;

	for(i = 0; i < num; i++) {
		nattrs[i] = talloc_strdup(nattrs, attrs[i]);
		if (!nattrs[i]) {
			talloc_free(nattrs);
			return NULL;
		}
	}
	nattrs[i] = NULL;

	return nattrs;
}

static bool add_attrs(void *mem_ctx, char ***attrs, const char *attr)
{
	char **nattrs;
	unsigned int num;

	for (num = 0; (*attrs)[num]; num++);

	nattrs = talloc_realloc(mem_ctx, *attrs, char *, num + 2);
	if (!nattrs) return false;

	*attrs = nattrs;

	nattrs[num] = talloc_strdup(nattrs, attr);
	if (!nattrs[num]) return false;

	nattrs[num + 1] = NULL;

	return true;
}

/* Inject the extended DN components, so the DN cn=Adminstrator,cn=users,dc=samba,dc=example,dc=com becomes
   <GUID=541203ae-f7d6-47ef-8390-bfcf019f9583>;<SID=S-1-5-21-4177067393-1453636373-93818737-500>;cn=Adminstrator,cn=users,dc=samba,dc=example,dc=com */

static int inject_extended_dn_out(struct ldb_reply *ares,
				  struct ldb_context *ldb,
				  int type,
				  bool remove_guid,
				  bool remove_sid)
{
	int ret;
	const DATA_BLOB *guid_blob;
	const DATA_BLOB *sid_blob;

	guid_blob = ldb_msg_find_ldb_val(ares->message, "objectGUID");
	sid_blob = ldb_msg_find_ldb_val(ares->message, "objectSid");

	if (!guid_blob) {
		ldb_set_errstring(ldb, "Did not find objectGUID to inject into extended DN");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_dn_set_extended_component(ares->message->dn, "GUID", guid_blob);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (sid_blob) {
		ret = ldb_dn_set_extended_component(ares->message->dn, "SID", sid_blob);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (remove_guid) {
		ldb_msg_remove_attr(ares->message, "objectGUID");
	}

	if (sid_blob && remove_sid) {
		ldb_msg_remove_attr(ares->message, "objectSid");
	}

	return LDB_SUCCESS;
}

/* search */
struct extended_search_context {
	struct ldb_module *module;
	const struct dsdb_schema *schema;
	struct ldb_request *req;
	bool inject;
	bool remove_guid;
	bool remove_sid;
	int extended_type;
};


/*
   fix one-way links to have the right string DN, to cope with
   renames of the target
*/
static int fix_one_way_link(struct extended_search_context *ac, struct ldb_dn *dn,
			    bool is_deleted_objects, bool *remove_value,
			    uint32_t linkID)
{
	struct GUID guid;
	NTSTATUS status;
	int ret;
	struct ldb_dn *real_dn;
	uint32_t search_flags;
	TALLOC_CTX *tmp_ctx = talloc_new(ac);
	const char *attrs[] = { NULL };
	struct ldb_result *res;

	(*remove_value) = false;

	status = dsdb_get_extended_dn_guid(dn, &guid, "GUID");
	if (!NT_STATUS_IS_OK(status)) {
		/* this is a strange DN that doesn't have a GUID! just
		   return the current DN string?? */
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	search_flags = DSDB_FLAG_NEXT_MODULE | DSDB_SEARCH_SEARCH_ALL_PARTITIONS | DSDB_SEARCH_ONE_ONLY;

	if (linkID == 0) {
		/* You must ALWAYS show one-way links regardless of the state of the target */
		search_flags |= (DSDB_SEARCH_SHOW_DELETED | DSDB_SEARCH_SHOW_RECYCLED);
	}

	ret = dsdb_module_search(ac->module, tmp_ctx, &res, NULL, LDB_SCOPE_SUBTREE, attrs,
				 search_flags, ac->req, "objectguid=%s", GUID_string(tmp_ctx, &guid));
	if (ret != LDB_SUCCESS || res->count != 1) {
		/* if we can't resolve this GUID, then we don't
		   display the link. This could be a link to a NC that we don't
		   have, or it could be a link to a deleted object
		*/
		(*remove_value) = true;
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}
	real_dn = res->msgs[0]->dn;

	if (strcmp(ldb_dn_get_linearized(dn), ldb_dn_get_linearized(real_dn)) == 0) {
		/* its already correct */
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	/* fix the DN by replacing its components with those from the
	 * real DN
	 */
	if (!ldb_dn_replace_components(dn, real_dn)) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb_module_get_ctx(ac->module));
	}
	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}


/*
  this is called to post-process the results from the search
 */
static int extended_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct extended_search_context *ac;
	int ret;
	unsigned int i, j, k;
	struct ldb_message *msg;
	struct extended_dn_out_private *p;
	struct ldb_context *ldb;
	bool have_reveal_control=false;

	ac = talloc_get_type(req->context, struct extended_search_context);
	p = talloc_get_type(ldb_module_get_private(ac->module), struct extended_dn_out_private);
	ldb = ldb_module_get_ctx(ac->module);
	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	msg = ares->message;

	switch (ares->type) {
	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(ac->req, ares->referral);

	case LDB_REPLY_DONE:
		return ldb_module_done(ac->req, ares->controls,
					ares->response, LDB_SUCCESS);
	case LDB_REPLY_ENTRY:
		break;
	}

	if (p && p->normalise) {
		ret = dsdb_fix_dn_rdncase(ldb, ares->message->dn);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
	}
			
	if (ac->inject) {
		/* for each record returned post-process to add any derived
		   attributes that have been asked for */
		ret = inject_extended_dn_out(ares, ldb,
					     ac->extended_type, ac->remove_guid,
					     ac->remove_sid);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
	}

	if ((p && p->normalise) || ac->inject) {
		const struct ldb_val *val = ldb_msg_find_ldb_val(ares->message, "distinguishedName");
		if (val) {
			ldb_msg_remove_attr(ares->message, "distinguishedName");
			if (ac->inject) {
				ret = ldb_msg_add_steal_string(ares->message, "distinguishedName", 
							       ldb_dn_get_extended_linearized(ares->message, ares->message->dn, ac->extended_type));
			} else {
				ret = ldb_msg_add_linearized_dn(ares->message,
								"distinguishedName",
								ares->message->dn);
			}
			if (ret != LDB_SUCCESS) {
				return ldb_oom(ldb);
			}
		}
	}

	have_reveal_control =
		dsdb_request_has_control(req, LDB_CONTROL_REVEAL_INTERNALS);

	/* 
	 * Shortcut for repl_meta_data.  We asked for the data
	 * 'as-is', so stop processing here!
	 */
	if (have_reveal_control && p->normalise == false && ac->inject == true) {
		return ldb_module_send_entry(ac->req, msg, ares->controls);
	}
	
	/* Walk the returned elements (but only if we have a schema to
	 * interpret the list with) */
	for (i = 0; ac->schema && i < msg->num_elements; i++) {
		bool make_extended_dn;
		const struct dsdb_attribute *attribute;

		attribute = dsdb_attribute_by_lDAPDisplayName(ac->schema, msg->elements[i].name);
		if (!attribute) {
			continue;
		}

		if (p && p->normalise) {
			/* If we are also in 'normalise' mode, then
			 * fix the attribute names to be in the
			 * correct case */
			msg->elements[i].name = talloc_strdup(msg->elements, attribute->lDAPDisplayName);
			if (!msg->elements[i].name) {
				ldb_oom(ldb);
				return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
			}
		}

		/* distinguishedName has been dealt with above */
		if (ldb_attr_cmp(msg->elements[i].name, "distinguishedName") == 0) {
			continue;
		}

		/* Look to see if this attributeSyntax is a DN */
		if (attribute->dn_format == DSDB_INVALID_DN) {
			continue;
		}

		make_extended_dn = ac->inject;

		/* Always show plain DN in case of Object(OR-Name) syntax */
		if (make_extended_dn) {
			make_extended_dn = (strcmp(attribute->syntax->ldap_oid, DSDB_SYNTAX_OR_NAME) != 0);
		}

		for (k = 0, j = 0; j < msg->elements[i].num_values; j++) {
			const char *dn_str;
			struct ldb_dn *dn;
			struct dsdb_dn *dsdb_dn = NULL;
			struct ldb_val *plain_dn = &msg->elements[i].values[j];
			bool is_deleted_objects = false;

			/* this is a fast method for detecting deleted
			   linked attributes, working on the unparsed
			   ldb_val */
			if (dsdb_dn_is_deleted_val(plain_dn) && !have_reveal_control) {
				/* it's a deleted linked attribute,
				  and we don't have the reveal control */
				/* we won't keep this one, so not incrementing k */
				continue;
			}


			dsdb_dn = dsdb_dn_parse_trusted(msg, ldb, plain_dn, attribute->syntax->ldap_oid);

			if (!dsdb_dn) {
				ldb_asprintf_errstring(ldb,
						       "could not parse %.*s in %s on %s as a %s DN",
						       (int)plain_dn->length, plain_dn->data,
						       msg->elements[i].name, ldb_dn_get_linearized(msg->dn),
						       attribute->syntax->ldap_oid);
				talloc_free(dsdb_dn);
				return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_INVALID_DN_SYNTAX);
			}
			dn = dsdb_dn->dn;

			/* we need to know if this is a link to the
			   deleted objects container for fixing one way
			   links */
			if (dsdb_dn->extra_part.length == 16) {
				char *hex_string = data_blob_hex_string_upper(req, &dsdb_dn->extra_part);
				if (hex_string && strcmp(hex_string, DS_GUID_DELETED_OBJECTS_CONTAINER) == 0) {
					is_deleted_objects = true;
				}
				talloc_free(hex_string);
			}

			if (p->normalise) {
				ret = dsdb_fix_dn_rdncase(ldb, dn);
				if (ret != LDB_SUCCESS) {
					talloc_free(dsdb_dn);
					return ldb_module_done(ac->req, NULL, NULL, ret);
				}
			}

			/* Look for this value in the attribute */

			/* note that we don't fixup objectCategory as
			   it should not be possible to move
			   objectCategory elements in the schema */
			if (attribute->one_way_link &&
			    strcasecmp(attribute->lDAPDisplayName, "objectCategory") != 0) {
				bool remove_value;
				ret = fix_one_way_link(ac, dn, is_deleted_objects, &remove_value,
						       attribute->linkID);
				if (ret != LDB_SUCCESS) {
					talloc_free(dsdb_dn);
					return ldb_module_done(ac->req, NULL, NULL, ret);
				}
				if (remove_value &&
				    !ldb_request_get_control(req, LDB_CONTROL_REVEAL_INTERNALS)) {
					/* we show these with REVEAL
					   to allow dbcheck to find and
					   cleanup these orphaned links */
					/* we won't keep this one, so not incrementing k */
					continue;
				}
			}
			
			if (make_extended_dn) {
				if (!ldb_dn_validate(dsdb_dn->dn)) {
					ldb_asprintf_errstring(ldb, 
							       "could not parse %.*s in %s on %s as a %s DN", 
							       (int)plain_dn->length, plain_dn->data,
							       msg->elements[i].name, ldb_dn_get_linearized(msg->dn),
							       attribute->syntax->ldap_oid);
					talloc_free(dsdb_dn);
					return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_INVALID_DN_SYNTAX);
				}
				/* don't let users see the internal extended
				   GUID components */
				if (!have_reveal_control) {
					const char *accept[] = { "GUID", "SID", NULL };
					ldb_dn_extended_filter(dn, accept);
				}
				dn_str = dsdb_dn_get_extended_linearized(msg->elements[i].values,
									 dsdb_dn, ac->extended_type);
			} else {
				dn_str = dsdb_dn_get_linearized(msg->elements[i].values,
								dsdb_dn);
			}

			if (!dn_str) {
				ldb_oom(ldb);
				talloc_free(dsdb_dn);
				return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
			}
			msg->elements[i].values[k] = data_blob_string_const(dn_str);
			talloc_free(dsdb_dn);
			k++;
		}

		if (k == 0) {
			/* we've deleted all of the values from this
			 * element - remove the element */
			ldb_msg_remove_element(msg, &msg->elements[i]);
			i--;
		} else {
			msg->elements[i].num_values = k;
		}
	}
	return ldb_module_send_entry(ac->req, msg, ares->controls);
}

static int extended_callback_ldb(struct ldb_request *req, struct ldb_reply *ares)
{
	return extended_callback(req, ares);
}

static int extended_dn_out_search(struct ldb_module *module, struct ldb_request *req,
		int (*callback)(struct ldb_request *req, struct ldb_reply *ares))
{
	struct ldb_control *control;
	struct ldb_control *storage_format_control;
	struct ldb_extended_dn_control *extended_ctrl = NULL;
	struct extended_search_context *ac;
	struct ldb_request *down_req;
	char **new_attrs;
	const char * const *const_attrs;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret;

	struct extended_dn_out_private *p = talloc_get_type(ldb_module_get_private(module), struct extended_dn_out_private);

	/* The schema manipulation does not apply to special DNs */
	if (ldb_dn_is_special(req->op.search.base)) {
		return ldb_next_request(module, req);
	}

	/* check if there's an extended dn control */
	control = ldb_request_get_control(req, LDB_CONTROL_EXTENDED_DN_OID);
	if (control && control->data) {
		extended_ctrl = talloc_get_type(control->data, struct ldb_extended_dn_control);
		if (!extended_ctrl) {
			return LDB_ERR_PROTOCOL_ERROR;
		}
	}

	/* Look to see if, as we are in 'store DN+GUID+SID' mode, the
	 * client is after the storage format (to fill in linked
	 * attributes) */
	storage_format_control = ldb_request_get_control(req, DSDB_CONTROL_DN_STORAGE_FORMAT_OID);
	if (!control && storage_format_control && storage_format_control->data) {
		extended_ctrl = talloc_get_type(storage_format_control->data, struct ldb_extended_dn_control);
		if (!extended_ctrl) {
			ldb_set_errstring(ldb, "extended_dn_out: extended_ctrl was of the wrong data type");
			return LDB_ERR_PROTOCOL_ERROR;
		}
	}

	ac = talloc_zero(req, struct extended_search_context);
	if (ac == NULL) {
		return ldb_oom(ldb);
	}

	ac->module = module;
	ac->schema = dsdb_get_schema(ldb, ac);
	ac->req = req;
	ac->inject = false;
	ac->remove_guid = false;
	ac->remove_sid = false;
	
	const_attrs = req->op.search.attrs;

	/* We only need to do special processing if we were asked for
	 * the extended DN, or we are 'store DN+GUID+SID'
	 * (!dereference) mode.  (This is the normal mode for LDB on
	 * tdb). */
	if (control || (storage_format_control && p)) {
		ac->inject = true;
		if (extended_ctrl) {
			ac->extended_type = extended_ctrl->type;
		} else {
			ac->extended_type = 0;
		}

		/* check if attrs only is specified, in that case check whether we need to modify them */
		if (req->op.search.attrs && !is_attr_in_list(req->op.search.attrs, "*")) {
			if (! is_attr_in_list(req->op.search.attrs, "objectGUID")) {
				ac->remove_guid = true;
			}
			if (! is_attr_in_list(req->op.search.attrs, "objectSid")) {
				ac->remove_sid = true;
			}
			if (ac->remove_guid || ac->remove_sid) {
				new_attrs = copy_attrs(ac, req->op.search.attrs);
				if (new_attrs == NULL) {
					return ldb_oom(ldb);
				}

				if (ac->remove_guid) {
					if (!add_attrs(ac, &new_attrs, "objectGUID"))
						return ldb_operr(ldb);
				}
				if (ac->remove_sid) {
					if (!add_attrs(ac, &new_attrs, "objectSid"))
						return ldb_operr(ldb);
				}
				const_attrs = (const char * const *)new_attrs;
			}
		}
	}

	ret = ldb_build_search_req_ex(&down_req,
				      ldb, ac,
				      req->op.search.base,
				      req->op.search.scope,
				      req->op.search.tree,
				      const_attrs,
				      req->controls,
				      ac, callback,
				      req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* mark extended DN and storage format controls as done */
	if (control) {
		control->critical = 0;
	}

	if (storage_format_control) {
		storage_format_control->critical = 0;
	}

	/* perform the search */
	return ldb_next_request(module, down_req);
}

static int extended_dn_out_ldb_search(struct ldb_module *module, struct ldb_request *req)
{
	return extended_dn_out_search(module, req, extended_callback_ldb);
}

static int extended_dn_out_ldb_init(struct ldb_module *module)
{
	int ret;

	struct extended_dn_out_private *p = talloc(module, struct extended_dn_out_private);
	struct dsdb_extended_dn_store_format *dn_format;

	ldb_module_set_private(module, p);

	if (!p) {
		return ldb_oom(ldb_module_get_ctx(module));
	}

	dn_format = talloc(p, struct dsdb_extended_dn_store_format);
	if (!dn_format) {
		talloc_free(p);
		return ldb_oom(ldb_module_get_ctx(module));
	}

	dn_format->store_extended_dn_in_ldb = true;
	ret = ldb_set_opaque(ldb_module_get_ctx(module), DSDB_EXTENDED_DN_STORE_FORMAT_OPAQUE_NAME, dn_format);
	if (ret != LDB_SUCCESS) {
		talloc_free(p);
		return ret;
	}

	p->dereference = false;
	p->normalise = false;

	ret = ldb_mod_register_control(module, LDB_CONTROL_EXTENDED_DN_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb_module_get_ctx(module), LDB_DEBUG_ERROR,
			"extended_dn_out: Unable to register control with rootdse!\n");
		return ldb_operr(ldb_module_get_ctx(module));
	}

	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_extended_dn_out_ldb_module_ops = {
	.name		   = "extended_dn_out_ldb",
	.search            = extended_dn_out_ldb_search,
	.init_context	   = extended_dn_out_ldb_init,
};

/*
  initialise the module
 */
_PUBLIC_ int ldb_extended_dn_out_module_init(const char *version)
{
	int ret;
	LDB_MODULE_CHECK_VERSION(version);
	ret = ldb_register_module(&ldb_extended_dn_out_ldb_module_ops);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return LDB_SUCCESS;
}
