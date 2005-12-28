/* 
   Unix SMB/CIFS implementation.
   LDAP server SIMPLE LDB implementation
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "ldap_server/ldap_server.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "auth/auth.h"
#include "db_wrap.h"
#include "dsdb/samdb/samdb.h"

#define VALID_DN_SYNTAX(dn,i) do {\
	if (!(dn)) {\
		return NT_STATUS_NO_MEMORY;\
	} else if ((dn)->comp_num < (i)) {\
		result = LDAP_INVALID_DN_SYNTAX;\
		errstr = "Invalid DN (" #i " components needed for '" #dn "')";\
		goto reply;\
	}\
} while(0)


/*
  map an error code from ldb to ldap
*/
static int sldb_map_error(struct ldapsrv_partition *partition, int ldb_ret,
			  const char **errstr)
{
	struct ldb_context *samdb = talloc_get_type(partition->private, 
						    struct ldb_context);
	*errstr = ldb_errstring(samdb);

	/* its 1:1 for now */
	return ldb_ret;
}

/*
  connect to the sam database
*/
NTSTATUS sldb_Init(struct ldapsrv_partition *partition, struct ldapsrv_connection *conn) 
{
	TALLOC_CTX *mem_ctx = talloc_new(partition);
	struct ldb_context *ldb;
	const char *url;
	url = lp_parm_string(-1, "ldapsrv", "samdb");
	if (url) {

		ldb = ldb_wrap_connect(mem_ctx, url, conn->session_info, 
				       NULL, 0, NULL);
		if (ldb == NULL) {
			talloc_free(mem_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		talloc_steal(partition, ldb);
		partition->private = ldb;
		talloc_free(mem_ctx);
		return NT_STATUS_OK;
	}
	
	ldb = samdb_connect(mem_ctx, conn->session_info);
	if (ldb == NULL) {
		talloc_free(mem_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	talloc_steal(partition, ldb);
	partition->private = ldb;
	talloc_free(mem_ctx);
	return NT_STATUS_OK;
}

/*
  Re-connect to the ldb after a bind (this does not handle the bind
  itself, but just notes the change in credentials)
*/
NTSTATUS sldb_Bind(struct ldapsrv_partition *partition, struct ldapsrv_connection *conn) 
{
	struct ldb_context *samdb = partition->private;
	NTSTATUS status;
	status = sldb_Init(partition, conn);
	if (NT_STATUS_IS_OK(status)) {
		/* don't leak the old LDB */
		talloc_free(samdb);
	}
	return status;
}

static NTSTATUS sldb_Search(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
			    struct ldap_SearchRequest *r)
{
	void *local_ctx;
	struct ldb_dn *basedn;
	struct ldap_Result *done;
	struct ldap_SearchResEntry *ent;
	struct ldapsrv_reply *ent_r, *done_r;
	int result = LDAP_SUCCESS;
	struct ldb_context *samdb;
	struct ldb_result *res = NULL;
	int i, j, y, ret;
	int success_limit = 1;
	enum ldb_scope scope = LDB_SCOPE_DEFAULT;
	const char **attrs = NULL;
	const char *errstr = NULL;
	struct ldb_request lreq;

	local_ctx = talloc_named(call, 0, "sldb_Search local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = talloc_get_type(partition->private, struct ldb_context);

	basedn = ldb_dn_explode(local_ctx, r->basedn);
	VALID_DN_SYNTAX(basedn, 0);

	DEBUG(10, ("sldb_Search: basedn: [%s]\n", r->basedn));
	DEBUG(10, ("sldb_Search: filter: [%s]\n", ldb_filter_from_tree(call, r->tree)));

	switch (r->scope) {
		case LDAP_SEARCH_SCOPE_BASE:
			DEBUG(10,("sldb_Search: scope: [BASE]\n"));
			scope = LDB_SCOPE_BASE;
			success_limit = 0;
			break;
		case LDAP_SEARCH_SCOPE_SINGLE:
			DEBUG(10,("sldb_Search: scope: [ONE]\n"));
			scope = LDB_SCOPE_ONELEVEL;
			success_limit = 0;
			break;
		case LDAP_SEARCH_SCOPE_SUB:
			DEBUG(10,("sldb_Search: scope: [SUB]\n"));
			scope = LDB_SCOPE_SUBTREE;
			success_limit = 0;
			break;
	}

	if (r->num_attributes >= 1) {
		attrs = talloc_array(samdb, const char *, r->num_attributes+1);
		NT_STATUS_HAVE_NO_MEMORY(attrs);

		for (i=0; i < r->num_attributes; i++) {
			DEBUG(10,("sldb_Search: attrs: [%s]\n",r->attributes[i]));
			attrs[i] = r->attributes[i];
		}
		attrs[i] = NULL;
	}

	DEBUG(5,("ldb_request dn=%s filter=%s\n", 
		 r->basedn, ldb_filter_from_tree(call, r->tree)));

	ZERO_STRUCT(lreq);
	lreq.operation = LDB_REQ_SEARCH;
	lreq.op.search.base = basedn;
	lreq.op.search.scope = scope;
	lreq.op.search.tree = r->tree;
	lreq.op.search.attrs = attrs;

	ret = ldb_request(samdb, &lreq);

	res = talloc_steal(samdb, lreq.op.search.res);

	if (ret == LDB_SUCCESS) {
		for (i = 0; i < res->count; i++) {
			ent_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultEntry);
			NT_STATUS_HAVE_NO_MEMORY(ent_r);

			ent = &ent_r->msg->r.SearchResultEntry;
			ent->dn = ldb_dn_linearize(ent_r, res->msgs[i]->dn);
			ent->num_attributes = 0;
			ent->attributes = NULL;
			if (res->msgs[i]->num_elements == 0) {
				goto queue_reply;
			}
			ent->num_attributes = res->msgs[i]->num_elements;
			ent->attributes = talloc_array(ent_r, struct ldb_message_element, ent->num_attributes);
			NT_STATUS_HAVE_NO_MEMORY(ent->attributes);
			for (j=0; j < ent->num_attributes; j++) {
				ent->attributes[j].name = talloc_steal(ent->attributes, res->msgs[i]->elements[j].name);
				ent->attributes[j].num_values = 0;
				ent->attributes[j].values = NULL;
				if (r->attributesonly && (res->msgs[i]->elements[j].num_values == 0)) {
					continue;
				}
				ent->attributes[j].num_values = res->msgs[i]->elements[j].num_values;
				ent->attributes[j].values = talloc_array(ent->attributes,
								DATA_BLOB, ent->attributes[j].num_values);
				NT_STATUS_HAVE_NO_MEMORY(ent->attributes[j].values);
				for (y=0; y < ent->attributes[j].num_values; y++) {
					ent->attributes[j].values[y].length = res->msgs[i]->elements[j].values[y].length;
					ent->attributes[j].values[y].data = talloc_steal(ent->attributes[j].values,
										res->msgs[i]->elements[j].values[y].data);
				}
			}
queue_reply:
			ldapsrv_queue_reply(call, ent_r);
		}
	}

reply:
	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	NT_STATUS_HAVE_NO_MEMORY(done_r);

	if (ret == LDB_SUCCESS) {
		if (res->count >= success_limit) {
			DEBUG(10,("sldb_Search: results: [%d]\n", res->count));
			result = LDAP_SUCCESS;
			errstr = NULL;
		} else if (res->count == 0) {
			DEBUG(10,("sldb_Search: no results\n"));
			result = LDAP_NO_SUCH_OBJECT;
			errstr = ldb_errstring(samdb);
		}
	} else {
		DEBUG(10,("sldb_Search: error\n"));
		result = ret;
		errstr = ldb_errstring(samdb);
	}

	done = &done_r->msg->r.SearchResultDone;
	done->dn = NULL;
	done->resultcode = result;
	done->errormessage = (errstr?talloc_strdup(done_r, errstr):NULL);
	done->referral = NULL;

	talloc_free(local_ctx);

	ldapsrv_queue_reply(call, done_r);
	return NT_STATUS_OK;
}

static NTSTATUS sldb_Add(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
			 struct ldap_AddRequest *r)
{
	void *local_ctx;
	struct ldb_dn *dn;
	struct ldap_Result *add_result;
	struct ldapsrv_reply *add_reply;
	int ldb_ret;
	struct ldb_context *samdb;
	struct ldb_message *msg = NULL;
	int result = LDAP_SUCCESS;
	const char *errstr = NULL;
	int i,j;

	local_ctx = talloc_named(call, 0, "sldb_Add local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = talloc_get_type(partition->private, struct ldb_context);

	dn = ldb_dn_explode(local_ctx, r->dn);
	VALID_DN_SYNTAX(dn,1);

	DEBUG(10, ("sldb_add: dn: [%s]\n", r->dn));

	msg = talloc(local_ctx, struct ldb_message);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	msg->dn = dn;
	msg->private_data = NULL;
	msg->num_elements = 0;
	msg->elements = NULL;

	if (r->num_attributes > 0) {
		msg->num_elements = r->num_attributes;
		msg->elements = talloc_array(msg, struct ldb_message_element, msg->num_elements);
		NT_STATUS_HAVE_NO_MEMORY(msg->elements);

		for (i=0; i < msg->num_elements; i++) {
			msg->elements[i].name = discard_const_p(char, r->attributes[i].name);
			msg->elements[i].flags = 0;
			msg->elements[i].num_values = 0;
			msg->elements[i].values = NULL;
			
			if (r->attributes[i].num_values > 0) {
				msg->elements[i].num_values = r->attributes[i].num_values;
				msg->elements[i].values = talloc_array(msg, struct ldb_val, msg->elements[i].num_values);
				NT_STATUS_HAVE_NO_MEMORY(msg->elements[i].values);

				for (j=0; j < msg->elements[i].num_values; j++) {
					if (!(r->attributes[i].values[j].length > 0)) {
						result = LDAP_OTHER;
						errstr = "Empty attribute values are not allowed";
						goto reply;
					}
					msg->elements[i].values[j].length = r->attributes[i].values[j].length;
					msg->elements[i].values[j].data = r->attributes[i].values[j].data;			
				}
			} else {
				result = LDAP_OTHER;
				errstr = "No attribute values are not allowed";
				goto reply;
			}
		}
	} else {
		result = LDAP_OTHER;
		errstr = "No attributes are not allowed";
		goto reply;
	}

reply:
	add_reply = ldapsrv_init_reply(call, LDAP_TAG_AddResponse);
	NT_STATUS_HAVE_NO_MEMORY(add_reply);

	if (result == LDAP_SUCCESS) {
		ldb_ret = ldb_add(samdb, msg);
		result = sldb_map_error(partition, ldb_ret, &errstr);
	}

	add_result = &add_reply->msg->r.AddResponse;
	add_result->dn = NULL;
	add_result->resultcode = result;
	add_result->errormessage = (errstr?talloc_strdup(add_reply,errstr):NULL);
	add_result->referral = NULL;

	talloc_free(local_ctx);

	ldapsrv_queue_reply(call, add_reply);
	return NT_STATUS_OK;
}

static NTSTATUS sldb_Del(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_DelRequest *r)
{
	void *local_ctx;
	struct ldb_dn *dn;
	struct ldap_Result *del_result;
	struct ldapsrv_reply *del_reply;
	int ldb_ret;
	struct ldb_context *samdb;
	const char *errstr = NULL;
	int result = LDAP_SUCCESS;

	local_ctx = talloc_named(call, 0, "sldb_Del local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = talloc_get_type(partition->private, struct ldb_context);

	dn = ldb_dn_explode(local_ctx, r->dn);
	VALID_DN_SYNTAX(dn,1);

	DEBUG(10, ("sldb_Del: dn: [%s]\n", r->dn));

reply:
	del_reply = ldapsrv_init_reply(call, LDAP_TAG_DelResponse);
	NT_STATUS_HAVE_NO_MEMORY(del_reply);

	if (result == LDAP_SUCCESS) {
		ldb_ret = ldb_delete(samdb, dn);
		result = sldb_map_error(partition, ldb_ret, &errstr);
	}

	del_result = &del_reply->msg->r.DelResponse;
	del_result->dn = NULL;
	del_result->resultcode = result;
	del_result->errormessage = (errstr?talloc_strdup(del_reply,errstr):NULL);
	del_result->referral = NULL;

	talloc_free(local_ctx);

	ldapsrv_queue_reply(call, del_reply);
	return NT_STATUS_OK;
}

static NTSTATUS sldb_Modify(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_ModifyRequest *r)
{
	void *local_ctx;
	struct ldb_dn *dn;
	struct ldap_Result *modify_result;
	struct ldapsrv_reply *modify_reply;
	int ldb_ret;
	struct ldb_context *samdb;
	struct ldb_message *msg = NULL;
	int result = LDAP_SUCCESS;
	const char *errstr = NULL;
	int i,j;

	local_ctx = talloc_named(call, 0, "sldb_Modify local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = talloc_get_type(partition->private, struct ldb_context);

	dn = ldb_dn_explode(local_ctx, r->dn);
	VALID_DN_SYNTAX(dn, 1);

	DEBUG(10, ("sldb_modify: dn: [%s]\n", r->dn));

	msg = talloc(local_ctx, struct ldb_message);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	msg->dn = dn;
	msg->private_data = NULL;
	msg->num_elements = 0;
	msg->elements = NULL;

	if (r->num_mods > 0) {
		msg->num_elements = r->num_mods;
		msg->elements = talloc_array(msg, struct ldb_message_element, r->num_mods);
		NT_STATUS_HAVE_NO_MEMORY(msg->elements);

		for (i=0; i < msg->num_elements; i++) {
			msg->elements[i].name = discard_const_p(char, r->mods[i].attrib.name);
			msg->elements[i].num_values = 0;
			msg->elements[i].values = NULL;

			switch (r->mods[i].type) {
			default:
				result = LDAP_PROTOCOL_ERROR;
				errstr = "Invalid LDAP_MODIFY_* type";
				goto reply;
			case LDAP_MODIFY_ADD:
				msg->elements[i].flags = LDB_FLAG_MOD_ADD;
				break;
			case LDAP_MODIFY_DELETE:
				msg->elements[i].flags = LDB_FLAG_MOD_DELETE;
				break;
			case LDAP_MODIFY_REPLACE:
				msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
				break;
			}

			msg->elements[i].num_values = r->mods[i].attrib.num_values;
			if (msg->elements[i].num_values > 0) {
				msg->elements[i].values = talloc_array(msg, struct ldb_val, msg->elements[i].num_values);
				NT_STATUS_HAVE_NO_MEMORY(msg->elements[i].values);

				for (j=0; j < msg->elements[i].num_values; j++) {
					if (!(r->mods[i].attrib.values[j].length > 0)) {
						result = LDAP_OTHER;
						errstr = "Empty attribute values are not allowed";
						goto reply;
					}
					msg->elements[i].values[j].length = r->mods[i].attrib.values[j].length;
					msg->elements[i].values[j].data = r->mods[i].attrib.values[j].data;			
				}
			}
		}
	} else {
		result = LDAP_OTHER;
		errstr = "No mods are not allowed";
		goto reply;
	}

reply:
	modify_reply = ldapsrv_init_reply(call, LDAP_TAG_ModifyResponse);
	NT_STATUS_HAVE_NO_MEMORY(modify_reply);

	if (result == LDAP_SUCCESS) {
		ldb_ret = ldb_modify(samdb, msg);
		result = sldb_map_error(partition, ldb_ret, &errstr);
	}

	modify_result = &modify_reply->msg->r.AddResponse;
	modify_result->dn = NULL;
	modify_result->resultcode = result;
	modify_result->errormessage = (errstr?talloc_strdup(modify_reply,errstr):NULL);
	modify_result->referral = NULL;

	talloc_free(local_ctx);

	ldapsrv_queue_reply(call, modify_reply);
	return NT_STATUS_OK;
}

static NTSTATUS sldb_Compare(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_CompareRequest *r)
{
	void *local_ctx;
	struct ldb_dn *dn;
	struct ldap_Result *compare;
	struct ldapsrv_reply *compare_r;
	int result = LDAP_SUCCESS;
	struct ldb_context *samdb;
	struct ldb_result *res = NULL;
	const char *attrs[1];
	const char *errstr = NULL;
	const char *filter = NULL;
	int ret;

	local_ctx = talloc_named(call, 0, "sldb_Compare local_memory_context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = talloc_get_type(partition->private, struct ldb_context);

	dn = ldb_dn_explode(local_ctx, r->dn);
	VALID_DN_SYNTAX(dn, 1);

	DEBUG(10, ("sldb_Compare: dn: [%s]\n", r->dn));
	filter = talloc_asprintf(local_ctx, "(%s=%*s)", r->attribute, 
				 (int)r->value.length, r->value.data);
	NT_STATUS_HAVE_NO_MEMORY(filter);

	DEBUGADD(10, ("sldb_Compare: attribute: [%s]\n", filter));

	attrs[0] = NULL;

reply:
	compare_r = ldapsrv_init_reply(call, LDAP_TAG_CompareResponse);
	NT_STATUS_HAVE_NO_MEMORY(compare_r);

	if (result == LDAP_SUCCESS) {
		ret = ldb_search(samdb, dn, LDB_SCOPE_BASE, filter, attrs, &res);
		talloc_steal(samdb, res);
		if (ret != LDB_SUCCESS) {
			result = LDAP_OTHER;
			errstr = ldb_errstring(samdb);
			DEBUG(10,("sldb_Compare: error: %s\n", errstr));
		} else if (res->count == 0) {
			DEBUG(10,("sldb_Compare: doesn't matched\n"));
			result = LDAP_COMPARE_FALSE;
			errstr = NULL;
		} else if (res->count == 1) {
			DEBUG(10,("sldb_Compare: matched\n"));
			result = LDAP_COMPARE_TRUE;
			errstr = NULL;
		} else if (res->count > 1) {
			result = LDAP_OTHER;
			errstr = "too many objects match";
			DEBUG(10,("sldb_Compare: %d results: %s\n", res->count, errstr));
		}
	}

	compare = &compare_r->msg->r.CompareResponse;
	compare->dn = NULL;
	compare->resultcode = result;
	compare->errormessage = (errstr?talloc_strdup(compare_r,errstr):NULL);
	compare->referral = NULL;

	talloc_free(local_ctx);

	ldapsrv_queue_reply(call, compare_r);
	return NT_STATUS_OK;
}

static NTSTATUS sldb_ModifyDN(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_ModifyDNRequest *r)
{
	void *local_ctx;
	struct ldb_dn *olddn, *newdn, *newrdn;
	struct ldb_dn *parentdn = NULL;
	struct ldap_Result *modifydn;
	struct ldapsrv_reply *modifydn_r;
	int ldb_ret;
	struct ldb_context *samdb;
	const char *errstr = NULL;
	int result = LDAP_SUCCESS;

	local_ctx = talloc_named(call, 0, "sldb_ModifyDN local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = talloc_get_type(partition->private, struct ldb_context);

	olddn = ldb_dn_explode(local_ctx, r->dn);
	VALID_DN_SYNTAX(olddn, 2);

	newrdn = ldb_dn_explode(local_ctx, r->newrdn);
	VALID_DN_SYNTAX(newrdn, 1);

	DEBUG(10, ("sldb_ModifyDN: olddn: [%s]\n", r->dn));
	DEBUG(10, ("sldb_ModifyDN: newrdn: [%s]\n", r->newrdn));

	/* we can't handle the rename if we should not remove the old dn */
	if (!r->deleteolddn) {
		result = LDAP_UNWILLING_TO_PERFORM;
		errstr = "Old RDN must be deleted";
		goto reply;
	}

	if (newrdn->comp_num > 1) {
		result = LDAP_NAMING_VIOLATION;
		errstr = "Error new RDN invalid";
		goto reply;
	}

	if (r->newsuperior) {
		parentdn = ldb_dn_explode(local_ctx, r->newsuperior);
		VALID_DN_SYNTAX(parentdn, 0);
		DEBUG(10, ("sldb_ModifyDN: newsuperior: [%s]\n", r->newsuperior));
		
		if (parentdn->comp_num < 1) {
			result = LDAP_AFFECTS_MULTIPLE_DSAS;
			errstr = "Error new Superior DN invalid";
			goto reply;
		}
	}

	if (!parentdn) {
		parentdn = ldb_dn_get_parent(local_ctx, olddn);
		NT_STATUS_HAVE_NO_MEMORY(parentdn);
	}

	newdn = ldb_dn_make_child(local_ctx, ldb_dn_get_rdn(local_ctx, newrdn), parentdn);
	NT_STATUS_HAVE_NO_MEMORY(newdn);

reply:
	modifydn_r = ldapsrv_init_reply(call, LDAP_TAG_ModifyDNResponse);
	NT_STATUS_HAVE_NO_MEMORY(modifydn_r);

	if (result == LDAP_SUCCESS) {
		ldb_ret = ldb_rename(samdb, olddn, newdn);
		result = sldb_map_error(partition, ldb_ret, &errstr);
	}

	modifydn = &modifydn_r->msg->r.ModifyDNResponse;
	modifydn->dn = NULL;
	modifydn->resultcode = result;
	modifydn->errormessage = (errstr?talloc_strdup(modifydn_r,errstr):NULL);
	modifydn->referral = NULL;

	talloc_free(local_ctx);

	ldapsrv_queue_reply(call, modifydn_r);
	return NT_STATUS_OK;
}

static const struct ldapsrv_partition_ops sldb_ops = {
	.Init           = sldb_Init,
	.Bind           = sldb_Bind,
	.Search		= sldb_Search,
	.Add		= sldb_Add,
	.Del		= sldb_Del,
	.Modify		= sldb_Modify,
	.Compare	= sldb_Compare,
	.ModifyDN	= sldb_ModifyDN
};

const struct ldapsrv_partition_ops *ldapsrv_get_sldb_partition_ops(void)
{
	return &sldb_ops;
}
