/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Stefan Metzmacher 2004
   
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
#include "lib/util/dlinklist.h"
#include "libcli/ldap/ldap.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/db_wrap.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"

#define VALID_DN_SYNTAX(dn,i) do {\
	if (!(dn)) {\
		return NT_STATUS_NO_MEMORY;\
	} else if (ldb_dn_get_comp_num(dn) < (i)) {\
		result = LDAP_INVALID_DN_SYNTAX;\
		errstr = "Invalid DN (" #i " components needed for '" #dn "')";\
		goto reply;\
	}\
} while(0)

static int map_ldb_error(struct ldb_context *ldb, int err, const char **errstring)
{
	*errstring = ldb_errstring(ldb);
	
	/* its 1:1 for now */
	return err;
}

/*
  connect to the sam database
*/
NTSTATUS ldapsrv_backend_Init(struct ldapsrv_connection *conn) 
{
	conn->ldb = ldb_wrap_connect(conn, lp_sam_url(), conn->session_info,
				     NULL, conn->global_catalog ? LDB_FLG_RDONLY : 0, NULL);
	if (conn->ldb == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (conn->server_credentials) {
		char **sasl_mechs = NULL;
		struct gensec_security_ops **backends = gensec_security_all();
		enum credentials_use_kerberos use_kerberos
			= cli_credentials_get_kerberos_state(conn->server_credentials);
		struct gensec_security_ops **ops
			= gensec_use_kerberos_mechs(conn, backends, use_kerberos);
		int i, j = 0;
		for (i = 0; ops && ops[i]; i++) {
			if (ops[i]->sasl_name && ops[i]->server_start) {
				char *sasl_name = talloc_strdup(conn, ops[i]->sasl_name);

				if (!sasl_name) {
					return NT_STATUS_NO_MEMORY;
				}
				sasl_mechs = talloc_realloc(conn, sasl_mechs, char *, j + 2);
				if (!sasl_mechs) {
					return NT_STATUS_NO_MEMORY;
				}
				sasl_mechs[j] = sasl_name;
				talloc_steal(sasl_mechs, sasl_name);
				sasl_mechs[j+1] = NULL;
				j++;
			}
		}
		talloc_free(ops);
		ldb_set_opaque(conn->ldb, "supportedSASLMechanims", sasl_mechs);
	}

	if (conn->global_catalog) {
		ldb_set_opaque(conn->ldb, "global_catalog", (void *)(-1));
	}

	return NT_STATUS_OK;
}

struct ldapsrv_reply *ldapsrv_init_reply(struct ldapsrv_call *call, uint8_t type)
{
	struct ldapsrv_reply *reply;

	reply = talloc(call, struct ldapsrv_reply);
	if (!reply) {
		return NULL;
	}
	reply->msg = talloc(reply, struct ldap_message);
	if (reply->msg == NULL) {
		talloc_free(reply);
		return NULL;
	}

	reply->msg->messageid = call->request->messageid;
	reply->msg->type = type;
	reply->msg->controls = NULL;

	return reply;
}

void ldapsrv_queue_reply(struct ldapsrv_call *call, struct ldapsrv_reply *reply)
{
	DLIST_ADD_END(call->replies, reply, struct ldapsrv_reply *);
}

NTSTATUS ldapsrv_unwilling(struct ldapsrv_call *call, int error)
{
	struct ldapsrv_reply *reply;
	struct ldap_ExtendedResponse *r;

	DEBUG(10,("Unwilling type[%d] id[%d]\n", call->request->type, call->request->messageid));

	reply = ldapsrv_init_reply(call, LDAP_TAG_ExtendedResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}

	r = &reply->msg->r.ExtendedResponse;
	r->response.resultcode = error;
	r->response.dn = NULL;
	r->response.errormessage = NULL;
	r->response.referral = NULL;
	r->oid = NULL;
	r->value = NULL;

	ldapsrv_queue_reply(call, reply);
	return NT_STATUS_OK;
}

static int ldapsrv_SearchCallback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct ldb_result *res;
	int n;
	
 	if (!context || !ares) {
		DEBUG(3, ("NULL Context or Ares in ldapsrv_SearchCallback"));
		return LDB_ERR_OPERATIONS_ERROR;
	}	

	res = talloc_get_type(context, struct ldb_result);

	if (ares->type == LDB_REPLY_ENTRY) {
		res->msgs = talloc_realloc(res, res->msgs, struct ldb_message *, res->count + 2);
		if (! res->msgs) {
			goto error;
		}

		res->msgs[res->count + 1] = NULL;

		res->msgs[res->count] = talloc_steal(res->msgs, ares->message);
		if (! res->msgs[res->count]) {
			goto error;
		}

		res->count++;
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		if (res->refs) {
			for (n = 0; res->refs[n]; n++) /*noop*/ ;
		} else {
			n = 0;
		}

		res->refs = talloc_realloc(res, res->refs, char *, n + 2);
		if (! res->refs) {
			goto error;
		}

		res->refs[n] = talloc_steal(res->refs, ares->referral);
		res->refs[n + 1] = NULL;
	}

	if (ares->controls) {
		res->controls = talloc_steal(res, ares->controls);
		if (! res->controls) {
			goto error;
		}
	}

	talloc_free(ares);
	return LDB_SUCCESS;

error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static NTSTATUS ldapsrv_SearchRequest(struct ldapsrv_call *call)
{
	struct ldap_SearchRequest *req = &call->request->r.SearchRequest;
	struct ldap_SearchResEntry *ent;
	struct ldap_Result *done;
	struct ldapsrv_reply *ent_r, *done_r;
	void *local_ctx;
	struct ldb_context *samdb = talloc_get_type(call->conn->ldb, struct ldb_context);
	struct ldb_dn *basedn;
	struct ldb_result *res = NULL;
	struct ldb_request *lreq;
	enum ldb_scope scope = LDB_SCOPE_DEFAULT;
	const char **attrs = NULL;
	const char *errstr = NULL;
	int success_limit = 1;
	int result = -1;
	int ldb_ret = -1;
	int i, j;

	DEBUG(10, ("SearchRequest"));
	DEBUGADD(10, (" basedn: %s", req->basedn));
	DEBUGADD(10, (" filter: %s\n", ldb_filter_from_tree(call, req->tree)));

	local_ctx = talloc_new(call);
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	basedn = ldb_dn_explode(local_ctx, req->basedn);
	VALID_DN_SYNTAX(basedn, 0);

	DEBUG(10, ("SearchRequest: basedn: [%s]\n", req->basedn));
	DEBUG(10, ("SearchRequest: filter: [%s]\n", ldb_filter_from_tree(call, req->tree)));

	switch (req->scope) {
		case LDAP_SEARCH_SCOPE_BASE:
			DEBUG(10,("SearchRequest: scope: [BASE]\n"));
			scope = LDB_SCOPE_BASE;
			success_limit = 0;
			break;
		case LDAP_SEARCH_SCOPE_SINGLE:
			DEBUG(10,("SearchRequest: scope: [ONE]\n"));
			scope = LDB_SCOPE_ONELEVEL;
			success_limit = 0;
			break;
		case LDAP_SEARCH_SCOPE_SUB:
			DEBUG(10,("SearchRequest: scope: [SUB]\n"));
			scope = LDB_SCOPE_SUBTREE;
			success_limit = 0;
			break;
	        default:
			result = LDAP_PROTOCOL_ERROR;
			errstr = "Invalid scope";
			break;
	}

	if (req->num_attributes >= 1) {
		attrs = talloc_array(samdb, const char *, req->num_attributes+1);
		NT_STATUS_HAVE_NO_MEMORY(attrs);

		for (i=0; i < req->num_attributes; i++) {
			DEBUG(10,("SearchRequest: attrs: [%s]\n",req->attributes[i]));
			attrs[i] = req->attributes[i];
		}
		attrs[i] = NULL;
	}

	DEBUG(5,("ldb_request dn=%s filter=%s\n", 
		 req->basedn, ldb_filter_from_tree(call, req->tree)));

	lreq = talloc(local_ctx, struct ldb_request);
	NT_STATUS_HAVE_NO_MEMORY(lreq);

	res = talloc_zero(local_ctx, struct ldb_result);
	NT_STATUS_HAVE_NO_MEMORY(res);
	
	lreq->operation = LDB_SEARCH;
	lreq->op.search.base = basedn;
	lreq->op.search.scope = scope;
	lreq->op.search.tree = req->tree;
	lreq->op.search.attrs = attrs;

	lreq->controls = call->request->controls;

	lreq->context = res;
	lreq->callback = ldapsrv_SearchCallback;

	/* Copy the timeout from the incoming call */
	ldb_set_timeout(samdb, lreq, req->timelimit);

	ldb_ret = ldb_request(samdb, lreq);

	if (ldb_ret != LDB_SUCCESS) {
		goto reply;
	}

	ldb_ret = ldb_wait(lreq->handle, LDB_WAIT_ALL);

	if (ldb_ret == LDB_SUCCESS) {
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
				if (req->attributesonly && (res->msgs[i]->elements[j].num_values == 0)) {
					continue;
				}
				ent->attributes[j].num_values = res->msgs[i]->elements[j].num_values;
				ent->attributes[j].values = res->msgs[i]->elements[j].values;
				talloc_steal(ent->attributes, res->msgs[i]->elements[j].values);
			}
queue_reply:
			ldapsrv_queue_reply(call, ent_r);
		}
	}

reply:
	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	NT_STATUS_HAVE_NO_MEMORY(done_r);

	done = &done_r->msg->r.SearchResultDone;
	done->dn = NULL;
	done->referral = NULL;

	if (result != -1) {
	} else if (ldb_ret == LDB_SUCCESS) {
		if (res->count >= success_limit) {
			DEBUG(10,("SearchRequest: results: [%d]\n", res->count));
			result = LDAP_SUCCESS;
			errstr = NULL;
		} else if (res->count == 0) {
			DEBUG(10,("SearchRequest: no results\n"));
			result = LDAP_NO_SUCH_OBJECT;
			errstr = ldb_errstring(samdb);
		}
		if (res->controls) {
			done_r->msg->controls = res->controls;
			talloc_steal(done_r, res->controls);
		}
	} else {
		DEBUG(10,("SearchRequest: error\n"));
		result = map_ldb_error(samdb, ldb_ret, &errstr);
	}

	done->resultcode = result;
	done->errormessage = (errstr?talloc_strdup(done_r, errstr):NULL);

	talloc_free(local_ctx);

	ldapsrv_queue_reply(call, done_r);
	return NT_STATUS_OK;
}

static NTSTATUS ldapsrv_ModifyRequest(struct ldapsrv_call *call)
{
	struct ldap_ModifyRequest *req = &call->request->r.ModifyRequest;
	struct ldap_Result *modify_result;
	struct ldapsrv_reply *modify_reply;
	void *local_ctx;
	struct ldb_context *samdb = call->conn->ldb;
	struct ldb_message *msg = NULL;
	struct ldb_dn *dn;
	const char *errstr = NULL;
	int result = LDAP_SUCCESS;
	int ldb_ret;
	int i,j;

	DEBUG(10, ("ModifyRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	local_ctx = talloc_named(call, 0, "ModifyRequest local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	dn = ldb_dn_explode(local_ctx, req->dn);
	VALID_DN_SYNTAX(dn, 1);

	DEBUG(10, ("ModifyRequest: dn: [%s]\n", req->dn));

	msg = talloc(local_ctx, struct ldb_message);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	msg->dn = dn;
	msg->private_data = NULL;
	msg->num_elements = 0;
	msg->elements = NULL;

	if (req->num_mods > 0) {
		msg->num_elements = req->num_mods;
		msg->elements = talloc_array(msg, struct ldb_message_element, req->num_mods);
		NT_STATUS_HAVE_NO_MEMORY(msg->elements);

		for (i=0; i < msg->num_elements; i++) {
			msg->elements[i].name = discard_const_p(char, req->mods[i].attrib.name);
			msg->elements[i].num_values = 0;
			msg->elements[i].values = NULL;

			switch (req->mods[i].type) {
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

			msg->elements[i].num_values = req->mods[i].attrib.num_values;
			if (msg->elements[i].num_values > 0) {
				msg->elements[i].values = talloc_array(msg, struct ldb_val, msg->elements[i].num_values);
				NT_STATUS_HAVE_NO_MEMORY(msg->elements[i].values);

				for (j=0; j < msg->elements[i].num_values; j++) {
					if (!(req->mods[i].attrib.values[j].length > 0)) {
						result = LDAP_OTHER;
						errstr = "Empty attribute values are not allowed";
						goto reply;
					}
					msg->elements[i].values[j].length = req->mods[i].attrib.values[j].length;
					msg->elements[i].values[j].data = req->mods[i].attrib.values[j].data;			
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
		result = map_ldb_error(samdb, ldb_ret, &errstr);
	}

	modify_result = &modify_reply->msg->r.AddResponse;
	modify_result->dn = NULL;
	modify_result->resultcode = result;
	modify_result->errormessage = (errstr?talloc_strdup(modify_reply, errstr):NULL);
	modify_result->referral = NULL;

	talloc_free(local_ctx);

	ldapsrv_queue_reply(call, modify_reply);
	return NT_STATUS_OK;

}

static NTSTATUS ldapsrv_AddRequest(struct ldapsrv_call *call)
{
	struct ldap_AddRequest *req = &call->request->r.AddRequest;
	struct ldap_Result *add_result;
	struct ldapsrv_reply *add_reply;
	void *local_ctx;
	struct ldb_context *samdb = call->conn->ldb;
	struct ldb_message *msg = NULL;
	struct ldb_dn *dn;
	const char *errstr = NULL;
	int result = LDAP_SUCCESS;
	int ldb_ret;
	int i,j;

	DEBUG(10, ("AddRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	local_ctx = talloc_named(call, 0, "AddRequest local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	dn = ldb_dn_explode(local_ctx, req->dn);
	VALID_DN_SYNTAX(dn,1);

	DEBUG(10, ("AddRequest: dn: [%s]\n", req->dn));

	msg = talloc(local_ctx, struct ldb_message);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	msg->dn = dn;
	msg->private_data = NULL;
	msg->num_elements = 0;
	msg->elements = NULL;

	if (req->num_attributes > 0) {
		msg->num_elements = req->num_attributes;
		msg->elements = talloc_array(msg, struct ldb_message_element, msg->num_elements);
		NT_STATUS_HAVE_NO_MEMORY(msg->elements);

		for (i=0; i < msg->num_elements; i++) {
			msg->elements[i].name = discard_const_p(char, req->attributes[i].name);
			msg->elements[i].flags = 0;
			msg->elements[i].num_values = 0;
			msg->elements[i].values = NULL;
			
			if (req->attributes[i].num_values > 0) {
				msg->elements[i].num_values = req->attributes[i].num_values;
				msg->elements[i].values = talloc_array(msg, struct ldb_val, msg->elements[i].num_values);
				NT_STATUS_HAVE_NO_MEMORY(msg->elements[i].values);

				for (j=0; j < msg->elements[i].num_values; j++) {
					if (!(req->attributes[i].values[j].length > 0)) {
						result = LDAP_OTHER;
						errstr = "Empty attribute values are not allowed";
						goto reply;
					}
					msg->elements[i].values[j].length = req->attributes[i].values[j].length;
					msg->elements[i].values[j].data = req->attributes[i].values[j].data;			
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
		result = map_ldb_error(samdb, ldb_ret, &errstr);
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

static NTSTATUS ldapsrv_DelRequest(struct ldapsrv_call *call)
{
	struct ldap_DelRequest *req = &call->request->r.DelRequest;
	struct ldap_Result *del_result;
	struct ldapsrv_reply *del_reply;
	void *local_ctx;
	struct ldb_context *samdb = call->conn->ldb;
	struct ldb_dn *dn;
	const char *errstr = NULL;
	int result = LDAP_SUCCESS;
	int ldb_ret;

	DEBUG(10, ("DelRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	local_ctx = talloc_named(call, 0, "DelRequest local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	dn = ldb_dn_explode(local_ctx, req->dn);
	VALID_DN_SYNTAX(dn,1);

	DEBUG(10, ("DelRequest: dn: [%s]\n", req->dn));

reply:
	del_reply = ldapsrv_init_reply(call, LDAP_TAG_DelResponse);
	NT_STATUS_HAVE_NO_MEMORY(del_reply);

	if (result == LDAP_SUCCESS) {
		ldb_ret = ldb_delete(samdb, dn);
		result = map_ldb_error(samdb, ldb_ret, &errstr);
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

static NTSTATUS ldapsrv_ModifyDNRequest(struct ldapsrv_call *call)
{
	struct ldap_ModifyDNRequest *req = &call->request->r.ModifyDNRequest;
	struct ldap_Result *modifydn;
	struct ldapsrv_reply *modifydn_r;
	void *local_ctx;
	struct ldb_context *samdb = call->conn->ldb;
	struct ldb_dn *olddn, *newdn=NULL, *newrdn;
	struct ldb_dn *parentdn = NULL;
	const char *errstr = NULL;
	int result = LDAP_SUCCESS;
	int ldb_ret;

	DEBUG(10, ("ModifyDNRequrest"));
	DEBUGADD(10, (" dn: %s", req->dn));
	DEBUGADD(10, (" newrdn: %s", req->newrdn));

	local_ctx = talloc_named(call, 0, "ModifyDNRequest local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	olddn = ldb_dn_explode(local_ctx, req->dn);
	VALID_DN_SYNTAX(olddn, 2);

	newrdn = ldb_dn_explode(local_ctx, req->newrdn);
	VALID_DN_SYNTAX(newrdn, 1);

	DEBUG(10, ("ModifyDNRequest: olddn: [%s]\n", req->dn));
	DEBUG(10, ("ModifyDNRequest: newrdn: [%s]\n", req->newrdn));

	/* we can't handle the rename if we should not remove the old dn */
	if (!req->deleteolddn) {
		result = LDAP_UNWILLING_TO_PERFORM;
		errstr = "Old RDN must be deleted";
		goto reply;
	}

	if (ldb_dn_get_comp_num(newrdn) > 1) {
		result = LDAP_NAMING_VIOLATION;
		errstr = "Error new RDN invalid";
		goto reply;
	}

	if (req->newsuperior) {
		parentdn = ldb_dn_explode(local_ctx, req->newsuperior);
		VALID_DN_SYNTAX(parentdn, 0);
		DEBUG(10, ("ModifyDNRequest: newsuperior: [%s]\n", req->newsuperior));
		
		if (ldb_dn_get_comp_num(parentdn) < 1) {
			result = LDAP_AFFECTS_MULTIPLE_DSAS;
			errstr = "Error new Superior DN invalid";
			goto reply;
		}
	}

	if (!parentdn) {
		parentdn = ldb_dn_get_parent(local_ctx, olddn);
		NT_STATUS_HAVE_NO_MEMORY(parentdn);
	}

	newdn = ldb_dn_build_child(local_ctx,
				   ldb_dn_get_rdn_name(newrdn),
				   (char *)ldb_dn_get_rdn_val(newrdn)->data,
				   parentdn);
	NT_STATUS_HAVE_NO_MEMORY(newdn);

reply:
	modifydn_r = ldapsrv_init_reply(call, LDAP_TAG_ModifyDNResponse);
	NT_STATUS_HAVE_NO_MEMORY(modifydn_r);

	if (result == LDAP_SUCCESS) {
		ldb_ret = ldb_rename(samdb, olddn, newdn);
		result = map_ldb_error(samdb, ldb_ret, &errstr);
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

static NTSTATUS ldapsrv_CompareRequest(struct ldapsrv_call *call)
{
	struct ldap_CompareRequest *req = &call->request->r.CompareRequest;
	struct ldap_Result *compare;
	struct ldapsrv_reply *compare_r;
	void *local_ctx;
	struct ldb_context *samdb = call->conn->ldb;
	struct ldb_result *res = NULL;
	struct ldb_dn *dn;
	const char *attrs[1];
	const char *errstr = NULL;
	const char *filter = NULL;
	int result = LDAP_SUCCESS;
	int ldb_ret;

	DEBUG(10, ("CompareRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	local_ctx = talloc_named(call, 0, "CompareRequest local_memory_context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	dn = ldb_dn_explode(local_ctx, req->dn);
	VALID_DN_SYNTAX(dn, 1);

	DEBUG(10, ("CompareRequest: dn: [%s]\n", req->dn));
	filter = talloc_asprintf(local_ctx, "(%s=%*s)", req->attribute, 
				 (int)req->value.length, req->value.data);
	NT_STATUS_HAVE_NO_MEMORY(filter);

	DEBUGADD(10, ("CompareRequest: attribute: [%s]\n", filter));

	attrs[0] = NULL;

reply:
	compare_r = ldapsrv_init_reply(call, LDAP_TAG_CompareResponse);
	NT_STATUS_HAVE_NO_MEMORY(compare_r);

	if (result == LDAP_SUCCESS) {
		ldb_ret = ldb_search(samdb, dn, LDB_SCOPE_BASE, filter, attrs, &res);
		talloc_steal(samdb, res);
		if (ldb_ret != LDB_SUCCESS) {
			result = map_ldb_error(samdb, ldb_ret, &errstr);
			DEBUG(10,("CompareRequest: error: %s\n", errstr));
		} else if (res->count == 0) {
			DEBUG(10,("CompareRequest: doesn't matched\n"));
			result = LDAP_COMPARE_FALSE;
			errstr = NULL;
		} else if (res->count == 1) {
			DEBUG(10,("CompareRequest: matched\n"));
			result = LDAP_COMPARE_TRUE;
			errstr = NULL;
		} else if (res->count > 1) {
			result = LDAP_OTHER;
			errstr = "too many objects match";
			DEBUG(10,("CompareRequest: %d results: %s\n", res->count, errstr));
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

static NTSTATUS ldapsrv_AbandonRequest(struct ldapsrv_call *call)
{
/*	struct ldap_AbandonRequest *req = &call->request.r.AbandonRequest;*/
	DEBUG(10, ("AbandonRequest\n"));
	return NT_STATUS_OK;
}

NTSTATUS ldapsrv_do_call(struct ldapsrv_call *call)
{
	switch(call->request->type) {
	case LDAP_TAG_BindRequest:
		return ldapsrv_BindRequest(call);
	case LDAP_TAG_UnbindRequest:
		return ldapsrv_UnbindRequest(call);
	case LDAP_TAG_SearchRequest:
		return ldapsrv_SearchRequest(call);
	case LDAP_TAG_ModifyRequest:
		return ldapsrv_ModifyRequest(call);
	case LDAP_TAG_AddRequest:
		return ldapsrv_AddRequest(call);
	case LDAP_TAG_DelRequest:
		return ldapsrv_DelRequest(call);
	case LDAP_TAG_ModifyDNRequest:
		return ldapsrv_ModifyDNRequest(call);
	case LDAP_TAG_CompareRequest:
		return ldapsrv_CompareRequest(call);
	case LDAP_TAG_AbandonRequest:
		return ldapsrv_AbandonRequest(call);
	case LDAP_TAG_ExtendedRequest:
		return ldapsrv_ExtendedRequest(call);
	default:
		return ldapsrv_unwilling(call, 2);
	}
}
