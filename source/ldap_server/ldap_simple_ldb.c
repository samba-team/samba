/* 
   Unix SMB/CIFS implementation.
   LDAP server SIMPLE LDB implementation
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

/* TODO: samdb_context is not a pulblic struct */
struct samdb_context {
	struct ldb_context *ldb;
	struct samdb_context **static_ptr;
};


#define ALLOC_CHECK(ptr) do {\
	if (!(ptr)) {\
		return NT_STATUS_NO_MEMORY;\
	}\
} while(0)

static NTSTATUS sldb_Search(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_SearchRequest *r)
{
	NTSTATUS status;
	struct ldap_Result *done;
	struct ldap_SearchResEntry *ent;
	struct ldapsrv_reply *ent_r, *done_r;
	int result = 80;
	struct samdb_context *samdb;
	struct ldb_message **res;
	int i, j, y, count;
	struct ldb_context *ldb;
	enum ldb_scope scope = LDB_SCOPE_DEFAULT;
	const char **attrs = NULL;

	DEBUG(0, ("sldb_Search: %s\n", r->filter));

	samdb = samdb_connect(call);
	ldb = samdb->ldb;

	switch (r->scope) {
		case LDAP_SEARCH_SCOPE_BASE:
			scope = LDB_SCOPE_BASE;
			break;
		case LDAP_SEARCH_SCOPE_SINGLE:
			scope = LDB_SCOPE_ONELEVEL;
			break;
		case LDAP_SEARCH_SCOPE_SUB:
			scope = LDB_SCOPE_SUBTREE;
			break;
	}

	if (r->num_attributes >= 1) {
		attrs = talloc_array_p(samdb, const char *, r->num_attributes+1);
		ALLOC_CHECK(attrs);

		for (i=0; i < r->num_attributes; i++) {
			attrs[i] = r->attributes[i];
		}
		attrs[i] = NULL;
	}

	ldb_set_alloc(ldb, talloc_ldb_alloc, samdb);
	count = ldb_search(ldb, r->basedn, scope, r->filter, attrs, &res);

	if (count > 0) {
		result = 0;
	} else if (count == 0) {
		result = 32;
	} else if (count == -1) {
		result = 1;
	}

	for (i=0; i < count; i++) {
		ent_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultEntry);
		ALLOC_CHECK(ent_r);

		ent = &ent_r->msg.r.SearchResultEntry;
		ent->dn = talloc_steal(ent_r, res[i]->dn);
		ent->num_attributes = 0;
		ent->attributes = NULL;
		if (res[i]->num_elements == 0) {
			continue;
		}
		ent->num_attributes = res[i]->num_elements;
		ent->attributes = talloc_array_p(ent_r, struct ldap_attribute, ent->num_attributes);
		ALLOC_CHECK(ent->attributes);
		for (j=0; j < ent->num_attributes; j++) {
			ent->attributes[j].name = talloc_steal(ent->attributes, res[i]->elements[j].name);
			ent->attributes[j].num_values = 0;
			ent->attributes[j].values = NULL;
			if (r->attributesonly && (res[i]->elements[j].num_values == 0)) {
				continue;
			}
			ent->attributes[j].num_values = res[i]->elements[j].num_values;
			ent->attributes[j].values = talloc_array_p(ent->attributes,
							DATA_BLOB, ent->attributes[j].num_values);
			ALLOC_CHECK(ent->attributes[j].values);
			for (y=0; y < ent->attributes[j].num_values; y++) {
				ent->attributes[j].values[y].length = res[i]->elements[j].values[y].length;
				ent->attributes[j].values[y].data = talloc_steal(ent->attributes[j].values,
									res[i]->elements[j].values[y].data);
			}
		}

		status = ldapsrv_queue_reply(call, ent_r);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	talloc_free(samdb);

	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	ALLOC_CHECK(done_r);

	done = &done_r->msg.r.SearchResultDone;
	done->resultcode = result;
	done->dn = NULL;
	done->errormessage = NULL;
	done->referral = NULL;

	return ldapsrv_queue_reply(call, done_r);
}

static NTSTATUS sldb_Delete(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_DeleteRequest *r)
{
	struct ldap_Result *delete_result;
	struct ldapsrv_reply *delete_reply;
	int ldb_ret;
	struct samdb_context *samdb;
	struct ldb_context *ldb;

	DEBUG(0, ("sldb_Delete: %s\n", r->dn));

	samdb = samdb_connect(call);
	ldb = samdb->ldb;

	ldb_set_alloc(ldb, talloc_ldb_alloc, samdb);
	ldb_ret = ldb_delete(ldb, r->dn);

	delete_reply = ldapsrv_init_reply(call, LDAP_TAG_DeleteResponse);

	delete_result = &delete_reply->msg.r.DeleteResponse;
	delete_result->dn = talloc_steal(delete_reply, r->dn);

	if (ldb_ret != 0) {
		/* currently we have no way to tell if there was an internal ldb error
		 * or if the object was not found, return the most probable error
		 */
		delete_result->resultcode = LDAP_NO_SUCH_OBJECT;
		delete_result->errormessage = ldb_errstring(ldb);
		delete_result->referral = NULL;
	} else {	
		delete_result->resultcode = LDAP_SUCCESS;
		delete_result->errormessage = NULL;
		delete_result->referral = NULL;
	}

	ldapsrv_queue_reply(call, delete_reply);

	talloc_free(samdb);

	return NT_STATUS_OK;
}

static const struct ldapsrv_partition_ops sldb_ops = {
	.Search		= sldb_Search,
	.Delete		= sldb_Delete
};

const struct ldapsrv_partition_ops *ldapsrv_get_sldb_partition_ops(void)
{
	return &sldb_ops;
}
