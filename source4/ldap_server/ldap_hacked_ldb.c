/* 
   Unix SMB/CIFS implementation.
   LDAP server HACKED LDB implementation to hopefully get a DsGetNCChanges() request from a
   w2k3 box

   Copyright (C) Stefan Metzmacher 2004-2005
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
#include "dynconfig.h"
#include "ldap_server/ldap_server.h"
#include "ldap_parse.h"
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/ndr_security.h"


#define VALID_DN_SYNTAX(dn,i) do {\
	if (!(dn)) {\
		return NT_STATUS_NO_MEMORY;\
	} else if ((dn)->comp_num < (i)) {\
		result = LDAP_INVALID_DN_SYNTAX;\
		errstr = "Invalid DN (" #i " components needed for '" #dn "')";\
		goto reply;\
	}\
} while(0)

#define ATTR_BLOB_CONST(val) data_blob_talloc(mem_ctx, val, sizeof(val)-1)

#define ATTR_SINGLE_NOVAL(ctx, attr, blob, num, nam) do { \
	attr->name = talloc_strdup(ctx, nam);\
	NT_STATUS_HAVE_NO_MEMORY(attr->name);\
	attr->num_values = num; \
	attr->values = blob;\
} while(0)				 


static NTSTATUS convert_values(TALLOC_CTX *mem_ctx,
			       struct ldb_message_element *elem,
			       struct ldap_attribute *attrs,
			       struct ldb_wrap *samdb,
			       const char **dn,
			       struct ldap_SearchRequest *r)
{
	NTSTATUS status;
	DEBUG(10, ("convert_values for %s\n", attrs[0].name));

	attrs->name = talloc_steal(mem_ctx, elem->name);
	attrs->values[0].length = elem->values[0].length;
	attrs->values[0].data = talloc_steal(mem_ctx, elem->values[0].data);

	if (strcasecmp(attrs->name, "objectGUID") == 0 ||
	    strcasecmp(attrs->name, "invocationID") == 0)
	{
		struct GUID guid;
		DATA_BLOB blob;

		status = GUID_from_string((const char *)elem->values[0].data, &guid);
		NT_STATUS_NOT_OK_RETURN(status);

		status = ndr_push_struct_blob(&blob, mem_ctx, &guid,
			      (ndr_push_flags_fn_t)ndr_push_GUID);
		NT_STATUS_NOT_OK_RETURN(status);

		attrs->values[0].length = blob.length;
		attrs->values[0].data = talloc_steal(mem_ctx, blob.data);
	}

	if (strcasecmp(attrs->name, "objectSID") == 0)
	{
		struct dom_sid *sid;
		DATA_BLOB blob;

		sid = dom_sid_parse_talloc(mem_ctx, (const char *)elem->values[0].data);
		NT_STATUS_HAVE_NO_MEMORY(sid);

		status = ndr_push_struct_blob(&blob, mem_ctx, sid,
			      (ndr_push_flags_fn_t)ndr_push_dom_sid);
		NT_STATUS_NOT_OK_RETURN(status);

		attrs->values[0].length = blob.length;
		attrs->values[0].data = talloc_steal(mem_ctx, blob.data);
	}

	if (strcasecmp(attrs->name, "ncname") == 0)
	{
		char *filter = talloc_strdup(mem_ctx, r->filter);
		struct ldb_message **res = NULL;
		int count;
		const char *dom_dn;
		const char *dom_filter;

		const char *dom_sid_str;
		struct dom_sid *dom_sid;
		DATA_BLOB dom_sid_blob;
		const char *dom_sid_hex;

		const char *dom_guid_str;
		struct GUID dom_guid;
		DATA_BLOB dom_guid_blob;
		const char *dom_guid_hex;

		const char *nc_filter;
		const char *nc_guid_str;
		struct GUID nc_guid;
		DATA_BLOB nc_guid_blob;
		char *nc_guid_hex;
		const char *ncname;

		const char *s_attrs[] = {"objectGUID", "objectSid", NULL};
		char *p2;

		nc_filter = talloc_asprintf(mem_ctx, "(dn=%s)", *dn);
DEBUG(0, (__location__": convert_values(ncname): nc dn = '%s'\n", nc_filter));

		
		/* first the NC stuff */
		count = ldb_search(samdb->ldb, "", LDB_SCOPE_BASE, nc_filter, s_attrs, &res);
		if (count != 1) {
			DEBUG(0, (__location__": convert_values(ncname): nc_count: %d \n", count));
			return NT_STATUS_FOOBAR;
		}
DEBUG(0, (__location__": convert_values(ncname): nc_res '%s'\n", res[0]->dn));
		nc_guid_str = samdb_result_string(res[0], "objectGUID", NULL);

		status = GUID_from_string(nc_guid_str, &nc_guid);

		status = ndr_push_struct_blob(&nc_guid_blob, mem_ctx, &nc_guid,
			      (ndr_push_flags_fn_t)ndr_push_GUID);

		nc_guid_hex = data_blob_hex_string(mem_ctx, &nc_guid_blob);

		/* overwrite the dn of the search result */
		*dn = talloc_asprintf(mem_ctx, "<GUID=%s>;%s", nc_guid_hex, *dn);
DEBUG(0, (__location__": convert_values(ncname): dn='%s'\n",*dn));
		/* now the domain stuff */

		dom_dn = strchr(filter, '=');
		dom_dn++;

		p2 = strchr(filter, ')');
		*p2 ='\0';

		dom_filter = talloc_asprintf(mem_ctx, "(dn=%s)", dom_dn);
DEBUG(0, (__location__": convert_values(ncname): dom dn = '%s'\n", dom_filter));
		count = ldb_search(samdb->ldb, "", LDB_SCOPE_BASE, dom_filter, s_attrs, &res);
		if (count != 1) {
			DEBUG(0, (__location__": convert_values(ncname): dom_count: %d \n", count));
			return NT_STATUS_OK;
		}

		dom_guid_str = samdb_result_string(res[0], "objectGUID", NULL);

		status = GUID_from_string(dom_guid_str, &dom_guid);

		status = ndr_push_struct_blob(&dom_guid_blob, mem_ctx, &dom_guid,
			      (ndr_push_flags_fn_t)ndr_push_GUID);

		dom_guid_hex = data_blob_hex_string(mem_ctx, &dom_guid_blob);

		dom_sid_str = samdb_result_string(res[0], "objectSid", NULL);

		dom_sid = dom_sid_parse_talloc(mem_ctx, dom_sid_str);

		status = ndr_push_struct_blob(&dom_sid_blob, mem_ctx, dom_sid,
			      (ndr_push_flags_fn_t)ndr_push_dom_sid);

		dom_sid_hex = data_blob_hex_string(mem_ctx, &dom_sid_blob);

		ncname = talloc_asprintf(mem_ctx, "<GUID=%s>;<SID=%s>;%s",
					dom_guid_hex, dom_sid_hex, dom_dn);
DEBUG(0, (__location__": convert_values(ncname): ncname='%s'\n",ncname));

		attrs->values[0].length = strlen(ncname);
		attrs->values[0].data = talloc_steal(mem_ctx, ncname);
DEBUG(0, (__location__": convert_values(ncname): end ok\n"));
	}

	return NT_STATUS_OK;
}

static NTSTATUS hacked_wellknown_Search(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_SearchRequest *r)
{
	NTSTATUS status;
	void *local_ctx;
	struct ldap_SearchResEntry *ent;
	struct ldap_Result *done;
	struct ldapsrv_reply *ent_r, *done_r;
	int count;
	const char *dn_prefix;
	const char *wkdn;
	char *p, *p2;
	enum ldb_scope scope = LDB_SCOPE_DEFAULT;
	char *basedn_str;

	local_ctx = talloc_named(call, 0, "hacked_wellknown_Search local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	switch (r->scope) {
		case LDAP_SEARCH_SCOPE_BASE:
			scope = LDB_SCOPE_BASE;
			break;
		default:
			return NT_STATUS_NOT_IMPLEMENTED;
	}

#define WKGUID_prefix "<WKGUID="
	if (strncasecmp(WKGUID_prefix, r->basedn, strlen(WKGUID_prefix)) != 0) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	basedn_str = talloc_strdup(call, r->basedn);

#define WKGUID_Infrastructure "<WKGUID=2FBAC1870ADE11D297C400C04FD8D5CD,"
#define WKGUID_Infrastructure_DN "CN=Infrastructure,"
	if (strncasecmp(WKGUID_Infrastructure, r->basedn, strlen(WKGUID_Infrastructure)) == 0) {
		dn_prefix = WKGUID_Infrastructure_DN;
	} else
#define WKGUID_Domain_Controllers "<WKGUID=A361B2FFFFD211D1AA4B00C04FD7D83A,"
#define WKGUID_Domain_Controllers_DN "OU=Domain Controllers,"	
	if (strncasecmp(WKGUID_Domain_Controllers, r->basedn, strlen(WKGUID_Domain_Controllers)) == 0) {
		dn_prefix = WKGUID_Domain_Controllers_DN;
	} else {
		DEBUG(0,("UKNOWN dn '%s'\n", basedn_str));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	p = strchr(basedn_str, ',');
	p++;

	p2 = strchr(basedn_str, '>');
	*p2 ='\0';

	wkdn = talloc_asprintf(call, "%s%s", dn_prefix, p);

	count = 1;
	ent_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultEntry);
	NT_STATUS_HAVE_NO_MEMORY(ent_r);

	ent = &ent_r->msg.r.SearchResultEntry;
	ent->dn = talloc_steal(ent_r, wkdn);
	DEBUG(0,("hacked result [0] dn: %s\n", ent->dn));
	ent->num_attributes = 0;
	ent->attributes = NULL;

	status = ldapsrv_queue_reply(call, ent_r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	NT_STATUS_HAVE_NO_MEMORY(done_r);

	DEBUG(10,("hacked_Search: results: [%d]\n",count));

	done = &done_r->msg.r.SearchResultDone;
	done->dn = NULL;
	done->resultcode = LDAP_SUCCESS;
	done->errormessage = NULL;
	done->referral = NULL;

	talloc_free(local_ctx);

	return ldapsrv_queue_reply(call, done_r);
}

static NTSTATUS hacked_Search(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_SearchRequest *r, struct ldb_wrap *samdb)
{
	NTSTATUS status;
	void *local_ctx;
	struct ldap_SearchResEntry *ent;
	struct ldap_Result *done;
	struct ldb_message **res = NULL;
	int result = LDAP_SUCCESS;
	struct ldapsrv_reply *ent_r, *done_r;
	const char *errstr = NULL;
	int count, j, y, i;
	const char **attrs = NULL;
	enum ldb_scope scope = LDB_SCOPE_DEFAULT;
	struct ldap_dn *basedn;
	const char *basedn_str;

	local_ctx = talloc_named(call, 0, "hacked_Search local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	basedn = ldap_parse_dn(local_ctx, r->basedn);
	if (!basedn) {
		basedn_str = r->basedn;
	} else {
		basedn_str = basedn->dn;
	}

	switch (r->scope) {
		case LDAP_SEARCH_SCOPE_BASE:
			DEBUG(10,("hldb_Search: scope: [BASE]\n"));
			scope = LDB_SCOPE_BASE;
			break;
		case LDAP_SEARCH_SCOPE_SINGLE:
			DEBUG(10,("hldb_Search: scope: [ONE]\n"));
			scope = LDB_SCOPE_ONELEVEL;
			break;
		case LDAP_SEARCH_SCOPE_SUB:
			DEBUG(10,("hldb_Search: scope: [SUB]\n"));
			scope = LDB_SCOPE_SUBTREE;
			break;
	}

	if (r->num_attributes >= 1) {
		attrs = talloc_array(samdb, const char *, r->num_attributes+1);
		NT_STATUS_HAVE_NO_MEMORY(attrs);

		for (j=0; j < r->num_attributes; j++) {
			DEBUG(10,("hacked_Search: attrs: [%s]\n",r->attributes[j]));
			attrs[j] = r->attributes[j];
		}
		attrs[j] = NULL;
	}
DEBUG(0,("hacked basedn: %s\n", basedn_str));
DEBUGADD(0,("hacked filter: %s\n", r->filter));
	count = ldb_search(samdb->ldb, basedn_str, scope, r->filter, attrs, &res);
	talloc_steal(samdb, res);

	if (count < 1) {
		DEBUG(0,("hacked not found\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (scope == LDAP_SEARCH_SCOPE_BASE) {
		ent_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultEntry);
		NT_STATUS_HAVE_NO_MEMORY(ent_r);

		ent = &ent_r->msg.r.SearchResultEntry;
		ent->dn = talloc_steal(ent_r, res[0]->dn);
		DEBUG(0,("hacked result [0] dn: %s\n", ent->dn));
		ent->num_attributes = 0;
		ent->attributes = NULL;
		if (res[0]->num_elements == 0) {
			goto queue_reply;
		}
		ent->num_attributes = res[0]->num_elements;
		ent->attributes = talloc_array(ent_r, struct ldap_attribute, ent->num_attributes);
		NT_STATUS_HAVE_NO_MEMORY(ent->attributes);
		for (j=0; j < ent->num_attributes; j++) {
			ent->attributes[j].name = talloc_steal(ent->attributes, res[0]->elements[j].name);
			ent->attributes[j].num_values = 0;
			ent->attributes[j].values = NULL;
			ent->attributes[j].num_values = res[0]->elements[j].num_values;
			if (ent->attributes[j].num_values == 1) {
				ent->attributes[j].values = talloc_array(ent->attributes,
								DATA_BLOB, ent->attributes[j].num_values);
				NT_STATUS_HAVE_NO_MEMORY(ent->attributes[j].values);
				status = convert_values(ent_r,
							&(res[0]->elements[j]),
							&(ent->attributes[j]),
							samdb, &ent->dn, r);
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			} else {
				ent->attributes[j].values = talloc_array(ent->attributes,
								DATA_BLOB, ent->attributes[j].num_values);
				NT_STATUS_HAVE_NO_MEMORY(ent->attributes[j].values);
				for (y=0; y < ent->attributes[j].num_values; y++) {
					ent->attributes[j].values[y].length = res[0]->elements[j].values[y].length;
					ent->attributes[j].values[y].data = talloc_steal(ent->attributes[j].values,
										res[0]->elements[j].values[y].data);
				}
			}
		}
queue_reply:
		status = ldapsrv_queue_reply(call, ent_r);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		for (i=0; i < count; i++) {
			ent_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultEntry);
			NT_STATUS_HAVE_NO_MEMORY(ent_r);

			ent = &ent_r->msg.r.SearchResultEntry;
			ent->dn = talloc_steal(ent_r, res[i]->dn);
			DEBUG(0,("hacked result [%d] dn: %s\n", i, ent->dn));
			ent->num_attributes = 0;
			ent->attributes = NULL;
			if (res[i]->num_elements == 0) {
				goto queue_reply2;
			}
			ent->num_attributes = res[i]->num_elements;
			ent->attributes = talloc_array(ent_r, struct ldap_attribute, ent->num_attributes);
			NT_STATUS_HAVE_NO_MEMORY(ent->attributes);
			for (j=0; j < ent->num_attributes; j++) {
				ent->attributes[j].name = talloc_steal(ent->attributes, res[i]->elements[j].name);
				ent->attributes[j].num_values = 0;
				ent->attributes[j].values = NULL;
				if (r->attributesonly && (res[i]->elements[j].num_values == 0)) {
					continue;
				}
				ent->attributes[j].num_values = res[i]->elements[j].num_values;
				ent->attributes[j].values = talloc_array(ent->attributes,
								DATA_BLOB, ent->attributes[j].num_values);
				NT_STATUS_HAVE_NO_MEMORY(ent->attributes[j].values);
				if (ent->attributes[j].num_values == 1) {
					status = convert_values(ent_r,
							&(res[0]->elements[j]),
							&(ent->attributes[j]),
							samdb, &ent->dn, r);
					if (!NT_STATUS_IS_OK(status)) {
						return status;
					}
				} else {
					for (y=0; y < ent->attributes[j].num_values; y++) {
						ent->attributes[j].values[y].length = res[i]->elements[j].values[y].length;
						ent->attributes[j].values[y].data = talloc_steal(ent->attributes[j].values,
										res[i]->elements[j].values[y].data);
					}
				}
			}
queue_reply2:
			status = ldapsrv_queue_reply(call, ent_r);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}

	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	NT_STATUS_HAVE_NO_MEMORY(done_r);

	if (count > 0) {
		DEBUG(10,("hacked_Search: results: [%d]\n",count));
		result = LDAP_SUCCESS;
		errstr = NULL;
	} else if (count == 0) {
		DEBUG(10,("hacked_Search: no results\n"));
		result = LDAP_NO_SUCH_OBJECT;
		errstr = ldb_errstring(samdb->ldb);	
	} else if (count == -1) {
		DEBUG(10,("hacked_Search: error\n"));
		result = LDAP_OTHER;
		errstr = ldb_errstring(samdb->ldb);
	}

	done = &done_r->msg.r.SearchResultDone;
	done->dn = NULL;
	done->resultcode = result;
	done->errormessage = (errstr?talloc_strdup(done_r,errstr):NULL);;
	done->referral = NULL;

	talloc_free(local_ctx);

	return ldapsrv_queue_reply(call, done_r);
}

static NTSTATUS hldb_Search(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_SearchRequest *r)
{
	NTSTATUS status;
	void *local_ctx;
	struct ldb_wrap *samdb;
#if 0
	struct ldap_dn *basedn;
	struct ldap_Result *done;
	struct ldap_SearchResEntry *ent;
	struct ldapsrv_reply *ent_r, *done_r;
	int result = LDAP_SUCCESS;
	struct ldb_message **res = NULL;
	int i, j, y, count = 0;
	enum ldb_scope scope = LDB_SCOPE_DEFAULT;
	const char **attrs = NULL;
	const char *errstr = NULL;
#endif
	local_ctx = talloc_named(call, 0, "hldb_Search local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = samdb_connect(local_ctx);
	NT_STATUS_HAVE_NO_MEMORY(samdb);

	status = hacked_Search(partition, call, r, samdb);
	talloc_free(local_ctx);
	NT_STATUS_IS_OK_RETURN(status);
	status = hacked_wellknown_Search(partition, call, r);
	NT_STATUS_IS_OK_RETURN(status);
	return status;
#if 0
	basedn = ldap_parse_dn(local_ctx, r->basedn);
	VALID_DN_SYNTAX(basedn,0);

	DEBUG(10, ("hldb_Search: basedn: [%s]\n", basedn->dn));
	DEBUG(10, ("hldb_Search: filter: [%s]\n", r->filter));

	switch (r->scope) {
		case LDAP_SEARCH_SCOPE_BASE:
			DEBUG(10,("hldb_Search: scope: [BASE]\n"));
			scope = LDB_SCOPE_BASE;
			break;
		case LDAP_SEARCH_SCOPE_SINGLE:
			DEBUG(10,("hldb_Search: scope: [ONE]\n"));
			scope = LDB_SCOPE_ONELEVEL;
			break;
		case LDAP_SEARCH_SCOPE_SUB:
			DEBUG(10,("hldb_Search: scope: [SUB]\n"));
			scope = LDB_SCOPE_SUBTREE;
			break;
	}

	if (r->num_attributes >= 1) {
		attrs = talloc_array(samdb, const char *, r->num_attributes+1);
		NT_STATUS_HAVE_NO_MEMORY(attrs);

		for (i=0; i < r->num_attributes; i++) {
			DEBUG(10,("hldb_Search: attrs: [%s]\n",r->attributes[i]));
			attrs[i] = r->attributes[i];
		}
		attrs[i] = NULL;
	}

	count = ldb_search(samdb->ldb, basedn->dn, scope, r->filter, attrs, &res);
	talloc_steal(samdb, res);

	if (count < 1) {
		status = hacked_Search(partition, call, r, samdb);
		NT_STATUS_IS_OK_RETURN(status);
		status = hacked_wellknown_Search(partition, call, r);
		NT_STATUS_IS_OK_RETURN(status);
	}

	for (i=0; i < count; i++) {
		ent_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultEntry);
		NT_STATUS_HAVE_NO_MEMORY(ent_r);

		ent = &ent_r->msg.r.SearchResultEntry;
		ent->dn = talloc_steal(ent_r, res[i]->dn);
		ent->num_attributes = 0;
		ent->attributes = NULL;
		if (res[i]->num_elements == 0) {
			goto queue_reply;
		}
		ent->num_attributes = res[i]->num_elements;
		ent->attributes = talloc_array(ent_r, struct ldap_attribute, ent->num_attributes);
		NT_STATUS_HAVE_NO_MEMORY(ent->attributes);
		for (j=0; j < ent->num_attributes; j++) {
			ent->attributes[j].name = talloc_steal(ent->attributes, res[i]->elements[j].name);
			ent->attributes[j].num_values = 0;
			ent->attributes[j].values = NULL;
			if (r->attributesonly && (res[i]->elements[j].num_values == 0)) {
				continue;
			}
			ent->attributes[j].num_values = res[i]->elements[j].num_values;
			ent->attributes[j].values = talloc_array(ent->attributes,
							DATA_BLOB, ent->attributes[j].num_values);
			NT_STATUS_HAVE_NO_MEMORY(ent->attributes[j].values);
			for (y=0; y < ent->attributes[j].num_values; y++) {
				ent->attributes[j].values[y].length = res[i]->elements[j].values[y].length;
				ent->attributes[j].values[y].data = talloc_steal(ent->attributes[j].values,
									res[i]->elements[j].values[y].data);
			}
		}
queue_reply:
		status = ldapsrv_queue_reply(call, ent_r);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

reply:
	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	NT_STATUS_HAVE_NO_MEMORY(done_r);

	if (result == LDAP_SUCCESS) {
		if (count > 0) {
			DEBUG(10,("hldb_Search: results: [%d]\n",count));
			result = LDAP_SUCCESS;
			errstr = NULL;
		} else if (count == 0) {
			DEBUG(10,("hldb_Search: no results\n"));
			result = LDAP_NO_SUCH_OBJECT;
			errstr = ldb_errstring(samdb->ldb);
		} else if (count == -1) {
			DEBUG(10,("hldb_Search: error\n"));
			result = LDAP_OTHER;
			errstr = ldb_errstring(samdb->ldb);
		}
	}

	done = &done_r->msg.r.SearchResultDone;
	done->dn = NULL;
	done->resultcode = result;
	done->errormessage = (errstr?talloc_strdup(done_r,errstr):NULL);
	done->referral = NULL;

	talloc_free(local_ctx);

	return ldapsrv_queue_reply(call, done_r);
#endif
}

static NTSTATUS hldb_Add(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_AddRequest *r)
{
	void *local_ctx;
	struct ldap_dn *dn;
	struct ldap_Result *add_result;
	struct ldapsrv_reply *add_reply;
	int ldb_ret;
	struct ldb_wrap *samdb;
	struct ldb_message *msg = NULL;
	int result = LDAP_SUCCESS;
	const char *errstr = NULL;
	int i,j;

	local_ctx = talloc_named(call, 0, "hldb_Add local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = samdb_connect(local_ctx);
	NT_STATUS_HAVE_NO_MEMORY(samdb);

	dn = ldap_parse_dn(local_ctx, r->dn);
	VALID_DN_SYNTAX(dn,1);

	DEBUG(10, ("hldb_add: dn: [%s]\n", dn->dn));

	msg = talloc(local_ctx, struct ldb_message);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	msg->dn = dn->dn;
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
		ldb_ret = ldb_add(samdb->ldb, msg);
		if (ldb_ret == 0) {
			DEBUG(0,("hldb_Add: added: '%s'\n", msg->dn));
			result = LDAP_SUCCESS;
			errstr = NULL;
		} else {
			/* currently we have no way to tell if there was an internal ldb error
		 	 * or if the object was not found, return the most probable error
		 	 */
			result = LDAP_OPERATIONS_ERROR;
			errstr = ldb_errstring(samdb->ldb);
		}
	}

	add_result = &add_reply->msg.r.AddResponse;
	add_result->dn = NULL;
	add_result->resultcode = result;
	add_result->errormessage = (errstr?talloc_strdup(add_reply,errstr):NULL);
	add_result->referral = NULL;

	talloc_free(local_ctx);

	return ldapsrv_queue_reply(call, add_reply);
}

static NTSTATUS hldb_Del(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_DelRequest *r)
{
	void *local_ctx;
	struct ldap_dn *dn;
	struct ldap_Result *del_result;
	struct ldapsrv_reply *del_reply;
	int ldb_ret;
	struct ldb_wrap *samdb;
	const char *errstr = NULL;
	int result = LDAP_SUCCESS;

	local_ctx = talloc_named(call, 0, "hldb_Del local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = samdb_connect(local_ctx);
	NT_STATUS_HAVE_NO_MEMORY(samdb);

	dn = ldap_parse_dn(local_ctx, r->dn);
	VALID_DN_SYNTAX(dn,1);

	DEBUG(10, ("hldb_Del: dn: [%s]\n", dn->dn));

reply:
	del_reply = ldapsrv_init_reply(call, LDAP_TAG_DelResponse);
	NT_STATUS_HAVE_NO_MEMORY(del_reply);

	if (result == LDAP_SUCCESS) {
		ldb_ret = ldb_delete(samdb->ldb, dn->dn);
		if (ldb_ret == 0) {
			result = LDAP_SUCCESS;
			errstr = NULL;
		} else {
			/* currently we have no way to tell if there was an internal ldb error
			 * or if the object was not found, return the most probable error
			 */
			result = LDAP_NO_SUCH_OBJECT;
			errstr = ldb_errstring(samdb->ldb);
		}
	}

	del_result = &del_reply->msg.r.DelResponse;
	del_result->dn = NULL;
	del_result->resultcode = result;
	del_result->errormessage = (errstr?talloc_strdup(del_reply,errstr):NULL);
	del_result->referral = NULL;

	talloc_free(local_ctx);

	return ldapsrv_queue_reply(call, del_reply);
}

static NTSTATUS hldb_Modify(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_ModifyRequest *r)
{
	void *local_ctx;
	struct ldap_dn *dn;
	struct ldap_Result *modify_result;
	struct ldapsrv_reply *modify_reply;
	int ldb_ret;
	struct ldb_wrap *samdb;
	struct ldb_message *msg = NULL;
	int result = LDAP_SUCCESS;
	const char *errstr = NULL;
	int i,j;

	local_ctx = talloc_named(call, 0, "hldb_Modify local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = samdb_connect(local_ctx);
	NT_STATUS_HAVE_NO_MEMORY(samdb);

	dn = ldap_parse_dn(local_ctx, r->dn);
	VALID_DN_SYNTAX(dn,1);

	DEBUG(10, ("hldb_modify: dn: [%s]\n", dn->dn));

	msg = talloc(local_ctx, struct ldb_message);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	msg->dn = dn->dn;
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
		ldb_ret = ldb_modify(samdb->ldb, msg);
		if (ldb_ret == 0) {
			result = LDAP_SUCCESS;
			errstr = NULL;
		} else {
			/* currently we have no way to tell if there was an internal ldb error
		 	 * or if the object was not found, return the most probable error
		 	 */
		 		result = LDAP_ATTRIBUTE_OR_VALUE_EXISTS;
			result = LDAP_OPERATIONS_ERROR;
			errstr = ldb_errstring(samdb->ldb);
			if (strcmp("Type or value exists", errstr) ==0){
				result = LDAP_ATTRIBUTE_OR_VALUE_EXISTS;
			}
			DEBUG(0,("failed to modify: %s - %u - %s\n", msg->dn, result, errstr));
		}
	}

	modify_result = &modify_reply->msg.r.AddResponse;
	modify_result->dn = NULL;
	modify_result->resultcode = result;
	modify_result->errormessage = (errstr?talloc_strdup(modify_reply,errstr):NULL);
	modify_result->referral = NULL;

	talloc_free(local_ctx);

	return ldapsrv_queue_reply(call, modify_reply);
}

static NTSTATUS hldb_Compare(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_CompareRequest *r)
{
	void *local_ctx;
	struct ldap_dn *dn;
	struct ldap_Result *compare;
	struct ldapsrv_reply *compare_r;
	int result = LDAP_SUCCESS;
	struct ldb_wrap *samdb;
	struct ldb_message **res = NULL;
	const char *attrs[1];
	const char *errstr = NULL;
	const char *filter = NULL;
	int count;

	local_ctx = talloc_named(call, 0, "hldb_Compare local_memory_context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = samdb_connect(local_ctx);
	NT_STATUS_HAVE_NO_MEMORY(samdb);

	dn = ldap_parse_dn(local_ctx, r->dn);
	VALID_DN_SYNTAX(dn,1);

	DEBUG(10, ("hldb_Compare: dn: [%s]\n", dn->dn));
	filter = talloc_asprintf(local_ctx, "(%s=%*s)", r->attribute, r->value.length, r->value.data);
	NT_STATUS_HAVE_NO_MEMORY(filter);

	DEBUGADD(10, ("hldb_Compare: attribute: [%s]\n", filter));

	attrs[0] = NULL;

reply:
	compare_r = ldapsrv_init_reply(call, LDAP_TAG_CompareResponse);
	NT_STATUS_HAVE_NO_MEMORY(compare_r);

	if (result == LDAP_SUCCESS) {
		count = ldb_search(samdb->ldb, dn->dn, LDB_SCOPE_BASE, filter, attrs, &res);
		talloc_steal(samdb, res);
		if (count == 1) {
			DEBUG(10,("hldb_Compare: matched\n"));
			result = LDAP_COMPARE_TRUE;
			errstr = NULL;
		} else if (count == 0) {
			DEBUG(10,("hldb_Compare: doesn't matched\n"));
			result = LDAP_COMPARE_FALSE;
			errstr = NULL;
		} else if (count > 1) {
			result = LDAP_OTHER;
			errstr = "too many objects match";
			DEBUG(10,("hldb_Compare: %d results: %s\n", count, errstr));
		} else if (count == -1) {
			result = LDAP_OTHER;
			errstr = ldb_errstring(samdb->ldb);
			DEBUG(10,("hldb_Compare: error: %s\n", errstr));
		}
	}

	compare = &compare_r->msg.r.CompareResponse;
	compare->dn = NULL;
	compare->resultcode = result;
	compare->errormessage = (errstr?talloc_strdup(compare_r,errstr):NULL);
	compare->referral = NULL;

	talloc_free(local_ctx);

	return ldapsrv_queue_reply(call, compare_r);
}

static NTSTATUS hldb_ModifyDN(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_ModifyDNRequest *r)
{
	void *local_ctx;
	struct ldap_dn *olddn, *newrdn, *newsuperior;
	struct ldap_Result *modifydn;
	struct ldapsrv_reply *modifydn_r;
	int ldb_ret;
	struct ldb_wrap *samdb;
	const char *errstr = NULL;
	int result = LDAP_SUCCESS;
	const char *newdn = NULL;
	char *parentdn = NULL;

	local_ctx = talloc_named(call, 0, "hldb_ModifyDN local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	samdb = samdb_connect(local_ctx);
	NT_STATUS_HAVE_NO_MEMORY(samdb);

	olddn = ldap_parse_dn(local_ctx, r->dn);
	VALID_DN_SYNTAX(olddn,2);

	newrdn = ldap_parse_dn(local_ctx, r->newrdn);
	VALID_DN_SYNTAX(newrdn,1);

	DEBUG(10, ("hldb_ModifyDN: olddn: [%s]\n", olddn->dn));
	DEBUG(10, ("hldb_ModifyDN: newrdn: [%s]\n", newrdn->dn));

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
		newsuperior = ldap_parse_dn(local_ctx, r->newsuperior);
		VALID_DN_SYNTAX(newsuperior,0);
		DEBUG(10, ("hldb_ModifyDN: newsuperior: [%s]\n", newsuperior->dn));
		
		if (newsuperior->comp_num < 1) {
			result = LDAP_AFFECTS_MULTIPLE_DSAS;
			errstr = "Error new Superior DN invalid";
			goto reply;
		}
		parentdn = newsuperior->dn;
	}

	if (!parentdn) {
		int i;
		parentdn = talloc_strdup(local_ctx, olddn->components[1]->component);
		NT_STATUS_HAVE_NO_MEMORY(parentdn);
		for(i=2; i < olddn->comp_num; i++) {
			char *old = parentdn;
			parentdn = talloc_asprintf(local_ctx, "%s,%s", old, olddn->components[i]->component);
			NT_STATUS_HAVE_NO_MEMORY(parentdn);
			talloc_free(old);
		}
	}
	newdn = talloc_asprintf(local_ctx, "%s,%s", newrdn->dn, parentdn);
	NT_STATUS_HAVE_NO_MEMORY(newdn);

reply:
	modifydn_r = ldapsrv_init_reply(call, LDAP_TAG_ModifyDNResponse);
	NT_STATUS_HAVE_NO_MEMORY(modifydn_r);

	if (result == LDAP_SUCCESS) {
		ldb_ret = ldb_rename(samdb->ldb, olddn->dn, newdn);
		if (ldb_ret == 0) {
			result = LDAP_SUCCESS;
			errstr = NULL;
		} else {
			/* currently we have no way to tell if there was an internal ldb error
			 * or if the object was not found, return the most probable error
			 */
			result = LDAP_NO_SUCH_OBJECT;
			errstr = ldb_errstring(samdb->ldb);
		}
	}

	modifydn = &modifydn_r->msg.r.ModifyDNResponse;
	modifydn->dn = NULL;
	modifydn->resultcode = result;
	modifydn->errormessage = (errstr?talloc_strdup(modifydn_r,errstr):NULL);
	modifydn->referral = NULL;

	talloc_free(local_ctx);

	return ldapsrv_queue_reply(call, modifydn_r);
}

static const struct ldapsrv_partition_ops hldb_ops = {
	.Search		= hldb_Search,
	.Add		= hldb_Add,
	.Del		= hldb_Del,
	.Modify		= hldb_Modify,
	.Compare	= hldb_Compare,
	.ModifyDN	= hldb_ModifyDN
};

const struct ldapsrv_partition_ops *ldapsrv_get_hldb_partition_ops(void)
{
	return &hldb_ops;
}
