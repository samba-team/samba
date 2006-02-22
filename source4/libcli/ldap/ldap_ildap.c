/* 
   Unix SMB/CIFS mplementation.

   ildap api - an api similar to the traditional ldap api
   
   Copyright (C) Andrew Tridgell  2005
    
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
#include "libcli/ldap/ldap.h"
#include "libcli/ldap/ldap_client.h"

/*
  delete a record
 */
NTSTATUS ildap_delete(struct ldap_connection *conn, const char *dn)
{
	struct ldap_message *msg;
	NTSTATUS status;

	msg = new_ldap_message(conn);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	msg->type = LDAP_TAG_DelRequest;
	msg->r.DelRequest.dn = dn;

	status = ldap_transaction(conn, msg);

	talloc_free(msg);

	return status;
}

/*
  add a record
 */
NTSTATUS ildap_add(struct ldap_connection *conn, const char *dn, struct ldap_mod **mods)
{
	struct ldap_message *msg;
	int n, i;
	NTSTATUS status;

	msg = new_ldap_message(conn);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	for (n=0;mods[n];n++) /* noop */ ;

	msg->type = LDAP_TAG_AddRequest;
	msg->r.AddRequest.dn = dn;
	msg->r.AddRequest.num_attributes = n;
	msg->r.AddRequest.attributes = talloc_array(msg, struct ldb_message_element, n);
	if (msg->r.AddRequest.attributes == NULL) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<n;i++) {
		msg->r.AddRequest.attributes[i] = mods[i]->attrib;
	}

	status = ldap_transaction(conn, msg);

	talloc_free(msg);

	return status;
}


/*
  modify a record
 */
NTSTATUS ildap_modify(struct ldap_connection *conn, const char *dn, struct ldap_mod **mods)
{
	struct ldap_message *msg;
	int n, i;
	NTSTATUS status;

	msg = new_ldap_message(conn);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	for (n=0;mods[n];n++) /* noop */ ;

	msg->type = LDAP_TAG_ModifyRequest;
	msg->r.ModifyRequest.dn = dn;
	msg->r.ModifyRequest.num_mods = n;
	msg->r.ModifyRequest.mods = talloc_array(msg, struct ldap_mod, n);
	if (msg->r.ModifyRequest.mods == NULL) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<n;i++) {
		msg->r.ModifyRequest.mods[i] = *mods[i];
	}

	status = ldap_transaction(conn, msg);

	talloc_free(msg);

	return status;
}


/*
  rename a record
 */
NTSTATUS ildap_rename(struct ldap_connection *conn, const char *dn, const char *newrdn, 
		      const char *parentdn, BOOL deleteolddn)
{
	struct ldap_message *msg;
	NTSTATUS status;

	msg = new_ldap_message(conn);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	msg->type = LDAP_TAG_ModifyDNRequest;
	msg->r.ModifyDNRequest.dn = dn;
	msg->r.ModifyDNRequest.newrdn = newrdn;
	msg->r.ModifyDNRequest.deleteolddn = deleteolddn;
	msg->r.ModifyDNRequest.newsuperior = parentdn;

	status = ldap_transaction(conn, msg);

	talloc_free(msg);

	return status;
}


/*
  count the returned search entries
*/
int ildap_count_entries(struct ldap_connection *conn, struct ldap_message **res)
{
	int i;
	for (i=0;res && res[i];i++) /* noop */ ;
	return i;
}


/*
  perform a synchronous ldap search
*/
NTSTATUS ildap_search_bytree(struct ldap_connection *conn, const char *basedn, 
			     int scope, struct ldb_parse_tree *tree,
			     const char * const *attrs, BOOL attributesonly, 
			     struct ldb_control **control_req,
			     struct ldb_control ***control_res,
			     struct ldap_message ***results)
{
	struct ldap_message *msg;
	int n, i;
	NTSTATUS status;
	struct ldap_request *req;

	if (control_res)
		*control_res = NULL;
	*results = NULL;

	msg = new_ldap_message(conn);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	for (n=0;attrs && attrs[n];n++) /* noop */ ;
	
	msg->type = LDAP_TAG_SearchRequest;
	msg->r.SearchRequest.basedn = basedn;
	msg->r.SearchRequest.scope  = scope;
	msg->r.SearchRequest.deref  = LDAP_DEREFERENCE_NEVER;
	msg->r.SearchRequest.timelimit = 0;
	msg->r.SearchRequest.sizelimit = 0;
	msg->r.SearchRequest.attributesonly = attributesonly;
	msg->r.SearchRequest.tree = tree;
	msg->r.SearchRequest.num_attributes = n;
	msg->r.SearchRequest.attributes = discard_const(attrs);
	msg->controls = control_req;

	req = ldap_request_send(conn, msg);
	talloc_steal(msg, req);
	
	for (i=n=0;True;i++) {
		struct ldap_message *res;
		status = ldap_result_n(req, i, &res);
		if (!NT_STATUS_IS_OK(status)) break;

		if (res->type == LDAP_TAG_SearchResultDone) {
			status = ldap_check_response(conn, &res->r.GeneralResult);
			if (control_res) {
				*control_res = talloc_steal(conn, res->controls);
			}
			break;
		}

		if (res->type != LDAP_TAG_SearchResultEntry &&
		    res->type != LDAP_TAG_SearchResultReference)
			continue;
		
		(*results) = talloc_realloc(conn, *results, struct ldap_message *, n+2);
		if (*results == NULL) {
			talloc_free(msg);
			return NT_STATUS_NO_MEMORY;
		}
		(*results)[n] = talloc_steal(*results, res);
		(*results)[n+1] = NULL;
		n++;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
		status = NT_STATUS_OK;
	}

	return status;
}

/*
  perform a ldap search
*/
NTSTATUS ildap_search(struct ldap_connection *conn, const char *basedn, 
		      int scope, const char *expression, 
		      const char * const *attrs, BOOL attributesonly, 
		      struct ldb_control **control_req,
		      struct ldb_control ***control_res,
		      struct ldap_message ***results)
{
	struct ldb_parse_tree *tree = ldb_parse_tree(conn, expression);
	NTSTATUS status;
	status = ildap_search_bytree(conn, basedn, scope, tree, attrs,
				     attributesonly, control_req,
				     control_res, results);
	talloc_free(tree);
	return status;
}
