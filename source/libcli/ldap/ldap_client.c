/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Volker Lendecke 2004
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
#include "system/network.h"
#include "auth/auth.h"
#include "asn_1.h"
#include "dlinklist.h"

#if 0
static struct ldap_message *new_ldap_search_message(struct ldap_connection *conn,
					     const char *base,
					     enum ldap_scope scope,
					     char *filter,
					     int num_attributes,
					     const char **attributes)
{
	struct ldap_message *res;

	res = new_ldap_message(conn);
	if (!res) {
		return NULL;
	}

	res->type = LDAP_TAG_SearchRequest;
	res->r.SearchRequest.basedn = base;
	res->r.SearchRequest.scope = scope;
	res->r.SearchRequest.deref = LDAP_DEREFERENCE_NEVER;
	res->r.SearchRequest.timelimit = 0;
	res->r.SearchRequest.sizelimit = 0;
	res->r.SearchRequest.attributesonly = False;
	res->r.SearchRequest.filter = filter;
	res->r.SearchRequest.num_attributes = num_attributes;
	res->r.SearchRequest.attributes = attributes;

	return res;
}
#endif

static struct ldap_message *new_ldap_simple_bind_msg(struct ldap_connection *conn, const char *dn, const char *pw)
{
	struct ldap_message *res;

	res = new_ldap_message(conn);
	if (!res) {
		return NULL;
	}

	res->type = LDAP_TAG_BindRequest;
	res->r.BindRequest.version = 3;
	res->r.BindRequest.dn = talloc_strdup(res->mem_ctx, dn);
	res->r.BindRequest.mechanism = LDAP_AUTH_MECH_SIMPLE;
	res->r.BindRequest.creds.password = talloc_strdup(res->mem_ctx, pw);

	return res;
}

static struct ldap_message *new_ldap_sasl_bind_msg(struct ldap_connection *conn, const char *sasl_mechanism, DATA_BLOB *secblob)
{
	struct ldap_message *res;

	res = new_ldap_message(conn);
	if (!res) {
		return NULL;
	}

	res->type = LDAP_TAG_BindRequest;
	res->r.BindRequest.version = 3;
	res->r.BindRequest.dn = "";
	res->r.BindRequest.mechanism = LDAP_AUTH_MECH_SASL;
	res->r.BindRequest.creds.SASL.mechanism = talloc_strdup(res->mem_ctx, sasl_mechanism);
	res->r.BindRequest.creds.SASL.secblob = *secblob;

	return res;
}

static struct ldap_connection *new_ldap_connection(TALLOC_CTX *mem_ctx)
{
	struct ldap_connection *result;

	result = talloc_p(mem_ctx, struct ldap_connection);

	if (!result) {
		return NULL;
	}

	result->mem_ctx = result;
	result->next_msgid = 1;
	result->outstanding = NULL;
	result->searchid = 0;
	result->search_entries = NULL;
	result->auth_dn = NULL;
	result->simple_pw = NULL;
	result->gensec = NULL;

	return result;
}

struct ldap_connection *ldap_connect(TALLOC_CTX *mem_ctx, const char *url)
{
	struct hostent *hp;
	struct ipv4_addr ip;
	struct ldap_connection *conn;
	BOOL ret;

	conn = new_ldap_connection(mem_ctx);
	if (!conn) {
		return NULL;
	}

	ret = ldap_parse_basic_url(conn->mem_ctx, url, &conn->host,
				  &conn->port, &conn->ldaps);
	if (!ret) {
		talloc_free(conn);
		return NULL;
	}

	hp = sys_gethostbyname(conn->host);
	if (!hp || !hp->h_addr) {
		talloc_free(conn);
		return NULL;
	}

	putip((char *)&ip, (char *)hp->h_addr);

	conn->sock = open_socket_out(SOCK_STREAM, &ip, conn->port, LDAP_CONNECTION_TIMEOUT);
	if (conn->sock < 0) {
		talloc_free(conn);
		return NULL;
	}

	return conn;
}

struct ldap_message *new_ldap_message(TALLOC_CTX *mem_ctx)
{
	struct ldap_message *result;

	result = talloc_p(mem_ctx, struct ldap_message);

	if (!result) {
		return NULL;
	}

	result->mem_ctx = result;

	return result;
}

BOOL ldap_send_msg(struct ldap_connection *conn, struct ldap_message *msg,
		   const struct timeval *endtime)
{
	DATA_BLOB request;
	BOOL result;
	struct ldap_queue_entry *entry;

	msg->messageid = conn->next_msgid++;

	if (!ldap_encode(msg, &request))
		return False;

	result = (write_data_until(conn->sock, request.data, request.length,
				   endtime) == request.length);

	data_blob_free(&request);

	if (!result)
		return result;

	/* abandon and unbind don't expect results */

	if ((msg->type == LDAP_TAG_AbandonRequest) ||
	    (msg->type == LDAP_TAG_UnbindRequest))
		return True;

	entry = malloc_p(struct ldap_queue_entry);

	if (entry == NULL)
		return False;

	entry->msgid = msg->messageid;
	entry->msg = NULL;
	DLIST_ADD(conn->outstanding, entry);

	return True;
}

BOOL ldap_receive_msg(struct ldap_connection *conn, struct ldap_message *msg,
		      const struct timeval *endtime)
{
        struct asn1_data data;
        BOOL result;

        if (!asn1_read_sequence_until(conn->sock, &data, endtime))
                return False;

        result = ldap_decode(&data, msg);

        asn1_free(&data);
        return result;
}

static struct ldap_message *recv_from_queue(struct ldap_connection *conn,
					    int msgid)
{
	struct ldap_queue_entry *e;

	for (e = conn->outstanding; e != NULL; e = e->next) {

		if (e->msgid == msgid) {
			struct ldap_message *result = e->msg;
			DLIST_REMOVE(conn->outstanding, e);
			SAFE_FREE(e);
			return result;
		}
	}

	return NULL;
}

static void add_search_entry(struct ldap_connection *conn,
			     struct ldap_message *msg)
{
	struct ldap_queue_entry *e = malloc_p(struct ldap_queue_entry);

	if (e == NULL)
		return;

	e->msg = msg;
	DLIST_ADD_END(conn->search_entries, e, struct ldap_queue_entry *);
	return;
}

static void fill_outstanding_request(struct ldap_connection *conn,
				     struct ldap_message *msg)
{
	struct ldap_queue_entry *e;

	for (e = conn->outstanding; e != NULL; e = e->next) {
		if (e->msgid == msg->messageid) {
			e->msg = msg;
			return;
		}
	}

	/* This reply has not been expected, destroy the incoming msg */
	talloc_free(msg);
	return;
}

struct ldap_message *ldap_receive(struct ldap_connection *conn, int msgid,
				  const struct timeval *endtime)
{
	struct ldap_message *result = recv_from_queue(conn, msgid);

	if (result != NULL)
		return result;

	while (True) {
		struct asn1_data data;
		BOOL res;

		result = new_ldap_message(conn);

		if (!asn1_read_sequence_until(conn->sock, &data, endtime))
			return NULL;

		res = ldap_decode(&data, result);
		asn1_free(&data);

		if (!res)
			return NULL;

		if (result->messageid == msgid)
			return result;

		if (result->type == LDAP_TAG_SearchResultEntry) {
			add_search_entry(conn, result);
		} else {
			fill_outstanding_request(conn, result);
		}
	}

	return NULL;
}

struct ldap_message *ldap_transaction(struct ldap_connection *conn,
				      struct ldap_message *request)
{
	if (!ldap_send_msg(conn, request, NULL))
		return False;

	return ldap_receive(conn, request->messageid, NULL);
}

int ldap_bind_simple(struct ldap_connection *conn, const char *userdn, const char *password)
{
	struct ldap_message *response;
	struct ldap_message *msg;
	const char *dn, *pw;
	int result = LDAP_OTHER;

	if (conn == NULL)
		return result;

	if (userdn) {
		dn = userdn;
	} else {
		if (conn->auth_dn) {
			dn = conn->auth_dn;
		} else {
			dn = "";
		}
	}

	if (password) {
		pw = password;
	} else {
		if (conn->simple_pw) {
			pw = conn->simple_pw;
		} else {
			pw = "";
		}
	}

	msg =  new_ldap_simple_bind_msg(conn, dn, pw);
	if (!msg)
		return result;

	response = ldap_transaction(conn, msg);
	if (!response) {
		talloc_free(msg);
		return result;
	}
		
	result = response->r.BindResponse.response.resultcode;

	talloc_free(msg);
	talloc_free(response);

	return result;
}

int ldap_bind_sasl(struct ldap_connection *conn, const char *username, const char *domain, const char *password)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = NULL;
	struct ldap_message *response;
	struct ldap_message *msg;
	DATA_BLOB input = data_blob(NULL, 0);
	DATA_BLOB output = data_blob(NULL, 0);
	int result = LDAP_OTHER;

	if (conn == NULL)
		return result;

	status = gensec_client_start(conn, &conn->gensec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to start GENSEC engine (%s)\n", nt_errstr(status)));
		return result;
	}

	gensec_want_feature(conn->gensec, GENSEC_FEATURE_SIGN | GENSEC_FEATURE_SEAL);

	status = gensec_set_domain(conn->gensec, domain);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client domain to %s: %s\n", 
			  domain, nt_errstr(status)));
		goto done;
	}

	status = gensec_set_username(conn->gensec, username);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client username to %s: %s\n", 
			  username, nt_errstr(status)));
		goto done;
	}

	status = gensec_set_password(conn->gensec, password);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client password: %s\n", 
			  nt_errstr(status)));
		goto done;
	}

	status = gensec_set_target_hostname(conn->gensec, conn->host);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target hostname: %s\n", 
			  nt_errstr(status)));
		goto done;
	}

	status = gensec_start_mech_by_sasl_name(conn->gensec, "GSS-SPNEGO");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client SPNEGO mechanism: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	mem_ctx = talloc_init("ldap_bind_sasl");
	if (!mem_ctx)
		goto done;

	status = gensec_update(conn->gensec, mem_ctx,
			       input,
			       &output);

	while(1) {
		if (NT_STATUS_IS_OK(status) && output.length == 0) {
			break;
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) && !NT_STATUS_IS_OK(status)) {
			break;
		}

		msg =  new_ldap_sasl_bind_msg(conn, "GSS-SPNEGO", &output);
		if (!msg)
			goto done;

		response = ldap_transaction(conn, msg);
		talloc_free(msg);

		if (!response) {
			goto done;
		}

		result = response->r.BindResponse.response.resultcode;

		if (result != LDAP_SUCCESS && result != LDAP_SASL_BIND_IN_PROGRESS) {
			break;
		}

		status = gensec_update(conn->gensec, mem_ctx,
				       response->r.BindResponse.SASL.secblob,
				       &output);

		talloc_free(response);
	}

done:
	if (mem_ctx)
		talloc_destroy(mem_ctx);

	return result;
}

struct ldap_connection *ldap_setup_connection(TALLOC_CTX *mem_ctx, const char *url, 
						const char *userdn, const char *password)
{
	struct ldap_connection *conn;
	int result;

	conn =ldap_connect(mem_ctx, url);
	if (!conn) {
		return NULL;
	}

	result = ldap_bind_simple(conn, userdn, password);
	if (result != LDAP_SUCCESS) {
		talloc_free(conn);
		return NULL;
	}

	return conn;
}

struct ldap_connection *ldap_setup_connection_with_sasl(TALLOC_CTX *mem_ctx, const char *url,
							const char *username, const char *domain, const char *password)
{
	struct ldap_connection *conn;
	int result;

	conn =ldap_connect(mem_ctx, url);
	if (!conn) {
		return NULL;
	}

	result = ldap_bind_sasl(conn, username, domain, password);
	if (result != LDAP_SUCCESS) {
		talloc_free(conn);
		return NULL;
	}

	return conn;
}

BOOL ldap_abandon_message(struct ldap_connection *conn, int msgid,
				 const struct timeval *endtime)
{
	struct ldap_message *msg = new_ldap_message(conn);
	BOOL result;

	if (msg == NULL)
		return False;

	msg->type = LDAP_TAG_AbandonRequest;
	msg->r.AbandonRequest.messageid = msgid;

	result = ldap_send_msg(conn, msg, endtime);
	talloc_free(msg);
	return result;
}

BOOL ldap_setsearchent(struct ldap_connection *conn, struct ldap_message *msg,
		       const struct timeval *endtime)
{
	if ((conn->searchid != 0) &&
	    (!ldap_abandon_message(conn, conn->searchid, endtime)))
		return False;

	conn->searchid = conn->next_msgid;
	return ldap_send_msg(conn, msg, endtime);
}

struct ldap_message *ldap_getsearchent(struct ldap_connection *conn,
				       const struct timeval *endtime)
{
	struct ldap_message *result;

	if (conn->search_entries != NULL) {
		struct ldap_queue_entry *e = conn->search_entries;

		result = e->msg;
		DLIST_REMOVE(conn->search_entries, e);
		SAFE_FREE(e);
		return result;
	}

	result = ldap_receive(conn, conn->searchid, endtime);
	if (!result) {
		return NULL;
	}

	if (result->type == LDAP_TAG_SearchResultEntry)
		return result;

	if (result->type == LDAP_TAG_SearchResultDone) {
		/* TODO: Handle Paged Results */
		talloc_free(result);
		return NULL;
	}

	/* TODO: Handle Search References here */
	return NULL;
}

void ldap_endsearchent(struct ldap_connection *conn,
		       const struct timeval *endtime)
{
	struct ldap_queue_entry *e;

	e = conn->search_entries;

	while (e != NULL) {
		struct ldap_queue_entry *next = e->next;
		DLIST_REMOVE(conn->search_entries, e);
		SAFE_FREE(e);
		e = next;
	}
}

struct ldap_message *ldap_searchone(struct ldap_connection *conn,
				    struct ldap_message *msg,
				    const struct timeval *endtime)
{
	struct ldap_message *res1, *res2 = NULL;
	if (!ldap_setsearchent(conn, msg, endtime))
		return NULL;

	res1 = ldap_getsearchent(conn, endtime);

	if (res1 != NULL)
		res2 = ldap_getsearchent(conn, endtime);

	ldap_endsearchent(conn, endtime);

	if (res1 == NULL)
		return NULL;

	if (res2 != NULL) {
		/* More than one entry */
		talloc_free(res1);
		talloc_free(res2);
		return NULL;
	}

	return res1;
}

BOOL ldap_find_single_value(struct ldap_message *msg, const char *attr,
			    DATA_BLOB *value)
{
	int i;
	struct ldap_SearchResEntry *r = &msg->r.SearchResultEntry;

	if (msg->type != LDAP_TAG_SearchResultEntry)
		return False;

	for (i=0; i<r->num_attributes; i++) {
		if (strequal(attr, r->attributes[i].name)) {
			if (r->attributes[i].num_values != 1)
				return False;

			*value = r->attributes[i].values[0];
			return True;
		}
	}
	return False;
}

BOOL ldap_find_single_string(struct ldap_message *msg, const char *attr,
			     TALLOC_CTX *mem_ctx, char **value)
{
	DATA_BLOB blob;

	if (!ldap_find_single_value(msg, attr, &blob))
		return False;

	*value = talloc(mem_ctx, blob.length+1);

	if (*value == NULL)
		return False;

	memcpy(*value, blob.data, blob.length);
	(*value)[blob.length] = '\0';
	return True;
}

BOOL ldap_find_single_int(struct ldap_message *msg, const char *attr,
			  int *value)
{
	DATA_BLOB blob;
	char *val;
	int errno_save;
	BOOL res;

	if (!ldap_find_single_value(msg, attr, &blob))
		return False;

	val = malloc(blob.length+1);
	if (val == NULL)
		return False;

	memcpy(val, blob.data, blob.length);
	val[blob.length] = '\0';

	errno_save = errno;
	errno = 0;

	*value = strtol(val, NULL, 10);

	res = (errno == 0);

	free(val);
	errno = errno_save;

	return res;
}

int ldap_error(struct ldap_connection *conn)
{
	return 0;
}

NTSTATUS ldap2nterror(int ldaperror)
{
	return NT_STATUS_OK;
}
