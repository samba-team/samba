/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Volker Lendecke 2004
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

/*
  close the socket and shutdown a server_context
*/
static void ldapsrv_terminate_connection(struct ldapsrv_connection *ldap_conn, const char *reason)
{
	server_terminate_connection(ldap_conn->connection, reason);
}

/*
  add a socket address to the list of events, one event per port
*/
static void add_socket(struct server_service *service, 
		       const struct model_ops *model_ops, 
		       struct in_addr *ifip)
{
	uint16_t port = 389;
	char *ip_str = talloc_strdup(service->mem_ctx, inet_ntoa(*ifip));

	service_setup_socket(service, model_ops, ip_str, &port);

	talloc_free(ip_str);
}

/****************************************************************************
 Open the socket communication.
****************************************************************************/
static void ldapsrv_init(struct server_service *service,
			 const struct model_ops *model_ops)
{	
	DEBUG(1,("ldapsrv_init\n"));

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;

		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);

			if (ifip == NULL) {
				DEBUG(0,("ldapsrv_init: interface %d has NULL "
					 "IP address !\n", i));
				continue;
			}

			add_socket(service, model_ops, ifip);
		}
	} else {
		struct in_addr *ifip;
		TALLOC_CTX *mem_ctx = talloc_init("ldapsrv_init");

		if (!mem_ctx) {
			smb_panic("No memory");
		}	

		/* Just bind to lp_socket_address() (usually 0.0.0.0) */
		ifip = interpret_addr2(mem_ctx, lp_socket_address());
		add_socket(service, model_ops, ifip);

		talloc_destroy(mem_ctx);
	}
}

/* This rw-buf api is made to avoid memcpy. For now do that like mad...  The
   idea is to write into a circular list of buffers where the ideal case is
   that a read(2) holds a complete request that is then thrown away
   completely. */

static BOOL append_to_buf(struct rw_buffer *buf, uint8_t *data, size_t length)
{
	buf->data = realloc(buf->data, buf->length+length);

	if (buf->data == NULL)
		return False;

	memcpy(buf->data+buf->length, data, length);

	buf->length += length;
	return True;
}

static BOOL read_into_buf(struct socket_context *sock, struct rw_buffer *buf)
{
	NTSTATUS status;
	DATA_BLOB tmp_blob;
	BOOL ret;

	status = socket_recv(sock, sock, &tmp_blob, 1024, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("socket_recv: %s\n",nt_errstr(status)));
		return False;
	}

	ret = append_to_buf(buf, tmp_blob.data, tmp_blob.length);

	talloc_free(tmp_blob.data);

	return ret;
}

static BOOL write_from_buf(struct socket_context *sock, struct rw_buffer *buf)
{
	NTSTATUS status;
	DATA_BLOB tmp_blob;
	size_t sendlen;

	tmp_blob.data = buf->data;
	tmp_blob.length = buf->length;

	status = socket_send(sock, sock, &tmp_blob, &sendlen, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if (buf->length != sendlen) {
		return False;
	}

	return True;
}

static void peek_into_read_buf(struct rw_buffer *buf, uint8_t **out,
			       size_t *out_length)
{
	*out = buf->data;
	*out_length = buf->length;
}

static void consumed_from_read_buf(struct rw_buffer *buf,
				   size_t length)
{
	memcpy(buf->data, buf->data+length, buf->length-length);
	buf->length -= length;
}

static BOOL ldap_append_to_buf(struct ldap_message *msg, struct rw_buffer *buf)
{
	DATA_BLOB blob;
	BOOL res;

	if (!ldap_encode(msg, &blob))
		return False;

	res = append_to_buf(buf, blob.data, blob.length);

	data_blob_free(&blob);
	return res;
}

static void reply_unwilling(struct ldapsrv_connection *ldap_conn, int error)
{
	struct ldap_message *msg;
	struct ldap_ExtendedResponse *r;

	msg = new_ldap_message();

	if (msg == NULL) {
		ldapsrv_terminate_connection(ldap_conn, "new_ldap_message() failed");
		return;
	}

	msg->messageid = 0;
	r = &msg->r.ExtendedResponse;	

	/* When completely freaking out, OpenLDAP responds with an ExtResp */
	msg->type = LDAP_TAG_ExtendedResponse;
	r->response.resultcode = error;
	r->response.dn = NULL;
	r->response.errormessage = NULL;
	r->response.referral = NULL;
	r->name = NULL;
	r->value.data = NULL;
	r->value.length = 0;

	ldap_append_to_buf(msg, &ldap_conn->out_buffer);

	talloc_destroy(msg->mem_ctx);
}

static void ldap_reply_BindRequest(struct ldapsrv_connection *conn, 
				   struct ldap_message *request)
{
	struct ldap_BindRequest *req = &request->r.BindRequest;

	struct ldap_message *msg;
	struct ldap_BindResponse *resp;

	DEBUG(5, ("Binding as %s with pw %s\n",
		  req->dn, req->creds.password));

	msg = new_ldap_message();

	if (msg == NULL) {
		ldapsrv_terminate_connection(conn, "new_ldap_message() failed");
		return;
	}

	resp = &msg->r.BindResponse;

	msg->messageid = request->messageid;
	msg->type = LDAP_TAG_BindResponse;
	resp->response.resultcode = 0;
	resp->response.dn = NULL;
	resp->response.errormessage = NULL;
	resp->response.referral = NULL;
	resp->SASL.secblob = data_blob(NULL, 0);

	ldap_append_to_buf(msg, &conn->out_buffer);
	talloc_destroy(msg->mem_ctx);
}

static void ldap_reply_SearchRequest(struct ldapsrv_connection *conn,
				     struct ldap_message *request)
{
	struct ldap_SearchRequest *req = &request->r.SearchRequest;

	struct ldap_message *msg;
	struct ldap_Result *resp;

	DEBUG(10, ("Search filter: %s\n", req->filter));

	msg = new_ldap_message();

	if (msg == NULL) {
		ldapsrv_terminate_connection(conn, "new_ldap_message() failed");
		return;
	}

	msg->messageid = request->messageid;
	resp = &msg->r.SearchResultDone;

	/* Is this a rootdse request? */
	if ((strlen(req->basedn) == 0) &&
	    (req->scope == LDAP_SEARCH_SCOPE_BASE) &&
	    strequal(req->filter, "(objectclass=*)")) {

#define ATTR_BLOB_CONST(val) data_blob(val, sizeof(val)-1)
#define ATTR_CONST_SINGLE(attr, blob, nam, val) do { \
	attr.name = nam; \
	attr.num_values = ARRAY_SIZE(blob); \
	attr.values = blob; \
	blob[0] = ATTR_BLOB_CONST(val); \
} while(0)
#define ATTR_CONST_SINGLE_NOVAL(attr, blob, nam) do { \
	attr.name = nam;\
	attr.num_values = ARRAY_SIZE(blob); \
	attr.values = blob;\
} while(0)
		TALLOC_CTX *mem_ctx;
		struct ldap_attribute attrs[3];
		DATA_BLOB currentTime[1];
		DATA_BLOB supportedLDAPVersion[2];
		DATA_BLOB dnsHostName[1];

		mem_ctx = talloc_init("rootDSE");
		if (!mem_ctx) {
			ldapsrv_terminate_connection(conn, "no memory");
			return;
		}

		/* 
		 * currentTime
		 * 20040918090350.0Z
		 */
		ATTR_CONST_SINGLE_NOVAL(attrs[0], currentTime, "currentTime");
		{
			char *str = ldap_timestring(mem_ctx, time(NULL));
			if (!str) {
				ldapsrv_terminate_connection(conn, "no memory");
				return;
			}
			currentTime[0] = data_blob(str, strlen(str));
			talloc_free(str);
		}

		/* 
		 * subschemaSubentry 
		 * CN=Aggregate,CN=Schema,CN=Configuration,DC=DOM,DC=TLD
		 */

		/* 
		 * dsServiceName
		 * CN=NTDS Settings,CN=NETBIOSNAME,CN=Servers,CN=Default-First-Site,CN=Sites,CN=Configuration,DC=DOM,DC=TLD
		 */

		/* 
		 * namingContexts
		 * DC=DOM,DC=TLD
		 * CN=Configuration,DC=DOM,DC=TLD
		 * CN=Schema,CN=Configuration,DC=DOM,DC=TLD
		 * DC=DomainDnsZones,DC=DOM,DC=TLD
		 * DC=ForestDnsZones,DC=DOM,DC=TLD
		 */

		/* 
		 * defaultNamingContext
		 * DC=DOM,DC=TLD
		 */

		/* 
		 * schemaNamingContext
		 * CN=Schema,CN=Configuration,DC=DOM,DC=TLD
		 */

		/* 
		 * configurationNamingContext
		 * CN=Configuration,DC=DOM,DC=TLD
		 */

		/* 
		 * rootDomainNamingContext
		 * DC=DOM,DC=TLD
		 */

		/* 
		 * supportedControl
		 * 1.2.840.113556.1.4.319
		 * 1.2.840.113556.1.4.801
		 * 1.2.840.113556.1.4.473
		 * 1.2.840.113556.1.4.528
		 * 1.2.840.113556.1.4.417
		 * 1.2.840.113556.1.4.619
		 * 1.2.840.113556.1.4.841
		 * 1.2.840.113556.1.4.529
		 * 1.2.840.113556.1.4.805
		 * 1.2.840.113556.1.4.521
		 * 1.2.840.113556.1.4.970
		 * 1.2.840.113556.1.4.1338
		 * 1.2.840.113556.1.4.474
		 * 1.2.840.113556.1.4.1339
		 * 1.2.840.113556.1.4.1340
		 * 1.2.840.113556.1.4.1413
		 * 2.16.840.1.113730.3.4.9
		 * 2.16.840.1.113730.3.4.10
		 * 1.2.840.113556.1.4.1504
		 * 1.2.840.113556.1.4.1852
		 * 1.2.840.113556.1.4.802
		 */

		/* 
		 * supportedLDAPVersion 
		 * 3
		 * 2
		 */
		ATTR_CONST_SINGLE_NOVAL(attrs[1], supportedLDAPVersion, "supportedLDAPVersion");
		supportedLDAPVersion[0] = ATTR_BLOB_CONST("3");
		supportedLDAPVersion[1] = ATTR_BLOB_CONST("2");

		/* 
		 * supportedLDAPPolicies
		 * MaxPoolThreads
		 * MaxDatagramRecv
		 * MaxReceiveBuffer
		 * InitRecvTimeout
		 * MaxConnections
		 * MaxConnIdleTime
		 * MaxPageSize
		 * MaxQueryDuration
		 * MaxTempTableSize
		 * MaxResultSetSize
		 * MaxNotificationPerConn
		 * MaxValRange
		 */

		/* 
		 * highestCommittedUSN 
		 * 4555
		 */

		/* 
		 * supportedSASLMechanisms
		 * GSSAPI
		 * GSS-SPNEGO
		 * EXTERNAL
		 * DIGEST-MD5
		 */

		/* 
		 * dnsHostName
		 * netbiosname.dom.tld
		 */
		ATTR_CONST_SINGLE_NOVAL(attrs[2], dnsHostName, "dnsHostName");
		dnsHostName[0] = data_blob(lp_netbios_name(),strlen(lp_netbios_name()));

		/* 
		 * ldapServiceName
		 * dom.tld:netbiosname$@DOM.TLD
		 */

		/* 
		 * serverName:
		 * CN=NETBIOSNAME,CN=Servers,CN=Default-First-Site,CN=Sites,CN=Configuration,DC=DOM,DC=TLD
		 */

		/* 
		 * supportedCapabilities
		 * 1.2.840.113556.1.4.800
		 * 1.2.840.113556.1.4.1670
		 * 1.2.840.113556.1.4.1791
		 */

		/* 
		 * isSynchronized:
		 * TRUE/FALSE
		 */

		/* 
		 * isGlobalCatalogReady
		 * TRUE/FALSE
		 */

		/* 
		 * domainFunctionality
		 * 0
		 */

		/* 
		 * forestFunctionality
		 * 0
		 */

		/* 
		 * domainControllerFunctionality
		 * 2
		 */

		msg->type = LDAP_TAG_SearchResultEntry;
		msg->r.SearchResultEntry.dn = "";
		msg->r.SearchResultEntry.num_attributes = ARRAY_SIZE(attrs);
		msg->r.SearchResultEntry.attributes = attrs;

		ldap_append_to_buf(msg, &conn->out_buffer);
		talloc_free(mem_ctx);
	}

	msg->type = LDAP_TAG_SearchResultDone;
	resp->resultcode = 0;
	resp->dn = NULL;
	resp->errormessage = NULL;
	resp->referral = NULL;

	ldap_append_to_buf(msg, &conn->out_buffer);
	talloc_destroy(msg->mem_ctx);
}

static void switch_ldap_message(struct ldapsrv_connection *conn,
			 struct ldap_message *msg)
{
	switch(msg->type) {
	case LDAP_TAG_BindRequest:
		ldap_reply_BindRequest(conn, msg);
		break;
	case LDAP_TAG_SearchRequest:
		ldap_reply_SearchRequest(conn, msg);
		break;
	default:
		reply_unwilling(conn, 2);
		break;
	}
}

static void ldap_queue_run(struct server_connection *conn)
{
	struct ldapsrv_connection *ldap_conn = conn->private_data;
	
	while (ldap_conn->in_queue) {
		struct ldap_message_queue *req = ldap_conn->in_queue;
		DLIST_REMOVE(ldap_conn->in_queue, req);

		switch_ldap_message(ldap_conn, req->msg);
		talloc_destroy(req->msg->mem_ctx);
	}
}

/*
  called when a LDAP socket becomes readable
*/
static void ldapsrv_recv(struct server_connection *conn, time_t t,
			 uint16_t flags)
{
	struct ldapsrv_connection *ldap_conn = conn->private_data;
	uint8_t *buf;
	int buf_length, msg_length;
	DATA_BLOB blob;
	ASN1_DATA data;
	struct ldap_message *msg;
	struct ldap_message_queue *queue_entry;

	DEBUG(10,("ldapsrv_recv\n"));

	if (!read_into_buf(conn->socket, &ldap_conn->in_buffer)) {
		ldapsrv_terminate_connection(ldap_conn, "read_into_buf() failed");
		return;
	}

	peek_into_read_buf(&ldap_conn->in_buffer, &buf, &buf_length);

	while (buf_length > 0) {

		/* LDAP Messages are always SEQUENCES */

		if (!asn1_object_length(buf, buf_length, ASN1_SEQUENCE(0),
					&msg_length)) {
			ldapsrv_terminate_connection(ldap_conn, "asn1_object_length() failed");
			return;
		}

		if (buf_length < msg_length) {
			/* Not enough yet */
			break;
		}

		/* We've got a complete LDAP request in the in-buffer, convert
		 * that to a ldap_message and put it into the incoming
		 * queue. */

		blob.data = buf;
		blob.length = msg_length;

		if (!asn1_load(&data, blob)) {
			ldapsrv_terminate_connection(ldap_conn, "asn1_load() failed");
			return;
		}

		msg = new_ldap_message();

		if ((msg == NULL) || !ldap_decode(&data, msg)) {
			ldapsrv_terminate_connection(ldap_conn, "ldap_decode() failed");
			return;
		}

		queue_entry = talloc_p(msg->mem_ctx, struct ldap_message_queue);

		if (queue_entry == NULL) {
			ldapsrv_terminate_connection(ldap_conn, "alloc_p(msg->mem_ctx, struct ldap_message_queue) failed");
			return;
		}

		queue_entry->msg = msg;

		DLIST_ADD_END(ldap_conn->in_queue, queue_entry,
			      struct ldap_message_queue *);

		consumed_from_read_buf(&ldap_conn->in_buffer, msg_length);

		peek_into_read_buf(&ldap_conn->in_buffer, &buf, &buf_length);
	}

	ldap_queue_run(conn);

	conn->event.fde->flags |= EVENT_FD_WRITE;

	return;
}
	
/*
  called when a LDAP socket becomes writable
*/
static void ldapsrv_send(struct server_connection *conn, time_t t,
			 uint16_t flags)
{
	struct ldapsrv_connection *ldap_conn = conn->private_data;

	DEBUG(10,("ldapsrv_send\n"));

	if (!write_from_buf(conn->socket, &ldap_conn->out_buffer)) {
		ldapsrv_terminate_connection(ldap_conn, "write_from_buf() failed");
		return;
	}

	conn->event.fde->flags &= ~EVENT_FD_WRITE;

	return;
}

/*
  called when connection is idle
*/
static void ldapsrv_idle(struct server_connection *conn, time_t t)
{
	DEBUG(10,("ldapsrv_idle: not implemented!\n"));
	return;
}

static void ldapsrv_close(struct server_connection *conn, const char *reason)
{
	struct ldapsrv_connection *ldap_conn = conn->private_data;

	talloc_free(ldap_conn);

	return;
}

/*
  initialise a server_context from a open socket and register a event handler
  for reading from that socket
*/
static void ldapsrv_accept(struct server_connection *conn)
{
	struct ldapsrv_connection *ldap_conn;

	DEBUG(5, ("ldapsrv_accept\n"));

	ldap_conn = talloc_p(NULL, struct ldapsrv_connection);

	if (ldap_conn == NULL)
		return;

	ZERO_STRUCTP(ldap_conn);
	ldap_conn->connection = conn;

	conn->private_data = ldap_conn;

	return;
}

/*
  called on a fatal error that should cause this server to terminate
*/
static void ldapsrv_exit(struct server_service *service, const char *reason)
{
	DEBUG(1,("ldapsrv_exit\n"));
	return;
}

static const struct server_service_ops ldap_server_ops = {
	.name			= "ldap",
	.service_init		= ldapsrv_init,
	.accept_connection	= ldapsrv_accept,
	.recv_handler		= ldapsrv_recv,
	.send_handler		= ldapsrv_send,
	.idle_handler		= ldapsrv_idle,
	.close_connection	= ldapsrv_close,
	.service_exit		= ldapsrv_exit,	
};

const struct server_service_ops *ldapsrv_get_ops(void)
{
	return &ldap_server_ops;
}

NTSTATUS server_service_ldap_init(void)
{
	return NT_STATUS_OK;	
}
