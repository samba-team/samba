/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   
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
#include "asn_1.h"

NTSTATUS torture_ldap_bind(struct ldap_connection *conn, const char *userdn, const char *password)
{
        NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int result;

	if (!conn) {
		printf("We need a valid ldap_connection structure and be connected\n");
		return status;
	}

	result = ldap_bind_simple(conn, userdn, password);
	if (result != LDAP_SUCCESS) {
		printf("Failed to bind with provided credentials\n");
		/* FIXME: what abut actually implementing an ldap_connection_free() function ?
		          :-) sss */
		return status;
	}
 
	return NT_STATUS_OK;
}

NTSTATUS torture_ldap_bind_sasl(struct ldap_connection *conn, const char *username, const char *domain, const char *password)
{
        NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int result;

	if (!conn) {
		printf("We need a valid ldap_connection structure and be connected\n");
		return status;
	}

	result = ldap_bind_sasl(conn, username, domain, password);
	if (result != LDAP_SUCCESS) {
		printf("Failed to bind with provided credentials and SASL mechanism\n");
		/* FIXME: what abut actually implementing an ldap_connection_free() function ?
		          :-) sss */
		return status;
	}
 
	return NT_STATUS_OK;
}

/* open a ldap connection to a server */
NTSTATUS torture_ldap_connection(TALLOC_CTX *mem_ctx, struct ldap_connection **conn, 
				const char *url, const char *userdn, const char *password)
{
        NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int ret;

	if (!url) {
		printf("You must specify a url string\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	*conn = ldap_connect(mem_ctx, url);
	if (!*conn) {
		printf("Failed to initialize ldap_connection structure\n");
		return status;
	}

	ret = ldap_bind_simple(*conn, userdn, password);
	if (ret != LDAP_SUCCESS) {
		printf("Failed to connect with url [%s]\n", url);
		/* FIXME: what abut actually implementing an ldap_connection_free() function ?
		          :-) sss */
		return status;
	}
 
	return NT_STATUS_OK;
}

/* close an ldap connection to a server */
NTSTATUS torture_ldap_close(struct ldap_connection *conn)
{
	/* FIXME: what about actually implementing ldap_close() ?
		  :-) sss */
	return NT_STATUS_OK;
}


/*
 Write data to a fd
*/
static ssize_t write_data(int fd, char *buffer, size_t N)
{
	size_t total=0;
	ssize_t ret;

	while (total < N) {
		ret = sys_write(fd,buffer + total,N - total);

		if (ret == -1) {
			DEBUG(0,("write_data: write failure. Error = %s\n", strerror(errno) ));
			return -1;
		}
		if (ret == 0)
			return total;

		total += ret;
	}

	return (ssize_t)total;
}


/*
 Read data from the client, reading exactly N bytes
*/
static ssize_t read_data(int fd, char *buffer, size_t N)
{
	ssize_t ret;
	size_t total=0;  
 
	while (total < N) {

		ret = sys_read(fd,buffer + total,N - total);

		if (ret == 0) {
			DEBUG(10,("read_data: read of %d returned 0. Error = %s\n", 
				  (int)(N - total), strerror(errno) ));
			return 0;
		}

		if (ret == -1) {
			DEBUG(0,("read_data: read failure for %d. Error = %s\n", 
				 (int)(N - total), strerror(errno) ));
			return -1;
		}
		total += ret;
	}

	return (ssize_t)total;
}

BOOL ldap_sasl_send_msg(struct ldap_connection *conn, struct ldap_message *msg,
		   const struct timeval *endtime)
{
	NTSTATUS status;
	DATA_BLOB request;
	BOOL result;
	DATA_BLOB wrapped;
	int len;
	char length[4];
	struct asn1_data asn1;
	TALLOC_CTX *mem_ctx;

	msg->messageid = conn->next_msgid++;

	if (!ldap_encode(msg, &request))
		return False;

	status = gensec_wrap(conn->gensec, 
			     msg->mem_ctx, 
			     &request,
			     &wrapped);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("gensec_wrap: %s\n",nt_errstr(status)));
		return False;
	}

	RSIVAL(length, 0, wrapped.length);

	result = (write_data(conn->sock, length, 4) == 4);
	if (!result)
		return result;

	result = (write_data(conn->sock, wrapped.data, wrapped.length) == wrapped.length);
	if (!result)
		return result;

	wrapped = data_blob(NULL, 0x4000);
	data_blob_clear(&wrapped);

	result = (read_data(conn->sock, length, 4) == 4);
	if (!result)
		return result;

	len = RIVAL(length,0);

	result = (read_data(conn->sock, wrapped.data, MIN(wrapped.length,len)) == len);
	if (!result)
		return result;

	wrapped.length = len;

	status = gensec_unwrap(conn->gensec,
			       msg->mem_ctx,
			       &wrapped,
			       &request);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("gensec_unwrap: %s\n",nt_errstr(status)));
		return False;
	}

	mem_ctx = msg->mem_ctx;
	ZERO_STRUCTP(msg);
	msg->mem_ctx = mem_ctx;

	asn1_load(&asn1, request);
	if (!ldap_decode(&asn1, msg)) {
		return False;
	}

	result = True;

	return result;
}
