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
#include "libcli/ldap/ldap.h"
#include "auth/gensec/gensec.h"

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

NTSTATUS torture_ldap_bind_sasl(struct ldap_connection *conn, 
				struct cli_credentials *creds)
{
        NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int result;

	if (!conn) {
		printf("We need a valid ldap_connection structure and be connected\n");
		return status;
	}

	result = ldap_bind_sasl(conn, creds);
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
				const char *url)
{
        NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	if (!url) {
		printf("You must specify a url string\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	*conn = ldap_connect(mem_ctx, url);
	if (!*conn) {
		printf("Failed to initialize ldap_connection structure\n");
		return status;
	}

	return NT_STATUS_OK;
}

/* open a ldap connection to a server */
NTSTATUS torture_ldap_connection2(TALLOC_CTX *mem_ctx, struct ldap_connection **conn, 
				const char *url, const char *userdn, const char *password)
{
        NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int ret;

	status = torture_ldap_connection(mem_ctx, conn, url);
	NT_STATUS_NOT_OK_RETURN(status);

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
