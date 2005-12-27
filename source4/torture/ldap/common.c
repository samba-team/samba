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

NTSTATUS torture_ldap_bind(struct ldap_connection *conn, const char *userdn, const char *password)
{
	NTSTATUS status;

	status = ldap_bind_simple(conn, userdn, password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to bind with provided credentials - %s\n", 
		       nt_errstr(status));
	}

	return status;
}

NTSTATUS torture_ldap_bind_sasl(struct ldap_connection *conn, 
				struct cli_credentials *creds)
{
        NTSTATUS status;

	status = ldap_bind_sasl(conn, creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed sasl bind with provided credentials - %s\n", 
		       nt_errstr(status));
	}
 
	return status;
}

/* open a ldap connection to a server */
NTSTATUS torture_ldap_connection(TALLOC_CTX *mem_ctx, struct ldap_connection **conn, 
				const char *url)
{
	NTSTATUS status;

	if (!url) {
		printf("You must specify a url string\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	*conn = ldap_new_connection(mem_ctx, NULL);

	status = ldap_connect(*conn, url);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect to ldap server '%s' - %s\n",
		       url, nt_errstr(status));
	}

	return status;
}

/* open a ldap connection to a server */
NTSTATUS torture_ldap_connection2(TALLOC_CTX *mem_ctx, struct ldap_connection **conn, 
				const char *url, const char *userdn, const char *password)
{
        NTSTATUS status;

	status = torture_ldap_connection(mem_ctx, conn, url);
	NT_STATUS_NOT_OK_RETURN(status);

	status = ldap_bind_simple(*conn, userdn, password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed a simple ldap bind - %s\n", ldap_errstr(*conn, status));
	}
 
	return status;
}

/* close an ldap connection to a server */
NTSTATUS torture_ldap_close(struct ldap_connection *conn)
{
	talloc_free(conn);
	return NT_STATUS_OK;
}
