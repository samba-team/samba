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

BOOL test_bind_simple(struct ldap_connection *conn, const char *userdn, const char *password)
{
	NTSTATUS status;
	BOOL ret = True;

	status = torture_ldap_bind(conn, userdn, password);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
	}

	return ret;
}

BOOL test_bind_sasl(struct ldap_connection *conn, const char *username, const char *domain, const char *password)
{
	NTSTATUS status;
	BOOL ret = True;

	status = torture_ldap_bind_sasl(conn, username, domain, password);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
	}

	return ret;
}

BOOL test_multibind(struct ldap_connection *conn, const char *userdn, const char *password)
{
	BOOL ret = True;

	printf("\nTesting multiple binds on a single connnection as anonymous and user\n");

	ret = test_bind_simple(conn, NULL, NULL);
	if (!ret) {
		printf("1st bind as anonymous failed\n");
		return ret;
	}

	ret = test_bind_simple(conn, userdn, password);
	if (!ret) {
		printf("2nd bind as authenticated user failed\n");
	}

	return ret;
}

BOOL torture_ldap_basic(int dummy)
{
        NTSTATUS status;
        struct ldap_connection *conn;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *username = lp_parm_string(-1, "torture", "username");
	const char *domain = lp_workgroup();
	const char *password = lp_parm_string(-1, "torture", "password");
	const char *userdn = lp_parm_string(-1, "torture", "ldap_userdn");
	const char *basedn = lp_parm_string(-1, "torture", "ldap_basedn");
	const char *secret = lp_parm_string(-1, "torture", "ldap_secret");
	char *url;

	mem_ctx = talloc_init("torture_ldap_basic");

	url = talloc_asprintf(mem_ctx, "ldap://%s/", host);

	status = torture_ldap_connection(&conn, url, userdn, secret);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* other basic tests here */

	if (!test_multibind(conn, userdn, secret)) {
		ret = False;
	}

	if (!test_bind_sasl(conn, username, domain, password)) {
		ret = False;
	}

	/* no more test we are closing */

	talloc_destroy(mem_ctx);

        torture_ldap_close(conn);

	return ret;
}

