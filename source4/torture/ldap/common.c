/* 
   Unix SMB/CIFS Implementation.
   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2004
    
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
   
*/

#include "includes.h"
#include "libcli/ldap/ldap_client.h"
#include "torture/smbtorture.h"
#include "torture/ldap/proto.h"

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
				struct cli_credentials *creds, 
				struct loadparm_context *lp_ctx)
{
        NTSTATUS status;

	status = ldap_bind_sasl(conn, creds, lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed sasl bind with provided credentials - %s\n", 
		       nt_errstr(status));
	}
 
	return status;
}

/* open a ldap connection to a server */
NTSTATUS torture_ldap_connection(struct torture_context *tctx, 
					  struct ldap_connection **conn, 
					  const char *url)
{
	NTSTATUS status;

	if (!url) {
		printf("You must specify a url string\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	*conn = ldap4_new_connection(tctx, tctx->lp_ctx, tctx->ev);

	status = ldap_connect(*conn, url);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect to ldap server '%s' - %s\n",
		       url, nt_errstr(status));
	}

	return status;
}

/* close an ldap connection to a server */
NTSTATUS torture_ldap_close(struct ldap_connection *conn)
{
	struct ldap_message *msg;
	struct ldap_request *req;
	NTSTATUS status;

	printf("Closing the connection...\n");

	msg = new_ldap_message(conn);
	if (!msg) {
		talloc_free(conn);
		return NT_STATUS_NO_MEMORY;
	}

	printf(" Try a UnbindRequest\n");

	msg->type = LDAP_TAG_UnbindRequest;

	req = ldap_request_send(conn, msg);
	if (!req) {
		talloc_free(conn);
		return NT_STATUS_NO_MEMORY;
	}

	status = ldap_request_wait(req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("error in ldap unbind request - %s\n", nt_errstr(status));
		talloc_free(conn);
		return status;
	}

	talloc_free(conn);
	return NT_STATUS_OK;
}

NTSTATUS torture_ldap_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "ldap");
	torture_suite_add_simple_test(suite, "bench-cldap", torture_bench_cldap);
	torture_suite_add_simple_test(suite, "basic", torture_ldap_basic);
	torture_suite_add_simple_test(suite, "sort", torture_ldap_sort);
	torture_suite_add_simple_test(suite, "cldap", torture_cldap);
	torture_suite_add_simple_test(suite, "netlogon-udp", torture_netlogon_udp);
	torture_suite_add_simple_test(suite, "netlogon-tcp", torture_netlogon_tcp);
	torture_suite_add_simple_test(suite,
				      "netlogon-ping",
				      torture_netlogon_ping);
	torture_suite_add_simple_test(suite, "schema", torture_ldap_schema);
	torture_suite_add_simple_test(suite, "uptodatevector", torture_ldap_uptodatevector);
	torture_suite_add_simple_test(suite, "nested-search", test_ldap_nested_search);
	torture_suite_add_simple_test(
		suite, "session-expiry", torture_ldap_session_expiry);

	suite->description = talloc_strdup(suite, "LDAP and CLDAP tests");

	torture_register_suite(ctx, suite);

	return NT_STATUS_OK;
}
