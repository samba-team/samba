
#include "includes.h"

BOOL test_multibind(struct ldap_connection *conn, TALLOC_CTX *mem_ctx, const char *userdn, const char *password)
{
	NTSTATUS status;
	BOOL ret = True;

	printf("\nTesting multiple binds on a single connnection as anonymous and user\n");

	status = torture_ldap_bind(conn, userdn, password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("1st bind as user over an anonymous bind failed\n");
		return False;
	}

	status = torture_ldap_bind(conn, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("2nd bind as anonymous over an authenticated bind failed\n");
		return False;
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
	const char *userdn = lp_parm_string(-1, "torture", "ldap_userdn");
	const char *basedn = lp_parm_string(-1, "torture", "ldap_basedn");
	const char *secret = lp_parm_string(-1, "torture", "ldap_secret");
	char *url;

	mem_ctx = talloc_init("torture_ldap_basic");

	url = talloc_asprintf(mem_ctx, "ldap://%s/", host);

	status = torture_ldap_connection(&conn, url, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* other basic tests here */

	if (!test_multibind(conn, mem_ctx, userdn, secret)) {
		ret = False;
	}

	/* no more test we are closing */

	talloc_destroy(mem_ctx);

        torture_ldap_close(conn);

	return ret;
}

