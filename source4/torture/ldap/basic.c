
#include "includes.h"

BOOL torture_ldap_basic(int dummy)
{
        NTSTATUS status;
        struct ldap_connection *conn;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	const char *host = lp_parm_string(-1, "torture", "host");
	char *url;

	mem_ctx = talloc_init("torture_ldap_basic");

	url = talloc_asprintf(mem_ctx, "ldap://%s/", host);

	status = torture_ldap_connection(&conn, url);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* other basic tests here */

	/* ---  nothing yet :-) --- */

	/* no more test we are closing */

	talloc_destroy(mem_ctx);

        torture_ldap_close(conn);

	return ret;
}

