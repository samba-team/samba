#include <ldap.h>

struct lldb_private {
	char **options;
	const char *basedn;
	LDAP *ldap;
	int last_rc;
};
