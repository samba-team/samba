/*
 * A list of default domain/local users/groups.
 */

/* Domain users and groups.  Don't forget to prepend a domain name. */

char *domain_users[] = {
	"Administrator",
	"Guest",
	NULL
};

#define NUM_DOMAIN_USERS 2

char *domain_groups[] = {
	"Domain Admins",
	"Domain Guests",
	"Domain Users",
	NULL
};

#define NUM_DOMAIN_GROUPS 3

/* Local domain groups (aliases) */

char *local_groups[] = {
	"BUILTIN/Replicator",
	"BUILTIN/Server Operators",
        "BUILTIN/Account Operators",
	"BUILTIN/Backup Operators",
        "BUILTIN/Print Operators",
	"BUILTIN/Guests",
	"BUILTIN/Users",
        "BUILTIN/Administrators",
	NULL
};

#define NUM_LOCAL_GROUPS 8
