#include "krb5_locl.h"
#include "config_file.h"

RCSID("$Id$");

static int
exact_match (const char *s, const char *pattern)
{
    return strcasecmp (s, pattern) == 0;
}

static int
domain_match (const char *s, const char *pattern)
{
    const char *dot = strchr (s, '.');

    return dot && strcasecmp (dot, pattern) == 0;
}

krb5_error_code
krb5_get_host_realm(krb5_context context,
		    const char *host,
		    char ***realms)
{
    char hostname[MAXHOSTNAMELEN];
    char *res = NULL;
    const char *partial = NULL;
    const krb5_config_binding *l;

    if (host == NULL) {
	if (gethostname (hostname, sizeof(hostname)))
	    return errno;
	host = hostname;
    }

    *realms = malloc(2 * sizeof(char*));
    if (*realms == NULL)
	return ENOMEM;
    (*realms)[0] = NULL;
    (*realms)[1] = NULL;

    for(l = krb5_config_get_list (context->cf,
				  "domain_realm",
				  NULL);
	l;
	l = l->next) {
	if (l->type != STRING)
	    continue;
	if (exact_match (host, l->name)) {
	    res = l->u.string;
	    break;
	} else if (domain_match (host, l->name)) {
	    res = l->u.string;
	}
    }

    if (res) {
	(*realms)[0] = strdup(res);
	if ((*realms)[0] == NULL) {
	    free (*realms);
	    return ENOMEM;
	}
    } else {
	const char *dot = strchr (host, '.');

	if (dot != NULL) {
	    (*realms)[0] = strdup (dot + 1);
	    if ((*realms)[0] == NULL) {
		free (*realms);
		return ENOMEM;
	    }
	    strupr ((*realms)[0]);
	} else {
	    free (*realms);
	    *realms = NULL;
	}
    }

    return 0;
}
