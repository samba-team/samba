#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_get_krbhst (krb5_context context,
		 const krb5_realm *realm,
		 char ***hostlist)
{
    char **res;
    unsigned max, count;
    krb5_config_binding *pointer;
    char *r;
    char *h;
    krb5_boolean done;
    char **tmp;

     r = *realm;

    count = 0;
    max = 10;
    res = malloc(max * sizeof(*res));
    if(res == NULL)
	return KRB5_REALM_UNKNOWN;
    pointer = NULL;
    for(done = FALSE; !done;) {
	char *h = (char *)krb5_config_get_next (context->cf,
						&pointer,
						STRING,
						"realms",
						r,
						"kdc",
						NULL);

	if (count > max - 2) {
	    max += 10;
	    tmp = realloc (res, max * sizeof(*res));
	    if (tmp == NULL) {
		res[count] = NULL;
		free (r);
		krb5_free_krbhst (context, res);
		return KRB5_REALM_UNKNOWN;
	    }
	    res = tmp;
	}
	if (h == NULL) {
	    done = TRUE;
	    asprintf(&res[count], "kerberos.%s", r);
	} else {
	    res[count] = strdup(h);
	}
	if (res[count] == NULL) {
	    free(r);
	    krb5_free_krbhst (context, res);
	    return KRB5_REALM_UNKNOWN;
	}
	++count;
    }

    /* There should always be room for the NULL here */
    res[count++] = NULL;
    tmp = realloc (res, count * sizeof(*res));
    if (tmp == NULL) {
	krb5_free_krbhst (context, res);
	return KRB5_REALM_UNKNOWN;
    }
    res = tmp;
    *hostlist = res;
    return 0;
}

krb5_error_code
krb5_free_krbhst (krb5_context context,
		  char **hostlist)
{
    char **p;

    for (p = hostlist; *p; ++p)
	free (*p);
    free (hostlist);
    return 0;
}
