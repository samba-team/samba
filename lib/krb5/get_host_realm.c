#include "krb5_locl.h"

krb5_error_code
krb5_get_host_realm(krb5_context context,
		    const char *host,
		    char ***realms)
{
    *realms = malloc(2 * sizeof(char*));
    (*realms)[0] = strdup("FOO.SE");
    (*realms)[1] = NULL;
    return 0;
}
