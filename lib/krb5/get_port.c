#include <krb5_locl.h>

RCSID("$Id$");

int
krb5_getportbyname (const char *service,
		    const char *proto,
		    int default_port)
{
    struct servent *sp;

    if ((sp = getservbyname (service, proto)) == NULL) {
	 fprintf (stderr, "%s/%s unknown service, "
		  "using default port %d\n", service, proto,
		  ntohs(default_port));
	 return default_port;
    } else
	 return sp->s_port;
}
