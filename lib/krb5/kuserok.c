#include "krb5_locl.h"

RCSID("$Id$");

krb5_boolean
krb5_kuserok (krb5_context context,
	      krb5_principal principal,
	      const char *luser)
{
    char buf[BUFSIZ];
    struct passwd *pwd;
    FILE *f;

    pwd = getpwnam (luser);	/* XXX - Should use k_getpwnam? */
    if (pwd == NULL)
	return FALSE;
    snprintf (buf, sizeof(buf), "%s/.k5login", pwd->pw_dir);
    f = fopen (buf, "r");
    if (f == NULL)
	return FALSE;
    

}
