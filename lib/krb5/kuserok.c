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
    char *realm;
    krb5_principal local_principal;
    krb5_error_code ret;
    krb5_boolean b;

    ret = krb5_get_default_realm (context, &realm);
    if (ret) {
	free (realm);
	return FALSE;
    }

    ret = krb5_build_principal (context,
				&local_principal,
				strlen(realm),
				realm,
				luser,
				NULL);
    free (realm);
    if (ret)
	return FALSE;

    b = krb5_principal_compare (context, principal, local_principal);
    krb5_free_principal (context, local_principal);
    if (b)
	return TRUE;

    pwd = getpwnam (luser);	/* XXX - Should use k_getpwnam? */
    if (pwd == NULL)
	return FALSE;
    snprintf (buf, sizeof(buf), "%s/.k5login", pwd->pw_dir);
    f = fopen (buf, "r");
    if (f == NULL)
	return FALSE;
    while (fgets (buf, sizeof(buf), f) != NULL) {
	krb5_principal tmp;

	if(buf[strlen(buf) - 1] == '\n')
	    buf[strlen(buf) - 1] = '\0';

	ret = krb5_parse_name (context, buf, &tmp);
	if (ret) {
	    fclose (f);
	    return FALSE;
	}
	b = krb5_principal_compare (context, principal, tmp);
	krb5_free_principal (context, tmp);
	if (b) {
	    fclose (f);
	    return TRUE;
	}
    }
    fclose (f);
    return FALSE;
}
