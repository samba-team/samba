#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif /* HAVE_CONFIG_H */

#include "roken.h"
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif

struct passwd *
k_getpwnam (char *user)
{
     struct passwd *p;

     p = getpwnam (user);
#ifdef HAVE_GETSPNAM
     if(p)
     {
	  struct spwd *spwd;

	  spwd = getspnam (user);
	  if (spwd)
	       p->pw_passwd = spwd->sp_pwdp;
	  endspent ();
     }
#else
     endpwent ();
#endif
     return p;
}
