#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif /* HAVE_CONFIG_H */

#include "roken.h"
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif

struct passwd *
k_getpwuid (uid_t uid)
{
     struct passwd *p;

     p = getpwuid (uid);
#ifdef HAVE_GETSPUID
     if (p)
     {
	  struct spwd *spwd;

	  spwd = getspuid (uid);
	  if (spwd)
	       p->pw_passwd = spwd->sp_pwdp;
	  endspent ();
     }
#endif
     return p;
}
