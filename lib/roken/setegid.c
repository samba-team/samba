#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

int
setegid(int egid)
{
#ifdef HAVE_SETREGID
    return setregid(-1, egid);
#endif

#ifdef HAVE_SETRESGID
    return setresgid(-1, egid, -1);
#endif

    return -1;
}
