#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

int
seteuid(int euid)
{
#ifdef HAVE_SETREUID
    return setreuid(-1, euid);
#endif

#ifdef HAVE_SETRESUID
    return setresuid(-1, euid, -1);
#endif

    return -1;
}
