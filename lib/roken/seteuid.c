#include <config.h>

RCSID("$Id$");

int seteuid(int euid)
{
#ifdef HAVE_SETREUID
    return setreuid(-1, euid);
#endif

#ifdef HAVE_SETRESUID
    return setresuid(-1, euid, -1);
#endif

    return -1
}
