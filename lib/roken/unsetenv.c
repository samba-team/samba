#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <stdlib.h>
#include <string.h>

#include "roken.h"

extern char **environ;

/*
 * unsetenv --
 */
void
unsetenv(const char *name)
{
  int len;
  const char *np;
  char **p;

  if (name == 0 || environ == 0)
    return;

  for (np = name; *np && *np != '='; np++)
    /* nop */;
  len = np - name;
  
  for (p = environ; *p != 0; p++)
    if (strncmp(*p, name, len) == 0 && (*p)[len] == '=')
      break;

  for (; *p != 0; p++)
    *p = *(p + 1);
}

