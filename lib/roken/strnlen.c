/* Copyright 1996 */

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

int
strnlen(char *s, int len)
{
    int i;
    for(i = 0; i < len && s[i]; i++)
	;
    return i;
}
