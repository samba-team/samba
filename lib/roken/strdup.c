#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_STRDUP
char *
strdup(const char *old)
{
	char *t = malloc(strlen(old)+1);
	if (t != 0)
		strcpy(t, old);
	return t;
}
#endif
