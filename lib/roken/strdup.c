#include "bsd_locl.h"

#ifndef HAVE_STRDUP
static char *
strdup(const char *old)
{
	char *t = malloc(strlen(old)+1);
	if (t != 0)
		strcpy(t, old);
	return t;
}
#endif
