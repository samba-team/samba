#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#ifndef HAVE_SWAB
void
swab (char *from, char *to, int nbytes)
{
     while(nbytes >= 2) {
	  *(to + 1) = *from;
	  *to = *(from + 1);
	  to += 2;
	  from += 2;
	  nbytes -= 2;
     }
}
#endif
