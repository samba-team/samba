#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <netdb.h>
#include "roken.h"

/*
 * Get a verified name for `addr'.
 * If unable to find it in the DNS, return x.y.z.a
 */

void
inaddr2str(struct in_addr addr, char *s, size_t len)
{
  struct hostent *h;
  char *p;

  h = gethostbyaddr ((const char *)&addr, sizeof(addr), AF_INET);
  if (h) {
    h = gethostbyname (h->h_name);
    if(h)
      while ((p = *(h->h_addr_list)++))
	if (memcmp (p, &addr, h->h_length) == 0) {
	  strncpy (s, h->h_name, len);
	  s[len - 1] = '\0';
	  return;
	}
  }
  strncpy (s, inet_ntoa (addr), len);
  s[len - 1] = '\0';
  return;
}
