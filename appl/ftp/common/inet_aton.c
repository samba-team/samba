#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

RCSID("$Id$");

int inet_aton(char *cp, struct in_addr *adr)
{
  int a, b, c, d;

  if(sscanf(cp, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
    return 0;
  if(a < 0 || a > 255 ||
     b < 0 || b > 255 ||
     c < 0 || c > 255 ||
     d < 0 || d > 255)
    return 0;
  adr->s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
  return 1;
}
