#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "roken.h"

#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>

RCSID("$Id$");


/* Minimal implementation of inet_aton. Doesn't handle hex numbers. */

int inet_aton(char *cp, struct in_addr *adr)
{
  unsigned int a, b, c, d;

  int num;
  
  num = sscanf(cp, "%u.%u.%u.%u", &a, &b, &c, &d);

  if(num < 2)
    return 0;

  if(num == 2){
    c = b & 0xffff;
    b = b >> 16;
  }
  if(num < 4){
    d = c & 0xff;
    c = c >> 8;
  }

  if(a > 255 || b > 255 || c > 255 || d > 255)
    return 0;
  adr->s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
  return 1;
}
