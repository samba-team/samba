/* 
 * memmove for systems that doesn't have it 
 *
 * $Id$
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>

RCSID("$Id$");

void* memmove(void *s1, const void *s2, size_t n)
{
  char *s=(char*)s2, *d=(char*)s1;

  if(d > s){
    s+=n-1;
    d+=n-1;
    while(n){
      *d--=*s--;
      n--;
    }
  }else if(d < s)
    while(n){
      *d++=*s++;
      n--;
    }
  return s1;
}
