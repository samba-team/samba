#include <stdlib.h>
#include <string.h>
#include "base64.h"
#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

static char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int pos(char c)
{
  char *p;
  for(p = base64; *p; p++)
    if(*p == c)
      return p - base64;
  return -1;
}

int base64_encode(const void *data, int size, char **str)
{
  char *s, *p;
  int i;
  int c;
  unsigned char *q;

  p = s = (char*)malloc(size*4/3+4);
  q = (unsigned char*)data;
  i=0;
  for(i = 0; i < size;){
    c=q[i++];
    c*=256;
    if(i < size)
      c+=q[i];
    i++;
    c*=256;
    if(i < size)
      c+=q[i];
    i++;
    p[0]=base64[(c&0x00fc0000) >> 18];
    p[1]=base64[(c&0x0003f000) >> 12];
    p[2]=base64[(c&0x00000fc0) >> 6];
    p[3]=base64[(c&0x0000003f) >> 0];
    if(i > size)
      p[3]='=';
    if(i > size+1)
      p[2]='=';
    p+=4;
  }
  *p=0;
  *str = s;
  return strlen(s);
}

int base64_decode(const char *str, void *data)
{
  const char *p;
  unsigned char *q;
  int c;
  int x;
  int done = 0;
  q=(unsigned char*)data;
  for(p=str; *p && !done; p+=4){
    x = pos(p[0]);
    if(x >= 0)
      c = x;
    else{
      done = 3;
      break;
    }
    c*=64;
    
    x = pos(p[1]);
    if(x >= 0)
      c += x;
    else
      return -1;
    c*=64;
    
    if(p[2] == '=')
      done++;
    else{
      x = pos(p[2]);
      if(x >= 0)
	c += x;
      else
	return -1;
    }
    c*=64;
    
    if(p[3] == '=')
      done++;
    else{
      if(done)
	return -1;
      x = pos(p[3]);
      if(x >= 0)
	c += x;
      else
	return -1;
    }
    if(done < 3)
      *q++=(c&0x00ff0000)>>16;
      
    if(done < 2)
      *q++=(c&0x0000ff00)>>8;
    if(done < 1)
      *q++=(c&0x000000ff)>>0;
  }
  return q - (unsigned char*)data;
}
