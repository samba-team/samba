/* rand_key.c */
/* Copyright (C) 1993 Eric Young - see README for more details */
#include "des_locl.h"

int des_random_key(unsigned char *ret)
{
  des_key_schedule ks;
  static u_int32_t c=0;
  static unsigned short pid=0;
  static des_cblock data={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
  des_cblock key;
  unsigned char *p;
  u_int32_t t, now;

  now=(unsigned long)time(NULL);
#ifdef MSDOS
  pid=1;
#else
  if (!pid) pid=getpid();
#endif
 try_again:
  p=key;
  t=now;
  l2c(t,p);
  t=(u_int32_t)((pid)|((c++)<<16));
  l2c(t,p);

  des_set_odd_parity((des_cblock *)data);
  des_set_key((des_cblock *)data,ks);
  des_cbc_cksum((des_cblock *)key,(des_cblock *)key,
		(long)sizeof(key),ks,(des_cblock *)data);
  des_set_odd_parity((des_cblock *)key);
  des_cbc_cksum((des_cblock *)key,(des_cblock *)key,
		(long)sizeof(key),ks,(des_cblock *)data);

  memcpy(ret,key,sizeof(key));
  memset(key,0,sizeof(key));
  memset(ks,0,sizeof(ks));
  t=0;
  /* random key must have odd parity and not be weak */
  des_set_odd_parity((des_cblock *)ret);
  if (des_is_weak_key((des_cblock *)ret)) goto try_again;
  return(0);
}
