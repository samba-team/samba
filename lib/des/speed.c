/* speed.c */
/* Copyright (C) 1993 Eric Young - see README for more details */
/* 11-Sep-92 Andrew Daviel   Support for Silicon Graphics IRIX added */
/* 06-Apr-92 Luke Brennan    Support for VMS and add extra signal calls */

#ifndef MSDOS
#define TIMES
#endif

#include <stdio.h>
#include <signal.h>
#ifndef VMS
#if !(defined(_IRIX) || defined(sgi))
#include <time.h>
#endif
#ifdef TIMES
#include <sys/types.h>
#include <sys/times.h>
#endif /* TIMES */
#else /* VMS */
#include <types.h>
struct tms {
  time_t tms_utime;
  time_t tms_stime;
  time_t tms_uchild;		/* I dunno...  */
  time_t tms_uchildsys;		/* so these names are a guess :-) */
}
#endif
#ifndef TIMES
#include <sys/timeb.h>
#endif
#include "des.h"

/* The following if from times(3) man page.  It may need to be changed */
#ifndef CLK_TCK
#ifndef VMS
#define HZ	60.0
#else /* VMS */
#define HZ	100.0
#endif
#else /* CLK_TCK */
#define HZ ((double)CLK_TCK)
#endif

#define BUFSIZE	((long)1024*8)
long run=0;

#ifdef SIGALRM
#ifdef __STDC__
#define SIGRETTYPE void
#else
#define SIGRETTYPE int
#endif 

static SIGRETTYPE
sig_done(int sig)
{
  signal(SIGALRM,sig_done);
  run=0;
}

unsigned int alarm(int seconds);
#endif

#define START	0
#define STOP	1

static double
Time_F(int s)
{
  double ret;
#ifdef TIMES
  static struct tms tstart,tend;

  if (s == START)
    {
      times(&tstart);
      return(0);
    }
  else
    {
      times(&tend);
      ret=((double)(tend.tms_utime-tstart.tms_utime))/HZ;
      return((ret == 0.0)?1e-6:ret);
    }
#else  /* !times() */
  static struct timeb tstart,tend;
  long i;

  if (s == START)
    {
      ftime(&tstart);
      return(0);
    }
  else
    {
      ftime(&tend);
      i=(long)tend.millitm-(long)tstart.millitm;
      ret=((double)(tend.time-tstart.time))+((double)i)/1000.0;
      return((ret == 0.0)?1e-6:ret);
    }
#endif
}

void
main(int argc, char **argv)
{
  long count;
  static unsigned char buf[BUFSIZE];
  static des_cblock key={0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
  des_key_schedule sch;
  double d,a,b,c;
#ifndef SIGALRM
  long ca,cb,cc,cd;
#endif

#ifndef TIMES
  printf("To get the most acurate results, try to run this\n");
  printf("program when this computer is idle.\n");
#endif

#ifndef SIGALRM
  printf("First we calculate the aproximate speed ...\n");
  des_set_key((des_cblock *)key,sch);
  count=10;
  do	{
    int i;
    count*=2;
    Time_F(START);
    for (i=count; i; i--)
      des_ecb_encrypt((des_cblock *)buf,(des_cblock *)buf,
		      &(sch[0]),DES_ENCRYPT);
    d=Time_F(STOP);
  } while (d <3);
  ca=count;
  cb=count*10;
  cc=count*10*8/BUFSIZE+1;
  cd=count/20+1;
  printf("Doing set_key %ld times\n",ca);
#define COND(d)	(count != (d))
#define COUNT(d) (d)
#else
#define COND(c)	(run)
#define COUNT(d) (count)
  signal(SIGALRM,sig_done);
  printf("Doing set_key for 10 seconds\n");
  alarm(10);
#endif

  Time_F(START);
  for (count=0,run=1; COND(ca); count++)
    des_set_key((des_cblock *)key,sch);
  d=Time_F(STOP);
  printf("%ld set_key's in %.2f seconds\n",count,d);
  a=((double)COUNT(ca))/d;

#ifdef SIGALRM
  printf("Doing des_ecb_encrypt's for 10 seconds\n");
  alarm(10);
#else
  printf("Doing des_ecb_encrypt %ld times\n",cb);
#endif
  Time_F(START);
  for (count=0,run=1; COND(cb); count++)
    des_ecb_encrypt((des_cblock *)buf,(des_cblock *)buf,
		    &(sch[0]),DES_ENCRYPT);
  d=Time_F(STOP);
  printf("%ld des_ecb_encrypt's in %.2f second\n",count,d);
  b=((double)COUNT(cb)*8)/d;

#ifdef SIGALRM
  printf("Doing des_cbc_encrypt on %ld byte blocks for 10 seconds\n",
	 BUFSIZE);
  alarm(10);
#else
  printf("Doing des_cbc_encrypt %ld times on %ld byte blocks\n",cc,
	 BUFSIZE);
#endif
  Time_F(START);
  for (count=0,run=1; COND(cc); count++)
    des_cbc_encrypt((des_cblock *)buf,(des_cblock *)buf,BUFSIZE,&(sch[0]),
		    (des_cblock *)&(key[0]),DES_ENCRYPT);
  d=Time_F(STOP);
  printf("%ld des_cbc_encrypt's of %ld byte blocks in %.2f second\n",
	 count,BUFSIZE,d);
  c=((double)COUNT(cc)*BUFSIZE)/d;

#ifdef SIGALRM
  printf("Doing crypt for 10 seconds\n");
  alarm(10);
#else
  printf("Doing crypt %ld times\n",cd);
#endif
  Time_F(START);
  for (count=0,run=1; COND(cd); count++)
    crypt("testing1","ef");
  d=Time_F(STOP);
  printf("%ld crypts in %.2f second\n",count,d);
  d=((double)COUNT(cd))/d;

  printf("set_key       per sec = %12.2f (%5.1fuS)\n",a,1.0e6/a);
  printf("DES ecb bytes per sec = %12.2f (%5.1fuS)\n",b,8.0e6/b);
  printf("DES cbc bytes per sec = %12.2f (%5.1fuS)\n",c,8.0e6/c);
  printf("crypt         per sec = %12.2f (%5.1fuS)\n",d,1.0e6/d);
}
