/* read_pwd.c */
/* Copyright (C) 1993 Eric Young - see README for more details */
/* 06-Apr-92 Luke Brennan    Support for VMS */
#include "des_locl.h"
#include <string.h>
#include <signal.h>
#include <setjmp.h>

#ifndef VMS
#ifndef MSDOS
#if !(defined(_IRIX) || defined(sgi))
#ifdef CRAY
#include <termio.h>
#define sgttyb termio
#define sg_flags c_lflag
#else /* !CRAY */
#ifndef USE_TERMIO
#include <sgtty.h>
#else
#include <termio.h>
#endif
#endif
#include <sys/ioctl.h>
#else /* _IRIX */
#define USE_TERMIO
#include <termio.h>
#define sgttyb termios
#define sg_flags c_lflag
#endif
#else /* MSDOS */
#define fgets(a,b,c) noecho_fgets(a,b,c)
#ifndef NSIG
#define NSIG 32
#endif
#endif
#else /* VMS */
#include <ssdef.h>
#include <iodef.h>
#include <ttdef.h>
#include <descrip.h>
struct IOSB {
  short iosb$w_value;
  short iosb$w_count;
  long  iosb$l_info;
};
#endif

static void read_till_nl(FILE *in);
static int read_pw(char *buf, char *buff, int size, char *prompt, int verify);
#ifdef MSDOS
static int noecho_fgets();
#endif

static void (*savsig[NSIG])();
     static jmp_buf save;

static RETSIGTYPE
recsig()
{
  longjmp(save,1);
}
     
static RETSIGTYPE
pushsig()
{
  int i;

  for (i=0; i<NSIG; i++)
    savsig[i]=signal(i,recsig);
}

static RETSIGTYPE
popsig()
{
  int i;

  for (i=0; i<NSIG; i++)
    signal(i,savsig[i]);
}

int
des_read_password(des_cblock (*key), char *prompt, int verify)
{
  int ok;
  char buf[BUFSIZ],buff[BUFSIZ];

  if ((ok=read_pw(buf,buff,BUFSIZ,prompt,verify)) == 0)
    des_string_to_key(buf,key);
  memset(buf,0,BUFSIZ);
  memset(buff,0,BUFSIZ);
  return(ok);
}

int des_read_2passwords(des_cblock (*key1), des_cblock (*key2), char *prompt, int verify)
{
  int ok;
  char buf[BUFSIZ],buff[BUFSIZ];

  if ((ok=read_pw(buf,buff,BUFSIZ,prompt,verify)) == 0)
    des_string_to_2keys(buf,key1,key2);
  memset(buf,0,BUFSIZ);
  memset(buff,0,BUFSIZ);
  return(ok);
}

int des_read_pw_string(char *buf, int length, char *prompt, int verify)
{
  char buff[BUFSIZ];
  int ret;

  ret=read_pw(buf,buff,(length>BUFSIZ)?BUFSIZ:length,prompt,verify);
  memset(buff,0,BUFSIZ);
  return(ret);
}

static void read_till_nl(FILE *in)
{
#define SIZE 4
  char buf[SIZE+1];

  do	{
    fgets(buf,SIZE,in);
  } while (strchr(buf,'\n') == NULL);
}

/* return 0 if ok, 1 (or -1) otherwise */
static int
read_pw(char *buf, char *buff, int size, char *prompt, int verify)
{
#ifndef VMS
#ifndef MSDOS
#ifndef USE_TERMIO
  struct sgttyb tty_orig,tty_new;
#else
  struct termios tty_orig, tty_new;
#endif
#endif /* !MSDOS */
#else
  struct IOSB iosb;
  $DESCRIPTOR(terminal,"TT");
  long tty_orig[3], tty_new[3];
  long status;
  unsigned short channel = 0;
#endif
  volatile int ok=0;
  char *p;
  volatile int ps=0;
  FILE *tty;

#ifndef MSDOS
  if ((tty=fopen("/dev/tty","r")) == NULL)
    tty=stdin;
#else  /* MSDOS */
  if ((tty=fopen("con","r")) == NULL)
    tty=stdin;
#endif /* MSDOS */
#ifndef VMS
#ifdef TIOCGETP
#ifdef USE_TERMIO
  if (tcgetattr(fileno(tty), &tty_orig) == -1)
    return(-1);
#else
  if (ioctl(fileno(tty),TIOCGETP,(char *)&tty_orig) == -1)
    return(-1);
#endif
  memcpy(&(tty_new),&(tty_orig),sizeof(tty_orig));
#endif
#else  /* VMS */
  status = SYS$ASSIGN(&terminal,&channel,0,0);
  if (status != SS$_NORMAL)
    return(-1);
  status=SYS$QIOW(0,channel,IO$_SENSEMODE,&iosb,0,0,tty_orig,12,0,0,0,0);
  if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
    return(-1);
#endif

  if (setjmp(save))
    {
      ok=0;
      goto error;
    }
  pushsig();
  ps=1;
#ifndef VMS
#ifndef MSDOS
#ifndef USE_TERMIO
  tty_new.sg_flags &= ~ECHO;
#else
  tty_new.c_lflag &= ~ECHO;
#endif
#endif /* !MSDOS */
#ifdef TIOCSETP
#ifdef USE_TERMIO
  if (tcsetattr(fileno(tty), TCSANOW, &tty_new) == -1)
    return(-1);
#else
  if (ioctl(fileno(tty),TIOCSETP,(char *)&tty_new) == -1)
    return(-1);
#endif
#endif
#else  /* VMS */
  tty_new[0] = tty_orig[0];
  tty_new[1] = tty_orig[1] | TT$M_NOECHO;
  tty_new[2] = tty_orig[2];
  status = SYS$QIOW(0,channel,IO$_SETMODE,&iosb,0,0,tty_new,12,0,0,0,0);
  if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
    return(-1);
#endif /* VMS */
  ps=2;

  while (!ok)
    {
      fputs(prompt,stderr);
      fflush(stderr);

      buf[0]='\0';
      fgets(buf,size,tty);
      if (feof(tty)) goto error;
      if ((p=(char *)strchr(buf,'\n')) != NULL)
	*p='\0';
      else	read_till_nl(tty);
      if (verify)
	{
	  fprintf(stderr,"\nVerifying password %s",prompt);
	  fflush(stderr);
	  buff[0]='\0';
	  fgets(buff,size,tty);
	  if (feof(tty)) goto error;
	  if ((p=(char *)strchr(buff,'\n')) != NULL)
	    *p='\0';
	  else	read_till_nl(tty);
				
	  if (strcmp(buf,buff) != 0)
	    {
	      fprintf(stderr,"\nVerify failure - try again\n");
	      fflush(stderr);
	      continue;
	    }
	}
      ok=1;
    }

 error:
  fprintf(stderr,"\n");
  /* What can we do if there is an error? */
#ifndef VMS
#ifdef TIOCSETP
#ifdef USE_TERMIO
  if (ps >= 2) tcsetattr(fileno(tty), TCSANOW, &tty_orig);
#else
  if (ps >= 2) ioctl(fileno(tty),TIOCSETP,(char *)&tty_orig);
#endif
#endif
#else  /* VMS */
  if (ps >= 2)
    status = SYS$QIOW(0,channel,IO$_SETMODE,&iosb,0,0
		      ,tty_orig,12,0,0,0,0);
#endif /* VMS */
	
  if (ps >= 1) popsig();
  if (stdin != tty) fclose(tty);
#ifdef VMS
  status = SYS$DASSGN(channel);
#endif
  return(!ok);
}

#ifdef MSDOS
static int noecho_fgets(buf,size,tty)
     char *buf;
     int size;
     FILE *tty;
{
  int i;
  char *p;

  p=buf;
  for (;;)
    {
      if (size == 0)
	{
	  *p='\0';
	  break;
	}
      size--;
      i=getch();
      if (i == '\r') i='\n';
      *(p++)=i;
      if (i == '\n')
	{
	  *p='\0';
	  break;
	}
    }
}
#endif
