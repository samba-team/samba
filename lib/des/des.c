/* des.c */
/* Copyright (C) 1993 Eric Young - see README for more details */
#include <stdio.h>
#include <string.h>
#ifdef VMS
#include <types.h>
#include <stat.h>
#else
#if !defined(_IRIX)
#include <sys/types.h>
#endif
#include <sys/stat.h>
#endif
#include "des_locl.h"

void usage(void);
void doencryption(void);
int uufwrite(char *data, int size, int num, FILE *fp);
void uufwriteEnd(FILE *fp);
int uufread(char *out,int size,int num,FILE *fp);
int uuencode(unsigned char *in,int num,unsigned char *out);
int uudecode(unsigned char *in,int num,unsigned char *out);

#ifdef VMS
#define EXIT(a) exit(a&0x10000000)
#else
#define EXIT(a) exit(a)
#endif

#define BUFSIZE (8*1024)
#define VERIFY  1
#define KEYSIZ	8
#define KEYSIZB 1024 /* should hit tty line limit first :-) */
char key[KEYSIZB+1];
int do_encrypt,longk=0;
char *in=NULL,*out=NULL;
FILE *DES_IN,*DES_OUT,*CKSUM_OUT;
char uuname[200];
char uubuf[50];
int uubufnum;
#define INUUBUFN	(45*100)
#define OUTUUBUF	(65*100)
char b[OUTUUBUF];
char bb[300];
des_cblock cksum={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
char cksumname[200]="";

int cflag,eflag,dflag,kflag,bflag,fflag,sflag,uflag,flag3,hflag,error;

void
main(int argc, char **argv)
{
  int i;
  struct stat ins,outs;
  char *p;

  cflag=eflag=dflag=kflag=hflag=bflag=fflag=sflag=uflag=flag3=0,error=0;
  memset(key,0,sizeof(key));

  for (i=1; i<argc; i++)
    {
      p=argv[i];
      if ((p[0] == '-') && (p[1] != '\0'))
	{
	  p++;
	  while (*p)
	    {
	      switch (*(p++))
		{
		case '3':
		  flag3=1;
		  /*	bflag=0; */
		  longk=1;
		  break;
		case 'c':
		  cflag=1;
		  strncpy(cksumname,p,200);
		  p+=strlen(cksumname);
		  break;
		case 'C':
		  cflag=1;
		  longk=1;
		  strncpy(cksumname,p,200);
		  p+=strlen(cksumname);
		  break;
		case 'e':
		  eflag=1;
		  break;
		case 'E':
		  eflag=1;
		  longk=1;
		  break;
		case 'd':
		  dflag=1;
		  break;
		case 'D':
		  dflag=1;
		  longk=1;
		  break;
		case 'b':
		  bflag=1;
		  flag3=0;
		  break;
		case 'f':
		  fflag=1;
		  break;
		case 's':
		  sflag=1;
		  break;
		case 'u':
		  uflag=1;
		  strncpy(uuname,p,200);
		  p+=strlen(uuname);
		  break;
		case 'h':
		  hflag=1;
		  break;
		case 'k':
		  kflag=1;
		  if ((i+1) == argc)
		    {
		      fputs("must have a key with the -k option\n",stderr);
		      error=1;
		    }
		  else
		    {
		      int j;

		      i++;
		      strncpy(key,argv[i],KEYSIZB);
		      for (j=strlen(argv[i])-1; j>=0; j--)
			argv[i][j]='\0';
		    }
		  break;
		default:
		  fprintf(stderr,"'%c' unknown flag\n",p[-1]);
		  error=1;
		  break;
		}
	    }
	}
      else
	{
	  if (in == NULL)
	    in=argv[i];
	  else if (out == NULL)
	    out=argv[i];
	  else
	    error=1;
	}
    }
  if (error) usage();
  /* We either
   * do checksum or
   * do encrypt or
   * do decrypt or
   * do decrypt then ckecksum or
   * do checksum then encrypt
   */
  if (((eflag+dflag) == 1) || cflag)
    {
      if (eflag) do_encrypt=DES_ENCRYPT;
      if (dflag) do_encrypt=DES_DECRYPT;
    }
  else
    usage();

  if (	(in != NULL) &&
      (out != NULL) &&
#ifndef MSDOS
      (stat(in,&ins) != -1) &&
      (stat(out,&outs) != -1) &&
      (ins.st_dev == outs.st_dev) &&
      (ins.st_ino == outs.st_ino))
#else  /* MSDOS */
    (strcmp(in,out) == 0))
#endif
{
  fputs("input and output file are the same\n",stderr);
  EXIT(3);
}

if (!kflag)
     if (des_read_pw_string(key,KEYSIZB+1,"Enter key:",eflag?VERIFY:0))
{
  fputs("password error\n",stderr);
  EXIT(2);
}

if (in == NULL)
     DES_IN=stdin;
else if ((DES_IN=fopen(in,"r")) == NULL)
{
  perror("opening input file");
  EXIT(4);
}

CKSUM_OUT=stdout;
if (out == NULL)
{
  DES_OUT=stdout;
  CKSUM_OUT=stderr;
}
else if ((DES_OUT=fopen(out,"w")) == NULL)
{
  perror("opening output file");
  EXIT(5);
}

#ifdef MSDOS
/* This should set the file to binary mode. */
{
#include <fcntl.h>
  if (!(uflag && dflag))
    setmode(fileno(DES_IN),O_BINARY);
  if (!(uflag && eflag))
    setmode(fileno(DES_OUT),O_BINARY);
}
#endif

doencryption();
fclose(DES_IN);
fclose(DES_OUT);
EXIT(0);
}

void
usage(void)
{
  char **u;
  static char *usage[]={
    "des <options> [input-file [output-file]]",
    "options:",
    "-e         : encrypt using sunOS compatible user key to DES key conversion.",
    "-E         : encrypt ",
    "-d         : decrypt using sunOS compatible user key to DES key conversion.",
    "-D         : decrypt ",
    "-c[ckname] : generate a cbc_cksum using sunOS compatible user key to",
    "             DES key conversion and output to ckname (stdout default,",
    "             stderr if data being output on stdout).  The checksum is",
    "             generated before encryption and after decryption if used",
    "             in conjunction with -[eEdD].",
    "-C[ckname] : generate a cbc_cksum as for -c but compatible with -[ED].",
    "-k key     : use key 'key'",
    "-h         : the key that is entered will be a hexidecimal number",
    "-u[uuname] : input file is uudecoded if -[dD] or output uuencoded",
    "             data if -[eE] (uuname is the filename to put in the",
    "             uuencode header).",
    "-b         : encrypt using DES in ecb encryption mode, the defaut is",
    "             cbc mode.",
    "-3         : encrypt using tripple DES encryption.  This uses 2 keys",
    "             generated from the input key.  If the input key is less",
    "             than 8 characters long, this is equivelent to normal",
    "             encryption.  Default is tripple cbc, -b makes it tripple ecb.",
    NULL
  };
  for (u=usage; *u; u++)
    {
      fputs(*u,stderr);
      fputc('\n',stderr);
    }

  EXIT(1);
}

void
doencryption(void)
{
  register int i;
  des_key_schedule ks,ks2;
  unsigned char iv[8],iv2[8],iv3[8];
  char *p;
  int num=0,j,k,l,rem,ll,len,last,ex=0;
  des_cblock kk,k2;
  FILE *O;
  int Exit=0;
#ifndef MSDOS
  static unsigned char buf[BUFSIZE+8],obuf[BUFSIZE+8];
#else
  static unsigned char *buf=NULL,*obuf=NULL;

  if (buf == NULL)
    {
      if (    (( buf=(unsigned char *)malloc(BUFSIZE+8)) == NULL) ||
	  ((obuf=(unsigned char *)malloc(BUFSIZE+8)) == NULL))
	{
	  fputs("Not enough memory\n",stderr);
	  Exit=10;
	  goto problems;
	}
    }
#endif

  if (hflag)
    {
      j=(flag3?16:8);
      p=key;
      for (i=0; i<j; i++)
	{
	  k=0;
	  if ((*p <= '9') && (*p >= '0'))
	    k=(*p-'0')<<4;
	  else if ((*p <= 'f') && (*p >= 'a'))
	    k=(*p-'a'+10)<<4;
	  else if ((*p <= 'F') && (*p >= 'A'))
	    k=(*p-'A'+10)<<4;
	  else
	    {
	      fputs("Bad hex key\n",stderr);
	      Exit=9;
	      goto problems;
	    }
	  p++;
	  if ((*p <= '9') && (*p >= '0'))
	    k|=(*p-'0');
	  else if ((*p <= 'f') && (*p >= 'a'))
	    k|=(*p-'a'+10);
	  else if ((*p <= 'F') && (*p >= 'A'))
	    k|=(*p-'A'+10);
	  else
	    {
	      fputs("Bad hex key\n",stderr);
	      Exit=9;
	      goto problems;
	    }
	  p++;
	  if (i < 8)
	    kk[i]=k;
	  else
	    k2[i-8]=k;
	}
      des_set_key((des_cblock *)k2,ks2);
      memset(k2,0,sizeof(k2));
    }
  else if (longk || flag3)
    {
      if (flag3)
	{
	  des_string_to_2keys(key,(des_cblock *)kk,(des_cblock *)k2);
	  des_set_key((des_cblock *)k2,ks2);
	  memset(k2,0,sizeof(k2));
	}
      else
	des_string_to_key(key,(des_cblock *)kk);
    }
  else
    for (i=0; i<KEYSIZ; i++)
      {
	l=0;
	k=key[i];
	for (j=0; j<8; j++)
	  {
	    if (k&1) l++;
	    k>>=1;
	  }
	if (l & 1)
	  kk[i]=key[i]&0x7f;
	else
	  kk[i]=key[i]|0x80;
      }

  des_set_key((des_cblock *)kk,ks);
  memset(key,0,sizeof(key));
  memset(kk,0,sizeof(kk));
  /* woops - A bug that does not showup under unix :-( */
  memset(iv,0,sizeof(iv));
  memset(iv2,0,sizeof(iv2));
  memset(iv3,0,sizeof(iv3));

  l=1;
  rem=0;
  /* first read */
  if (eflag || (!dflag && cflag))
    {
      for (;;)
	{
	  num=l=fread(&(buf[rem]),1,BUFSIZE,DES_IN);
	  l+=rem;
	  num+=rem;
	  if (l < 0)
	    {
	      perror("read error");
	      Exit=6;
	      goto problems;
	    }

	  rem=l%8;
	  len=l-rem;
	  if (feof(DES_IN))
	    {
	      srandom(time(NULL));
	      for (i=7-rem; i>0; i--)
		buf[l++]=random()&0xff;
	      buf[l++]=rem;
	      ex=1;
	      len+=rem;
	    }
	  else
	    l-=rem;

	  if (cflag)
	    {
	      des_cbc_cksum((des_cblock *)buf,(des_cblock *)cksum,
			    (long)len,ks,(des_cblock *)cksum);
	      if (!eflag)
		{
		  if (feof(DES_IN)) break;
		  else continue;
		}
	    }

	  if (bflag && !flag3)
	    for (i=0; i<l; i+=8)
	      des_ecb_encrypt(
			      (des_cblock *)&(buf[i]),
			      (des_cblock *)&(obuf[i]),
			      ks,do_encrypt);
	  else if (flag3 && bflag)
	    for (i=0; i<l; i+=8)
	      des_3ecb_encrypt(
			       (des_cblock *)&(buf[i]),
			       (des_cblock *)&(obuf[i]),
			       ks,ks2,do_encrypt);
	  else if (flag3 && !bflag)
	    {
	      char tmpbuf[8];

	      if (rem) memcpy(tmpbuf,&(buf[l]),rem);
	      des_3cbc_encrypt(
			       (des_cblock *)buf,(des_cblock *)obuf,
			       (long)l,ks,ks2,(des_cblock *)iv,
			       (des_cblock *)iv2,do_encrypt);
	      if (rem) memcpy(&(buf[l]),tmpbuf,rem);
	    }
	  else
	    {
	      des_cbc_encrypt(
			      (des_cblock *)buf,(des_cblock *)obuf,
			      (long)l,ks,(des_cblock *)iv,do_encrypt);
	      if (l >= 8) memcpy(iv,&(obuf[l-8]),8);
	    }
	  if (rem) memcpy(buf,&(buf[l]),rem);

	  i=0;
	  while (i < l)
	    {
	      if (uflag)
		j=uufwrite(obuf,1,l-i,DES_OUT);
	      else
		j=fwrite(obuf,1,l-i,DES_OUT);
	      if (j == -1)
		{
		  perror("Write error");
		  Exit=7;
		  goto problems;
		}
	      i+=j;
	    }
	  if (feof(DES_IN))
	    {
	      if (uflag) uufwriteEnd(DES_OUT);
	      break;
	    }
	}
    }
  else				/* decrypt */
    {
      ex=1;
      for (;;)
	{
	  if (ex) {
	    if (uflag)
	      l=uufread(buf,1,BUFSIZE,DES_IN);
	    else
	      l=fread(buf,1,BUFSIZE,DES_IN);
	    ex=0;
	    rem=l%8;
	    l-=rem;
	  }
	  if (l < 0)
	    {
	      perror("read error");
	      Exit=6;
	      goto problems;
	    }

	  if (bflag && !flag3)
	    for (i=0; i<l; i+=8)
	      des_ecb_encrypt(
			      (des_cblock *)&(buf[i]),
			      (des_cblock *)&(obuf[i]),
			      ks,do_encrypt);
	  else if (flag3 && bflag)
	    for (i=0; i<l; i+=8)
	      des_3ecb_encrypt(
			       (des_cblock *)&(buf[i]),
			       (des_cblock *)&(obuf[i]),
			       ks,ks2,do_encrypt);
	  else if (flag3 && !bflag)
	    {
	      des_3cbc_encrypt(
			       (des_cblock *)buf,(des_cblock *)obuf,
			       (long)l,ks,ks2,(des_cblock *)iv,
			       (des_cblock *)iv2,do_encrypt);
	    }
	  else
	    {
	      des_cbc_encrypt(
			      (des_cblock *)buf,(des_cblock *)obuf,
			      (long)l,ks,(des_cblock *)iv,do_encrypt);
	      if (l >= 8) memcpy(iv,&(buf[l-8]),8);
	    }

	  if (uflag)
	    ll=uufread(&(buf[rem]),1,BUFSIZE,DES_IN);
	  else
	    ll=fread(&(buf[rem]),1,BUFSIZE,DES_IN);
	  ll+=rem;
	  rem=ll%8;
	  ll-=rem;
	  if (feof(DES_IN) && (ll == 0))
	    {
	      last=obuf[l-1];

	      if ((last > 7) || (last < 0))
		{
		  fputs("The file was not decrypted correctly.\n",
			stderr);
		  /*Exit=8;
		    goto problems;*/
		  last=0;
		}
	      l=l-8+last;
	    }
	  i=0;
	  if (cflag) des_cbc_cksum((des_cblock *)obuf,
				   (des_cblock *)cksum,(long)l/8*8,ks,
				   (des_cblock *)cksum);
	  while (i != l)
	    {
	      j=fwrite(obuf,1,l-i,DES_OUT);
	      if (j == -1)
		{
		  perror("Write error");
		  Exit=7;
		  goto problems;
		}
	      i+=j;
	    }
	  l=ll;
	  if ((l == 0) && feof(DES_IN)) break;
	}
    }
  if (cflag)
    {
      l=0;
      if (cksumname[0] != '\0')
	{
	  if ((O=fopen(cksumname,"w")) != NULL)
	    {
	      CKSUM_OUT=O;
	      l=1;
	    }
	}
      for (i=0; i<8; i++)
	fprintf(CKSUM_OUT,"%02X",cksum[i]);
      fprintf(CKSUM_OUT,"\n");
      if (l) fclose(CKSUM_OUT);
    }
 problems:
  memset(buf,0,sizeof(buf));
  memset(obuf,0,sizeof(obuf));
  memset(ks,0,sizeof(ks));
  memset(ks2,0,sizeof(ks2));
  memset(iv,0,sizeof(iv));
  memset(iv2,0,sizeof(iv2));
  memset(iv3,0,sizeof(iv3));
  memset(kk,0,sizeof(kk));
  memset(k2,0,sizeof(k2));
  memset(uubuf,0,sizeof(uubuf));
  memset(b,0,sizeof(b));
  memset(bb,0,sizeof(bb));
  memset(cksum,0,sizeof(cksum));
  if (Exit) EXIT(Exit);
}

int uufwrite(char *data, int size, int num, FILE *fp)
     
     /* We ignore this parameter but it should be > ~50 I believe */
     
     
{
  int i,j,left,rem,ret=num;
  static int start=1;

  if (start)
    {
      fprintf(fp,"begin 600 %s\n",
	      (uuname[0] == '\0')?"text.d":uuname);
      start=0;
    }

  if (uubufnum)
    {
      if (uubufnum+num < 45)
	{
	  memcpy(&(uubuf[uubufnum]),data,num);
	  uubufnum+=num;
	  return(num);
	}
      else
	{
	  i=45-uubufnum;
	  memcpy(&(uubuf[uubufnum]),data,i);
	  j=uuencode(uubuf,45,b);
	  fwrite(b,1,j,fp);
	  uubufnum=0;
	  data+=i;
	  num-=i;
	}
    }

  for (i=0; i<(num-INUUBUFN); i+=INUUBUFN)
    {
      j=uuencode(&(data[i]),INUUBUFN,b);
      fwrite(b,1,j,fp);
    }
  rem=(num-i)%45;
  left=(num-i-rem);
  if (left)
    {
      j=uuencode(&(data[i]),left,b);
      fwrite(b,1,j,fp);
      i+=left;
    }
  if (i != num)
    {
      memcpy(uubuf,&(data[i]),rem);
      uubufnum=rem;
    }
  return(ret);
}

void
uufwriteEnd(FILE *fp)
{
  int j;
  static char *end=" \nend\n";

  if (uubufnum != 0)
    {
      uubuf[uubufnum]='\0';
      uubuf[uubufnum+1]='\0';
      uubuf[uubufnum+2]='\0';
      j=uuencode(uubuf,uubufnum,b);
      fwrite(b,1,j,fp);
    }
  fwrite(end,1,strlen(end),fp);
}

int uufread(char *out, int size, int num, FILE *fp)
     
     /* should always be > ~ 60; I actually ignore this parameter :-) */
     
     
{
  int i,j,tot;
  static int done=0;
  static int valid=0;
  static int start=1;

  if (start)
    {
      for (;;)
	{
	  b[0]='\0';
	  fgets(b,300,fp);
	  if (b[0] == '\0')
	    {
	      fprintf(stderr,"no 'begin' found in uuencoded input\n");
	      return(-1);
	    }
	  if (strncmp(b,"begin ",6) == 0) break;
	}
      start=0;
    }
  if (done) return(0);
  tot=0;
  if (valid)
    {
      memcpy(out,bb,valid);
      tot=valid;
      valid=0;
    }
  for (;;)
    {
      b[0]='\0';
      fgets(b,300,fp);
      if (b[0] == '\0') break;
      i=strlen(b);
      if ((b[0] == 'e') && (b[1] == 'n') && (b[2] == 'd'))
	{
	  done=1;
	  while (!feof(fp))
	    {
	      fgets(b,300,fp);
	    }
	  break;
	}
      i=uudecode(b,i,bb);
      if (i < 0) break;
      if ((i+tot+8) > num)
	{
	  /* num to copy to make it a multiple of 8 */
	  j=(num/8*8)-tot-8;
	  memcpy(&(out[tot]),bb,j);
	  tot+=j;
	  memcpy(bb,&(bb[j]),i-j);
	  valid=i-j;
	  break;
	}
      memcpy(&(out[tot]),bb,i);
      tot+=i;
    }
  return(tot);
}

#define ccc2l(c,l)      (l =((u_int32_t)(*((c)++)))<<16, \
			 l|=((u_int32_t)(*((c)++)))<< 8, \
		 	 l|=((u_int32_t)(*((c)++))))

#define l2ccc(l,c)      (*((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))


int uuencode(unsigned char *in, int num, unsigned char *out)
{
  int j,i,n,tot=0;
  u_int32_t l;
  register unsigned char *p;
  p=out;

  for (j=0; j<num; j+=45)
    {
      if (j+45 > num)
	i=(num-j);
      else	i=45;
      *(p++)=i+' ';
      for (n=0; n<i; n+=3)
	{
	  ccc2l(in,l);
	  *(p++)=((l>>18)&0x3f)+' ';
	  *(p++)=((l>>12)&0x3f)+' ';
	  *(p++)=((l>> 6)&0x3f)+' ';
	  *(p++)=((l    )&0x3f)+' ';
	  tot+=4;
	}
      *(p++)='\n';
      tot+=2;
    }
  *p='\0';
  l=0;
  return(tot);
}

int uudecode(unsigned char *in, int num, unsigned char *out)
{
  int j,i,k;
  unsigned int n,space=0;
  u_int32_t l;
  u_int32_t w,x,y,z;
  unsigned int blank='\n'-' ';

  for (j=0; j<num; )
    {
      n= *(in++)-' ';
      if (n == blank)
	{
	  n=0;
	  in--;
	}
      if (n > 60)
	{
	  fprintf(stderr,"uuencoded line length too long\n");
	  return(-1);
	}
      j++;

      for (i=0; i<n; j+=4,i+=3)
	{
	  /* the following is for cases where spaces are
	   * removed from lines.
	   */
	  if (space)
	    {
	      w=x=y=z=0;
	    }
	  else
	    {
	      w= *(in++)-' ';
	      x= *(in++)-' ';
	      y= *(in++)-' ';
	      z= *(in++)-' ';
	    }
	  if ((w > 63) || (x > 63) || (y > 63) || (z > 63))
	    {
	      k=0;
	      if (w == blank) k=1;
	      if (x == blank) k=2;
	      if (y == blank) k=3;
	      if (z == blank) k=4;
	      space=1;
	      switch (k) {
	      case 1:	w=0; in--;
	      case 2: x=0; in--;
	      case 3: y=0; in--;
	      case 4: z=0; in--;
		break;
	      case 0:
		space=0;
		fprintf(stderr,"bad uuencoded data values\n");
		w=x=y=z=0;
		return(-1);
		break;
	      }
	    }
	  l=(w<<18)|(x<<12)|(y<< 6)|(z    );
	  l2ccc(l,out);
	}
      if (*(in++) != '\n')
	{
	  fprintf(stderr,"missing nl in uuencoded line\n");
	  w=x=y=z=0;
	  return(-1);
	}
      j++;
    }
  *out='\0';
  w=x=y=z=0;
  return(n);
}
