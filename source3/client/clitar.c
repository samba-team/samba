/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Tar Extensions
   Copyright (C) Ricky Poulten 1995
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#include "includes.h"
#include "clitar.h"

extern BOOL recurse;

#define SEPARATORS " \t\n\r"
extern int DEBUGLEVEL;
extern int Client;

/* These defines are for the do_setrattr routine, to indicate
 * setting and reseting of file attributes in the function call */
#define ATTRSET 1
#define ATTRRESET 0

static int attribute = aDIR | aSYSTEM | aHIDDEN;

#ifndef CLIENT_TIMEOUT
#define CLIENT_TIMEOUT (30*1000)
#endif

static char *tarbuf;
static int tp, ntarf, tbufsiz;
/* Incremental mode */
BOOL tar_inc=False;
/* Reset archive bit */
BOOL tar_reset=False;
/* Include / exclude mode (true=include, false=exclude) */
BOOL tar_excl=True;
char tar_type='\0';
static char **cliplist=NULL;
static int clipn=0;

extern file_info def_finfo;
extern BOOL lowercase;
extern int cnum;
extern BOOL readbraw_supported;
extern int max_xmit;
extern pstring cur_dir;
extern int get_total_time_ms;
extern int get_total_size;
extern int Protocol;

int blocksize=20;
int tarhandle;

static void writetarheader();
static void do_atar();
static void do_tar();
static void oct_it();
static void fixtarname();
static int dotarbuf();
static void dozerobuf();
static void dotareof();
static void initarbuf();
static int do_setrattr();

/* restore functions */
static long readtarheader();
static long unoct();
static void do_tarput();
static void unfixtarname();

/*
 * tar specific utitlities
 */

/****************************************************************************
Write a tar header to buffer
****************************************************************************/
static void writetarheader(int f,  char *aname, int size, time_t mtime,
		    char *amode)
{
  union hblock hb;
  int i, chk, l;
  char *jp;

  memset(hb.dummy, 0, sizeof(hb.dummy));
  
  l=strlen(aname);
  if (l >= NAMSIZ)
    {
      DEBUG(0, ("tar file %s name length exceeds NAMSIZ\n", aname));
    }

  /* use l + 1 to do the null too */
  fixtarname(hb.dbuf.name, aname, (l >= NAMSIZ) ? NAMSIZ : l + 1);

  if (lowercase)
    strlower(hb.dbuf.name);

  /* write out a "standard" tar format header */

  hb.dbuf.name[NAMSIZ-1]='\0';
  strcpy(hb.dbuf.mode, amode);
  oct_it(0L, 8, hb.dbuf.uid);
  oct_it(0L, 8, hb.dbuf.gid);
  oct_it((long) size, 13, hb.dbuf.size);
  oct_it((long) mtime, 13, hb.dbuf.mtime);
  memcpy(hb.dbuf.chksum, "        ", sizeof(hb.dbuf.chksum));
  hb.dbuf.linkflag='0';
  memset(hb.dbuf.linkname, 0, NAMSIZ);
  
  for (chk=0, i=sizeof(hb.dummy), jp=hb.dummy; --i>=0;) chk+=(0xFF & *jp++);

  oct_it((long) chk, 8, hb.dbuf.chksum);
  hb.dbuf.chksum[6] = '\0';

  (void) dotarbuf(f, hb.dummy, sizeof(hb.dummy));
}

/****************************************************************************
Read a tar header into a hblock structure, and validate
***************************************************************************/
static long readtarheader(union hblock *hb, file_info *finfo, char *prefix)
{
  long chk, fchk;
  int i;
  char *jp;

  /*
   * read in a "standard" tar format header - we're not that interested
   * in that many fields, though
   */

  /* check the checksum */
  for (chk=0, i=sizeof(hb->dummy), jp=hb->dummy; --i>=0;) chk+=(0xFF & *jp++);

  if (chk == 0)
    return chk;

  /* compensate for blanks in chksum header */
  for (i=sizeof(hb->dbuf.chksum), jp=hb->dbuf.chksum; --i>=0;)
    chk-=(0xFF & *jp++);

  chk += ' ' * sizeof(hb->dbuf.chksum);

  fchk=unoct(hb->dbuf.chksum, sizeof(hb->dbuf.chksum));

  DEBUG(5, ("checksum totals chk=%d fchk=%d chksum=%s\n",
	    chk, fchk, hb->dbuf.chksum));

  if (fchk != chk)
    {
      DEBUG(0, ("checksums don't match %d %d\n", fchk, chk));
      return -1;
    }

  strcpy(finfo->name, prefix);

  /* use l + 1 to do the null too; do prefix - prefcnt to zap leading slash */
  unfixtarname(finfo->name + strlen(prefix), hb->dbuf.name,
	       strlen(hb->dbuf.name) + 1);

/* can't handle links at present */
  if (hb->dbuf.linkflag != '0') {
    if (hb->dbuf.linkflag == 0) {
      DEBUG(6, ("Warning: NULL link flag (gnu tar archive ?) %s\n",
		finfo->name));
    } else { 
      DEBUG(0, ("this tar file appears to contain some kind of link - ignoring\n"));
      return -2;
    }
  }
    
  if ((unoct(hb->dbuf.mode, sizeof(hb->dbuf.mode)) & S_IFDIR)
    || (*(finfo->name+strlen(finfo->name)-1) == '\\'))
    {
      finfo->mode=aDIR;
    }
  else
    finfo->mode=0; /* we don't care about mode at the moment, we'll
		    * just make it a regular file */
  /*
   * Bug fix by richard@sj.co.uk
   *
   * REC: restore times correctly (as does tar)
   * We only get the modification time of the file; set the creation time
   * from the mod. time, and the access time to current time
   */
  finfo->mtime = finfo->ctime = strtol(hb->dbuf.mtime, NULL, 8);
  finfo->atime = time(NULL);
  finfo->size = unoct(hb->dbuf.size, sizeof(hb->dbuf.size));

  return True;
}

/****************************************************************************
Write out the tar buffer to tape or wherever
****************************************************************************/
static int dotarbuf(int f, char *b, int n)
{
  int fail=1, writ=n;

  /* This routine and the next one should be the only ones that do write()s */
  if (tp + n >= tbufsiz)
    {
      int diff;

      diff=tbufsiz-tp;
      memcpy(tarbuf + tp, b, diff);
      fail=fail && (1+write(f, tarbuf, tbufsiz));
      n-=diff;
      b+=diff;
      tp=0;

      while (n >= tbufsiz)
	{
	  fail=fail && (1 + write(f, b, tbufsiz));
	  n-=tbufsiz;
	  b+=tbufsiz;
	}
    }
  if (n>0) {
    memcpy(tarbuf+tp, b, n);
    tp+=n;
  }

  return(fail ? writ : 0);
}

/****************************************************************************
Write a zeros to buffer / tape
****************************************************************************/
static void dozerobuf(int f, int n)
{
  /* short routine just to write out n zeros to buffer -
   * used to round files to nearest block
   * and to do tar EOFs */

  if (n+tp >= tbufsiz)
    {
      memset(tarbuf+tp, 0, tbufsiz-tp);
      write(f, tarbuf, tbufsiz);
      memset(tarbuf, 0, (tp+=n-tbufsiz));
    }
  else
    {
      memset(tarbuf+tp, 0, n);
      tp+=n;
    }
}

/****************************************************************************
Malloc tape buffer
****************************************************************************/
static void initarbuf()
{
  /* initialize tar buffer */
  tbufsiz=blocksize*TBLOCK;
  tarbuf=malloc(tbufsiz);

  /* reset tar buffer pointer and tar file counter */
  tp=0; ntarf=0;
}

/****************************************************************************
Write two zero blocks at end of file
****************************************************************************/
static void dotareof(int f)
{
  struct stat stbuf;
  /* Two zero blocks at end of file, write out full buffer */

  (void) dozerobuf(f, TBLOCK);
  (void) dozerobuf(f, TBLOCK);

  if (fstat(f, &stbuf) == -1)
    {
      DEBUG(0, ("Couldn't stat file handle\n"));
      return;
    }

  /* Could be a pipe, in which case S_ISREG should fail,
   * and we should write out at full size */
  if (tp > 0) write(f, tarbuf, S_ISREG(stbuf.st_mode) ? tp : tbufsiz);
}

/****************************************************************************
(Un)mangle DOS pathname, make nonabsolute
****************************************************************************/
static void fixtarname(char *tptr, char *fp, int l)
{
  /* add a '.' to start of file name, convert from ugly dos \'s in path
   * to lovely unix /'s :-} */

  *tptr++='.';
#ifdef KANJI
  while (l > 0) {
    if (is_shift_jis (*fp)) {
      *tptr++ = *fp++;
      *tptr++ = *fp++;
      l -= 2;
    } else if (is_kana (*fp)) {
      *tptr++ = *fp++;
      l--;
    } else if (*fp == '\\') {
      *tptr++ = '/';
      fp++;
      l--;
    } else {
      *tptr++ = *fp++;
      l--;
    }
  }
#else
  while (l--) { *tptr=(*fp == '\\') ? '/' : *fp; tptr++; fp++; }
#endif
}

/****************************************************************************
Convert from decimal to octal string
****************************************************************************/
static void oct_it (register long value, register int ndgs, register char *p)
{
  /* Converts long to octal string, pads with leading zeros */

  /* skip final null, but do final space */
  --ndgs;
  p[--ndgs] = ' ';
 
  /* Loop does at least one digit */
  do {
      p[--ndgs] = '0' + (char) (value & 7);
      value >>= 3;
    }
  while (ndgs > 0 && value != 0);
 
  /* Do leading zeros */
  while (ndgs > 0)
    p[--ndgs] = '0';
}

/****************************************************************************
Convert from octal string to long
***************************************************************************/
static long unoct(char *p, int ndgs)
{
  long value=0;
  /* Converts octal string to long, ignoring any non-digit */

  while (--ndgs)
    {
      if (isdigit(*p))
        value = (value << 3) | (long) (*p - '0');

      p++;
    }

  return value;
}

/****************************************************************************
Compare two strings in a slash insensitive way
***************************************************************************/
int strslashcmp(const char *s1, const char *s2)
{
  while(*s1 && *s2 &&
	(*s1 == *s2
	 || tolower(*s1) == tolower(*s2)
	 || (*s1 == '\\' && *s2=='/')
	 || (*s1 == '/' && *s2=='\\'))) {
	  s1++; s2++;
  }

  return *s1-*s2;
}

/*
 * general smb utility functions
 */
/****************************************************************************
Set DOS file attributes
***************************************************************************/
static int do_setrattr(char *fname, int attr, int setit)
{
  /*
   * First get the existing attribs from existing file
   */
  char *inbuf,*outbuf;
  char *p;
  pstring name;
  int fattr;

  strcpy(name,fname);
  strcpy(fname,"\\");
  strcat(fname,name);

  inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if (!inbuf || !outbuf)
    {
      DEBUG(0,("out of memory\n"));
      return False;
    }

  /* send an smb getatr message */

  memset(outbuf,0,smb_size);
  set_message(outbuf,0,2 + strlen(fname),True);
  CVAL(outbuf,smb_com) = SMBgetatr;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  p = smb_buf(outbuf);
  *p++ = 4;
  strcpy(p,fname);
  p += (strlen(fname)+1);
  
  *p++ = 4;
  *p++ = 0;

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (CVAL(inbuf,smb_rcls) != 0)
    DEBUG(5,("getatr: %s\n",smb_errstr(inbuf)));
  else
    {
      DEBUG(5,("\nattr 0x%X  time %d  size %d\n",
	       (int)CVAL(inbuf,smb_vwv0),
	       SVAL(inbuf,smb_vwv1),
	       SVAL(inbuf,smb_vwv3)));
    }

  fattr=CVAL(inbuf,smb_vwv0);

  /* combine found attributes with bits to be set or reset */

  attr=setit ? (fattr | attr) : (fattr & ~attr);

  /* now try and set attributes by sending smb reset message */

  /* clear out buffer and start again */
  memset(outbuf,0,smb_size);
  set_message(outbuf,8,4 + strlen(fname),True);
  CVAL(outbuf,smb_com) = SMBsetatr;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,attr);

  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,fname);
  p += (strlen(fname)+1);
  
  *p++ = 4;
  *p++ = 0;

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s setting attributes on file %s\n",
	    smb_errstr(inbuf), fname));
      free(inbuf);free(outbuf);
      return(False);
    }

  free(inbuf);free(outbuf);
  return(True);
}

/****************************************************************************
Create a file on a share
***************************************************************************/
static BOOL smbcreat(file_info finfo, int *fnum, char *inbuf, char *outbuf)
{
  char *p;
  /* *must* be called with buffer ready malloc'ed */
  /* open remote file */
  
  memset(outbuf,0,smb_size);
  set_message(outbuf,3,2 + strlen(finfo.name),True);
  CVAL(outbuf,smb_com) = SMBcreate;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);
  
  SSVAL(outbuf,smb_vwv0,finfo.mode);
  put_dos_date3(outbuf,smb_vwv1,finfo.mtime);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,finfo.name);
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s opening remote file %s\n",smb_errstr(inbuf),
	       finfo.name));
      return 0;
    }
  
  *fnum = SVAL(inbuf,smb_vwv0);
  return True;
}

/****************************************************************************
Write a file to a share
***************************************************************************/
static BOOL smbwrite(int fnum, int n, int low, int high, int left,
		     char *bufferp, char *inbuf, char *outbuf)
{
  /* *must* be called with buffer ready malloc'ed */

  memset(outbuf,0,smb_size);
  set_message(outbuf,5,n + 3,True);
  
  memcpy(smb_buf(outbuf)+3, bufferp, n);
  
  set_message(outbuf,5,n + 3, False);
  CVAL(outbuf,smb_com) = SMBwrite;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);
  
  SSVAL(outbuf,smb_vwv0,fnum);
  SSVAL(outbuf,smb_vwv1,n);
  SIVAL(outbuf,smb_vwv2,low);
  SSVAL(outbuf,smb_vwv4,left);
  CVAL(smb_buf(outbuf),0) = 1;
  SSVAL(smb_buf(outbuf),1,n);

  send_smb(Client,outbuf); 
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s writing remote file\n",smb_errstr(inbuf)));
      return False;
    }
  
  if (n != SVAL(inbuf,smb_vwv0))
    {
      DEBUG(0,("Error: only wrote %d bytes out of %d\n",
	       SVAL(inbuf,smb_vwv0), n));
      return False;
    }

  return True;
}

/****************************************************************************
Close a file on a share
***************************************************************************/
static BOOL smbshut(file_info finfo, int fnum, char *inbuf, char *outbuf)
{
  /* *must* be called with buffer ready malloc'ed */

  memset(outbuf,0,smb_size);
  set_message(outbuf,3,0,True);
  CVAL(outbuf,smb_com) = SMBclose;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);
  
  SSVAL(outbuf,smb_vwv0,fnum);
  put_dos_date3(outbuf,smb_vwv1,finfo.mtime);
  
  DEBUG(3,("Setting date to %s (0x%X)",
	   asctime(LocalTime(&finfo.mtime)),
	   finfo.mtime));
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s closing remote file %s\n",smb_errstr(inbuf),
	       finfo.name));
      return False;
    }

  return True;
}

/****************************************************************************
Verify existence of path on share
***************************************************************************/
static BOOL smbchkpath(char *fname, char *inbuf, char *outbuf)
{
  char *p;

  memset(outbuf,0,smb_size);
  set_message(outbuf,0,4 + strlen(fname),True);
  CVAL(outbuf,smb_com) = SMBchkpth;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  p = smb_buf(outbuf);
  *p++ = 4;
  strcpy(p,fname);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  DEBUG(5,("smbchkpath: %s\n",smb_errstr(inbuf)));

  return(CVAL(inbuf,smb_rcls) == 0);
}

/****************************************************************************
Make a directory on share
***************************************************************************/
static BOOL smbmkdir(char *fname, char *inbuf, char *outbuf)
{
  /* *must* be called with buffer ready malloc'ed */
  char *p;

  memset(outbuf,0,smb_size);
  set_message(outbuf,0,2 + strlen(fname),True);
  
  CVAL(outbuf,smb_com) = SMBmkdir;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,fname);
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s making remote directory %s\n",
	       smb_errstr(inbuf),fname));
      return(False);
    }

  return(True);
}

/****************************************************************************
Ensure a remote path exists (make if necessary)
***************************************************************************/
static BOOL ensurepath(char *fname, char *inbuf, char *outbuf)
{
  /* *must* be called with buffer ready malloc'ed */
  /* ensures path exists */

  pstring partpath, ffname;
  char *p=fname, *basehack;

  *partpath = 0;

  /* fname copied to ffname so can strtok */

  strcpy(ffname, fname);

  /* do a `basename' on ffname, so don't try and make file name directory */
  if ((basehack=strrchr(ffname, '\\')) == NULL)
    return True;
  else
    *basehack='\0';

  p=strtok(ffname, "\\");

  while (p)
    {
      strcat(partpath, p);

      if (!smbchkpath(partpath, inbuf, outbuf)) {
	if (!smbmkdir(partpath, inbuf, outbuf))
	  {
	    DEBUG(0, ("Error mkdirhiering\n"));
	    return False;
	  }
	else
	  DEBUG(3, ("mkdirhiering %s\n", partpath));

      }

      strcat(partpath, "\\");
      p = strtok(NULL,"/\\");
    }

    return True;
}

/*
 * smbclient functions
 */
/****************************************************************************
append one remote file to the tar file
***************************************************************************/
static void do_atar(char *rname,char *lname,file_info *finfo1)
{
  int fnum;
  uint32 nread=0;
  char *p;
  char *inbuf,*outbuf;
  file_info finfo;
  BOOL close_done = False;
  BOOL shallitime=True;
  BOOL ignore_close_error = False;
  char *dataptr=NULL;
  int datalen=0;

  struct timeval tp_start;
  GetTimeOfDay(&tp_start);

  if (finfo1) 
    finfo = *finfo1;
  else
    finfo = def_finfo;

  inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if (!inbuf || !outbuf)
    {
      DEBUG(0,("out of memory\n"));
      return;
    }

  memset(outbuf,0,smb_size);
  set_message(outbuf,15,1 + strlen(rname),True);

  CVAL(outbuf,smb_com) = SMBopenX;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0xFF);
  SSVAL(outbuf,smb_vwv2,1);
  SSVAL(outbuf,smb_vwv3,(DENY_NONE<<4));
  SSVAL(outbuf,smb_vwv4,aSYSTEM | aHIDDEN);
  SSVAL(outbuf,smb_vwv5,aSYSTEM | aHIDDEN);
  SSVAL(outbuf,smb_vwv8,1);

  p = smb_buf(outbuf);
  strcpy(p,rname);
  p = skip_string(p,1);

  dos_clean_name(rname);

  /* do a chained openX with a readX? */  
  if (finfo.size > 0)
    {
      SSVAL(outbuf,smb_vwv0,SMBreadX);
      SSVAL(outbuf,smb_vwv1,PTR_DIFF(p,outbuf) - 4);
      memset(p,0,200);
      p -= smb_wct;
      SSVAL(p,smb_wct,10);
      SSVAL(p,smb_vwv0,0xFF);
      SSVAL(p,smb_vwv5,MIN(max_xmit-500,finfo.size));
      SSVAL(p,smb_vwv9,MIN(0xFFFF,finfo.size));
      smb_setlen(outbuf,smb_len(outbuf)+11*2+1);  
    }
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      if (CVAL(inbuf,smb_rcls) == ERRSRV &&
	  SVAL(inbuf,smb_err) == ERRnoresource &&
	  reopen_connection(inbuf,outbuf))
	{
	  do_atar(rname,lname,finfo1);
	  free(inbuf);free(outbuf);
	  return;
	}

      DEBUG(0,("%s opening remote file %s\n",smb_errstr(inbuf),rname));
      free(inbuf);free(outbuf);
      return;
    }

  strcpy(finfo.name,rname);
  if (!finfo1)
    {
      finfo.mode = SVAL(inbuf,smb_vwv3);
      finfo.size = IVAL(inbuf,smb_vwv4);
      finfo.mtime = make_unix_date3(inbuf+smb_vwv6);
      finfo.atime = finfo.ctime = finfo.mtime;
    }

  DEBUG(3,("file %s attrib 0x%X\n",finfo.name,finfo.mode));

  fnum = SVAL(inbuf,smb_vwv2);

  if (tar_inc && !(finfo.mode & aARCH))
    {
      DEBUG(4, ("skipping %s - archive bit not set\n", finfo.name));
      shallitime=0;
    }
  else
    {
      if (SVAL(inbuf,smb_vwv0) == SMBreadX)
	{
	  p = (inbuf+4+SVAL(inbuf,smb_vwv1)) - smb_wct;
	  datalen = SVAL(p,smb_vwv5);
	  dataptr = inbuf + 4 + SVAL(p,smb_vwv6);
	}
      else
	{
	  dataptr = NULL;
	  datalen = 0;
	}

      DEBUG(2,("getting file %s of size %d bytes as a tar file %s",
	       finfo.name,
	       finfo.size,
	       lname));
      
      /* write a tar header, don't bother with mode - just set to 100644 */
      writetarheader(tarhandle, rname, finfo.size, finfo.mtime, "100644 \0");
      
      while (nread < finfo.size && !close_done)
	{
	  int method = -1;
	  static BOOL can_chain_close=True;

	  p=NULL;
	  
	  DEBUG(3,("nread=%d\n",nread));
	  
	  /* 3 possible read types. readbraw if a large block is required.
	     readX + close if not much left and read if neither is supported */

	  /* we might have already read some data from a chained readX */
	  if (dataptr && datalen>0)
	    method=3;
	  
	  /* if we can finish now then readX+close */
	  if (method<0 && can_chain_close && (Protocol >= PROTOCOL_LANMAN1) && 
	      ((finfo.size - nread) < 
	       (max_xmit - (2*smb_size + 13*SIZEOFWORD + 300))))
	    method = 0;
	  
	  /* if we support readraw then use that */
	  if (method<0 && readbraw_supported)
	    method = 1;
	  
	  /* if we can then use readX */
	  if (method<0 && (Protocol >= PROTOCOL_LANMAN1))
	    method = 2;
	  
	  
	  switch (method)
	    {
	      /* use readX */
	    case 0:
	    case 2:
	      if (method == 0)
		close_done = True;
	      
	      /* use readX + close */
	      memset(outbuf,0,smb_size);
	      set_message(outbuf,10,0,True);
	      CVAL(outbuf,smb_com) = SMBreadX;
	      SSVAL(outbuf,smb_tid,cnum);
	      setup_pkt(outbuf);
	      
	      if (close_done)
		{
		  CVAL(outbuf,smb_vwv0) = SMBclose;
		  SSVAL(outbuf,smb_vwv1,PTR_DIFF(smb_buf(outbuf),outbuf) - 4);
		}
	      else
		CVAL(outbuf,smb_vwv0) = 0xFF;	      
	      
	      
	      SSVAL(outbuf,smb_vwv2,fnum);
	      SIVAL(outbuf,smb_vwv3,nread);
	      SSVAL(outbuf,smb_vwv5,MIN(max_xmit-200,finfo.size - nread));
	      SSVAL(outbuf,smb_vwv6,0);
	      SIVAL(outbuf,smb_vwv7,0);
	      SSVAL(outbuf,smb_vwv9,MIN(0xFFFF,finfo.size-nread));
	      
	      if (close_done)
		{
		  p = smb_buf(outbuf);
		  memset(p,0,9);
		  
		  CVAL(p,0) = 3;
		  SSVAL(p,1,fnum);
		  SIVALS(p,3,-1);
		  
		  /* now set the total packet length */
		  smb_setlen(outbuf,smb_len(outbuf)+9);
		}
	      
	      send_smb(Client,outbuf);
	      receive_smb(Client,inbuf,CLIENT_TIMEOUT);
	      
	      if (CVAL(inbuf,smb_rcls) != 0)
		{
		  DEBUG(0,("Error %s reading remote file\n",smb_errstr(inbuf)));
		  break;
		}
	      
	      if (close_done &&
		  SVAL(inbuf,smb_vwv0) != SMBclose)
		{
		  /* NOTE: WfWg sometimes just ignores the chained
		     command! This seems to break the spec? */
		  DEBUG(3,("Rejected chained close?\n"));
		  close_done = False;
		  can_chain_close = False;
		  ignore_close_error = True;
		}
	      
	      datalen = SVAL(inbuf,smb_vwv5);
	      dataptr = inbuf + 4 + SVAL(inbuf,smb_vwv6);
	      break;
	      
	      
	      /* use readbraw */
	    case 1:
	      {
		static int readbraw_size = 0xFFFF;
		
		extern int Client;
		memset(outbuf,0,smb_size);
		set_message(outbuf,8,0,True);
		CVAL(outbuf,smb_com) = SMBreadbraw;
		SSVAL(outbuf,smb_tid,cnum);
		setup_pkt(outbuf);
		SSVAL(outbuf,smb_vwv0,fnum);
		SIVAL(outbuf,smb_vwv1,nread);
		SSVAL(outbuf,smb_vwv3,MIN(finfo.size-nread,readbraw_size));
		SSVAL(outbuf,smb_vwv4,0);
		SIVALS(outbuf,smb_vwv5,-1);
		send_smb(Client,outbuf);
		
		/* Now read the raw data into the buffer and write it */	  
		if(read_smb_length(Client,inbuf,0) == -1) {
		  DEBUG(0,("Failed to read length in readbraw\n"));	    
		  exit(1);
		}
		
		/* Even though this is not an smb message, smb_len
		   returns the generic length of an smb message */
		datalen = smb_len(inbuf);
		
		if (datalen == 0)
		  {
		    /* we got a readbraw error */
		    DEBUG(4,("readbraw error - reducing size\n"));
		    readbraw_size = (readbraw_size * 9) / 10;
		    
		    if (readbraw_size < max_xmit)
		      {
			DEBUG(0,("disabling readbraw\n"));
			readbraw_supported = False;
		      }

		    dataptr=NULL;
		    continue;
		  }

		if(read_data(Client,inbuf,datalen) != datalen) {
		  DEBUG(0,("Failed to read data in readbraw\n"));
		  exit(1);
		}
		dataptr = inbuf;
	      }
	      break;

	    case 3:
	      /* we've already read some data with a chained readX */
	      break;
	      
	    default:
	      /* use plain read */
	      memset(outbuf,0,smb_size);
	      set_message(outbuf,5,0,True);
	      CVAL(outbuf,smb_com) = SMBread;
	      SSVAL(outbuf,smb_tid,cnum);
	      setup_pkt(outbuf);
	      
	      SSVAL(outbuf,smb_vwv0,fnum);
	      SSVAL(outbuf,smb_vwv1,MIN(max_xmit-200,finfo.size - nread));
	      SIVAL(outbuf,smb_vwv2,nread);
	      SSVAL(outbuf,smb_vwv4,finfo.size - nread);
	      
	      send_smb(Client,outbuf);
	      receive_smb(Client,inbuf,CLIENT_TIMEOUT);
	      
	      if (CVAL(inbuf,smb_rcls) != 0)
		{
		  DEBUG(0,("Error %s reading remote file\n",smb_errstr(inbuf)));
		  break;
		}
	      
	      datalen = SVAL(inbuf,smb_vwv0);
	      dataptr = smb_buf(inbuf) + 3;
	      break;
	    }
	  
	  
	  /* add received bits of file to buffer - dotarbuf will
	   * write out in 512 byte intervals */
	  if (dotarbuf(tarhandle,dataptr,datalen) != datalen)
	    {
	      DEBUG(0,("Error writing local file\n"));
	      break;
	    }
	  
	  nread += datalen;
	  if (datalen == 0) 
	    {
	      DEBUG(0,("Error reading file %s. Got 0 bytes\n", rname));
	      break;
	    }

	  dataptr=NULL;
	  datalen=0;
	}
      
      /* round tar file to nearest block */
      if (finfo.size % TBLOCK)
	dozerobuf(tarhandle, TBLOCK - (finfo.size % TBLOCK));
      
      ntarf++;
    }
  
  if (!close_done)
    {
      memset(outbuf,0,smb_size);
      set_message(outbuf,3,0,True);
      CVAL(outbuf,smb_com) = SMBclose;
      SSVAL(outbuf,smb_tid,cnum);
      setup_pkt(outbuf);
      
      SSVAL(outbuf,smb_vwv0,fnum);
      SIVALS(outbuf,smb_vwv1,-1);
      
      send_smb(Client,outbuf);
      receive_smb(Client,inbuf,CLIENT_TIMEOUT);
      
      if (!ignore_close_error && CVAL(inbuf,smb_rcls) != 0)
	{
	  DEBUG(0,("Error %s closing remote file\n",smb_errstr(inbuf)));
	  free(inbuf);free(outbuf);
	  return;
	}
    }

  if (shallitime)
    {
      struct timeval tp_end;
      int this_time;

      /* if shallitime is true then we didn't skip */
      if (tar_reset) (void) do_setrattr(finfo.name, aARCH, ATTRRESET);
      
      GetTimeOfDay(&tp_end);
      this_time = 
	(tp_end.tv_sec - tp_start.tv_sec)*1000 +
	  (tp_end.tv_usec - tp_start.tv_usec)/1000;
      get_total_time_ms += this_time;
      get_total_size += finfo.size;

      /* Thanks to Carel-Jan Engel (ease@mail.wirehub.nl) for this one */
      DEBUG(2,("(%g kb/s) (average %g kb/s)\n",
	       finfo.size / MAX(0.001, (1.024*this_time)),
	       get_total_size / MAX(0.001, (1.024*get_total_time_ms))));
    }
  
  free(inbuf);free(outbuf);
}

/****************************************************************************
Append single file to tar file (or not)
***************************************************************************/
static void do_tar(file_info *finfo)
{
  pstring rname;

  if (strequal(finfo->name,".") || strequal(finfo->name,".."))
    return;

  /* Is it on the exclude list ? */
  if (!tar_excl && clipn) {
    pstring exclaim;

    strcpy(exclaim, cur_dir);
    *(exclaim+strlen(exclaim)-1)='\0';

    if (clipfind(cliplist, clipn, exclaim)) {
      DEBUG(3,("Skipping directory %s\n", exclaim));
      return;
    }

    strcat(exclaim, "\\");
    strcat(exclaim, finfo->name);

    if (clipfind(cliplist, clipn, exclaim)) {
      DEBUG(3,("Skipping file %s\n", exclaim));
      return;
    }
  }

  if (finfo->mode & aDIR)
    {
      pstring saved_curdir;
      pstring mtar_mask;
      char *inbuf,*outbuf;

      inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
      outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

      if (!inbuf || !outbuf)
	{
	  DEBUG(0,("out of memory\n"));
	  return;
	}

      strcpy(saved_curdir,cur_dir);

      strcat(cur_dir,finfo->name);
      strcat(cur_dir,"\\");

      /* write a tar directory, don't bother with mode - just set it to
       * 40755 */
      writetarheader(tarhandle, cur_dir, 0, finfo->mtime, "040755 \0");
      strcpy(mtar_mask,cur_dir);
      strcat(mtar_mask,"*");
      
      do_dir((char *)inbuf,(char *)outbuf,mtar_mask,attribute,do_tar,recurse);
      strcpy(cur_dir,saved_curdir);
      free(inbuf);free(outbuf);
    }
  else
    {
      strcpy(rname,cur_dir);
      strcat(rname,finfo->name);
      do_atar(rname,finfo->name,finfo);
    }
}

/****************************************************************************
Convert from UNIX to DOS file names
***************************************************************************/
static void unfixtarname(char *tptr, char *fp, int l)
{
  /* remove '.' from start of file name, convert from unix /'s to
   * dos \'s in path. Kill any absolute path names.
   */

  if (*fp == '.') fp++;
  if (*fp == '\\' || *fp == '/') fp++;

#ifdef KANJI
  while (l > 0) {
    if (is_shift_jis (*fp)) {
      *tptr++ = *fp++;
      *tptr++ = *fp++;
      l -= 2;
    } else if (is_kana (*fp)) {
      *tptr++ = *fp++;
      l--;
    } else if (*fp == '/') {
      *tptr++ = '\\';
      fp++;
      l--;
    } else {
      *tptr++ = *fp++;
      l--;
    }
  }
#else
  while (l--) { *tptr=(*fp == '/') ? '\\' : *fp; tptr++; fp++; }
#endif
}

static void do_tarput()
{
  file_info finfo;
  int nread=0, bufread;
  char *inbuf,*outbuf; 
  int fsize=0;
  int fnum;
  struct timeval tp_start;
  BOOL tskip=False;       /* We'll take each file as it comes */

  GetTimeOfDay(&tp_start);
  
  inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  
  if (!inbuf || !outbuf)
    {
      DEBUG(0,("out of memory\n"));
      return;
    }
  
  /*
   * Must read in tbufsiz dollops
   */

  /* These should be the only reads in clitar.c */
  while ((bufread=read(tarhandle, tarbuf, tbufsiz))>0) {
    char *bufferp, *endofbuffer;
    int chunk;

    /* Code to handle a short read.
     * We always need a TBLOCK full of stuff
     */
    if (bufread % TBLOCK) {
      int lchunk=TBLOCK-(bufread % TBLOCK);
      int lread;

      /* It's a shorty - a short read that is */
      DEBUG(3, ("Short read, read %d so far (need %d)\n", bufread, lchunk));

      while ((lread=read(tarhandle, tarbuf+bufread, lchunk))>0) {
	bufread+=lread;
	if (!(lchunk-=lread)) break;
      }

      /* If we've reached EOF then that must be a short file */
      if (lread<=0) break;
    }

    bufferp=tarbuf; 
    endofbuffer=tarbuf+bufread;

    if (tskip) {
      if (fsize<bufread) {
	tskip=False;
	bufferp+=fsize;
	fsize=0;
      } else {
	if (fsize==bufread) tskip=False;
	fsize-=bufread;
	continue;
      }
    }

    do {
      if (!fsize)
	{
	  switch (readtarheader((union hblock *) bufferp, &finfo, cur_dir))
	    {
	    case -2:             /* something dodgy but not fatal about this */
	      DEBUG(0, ("skipping %s...\n", finfo.name));
	      bufferp+=TBLOCK;   /* header - like a link */
	      continue;
	    case -1:
	      DEBUG(0, ("abandoning restore\n"));
	      free(inbuf); free(outbuf);
	      return;
	    case 0: /* chksum is zero - we assume that one all zero
		     *header block will do for eof */
	      DEBUG(0,
		    ("total of %d tar files restored to share\n", ntarf));
	      free(inbuf); free(outbuf);
	      return;
	    default:
	      break;
	    }

	  tskip=clipn
	    && (clipfind(cliplist, clipn, finfo.name) ^ tar_excl);
	  if (tskip) {
	    bufferp+=TBLOCK;
	    if (finfo.mode & aDIR)
	      continue;
	    else if ((fsize=finfo.size) % TBLOCK) {
	      fsize+=TBLOCK-(fsize%TBLOCK);
	    }
	    if (fsize<endofbuffer-bufferp) {
	      bufferp+=fsize;
	      fsize=0;
	      continue;
	    } else {
	      fsize-=endofbuffer-bufferp;
	      break;
	    }
	  }

	  if (finfo.mode & aDIR)
	    {
	      if (!smbchkpath(finfo.name, inbuf, outbuf)
		  && !smbmkdir(finfo.name, inbuf, outbuf))
		{
		  DEBUG(0, ("abandoning restore\n"));
		  free(inbuf); free(outbuf);
		  return;
	      }
	      else
		{
		  bufferp+=TBLOCK;
		  continue;
		}
	    }
	  
	  fsize=finfo.size;

	  if (ensurepath(finfo.name, inbuf, outbuf)
	      && !smbcreat(finfo, &fnum, inbuf, outbuf))
	    {
	      DEBUG(0, ("abandoning restore\n"));
	      free(inbuf);free(outbuf);
	      return;
	    }

	  DEBUG(0,("restore tar file %s of size %d bytes\n",
		   finfo.name,finfo.size));

	  nread=0;
	  if ((bufferp+=TBLOCK) >= endofbuffer) break;	  
	} /* if (!fsize) */
	
      /* write out the file in chunk sized chunks - don't
       * go past end of buffer though */
      chunk=(fsize-nread < endofbuffer - bufferp)
	? fsize - nread : endofbuffer - bufferp;
      
      while (chunk > 0) {
	int minichunk=MIN(chunk, max_xmit-200);
	
	if (!smbwrite(fnum, /* file descriptor */
		      minichunk, /* n */
		      nread, /* offset low */
		      0, /* offset high - not implemented */
		      fsize-nread, /* left - only hint to server */
		      bufferp,
		      inbuf,
		      outbuf))
	  {
	    DEBUG(0, ("Error writing remote file\n"));
	    free(inbuf); free(outbuf);
	    return;
	  }
	DEBUG(5, ("chunk writing fname=%s fnum=%d nread=%d minichunk=%d chunk=%d size=%d\n", finfo.name, fnum, nread, minichunk, chunk, fsize));
	
	bufferp+=minichunk; nread+=minichunk;
	chunk-=minichunk;
      }
      
      if (nread>=fsize)
	{
	  if (!smbshut(finfo, fnum, inbuf, outbuf))
	    {
	      DEBUG(0, ("Error closing remote file\n"));
	      free(inbuf);free(outbuf);
	      return;
	    }
	  if (fsize % TBLOCK) bufferp+=TBLOCK - (fsize % TBLOCK);
	  DEBUG(5, ("bufferp is now %d (psn=%d)\n",
		    (long) bufferp, (long)(bufferp - tarbuf)));
	  ntarf++;
	  fsize=0;
	}
    } while (bufferp < endofbuffer);
  }

  DEBUG(0, ("premature eof on tar file ?\n"));
  DEBUG(0,("total of %d tar files restored to share\n", ntarf));

  free(inbuf); free(outbuf);
}

/*
 * samba interactive commands
 */

/****************************************************************************
Blocksize command
***************************************************************************/
void cmd_block(void)
{
  fstring buf;
  int block;

  if (!next_token(NULL,buf,NULL))
    {
      DEBUG(0, ("blocksize <n>\n"));
      return;
    }

  block=atoi(buf);
  if (block < 0 || block > 65535)
    {
      DEBUG(0, ("blocksize out of range"));
      return;
    }

  blocksize=block;
  DEBUG(2,("blocksize is now %d\n", blocksize));
}

/****************************************************************************
command to set incremental / reset mode
***************************************************************************/
void cmd_tarmode(void)
{
  fstring buf;

  while (next_token(NULL,buf,NULL)) {
    if (strequal(buf, "full"))
      tar_inc=False;
    else if (strequal(buf, "inc"))
      tar_inc=True;
    else if (strequal(buf, "reset"))
      tar_reset=True;
    else if (strequal(buf, "noreset"))
      tar_reset=False;
    else DEBUG(0, ("tarmode: unrecognised option %s\n", buf));
  }

  DEBUG(0, ("tarmode is now %s, %s\n",
	    tar_inc ? "incremental" : "full",
	    tar_reset ? "reset" : "noreset"));
}

/****************************************************************************
Feeble attrib command
***************************************************************************/
void cmd_setmode(void)
{
  char *q;
  fstring buf;
  pstring fname;
  int attra[2];
  int direct=1;

  attra[0] = attra[1] = 0;

  if (!next_token(NULL,buf,NULL))
    {
      DEBUG(0, ("setmode <filename> <perm=[+|-]rsha>\n"));
      return;
    }

  strcpy(fname, cur_dir);
  strcat(fname, buf);

  while (next_token(NULL,buf,NULL)) {
    q=buf;

    while(*q)
      switch (*q++) {
      case '+': direct=1;
	break;
      case '-': direct=0;
	break;
      case 'r': attra[direct]|=aRONLY;
	break;
      case 'h': attra[direct]|=aHIDDEN;
	break;
      case 's': attra[direct]|=aSYSTEM;
	break;
      case 'a': attra[direct]|=aARCH;
	break;
      default: DEBUG(0, ("setmode <filename> <perm=[+|-]rsha>\n"));
	return;
      }
  }

  if (attra[ATTRSET]==0 && attra[ATTRRESET]==0)
    {
      DEBUG(0, ("setmode <filename> <perm=[+|-]rsha>\n"));
      return;
    }

  DEBUG(2, ("\nperm set %d %d\n", attra[ATTRSET], attra[ATTRRESET]));
  (void) do_setrattr(fname, attra[ATTRSET], ATTRSET);
  (void) do_setrattr(fname, attra[ATTRRESET], ATTRRESET);
}

/****************************************************************************
Principal command for creating / extracting
***************************************************************************/
void cmd_tar(char *inbuf, char *outbuf)
{
  fstring buf;
  char **argl;
  int argcl;

  if (!next_token(NULL,buf,NULL))
    {
      DEBUG(0,("tar <c|x>[IXbga] <filename>\n"));
      return;
    }

  argl=toktocliplist(&argcl, NULL);
  if (!tar_parseargs(argcl, argl, buf, 0))
    return;

  process_tar(inbuf, outbuf);

  free(argl);
}

/****************************************************************************
Command line (option) version
***************************************************************************/
int process_tar(char *inbuf, char *outbuf)
{
  initarbuf();
  switch(tar_type) {
  case 'x':
    do_tarput();
    free(tarbuf);
    close(tarhandle);
    break;
  case 'r':
  case 'c':
    if (clipn && tar_excl) {
      int i;
      pstring tarmac;

      for (i=0; i<clipn; i++) {
	DEBUG(0,("arg %d = %s\n", i, cliplist[i]));

	if (*(cliplist[i]+strlen(cliplist[i])-1)=='\\') {
	  *(cliplist[i]+strlen(cliplist[i])-1)='\0';
	}
	
	if (strrchr(cliplist[i], '\\')) {
	  pstring saved_dir;
	  
	  strcpy(saved_dir, cur_dir);
	  
	  if (*cliplist[i]=='\\') {
	    strcpy(tarmac, cliplist[i]);
	  } else {
	    strcpy(tarmac, cur_dir);
	    strcat(tarmac, cliplist[i]);
	  }
	  strcpy(cur_dir, tarmac);
	  *(strrchr(cur_dir, '\\')+1)='\0';

	  do_dir((char *)inbuf,(char *)outbuf,tarmac,attribute,do_tar,recurse);
	  strcpy(cur_dir,saved_dir);
	} else {
	  strcpy(tarmac, cur_dir);
	  strcat(tarmac, cliplist[i]);
	  do_dir((char *)inbuf,(char *)outbuf,tarmac,attribute,do_tar,recurse);
	}
      }
    } else {
      pstring mask;
      strcpy(mask,cur_dir);
      strcat(mask,"\\*");
      do_dir((char *)inbuf,(char *)outbuf,mask,attribute,do_tar,recurse);
    }
    
    if (ntarf) dotareof(tarhandle);
    close(tarhandle);
    free(tarbuf);
    
    DEBUG(0, ("tar: dumped %d tar files\n", ntarf));
    break;
  }

  return(0);
}

/****************************************************************************
Find a token (filename) in a clip list
***************************************************************************/
int clipfind(char **aret, int ret, char *tok)
{
  if (aret==NULL) return 0;

  /* ignore leading slashes or dots in token */
  while(strchr("/\\.", *tok)) tok++;

  while(ret--) {
    char *pkey=*aret++;

    /* ignore leading slashes or dots in list */
    while(strchr("/\\.", *pkey)) pkey++;

    if (!strslashcmp(pkey, tok)) return 1;
  }

  return 0;
}

/****************************************************************************
Parse tar arguments. Sets tar_type, tar_excl, etc.
***************************************************************************/
int tar_parseargs(int argc, char *argv[], char *Optarg, int Optind)
{
  char tar_clipfl='\0';

  /* Reset back to defaults - could be from interactive version 
   * reset mode and archive mode left as they are though
   */
  tar_type='\0';
  tar_excl=True;

  while (*Optarg) 
    switch(*Optarg++) {
    case 'c':
      tar_type='c';
      break;
    case 'x':
      if (tar_type=='c') {
	printf("Tar must be followed by only one of c or x.\n");
	return 0;
      }
      tar_type='x';
      break;
    case 'b':
      if (Optind>=argc || !(blocksize=atoi(argv[Optind]))) {
	DEBUG(0,("Option b must be followed by valid blocksize\n"));
	return 0;
      } else {
	Optind++;
      }
      break;
    case 'g':
      tar_inc=True;
      break;
    case 'N':
      if (Optind>=argc) {
	DEBUG(0,("Option N must be followed by valid file name\n"));
	return 0;
      } else {
	struct stat stbuf;
	extern time_t newer_than;
	
	if (sys_stat(argv[Optind], &stbuf) == 0) {
	  newer_than = stbuf.st_mtime;
	  DEBUG(1,("Getting files newer than %s",
		   asctime(LocalTime(&newer_than))));
	  Optind++;
	} else {
	  DEBUG(0,("Error setting newer-than time\n"));
	  return 0;
	}
      }
      break;
    case 'a':
      tar_reset=True;
      break;
    case 'I':
      if (tar_clipfl) {
	DEBUG(0,("Only one of I,X must be specified\n"));
	return 0;
      }
      tar_clipfl='I';
      break;
    case 'X':
      if (tar_clipfl) {
	DEBUG(0,("Only one of I,X must be specified\n"));
	return 0;
      }
      tar_clipfl='X';
      break;
    default:
      DEBUG(0,("Unknown tar option\n"));
      return 0;
    }

  if (!tar_type) {
    printf("Option T must be followed by one of c or x.\n");
    return 0;
  }

  if (Optind>=argc || !strcmp(argv[Optind], "-")) {
    /* Sets tar handle to either 0 or 1, as appropriate */
    tarhandle=(tar_type=='c');
  } else {
    tar_excl=tar_clipfl!='X';
    
    if (Optind+1<argc) {
      cliplist=argv+Optind+1;
      clipn=argc-Optind-1;
    }

    if ((tar_type=='x' && (tarhandle = open(argv[Optind], O_RDONLY)) == -1)
	|| (tar_type=='c' && (tarhandle=creat(argv[Optind], 0644)) < 0))
      {
	DEBUG(0,("Error opening local file %s\n",argv[Optind]));
	return(0);
      }
  }

  return 1;
}
