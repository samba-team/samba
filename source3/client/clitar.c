/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Tar Extensions
   Copyright (C) Ricky Poulten 1995-1998
   
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
/* The following changes developed by Richard Sharpe for Canon Information
   Systems Research Australia (CISRA) are Copyright (C) 1998 by CISRA and are 
   made available under the terms of the GPL as listed above:

   1. Restore can now restore files with long file names
   2. Save now saves directory information so that we can restore 
      directory creation times
   3. tar now accepts both UNIX path names and DOS path names. I prefer
      those lovely /'s to those UGLY \'s :-)
   4. the files to exclude can be specified as a regular expression by adding
      an r flag to the other tar flags. Eg:

         -TcrX file.tar "*.(obj|exe)"

      will skip all .obj and .exe files
*/


#include "includes.h"
#include "clitar.h"

typedef struct file_info_struct file_info2;

struct file_info_struct
{
  int size;
  int mode;
  int uid;
  int gid;
  /* These times are normally kept in GMT */
  time_t mtime;
  time_t atime;
  time_t ctime;
  char *name;     /* This is dynamically allocate */

  file_info2 *next, *prev;  /* Used in the stack ... */

};

typedef struct
{
  file_info2 *top;
  int items;

} stack;

stack dir_stack = {NULL, 0}; /* Want an empty stack */

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
static int tp, ntarf, tbufsiz, ttarf;
/* Incremental mode */
BOOL tar_inc=False;
/* Reset archive bit */
BOOL tar_reset=False;
/* Include / exclude mode (true=include, false=exclude) */
BOOL tar_excl=True;
/* use regular expressions for search on file names */
BOOL tar_re_search=False;
#ifdef HAVE_REGEX_H
regex_t *preg;
#endif
/* Dump files with System attribute */
BOOL tar_system=False;
/* Dump files with Hidden attribute */
BOOL tar_hidden=True;
/* Be noisy - make a catalogue */
BOOL tar_noisy=True;

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

static void writetarheader(int f,  char *aname, int size, time_t mtime,
			   char *amode, unsigned char ftype);
static void do_atar(char *rname,char *lname,file_info *finfo1);
static void do_tar(file_info *finfo);
static void oct_it(long value, int ndgs, char *p);
static void fixtarname(char *tptr, char *fp, int l);
static int dotarbuf(int f, char *b, int n);
static void dozerobuf(int f, int n);
static void dotareof(int f);
static void initarbuf(void);
static int do_setrattr(char *fname, int attr, int setit);

/* restore functions */
static long readtarheader(union hblock *hb, file_info2 *finfo, char *prefix);
static long unoct(char *p, int ndgs);
static void do_tarput(void);
static void unfixtarname(char *tptr, char *fp, int l);

/*
 * tar specific utitlities
 */

#if 0 /* Removed to get around gcc 'defined but not used' error. */

/*
 * Stack routines, push_dir, pop_dir, top_dir_name
 */

static BOOL push_dir(stack *tar_dir_stack, file_info2 *dir)
{
  dir -> next = tar_dir_stack -> top;
  dir -> prev = NULL;
  tar_dir_stack -> items++;
  tar_dir_stack -> top = dir;
  return(True);

}

static file_info2 *pop_dir(stack *tar_dir_stack)
{
  file_info2 *ptr;
  
  ptr = tar_dir_stack -> top;
  if (tar_dir_stack -> top != NULL) {

    tar_dir_stack -> top = tar_dir_stack -> top -> next;
    tar_dir_stack -> items--;

  }

  return ptr;

}

static char *top_dir_name(stack *tar_dir_stack)
{

  return(tar_dir_stack -> top != NULL?tar_dir_stack -> top -> name:NULL);

}

static BOOL sub_dir(char *dir1, char *dir2)
{

  return(True);

}

#endif /* Removed to get around gcc 'defined but not used' error. */

/* Create a string of size size+1 (for the null) */
static char * string_create_s(int size)
{
  char *tmp;

  tmp = (char *)malloc(size+1);

  if (tmp == NULL) {

    DEBUG(0, ("Out of memory in string_create_s\n"));

  }

  return(tmp);

}

/****************************************************************************
Write a tar header to buffer
****************************************************************************/
static void writetarheader(int f,  char *aname, int size, time_t mtime,
			   char *amode, unsigned char ftype)
{
  union hblock hb;
  int i, chk, l;
  char *jp;

  DEBUG(5, ("WriteTarHdr, Type = %c, Size= %i, Name = %s\n", ftype, size, aname));

  memset(hb.dummy, 0, sizeof(hb.dummy));
  
  l=strlen(aname);
  if (l >= NAMSIZ) {
	  /* write a GNU tar style long header */
	  char *b;
	  b = (char *)malloc(l+TBLOCK+100);
	  if (!b) {
		  DEBUG(0,("out of memory\n"));
		  exit(1);
	  }
	  writetarheader(f, "/./@LongLink", l+1, 0, "     0 \0", 'L');
	  memset(b, 0, l+TBLOCK+100);
	  fixtarname(b, aname, l+1);
	  i = strlen(b)+1;
	  DEBUG(5, ("File name in tar file: %s, size=%i, \n", b, strlen(b)));
	  dotarbuf(f, b, TBLOCK*(((i-1)/TBLOCK)+1));
	  free(b);
  }

  /* use l + 1 to do the null too */
  fixtarname(hb.dbuf.name, aname, (l >= NAMSIZ) ? NAMSIZ : l + 1);

  if (lowercase)
    strlower(hb.dbuf.name);

  /* write out a "standard" tar format header */

  hb.dbuf.name[NAMSIZ-1]='\0';
  fstrcpy(hb.dbuf.mode, amode);
  oct_it(0L, 8, hb.dbuf.uid);
  oct_it(0L, 8, hb.dbuf.gid);
  oct_it((long) size, 13, hb.dbuf.size);
  oct_it((long) mtime, 13, hb.dbuf.mtime);
  memcpy(hb.dbuf.chksum, "        ", sizeof(hb.dbuf.chksum));
  memset(hb.dbuf.linkname, 0, NAMSIZ);
  hb.dbuf.linkflag=ftype;
  
  for (chk=0, i=sizeof(hb.dummy), jp=hb.dummy; --i>=0;) chk+=(0xFF & *jp++);

  oct_it((long) chk, 8, hb.dbuf.chksum);
  hb.dbuf.chksum[6] = '\0';

  (void) dotarbuf(f, hb.dummy, sizeof(hb.dummy));
}

/****************************************************************************
Read a tar header into a hblock structure, and validate
***************************************************************************/
static long readtarheader(union hblock *hb, file_info2 *finfo, char *prefix)
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

  if ((finfo->name = string_create_s(strlen(prefix) + strlen(hb -> dbuf.name) + 3)) == NULL) {

    DEBUG(0, ("Out of space creating file_info2 for %s\n", hb -> dbuf.name));
    return(-1);

  }

  pstrcpy(finfo->name, prefix);

  /* use l + 1 to do the null too; do prefix - prefcnt to zap leading slash */
  unfixtarname(finfo->name + strlen(prefix), hb->dbuf.name,
	       strlen(hb->dbuf.name) + 1);

/* can't handle some links at present */
  if ((hb->dbuf.linkflag != '0') && (hb -> dbuf.linkflag != '5')) {
    if (hb->dbuf.linkflag == 0) {
      DEBUG(6, ("Warning: NULL link flag (gnu tar archive ?) %s\n",
		finfo->name));
    } else { 
      if (hb -> dbuf.linkflag == 'L') { /* We have a longlink */
         /* Do nothing here at the moment. do_tarput will handle this
            as long as the longlink gets back to it, as it has to advance 
            the buffer pointer, etc */

      } else {
        DEBUG(0, ("this tar file appears to contain some kind of link other than a GNUtar Longlink - ignoring\n"));
        return -2;
      }
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
Write zeros to buffer / tape
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
  tarbuf=malloc(tbufsiz);      /* FIXME: We might not get the buffer */

  /* reset tar buffer pointer and tar file counter and total dumped */
  tp=0; ntarf=0; ttarf=0;
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

  while (l > 0) {
    int skip;
    if((skip = skip_multibyte_char( *fp)) != 0) {
      if (skip == 2) {
        *tptr++ = *fp++;
        *tptr++ = *fp++;
        l -= 2;
      } else if (skip == 1) {
        *tptr++ = *fp++;
        l--;
      }
    } else if (*fp == '\\') {
      *tptr++ = '/';
      fp++;
      l--;
    } else {
      *tptr++ = *fp++;
      l--;
    }
  }
}

/****************************************************************************
Convert from decimal to octal string
****************************************************************************/
static void oct_it (long value, int ndgs, char *p)
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
Compare two strings in a slash insensitive way, allowing s1 to match s2 
if s1 is an "initial" string (up to directory marker).  Thus, if s2 is 
a file in any subdirectory of s1, declare a match.
***************************************************************************/
static int strslashcmp(char *s1, char *s2)
{
  char *s1_0=s1;

  while(*s1 && *s2 &&
	(*s1 == *s2
	 || tolower(*s1) == tolower(*s2)
	 || (*s1 == '\\' && *s2=='/')
	 || (*s1 == '/' && *s2=='\\'))) {
	  s1++; s2++;
  }

  /* if s1 has a trailing slash, it compared equal, so s1 is an "initial" 
     string of s2.
   */
  if (!*s1 && s1 != s1_0 && (*(s1-1) == '/' || *(s1-1) == '\\')) return 0;

  /* ignore trailing slash on s1 */
  if (!*s2 && (*s1 == '/' || *s1 == '\\') && !*(s1+1)) return 0;

  /* check for s1 is an "initial" string of s2 */
  if (*s2 == '/' || *s2 == '\\') return 0;

  return *s1-*s2;
}

/*
 * general smb utility functions
 */
/**********************************************************************
do_setrtime, set time on a file or dir ...
**********************************************************************/

static int do_setrtime(char *fname, int mtime)
{
  char *inbuf, *outbuf, *p;
  char *name;

  DEBUG(5, ("Setting time on: %s, fnlen=%i.\n", fname, strlen(fname)));

  name = (char *)malloc(strlen(fname) + 1 + 1);
  if (name == NULL) {

     DEBUG(0, ("Failed to allocate space while setting time on file: %s", fname));
     return False;

  }

  pstrcpy(name, fname);
  pstrcpy(fname, "\\");
  pstrcat(fname, name);

  inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if (!inbuf || !outbuf) {

    DEBUG(0, ("Could not allocate memory for inbuf or outbuf while changing time on: %s\n", fname));
    return False;

  }

  memset(outbuf, 0, smb_size);
  set_message(outbuf, 8, 4 + strlen(fname), True);
  CVAL(outbuf, smb_com) = SMBsetatr;
  SSVAL(outbuf, smb_tid, cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf, smb_vwv0, 0);
  put_dos_date3(outbuf, smb_vwv1, mtime);

  p = smb_buf(outbuf);
  *p++ = 4;
  pstrcpy(p, fname);
  p+= (strlen(fname)+1);

  *p++ = 4;
  *p++ = 0;

  send_smb(Client, outbuf);
  client_receive_smb(Client, inbuf, CLIENT_TIMEOUT);

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

  pstrcpy(name,fname);
  pstrcpy(fname,"\\");
  pstrcat(fname,name);

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
  cli_setup_pkt(outbuf);

  p = smb_buf(outbuf);
  *p++ = 4;
  pstrcpy(p,fname);
  p += (strlen(fname)+1);
  
  *p++ = 4;
  *p++ = 0;

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,attr);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  pstrcpy(p,fname);
  p += (strlen(fname)+1);
  
  *p++ = 4;
  *p++ = 0;

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
static BOOL smbcreat(file_info2 finfo, int *fnum, char *inbuf, char *outbuf)
{
  char *p;
  /* *must* be called with buffer ready malloc'ed */
  /* open remote file */

  memset(outbuf,0,smb_size);
  set_message(outbuf,3,2 + strlen(finfo.name),True);
  CVAL(outbuf,smb_com) = SMBcreate;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);
  
  SSVAL(outbuf,smb_vwv0,finfo.mode);
  put_dos_date3(outbuf,smb_vwv1,finfo.mtime);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  pstrcpy(p,finfo.name);
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
  cli_setup_pkt(outbuf);
  
  SSVAL(outbuf,smb_vwv0,fnum);
  SSVAL(outbuf,smb_vwv1,n);
  SIVAL(outbuf,smb_vwv2,low);
  SSVAL(outbuf,smb_vwv4,left);
  CVAL(smb_buf(outbuf),0) = 1;
  SSVAL(smb_buf(outbuf),1,n);

  send_smb(Client,outbuf); 
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
static BOOL smbshut(file_info2 finfo, int fnum, char *inbuf, char *outbuf)
{
  /* *must* be called with buffer ready malloc'ed */

  memset(outbuf,0,smb_size);
  set_message(outbuf,3,0,True);
  CVAL(outbuf,smb_com) = SMBclose;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);
  
  SSVAL(outbuf,smb_vwv0,fnum);
  put_dos_date3(outbuf,smb_vwv1,finfo.mtime);
  
  DEBUG(3,("Setting date to %s (0x%X)",
	   asctime(LocalTime(&finfo.mtime)),
	   finfo.mtime));
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
  cli_setup_pkt(outbuf);

  p = smb_buf(outbuf);
  *p++ = 4;
  pstrcpy(p,fname);

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
  cli_setup_pkt(outbuf);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  pstrcpy(p,fname);
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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

  char *partpath, *ffname;
  char *p=fname, *basehack;

  DEBUG(5, ( "Ensurepath called with: %s\n", fname));

  partpath = string_create_s(strlen(fname));
  ffname = string_create_s(strlen(fname));

  if ((partpath == NULL) || (ffname == NULL)){

    DEBUG(0, ("Out of memory in ensurepath: %s\n", fname));
    return(False);

  }

  *partpath = 0;

  /* fname copied to ffname so can strtok */

  pstrcpy(ffname, fname);

  /* do a `basename' on ffname, so don't try and make file name directory */
  if ((basehack=strrchr(ffname, '\\')) == NULL)
    return True;
  else
    *basehack='\0';

  p=strtok(ffname, "\\");

  while (p)
    {
      pstrcat(partpath, p);

      if (!smbchkpath(partpath, inbuf, outbuf)) {
	if (!smbmkdir(partpath, inbuf, outbuf))
	  {
	    DEBUG(0, ("Error mkdirhiering\n"));
	    return False;
	  }
	else
	  DEBUG(3, ("mkdirhiering %s\n", partpath));

      }

      pstrcat(partpath, "\\");
      p = strtok(NULL,"/\\");
    }

    return True;
}

int padit(char *buf, int bufsize, int padsize)
{
  int berr= 0;
  int bytestowrite;
  
  DEBUG(5, ("Padding with %d zeros\n", padsize));
  memset(buf, 0, bufsize);
  while( !berr && padsize > 0 ) {
    bytestowrite= MIN(bufsize, padsize);
    berr = dotarbuf(tarhandle, buf, bytestowrite) != bytestowrite;
    padsize -= bytestowrite;
  }
  
  return berr;
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
  char *p, ftype;
  char *inbuf,*outbuf;
  file_info finfo;
  BOOL close_done = False;
  BOOL shallitime=True;
  BOOL ignore_close_error = False;
  char *dataptr=NULL;
  int datalen=0;

  struct timeval tp_start;
  GetTimeOfDay(&tp_start);

  ftype = '0'; /* An ordinary file ... */

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
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0xFF);
  SSVAL(outbuf,smb_vwv2,1);
  SSVAL(outbuf,smb_vwv3,(DENY_NONE<<4));
  SSVAL(outbuf,smb_vwv4,aSYSTEM | aHIDDEN);
  SSVAL(outbuf,smb_vwv5,aSYSTEM | aHIDDEN);
  SSVAL(outbuf,smb_vwv8,1);

  p = smb_buf(outbuf);
  pstrcpy(p,rname);
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
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      if (CVAL(inbuf,smb_rcls) == ERRSRV &&
	  SVAL(inbuf,smb_err) == ERRnoresource &&
	  cli_reopen_connection(inbuf,outbuf))
	{
	  do_atar(rname,lname,finfo1);
	  free(inbuf);free(outbuf);
	  return;
	}

      DEBUG(0,("%s opening remote file %s\n",smb_errstr(inbuf),rname));
      free(inbuf);free(outbuf);
      return;
    }

  pstrcpy(finfo.name,rname);
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
  else if (!tar_system && (finfo.mode & aSYSTEM))
    {
      DEBUG(4, ("skipping %s - system bit is set\n", finfo.name));
      shallitime=0;
    }
  else if (!tar_hidden && (finfo.mode & aHIDDEN))
    {
      DEBUG(4, ("skipping %s - hidden bit is set\n", finfo.name));
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

      DEBUG(3,("getting file %s of size %d bytes as a tar file %s",
	       finfo.name,
	       finfo.size,
	       lname));
      
      /* write a tar header, don't bother with mode - just set to 100644 */
      writetarheader(tarhandle, rname, finfo.size, finfo.mtime, "100644 \0", ftype);
      
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
	      cli_setup_pkt(outbuf);
	      
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
	      client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
	      
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
		cli_setup_pkt(outbuf);
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
	      cli_setup_pkt(outbuf);
	      
	      SSVAL(outbuf,smb_vwv0,fnum);
	      SSVAL(outbuf,smb_vwv1,MIN(max_xmit-200,finfo.size - nread));
	      SIVAL(outbuf,smb_vwv2,nread);
	      SSVAL(outbuf,smb_vwv4,finfo.size - nread);
	      
	      send_smb(Client,outbuf);
	      client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
	      
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
	      DEBUG(0,("Error writing to tar file - %s\n", strerror(errno)));
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

       /* pad tar file with zero's if we couldn't get entire file */
       if (nread < finfo.size)
        {
          DEBUG(0, ("Didn't get entire file. size=%d, nread=%d\n", finfo.size, nread));
          if (padit(inbuf, BUFFER_SIZE, finfo.size - nread))
              DEBUG(0,("Error writing tar file - %s\n", strerror(errno)));
        }

      /* round tar file to nearest block */
      if (finfo.size % TBLOCK)
	dozerobuf(tarhandle, TBLOCK - (finfo.size % TBLOCK));
      
      ttarf+=finfo.size + TBLOCK - (finfo.size % TBLOCK);
      ntarf++;
    }
  
  if (!close_done)
    {
      memset(outbuf,0,smb_size);
      set_message(outbuf,3,0,True);
      CVAL(outbuf,smb_com) = SMBclose;
      SSVAL(outbuf,smb_tid,cnum);
      cli_setup_pkt(outbuf);
      
      SSVAL(outbuf,smb_vwv0,fnum);
      SIVALS(outbuf,smb_vwv1,-1);
      
      send_smb(Client,outbuf);
      client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
      
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
      DEBUG(3,("(%g kb/s) (average %g kb/s)\n",
	       finfo.size / MAX(0.001, (1.024*this_time)),
	       get_total_size / MAX(0.001, (1.024*get_total_time_ms))));
      if (tar_noisy)
	{
	  printf("%10d (%7.1f kb/s) %s\n",
	       finfo.size, finfo.size / MAX(0.001, (1.024*this_time)),
               finfo.name);
	}

    }
  
  free(inbuf);free(outbuf);
}

/****************************************************************************
Append single file to tar file (or not)
***************************************************************************/
static void do_tar(file_info *finfo)
{
  pstring rname;

  if (strequal(finfo->name,".."))
    return;

  /* Is it on the exclude list ? */
  if (!tar_excl && clipn) {
    pstring exclaim;

    pstrcpy(exclaim, cur_dir);
    *(exclaim+strlen(exclaim)-1)='\0';

    pstrcat(exclaim, "\\");
    pstrcat(exclaim, finfo->name);

    DEBUG(5, ("...tar_re_search: %d\n", tar_re_search));

    if ((!tar_re_search && clipfind(cliplist, clipn, exclaim)) ||
#ifdef HAVE_REGEX_H
	(tar_re_search && !regexec(preg, exclaim, 0, NULL, 0))) {
#else
        (tar_re_search && mask_match(exclaim, cliplist[0], True, False))) {
#endif
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

      pstrcpy(saved_curdir,cur_dir);

      pstrcat(cur_dir,finfo->name);
      pstrcat(cur_dir,"\\");

      DEBUG(5, ("Writing a dir, Name = %s\n", cur_dir));

      /* write a tar directory, don't bother with mode - just set it to
       * 40755 */
      writetarheader(tarhandle, cur_dir, 0, finfo->mtime, "040755 \0", '5');
      ntarf++;  /* Make sure we have a file on there */
      pstrcpy(mtar_mask,cur_dir);
      pstrcat(mtar_mask,"*");
      /*      do_dir((char *)inbuf,(char *)outbuf,mtar_mask,attribute,do_tar,recurse,True); */
	      pstrcpy(cur_dir,saved_curdir);
      free(inbuf);free(outbuf);
    }
  else
    {
      pstrcpy(rname,cur_dir);
      pstrcat(rname,finfo->name);
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

  while (l > 0) {
    int skip;
    if(( skip = skip_multibyte_char( *fp )) != 0) {
      if (skip == 2) {
        *tptr++ = *fp++;
        *tptr++ = *fp++;
        l -= 2;
      } else if (skip == 1) {
        *tptr++ = *fp++;
        l--;
      }
    } else if (*fp == '/') {
      *tptr++ = '\\';
      fp++;
      l--;
    } else {
      *tptr++ = *fp++;
      l--;
    }
  }
}

#if 0 /* Removed to get around gcc 'defined but not used' error. */

/****************************************************************************
Move to the next block in the buffer, which may mean read in another set of
blocks.
****************************************************************************/
static int next_block(char *ltarbuf, char *bufferp, int bufsiz)
{
  int bufread, total = 0;

  if (bufferp >= (ltarbuf + bufsiz)) {
    
    for (bufread = read(tarhandle, ltarbuf, bufsiz); total < bufsiz; total += bufread) {

      if (bufread <= 0) { /* An error, return false */
	return (total > 0 ? -2 : bufread);
      }

    }

    bufferp = ltarbuf;

  }
  else {

    bufferp += TBLOCK;

  }

  return(0);

}

static int skip_file(int skip)
{

  return(0);
}

static int get_file(file_info2 finfo)
{

  return(0);

}

static int get_dir(file_info2 finfo)
{

  return(0);

}

static char * get_longfilename(file_info2 finfo)
{

  return(NULL);

}

static char * bufferp;

static void do_tarput2(void)
{
  file_info2 finfo, *finfo2;
  struct timeval tp_start;
  char *inbuf, *outbuf, *longfilename = NULL;
  int skip = False;

  GetTimeOfDay(&tp_start);

  bufferp = tarbuf + tbufsiz;  /* init this to force first read */

  if (push_dir(&dir_stack, &finfo)) {

    finfo2 = pop_dir(&dir_stack);
    inbuf = top_dir_name(&dir_stack); /* FIXME */
    if (sub_dir(inbuf, finfo2 -> name)){

      DEBUG(0, (""));

    }
  }

  inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if (!inbuf || !outbuf) {

    DEBUG(0, ("Out of memory during allocate of inbuf and outbuf!\n"));
    return;

  }

  if (next_block(tarbuf, bufferp, tbufsiz) <= 0) {

    DEBUG(0, ("Empty file or short tar file: %s\n", strerror(errno)));

  }

  /* Now read through those files ... */

  while (True) {

    switch (readtarheader((union hblock *) bufferp, &finfo, cur_dir)) {

    case -2:    /* Hmm, not good, but not fatal */
      DEBUG(0, ("Skipping %s...\n", finfo.name));
      if ((next_block(tarbuf, bufferp, tbufsiz) <= 0) &&
          !skip_file(finfo.size)) {

	DEBUG(0, ("Short file, bailing out...\n"));
	free(inbuf); free(outbuf);
	continue;

      }

      break;

    case -1:
      DEBUG(0, ("abandoning restore, -1 from read tar header\n"));
      free(inbuf); free(outbuf);
      return;

    case 0: /* chksum is zero - looks like an EOF */
      DEBUG(0, ("total of %d tar files restored to share\n", ntarf));
      free(inbuf); free(outbuf);
      return;        /* Hmmm, bad here ... */

    default:
      break;

    }

    /* Now, do we have a long file name? */

    if (longfilename != NULL) {
      if (strlen(longfilename) < sizeof(finfo.name)) { /* if we have space */

	strncpy(finfo.name, longfilename, sizeof(finfo.name) - 1);
	free(longfilename);
	longfilename = NULL;

      }
      else {

	DEBUG(0, ("filename: %s too long, skipping\n", strlen(longfilename)));
	skip = True;

      }
    }

    /* Well, now we have a header, process the file ... */

    /* Should we skip the file?                         */

    if (skip) {

      skip_file(finfo.size);
      continue;

    }

    /* We only get this far if we should process the file */

    switch (((union hblock *)bufferp) -> dbuf.linkflag) {

    case '0':  /* Should use symbolic names--FIXME */
      get_file(finfo);
      break;

    case '5':
      get_dir(finfo);
      break;

    case 'L':
      longfilename = get_longfilename(finfo);
      break;

    default:
      skip_file(finfo.size);  /* Don't handle these yet */
      break;

    }

  }


}
#endif /* Removed to get around gcc 'defined but not used' error. */

static void do_tarput()
{
  file_info2 finfo;
  int nread=0, bufread;
  char *inbuf,*outbuf, *longname = NULL; 
  int fsize=0;
  int fnum;
  struct timeval tp_start;
  BOOL tskip=False;       /* We'll take each file as it comes */

  finfo.name = NULL;      /* No name in here ... */

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
    char *buffer_p, *endofbuffer;
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

    buffer_p=tarbuf; 
    endofbuffer=tarbuf+bufread;

    if (tskip) {
      if (fsize<bufread) {
	tskip=False;
	buffer_p+=fsize;
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
          int next_header = 1;  /* Want at least one header */
          while (next_header) 
            {  
            if (buffer_p >= endofbuffer) {

              bufread = read(tarhandle, tarbuf, tbufsiz);
              buffer_p = tarbuf;

            }
            next_header = 0;    /* Don't want the next one ... */

	    if (finfo.name != NULL) { /* Free the space */

	      free(finfo.name);
	      finfo.name = NULL;

	    }
	    switch (readtarheader((union hblock *) buffer_p, &finfo, cur_dir))
	      {
	      case -2:             /* something dodgy but not fatal about this */
	        DEBUG(0, ("skipping %s...\n", finfo.name));
	        buffer_p+=TBLOCK;   /* header - like a link */
	        continue;
	      case -1:
	        DEBUG(0, ("abandoning restore, -1 from readtarheader\n"));
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

            /* If we have a longname left from the last time through, 
               copy it into finfo.name and free it.

               The size of a pstring is the limiting factor on filenames
               and directory names now. The total pathname length must be
               less than sizeof(pstring) - 1, which is currently 1023. */

            if (longname != NULL) {

	      free(finfo.name);  /* Free the name in the finfo */
	      finfo.name = string_create_s(strlen(longname) + 2);
              strncpy(finfo.name, longname, strlen(longname) + 1);
	      DEBUG(5, ("Long name = \"%s\", filename=\"%s\"\n", longname, finfo.name));
              free(longname);
              longname = NULL;

            }

            /* Check if a long-link. We do this before the clip checking
               because clip-checking should clip on real name - RJS */

            if (((union hblock *)buffer_p) -> dbuf.linkflag == 'L') {

              /* Skip this header, but pick up length, get the name and 
                 fix the name and skip the name. Hmmm, what about end of
                 buffer??? */

	      DEBUG(5, ("Buffer size = %i\n", finfo.size + strlen(cur_dir) +1));
              longname = malloc(finfo.size + strlen(cur_dir) + 1);
              if (longname == NULL) {

                 DEBUG(0, ("could not allocate buffer of size %d for longname\n",
	 	           finfo.size + strlen(cur_dir) + 1)
                      );
                 free(inbuf); free(outbuf);
                 return;
              }

              buffer_p += TBLOCK;   /* Skip that longlink header */

              /* This needs restructuring ... */

	      if (buffer_p >= endofbuffer) {

		bufread = read(tarhandle, tarbuf, tbufsiz);

		buffer_p = tarbuf;

              }

              strncpy(longname, cur_dir, strlen(cur_dir) + 1); 
              unfixtarname(longname+strlen(cur_dir), buffer_p, finfo.size);
	      DEBUG(5, ("UnfixedName: %s, buffer: %s\n", longname, buffer_p));

              /* Next rounds up to next TBLOCK and takes care of us being right
                 on a TBLOCK boundary */

              buffer_p += (((finfo.size - 1)/TBLOCK)+1)*TBLOCK;
              next_header = 1;  /* Force read of next header */

            }
          }
	  tskip=clipn
	    && ((!tar_re_search && clipfind(cliplist, clipn, finfo.name) ^ tar_excl)
#ifdef HAVE_REGEX_H
		|| (tar_re_search && !regexec(preg, finfo.name, 0, NULL, 0)));
#else
	        || (tar_re_search && mask_match(finfo.name, cliplist[0], True, False)));
#endif
	  if (tskip) {
	    buffer_p+=TBLOCK;
	    if (finfo.mode & aDIR)
	      continue;
	    else if ((fsize=finfo.size) % TBLOCK) {
	      fsize+=TBLOCK-(fsize%TBLOCK);
	    }
	    if (fsize<endofbuffer-buffer_p) {
	      buffer_p+=fsize;
	      fsize=0;
	      continue;
	    } else {
	      fsize-=endofbuffer-buffer_p;
	      break;
	    }
	  }

	  DEBUG(5, ("do_tarput: File is: %s\n", finfo.name));

	  if (finfo.mode & aDIR)
	    {

	      DEBUG(5, ("Creating directory: %s\n", finfo.name));

	      if (!ensurepath(finfo.name, inbuf, outbuf))
		{
		  DEBUG(0, ("abandoning restore, problems ensuring path\n"));
		  free(inbuf); free(outbuf);
		  return;
	      }
	      else
		{
		  /* Now we update the creation date ... */

		  DEBUG(0, ("Updating creation date on %s\n", finfo.name));

		  if (!do_setrtime(finfo.name, finfo.mtime)) {

                    DEBUG(0, ("Could not set time on file: %s\n", finfo.name));
                    return;

                  }

		  ntarf++;
		  buffer_p+=TBLOCK;
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

	  DEBUG(0 ,("restore tar file %s of size %d bytes\n",
		   finfo.name,finfo.size));

	  /*          if (!finfo.size) {
	    if (!smbshut(finfo, fnum, inbuf, outbuf)){
              DEBUG(0, ("Error closing remote file of length 0: %s\n", finfo.name));
	      free(inbuf);free(outbuf);
              return;
            }
	    } */

	  nread=0;
	  if ((buffer_p+=TBLOCK) >= endofbuffer) break;	  
	} /* if (!fsize) */
	
      /* write out the file in chunk sized chunks - don't
       * go past end of buffer though */
      chunk=(fsize-nread < endofbuffer - buffer_p)
	? fsize - nread : endofbuffer - buffer_p;
      
      while (chunk > 0) {
	int minichunk=MIN(chunk, max_xmit-200);
	
	if (!smbwrite(fnum, /* file descriptor */
		      minichunk, /* n */
		      nread, /* offset low */
		      0, /* offset high - not implemented */
		      fsize-nread, /* left - only hint to server */
		      buffer_p,
		      inbuf,
		      outbuf))
	  {
	    DEBUG(0, ("Error writing remote file\n"));
	    free(inbuf); free(outbuf);
	    return;
	  }
	DEBUG(5, ("chunk writing fname=%s fnum=%d nread=%d minichunk=%d chunk=%d size=%d\n", finfo.name, fnum, nread, minichunk, chunk, fsize));
	
	buffer_p+=minichunk; nread+=minichunk;
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
	  if (fsize % TBLOCK) buffer_p+=TBLOCK - (fsize % TBLOCK);
	  DEBUG(5, ("buffer_p is now %d (psn=%d)\n",
		    (long) buffer_p, (long)(buffer_p - tarbuf)));
	  ntarf++;
	  fsize=0;

	}
    } while (buffer_p < endofbuffer);
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
void cmd_block(char *dum_in, char *dum_out)
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
void cmd_tarmode(char *dum_in, char *dum_out)
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
    else if (strequal(buf, "system"))
      tar_system=True;
    else if (strequal(buf, "nosystem"))
      tar_system=False;
    else if (strequal(buf, "hidden"))
      tar_hidden=True;
    else if (strequal(buf, "nohidden"))
      tar_hidden=False;
    else if (strequal(buf, "verbose") || strequal(buf, "noquiet"))
      tar_noisy=True;
    else if (strequal(buf, "quiet") || strequal(buf, "noverbose"))
      tar_noisy=False;
    else DEBUG(0, ("tarmode: unrecognised option %s\n", buf));
  }

  DEBUG(0, ("tarmode is now %s, %s, %s, %s, %s\n",
	    tar_inc ? "incremental" : "full",
	    tar_system ? "system" : "nosystem",
	    tar_hidden ? "hidden" : "nohidden",
	    tar_reset ? "reset" : "noreset",
	    tar_noisy ? "verbose" : "quiet"));

}

/****************************************************************************
Feeble attrib command
***************************************************************************/
void cmd_setmode(char *dum_in, char *dum_out)
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

  pstrcpy(fname, cur_dir);
  pstrcat(fname, buf);

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

#if 0
    do_tarput2();
#else
    do_tarput();
#endif
    free(tarbuf);
    close(tarhandle);
    break;
  case 'r':
  case 'c':
    if (clipn && tar_excl) {
      int i;
      pstring tarmac;

      for (i=0; i<clipn; i++) {
	DEBUG(5,("arg %d = %s\n", i, cliplist[i]));

	if (*(cliplist[i]+strlen(cliplist[i])-1)=='\\') {
	  *(cliplist[i]+strlen(cliplist[i])-1)='\0';
	}
	
	if (strrchr(cliplist[i], '\\')) {
	  pstring saved_dir;
	  
	  pstrcpy(saved_dir, cur_dir);
	  
	  if (*cliplist[i]=='\\') {
	    pstrcpy(tarmac, cliplist[i]);
	  } else {
	    pstrcpy(tarmac, cur_dir);
	    pstrcat(tarmac, cliplist[i]);
	  }
	  pstrcpy(cur_dir, tarmac);
	  *(strrchr(cur_dir, '\\')+1)='\0';

	  do_dir((char *)inbuf,(char *)outbuf,tarmac,attribute,do_tar,recurse, True);
	  pstrcpy(cur_dir,saved_dir);
	} else {
	  pstrcpy(tarmac, cur_dir);
	  pstrcat(tarmac, cliplist[i]);
	  do_dir((char *)inbuf,(char *)outbuf,tarmac,attribute,do_tar,recurse, True);
	}
      }
    } else {
      pstring mask;
      pstrcpy(mask,cur_dir);
      pstrcat(mask,"\\*");
      do_dir((char *)inbuf,(char *)outbuf,mask,attribute,do_tar,recurse, True);
    }
    
    if (ntarf) dotareof(tarhandle);
    close(tarhandle);
    free(tarbuf);
    
    DEBUG(0, ("tar: dumped %d tar files\n", ntarf));
    DEBUG(0, ("Total bytes written: %d\n", ttarf));
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
    case 'r':
      DEBUG(0, ("tar_re_search set\n"));
      tar_re_search = True;
      break;
    default:
      DEBUG(0,("Unknown tar option\n"));
      return 0;
    }

  if (!tar_type) {
    printf("Option T must be followed by one of c or x.\n");
    return 0;
  }

  tar_excl=tar_clipfl!='X';

  if (Optind+1<argc && !tar_re_search) { /* For backwards compatibility */
    char *tmpstr;
    char **tmplist;
    int clipcount;

    cliplist=argv+Optind+1;
    clipn=argc-Optind-1;
    clipcount = clipn;

    if ((tmplist=malloc(clipn*sizeof(char *))) == NULL) {
      DEBUG(0, ("Could not allocate space to process cliplist, count = %i\n", 
               clipn)
           );
      return 0;
    }

    for (clipcount = 0; clipcount < clipn; clipcount++) {

      DEBUG(5, ("Processing an item, %s\n", cliplist[clipcount]));

      if ((tmpstr = (char *)malloc(strlen(cliplist[clipcount])+1)) == NULL) {
        DEBUG(0, ("Could not allocate space for a cliplist item, # %i\n",
                 clipcount)
             );
        return 0;
      }
      unfixtarname(tmpstr, cliplist[clipcount], strlen(cliplist[clipcount]) + 1);
      tmplist[clipcount] = tmpstr;
      DEBUG(5, ("Processed an item, %s\n", tmpstr));

      DEBUG(5, ("Cliplist is: %s\n", cliplist[0]));
    }
    cliplist = tmplist;
  }

  if (Optind+1<argc && tar_re_search) {  /* Doing regular expression seaches */
#ifdef HAVE_REGEX_H
    int errcode;

    if ((preg = (regex_t *)malloc(65536)) == NULL) {

      DEBUG(0, ("Could not allocate buffer for regular expression search\n"));
      return;

    }

    if (errcode = regcomp(preg, argv[Optind + 1], REG_EXTENDED)) {
      char errstr[1024];
      size_t errlen;

      errlen = regerror(errcode, preg, errstr, sizeof(errstr) - 1);
      
      DEBUG(0, ("Could not compile pattern buffer for re search: %s\n%s\n", argv[Optind + 1], errstr));
      return;

    }
#endif

    clipn=argc-Optind-1;
    cliplist=argv+Optind+1;

  }

  if (Optind>=argc || !strcmp(argv[Optind], "-")) {
    /* Sets tar handle to either 0 or 1, as appropriate */
    tarhandle=(tar_type=='c');
  } else {
    if ((tar_type=='x' && (tarhandle = open(argv[Optind], O_RDONLY)) == -1)
	|| (tar_type=='c' && (tarhandle=creat(argv[Optind], 0644)) < 0))
      {
	DEBUG(0,("Error opening local file %s - %s\n",
		 argv[Optind], strerror(errno)));
	return(0);
      }
  }

  return 1;
}
