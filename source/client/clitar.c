/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Tar Extensions
   Copyright (C) Ricky Poulten 1995-1997
   
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

#define SEPARATORS " \t\n\r"
extern int DEBUGLEVEL;

/* These defines are for the do_setrattr routine, to indicate
 * setting and reseting of file attributes in the function call */
#define ATTRSET   True
#define ATTRRESET False

extern file_info def_finfo;


/****************************************************************************
Convert from UNIX to DOS file names
***************************************************************************/
static void unfixtarname(char *tar_ptr, char *fp, int l)
{
  /* remove '.' from start of file name, convert from unix /'s to
   * dos \'s in path. Kill any absolute path names.
   */

  if (*fp == '.') fp++;
  if (*fp == '\\' || *fp == '/') fp++;

  if(lp_client_code_page() == KANJI_CODEPAGE)
  {
    while (l > 0) {
      if (is_shift_jis (*fp)) {
        *tar_ptr++ = *fp++;
        *tar_ptr++ = *fp++;
        l -= 2;
      } else if (is_kana (*fp)) {
        *tar_ptr++ = *fp++;
        l--;
      } else if (*fp == '/') {
        *tar_ptr++ = '\\';
        fp++;
        l--;
      } else {
        *tar_ptr++ = *fp++;
        l--;
      }
    }
  }
  else
  {
    while (l--)
    {
      *tar_ptr=(*fp == '/') ? '\\' : *fp;
      tar_ptr++;
      fp++;
    }
  }
}

/****************************************************************************
(Un)mangle DOS pathname, make nonabsolute
****************************************************************************/
static void fixtarname(char *tar_ptr, char *fp, int l)
{
  /* add a '.' to start of file name, convert from ugly dos \'s in path
   * to lovely unix /'s :-} */

  *tar_ptr++='.';
  if(lp_client_code_page() == KANJI_CODEPAGE)
  {
    while (l > 0) {
      if (is_shift_jis (*fp)) {
        *tar_ptr++ = *fp++;
        *tar_ptr++ = *fp++;
        l -= 2;
      } else if (is_kana (*fp)) {
        *tar_ptr++ = *fp++;
        l--;
      } else if (*fp == '\\') {
        *tar_ptr++ = '/';
        fp++;
        l--;
      } else {
        *tar_ptr++ = *fp++;
        l--;
      }
    }
  }
  else
  {
    while (l--)
    {
      *tar_ptr=(*fp == '\\') ? '/' : *fp;
      tar_ptr++;
      fp++;
    }
  }
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
 * tar specific utitlities
 */

/****************************************************************************
Write out the tar buffer to tape or wherever
****************************************************************************/
static int do_tar_buf(struct client_info *info, int f, char *b, int n)
{
  int fail=1, writ=n;

  /* This routine and the next one should be the only ones that do write()s */
  if (info->tar.tp + n >= info->tar.buf_size)
    {
      int diff;

      diff=info->tar.buf_size-info->tar.tp;
      memcpy(info->tar.buf + info->tar.tp, b, diff);
      fail=fail && (1+write(f, info->tar.buf, info->tar.buf_size));
      n-=diff;
      b+=diff;
      info->tar.tp=0;

      while (n >= info->tar.buf_size)
	{
	  fail=fail && (1 + write(f, b, info->tar.buf_size));
	  n-=info->tar.buf_size;
	  b+=info->tar.buf_size;
	}
    }
  if (n>0) {
    memcpy(info->tar.buf+info->tar.tp, b, n);
    info->tar.tp+=n;
  }

  return(fail ? writ : 0);
}

/****************************************************************************
Write a tar header to buffer
****************************************************************************/
static void write_tar_hdr(struct client_info *info,
				int f,  char *aname, int size, time_t mtime)
{
  union hblock hb;
  int i, chk, l;
  char *jp;

  memset(hb.dummy, 0, sizeof(hb.dummy));
  
  l=strlen(aname);
  if (l >= NAMSIZ)
  {
    struct client_info in;
	char *b;
	memcpy(&in, info, sizeof(in));

	  /* write a GNU tar style long header */
	  b = (char *)malloc(l+TBLOCK+100);
	  if (!b) {
		  DEBUG(0,("out of memory\n"));
		  exit(1);
	  }

      in.tar.file_mode = "     0 \0";
	  write_tar_hdr(&in, f, "/./@LongLink", l+1, 0);
	  memset(b, 0, l+TBLOCK+100);
	  fixtarname(b, aname, l+1);
	  i = strlen(b)+1;
	  do_tar_buf(info, f, b, TBLOCK*((i+(TBLOCK-1)/TBLOCK)));
	  free(b);
  }

  /* use l + 1 to do the null too */
  fixtarname(hb.dbuf.name, aname, (l >= NAMSIZ) ? NAMSIZ : l + 1);

  if (info->lowercase)
    strlower(hb.dbuf.name);

  /* write out a "standard" tar format header */

  hb.dbuf.name[NAMSIZ-1]='\0';
  strcpy(hb.dbuf.mode, info->tar.file_mode);
  oct_it(0L, 8, hb.dbuf.uid);
  oct_it(0L, 8, hb.dbuf.gid);
  oct_it((long) size, 13, hb.dbuf.size);
  oct_it((long) mtime, 13, hb.dbuf.mtime);
  memcpy(hb.dbuf.chksum, "        ", sizeof(hb.dbuf.chksum));
  memset(hb.dbuf.linkname, 0, NAMSIZ);
  if (strcmp("/./@LongLink", aname) == 0) {
	  /* we're doing a GNU tar long filename */
	  hb.dbuf.linkflag='L';
  } else {
	  hb.dbuf.linkflag='0';
  }
  
  for (chk=0, i=sizeof(hb.dummy), jp=hb.dummy; --i>=0;) chk+=(0xFF & *jp++);

  oct_it((long) chk, 8, hb.dbuf.chksum);
  hb.dbuf.chksum[6] = '\0';

  (void) do_tar_buf(info, f, hb.dummy, sizeof(hb.dummy));
}

/****************************************************************************
Read a tar header into a hblock structure, and validate
***************************************************************************/
static long read_tar_hdr(struct cli_state *cli, int t_idx, struct client_info *info,
				union hblock *hb, file_info *finfo, char *prefix)
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
Write a zeros to buffer / tape
****************************************************************************/
static void do_zero_buf(struct client_info *info, int f, int n)
{
  /* short routine just to write out n zeros to buffer -
   * used to round files to nearest block
   * and to do tar EOFs */

  if (n+info->tar.tp >= info->tar.buf_size)
    {
      memset(info->tar.buf+info->tar.tp, 0, info->tar.buf_size-info->tar.tp);
      write(f, info->tar.buf, info->tar.buf_size);
      memset(info->tar.buf, 0, (info->tar.tp+=n-info->tar.buf_size));
    }
  else
    {
      memset(info->tar.buf+info->tar.tp, 0, n);
      info->tar.tp+=n;
    }
}

/****************************************************************************
Malloc tape buffer
****************************************************************************/
static void init_tar_buf(struct client_info *info)
{
  /* initialize tar buffer */
  info->tar.buf_size=info->tar.blocksize*TBLOCK;
  info->tar.buf=malloc(info->tar.buf_size);

  /* reset tar buffer pointer and tar file counter and total dumped */
  info->tar.tp=0; info->tar.num_files=0; info->tar.bytes_written=0;
}

/****************************************************************************
Write two zero blocks at end of file
****************************************************************************/
static void do_tar_eof(struct client_info *info, int f)
{
  struct stat stbuf;
  /* Two zero blocks at end of file, write out full buffer */

  (void) do_zero_buf(info, f, TBLOCK);
  (void) do_zero_buf(info, f, TBLOCK);

  if (fstat(f, &stbuf) == -1)
    {
      DEBUG(0, ("Couldn't stat file handle\n"));
      return;
    }

  /* Could be a pipe, in which case S_ISREG should fail,
   * and we should write out at full size */
  if (info->tar.tp > 0) write(f, info->tar.buf, S_ISREG(stbuf.st_mode) ? info->tar.tp : info->tar.buf_size);
}

/*
 * general smb utility functions
 */
/****************************************************************************
Set DOS file attributes
***************************************************************************/
static BOOL do_setrattr(struct cli_state *cli, int t_idx, struct client_info *info,
				char *fname, uint8 attr, int setit)
{
  /*
   * First get the existing attribs from existing file
   */
  pstring name;

  uint8 fattr;
  uint16 write_time;
  uint16 fsize;

  strcpy(name,fname);
  strcpy(fname,"\\");
  strcat(fname,name);

  /* combine found attributes with bits to be set or reset */

  if (!cli_getatr(cli, t_idx, fname, &fattr, &write_time, &fsize)) return False;

  attr = setit ? (fattr | attr) : (fattr & ~attr);

  return cli_setatr(cli, t_idx, fname, fattr, 0); /* zero write time: no change */
}

/****************************************************************************
Ensure a remote path exists (make if necessary)
***************************************************************************/
static BOOL ensurepath(struct cli_state *cli, int t_idx, struct client_info *info,
				char *fname)
{
  /* *must* be called with buffer ready malloc'ed */
  /* ensures path exists */

  pstring part_path, ffname;
  char *p=fname, *basehack;

  *part_path = 0;

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
      strcat(part_path, p);

      if (!cli_chkpath(cli, t_idx, part_path)) {
	if (!cli_mkdir(cli, t_idx, part_path))
	  {
	    DEBUG(0, ("Error mkdir\n"));
	    return False;
	  }
	else
	  DEBUG(3, ("mkdir %s\n", part_path));

      }

      strcat(part_path, "\\");
      p = strtok(NULL,"/\\");
    }

    return True;
}

static int padit(struct client_info *info, char *buf, int bufsize, int padsize)
{
  int berr= 0;
  int bytestowrite;
  
  DEBUG(0, ("Padding with %d zeros\n", padsize));
  memset(buf, 0, bufsize);
  while( !berr && padsize > 0 )
  {
    bytestowrite= MIN(bufsize, padsize);
    berr = do_tar_buf(info, info->tar.handle, buf, bytestowrite) != bytestowrite;
    padsize -= bytestowrite;
  }
  
  return berr;
}

/****************************************************************************
append one remote file to the tar file
***************************************************************************/
static BOOL tar_write_check(struct client_info *info,
				int handle, char *rname, file_info *finfo)
{
	DEBUG(3,("file %s attrib 0x%X\n", rname, finfo->mode));

	if (info->tar.inc && !(finfo->mode & aARCH))
	{
		DEBUG(4, ("skipping %s - archive bit not set\n", rname));
		return False;
	}

	/* write a tar header, don't bother with mode - just set to 100644 */
    info->tar.file_mode = "100644 \0";
	write_tar_hdr(info, handle, rname, finfo->size, finfo->mtime);

	return True;
}

/****************************************************************************
pad tar file out
***************************************************************************/
static BOOL tar_pad_check(struct client_info *info,
				int handle, char *buf, int nread, file_info *finfo)
{
	/* pad tar file with zero's if we couldn't get entire file */
	if (nread < finfo->size)
	{
		DEBUG(0, ("Didn't get entire file. size=%d, nread=%d\n",
					finfo->size, nread));
		if (padit(info, buf, BUFFER_SIZE, finfo->size - nread))
		{
			DEBUG(0,("Error writing tar file - %s\n", strerror(errno)));
			return False;
		}
	}

	/* round tar file to nearest block */
	if (finfo->size % TBLOCK)
	{
		do_zero_buf(info, info->tar.handle, TBLOCK - (finfo->size % TBLOCK));
	}

	info->tar.bytes_written += finfo->size + TBLOCK - (finfo->size % TBLOCK);
	info->tar.num_files++;

	return True;
}

/****************************************************************************
append one remote file to the tar file
***************************************************************************/
static void do_atar(struct cli_state *cli, int t_idx, struct client_info *info,
				char *rname,char *lname,file_info *finfo1)
{
	uint32 nread = cli_get(cli, t_idx, info, rname, lname, finfo1, info->tar.handle,
				tar_write_check, do_tar_buf, tar_pad_check);

	/* reset the archive bit */
	if (info->tar.reset)
	{
		do_setrattr(cli, t_idx, info, rname, aARCH, ATTRRESET);
	}
}

/****************************************************************************
Append single file to tar file (or not)
***************************************************************************/
static void do_tar(struct cli_state *cli, int t_idx, struct client_info *info,
				file_info *finfo)
{
  pstring rname;

  if (strequal(finfo->name,".") || strequal(finfo->name,".."))
    return;

  /* Is it on the exclude list ? */
  if (!info->tar.excl && info->tar.clipn) {
    pstring exclaim;

    strcpy(exclaim, info->cur_dir);
    *(exclaim+strlen(exclaim)-1)='\0';

    strcat(exclaim, "\\");
    strcat(exclaim, finfo->name);

    if (clipfind(info->tar.cliplist, info->tar.clipn, exclaim)) {
      DEBUG(3,("Skipping file %s\n", exclaim));
      return;
    }
  }

  if (finfo->mode & aDIR)
    {
      pstring saved_curdir;
      pstring mtar_mask;

      strcpy(saved_curdir,info->cur_dir);

      strcat(info->cur_dir,finfo->name);
      strcat(info->cur_dir,"\\");

      /* write a tar directory, don't bother with mode - just set it to
       * 40755 */
	
      info->tar.file_mode = "040755 \0";
      write_tar_hdr(info, info->tar.handle, info->cur_dir, 0, finfo->mtime);
      strcpy(mtar_mask,info->cur_dir);
      strcat(mtar_mask,"*");
      
      cli_dir(cli, t_idx, info, mtar_mask, info->tar.attrib, info->recurse_dir, do_tar);
      strcpy(info->cur_dir,saved_curdir);
    }
  else
    {
      strcpy(rname,info->cur_dir);
      strcat(rname,finfo->name);
      do_atar(cli, t_idx, info, rname,finfo->name,finfo);
    }
}

static void do_tarput(struct cli_state *cli, int t_idx, struct client_info *info)
{
  file_info finfo;
  int nread=0, bufread;
  int fsize=0;
  uint16 fnum;
  struct timeval tar_tp_start;
  BOOL tskip=False;       /* We'll take each file as it comes */

  GetTimeOfDay(&tar_tp_start);
  
  /*
   * Must read in info->tar.buf_size dollops
   */

  /* These should be the only reads in clitar.c */
  while ((bufread=read(info->tar.handle, info->tar.buf, info->tar.buf_size))>0) {
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

      while ((lread=read(info->tar.handle, info->tar.buf+bufread, lchunk))>0) {
	bufread+=lread;
	if (!(lchunk-=lread)) break;
      }

      /* If we've reached EOF then that must be a short file */
      if (lread<=0) break;
    }

    bufferp=info->tar.buf; 
    endofbuffer=info->tar.buf+bufread;

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
	  switch (read_tar_hdr(cli, t_idx, info, (union hblock *) bufferp, &finfo, info->cur_dir))
	    {
	    case -2:             /* something dodgy but not fatal about this */
	      DEBUG(0, ("skipping %s...\n", finfo.name));
	      bufferp+=TBLOCK;   /* header - like a link */
	      continue;
	    case -1:
	      DEBUG(0, ("abandoning restore\n"));
	      return;
	    case 0: /* chksum is zero - we assume that one all zero
		     *header block will do for eof */
	      DEBUG(0,
		    ("total of %d tar files restored to share\n", info->tar.num_files));
	      return;
	    default:
	      break;
	    }

	  tskip=info->tar.clipn
	    && (clipfind(info->tar.cliplist, info->tar.clipn, finfo.name) ^ info->tar.excl);
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
	      if (!cli_chkpath(cli, t_idx, finfo.name)
		  && !cli_mkdir(cli, t_idx, finfo.name))
		{
		  DEBUG(0, ("abandoning restore\n"));
		  return;
	      }
	      else
		{
		  bufferp+=TBLOCK;
		  continue;
		}
	    }
	  
	  fsize=finfo.size;

	  if (ensurepath(cli, t_idx, info, finfo.name) &&
          !cli_create(cli, t_idx, finfo.name, finfo.mode, finfo.mtime, &fnum))
	    {
	      DEBUG(0, ("abandoning restore\n"));
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
	int minichunk=MIN(chunk, cli->max_xmit-200);
	
	if (!cli_write(cli, t_idx, fnum, /* file descriptor */
		      nread, /* offset low */
		      bufferp,
		      minichunk)) /* n */
	  {
	    DEBUG(0, ("Error writing remote file\n"));
	    return;
	  }
	DEBUG(5, ("chunk writing fname=%s fnum=%d nread=%d minichunk=%d chunk=%d size=%d\n", finfo.name, fnum, nread, minichunk, chunk, fsize));
	
	bufferp+=minichunk; nread+=minichunk;
	chunk-=minichunk;
      }
      
      if (nread>=fsize)
	{
	  if (!cli_close(cli, t_idx, fnum, 0))
	    {
	      DEBUG(0, ("Error closing remote file\n"));
	      return;
	    }
	  if (fsize % TBLOCK) bufferp+=TBLOCK - (fsize % TBLOCK);
	  DEBUG(5, ("bufferp is now %d (psn=%d)\n",
		    (long) bufferp, (long)(bufferp - info->tar.buf)));
	  info->tar.num_files++;
	  fsize=0;
	}
    } while (bufferp < endofbuffer);
  }

  DEBUG(0, ("premature eof on tar file ?\n"));
  DEBUG(0,("total of %d tar files restored to share\n", info->tar.num_files));
}

/*
 * samba interactive commands
 */

/****************************************************************************
Blocksize command
***************************************************************************/
void cmd_block(struct cli_state *cli, int t_idx, struct client_info *info)
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

  info->tar.blocksize=block;
  DEBUG(1,("blocksize is now %d\n", info->tar.blocksize));
}

/****************************************************************************
command to set incremental / reset mode
***************************************************************************/
void cmd_tarmode(struct cli_state *cli, int t_idx, struct client_info *info)
{
  fstring buf;

  while (next_token(NULL,buf,NULL)) {
    if (strequal(buf, "full"))
      info->tar.inc=False;
    else if (strequal(buf, "inc"))
      info->tar.inc=True;
    else if (strequal(buf, "reset"))
      info->tar.reset=True;
    else if (strequal(buf, "noreset"))
      info->tar.reset=False;
    else DEBUG(0, ("tarmode: unrecognised option %s\n", buf));
  }

  DEBUG(0, ("tarmode is now %s, %s\n",
	    info->tar.inc ? "incremental" : "full",
	    info->tar.reset ? "reset" : "noreset"));
}

/****************************************************************************
Feeble attrib command
***************************************************************************/
void cmd_setmode(struct cli_state *cli, int t_idx, struct client_info *info)
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

  strcpy(fname, info->cur_dir);
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

  DEBUG(1, ("\nperm set %d %d\n", attra[ATTRSET], attra[ATTRRESET]));
  do_setrattr(cli, t_idx, info, fname, attra[ATTRSET], ATTRSET);
  do_setrattr(cli, t_idx, info, fname, attra[ATTRRESET], ATTRRESET);
}

/****************************************************************************
Principal command for creating / extracting
***************************************************************************/
void cmd_tar(struct cli_state *cli, int t_idx, struct client_info *info)
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
  if (!tar_parseargs(info, argcl, argl, buf, 0))
  {
    return;
  }

  process_tar(cli, t_idx, info);

  free(argl);
}

/****************************************************************************
Command line (option) version
***************************************************************************/
int process_tar(struct cli_state *cli, int t_idx, struct client_info *info)
{
  init_tar_buf(info);
  switch(info->tar.type) {
  case 'x':
    do_tarput(cli, t_idx, info);
    free(info->tar.buf);
    close(info->tar.handle);
    break;
  case 'r':
  case 'c':
    if (info->tar.clipn && info->tar.excl) {
      int i;
      pstring tarmac;

      for (i=0; i<info->tar.clipn; i++) {
	DEBUG(0,("arg %d = %s\n", i, info->tar.cliplist[i]));

	if (*(info->tar.cliplist[i]+strlen(info->tar.cliplist[i])-1)=='\\') {
	  *(info->tar.cliplist[i]+strlen(info->tar.cliplist[i])-1)='\0';
	}
	
	if (strrchr(info->tar.cliplist[i], '\\')) {
	  pstring saved_dir;
	  
	  strcpy(saved_dir, info->cur_dir);
	  
	  if (*info->tar.cliplist[i]=='\\') {
	    strcpy(tarmac, info->tar.cliplist[i]);
	  } else {
	    strcpy(tarmac, info->cur_dir);
	    strcat(tarmac, info->tar.cliplist[i]);
	  }
	  strcpy(info->cur_dir, tarmac);
	  *(strrchr(info->cur_dir, '\\')+1)='\0';

	  cli_dir(cli, t_idx, info, tarmac, info->tar.attrib, info->recurse_dir, do_tar);
	  strcpy(info->cur_dir,saved_dir);
	} else {
	  strcpy(tarmac, info->cur_dir);
	  strcat(tarmac, info->tar.cliplist[i]);
	  cli_dir(cli, t_idx, info, tarmac, info->tar.attrib, info->recurse_dir, do_tar);
	}
      }
    } else {
      pstring mask;
      strcpy(mask,info->cur_dir);
      strcat(mask,"\\*");
	  cli_dir(cli, t_idx, info, mask, info->tar.attrib, info->recurse_dir, do_tar);
    }
    
    if (info->tar.num_files) do_tar_eof(info, info->tar.handle);
    close(info->tar.handle);
    free(info->tar.buf);
    
    DEBUG(0, ("tar: dumped %d tar files\n", info->tar.num_files));
    DEBUG(0, ("Total bytes written: %d\n", info->tar.bytes_written));
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
Parse tar arguments. Sets info->tar.type, info->tar.excl, etc.
***************************************************************************/
int tar_parseargs(struct client_info *info,
				int argc, char *argv[], char *Optarg, int Optind)
{
  char tar_clipfl='\0';

  /* Reset back to defaults - could be from interactive version 
   * reset mode and archive mode left as they are though
   */
  info->tar.type='\0';
  info->tar.excl=True;

  while (*Optarg) 
    switch(*Optarg++) {
    case 'c':
      info->tar.type='c';
      break;
    case 'x':
      if (info->tar.type=='c') {
	printf("Tar must be followed by only one of c or x.\n");
	return 0;
      }
      info->tar.type='x';
      break;
    case 'b':
      if (Optind>=argc || !(info->tar.blocksize=atoi(argv[Optind]))) {
	DEBUG(0,("Option b must be followed by valid blocksize\n"));
	return 0;
      } else {
	Optind++;
      }
      break;
    case 'g':
      info->tar.inc=True;
      break;
    case 'N':
      if (Optind>=argc) {
	DEBUG(0,("Option N must be followed by valid file name\n"));
	return 0;
      } else {
	struct stat stbuf;
	
	if (sys_stat(argv[Optind], &stbuf) == 0)
	{
	  info->newer_than = stbuf.st_mtime;
	  DEBUG(1,("Getting files newer than %s",
		   asctime(LocalTime(&info->newer_than))));
	  Optind++;
	} else {
	  DEBUG(0,("Error setting newer-than time\n"));
	  return 0;
	}
      }
      break;
    case 'a':
      info->tar.reset=True;
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

  if (!info->tar.type) {
    printf("Option T must be followed by one of c or x.\n");
    return 0;
  }

  info->tar.excl=tar_clipfl!='X';
  if (Optind+1<argc) {
    info->tar.cliplist=argv+Optind+1;
    info->tar.clipn=argc-Optind-1;
  }
  if (Optind>=argc || !strcmp(argv[Optind], "-")) {
    /* Sets tar handle to either 0 or 1, as appropriate */
    info->tar.handle=(info->tar.type=='c');
  } else {
    if ((info->tar.type=='x' && (info->tar.handle = open(argv[Optind], O_RDONLY)) == -1)
	|| (info->tar.type=='c' && (info->tar.handle=creat(argv[Optind], 0644)) < 0))
      {
	DEBUG(0,("Error opening local file %s - %s\n",
		 argv[Optind], strerror(errno)));
	return(0);
      }
  }

  return 1;
}
