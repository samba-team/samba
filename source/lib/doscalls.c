/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba system utilities
   Copyright (C) Jeremy Allison 1992-1998
   
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

/*
 * Wrappers for calls that need to translate to
 * DOS/Windows semantics. Note that the pathnames
 * in all these functions referred to as 'DOS' names
 * are actually in UNIX path format (ie. '/' instead of
 * '\' directory separators etc.), but the codepage they
 * are in is still the client codepage, hence the 'DOS'
 * name.
 */

extern int DEBUGLEVEL;

/*******************************************************************
 Open() wrapper that calls dos_to_unix.
********************************************************************/

int dos_open(char *fname,int flags,mode_t mode)
{
  return(sys_open(dos_to_unix(fname,False),flags,mode));
}

/*******************************************************************
 A stat() wrapper that calls dos_to_unix.
********************************************************************/

int dos_stat(char *fname,SMB_STRUCT_STAT *sbuf)
{
  return(sys_stat(dos_to_unix(fname,False),sbuf));
}

/*********************************************************
 For rename across filesystems Patch from Warren Birnbaum 
 <warrenb@hpcvscdp.cv.hp.com>
**********************************************************/

int copy_reg(char *source, const char *dest)
{
  SMB_STRUCT_STAT source_stats;
  int ifd;
  int ofd;
  char *buf;
  int len;                      /* Number of bytes read into `buf'. */

  sys_lstat (source, &source_stats);
  if (!S_ISREG (source_stats.st_mode))
    return 1;

  if (unlink (dest) && errno != ENOENT)
    return 1;

  if((ifd = sys_open (source, O_RDONLY, 0)) < 0)
    return 1;

  if((ofd = sys_open (dest, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0 )
  {
    close (ifd);
    return 1;
  }

  if((buf = malloc( COPYBUF_SIZE )) == NULL)
  {
    close (ifd);  
    close (ofd);  
    unlink (dest);
    return 1;
  }

  while ((len = read(ifd, buf, COPYBUF_SIZE)) > 0)
  {
    if (write_data(ofd, buf, len) < 0)
    {
      close (ifd);
      close (ofd);
      unlink (dest);
      free(buf);
      return 1;
    }
  }
  free(buf);
  if (len < 0)
  {
    close (ifd);
    close (ofd);
    unlink (dest);
    return 1;
  }

  if (close (ifd) < 0)
  {
    close (ofd);
    return 1;
  }
  if (close (ofd) < 0)
    return 1;

  /* chown turns off set[ug]id bits for non-root,
     so do the chmod last.  */

  /* Try to copy the old file's modtime and access time.  */
  {
    struct utimbuf tv;

    tv.actime = source_stats.st_atime;
    tv.modtime = source_stats.st_mtime;
    if (utime (dest, &tv))
      return 1;
  }

  /* Try to preserve ownership.  For non-root it might fail, but that's ok.
     But root probably wants to know, e.g. if NFS disallows it.  */
  if (chown (dest, source_stats.st_uid, source_stats.st_gid)
      && (errno != EPERM))
    return 1;

  if (chmod (dest, source_stats.st_mode & 07777))
    return 1;

  unlink (source);
  return 0;
}
