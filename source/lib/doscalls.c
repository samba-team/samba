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

#if 0 /* Use vfs_unlink. */
/*******************************************************************
 Unlink wrapper that calls dos_to_unix.
********************************************************************/

int dos_unlink(char *fname)
{
  return(unlink(dos_to_unix(fname,False)));
}
#endif

/*******************************************************************
 Open() wrapper that calls dos_to_unix.
********************************************************************/

int dos_open(char *fname,int flags,mode_t mode)
{
  return(sys_open(dos_to_unix(fname,False),flags,mode));
}

/*******************************************************************
 Opendir() wrapper that calls dos_to_unix.  Should use the 
 vfs_ops->opendir() function instead.
********************************************************************/

#if 0
DIR *dos_opendir(char *dname)
{
  return(opendir(dos_to_unix(dname,False)));
}
#endif

/*******************************************************************
 Readdirname() wrapper that calls unix_to_dos.  Should use the 
 vfs_readdirname() function instead.
********************************************************************/

#if 0
char *dos_readdirname(DIR *p)
{
  char *dname = readdirname(p);

  if (!dname)
    return(NULL);
 
  unix_to_dos(dname, True);
  return(dname);
}
#endif

/*******************************************************************
 A chown() wrapper that calls dos_to_unix.
********************************************************************/

#if 0 /* Use vfs_chown. */
int dos_chown(char *fname, uid_t uid, gid_t gid)
{
  return(sys_chown(dos_to_unix(fname,False),uid,gid));
}
#endif

/*******************************************************************
 A stat() wrapper that calls dos_to_unix.
********************************************************************/

int dos_stat(char *fname,SMB_STRUCT_STAT *sbuf)
{
  return(sys_stat(dos_to_unix(fname,False),sbuf));
}

/*******************************************************************
 An lstat() that calls dos_to_unix.
********************************************************************/

int dos_lstat(char *fname,SMB_STRUCT_STAT *sbuf)
{
  return(sys_lstat(dos_to_unix(fname,False),sbuf));
}

#if 0 /* VFS */
/*******************************************************************
 Mkdir() that calls dos_to_unix.
 Cope with UNIXes that don't allow high order mode bits on mkdir.
 Patch from gcarter@lanier.com.
 Don't use this call unless you really want to access a file on 
 disk.  Use the vfs_ops.mkdir() function instead.
********************************************************************/

int dos_mkdir(char *dname,mode_t mode)
{
  int ret = mkdir(dos_to_unix(dname,False),mode);
  if(!ret)
    return(dos_chmod(dname,mode));
  else
    return ret;
}
#endif

/*******************************************************************
 Rmdir() - call dos_to_unix.
********************************************************************/

int dos_rmdir(char *dname)
{
  return(rmdir(dos_to_unix(dname,False)));
}

#if 0 /* VFS */
/*******************************************************************
 chdir() - call dos_to_unix.
********************************************************************/

int dos_chdir(char *dname)
{
  return(chdir(dos_to_unix(dname,False)));
}
#endif

/*******************************************************************
 Utime() - call dos_to_unix.
********************************************************************/

int dos_utime(char *fname,struct utimbuf *times)
{
  /* if the modtime is 0 or -1 then ignore the call and
     return success */
  if (times->modtime == (time_t)0 || times->modtime == (time_t)-1)
    return 0;
  
  /* if the access time is 0 or -1 then set it to the modtime */
  if (times->actime == (time_t)0 || times->actime == (time_t)-1)
    times->actime = times->modtime;
   
  return(utime(dos_to_unix(fname,False),times));
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

/*******************************************************************
 Rename() - call dos_to_unix.
********************************************************************/

int dos_rename(char *from, char *to)
{
    int rcode;  
    pstring zfrom, zto;

    pstrcpy (zfrom, dos_to_unix (from, False));
    pstrcpy (zto, dos_to_unix (to, False));
    rcode = rename (zfrom, zto);

    if (errno == EXDEV) 
    {
      /* Rename across filesystems needed. */
      rcode = copy_reg (zfrom, zto);        
    }
    return rcode;
}

/*******************************************************************
 Chmod - call dos_to_unix.
********************************************************************/

int dos_chmod(char *fname,mode_t mode)
{
  return(chmod(dos_to_unix(fname,False),mode));
}

#if 0 /* VFS */
/*******************************************************************
 Getwd - takes a UNIX directory name and returns the name
 in dos format.
********************************************************************/

char *dos_getwd(char *unix_path)
{
	char *wd;
	wd = sys_getwd(unix_path);
	if (wd)
		unix_to_dos(wd, True);
	return wd;
}
#endif /* VFS */

/*******************************************************************
 Check if a DOS file exists.  Use vfs_file_exist function instead.
********************************************************************/

#if 0
BOOL dos_file_exist(char *fname,SMB_STRUCT_STAT *sbuf)
{
  return file_exist(dos_to_unix(fname, False), sbuf);
}
#endif

/*******************************************************************
 Check if a DOS directory exists.
********************************************************************/

BOOL dos_directory_exist(char *dname,SMB_STRUCT_STAT *st)
{
  return directory_exist(dos_to_unix(dname, False), st);
}

/*******************************************************************
 Return the modtime of a DOS pathname.
********************************************************************/

time_t dos_file_modtime(char *fname)
{
  return file_modtime(dos_to_unix(fname, False));
}

/*******************************************************************
 Return the file size of a DOS pathname.
********************************************************************/

SMB_OFF_T dos_file_size(char *file_name)
{
  return get_file_size(dos_to_unix(file_name, False));
}
