/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB wrapper stat functions
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Derrell Lipman 2003-2005
   
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

#include "smbw.h"

static int timezone_diff = -1;

#define TM_YEAR_BASE 1900

/*******************************************************************
yield the difference between *A and *B, in seconds, ignoring leap seconds
********************************************************************/
static int tm_diff(struct tm *a, struct tm *b)
{
  int ay = a->tm_year + (TM_YEAR_BASE - 1);
  int by = b->tm_year + (TM_YEAR_BASE - 1);
  int intervening_leap_days =
    (ay/4 - by/4) - (ay/100 - by/100) + (ay/400 - by/400);
  int years = ay - by;
  int days = 365*years + intervening_leap_days + (a->tm_yday - b->tm_yday);
  int hours = 24*days + (a->tm_hour - b->tm_hour);
  int minutes = 60*hours + (a->tm_min - b->tm_min);
  int seconds = 60*minutes + (a->tm_sec - b->tm_sec);

  return seconds;
}

/*******************************************************************
  return the UTC offset in seconds west of UTC, or 0 if it cannot be determined
  ******************************************************************/
static int TimeZone(time_t t)
{
  struct tm *tm = gmtime(&t);
  struct tm tm_utc;
  if (!tm)
    return 0;
  tm_utc = *tm;
  tm = localtime(&t);
  if (!tm)
    return 0;
  return tm_diff(&tm_utc,tm);

}


static void copy_stat(struct SMBW_stat *external, struct stat *internal)
{
        if (timezone_diff < 0)
        {
            timezone_diff = TimeZone(time(NULL));
        }

        external->s_dev = internal->st_dev;
        external->s_ino = internal->st_ino;
        external->s_mode = internal->st_mode;
        external->s_nlink = internal->st_nlink;
        external->s_uid = internal->st_uid;
        external->s_gid = internal->st_gid;
        external->s_rdev = internal->st_rdev;
        external->s_size = internal->st_size;
        external->s_blksize = internal->st_blksize;
        external->s_blocks = internal->st_blocks;
        external->s_atime = internal->st_atime + timezone_diff;
        external->s_mtime = internal->st_mtime + timezone_diff;
        external->s_ctime = internal->st_ctime + timezone_diff;
}


/***************************************************** 
a wrapper for fstat()
*******************************************************/
int smbw_fstat(int fd_smbw, struct SMBW_stat *st)
{
        int fd_client = smbw_fd_map[fd_smbw];
        struct stat statbuf;

        if (smbc_fstat(fd_client, &statbuf) < 0) {
                return -1;
        }
        
        copy_stat(st, &statbuf);

	return 0;
}


/***************************************************** 
a wrapper for stat()
*******************************************************/
int smbw_stat(const char *fname, struct SMBW_stat *st)
{
        int simulate;
        char *p;
        char path[PATH_MAX];
        struct stat statbuf;

        SMBW_INIT();

        smbw_fix_path(fname, path);

        p = path + 6;           /* look just past smb:// */
        simulate = (strchr(p, '/') == NULL);

        /* special case for full-network scan, workgroups, and servers */
        if (simulate) {
            statbuf.st_dev = 0;
            statbuf.st_ino = 0;
            statbuf.st_mode = 0040777;
            statbuf.st_nlink = 1;
            statbuf.st_uid = 0;
            statbuf.st_gid = 0;
            statbuf.st_rdev = 0;
            statbuf.st_size = 0;
            statbuf.st_blksize = 1024;
            statbuf.st_blocks = 1;
            statbuf.st_atime = 0; /* beginning of epoch */
            statbuf.st_mtime = 0; /* beginning of epoch */
            statbuf.st_ctime = 0; /* beginning of epoch */

        } else if (smbc_stat(path, &statbuf) < 0) {
                return -1;
        }
        
        copy_stat(st, &statbuf);

	return 0;
}
