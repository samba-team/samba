/* 
   Unix SMB/Netbios implementation.
   Version 1.9.

   Functions to create reasonable random numbers for crypto use.

   Copyright (C) Jeremy Allison 1998
   
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

extern int DEBUGLEVEL;

/**************************************************************
 Try and get a good random number seed. Try a number of
 different factors. Firstly, try /dev/random and try and
 read from this. If this fails iterate through /tmp and
 XOR all the file timestamps. If this fails then just use
 a combination of pid and time of day (yes I know this
 sucks :-). Finally md4 the result.
**************************************************************/

static uint32 do_reseed(void)
{
  static int counter = 0;
  unsigned char md4_outbuf[16];
  unsigned char md4_inbuf[40];
  BOOL got_random = False;
  uint32 v1, v2, ret;
  int fd;
  struct timeval tval;

  memset(md4_inbuf, '\0', sizeof(md4_inbuf));

  fd = open( "/dev/random", O_RDONLY);
  if(fd >= 0) {
    /* 
     * We can use /dev/random !
     */
    if(read(fd, md4_inbuf, 40) == 40) {
      got_random = True;
      DEBUG(10,("do_reseed: got 40 bytes from /dev/random.\n"));
    }
    close(fd);
  }

  if(!got_random) {
    /*
     * /dev/random failed - try /tmp/ for timestamps.
     */
    void *dp = sys_opendir("/tmp");

    if(dp != NULL) {
      char *p;

      while ((p = readdirname(dp))) {           
        struct stat st;
        if(sys_stat(p,&st) != 0)
          SIVAL(md4_inbuf, ((counter%sizeof(md4_inbuf))/4), 
                IVAL(md4_inbuf,((counter%sizeof(md4_inbuf))/4)) ^ st.st_atime);
          counter++;
          DEBUG(10,("do_reseed: value from file %s.\n", p));
        }
      }
    closedir(dp); 
  }

  /*
   * Finally add the counter, time of day, and pid.
   */
  GetTimeOfDay(&tval);
  v1 = (counter++) + getpid() + tval.tv_sec;
  v2 = (counter++) * getpid() + tval.tv_usec;

  SIVAL(md4_inbuf, 32, v1 ^ IVAL(md4_inbuf, 32));
  SIVAL(md4_inbuf, 36, v1 ^ IVAL(md4_inbuf, 36));

  mdfour(md4_outbuf, md4_inbuf, sizeof(md4_inbuf));

  /* XOR everything togther in blocks of 4 bytes. */
  ret = IVAL(md4_outbuf,0);
  ret ^= IVAL(md4_outbuf,4);
  ret ^= IVAL(md4_outbuf,8);
  ret ^= IVAL(md4_outbuf,12);

  DEBUG(10,("do_reseed: returning seed %lu\n", ret));

  return ret;
}

/*******************************************************************
 Interface to the (hopefully) good crypto random number generator.
********************************************************************/

void generate_random_buffer( unsigned char *out, int len, BOOL re_seed)
{
  static BOOL done_reseed = False;
  unsigned char tmp_buf[64];
  unsigned char md4_buf[16];
  unsigned char *p;

  if(!done_reseed || re_seed) {
    srandom(do_reseed());
    done_reseed = True;
  }

  /*
   * Generate random numbers in chunks of 64 bytes,
   * then md4 them & copy to the output buffer.
   */

  p = out;
  while(len > 0) {
    int i;
    int copy_len = len > 16 ? 16 : len;
    for( i = 0; i < 16; i++)
      SIVAL(tmp_buf, i*4, random());
    mdfour(md4_buf, tmp_buf, sizeof(tmp_buf));
    memcpy(p, md4_buf, copy_len);
    p += copy_len;
    len -= copy_len;
  }
}
