/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
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

#ifndef _CLIENT_H
#define _CLIENT_H

/* the client asks for a smaller buffer to save ram and also to get more
   overlap on the wire */
#define CLI_BUFFER_SIZE (0x4000)

/*
 * These definitions depend on smb.h
 */

typedef struct file_info
{
  SMB_OFF_T size;
  int mode;
  uid_t uid;
  gid_t gid;
  /* these times are normally kept in GMT */
  time_t mtime;
  time_t atime;
  time_t ctime;
  pstring name;
} file_info;

struct pwd_info
{
    BOOL null_pwd;
    BOOL cleartext;
    BOOL crypted;

    fstring password;

    uchar smb_lm_pwd[16];
    uchar smb_nt_pwd[16];

    uchar smb_lm_owf[24];
    uchar smb_nt_owf[24];
};

struct cli_state {
  int fd;
  uint16 cnum;
  uint16 pid;
  uint16 mid;
  uint16 vuid;
  int protocol;
  int sec_mode;
  int rap_error;
  int privilages;

  fstring eff_name;
  fstring desthost;
  fstring user_name;
  fstring domain;

  fstring share;
  fstring dev;
  struct nmb_name called;
  struct nmb_name calling;
  fstring full_dest_host_name;
  struct in_addr dest_ip;

  struct pwd_info pwd;
  unsigned char cryptkey[8];
  uint32 sesskey;
  int serverzone;
  uint32 servertime;
  int readbraw_supported;
  int writebraw_supported;
  int timeout;
  int max_xmit;
  int max_mux;
  char *outbuf;
  char *inbuf;
  int bufsize;
  int initialised;
  int win95;
  uint32 capabilities;
  /*
   * Only used in NT domain calls.
   */
  uint32 nt_error;                   /* NT RPC error code. */
  uint16 nt_pipe_fnum;               /* Pipe handle. */
  unsigned char sess_key[16];        /* Current session key. */
  DOM_CRED clnt_cred;                /* Client credential. */
  fstring mach_acct;                 /* MYNAME$. */
  fstring srv_name_slash;            /* \\remote server. */
  fstring clnt_name_slash;            /* \\local client. */
};

#endif /* _CLIENT_H */
