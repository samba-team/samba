#ifndef _SMBPASS_H_
#define _SMBPASS_H_
/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Jeremy Allison 1995
   
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

struct smb_passwd {
	int smb_userid;
	char *smb_name;
	unsigned char *smb_passwd; /* Null if no password */
	unsigned char *smb_nt_passwd; /* Null if no password */
	/* Other fields / flags may be added later */
};

/* Return a smb_passwd struct given a user name, 0 if fails. */
struct smb_passwd *get_smbpwnam(char *user);

#ifndef uchar
#define uchar unsigned char
#endif

/* SMB Encryption functions. */
void str_to_key(unsigned char *str,unsigned char *key);
void E_P16(uchar *p14,uchar *p16);
void E_P24(unsigned char *p21, unsigned char *c8, unsigned char *p24);
void E_md4hash(uchar *passwd,uchar *p16);
void SMBencrypt(unsigned char *passwd, unsigned char *c8, unsigned char *p24);
void SMB_nt_encrypt(unsigned char *passwd, unsigned char *c8, unsigned char *p24);

/* Password file lock/unlock routines */
int pw_file_lock(char *name, int type, int secs);
int pw_file_unlock(int fd);
#endif
