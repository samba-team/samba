/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Modified by Jeremy Allison 1995.
   
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
#include "md4.h"

extern int DEBUGLEVEL;

#include "byteorder.h"

void E1(uchar *k, uchar *d, uchar *out)
{
	smbdes(out, d, k);
}
 
void E_P16(uchar *p14,uchar *p16)
{
	/* the following constant makes us compatible with other
	   implementations. Note that publishing this constant does not reduce the
	   security of the encryption mechanism */
	uchar sp8[] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
	E1(p14, sp8, p16);
	E1(p14+7, sp8, p16+8);
}

void E_P24(uchar *p21, uchar *c8, uchar *p24)
{
	E1(p21, c8, p24);
	E1(p21+7, c8, p24+8);
	E1(p21+14, c8, p24+16);
}


/*
   This implements the X/Open SMB password encryption
   It takes a password, a 8 byte "crypt key" and puts 24 bytes of 
   encrypted password into p24 */
void SMBencrypt(uchar *passwd, uchar *c8, uchar *p24)
{
  uchar p14[15], p21[21];

  memset(p21,'\0',21);
  memset(p14,'\0',14);
  StrnCpy((char *)p14,(char *)passwd,14);

  strupper((char *)p14);
  E_P16(p14, p21); 
  E_P24(p21, c8, p24);
}

/* Routines for Windows NT MD4 Hash functions. */
static int _my_wcslen(int16 *str)
{
	int len = 0;
	while(*str++ != 0)
		len++;
	return len;
}

/*
 * Convert a string into an NT UNICODE string.
 * Note that regardless of processor type 
 * this must be in intel (little-endian)
 * format.
 */
 
static int _my_mbstowcs(int16 *dst, uchar *src, int len)
{
	int i;
	int16 val;
 
	for(i = 0; i < len; i++) {
		val = *src;
		SSVAL(dst,0,val);
		dst++;
		src++;
		if(val == 0)
			break;
	}
	return i;
}

/* 
 * Creates the MD4 Hash of the users password in NT UNICODE.
 */
 
void E_md4hash(uchar *passwd, uchar *p16)
{
	int i, len;
	int16 wpwd[129];
	MDstruct MD;
 
	/* Password cannot be longer than 128 characters */
	len = strlen((char *)passwd);
	if(len > 128)
		len = 128;
	/* Password must be converted to NT unicode */
	_my_mbstowcs( wpwd, passwd, len);
	wpwd[len] = 0; /* Ensure string is null terminated */
	/* Calculate length in bytes */
	len = _my_wcslen(wpwd) * sizeof(int16);
 
	MDbegin(&MD);
	for(i = 0; i + 64 <= len; i += 64)
		MDupdate(&MD,wpwd + (i/2), 512);
	MDupdate(&MD,wpwd + (i/2),(len-i)*8);
	SIVAL(p16,0,MD.buffer[0]);
	SIVAL(p16,4,MD.buffer[1]);
	SIVAL(p16,8,MD.buffer[2]);
	SIVAL(p16,12,MD.buffer[3]);
}

/* Does the NT MD4 hash then des encryption. */
 
void SMBNTencrypt(uchar *passwd, uchar *c8, uchar *p24)
{
	uchar p21[21];
 
	memset(p21,'\0',21);
 
	E_md4hash(passwd, p21);    
	E_P24(p21, c8, p24);
}

