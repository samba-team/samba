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

extern int DEBUGLEVEL;

#include "byteorder.h"

/*
   This implements the X/Open SMB password encryption
   It takes a password, a 8 byte "crypt key" and puts 24 bytes of 
   encrypted password into p24
 */
void SMBencrypt(uchar *passwd, uchar *c8, uchar p24[24])
{
  uchar p14[15], p21[21];

  memset(p21,'\0',21);
  memset(p14,'\0',14);
  StrnCpy((char *)p14,(char *)passwd,14);

  strupper((char *)p14);
  E_P16(p14, p21); 
  E_P24(p21, c8, p24);
}

/* Does unicode string convert, then NT MD4 hash then p24 password encryption */
void SMBNTencrypt(char *passwd, uchar *c8, uchar p24[24])
{
	uchar p21[21];
 
	memset(p21,'\0',21);
 
	E_md4hash(passwd, p21);    
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
 
void E_md4hash(uchar *passwd, uchar p16[16])
{
	int len;
	int16 wpwd[129];
	
	/* Password cannot be longer than 128 characters */
	len = strlen((char *)passwd);
	if(len > 128)
		len = 128;
	/* Password must be converted to NT unicode */
	_my_mbstowcs(wpwd, passwd, len);
	wpwd[len] = 0; /* Ensure string is null terminated */
	/* Calculate length in bytes */
	len = _my_wcslen(wpwd) * sizeof(int16);

	mdfour(p16, (unsigned char *)wpwd, len);
}

/* Does the des encryption from the NT or LM MD4 hash. */
void SMBOWFencrypt(uchar passwd[16], uchar *c8, uchar p24[24])
{
	uchar p21[21];
 
	memset(p21,'\0',21);
 
	memcpy(p21, passwd, 16);    
	E_P24(p21, c8, p24);
}

/* Does the NT owf of a user's password */
void nt_owf_gen(char *pwd, uchar nt_p16[16])
{
	char passwd[130];
	StrnCpy(passwd, pwd, sizeof(passwd)-1);

	/* Calculate the MD4 hash (NT compatible) of the password */
	memset(nt_p16, '\0', 16);
	E_md4hash((uchar *)passwd, nt_p16);

	/* clear out local copy of user's password (just being paranoid). */
	bzero(passwd, sizeof(passwd));
}

/* Does both the NT and LM owfs of a user's password */
void nt_lm_owf_gen(char *pwd, uchar nt_p16[16], char p16[16])
{
	char passwd[130];
	StrnCpy(passwd, pwd, sizeof(passwd)-1);

	/* Calculate the MD4 hash (NT compatible) of the password */
	memset(nt_p16, '\0', 16);
	E_md4hash((uchar *)passwd, nt_p16);

	/* Mangle the passwords into Lanman format */
	passwd[14] = '\0';
	strupper(passwd);

	/* Calculate the SMB (lanman) hash functions of the password */

	memset(p16, '\0', 16);
	E_P16((uchar *) passwd, (uchar *)p16);

	/* clear out local copy of user's password (just being paranoid). */
	bzero(passwd, sizeof(passwd));
}

#ifdef USE_ARCFOUR
void arcfour(unsigned char data[16], unsigned char data_out[16], unsigned char data_in[16]);
#endif

#ifdef USE_DES
void des_encrypt8(unsigned char key[7], unsigned char data_in[8], unsigned char data_out[8]);
void des_decrypt8(unsigned char key[7], unsigned char data_in[8], unsigned char data_out[8]);
#endif

BOOL obfuscate_pwd(unsigned char pwd[16], unsigned char sess_key[16], uint8 mode)
{
	unsigned char pwd_c[16];
	
	memcpy(pwd_c, pwd, 16);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("obfuscate_pwd:"));
		dump_data(100, pwd, 16);
#endif

	if (mode == 1)
	{
#ifdef USE_ARCFOUR

		unsigned char arc4_key[16];
		memcpy(arc4_key, sess_key, 16);
		arcfour(arc4_key, pwd_c, pwd);

#else

		return False;

#endif
	}
	else
	{
		/* lkcl XXXX - bugger.  need to do two DES 8 byte encrypts */
#ifdef USE_DES

		/* use bytes 0-6 of sess key to encrypt 1st 8 bytes of pwd_c */
		/* use bytes 8-14 of sess key to encrypt 1st 8 bytes of pwd_c */
		/* yes, bytes 7 and 15 _are_ ignored... */

		if (mode == 0)
		{
			des_encrypt8(sess_key  , pwd_c  , pwd);
			des_encrypt8(sess_key+8, pwd_c+8, pwd);
		}
		else
		{
			des_decrypt8(sess_key  , pwd_c  , pwd);
			des_decrypt8(sess_key+8, pwd_c+8, pwd);
		}

#else

	return False;

#endif
	}

#ifdef DEBUG_PASSWORD
	DEBUG(100,("obfuscate_pwd:"));
	dump_data(100, pwd, 16);
#endif

	return True;
}

