/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
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
   encrypted password into p24 */
void SMBencrypt(uchar *passwd, uchar *c8, uchar *p24)
{
	uchar p14[15], p21[21];

	memset(p21,'\0',21);
	memset(p14,'\0',14);
	StrnCpy((char *)p14,(char *)passwd,14);

	strupper((char *)p14);
	E_P16(p14, p21); 

	SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("SMBencrypt: lm#, challenge, response\n"));
	dump_data(100, (char *)p21, 16);
	dump_data(100, (char *)c8, 8);
	dump_data(100, (char *)p24, 24);
#endif
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

/* Does both the NT and LM owfs of a user's password */
void nt_lm_owf_gen(char *pwd, uchar nt_p16[16], uchar p16[16])
{
	char passwd[514];

	memset(passwd,'\0',514);
	safe_strcpy( passwd, pwd, sizeof(passwd)-1);

	/* Calculate the MD4 hash (NT compatible) of the password */
	memset(nt_p16, '\0', 16);
	E_md4hash((uchar *)passwd, nt_p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: pwd, nt#\n"));
	dump_data(120, passwd, strlen(passwd));
	dump_data(100, (char *)nt_p16, 16);
#endif

	/* Mangle the passwords into Lanman format */
	passwd[14] = '\0';
	strupper(passwd);

	/* Calculate the SMB (lanman) hash functions of the password */

	memset(p16, '\0', 16);
	E_P16((uchar *) passwd, (uchar *)p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: pwd, lm#\n"));
	dump_data(120, passwd, strlen(passwd));
	dump_data(100, (char *)p16, 16);
#endif
	/* clear out local copy of user's password (just being paranoid). */
	memset(passwd, '\0', sizeof(passwd));
}

/* Does the des encryption from the NT or LM MD4 hash. */
void SMBOWFencrypt(uchar passwd[16], uchar *c8, uchar p24[24])
{
	uchar p21[21];
 
	memset(p21,'\0',21);
 
	memcpy(p21, passwd, 16);    
	E_P24(p21, c8, p24);
}

/* Does the des encryption from the FIRST 8 BYTES of the NT or LM MD4 hash. */
void NTLMSSPOWFencrypt(uchar passwd[8], uchar *ntlmchalresp, uchar p24[24])
{
	uchar p21[21];
 
	memset(p21,'\0',21);
	memcpy(p21, passwd, 8);    
	memset(p21 + 8, 0xbd, 8);    

	E_P24(p21, ntlmchalresp, p24);
#ifdef DEBUG_PASSWORD
	DEBUG(100,("NTLMSSPOWFencrypt: p21, c8, p24\n"));
	dump_data(100, (char *)p21, 21);
	dump_data(100, (char *)ntlmchalresp, 8);
	dump_data(100, (char *)p24, 24);
#endif
}


/* Does the NT MD4 hash then des encryption. */
 
void SMBNTencrypt(uchar *passwd, uchar *c8, uchar *p24)
{
	uchar p21[21];
 
	memset(p21,'\0',21);
 
	E_md4hash(passwd, p21);    
	SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("SMBNTencrypt: nt#, challenge, response\n"));
	dump_data(100, (char *)p21, 16);
	dump_data(100, (char *)c8, 8);
	dump_data(100, (char *)p24, 24);
#endif
}

BOOL make_oem_passwd_hash(char data[516], const char *passwd, uchar old_pw_hash[16], BOOL unicode)
{
	int new_pw_len = strlen(passwd) * (unicode ? 2 : 1);

	if (new_pw_len > 512)
	{
		DEBUG(0,("make_oem_passwd_hash: new password is too long.\n"));
		return False;
	}

	/*
	 * Now setup the data area.
	 * We need to generate a random fill
	 * for this area to make it harder to
	 * decrypt. JRA.
	 */
	generate_random_buffer((unsigned char *)data, 516, False);
	push_string(NULL, &data[512 - new_pw_len], passwd, new_pw_len, 
		    STR_NOALIGN | (unicode?STR_UNICODE:STR_ASCII));
	SIVAL(data, 512, new_pw_len);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("make_oem_passwd_hash\n"));
	dump_data(100, data, 516);
#endif
	SamOEMhash( (unsigned char *)data, (unsigned char *)old_pw_hash, 516);

	return True;
}

/***********************************************************
 encode a password buffer
************************************************************/
BOOL encode_pw_buffer(char buffer[516], const char *new_pass,
		      int new_pw_len, BOOL nt_pass_set)
{
	generate_random_buffer(buffer, 516, True);

	if (nt_pass_set) {
		new_pw_len *= 2;
		push_ucs2(NULL, &buffer[512 - new_pw_len], new_pass,
			  new_pw_len, 0);
	} else {
		push_ascii(&buffer[512 - new_pw_len], new_pass,
			   new_pw_len, 0);
	}

	/* 
	 * The length of the new password is in the last 4 bytes of
	 * the data buffer.
	 */
	SIVAL(buffer, 512, new_pw_len);

	return True;
}

/***********************************************************
 decode a password buffer
************************************************************/
BOOL decode_pw_buffer(char in_buffer[516], char *new_pwrd,
		      int new_pwrd_size, uint32 *new_pw_len,
		      uchar nt_p16[16], uchar p16[16])
{
	int uni_pw_len=0;
	int byte_len=0;
	char unicode_passwd[514];
	char lm_ascii_passwd[514];
	char passwd[514];

	/*
	  Warning !!! : This function is called from some rpc call.
	  The password IN the buffer is a UNICODE string.
	  The password IN new_pwrd is an ASCII string
	  If you reuse that code somewhere else check first.
	*/

	ZERO_STRUCT(unicode_passwd);
	ZERO_STRUCT(lm_ascii_passwd);
	ZERO_STRUCT(passwd);

	memset(nt_p16, '\0', 16);
	memset(p16, '\0', 16);

	/* The length of the new password is in the last 4 bytes of the data buffer. */

	byte_len = IVAL(in_buffer, 512);

#ifdef DEBUG_PASSWORD
	dump_data(100, in_buffer, 516);
#endif

	/* Password cannot be longer than 128 characters */
	if ( (byte_len < 0) || (byte_len > new_pwrd_size - 1)) {
		DEBUG(0, ("decode_pw_buffer: incorrect password length (%d).\n", byte_len));
		return False;
	}
	
 	pull_string(NULL, passwd, &in_buffer[512 - byte_len], -1, byte_len, STR_UNICODE);
	uni_pw_len = byte_len/2;

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: passwd: "));
	dump_data(100, (char *)passwd, uni_pw_len);
	DEBUG(100,("len:%d\n", uni_pw_len));
#endif
	memcpy(unicode_passwd, &in_buffer[512 - byte_len], byte_len);
		
	mdfour(nt_p16, (unsigned char *)unicode_passwd, byte_len);
	
#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: nt#:"));
	dump_data(100, (char *)nt_p16, 16);
	DEBUG(100,("\n"));
#endif
	
	/* Mangle the passwords into Lanman format */
	memcpy(lm_ascii_passwd, passwd, byte_len/2);
	lm_ascii_passwd[14] = '\0';
	strupper(lm_ascii_passwd);

	/* Calculate the SMB (lanman) hash functions of the password */
	E_P16((uchar *) lm_ascii_passwd, (uchar *)p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: lm#:"));
	dump_data(100, (char *)p16, 16);
	DEBUG(100,("\n"));
#endif

	/* copy the password and it's length to the return buffer */	
	*new_pw_len = byte_len/2;
	memcpy(new_pwrd, passwd, uni_pw_len);
	new_pwrd[uni_pw_len]='\0';
	
	/* clear out local copy of user's password (just being paranoid). */
	ZERO_STRUCT(unicode_passwd);
	ZERO_STRUCT(lm_ascii_passwd);
	ZERO_STRUCT(passwd);
	
	return True;

}

/* Calculate the NT owfs of a user's password */
void nt_owf_genW(const UNISTR2 *pwd, uchar nt_p16[16])
{
	char buf[512];
	int i;

	for (i = 0; i < MIN(pwd->uni_str_len, sizeof(buf) / 2); i++)
	{
		SIVAL(buf, i * 2, pwd->buffer[i]);
	}
	/* Calculate the MD4 hash (NT compatible) of the password */
	mdfour(nt_p16, buf, pwd->uni_str_len * 2);

	/* clear out local copy of user's password (just being paranoid). */
	ZERO_STRUCT(buf);
}
