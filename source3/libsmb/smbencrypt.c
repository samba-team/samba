/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Modified by Jeremy Allison 1995.
   Copyright (C) Jeremy Allison 1995-2000.
   Copyright (C) Luke Kennethc Casson Leighton 1996-2000.
   
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
#include "byteorder.h"

/*
   This implements the X/Open SMB password encryption
   It takes a password, a 8 byte "crypt key" and puts 24 bytes of 
   encrypted password into p24 */
void SMBencrypt(const uchar *passwd, const uchar *c8, uchar *p24)
{
	uchar p14[15], p21[21];

	memset(p21,'\0',21);
	memset(p14,'\0',14);
	StrnCpy((char *)p14,(const char *)passwd,14);

	strupper((char *)p14);
	E_P16(p14, p21); 

	SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("SMBencrypt: lm#, challenge, response\n"));
	dump_data(100, (char *)p21, 16);
	dump_data(100, (const char *)c8, 8);
	dump_data(100, (char *)p24, 24);
#endif
}

/* 
 * Creates the MD4 Hash of the users password in NT UNICODE.
 */
 
void E_md4hash(const uchar *passwd, uchar *p16)
{
	int len;
	smb_ucs2_t wpwd[129];
	
	/* Password cannot be longer than 128 characters */
	len = strlen((const char *)passwd);
	if(len > 128)
		len = 128;
	/* Password must be converted to NT unicode - null terminated. */
	push_ucs2(NULL, wpwd, (const char *)passwd, 256, STR_UNICODE|STR_NOALIGN|STR_TERMINATE);
	/* Calculate length in bytes */
	len = strlen_w(wpwd) * sizeof(int16);

	mdfour(p16, (unsigned char *)wpwd, len);
}

/* Does both the NT and LM owfs of a user's password */
void nt_lm_owf_gen(const char *pwd, uchar nt_p16[16], uchar p16[16])
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

/* Does both the NTLMv2 owfs of a user's password */
void ntv2_owf_gen(const uchar owf[16],
		  const char *user_n, const char *domain_n, uchar kr_buf[16])
{
	pstring user_u;
	pstring dom_u;
	HMACMD5Context ctx;

	int user_l = strlen(user_n);
	int domain_l = strlen(domain_n);

	push_ucs2(NULL, user_u, user_n, (user_l+1)*2, STR_UNICODE|STR_NOALIGN|STR_TERMINATE|STR_UPPER);
	push_ucs2(NULL, dom_u, domain_n, (domain_l+1)*2, STR_UNICODE|STR_NOALIGN|STR_TERMINATE|STR_UPPER);

	hmac_md5_init_limK_to_64(owf, 16, &ctx);
	hmac_md5_update((const unsigned char *)user_u, user_l * 2, &ctx);
	hmac_md5_update((const unsigned char *)dom_u, domain_l * 2, &ctx);
	hmac_md5_final(kr_buf, &ctx);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("ntv2_owf_gen: user, domain, owfkey, kr\n"));
	dump_data(100, user_u, user_l * 2);
	dump_data(100, dom_u, domain_l * 2);
	dump_data(100, owf, 16);
	dump_data(100, kr_buf, 16);
#endif
}

/* Does the des encryption from the NT or LM MD4 hash. */
void SMBOWFencrypt(const uchar passwd[16], const uchar *c8, uchar p24[24])
{
	uchar p21[21];
 
	memset(p21,'\0',21);
 
	memcpy(p21, passwd, 16);    
	E_P24(p21, c8, p24);
}

/* Does the des encryption from the FIRST 8 BYTES of the NT or LM MD4 hash. */
void NTLMSSPOWFencrypt(const uchar passwd[8], const uchar *ntlmchalresp, uchar p24[24])
{
	uchar p21[21];
 
	memset(p21,'\0',21);
	memcpy(p21, passwd, 8);    
	memset(p21 + 8, 0xbd, 8);    

	E_P24(p21, ntlmchalresp, p24);
#ifdef DEBUG_PASSWORD
	DEBUG(100,("NTLMSSPOWFencrypt: p21, c8, p24\n"));
	dump_data(100, (char *)p21, 21);
	dump_data(100, (const char *)ntlmchalresp, 8);
	dump_data(100, (char *)p24, 24);
#endif
}


/* Does the NT MD4 hash then des encryption. */
 
void SMBNTencrypt(const uchar *passwd, uchar *c8, uchar *p24)
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

/* Does the md5 encryption from the NT hash for NTLMv2. */
void SMBOWFencrypt_ntv2(const uchar kr[16],
			const DATA_BLOB srv_chal,
			const DATA_BLOB cli_chal,
			char resp_buf[16])
{
	HMACMD5Context ctx;

	hmac_md5_init_limK_to_64(kr, 16, &ctx);
	hmac_md5_update(srv_chal.data, srv_chal.length, &ctx);
	hmac_md5_update(cli_chal.data, cli_chal.length, &ctx);
	hmac_md5_final((unsigned char *)resp_buf, &ctx);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBOWFencrypt_ntv2: srv_chal, cli_chal, resp_buf\n"));
	dump_data(100, srv_chal.data, srv_chal.length);
	dump_data(100, cli_chal.data, cli_chal.length);
	dump_data(100, resp_buf, 16);
#endif
}

void SMBsesskeygen_ntv2(const uchar kr[16],
			const uchar * nt_resp, uint8 sess_key[16])
{
	HMACMD5Context ctx;

	hmac_md5_init_limK_to_64(kr, 16, &ctx);
	hmac_md5_update(nt_resp, 16, &ctx);
	hmac_md5_final((unsigned char *)sess_key, &ctx);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBsesskeygen_ntv2:\n"));
	dump_data(100, sess_key, 16);
#endif
}

void SMBsesskeygen_ntv1(const uchar kr[16],
			const uchar * nt_resp, uint8 sess_key[16])
{
	mdfour((unsigned char *)sess_key, kr, 16);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBsesskeygen_ntv1:\n"));
	dump_data(100, sess_key, 16);
#endif
}

/***********************************************************
 encode a password buffer.  The caller gets to figure out 
 what to put in it.
************************************************************/
BOOL encode_pw_buffer(char buffer[516], char *new_pw, int new_pw_length)
{
	generate_random_buffer((unsigned char *)buffer, 516, True);

	memcpy(&buffer[512 - new_pw_length], new_pw, new_pw_length);

	/* 
	 * The length of the new password is in the last 4 bytes of
	 * the data buffer.
	 */
	SIVAL(buffer, 512, new_pw_length);

	return True;
}

/***********************************************************
 decode a password buffer
 *new_pw_len is the length in bytes of the possibly mulitbyte
 returned password including termination.
************************************************************/
BOOL decode_pw_buffer(char in_buffer[516], char *new_pwrd,
		      int new_pwrd_size, uint32 *new_pw_len)
{
	int byte_len=0;

	/*
	  Warning !!! : This function is called from some rpc call.
	  The password IN the buffer is a UNICODE string.
	  The password IN new_pwrd is an ASCII string
	  If you reuse that code somewhere else check first.
	*/

	/* The length of the new password is in the last 4 bytes of the data buffer. */

	byte_len = IVAL(in_buffer, 512);

#ifdef DEBUG_PASSWORD
	dump_data(100, in_buffer, 516);
#endif

	/* Password cannot be longer than 128 characters */
	if ( (byte_len < 0) || (byte_len > new_pwrd_size - 1)) {
		DEBUG(0, ("decode_pw_buffer: incorrect password length (%d).\n", byte_len));
		DEBUG(0, ("decode_pw_buffer: check that 'encrypt passwords = yes'\n"));
		return False;
	}

	/* decode into the return buffer.  Buffer must be a pstring */
 	*new_pw_len = pull_string(NULL, new_pwrd, &in_buffer[512 - byte_len], new_pwrd_size, byte_len, STR_UNICODE);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("decode_pw_buffer: new_pwrd: "));
	dump_data(100, (char *)new_pwrd, *new_pw_len);
	DEBUG(100,("multibyte len:%d\n", *new_pw_len));
	DEBUG(100,("original char len:%d\n", byte_len/2));
#endif
	
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
	mdfour(nt_p16, (const unsigned char *)buf, pwd->uni_str_len * 2);

	/* clear out local copy of user's password (just being paranoid). */
	ZERO_STRUCT(buf);
}
