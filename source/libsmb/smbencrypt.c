/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-2000
   Modified by Jeremy Allison.
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

extern int DEBUGLEVEL;

/*
   This implements the X/Open SMB password encryption
   It takes a password, a 8 byte "crypt key" and puts 24 bytes of 
   encrypted password into p24 */
void SMBencrypt(uchar * pwrd, uchar * c8, uchar * p24)
{
	uchar p21[21];

	lm_owf_gen(pwrd, p21);
	SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBencrypt: lm#, challenge, response\n"));
	dump_data(100, p21, 16);
	dump_data(100, c8, 8);
	dump_data(100, p24, 24);
#endif
}

void SMBNTencrypt(uchar * pwrd, uchar * c8, uchar * p24)
{
	uchar p21[21];

	ZERO_STRUCT(p21);

	nt_owf_gen(pwrd, p21);
	SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBNTencrypt: nt#, challenge, response\n"));
	dump_data(100, p21, 16);
	dump_data(100, c8, 8);
	dump_data(100, p24, 24);
#endif
}

/* Routines for Windows NT MD4 Hash functions. */
static int _my_wcslen(int16 * str)
{
	int len = 0;
	while (*str++ != 0)
		len++;
	return len;
}

/*
 * Convert a string into an NT UNICODE string.
 * Note that regardless of processor type 
 * this must be in intel (little-endian)
 * format.
 */

static int _my_mbstowcsupper(int16 * dst, const uchar * src, int len)
{
	int i;
	int16 val;

	for (i = 0; i < len; i++)
	{
		val = toupper(*src);
		SSVAL(dst, 0, val);
		dst++;
		src++;
		if (val == 0)
			break;
	}
	return i;
}

static int _my_mbstowcs(int16 * dst, const uchar * src, int len)
{
	int i;
	int16 val;

	for (i = 0; i < len; i++)
	{
		val = *src;
		SSVAL(dst, 0, val);
		dst++;
		src++;
		if (val == 0)
			break;
	}
	return i;
}

/* 
 * Creates the MD4 Hash of the users password in NT UNICODE.
 */

void E_md4hash(uchar * pwrd, uchar * p16)
{
	int len;
	int16 wpwd[129];

	/* Password cannot be longer than 128 characters */
	len = strlen((char *)pwrd);
	if (len > 128)
		len = 128;
	/* Password must be converted to NT unicode */
	_my_mbstowcs(wpwd, pwrd, len);
	wpwd[len] = 0;		/* Ensure string is null terminated */
	/* Calculate length in bytes */
	len = _my_wcslen(wpwd) * sizeof(int16);

	mdfour(p16, (uchar *) wpwd, len);
}

/* Does the LM owf of a user's password */
void lm_owf_genW(const UNISTR2 * pwd, uchar p16[16])
{
	char pwrd[15];

	ZERO_STRUCT(pwrd);
	if (pwd != NULL)
	{
		unistr2_to_ascii(pwrd, pwd, sizeof(pwrd) - 1);
	}

	/* Mangle the passwords into Lanman format */
	pwrd[14] = '\0';
	strupper(pwrd);

	/* Calculate the SMB (lanman) hash functions of the password */

	E_P16((uchar *) pwrd, (uchar *) p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("lm_owf_genW: pwd, lm#\n"));
	dump_data(120, pwrd, strlen(pwrd));
	dump_data(100, p16, 16);
#endif
	/* clear out local copy of user's password (just being paranoid). */
	bzero(pwrd, sizeof(pwrd));
}

/* Does the LM owf of a user's password */
void lm_owf_gen(const char *pwd, uchar p16[16])
{
	char pwrd[15];

	ZERO_STRUCT(pwrd);
	
	if (pwd != NULL)
	{
		safe_strcpy(pwrd, pwd, sizeof(pwrd) - 1);
	}

	/* Mangle the passwords into Lanman format */
	pwrd[14] = '\0';
	strupper(pwrd);

	/* Calculate the SMB (lanman) hash functions of the password */

	E_P16((uchar *) pwrd, (uchar *) p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("nt_lm_owf_gen: pwd, lm#\n"));
	dump_data(120, pwrd, strlen(pwrd));
	dump_data(100, p16, 16);
#endif
	/* clear out local copy of user's password (just being paranoid). */
	bzero(pwrd, sizeof(pwrd));
}

/* Does both the NT and LM owfs of a user's password */
void nt_owf_genW(const UNISTR2 * pwd, uchar nt_p16[16])
{
	char buf[512];
	int i;
	
	for (i = 0; i < MIN(pwd->uni_str_len, sizeof(buf)/2); i++)
	{
		SIVAL(buf, i*2, pwd->buffer[i]);
	}
	/* Calculate the MD4 hash (NT compatible) of the password */
	mdfour(nt_p16, buf, pwd->uni_str_len * 2);

	dump_data_pw("nt_owf_genW:", buf, pwd->uni_str_len * 2);
	dump_data_pw("nt#:", nt_p16, 16);

	/* clear out local copy of user's password (just being paranoid). */
	ZERO_STRUCT(buf);
}

/* Does both the NT and LM owfs of a user's password */
void nt_owf_gen(const char *pwd, uchar nt_p16[16])
{
	char pwrd[130];

	ZERO_STRUCT(pwrd);
	if (pwd != NULL)
	{
		safe_strcpy(pwrd, pwd, sizeof(pwrd) - 1);
	}

	/* Calculate the MD4 hash (NT compatible) of the password */
	E_md4hash((uchar *) pwrd, nt_p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("nt_owf_gen: pwd, nt#\n"));
	dump_data(120, pwrd, strlen(pwrd));
	dump_data(100, nt_p16, 16);
#endif
	/* clear out local copy of user's password (just being paranoid). */
	bzero(pwrd, sizeof(pwrd));
}

/* Does both the NT and LM owfs of a user's UNICODE password */
void nt_lm_owf_genW(const UNISTR2 * pwd, uchar nt_p16[16], uchar lm_p16[16])
{
	nt_owf_genW(pwd, nt_p16);
	lm_owf_genW(pwd, lm_p16);
}

/* Does both the NT and LM owfs of a user's password */
void nt_lm_owf_gen(const char *pwd, uchar nt_p16[16], uchar lm_p16[16])
{
	nt_owf_gen(pwd, nt_p16);
	lm_owf_gen(pwd, lm_p16);
}

/* Does the des encryption from the NT or LM MD4 hash. */
void SMBOWFencrypt(const uchar pwrd[16], const uchar * c8, uchar p24[24])
{
	uchar p21[21];

	ZERO_STRUCT(p21);

	memcpy(p21, pwrd, 16);
	E_P24(p21, c8, p24);
}

void SMBOWFencrypt_ntv2(const uchar kr[16],
			const uchar * srv_chal, int srv_chal_len,
			const uchar * cli_chal, int cli_chal_len,
			char resp_buf[16])
{
	HMACMD5Context ctx;

	hmac_md5_init_limK_to_64(kr, 16, &ctx);
	hmac_md5_update(srv_chal, srv_chal_len, &ctx);
	hmac_md5_update(cli_chal, cli_chal_len, &ctx);
	hmac_md5_final(resp_buf, &ctx);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBOWFencrypt_ntv2: srv_chal, cli_chal, resp_buf\n"));
	dump_data(100, srv_chal, srv_chal_len);
	dump_data(100, cli_chal, cli_chal_len);
	dump_data(100, resp_buf, 16);
#endif
}

void SMBsesskeygen_ntv2(const uchar kr[16],
			const uchar * nt_resp, char sess_key[16])
{
	HMACMD5Context ctx;

	hmac_md5_init_limK_to_64(kr, 16, &ctx);
	hmac_md5_update(nt_resp, 16, &ctx);
	hmac_md5_final(sess_key, &ctx);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBsesskeygen_ntv2:\n"));
	dump_data(100, sess_key, 16);
#endif
}

void SMBsesskeygen_ntv1(const uchar kr[16],
			const uchar * nt_resp, char sess_key[16])
{
	mdfour(sess_key, kr, 16);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBsesskeygen_ntv1:\n"));
	dump_data(100, sess_key, 16);
#endif
}

/***************************************************************************
 tests showed that the nt challenge can be total random-length garbage!
 ***************************************************************************/
void SMBgenclientchals(char *lm_cli_chal,
		       char *nt_cli_chal, int *nt_cli_chal_len,
		       const char *srv, const char *dom)
{
	NTTIME nt_time;
	int srv_len = strlen(srv);
	int dom_len = strlen(dom);
	fstring server;
	fstring domain;
	fstrcpy(server, srv);
	fstrcpy(domain, dom);
	strupper(server);
	strupper(domain);

#if 0 EXPERIMENTATION_THIS_ACTUALLY_WORKS
	generate_random_buffer(nt_cli_chal, 64, False);
	(*nt_cli_chal_len) = 64;
	memcpy(lm_cli_chal, nt_cli_chal + 16, 8);
	generate_random_buffer(lm_cli_chal, 8, False);

	return;
#endif

	generate_random_buffer(lm_cli_chal, 8, False);
	unix_to_nt_time(&nt_time, time(NULL));

	CVAL(nt_cli_chal, 0) = 0x1;
	CVAL(nt_cli_chal, 1) = 0x1;
	SSVAL(nt_cli_chal, 2, 0x0);
	SIVAL(nt_cli_chal, 4, 0x0);
	SIVAL(nt_cli_chal, 8, nt_time.low);
	SIVAL(nt_cli_chal, 12, nt_time.high);
	memcpy(nt_cli_chal + 16, lm_cli_chal, 8);
	/* fill in offset 24, size of structure, later */

	*nt_cli_chal_len = 28;

	SSVAL(nt_cli_chal, *nt_cli_chal_len, 2);
	*nt_cli_chal_len += 2;
	SSVAL(nt_cli_chal, *nt_cli_chal_len, dom_len * 2);
	*nt_cli_chal_len += 2;
	ascii_to_unibuf(nt_cli_chal + (*nt_cli_chal_len), domain,
			dom_len * 2);
	*nt_cli_chal_len += dom_len * 2;
	*nt_cli_chal_len += 4 - ((*nt_cli_chal_len) % 4);

	SSVAL(nt_cli_chal, *nt_cli_chal_len, 2);
	*nt_cli_chal_len += 2;
	SSVAL(nt_cli_chal, 30, srv_len * 2);
	*nt_cli_chal_len += 2;
	ascii_to_unibuf(nt_cli_chal + (*nt_cli_chal_len), server,
			srv_len * 2);
	*nt_cli_chal_len += srv_len * 2;

	SSVAL(nt_cli_chal, 24, (*nt_cli_chal_len) + 16);
	SSVAL(nt_cli_chal, 26, (*nt_cli_chal_len) + 15);

	DEBUG(100, ("SMBgenclientchals: srv %s, dom %s\n", server, domain));
	dump_data(100, nt_cli_chal, *nt_cli_chal_len);
}

void ntv2_owf_gen(const uchar owf[16],
		  const char *user_n, const char *domain_n, uchar kr_buf[16])
{
	pstring user_u;
	pstring dom_u;
	HMACMD5Context ctx;

	int user_l = strlen(user_n);
	int domain_l = strlen(domain_n);

	_my_mbstowcsupper((int16 *) user_u, user_n, user_l * 2);
	_my_mbstowcsupper((int16 *) dom_u, domain_n, domain_l * 2);

	hmac_md5_init_limK_to_64(owf, 16, &ctx);
	hmac_md5_update(user_u, user_l * 2, &ctx);
	hmac_md5_update(dom_u, domain_l * 2, &ctx);
	hmac_md5_final(kr_buf, &ctx);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("ntv2_owf_gen: user, domain, owfkey, kr\n"));
	dump_data(100, user_u, user_l * 2);
	dump_data(100, dom_u, domain_l * 2);
	dump_data(100, owf, 16);
	dump_data(100, kr_buf, 16);
#endif
}

/* Does the des encryption from the FIRST 8 BYTES of the NT or LM MD4 hash. */
void NTLMSSPOWFencrypt(const uchar pwrd[8], const uchar * ntlmchalresp,
				uchar p24[24])
{
	uchar p21[21];

	ZERO_STRUCT(p21);
	memcpy(p21, pwrd, 8);
	memset(p21 + 8, 0xbd, 8);

	E_P24(p21, ntlmchalresp, p24);
#ifdef DEBUG_PASSWORD
	DEBUG(100, ("NTLMSSPOWFencrypt: p21, c8, p24\n"));
	dump_data(100, p21, 21);
	dump_data(100, ntlmchalresp, 8);
	dump_data(100, p24, 24);
#endif
}

BOOL make_oem_passwd_hash(uchar data[516],
			  const char *pwrd, int new_pw_len,
			  const uchar old_pw_hash[16], BOOL unicode)
{
	if (new_pw_len == 0)
	{
		new_pw_len = strlen(pwrd) * (unicode ? 2 : 1);
	}

	if (new_pw_len > 512)
	{
		DEBUG(0,
		      ("make_oem_passwd_hash: new password is too long.\n"));
		return False;
	}

	/*
	 * Now setup the data area.
	 * We need to generate a random fill
	 * for this area to make it harder to
	 * decrypt. JRA.
	 */
	generate_random_buffer(data, 516, False);
	if (unicode)
	{
		ascii_to_unibuf(&data[512 - new_pw_len], pwrd, new_pw_len);
	}
	else
	{
		fstrcpy(&data[512 - new_pw_len], pwrd);
	}
	SIVAL(data, 512, new_pw_len);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("make_oem_passwd_hash\n"));
	dump_data(100, data, 516);
#endif
	if (old_pw_hash != NULL)
	{
		SamOEMhash(data, old_pw_hash, True);
	}

	return True;
}

BOOL nt_encrypt_string2(STRING2 * out, const STRING2 * in, const uchar * key)
{
	const uchar *keyptr = key;
	const uchar *keyend = key + 16;
	int datalen = in->str_str_len;

	uchar *outbuf = (uchar *) out->buffer;
	const uchar *inbuf = (const uchar *)in->buffer;
	const uchar *inbufend;

	out->str_max_len = in->str_max_len;
	out->str_str_len = in->str_str_len;
	out->undoc = 0;

	inbufend = inbuf + datalen;

	dump_data_pw("nt_encrypt_string2\n", inbuf, datalen);

	while (inbuf < inbufend)
	{
		smbhash(outbuf, inbuf, keyptr, 1);

		keyptr += 7;
		if (keyptr + 7 > keyend)
		{
			keyptr = (keyend - keyptr) + key;
		}

		inbuf += 8;
		outbuf += 8;
	}

	dump_data_pw("nt_encrypt_string2\n", out->buffer, datalen);

	return True;
}

BOOL nt_decrypt_string2(STRING2 * out, const STRING2 * in, const uchar * key)
{
	int datalen = in->str_str_len;

	const uchar *keyptr = key;
	const uchar *keyend = key + 16;

	uchar *outbuf = (uchar *) out->buffer;
	const uchar *inbuf = (const uchar *)in->buffer;
	const uchar *inbufend;

	if (in->str_str_len > MAX_STRINGLEN)
	{
		DEBUG(0, ("nt_decrypt_string2: failed\n"));
		return False;
	}

	out->str_max_len = in->str_max_len;
	out->str_str_len = in->str_str_len;
	out->undoc = in->undoc;

	inbufend = inbuf + datalen;

	while (inbuf < inbufend)
	{
		smbhash(outbuf, inbuf, keyptr, 0);
		keyptr += 7;
		if (keyptr + 7 > keyend)
		{
			keyptr = (keyend - keyptr) + key;
		}

		inbuf += 8;
		outbuf += 8;
	}

	datalen = IVAL(out->buffer, 0);

	dump_data_pw("nt_decrypt_string2\n", out->buffer, out->str_str_len);

	if (datalen != in->str_str_len - 8)
	{
		DEBUG(2, ("nt_decrypt_string2: length-match failed\n"));
		return False;
	}

	return True;
}

/*******************************************************************
 creates a DCE/RPC bind authentication response

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
void create_ntlmssp_resp(struct pwd_info *pwd,
			 char *domain, char *user_name, char *my_name,
			 uint32 ntlmssp_cli_flgs, prs_struct * auth_resp)
{
	RPC_AUTH_NTLMSSP_RESP ntlmssp_resp;
	uchar lm_owf[24];
	uchar nt_owf[128];
	size_t nt_owf_len;

	pwd_get_lm_nt_owf(pwd, lm_owf, nt_owf, &nt_owf_len);

	make_rpc_auth_ntlmssp_resp(&ntlmssp_resp,
				   lm_owf, nt_owf, nt_owf_len,
				   domain, user_name, my_name,
				   ntlmssp_cli_flgs);

	smb_io_rpc_auth_ntlmssp_resp("ntlmssp_resp", &ntlmssp_resp, auth_resp,
				     0);
	prs_realloc_data(auth_resp, auth_resp->offset);
}

/***********************************************************
 decode a password buffer
************************************************************/
BOOL decode_pw_buffer(const char buffer[516], char *new_pwrd,
		      int new_pwrd_size, uint32 * new_pw_len)
{
	/* 
	 * The length of the new password is in the last 4 bytes of
	 * the data buffer.
	 */

	(*new_pw_len) = IVAL(buffer, 512);

#ifdef DEBUG_PASSWORD
	dump_data(100, buffer, 516);
#endif

	if ((*new_pw_len) < 0 || (*new_pw_len) > new_pwrd_size - 1)
	{
		DEBUG(0,
		      ("decode_pw_buffer: incorrect password length (%d).\n",
		       (*new_pw_len)));
		return False;
	}

	memcpy(new_pwrd, &buffer[512 - (*new_pw_len)], (*new_pw_len));
	new_pwrd[(*new_pw_len)] = '\0';

#ifdef DEBUG_PASSWORD
	dump_data(100, new_pwrd, (*new_pw_len));
#endif

	return True;
}

/***********************************************************
 encode a password buffer
************************************************************/
BOOL encode_pw_buffer(char buffer[516], const char *new_pass,
		      int new_pw_len, BOOL nt_pass_set)
{
	generate_random_buffer(buffer, 516, True);

	if (nt_pass_set)
	{
		/*
		 * nt passwords are in unicode.  last char overwrites NULL
		 * in ascii_to_unibuf, so use SIVAL *afterwards*.
		 */
		new_pw_len *= 2;
		ascii_to_unibuf(&buffer[512 - new_pw_len], new_pass,
				new_pw_len);
	}
	else
	{
		memcpy(&buffer[512 - new_pw_len], new_pass, new_pw_len);
	}

	/* 
	 * The length of the new password is in the last 4 bytes of
	 * the data buffer.
	 */

	SIVAL(buffer, 512, new_pw_len);

#ifdef DEBUG_PASSWORD
	dump_data(100, buffer, 516);
#endif

	return True;
}
