/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Modified by Jeremy Allison 1995.
   Copyright (C) Jeremy Allison 1995-2000.
   Copyright (C) Luke Kennethc Casson Leighton 1996-2000.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
   
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
   It takes a password ('unix' string), a 8 byte "crypt key" 
   and puts 24 bytes of encrypted password into p24 */
void SMBencrypt(const char *passwd, const uchar *c8, uchar p24[24])
{
	uchar p21[21];

	memset(p21,'\0',21);
	E_deshash(passwd, p21); 

	SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("SMBencrypt: lm#, challenge, response\n"));
	dump_data(100, (char *)p21, 16);
	dump_data(100, (const char *)c8, 8);
	dump_data(100, (char *)p24, 24);
#endif
}

/**
 * Creates the MD4 Hash of the users password in NT UNICODE.
 * @param passwd password in 'unix' charset.
 * @param p16 return password hashed with md4, caller allocated 16 byte buffer
 */
 
void E_md4hash(const char *passwd, uchar p16[16])
{
	int len;
	smb_ucs2_t wpwd[129];
	
	/* Password must be converted to NT unicode - null terminated. */
	push_ucs2(NULL, wpwd, (const char *)passwd, 256, STR_UNICODE|STR_NOALIGN|STR_TERMINATE);
	/* Calculate length in bytes */
	len = strlen_w(wpwd) * sizeof(int16);

	mdfour(p16, (unsigned char *)wpwd, len);
	ZERO_STRUCT(wpwd);	
}

/**
 * Creates the DES forward-only Hash of the users password in DOS ASCII charset
 * @param passwd password in 'unix' charset.
 * @param p16 return password hashed with DES, caller allocated 16 byte buffer
 */
 
void E_deshash(const char *passwd, uchar p16[16])
{
	fstring dospwd; 
	ZERO_STRUCT(dospwd);
	ZERO_STRUCTP(p16);
	
	/* Password must be converted to DOS charset - null terminated, uppercase. */
	push_ascii(dospwd, (const char *)passwd, sizeof(dospwd), STR_UPPER|STR_TERMINATE);

	/* Only the fisrt 14 chars are considered, password need not be null terminated. */
	E_P16(dospwd, p16);

	ZERO_STRUCT(dospwd);	
}

/**
 * Creates the MD4 and DES (LM) Hash of the users password.  
 * MD4 is of the NT Unicode, DES is of the DOS UPPERCASE password.
 * @param passwd password in 'unix' charset.
 * @param nt_p16 return password hashed with md4, caller allocated 16 byte buffer
 * @param p16 return password hashed with des, caller allocated 16 byte buffer
 */
 
/* Does both the NT and LM owfs of a user's password */
void nt_lm_owf_gen(const char *pwd, uchar nt_p16[16], uchar p16[16])
{
	/* Calculate the MD4 hash (NT compatible) of the password */
	memset(nt_p16, '\0', 16);
	E_md4hash(pwd, nt_p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: pwd, nt#\n"));
	dump_data(120, pwd, strlen(pwd));
	dump_data(100, (char *)nt_p16, 16);
#endif

	E_deshash(pwd, (uchar *)p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: pwd, lm#\n"));
	dump_data(120, pwd, strlen(pwd));
	dump_data(100, (char *)p16, 16);
#endif
}

/* Does both the NTLMv2 owfs of a user's password */
BOOL ntv2_owf_gen(const uchar owf[16],
		  const char *user_in, const char *domain_in, uchar kr_buf[16])
{
	smb_ucs2_t *user;
	smb_ucs2_t *domain;
	
	size_t user_byte_len;
	size_t domain_byte_len;

	HMACMD5Context ctx;

	user_byte_len = push_ucs2_allocate(&user, user_in);
	if (user_byte_len == (size_t)-1) {
		DEBUG(0, ("push_uss2_allocate() for user returned -1 (probably malloc() failure)\n"));
		return False;
	}

	domain_byte_len = push_ucs2_allocate(&domain, domain_in);
	if (domain_byte_len == (size_t)-1) {
		DEBUG(0, ("push_uss2_allocate() for domain returned -1 (probably malloc() failure)\n"));
		return False;
	}

	strupper_w(user);
	strupper_w(domain);

	SMB_ASSERT(user_byte_len >= 2);
	SMB_ASSERT(domain_byte_len >= 2);

	/* We don't want null termination */
	user_byte_len = user_byte_len - 2;
	domain_byte_len = domain_byte_len - 2;
	
	hmac_md5_init_limK_to_64(owf, 16, &ctx);
	hmac_md5_update((const unsigned char *)user, user_byte_len, &ctx);
	hmac_md5_update((const unsigned char *)domain, domain_byte_len, &ctx);
	hmac_md5_final(kr_buf, &ctx);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("ntv2_owf_gen: user, domain, owfkey, kr\n"));
	dump_data(100, (const char *)user, user_byte_len);
	dump_data(100, (const char *)domain, domain_byte_len);
	dump_data(100, owf, 16);
	dump_data(100, kr_buf, 16);
#endif

	SAFE_FREE(user);
	SAFE_FREE(domain);
	return True;
}

/* Does the des encryption from the NT or LM MD4 hash. */
void SMBOWFencrypt(const uchar passwd[16], const uchar *c8, uchar p24[24])
{
	uchar p21[21];

	ZERO_STRUCT(p21);
 
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
 
void SMBNTencrypt(const char *passwd, uchar *c8, uchar *p24)
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
			uchar resp_buf[16])
{
	HMACMD5Context ctx;

	hmac_md5_init_limK_to_64(kr, 16, &ctx);
	hmac_md5_update(srv_chal.data, srv_chal.length, &ctx);
	hmac_md5_update(cli_chal.data, cli_chal.length, &ctx);
	hmac_md5_final(resp_buf, &ctx);

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

DATA_BLOB NTLMv2_generate_response(uchar ntlm_v2_hash[16],
				   DATA_BLOB server_chal, size_t client_chal_length)
{
	uchar ntlmv2_response[16];
	DATA_BLOB ntlmv2_client_data;
	DATA_BLOB final_response;
	
	/* NTLMv2 */

	/* We also get to specify some random data */
	ntlmv2_client_data = data_blob(NULL, client_chal_length);
	generate_random_buffer(ntlmv2_client_data.data, ntlmv2_client_data.length, False);
	
	/* Given that data, and the challenge from the server, generate a response */
	SMBOWFencrypt_ntv2(ntlm_v2_hash, server_chal, ntlmv2_client_data, ntlmv2_response);
	
	/* put it into nt_response, for the code below to put into the packet */
	final_response = data_blob(NULL, ntlmv2_client_data.length + sizeof(ntlmv2_response));
	memcpy(final_response.data, ntlmv2_response, sizeof(ntlmv2_response));
	/* after the first 16 bytes is the random data we generated above, so the server can verify us with it */
	memcpy(final_response.data + sizeof(ntlmv2_response), ntlmv2_client_data.data, ntlmv2_client_data.length);
	data_blob_free(&ntlmv2_client_data);

	return final_response;
}

BOOL SMBNTLMv2encrypt(const char *user, const char *domain, const char *password, 
		      const DATA_BLOB server_chal, 
		      DATA_BLOB *lm_response, DATA_BLOB *nt_response, 
		      DATA_BLOB *session_key) 
{
	uchar nt_hash[16];
	uchar ntlm_v2_hash[16];
	E_md4hash(password, nt_hash);

	/* We don't use the NT# directly.  Instead we use it mashed up with
	   the username and domain.
	   This prevents username swapping during the auth exchange
	*/
	if (!ntv2_owf_gen(nt_hash, user, domain, ntlm_v2_hash)) {
		return False;
	}
	
	*nt_response = NTLMv2_generate_response(ntlm_v2_hash, server_chal, 64 /* pick a number, > 8 */);
	
	/* LMv2 */
	
	*lm_response = NTLMv2_generate_response(ntlm_v2_hash, server_chal, 8);
	
	*session_key = data_blob(NULL, 16);
	
	/* The NTLMv2 calculations also provide a session key, for signing etc later */
	/* use only the first 16 bytes of nt_response for session key */
	SMBsesskeygen_ntv2(ntlm_v2_hash, nt_response->data, session_key->data);

	return True;
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

/***********************************************************
 SMB signing - setup the MAC key.
************************************************************/

void cli_calculate_mac_key(struct cli_state *cli, const uchar user_session_key[16], const DATA_BLOB response)
{
	
	memcpy(&cli->sign_info.mac_key[0], user_session_key, 16);
	memcpy(&cli->sign_info.mac_key[16],response.data, MIN(response.length, 40 - 16));
	cli->sign_info.mac_key_len = MIN(response.length + 16, 40);
	cli->sign_info.use_smb_signing = True;

	/* These calls are INCONPATIBLE with SMB signing */
	cli->readbraw_supported = False;
	cli->writebraw_supported = False;

	/* Reset the sequence number in case we had a previous (aborted) attempt */
	cli->sign_info.send_seq_num = 2;
}

/***********************************************************
 SMB signing - calculate a MAC to send.
************************************************************/

void cli_caclulate_sign_mac(struct cli_state *cli)
{
	unsigned char calc_md5_mac[16];
	struct MD5Context md5_ctx;

	if (cli->sign_info.temp_smb_signing) {
		memcpy(&cli->outbuf[smb_ss_field], "SignRequest", 8);
		cli->sign_info.temp_smb_signing = False;
		return;
	}

	if (!cli->sign_info.use_smb_signing) {
		return;
	}

	/*
	 * Firstly put the sequence number into the first 4 bytes.
	 * and zero out the next 4 bytes.
	 */
	SIVAL(cli->outbuf, smb_ss_field, cli->sign_info.send_seq_num);
	SIVAL(cli->outbuf, smb_ss_field + 4, 0);

	/* Calculate the 16 byte MAC and place first 8 bytes into the field. */
	MD5Init(&md5_ctx);
	MD5Update(&md5_ctx, cli->sign_info.mac_key, cli->sign_info.mac_key_len);
	MD5Update(&md5_ctx, cli->outbuf + 4, smb_len(cli->outbuf));
	MD5Final(calc_md5_mac, &md5_ctx);

	memcpy(&cli->outbuf[smb_ss_field], calc_md5_mac, 8);

/*	cli->outbuf[smb_ss_field+2]=0; 
	Uncomment this to test if the remote server actually verifies signitures...*/
	cli->sign_info.send_seq_num++;
	cli->sign_info.reply_seq_num = cli->sign_info.send_seq_num;
	cli->sign_info.send_seq_num++;
}

/***********************************************************
 SMB signing - check a MAC sent by server.
************************************************************/

BOOL cli_check_sign_mac(struct cli_state *cli)
{
	unsigned char calc_md5_mac[16];
	unsigned char server_sent_mac[8];
	struct MD5Context md5_ctx;

	if (cli->sign_info.temp_smb_signing) {
		return True;
	}

	if (!cli->sign_info.use_smb_signing) {
		return True;
	}

	/*
	 * Firstly put the sequence number into the first 4 bytes.
	 * and zero out the next 4 bytes.
	 */

	memcpy(server_sent_mac, &cli->inbuf[smb_ss_field], sizeof(server_sent_mac));

	SIVAL(cli->inbuf, smb_ss_field, cli->sign_info.reply_seq_num);
	SIVAL(cli->inbuf, smb_ss_field + 4, 0);

	/* Calculate the 16 byte MAC and place first 8 bytes into the field. */
	MD5Init(&md5_ctx);
	MD5Update(&md5_ctx, cli->sign_info.mac_key, cli->sign_info.mac_key_len);
	MD5Update(&md5_ctx, cli->inbuf + 4, smb_len(cli->inbuf));
	MD5Final(calc_md5_mac, &md5_ctx);

	return (memcmp(server_sent_mac, calc_md5_mac, 8) == 0);
}
