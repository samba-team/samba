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
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "byteorder.h"

void SMBencrypt_hash(const uchar lm_hash[16], const uchar *c8, uchar p24[24])
{
	uchar p21[21];

	memset(p21,'\0',21);
	memcpy(p21, lm_hash, 16);

	SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("SMBencrypt_hash: lm#, challenge, response\n"));
	dump_data(100, p21, 16);
	dump_data(100, c8, 8);
	dump_data(100, p24, 24);
#endif
}

/*
   This implements the X/Open SMB password encryption
   It takes a password ('unix' string), a 8 byte "crypt key" 
   and puts 24 bytes of encrypted password into p24 

   Returns False if password must have been truncated to create LM hash
*/

bool SMBencrypt(const char *passwd, const uchar *c8, uchar p24[24])
{
	bool ret;
	uchar lm_hash[16];

	ret = E_deshash(passwd, lm_hash); 
	SMBencrypt_hash(lm_hash, c8, p24);
	return ret;
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
 * Creates the MD5 Hash of a combination of 16 byte salt and 16 byte NT hash.
 * @param 16 byte salt.
 * @param 16 byte NT hash.
 * @param 16 byte return hashed with md5, caller allocated 16 byte buffer
 */

void E_md5hash(const uchar salt[16], const uchar nthash[16], uchar hash_out[16])
{
	struct MD5Context tctx;
	uchar array[32];
	
	memset(hash_out, '\0', 16);
	memcpy(array, salt, 16);
	memcpy(&array[16], nthash, 16);
	MD5Init(&tctx);
	MD5Update(&tctx, array, 32);
	MD5Final(hash_out, &tctx);
}

/**
 * Creates the DES forward-only Hash of the users password in DOS ASCII charset
 * @param passwd password in 'unix' charset.
 * @param p16 return password hashed with DES, caller allocated 16 byte buffer
 * @return False if password was > 14 characters, and therefore may be incorrect, otherwise True
 * @note p16 is filled in regardless
 */
 
bool E_deshash(const char *passwd, uchar p16[16])
{
	bool ret = True;
	fstring dospwd; 
	ZERO_STRUCT(dospwd);
	
	/* Password must be converted to DOS charset - null terminated, uppercase. */
	push_ascii(dospwd, passwd, sizeof(dospwd), STR_UPPER|STR_TERMINATE);
       
	/* Only the fisrt 14 chars are considered, password need not be null terminated. */
	E_P16((const unsigned char *)dospwd, p16);

	if (strlen(dospwd) > 14) {
		ret = False;
	}

	ZERO_STRUCT(dospwd);	

	return ret;
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
	dump_data(120, (uint8 *)pwd, strlen(pwd));
	dump_data(100, nt_p16, 16);
#endif

	E_deshash(pwd, (uchar *)p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: pwd, lm#\n"));
	dump_data(120, (uint8 *)pwd, strlen(pwd));
	dump_data(100, p16, 16);
#endif
}

/* Does both the NTLMv2 owfs of a user's password */
bool ntv2_owf_gen(const uchar owf[16],
		  const char *user_in, const char *domain_in,
		  bool upper_case_domain, /* Transform the domain into UPPER case */
		  uchar kr_buf[16])
{
	smb_ucs2_t *user;
	smb_ucs2_t *domain;
	
	size_t user_byte_len;
	size_t domain_byte_len;

	HMACMD5Context ctx;

	if (!push_ucs2_allocate(&user, user_in, &user_byte_len)) {
		DEBUG(0, ("push_uss2_allocate() for user failed: %s\n",
			  strerror(errno)));
		return False;
	}

	if (!push_ucs2_allocate(&domain, domain_in, &domain_byte_len)) {
		DEBUG(0, ("push_uss2_allocate() for domain failed: %s\n",
			  strerror(errno)));
		SAFE_FREE(user);
		return False;
	}

	strupper_w(user);

	if (upper_case_domain)
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
	dump_data(100, (uint8 *)user, user_byte_len);
	dump_data(100, (uint8 *)domain, domain_byte_len);
	dump_data(100, (uint8 *)owf, 16);
	dump_data(100, (uint8 *)kr_buf, 16);
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
	dump_data(100, p21, 21);
	dump_data(100, ntlmchalresp, 8);
	dump_data(100, p24, 24);
#endif
}


/* Does the des encryption. */
 
void SMBNTencrypt_hash(const uchar nt_hash[16], uchar *c8, uchar *p24)
{
	uchar p21[21];
 
	memset(p21,'\0',21);
	memcpy(p21, nt_hash, 16);
	SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("SMBNTencrypt: nt#, challenge, response\n"));
	dump_data(100, p21, 16);
	dump_data(100, c8, 8);
	dump_data(100, p24, 24);
#endif
}

/* Does the NT MD4 hash then des encryption. Plaintext version of the above. */

void SMBNTencrypt(const char *passwd, uchar *c8, uchar *p24)
{
	uchar nt_hash[16];
	E_md4hash(passwd, nt_hash);    
	SMBNTencrypt_hash(nt_hash, c8, p24);
}

/* Does the md5 encryption from the Key Response for NTLMv2. */
void SMBOWFencrypt_ntv2(const uchar kr[16],
			const DATA_BLOB *srv_chal,
			const DATA_BLOB *cli_chal,
			uchar resp_buf[16])
{
	HMACMD5Context ctx;

	hmac_md5_init_limK_to_64(kr, 16, &ctx);
	hmac_md5_update(srv_chal->data, srv_chal->length, &ctx);
	hmac_md5_update(cli_chal->data, cli_chal->length, &ctx);
	hmac_md5_final(resp_buf, &ctx);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBOWFencrypt_ntv2: srv_chal, cli_chal, resp_buf\n"));
	dump_data(100, srv_chal->data, srv_chal->length);
	dump_data(100, cli_chal->data, cli_chal->length);
	dump_data(100, resp_buf, 16);
#endif
}

void SMBsesskeygen_ntv2(const uchar kr[16],
			const uchar * nt_resp, uint8 sess_key[16])
{
	/* a very nice, 128 bit, variable session key */
	
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
	/* yes, this session key does not change - yes, this 
	   is a problem - but it is 128 bits */
	
	mdfour((unsigned char *)sess_key, kr, 16);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBsesskeygen_ntv1:\n"));
	dump_data(100, sess_key, 16);
#endif
}

void SMBsesskeygen_lm_sess_key(const uchar lm_hash[16],
			const uchar lm_resp[24], /* only uses 8 */ 
			uint8 sess_key[16])
{
	uchar p24[24];
	uchar partial_lm_hash[16];
	
	memcpy(partial_lm_hash, lm_hash, 8);
	memset(partial_lm_hash + 8, 0xbd, 8);    

	SMBOWFencrypt(partial_lm_hash, lm_resp, p24);
	
	memcpy(sess_key, p24, 16);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBsesskeygen_lmv1_jerry:\n"));
	dump_data(100, sess_key, 16);
#endif
}

DATA_BLOB NTLMv2_generate_names_blob(const char *hostname, 
				     const char *domain)
{
	DATA_BLOB names_blob = data_blob_null;
	
	msrpc_gen(&names_blob, "aaa", 
		  NTLMSSP_NAME_TYPE_DOMAIN, domain,
		  NTLMSSP_NAME_TYPE_SERVER, hostname,
		  0, "");
	return names_blob;
}

static DATA_BLOB NTLMv2_generate_client_data(const DATA_BLOB *names_blob) 
{
	uchar client_chal[8];
	DATA_BLOB response = data_blob_null;
	char long_date[8];

	generate_random_buffer(client_chal, sizeof(client_chal));

	put_long_date(long_date, time(NULL));

	/* See http://www.ubiqx.org/cifs/SMB.html#SMB.8.5 */

	msrpc_gen(&response, "ddbbdb", 
		  0x00000101,     /* Header  */
		  0,              /* 'Reserved'  */
		  long_date, 8,	  /* Timestamp */
		  client_chal, 8, /* client challenge */
		  0,		  /* Unknown */
		  names_blob->data, names_blob->length);	/* End of name list */

	return response;
}

static DATA_BLOB NTLMv2_generate_response(const uchar ntlm_v2_hash[16],
					  const DATA_BLOB *server_chal,
					  const DATA_BLOB *names_blob)
{
	uchar ntlmv2_response[16];
	DATA_BLOB ntlmv2_client_data;
	DATA_BLOB final_response;
	
	/* NTLMv2 */
	/* generate some data to pass into the response function - including
	   the hostname and domain name of the server */
	ntlmv2_client_data = NTLMv2_generate_client_data(names_blob);

	/* Given that data, and the challenge from the server, generate a response */
	SMBOWFencrypt_ntv2(ntlm_v2_hash, server_chal, &ntlmv2_client_data, ntlmv2_response);
	
	final_response = data_blob(NULL, sizeof(ntlmv2_response) + ntlmv2_client_data.length);

	memcpy(final_response.data, ntlmv2_response, sizeof(ntlmv2_response));

	memcpy(final_response.data+sizeof(ntlmv2_response), 
	       ntlmv2_client_data.data, ntlmv2_client_data.length);

	data_blob_free(&ntlmv2_client_data);

	return final_response;
}

static DATA_BLOB LMv2_generate_response(const uchar ntlm_v2_hash[16],
					const DATA_BLOB *server_chal)
{
	uchar lmv2_response[16];
	DATA_BLOB lmv2_client_data = data_blob(NULL, 8);
	DATA_BLOB final_response = data_blob(NULL, 24);
	
	/* LMv2 */
	/* client-supplied random data */
	generate_random_buffer(lmv2_client_data.data, lmv2_client_data.length);	

	/* Given that data, and the challenge from the server, generate a response */
	SMBOWFencrypt_ntv2(ntlm_v2_hash, server_chal, &lmv2_client_data, lmv2_response);
	memcpy(final_response.data, lmv2_response, sizeof(lmv2_response));

	/* after the first 16 bytes is the random data we generated above, 
	   so the server can verify us with it */
	memcpy(final_response.data+sizeof(lmv2_response), 
	       lmv2_client_data.data, lmv2_client_data.length);

	data_blob_free(&lmv2_client_data);

	return final_response;
}

bool SMBNTLMv2encrypt_hash(const char *user, const char *domain, const uchar nt_hash[16], 
		      const DATA_BLOB *server_chal, 
		      const DATA_BLOB *names_blob,
		      DATA_BLOB *lm_response, DATA_BLOB *nt_response, 
		      DATA_BLOB *user_session_key) 
{
	uchar ntlm_v2_hash[16];

	/* We don't use the NT# directly.  Instead we use it mashed up with
	   the username and domain.
	   This prevents username swapping during the auth exchange
	*/
	if (!ntv2_owf_gen(nt_hash, user, domain, False, ntlm_v2_hash)) {
		return False;
	}
	
	if (nt_response) {
		*nt_response = NTLMv2_generate_response(ntlm_v2_hash, server_chal,
							names_blob); 
		if (user_session_key) {
			*user_session_key = data_blob(NULL, 16);
			
			/* The NTLMv2 calculations also provide a session key, for signing etc later */
			/* use only the first 16 bytes of nt_response for session key */
			SMBsesskeygen_ntv2(ntlm_v2_hash, nt_response->data, user_session_key->data);
		}
	}
	
	/* LMv2 */
	
	if (lm_response) {
		*lm_response = LMv2_generate_response(ntlm_v2_hash, server_chal);
	}
	
	return True;
}

/* Plaintext version of the above. */

bool SMBNTLMv2encrypt(const char *user, const char *domain, const char *password, 
		      const DATA_BLOB *server_chal, 
		      const DATA_BLOB *names_blob,
		      DATA_BLOB *lm_response, DATA_BLOB *nt_response, 
		      DATA_BLOB *user_session_key) 
{
	uchar nt_hash[16];
	E_md4hash(password, nt_hash);

	return SMBNTLMv2encrypt_hash(user, domain, nt_hash,
				server_chal,
				names_blob,
				lm_response, nt_response,
				user_session_key);
}

/***********************************************************
 encode a password buffer with a unicode password.  The buffer
 is filled with random data to make it harder to attack.
************************************************************/
bool encode_pw_buffer(uint8 buffer[516], const char *password, int string_flags)
{
	uchar new_pw[512];
	size_t new_pw_len;

	/* the incoming buffer can be any alignment. */
	string_flags |= STR_NOALIGN;

	new_pw_len = push_string(NULL, new_pw,
				 password, 
				 sizeof(new_pw), string_flags);
	
	memcpy(&buffer[512 - new_pw_len], new_pw, new_pw_len);

	generate_random_buffer(buffer, 512 - new_pw_len);

	/* 
	 * The length of the new password is in the last 4 bytes of
	 * the data buffer.
	 */
	SIVAL(buffer, 512, new_pw_len);
	ZERO_STRUCT(new_pw);
	return True;
}


/***********************************************************
 decode a password buffer
 *new_pw_len is the length in bytes of the possibly mulitbyte
 returned password including termination.
************************************************************/

bool decode_pw_buffer(TALLOC_CTX *ctx,
			uint8 in_buffer[516],
			char **pp_new_pwrd,
			uint32 *new_pw_len,
			int string_flags)
{
	int byte_len=0;

	*pp_new_pwrd = NULL;
	*new_pw_len = 0;

	/* the incoming buffer can be any alignment. */
	string_flags |= STR_NOALIGN;

	/*
	  Warning !!! : This function is called from some rpc call.
	  The password IN the buffer may be a UNICODE string.
	  The password IN new_pwrd is an ASCII string
	  If you reuse that code somewhere else check first.
	*/

	/* The length of the new password is in the last 4 bytes of the data buffer. */

	byte_len = IVAL(in_buffer, 512);

#ifdef DEBUG_PASSWORD
	dump_data(100, in_buffer, 516);
#endif

	/* Password cannot be longer than the size of the password buffer */
	if ( (byte_len < 0) || (byte_len > 512)) {
		DEBUG(0, ("decode_pw_buffer: incorrect password length (%d).\n", byte_len));
		DEBUG(0, ("decode_pw_buffer: check that 'encrypt passwords = yes'\n"));
		return false;
	}

	/* decode into the return buffer. */
	*new_pw_len = pull_string_talloc(ctx,
				NULL,
				0,
				pp_new_pwrd,
				&in_buffer[512 - byte_len],
				byte_len,
				string_flags);

	if (!*pp_new_pwrd || *new_pw_len == 0) {
		DEBUG(0, ("decode_pw_buffer: pull_string_talloc failed\n"));
		return false;
	}

#ifdef DEBUG_PASSWORD
	DEBUG(100,("decode_pw_buffer: new_pwrd: "));
	dump_data(100, (uint8 *)*pp_new_pwrd, *new_pw_len);
	DEBUG(100,("multibyte len:%d\n", *new_pw_len));
	DEBUG(100,("original char len:%d\n", byte_len/2));
#endif

	return true;
}

/***********************************************************
 Decode an arc4 encrypted password change buffer.
************************************************************/

void encode_or_decode_arc4_passwd_buffer(unsigned char pw_buf[532], const DATA_BLOB *psession_key)
{
	struct MD5Context tctx;
	unsigned char key_out[16];

	/* Confounder is last 16 bytes. */

	MD5Init(&tctx);
	MD5Update(&tctx, &pw_buf[516], 16);
	MD5Update(&tctx, psession_key->data, psession_key->length);
	MD5Final(key_out, &tctx);
	/* arc4 with key_out. */
	SamOEMhash(pw_buf, key_out, 516);
}

/***********************************************************
 Encrypt/Decrypt used for LSA secrets and trusted domain
 passwords.
************************************************************/

void sess_crypt_blob(DATA_BLOB *out, const DATA_BLOB *in, const DATA_BLOB *session_key, int forward)
{
	int i, k;

	for (i=0,k=0;
	     i<in->length;
	     i += 8, k += 7) {
		uint8 bin[8], bout[8], key[7];

		memset(bin, 0, 8);
		memcpy(bin,  &in->data[i], MIN(8, in->length-i));

		if (k + 7 > session_key->length) {
			k = (session_key->length - k);
		}
		memcpy(key, &session_key->data[k], 7);

		des_crypt56(bout, bin, key, forward?1:0);

		memcpy(&out->data[i], bout, MIN(8, in->length-i));
        }
}

/* Decrypts password-blob with session-key
 * @param nt_hash	NT hash for the session key
 * @param data_in 	DATA_BLOB encrypted password
 *
 * Returns cleartext password in CH_UNIX 
 * Caller must free the returned string
 */

char *decrypt_trustdom_secret(uint8_t nt_hash[16], DATA_BLOB *data_in)
{
	DATA_BLOB data_out, sess_key;
	uint32_t length;
	uint32_t version;
	fstring cleartextpwd;

	if (!data_in || !nt_hash)
		return NULL;

	/* hashed twice with md4 */
	mdfour(nt_hash, nt_hash, 16);

	/* 16-Byte session-key */
	sess_key = data_blob(nt_hash, 16);
	if (sess_key.data == NULL)
		return NULL;
	
	data_out = data_blob(NULL, data_in->length);
	if (data_out.data == NULL)
		return NULL;
	
	/* decrypt with des3 */
	sess_crypt_blob(&data_out, data_in, &sess_key, 0);

	/* 4 Byte length, 4 Byte version */
	length  = IVAL(data_out.data, 0);
	version = IVAL(data_out.data, 4);

	if (length > data_in->length - 8) {
		DEBUG(0,("decrypt_trustdom_secret: invalid length (%d)\n", length));
		return NULL;
	}
	
	if (version != 1) {
		DEBUG(0,("decrypt_trustdom_secret: unknown version number (%d)\n", version));
		return NULL;
	}
	
	rpcstr_pull(cleartextpwd, data_out.data + 8, sizeof(fstring), length, 0 );

#ifdef DEBUG_PASSWORD
	DEBUG(100,("decrypt_trustdom_secret: length is: %d, version is: %d, password is: %s\n", 
				length, version, cleartextpwd));
#endif

	data_blob_free(&data_out);
	data_blob_free(&sess_key);
	
	return SMB_STRDUP(cleartextpwd);

}

/* encode a wkssvc_PasswordBuffer:
 *
 * similar to samr_CryptPasswordEx. Different: 8byte confounder (instead of
 * 16byte), confounder in front of the 516 byte buffer (instead of after that
 * buffer), calling MD5Update() first with session_key and then with confounder
 * (vice versa in samr) - Guenther */

void encode_wkssvc_join_password_buffer(TALLOC_CTX *mem_ctx,
					const char *pwd,
					DATA_BLOB *session_key,
					struct wkssvc_PasswordBuffer **pwd_buf)
{
	uint8_t buffer[516];
	struct MD5Context ctx;
	struct wkssvc_PasswordBuffer *my_pwd_buf = NULL;
	DATA_BLOB confounded_session_key;
	int confounder_len = 8;
	uint8_t confounder[8];

	my_pwd_buf = talloc_zero(mem_ctx, struct wkssvc_PasswordBuffer);
	if (!my_pwd_buf) {
		return;
	}

	confounded_session_key = data_blob_talloc(mem_ctx, NULL, 16);

	encode_pw_buffer(buffer, pwd, STR_UNICODE);

	generate_random_buffer((uint8_t *)confounder, confounder_len);

	MD5Init(&ctx);
	MD5Update(&ctx, session_key->data, session_key->length);
	MD5Update(&ctx, confounder, confounder_len);
	MD5Final(confounded_session_key.data, &ctx);

	SamOEMhashBlob(buffer, 516, &confounded_session_key);

	memcpy(&my_pwd_buf->data[0], confounder, confounder_len);
	memcpy(&my_pwd_buf->data[8], buffer, 516);

	data_blob_free(&confounded_session_key);

	*pwd_buf = my_pwd_buf;
}

WERROR decode_wkssvc_join_password_buffer(TALLOC_CTX *mem_ctx,
					  struct wkssvc_PasswordBuffer *pwd_buf,
					  DATA_BLOB *session_key,
					  char **pwd)
{
	uint8_t buffer[516];
	struct MD5Context ctx;
	uint32_t pwd_len;

	DATA_BLOB confounded_session_key;

	int confounder_len = 8;
	uint8_t confounder[8];

	*pwd = NULL;

	if (!pwd_buf) {
		return WERR_BAD_PASSWORD;
	}

	if (session_key->length != 16) {
		DEBUG(10,("invalid session key\n"));
		return WERR_BAD_PASSWORD;
	}

	confounded_session_key = data_blob_talloc(mem_ctx, NULL, 16);

	memcpy(&confounder, &pwd_buf->data[0], confounder_len);
	memcpy(&buffer, &pwd_buf->data[8], 516);

	MD5Init(&ctx);
	MD5Update(&ctx, session_key->data, session_key->length);
	MD5Update(&ctx, confounder, confounder_len);
	MD5Final(confounded_session_key.data, &ctx);

	SamOEMhashBlob(buffer, 516, &confounded_session_key);

	if (!decode_pw_buffer(mem_ctx, buffer, pwd, &pwd_len, STR_UNICODE)) {
		data_blob_free(&confounded_session_key);
		return WERR_BAD_PASSWORD;
	}

	data_blob_free(&confounded_session_key);

	return WERR_OK;
}

DATA_BLOB decrypt_drsuapi_blob(TALLOC_CTX *mem_ctx,
			       const DATA_BLOB *session_key,
			       bool rcrypt,
			       uint32_t rid,
			       const DATA_BLOB *buffer)
{
	DATA_BLOB confounder;
	DATA_BLOB enc_buffer;

	struct MD5Context md5;
	uint8_t _enc_key[16];
	DATA_BLOB enc_key;

	DATA_BLOB dec_buffer;

	uint32_t crc32_given;
	uint32_t crc32_calc;
	DATA_BLOB checked_buffer;

	DATA_BLOB plain_buffer;

	/*
	 * the combination "c[3] s[1] e[1] d[0]..."
	 * was successful!!!!!!!!!!!!!!!!!!!!!!!!!!
	 */

	/*
	 * the first 16 bytes at the beginning are the confounder
	 * followed by the 4 byte crc32 checksum
	 */
	if (buffer->length < 20) {
		return data_blob_const(NULL, 0);
	}
	confounder = data_blob_const(buffer->data, 16);
	enc_buffer = data_blob_const(buffer->data + 16, buffer->length - 16);

	/*
	 * build the encryption key md5 over the session key followed
	 * by the confounder
	 *
	 * here the gensec session key is used and
	 * not the dcerpc ncacn_ip_tcp "SystemLibraryDTC" key!
	 */
	enc_key = data_blob_const(_enc_key, sizeof(_enc_key));
	MD5Init(&md5);
	MD5Update(&md5, session_key->data, session_key->length);
	MD5Update(&md5, confounder.data, confounder.length);
	MD5Final(enc_key.data, &md5);

	/*
	 * copy the encrypted buffer part and
	 * decrypt it using the created encryption key using arcfour
	 */
	dec_buffer = data_blob_talloc(mem_ctx, enc_buffer.data, enc_buffer.length);
	if (!dec_buffer.data) {
		return data_blob_const(NULL, 0);
	}
	SamOEMhashBlob(dec_buffer.data, dec_buffer.length, &enc_key);

	/*
	 * the first 4 byte are the crc32 checksum
	 * of the remaining bytes
	 */
	crc32_given = IVAL(dec_buffer.data, 0);
	crc32_calc = crc32_calc_buffer((const char *)dec_buffer.data + 4 , dec_buffer.length - 4);
	if (crc32_given != crc32_calc) {
		DEBUG(1,("CRC32: given[0x%08X] calc[0x%08X]\n",
		      crc32_given, crc32_calc));
		return data_blob_const(NULL, 0);
	}
	checked_buffer = data_blob_talloc(mem_ctx, dec_buffer.data + 4, dec_buffer.length - 4);
	if (!checked_buffer.data) {
		return data_blob_const(NULL, 0);
	}

	/*
	 * some attributes seem to be in a usable form after this decryption
	 * (supplementalCredentials, priorValue, currentValue, trustAuthOutgoing,
	 *  trustAuthIncoming, initialAuthOutgoing, initialAuthIncoming)
	 * At least supplementalCredentials contains plaintext
	 * like "Primary:Kerberos" (in unicode form)
	 *
	 * some attributes seem to have some additional encryption
	 * dBCSPwd, unicodePwd, ntPwdHistory, lmPwdHistory
	 *
	 * it's the sam_rid_crypt() function, as the value is constant,
	 * so it doesn't depend on sessionkeys.
	 */
	if (rcrypt) {
		uint32_t i, num_hashes;

		if ((checked_buffer.length % 16) != 0) {
			return data_blob_const(NULL, 0);
		}

		plain_buffer = data_blob_talloc(mem_ctx, checked_buffer.data, checked_buffer.length);
		if (!plain_buffer.data) {
			return data_blob_const(NULL, 0);
		}

		num_hashes = plain_buffer.length / 16;
		for (i = 0; i < num_hashes; i++) {
			uint32_t offset = i * 16;
			sam_pwd_hash(rid, checked_buffer.data + offset, plain_buffer.data + offset, 0);
		}
	} else {
		plain_buffer = checked_buffer;
	}

	return plain_buffer;
}


