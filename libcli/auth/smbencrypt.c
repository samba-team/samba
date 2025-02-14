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
#include "system/time.h"
#include "../libcli/auth/msrpc_parse.h"
#include "../lib/crypto/crypto.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/ndr_ntlmssp.h"
#include "lib/util/bytearray.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

int SMBencrypt_hash(const uint8_t lm_hash[16], const uint8_t *c8, uint8_t p24[24])
{
	uint8_t p21[21];
	int rc;

	memset(p21,'\0',21);
	memcpy(p21, lm_hash, 16);

	rc = SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("SMBencrypt_hash: lm#, challenge, response\n"));
	dump_data(100, p21, 16);
	dump_data(100, c8, 8);
	dump_data(100, p24, 24);
#endif

	return rc;
}

/*
   This implements the X/Open SMB password encryption
   It takes a password ('unix' string), a 8 byte "crypt key"
   and puts 24 bytes of encrypted password into p24

   Returns False if password must have been truncated to create LM hash
*/

bool SMBencrypt(const char *passwd, const uint8_t *c8, uint8_t p24[24])
{
	bool ret;
	uint8_t lm_hash[16];
	int rc;

	ret = E_deshash(passwd, lm_hash);
	rc = SMBencrypt_hash(lm_hash, c8, p24);
	if (rc != 0) {
		ret = false;
	}
	return ret;
}

/**
 * Creates the MD4 Hash of the users password in NT UNICODE.
 * @param passwd password in 'unix' charset.
 * @param p16 return password hashed with md4, caller allocated 16 byte buffer
 */

bool E_md4hash(const char *passwd, uint8_t p16[16])
{
	size_t len;
	smb_ucs2_t *wpwd;
	bool ret;

	ret = push_ucs2_talloc(NULL, &wpwd, passwd, &len);
	if (!ret || len < 2) {
		/* We don't want to return fixed data, as most callers
		 * don't check */
		mdfour(p16, (const uint8_t *)passwd, strlen(passwd));
		return false;
	}

	len -= 2;
	mdfour(p16, (const uint8_t *)wpwd, len);

	talloc_free(wpwd);
	return true;
}

/**
 * Creates the DES forward-only Hash of the users password in DOS ASCII charset
 * @param passwd password in 'unix' charset.
 * @param p16 return password hashed with DES, caller allocated 16 byte buffer
 * @return false if password was > 14 characters, and therefore may be incorrect, otherwise true
 * @note p16 is filled in regardless
 */

bool E_deshash(const char *passwd, uint8_t p16[16])
{
	bool ret;
	int rc;
	uint8_t dospwd[14];
	TALLOC_CTX *frame = talloc_stackframe();

	size_t converted_size;

	char *tmpbuf;

	ZERO_STRUCT(dospwd);

	tmpbuf = strupper_talloc(frame, passwd);
	if (tmpbuf == NULL) {
		/* Too many callers don't check this result, we need to fill in the buffer with something */
		strlcpy((char *)dospwd, passwd ? passwd : "", sizeof(dospwd));
		E_P16(dospwd, p16);
		talloc_free(frame);
		return false;
	}

	ZERO_STRUCT(dospwd);

	ret = convert_string_error(CH_UNIX, CH_DOS, tmpbuf, strlen(tmpbuf), dospwd, sizeof(dospwd), &converted_size);
	talloc_free(frame);

	/* Only the first 14 chars are considered, password need not
	 * be null terminated.  We do this in the error and success
	 * case to avoid returning a fixed 'password' buffer, but
	 * callers should not use it when E_deshash returns false */

	rc = E_P16((const uint8_t *)dospwd, p16);
	if (rc != 0) {
		ret = false;
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
void nt_lm_owf_gen(const char *pwd, uint8_t nt_p16[16], uint8_t p16[16])
{
	/* Calculate the MD4 hash (NT compatible) of the password */
	memset(nt_p16, '\0', 16);
	E_md4hash(pwd, nt_p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: pwd, nt#\n"));
	dump_data(120, (const uint8_t *)pwd, strlen(pwd));
	dump_data(100, nt_p16, 16);
#endif

	E_deshash(pwd, (uint8_t *)p16);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_lm_owf_gen: pwd, lm#\n"));
	dump_data(120, (const uint8_t *)pwd, strlen(pwd));
	dump_data(100, p16, 16);
#endif
}

/* Does both the NTLMv2 owfs of a user's password */
bool ntv2_owf_gen(const uint8_t owf[16],
		  const char *user_in, const char *domain_in,
		  uint8_t kr_buf[16])
{
	smb_ucs2_t *user;
	smb_ucs2_t *domain;
	size_t user_byte_len;
	size_t domain_byte_len;
	gnutls_hmac_hd_t hmac_hnd = NULL;
	int rc;
	bool ok = false;
	TALLOC_CTX *mem_ctx = talloc_init("ntv2_owf_gen for %s\\%s", domain_in, user_in);

	if (!mem_ctx) {
		return false;
	}

	if (!user_in) {
		user_in = "";
	}

	if (!domain_in) {
		domain_in = "";
	}

	user_in = strupper_talloc(mem_ctx, user_in);
	if (user_in == NULL) {
		talloc_free(mem_ctx);
		return false;
	}

	ok = push_ucs2_talloc(mem_ctx, &user, user_in, &user_byte_len );
	if (!ok) {
		DEBUG(0, ("push_uss2_talloc() for user failed)\n"));
		talloc_free(mem_ctx);
		return false;
	}

	ok = push_ucs2_talloc(mem_ctx, &domain, domain_in, &domain_byte_len);
	if (!ok) {
		DEBUG(0, ("push_ucs2_talloc() for domain failed\n"));
		talloc_free(mem_ctx);
		return false;
	}

	SMB_ASSERT(user_byte_len >= 2);
	SMB_ASSERT(domain_byte_len >= 2);

	/* We don't want null termination */
	user_byte_len = user_byte_len - 2;
	domain_byte_len = domain_byte_len - 2;

	rc = gnutls_hmac_init(&hmac_hnd,
			      GNUTLS_MAC_MD5,
			      owf,
			      16);
	if (rc < 0) {
		ok = false;
		goto out;
	}

	rc = gnutls_hmac(hmac_hnd, user, user_byte_len);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		ok = false;
		goto out;
	}
	rc = gnutls_hmac(hmac_hnd, domain, domain_byte_len);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		ok = false;
		goto out;
	}

	gnutls_hmac_deinit(hmac_hnd, kr_buf);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("ntv2_owf_gen: user, domain, owfkey, kr\n"));
	dump_data(100, (uint8_t *)user, user_byte_len);
	dump_data(100, (uint8_t *)domain, domain_byte_len);
	dump_data(100, owf, 16);
	dump_data(100, kr_buf, 16);
#endif

	ok = true;
out:
	talloc_free(mem_ctx);
	return ok;
}

/* Does the des encryption from the NT or LM MD4 hash. */
int SMBOWFencrypt(const uint8_t passwd[16], const uint8_t *c8, uint8_t p24[24])
{
	uint8_t p21[21];

	ZERO_STRUCT(p21);

	memcpy(p21, passwd, 16);
	return E_P24(p21, c8, p24);
}

/* Does the des encryption. */

int SMBNTencrypt_hash(const uint8_t nt_hash[16], const uint8_t *c8, uint8_t *p24)
{
	uint8_t p21[21];
	int rc;

	memset(p21,'\0',21);
	memcpy(p21, nt_hash, 16);
	rc = SMBOWFencrypt(p21, c8, p24);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("SMBNTencrypt: nt#, challenge, response\n"));
	dump_data(100, p21, 16);
	dump_data(100, c8, 8);
	dump_data(100, p24, 24);
#endif

	return rc;
}

/* Does the NT MD4 hash then des encryption. Plaintext version of the above. */

int SMBNTencrypt(const char *passwd, const uint8_t *c8, uint8_t *p24)
{
	uint8_t nt_hash[16];
	E_md4hash(passwd, nt_hash);
	return SMBNTencrypt_hash(nt_hash, c8, p24);
}


/* Does the md5 encryption from the Key Response for NTLMv2. */
NTSTATUS SMBOWFencrypt_ntv2(const uint8_t kr[16],
			    const DATA_BLOB *srv_chal,
			    const DATA_BLOB *smbcli_chal,
			    uint8_t resp_buf[16])
{
	gnutls_hmac_hd_t hmac_hnd = NULL;
	NTSTATUS status;
	int rc;

	rc = gnutls_hmac_init(&hmac_hnd,
			      GNUTLS_MAC_MD5,
			      kr,
			      16);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
	}

	rc = gnutls_hmac(hmac_hnd, srv_chal->data, srv_chal->length);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		goto out;
	}
	rc = gnutls_hmac(hmac_hnd, smbcli_chal->data, smbcli_chal->length);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		goto out;
	}


	status = NT_STATUS_OK;
out:
	gnutls_hmac_deinit(hmac_hnd, resp_buf);
#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBOWFencrypt_ntv2: srv_chal, smbcli_chal, resp_buf: %s\n",
		    nt_errstr(status)));
	dump_data(100, srv_chal->data, srv_chal->length);
	dump_data(100, smbcli_chal->data, smbcli_chal->length);
	dump_data(100, resp_buf, 16);
#endif
	return status;
}

NTSTATUS SMBsesskeygen_ntv2(const uint8_t kr[16],
			    const uint8_t *nt_resp,
			    uint8_t sess_key[16])
{
	int rc;

	/* a very nice, 128 bit, variable session key */
	rc = gnutls_hmac_fast(GNUTLS_MAC_MD5,
			      kr,
			      16,
			      nt_resp,
			      16,
			      sess_key);
	if (rc != 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
	}

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBsesskeygen_ntv2:\n"));
	dump_data(100, sess_key, 16);
#endif

	return NT_STATUS_OK;
}

void SMBsesskeygen_ntv1(const uint8_t kr[16], uint8_t sess_key[16])
{
	/* yes, this session key does not change - yes, this
	   is a problem - but it is 128 bits */

	mdfour((uint8_t *)sess_key, kr, 16);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBsesskeygen_ntv1:\n"));
	dump_data(100, sess_key, 16);
#endif
}

NTSTATUS SMBsesskeygen_lm_sess_key(const uint8_t lm_hash[16],
			       const uint8_t lm_resp[24], /* only uses 8 */
			       uint8_t sess_key[16])
{
	/* Calculate the LM session key (effective length 40 bits,
	   but changes with each session) */
	uint8_t p24[24];
	uint8_t partial_lm_hash[14];
	int rc;

	memcpy(partial_lm_hash, lm_hash, 8);
	memset(partial_lm_hash + 8, 0xbd, 6);

	rc = des_crypt56_gnutls(p24, lm_resp, partial_lm_hash, SAMBA_GNUTLS_ENCRYPT);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}
	rc = des_crypt56_gnutls(p24+8, lm_resp, partial_lm_hash + 7, SAMBA_GNUTLS_ENCRYPT);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}

	memcpy(sess_key, p24, 16);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("SMBsesskeygen_lm_sess_key: \n"));
	dump_data(100, sess_key, 16);
#endif

	return NT_STATUS_OK;
}

DATA_BLOB NTLMv2_generate_names_blob(TALLOC_CTX *mem_ctx,
				     const char *hostname,
				     const char *domain)
{
	DATA_BLOB names_blob = data_blob_talloc(mem_ctx, NULL, 0);

	/* Deliberately ignore return here.. */
	if (hostname != NULL) {
		(void)msrpc_gen(mem_ctx, &names_blob,
			  "aaa",
			  MsvAvNbDomainName, domain,
			  MsvAvNbComputerName, hostname,
			  MsvAvEOL, "");
	} else {
		(void)msrpc_gen(mem_ctx, &names_blob,
			  "aa",
			  MsvAvNbDomainName, domain,
			  MsvAvEOL, "");
	}
	return names_blob;
}

static DATA_BLOB NTLMv2_generate_client_data(TALLOC_CTX *mem_ctx,
					     NTTIME nttime,
					     const DATA_BLOB *names_blob)
{
	uint8_t client_chal[8];
	DATA_BLOB response = data_blob(NULL, 0);
	uint8_t long_date[8];

	generate_random_buffer(client_chal, sizeof(client_chal));

	push_nttime(long_date, 0, nttime);

	/* See http://www.ubiqx.org/cifs/SMB.html#SMB.8.5 */

	/* Deliberately ignore return here.. */
	(void)msrpc_gen(mem_ctx, &response, "ddbbdb",
		  0x00000101,     /* Header  */
		  0,              /* 'Reserved'  */
		  long_date, 8,	  /* Timestamp */
		  client_chal, 8, /* client challenge */
		  0,		  /* Unknown */
		  names_blob->data, names_blob->length);	/* End of name list */

	return response;
}

static DATA_BLOB NTLMv2_generate_response(TALLOC_CTX *out_mem_ctx,
					  const uint8_t ntlm_v2_hash[16],
					  const DATA_BLOB *server_chal,
					  NTTIME nttime,
					  const DATA_BLOB *names_blob)
{
	uint8_t ntlmv2_response[16];
	DATA_BLOB ntlmv2_client_data;
	DATA_BLOB final_response;
	NTSTATUS status;

	TALLOC_CTX *mem_ctx = talloc_named(out_mem_ctx, 0,
					   "NTLMv2_generate_response internal context");

	if (!mem_ctx) {
		return data_blob(NULL, 0);
	}

	/* NTLMv2 */
	/* generate some data to pass into the response function - including
	   the hostname and domain name of the server */
	ntlmv2_client_data = NTLMv2_generate_client_data(mem_ctx, nttime, names_blob);

	/* Given that data, and the challenge from the server, generate a response */
	status = SMBOWFencrypt_ntv2(ntlm_v2_hash,
				    server_chal,
				    &ntlmv2_client_data,
				    ntlmv2_response);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return data_blob(NULL, 0);
	}

	final_response = data_blob_talloc(out_mem_ctx, NULL, sizeof(ntlmv2_response) + ntlmv2_client_data.length);

	memcpy(final_response.data, ntlmv2_response, sizeof(ntlmv2_response));

	memcpy(final_response.data+sizeof(ntlmv2_response),
	       ntlmv2_client_data.data, ntlmv2_client_data.length);

	talloc_free(mem_ctx);

	return final_response;
}

static DATA_BLOB LMv2_generate_response(TALLOC_CTX *mem_ctx,
					const uint8_t ntlm_v2_hash[16],
					const DATA_BLOB *server_chal)
{
	uint8_t lmv2_response[16];
	DATA_BLOB lmv2_client_data = data_blob_talloc(mem_ctx, NULL, 8);
	DATA_BLOB final_response = data_blob_talloc(mem_ctx, NULL,24);
	NTSTATUS status;

	/* LMv2 */
	/* client-supplied random data */
	generate_random_buffer(lmv2_client_data.data, lmv2_client_data.length);

	/* Given that data, and the challenge from the server, generate a response */
	status = SMBOWFencrypt_ntv2(ntlm_v2_hash,
				    server_chal,
				    &lmv2_client_data,
				    lmv2_response);
	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&lmv2_client_data);
		return data_blob(NULL, 0);
	}
	memcpy(final_response.data, lmv2_response, sizeof(lmv2_response));

	/* after the first 16 bytes is the random data we generated above,
	   so the server can verify us with it */
	memcpy(final_response.data+sizeof(lmv2_response),
	       lmv2_client_data.data, lmv2_client_data.length);

	data_blob_free(&lmv2_client_data);

	return final_response;
}

bool SMBNTLMv2encrypt_hash(TALLOC_CTX *mem_ctx,
			   const char *user, const char *domain, const uint8_t nt_hash[16],
			   const DATA_BLOB *server_chal,
			   const NTTIME *server_timestamp,
			   const DATA_BLOB *names_blob,
			   DATA_BLOB *lm_response, DATA_BLOB *nt_response,
			   DATA_BLOB *lm_session_key, DATA_BLOB *user_session_key)
{
	uint8_t ntlm_v2_hash[16];
	NTSTATUS status;

	/* We don't use the NT# directly.  Instead we use it mashed up with
	   the username and domain.
	   This prevents username swapping during the auth exchange
	*/
	if (!ntv2_owf_gen(nt_hash, user, domain, ntlm_v2_hash)) {
		return false;
	}

	if (nt_response) {
		const NTTIME *nttime = server_timestamp;
		NTTIME _now = 0;

		if (nttime == NULL) {
			struct timeval tv_now = timeval_current();
			_now = timeval_to_nttime(&tv_now);
			nttime = &_now;
		}

		*nt_response = NTLMv2_generate_response(mem_ctx,
							ntlm_v2_hash,
							server_chal,
							*nttime,
							names_blob);
		if (user_session_key) {
			*user_session_key = data_blob_talloc(mem_ctx, NULL, 16);

			/* The NTLMv2 calculations also provide a session key, for signing etc later */
			/* use only the first 16 bytes of nt_response for session key */
			status = SMBsesskeygen_ntv2(ntlm_v2_hash,
						    nt_response->data,
						    user_session_key->data);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}
		}
	}

	/* LMv2 */

	if (lm_response) {
		if (server_timestamp != NULL) {
			*lm_response = data_blob_talloc_zero(mem_ctx, 24);
		} else {
			*lm_response = LMv2_generate_response(mem_ctx,
							      ntlm_v2_hash,
							      server_chal);
		}
		if (lm_session_key) {
			*lm_session_key = data_blob_talloc(mem_ctx, NULL, 16);

			/* The NTLMv2 calculations also provide a session key, for signing etc later */
			/* use only the first 16 bytes of lm_response for session key */
			status = SMBsesskeygen_ntv2(ntlm_v2_hash,
						    lm_response->data,
						    lm_session_key->data);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}
		}
	}

	return true;
}

bool SMBNTLMv2encrypt(TALLOC_CTX *mem_ctx,
		      const char *user, const char *domain,
		      const char *password,
		      const DATA_BLOB *server_chal,
		      const DATA_BLOB *names_blob,
		      DATA_BLOB *lm_response, DATA_BLOB *nt_response,
		      DATA_BLOB *lm_session_key, DATA_BLOB *user_session_key)
{
	uint8_t nt_hash[16];
	E_md4hash(password, nt_hash);

	return SMBNTLMv2encrypt_hash(mem_ctx,
				     user, domain, nt_hash,
				     server_chal, NULL, names_blob,
				     lm_response, nt_response, lm_session_key, user_session_key);
}

static NTSTATUS NTLMv2_RESPONSE_verify_workstation(const char *account_name,
			const char *account_domain,
			const struct NTLMv2_RESPONSE *v2_resp,
			const struct netlogon_creds_CredentialState *creds,
			const char *workgroup)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct AV_PAIR *av_nb_cn = NULL;
	const struct AV_PAIR *av_nb_dn = NULL;
	int cmp;

	/*
	 * Make sure the netbios computer name in the
	 * NTLMv2_RESPONSE matches the computer name
	 * in the secure channel credentials for workstation
	 * trusts.
	 *
	 * And the netbios domain name matches our
	 * workgroup.
	 *
	 * This prevents workstations from requesting
	 * the session key of NTLMSSP sessions of clients
	 * to other hosts.
	 */
	av_nb_cn = ndr_ntlmssp_find_av(&v2_resp->Challenge.AvPairs,
				       MsvAvNbComputerName);
	av_nb_dn = ndr_ntlmssp_find_av(&v2_resp->Challenge.AvPairs,
				       MsvAvNbDomainName);

	if (av_nb_cn != NULL) {
		const char *v = NULL;
		char *a = NULL;
		size_t len;

		v = av_nb_cn->Value.AvNbComputerName;

		a = talloc_strdup(frame, creds->account_name);
		if (a == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		len = strlen(a);
		if (len > 0 && a[len - 1] == '$') {
			a[len - 1] = '\0';
		}

		cmp = strcasecmp_m(a, v);
		if (cmp != 0) {
			DEBUG(2,("%s: NTLMv2_RESPONSE with "
				 "NbComputerName[%s] rejected "
				 "for user[%s\\%s] "
				 "against SEC_CHAN_WKSTA[%s/%s] "
				 "in workgroup[%s]\n",
				 __func__, v,
				 account_domain,
				 account_name,
				 creds->computer_name,
				 creds->account_name,
				 workgroup));
			TALLOC_FREE(frame);
			return NT_STATUS_LOGON_FAILURE;
		}
	}
	if (av_nb_dn != NULL) {
		const char *v = NULL;

		v = av_nb_dn->Value.AvNbDomainName;

		cmp = strcasecmp_m(workgroup, v);
		if (cmp != 0) {
			DEBUG(2,("%s: NTLMv2_RESPONSE with "
				 "NbDomainName[%s] rejected "
				 "for user[%s\\%s] "
				 "against SEC_CHAN_WKSTA[%s/%s] "
				 "in workgroup[%s]\n",
				 __func__, v,
				 account_domain,
				 account_name,
				 creds->computer_name,
				 creds->account_name,
				 workgroup));
			TALLOC_FREE(frame);
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS NTLMv2_RESPONSE_verify_trust(const char *account_name,
			const char *account_domain,
			const struct NTLMv2_RESPONSE *v2_resp,
			const struct netlogon_creds_CredentialState *creds,
			size_t num_domains,
			const struct trust_forest_domain_info *domains)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct trust_forest_domain_info *ld = NULL;
	const struct trust_forest_domain_info *rd = NULL;
	const struct AV_PAIR *av_nbt = NULL;
	const char *nbt = NULL;
	const struct AV_PAIR *av_dns = NULL;
	const char *dns = NULL;
	size_t di;
	size_t fi;
	bool match;
	const struct lsa_ForestTrustDomainInfo *nbt_match_rd = NULL;
	size_t nbt_matches = 0;
	const struct lsa_ForestTrustDomainInfo *dns_match_rd = NULL;
	size_t dns_matches = 0;
	const char *schan_name = NULL;

	switch (creds->secure_channel_type) {
	case SEC_CHAN_DNS_DOMAIN:
		schan_name = "SEC_CHAN_DNS_DOMAIN";
		break;
	case SEC_CHAN_DOMAIN:
		schan_name = "SEC_CHAN_DOMAIN";
		break;

	default:
		smb_panic(__location__);
		return NT_STATUS_INTERNAL_ERROR;
	}

	/*
	 * MS-NRPC 3.5.4.5.1.1 Pass-through domain name validation
	 */

	av_nbt = ndr_ntlmssp_find_av(&v2_resp->Challenge.AvPairs,
				     MsvAvNbDomainName);
	if (av_nbt != NULL) {
		nbt = av_nbt->Value.AvNbDomainName;
	}

	if (nbt == NULL) {
		/*
		 * Nothing to check
		 */
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	av_dns = ndr_ntlmssp_find_av(&v2_resp->Challenge.AvPairs,
				     MsvAvDnsDomainName);
	if (av_dns != NULL) {
		dns = av_dns->Value.AvDnsDomainName;
	}

	for (di = 0; di < num_domains; di++) {
		const struct trust_forest_domain_info *d =
				&domains[di];

		if (d->is_local_forest) {
			SMB_ASSERT(!d->is_checked_trust);
			SMB_ASSERT(ld == NULL);
			ld = d;
			continue;
		}

		if (d->is_checked_trust) {
			SMB_ASSERT(rd == NULL);
			rd = d;
			continue;
		}
	}

	SMB_ASSERT(ld != NULL);
	SMB_ASSERT(rd != NULL);

	/*
	 * All logic below doesn't handle WITHIN_FOREST trusts,
	 * but we don't supported them overall yet...
	 *
	 * Give an early error, so that the one
	 * implementing WITHIN_FOREST support will
	 * hit it easily...
	 */
	if (rd->tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
		DBG_ERR("remote tdo[%s/%s] WITHIN_FOREST not supported yet\n",
			rd->tdo->netbios_name.string,
			rd->tdo->domain_name.string);
		return NT_STATUS_NOT_SUPPORTED;
	}

	/*
	 * Check the names doesn't match
	 * anything in our local domain/forest
	 */

	match = strequal(nbt, ld->tdo->netbios_name.string);
	if (match) {
		DEBUG(2,("%s: NTLMv2_RESPONSE with "
			 "NbDomainName[%s] rejected "
			 "for user[%s\\%s] "
			 "against %s[%s/%s] "
			 "matches local tdo[%s/%s]\n",
			 __func__, nbt,
			 account_domain,
			 account_name,
			 schan_name,
			 creds->computer_name,
			 creds->account_name,
			 ld->tdo->netbios_name.string,
			 ld->tdo->domain_name.string));
		TALLOC_FREE(frame);
		return NT_STATUS_LOGON_FAILURE;
	}

	if (dns != NULL) {
		match = strequal(dns, ld->tdo->domain_name.string);
		if (match) {
			DEBUG(2,("%s: NTLMv2_RESPONSE with "
				 "DnsDomainName[%s] rejected "
				 "for user[%s\\%s] "
				 "against %s[%s/%s] "
				 "matches local tdo[%s/%s]\n",
				 __func__, dns,
				 account_domain,
				 account_name,
				 schan_name,
				 creds->computer_name,
				 creds->account_name,
				 ld->tdo->netbios_name.string,
				 ld->tdo->domain_name.string));
			TALLOC_FREE(frame);
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	for (fi = 0; ld->fti != NULL && fi < ld->fti->count; fi++) {
		const struct lsa_ForestTrustRecord2 *r = ld->fti->entries[fi];
		const struct lsa_ForestTrustDomainInfo *ldi = NULL;

		if (r == NULL) {
			continue;
		}

		if (r->type != LSA_FOREST_TRUST_DOMAIN_INFO) {
			continue;
		}
		ldi = &r->forest_trust_data.domain_info;

		match = strequal(nbt, ldi->netbios_domain_name.string);
		if (match) {
			DEBUG(2,("%s: NTLMv2_RESPONSE with "
				 "NbDomainName[%s] rejected "
				 "for user[%s\\%s] "
				 "against %s[%s/%s] "
				 "matches local forest tdi[%s/%s]\n",
				 __func__, nbt,
				 account_domain,
				 account_name,
				 schan_name,
				 creds->computer_name,
				 creds->account_name,
				 ldi->netbios_domain_name.string,
				 ldi->dns_domain_name.string));
			TALLOC_FREE(frame);
			return NT_STATUS_LOGON_FAILURE;
		}

		if (dns == NULL) {
			continue;
		}

		match = strequal(dns, ldi->dns_domain_name.string);
		if (match) {
			DEBUG(2,("%s: NTLMv2_RESPONSE with "
				 "DnsDomainName[%s] rejected "
				 "for user[%s\\%s] "
				 "against %s[%s/%s] "
				 "matches local forest tdi[%s/%s]\n",
				 __func__, dns,
				 account_domain,
				 account_name,
				 schan_name,
				 creds->computer_name,
				 creds->account_name,
				 ldi->netbios_domain_name.string,
				 ldi->dns_domain_name.string));
			TALLOC_FREE(frame);
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	if (!(rd->tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE)) {
		/*
		 * Now check it's from the external trust
		 */

		match = strequal(nbt, rd->tdo->netbios_name.string);
		if (!match) {
			DEBUG(2,("%s: NTLMv2_RESPONSE with "
				 "NbDomainName[%s] rejected "
				 "for user[%s\\%s] "
				 "against %s[%s/%s] "
				 "not matching remote tdo[%s/%s]\n",
				 __func__, nbt,
				 account_domain,
				 account_name,
				 schan_name,
				 creds->computer_name,
				 creds->account_name,
				 rd->tdo->netbios_name.string,
				 rd->tdo->domain_name.string));
			TALLOC_FREE(frame);
			return NT_STATUS_LOGON_FAILURE;
		}

		if (dns == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}

		match = strequal(dns, rd->tdo->domain_name.string);
		if (!match) {
			DEBUG(2,("%s: NTLMv2_RESPONSE with "
				 "DnsDomainName[%s] rejected "
				 "for user[%s\\%s] "
				 "against %s[%s/%s] "
				 "not matching remote tdo[%s/%s]\n",
				 __func__, dns,
				 account_domain,
				 account_name,
				 schan_name,
				 creds->computer_name,
				 creds->account_name,
				 rd->tdo->netbios_name.string,
				 rd->tdo->domain_name.string));
			TALLOC_FREE(frame);
			return NT_STATUS_LOGON_FAILURE;
		}

		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	/*
	 * Now we check the SCANNER_INFO records
	 * and make sure the values are missing
	 * or unique.
	 */

	for (di = 0; di < num_domains; di++) {
		const struct trust_forest_domain_info *d =
				&domains[di];

		if (d == ld) {
			/*
			 * Checked above
			 */
			continue;
		}

		if (ld->fti == NULL) {
			/*
			 * Nothing to check
			 * waiting for the
			 * forest trust scanner
			 * to catch it
			 */
			continue;
		}

		for (fi = 0; fi < ld->fti->count; fi++) {
			const struct lsa_ForestTrustRecord2 *r = ld->fti->entries[fi];
			const struct lsa_ForestTrustDomainInfo *lsi = NULL;

			if (r == NULL) {
				continue;
			}

			if (r->type != LSA_FOREST_TRUST_SCANNER_INFO) {
				continue;
			}
			lsi = &r->forest_trust_data.scanner_info;

			match = strequal(nbt, lsi->netbios_domain_name.string);
			if (match) {
				if (d == rd) {
					nbt_match_rd = lsi;
				}
				nbt_matches += 1;
			}

			if (dns == NULL) {
				continue;
			}

			match = strequal(dns, lsi->dns_domain_name.string);
			if (match) {
				if (d == rd) {
					dns_match_rd = lsi;
				}
				dns_matches += 1;
			}
		}
	}

	if (nbt_matches == 0) {
		/*
		 * No match of the netbios name at all,
		 * maybe the forest trust scanner did
		 * not run yet to catch it.
		 */
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (nbt_match_rd != NULL && nbt_matches == 1) {
		/*
		 * Exactly one match and that's from the
		 * remote trust that made the request.
		 */
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (nbt_match_rd == NULL) {
		/*
		 * There are matches only from other
		 * domains.
		 */
		DEBUG(2,("%s: NTLMv2_RESPONSE with "
			 "NbDomainName[%s] rejected "
			 "for user[%s\\%s] "
			 "against %s[%s/%s] "
			 "nbt_matches[%zu] dns_matches[%zu], "
			 "but not from forest[%s/%s]\n",
			 __func__, nbt,
			 account_domain,
			 account_name,
			 schan_name,
			 creds->computer_name,
			 creds->account_name,
			 nbt_matches,
			 dns_matches,
			 rd->tdo->netbios_name.string,
			 rd->tdo->domain_name.string));
		TALLOC_FREE(frame);
		return NT_STATUS_LOGON_FAILURE;
	}

	if (dns_match_rd == nbt_match_rd && dns_matches == 1) {
		/*
		 * We had a match in a scanner record of
		 * the remote trust and the dns part
		 * of that scanner record had a unique
		 * match.
		 */
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (dns != NULL) {
		DEBUG(2,("%s: NTLMv2_RESPONSE with "
			 "NbDomainName[%s] DnsDomainName[%s] rejected "
			 "for user[%s\\%s] "
			 "against %s[%s/%s] "
			 "nbt_matches[%zu] dns_matches[%zu], "
			 "but not from forest[%s/%s]\n",
			 __func__, nbt, dns,
			 account_domain,
			 account_name,
			 schan_name,
			 creds->computer_name,
			 creds->account_name,
			 nbt_matches,
			 dns_matches,
			 rd->tdo->netbios_name.string,
			 rd->tdo->domain_name.string));
	} else {
		DEBUG(2,("%s: NTLMv2_RESPONSE with "
			 "NbDomainName[%s] rejected "
			 "for user[%s\\%s] "
			 "against %s[%s/%s] "
			 "nbt_matches[%zu] dns_matches[%zu], "
			 "but not from forest[%s/%s]\n",
			 __func__, nbt,
			 account_domain,
			 account_name,
			 schan_name,
			 creds->computer_name,
			 creds->account_name,
			 nbt_matches,
			 dns_matches,
			 rd->tdo->netbios_name.string,
			 rd->tdo->domain_name.string));
	}

	TALLOC_FREE(frame);
	return NT_STATUS_LOGON_FAILURE;
}

NTSTATUS NTLMv2_RESPONSE_verify_netlogon_creds(const char *account_name,
			const char *account_domain,
			const DATA_BLOB response,
			const struct netlogon_creds_CredentialState *creds,
			const char *workgroup,
			size_t num_domains,
			const struct trust_forest_domain_info *domains,
			TALLOC_CTX *mem_ctx,
			char **_computer_name)
{
	TALLOC_CTX *frame = NULL;
	/* RespType + HiRespType */
	static const char *magic = "\x01\x01";
	int cmp;
	struct NTLMv2_RESPONSE v2_resp;
	enum ndr_err_code err;
	NTSTATUS status;

	if (_computer_name != NULL) {
		*_computer_name = NULL;
	}

	if (response.length < 48) {
		/*
		 * NTLMv2_RESPONSE has at least 48 bytes.
		 */
		return NT_STATUS_OK;
	}

	cmp = memcmp(response.data + 16, magic, 2);
	if (cmp != 0) {
		/*
		 * It doesn't look like a valid NTLMv2_RESPONSE
		 */
		return NT_STATUS_OK;
	}

	if (response.length == 95) {
		/*
		 * ndr_pull_NTLMv2_RESPONSE() fails on this strange blob,
		 * because the AvPairs content is not valid
		 * as AvLen of the first pair is 33032 (0x8108).
		 *
		 * I saw a single machine sending the following 3 times
		 * in a row, but I'm not sure if everything is static.
		 *
		 * Note this is NTLMv2_CLIENT_CHALLENGE only, not
		 * the full NTLMv2_RESPONSE (which has Response of 16 bytes
		 * before the NTLMv2_CLIENT_CHALLENGE).
		 *
		 * Note this code only prevents
		 * ndr_pull_error(Buffer Size Error): Pull bytes 39016
		 * debug message for a known case, the actual
		 * bug is also handled below in a generic way to
		 * map NT_STATUS_BUFFER_TOO_SMALL to NT_STATUS_OK.
		 *
		 * See https://bugzilla.samba.org/show_bug.cgi?id=14932
		 */
		static const char *netapp_magic =
			"\x01\x01\x00\x00\x00\x00\x00\x00"
			"\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f"
			"\xb8\x82\x3a\xf1\xb3\xdd\x08\x15"
			"\x00\x00\x00\x00\x11\xa2\x08\x81"
			"\x50\x38\x22\x78\x2b\x94\x47\xfe"
			"\x54\x94\x7b\xff\x17\x27\x5a\xb4"
			"\xf4\x18\xba\xdc\x2c\x38\xfd\x5b"
			"\xfb\x0e\xc1\x85\x1e\xcc\x92\xbb"
			"\x9b\xb1\xc4\xd5\x53\x14\xff\x8c"
			"\x76\x49\xf5\x45\x90\x19\xa2";
		/*
		 * First we check the initial bytes
		 * and the 0x3F timestamp.
		 */
		cmp = memcmp(response.data + 16,
			     netapp_magic,
			     16);
		if (cmp == 0) {
			/*
			 * Then check everything after the
			 * client challenge
			 */
			cmp = memcmp(response.data + 40,
				     netapp_magic + 24,
				     response.length - 40);
			if (cmp == 0) {
				DBG_DEBUG("Invalid NETAPP NTLMv2_RESPONSE "
					  "for user[%s\\%s] against "
					  "SEC_CHAN(%u)[%s/%s] "
					  "in workgroup[%s]\n",
					  account_domain,
					  account_name,
					  creds->secure_channel_type,
					  creds->computer_name,
					  creds->account_name,
					  workgroup);
				return NT_STATUS_OK;
			}
		}
	}

	frame = talloc_stackframe();

	err = ndr_pull_struct_blob(&response, frame, &v2_resp,
		(ndr_pull_flags_fn_t)ndr_pull_NTLMv2_RESPONSE);
	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		status = ndr_map_error2ntstatus(err);
		if (NT_STATUS_EQUAL(status, NT_STATUS_BUFFER_TOO_SMALL)) {
			/*
			 * We are supposed to ignore invalid buffers,
			 * see https://bugzilla.samba.org/show_bug.cgi?id=14932
			 */
			status = NT_STATUS_OK;
		}
		DEBUG(2,("%s: Failed to parse NTLMv2_RESPONSE length=%u "
			"for user[%s\\%s] against SEC_CHAN(%u)[%s/%s] "
			"in workgroup[%s] - %s %s %s\n",
			__func__,
			(unsigned)response.length,
			account_domain,
			account_name,
			creds->secure_channel_type,
			creds->computer_name,
			creds->account_name,
			workgroup,
			ndr_map_error2string(err),
			NT_STATUS_IS_OK(status) ? "(ignoring) =>" : "=>",
			nt_errstr(status)));
		dump_data(2, response.data, response.length);
		TALLOC_FREE(frame);
		return status;
	}

	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(NTLMv2_RESPONSE, &v2_resp);
	}

	if (_computer_name != NULL) {
		const struct AV_PAIR *av_nb_cn = NULL;
		const char *nb_cn = NULL;

		av_nb_cn = ndr_ntlmssp_find_av(&v2_resp.Challenge.AvPairs,
					       MsvAvNbComputerName);
		if (av_nb_cn != NULL) {
			nb_cn = av_nb_cn->Value.AvNbComputerName;
		}

		if (nb_cn != NULL) {
			*_computer_name = talloc_strdup(mem_ctx, nb_cn);
			if (*_computer_name == NULL) {
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}
		}
	}

	switch (creds->secure_channel_type) {
	case SEC_CHAN_NULL:
	case SEC_CHAN_LOCAL:
	case SEC_CHAN_LANMAN:
		TALLOC_FREE(frame);
		return NT_STATUS_NOT_SUPPORTED;

	case SEC_CHAN_WKSTA:
		status = NTLMv2_RESPONSE_verify_workstation(account_name,
							    account_domain,
							    &v2_resp,
							    creds,
							    workgroup);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}

		TALLOC_FREE(frame);
		return NT_STATUS_OK;

	case SEC_CHAN_DNS_DOMAIN:
	case SEC_CHAN_DOMAIN:
		status = NTLMv2_RESPONSE_verify_trust(account_name,
						      account_domain,
						      &v2_resp,
						      creds,
						      num_domains,
						      domains);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}

		TALLOC_FREE(frame);
		return NT_STATUS_OK;

	case SEC_CHAN_BDC:
		/* nothing to check */
		break;

	case SEC_CHAN_RODC:
		/*
		 * TODO:
		 * MS-NRPC 3.5.4.5.1.2 RODC server cachability validation
		 */
		break;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

enum encode_order {
	ENCODE_ORDER_PASSWORD_FIRST,
	ENCODE_ORDER_PASSWORD_LAST,
};

#define PASSWORD_BUFFER_LEN 512

static ssize_t _encode_pwd_buffer_from_str(uint8_t buf[PASSWORD_BUFFER_LEN],
					   const char *password,
					   int string_flags,
					   enum encode_order order)
{
	ssize_t new_pw_len;
	size_t pw_pos = 0;
	size_t random_pos = 0;
	size_t random_len = 0;

	/* The incoming buffer can be any alignment. */
	string_flags |= STR_NOALIGN;

	new_pw_len = push_string(buf,
				 password,
				 PASSWORD_BUFFER_LEN,
				 string_flags);
	if (new_pw_len < 0) {
		BURN_DATA_SIZE(buf, PASSWORD_BUFFER_LEN);
		return -1;
	}

	if (new_pw_len == PASSWORD_BUFFER_LEN) {
		return new_pw_len;
	}

	switch (order) {
	case ENCODE_ORDER_PASSWORD_FIRST:
		pw_pos = 0;
		random_pos = new_pw_len;
		random_len = PASSWORD_BUFFER_LEN - random_pos;
		break;
	case ENCODE_ORDER_PASSWORD_LAST:
		pw_pos = PASSWORD_BUFFER_LEN - new_pw_len;
		random_pos = 0;
		random_len = pw_pos;
		memmove(buf + pw_pos, buf, new_pw_len);
		break;
	}

	generate_random_buffer(buf + random_pos, random_len);

	return new_pw_len;
}

/***********************************************************
 encode a password buffer with a unicode password.  The buffer
 is filled with random data to make it harder to attack.
************************************************************/
bool encode_pw_buffer(uint8_t buffer[516], const char *password, int string_flags)
{
	ssize_t pw_len;

	pw_len = _encode_pwd_buffer_from_str(buffer,
					     password,
					     string_flags,
					     ENCODE_ORDER_PASSWORD_LAST);
	if (pw_len < 0 || pw_len > PASSWORD_BUFFER_LEN) {
		return false;
	}

	PUSH_LE_U32(buffer, PASSWORD_BUFFER_LEN, pw_len);

	return true;
}


/***********************************************************
 decode a password buffer
 *new_pw_len is the length in bytes of the possibly mulitbyte
 returned password including termination.
************************************************************/

bool decode_pw_buffer(TALLOC_CTX *ctx,
		      uint8_t in_buffer[516],
		      char **pp_new_pwrd,
		      size_t *new_pw_len,
		      charset_t string_charset)
{
	DATA_BLOB new_password;
	int byte_len=0;
	bool ok;

	*pp_new_pwrd = NULL;
	*new_pw_len = 0;

	ok = extract_pw_from_buffer(ctx, in_buffer, &new_password);
	if (!ok) {
		return false;
	}

	/*
	  Warning !!! : This function is called from some rpc call.
	  The password IN the buffer may be a UNICODE string.
	  The password IN new_pwrd is an ASCII string
	  If you reuse that code somewhere else check first.
	*/

	/* decode into the return buffer. */
	ok = convert_string_talloc(ctx,
				   string_charset,
				   CH_UNIX,
				   new_password.data,
				   new_password.length,
				   pp_new_pwrd,
				   new_pw_len);
	data_blob_free(&new_password);
	if (!ok) {
		DBG_ERR("Failed to convert incoming password\n");
		return false;
	}
	talloc_keep_secret(*pp_new_pwrd);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("decode_pw_buffer: new_pwrd: "));
	dump_data(100, (uint8_t *)*pp_new_pwrd, *new_pw_len);
	DEBUG(100,("multibyte len:%lu\n", (unsigned long int)*new_pw_len));
	DEBUG(100,("original char len:%d\n", byte_len/2));
#endif

	return true;
}

#define MAX_PASSWORD_LEN 256

/*
 * [MS-SAMR] 2.2.6.32 This creates the buffer to be sent. It is of type
 * SAMPR_USER_PASSWORD_AES.
 */
bool encode_pwd_buffer514_from_str(uint8_t buffer[514],
				   const char *password,
				   uint32_t string_flags)
{
	ssize_t pw_len;

	pw_len = _encode_pwd_buffer_from_str(buffer + 2,
					     password,
					     string_flags,
					     ENCODE_ORDER_PASSWORD_FIRST);
	if (pw_len < 0) {
		return false;
	}

	PUSH_LE_U16(buffer, 0, pw_len);

	return true;
}

bool extract_pwd_blob_from_buffer514(TALLOC_CTX *mem_ctx,
				     const uint8_t in_buffer[514],
				     DATA_BLOB *new_password)
{
#ifdef DEBUG_PASSWORD
	DEBUG(100, ("in_buffer: "));
	dump_data(100, in_buffer, 514);
#endif

	new_password->length = PULL_LE_U16(in_buffer, 0);
	if (new_password->length == 0 || new_password->length > 512) {
		return false;
	}

	new_password->data =
		talloc_memdup(mem_ctx, in_buffer + 2, new_password->length);
	if (new_password->data == NULL) {
		return false;
	}
	talloc_keep_secret(new_password->data);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("new_pwd_len: %zu\n", new_password->length));
	DEBUG(100, ("new_pwd: "));
	dump_data(100, new_password->data, new_password->length);
#endif

	return true;
}

bool decode_pwd_string_from_buffer514(TALLOC_CTX *mem_ctx,
				      const uint8_t in_buffer[514],
				      charset_t string_charset,
				      DATA_BLOB *decoded_password)
{
	DATA_BLOB new_password = {
		.length = 0,
	};
	bool ok;

	ok = extract_pwd_blob_from_buffer514(mem_ctx, in_buffer, &new_password);
	if (!ok) {
		return false;
	}

	ok = convert_string_talloc(mem_ctx,
				   string_charset,
				   CH_UNIX,
				   new_password.data,
				   new_password.length,
				   &decoded_password->data,
				   &decoded_password->length);
	data_blob_free(&new_password);
	if (!ok) {
		return false;
	}
	talloc_keep_secret(decoded_password->data);

	return true;
}

/***********************************************************
 Encode an arc4 password change buffer.
************************************************************/
NTSTATUS encode_rc4_passwd_buffer(const char *passwd,
				  const DATA_BLOB *session_key,
				  struct samr_CryptPasswordEx *out_crypt_pwd)
{
	uint8_t _confounder[16] = {0};
	DATA_BLOB confounder = data_blob_const(_confounder, 16);
	DATA_BLOB pw_data = data_blob_const(out_crypt_pwd->data, 516);
	bool ok;
	int rc;

	ok = encode_pw_buffer(pw_data.data, passwd, STR_UNICODE);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	generate_random_buffer(confounder.data, confounder.length);

	rc = samba_gnutls_arcfour_confounded_md5(&confounder,
						 session_key,
						 &pw_data,
						 SAMBA_GNUTLS_ENCRYPT);
	if (rc < 0) {
		ZERO_ARRAY(_confounder);
		data_blob_clear(&pw_data);
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}

	/*
	 * The packet format is the 516 byte RC4 encrypted
	 * password followed by the 16 byte confounder
	 * The confounder is a salt to prevent pre-computed hash attacks on the
	 * database.
	 */
	memcpy(&out_crypt_pwd->data[516], confounder.data, confounder.length);
	ZERO_ARRAY(_confounder);

	return NT_STATUS_OK;
}

/***********************************************************
 Decode an arc4 encrypted password change buffer.
************************************************************/

NTSTATUS decode_rc4_passwd_buffer(const DATA_BLOB *psession_key,
				  struct samr_CryptPasswordEx *inout_crypt_pwd)
{
	/* Confounder is last 16 bytes. */
	DATA_BLOB confounder = data_blob_const(&inout_crypt_pwd->data[516], 16);
	DATA_BLOB pw_data = data_blob_const(&inout_crypt_pwd->data, 516);
	int rc;

	rc = samba_gnutls_arcfour_confounded_md5(&confounder,
						 psession_key,
						 &pw_data,
						 SAMBA_GNUTLS_DECRYPT);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}

	return NT_STATUS_OK;
}

/***********************************************************
 encode a password buffer with an already unicode password.  The
 rest of the buffer is filled with random data to make it harder to attack.
************************************************************/

static bool create_pw_buffer_from_blob(uint8_t buffer[512],
				       const DATA_BLOB *in_password,
				       enum encode_order order)
{
	size_t pwd_pos = 0;
	size_t random_pos = 0;
	size_t random_len = 0;

	if (in_password->length > 512) {
		return false;
	}

	switch (order) {
	case ENCODE_ORDER_PASSWORD_FIRST:
		pwd_pos = 0;
		random_pos = in_password->length;
		break;
	case ENCODE_ORDER_PASSWORD_LAST:
		pwd_pos = PASSWORD_BUFFER_LEN - in_password->length;
		random_pos = 0;
		break;
	}
	random_len = PASSWORD_BUFFER_LEN - in_password->length;

	memcpy(buffer + pwd_pos, in_password->data, in_password->length);
	generate_random_buffer(buffer + random_pos, random_len);

	return true;
}

bool set_pw_in_buffer(uint8_t buffer[516], const DATA_BLOB *password)
{
	bool ok;

	ok = create_pw_buffer_from_blob(buffer,
					password,
					ENCODE_ORDER_PASSWORD_LAST);
	if (!ok) {
		return false;
	}

	/*
	 * The length of the new password is in the last 4 bytes of
	 * the data buffer.
	 */
	PUSH_LE_U32(buffer, PASSWORD_BUFFER_LEN, password->length);

	return true;
}

/***********************************************************
 decode a password buffer
 *new_pw_size is the length in bytes of the extracted unicode password
************************************************************/
bool extract_pw_from_buffer(TALLOC_CTX *mem_ctx,
			    uint8_t in_buffer[516], DATA_BLOB *new_pass)
{
	int byte_len=0;

	/* The length of the new password is in the last 4 bytes of the data buffer. */

	byte_len = IVAL(in_buffer, 512);

#ifdef DEBUG_PASSWORD
	dump_data(100, in_buffer, 516);
#endif

	/* Password cannot be longer than the size of the password buffer */
	if ( (byte_len < 0) || (byte_len > 512)) {
		return false;
	}

	*new_pass = data_blob_talloc(mem_ctx, &in_buffer[512 - byte_len], byte_len);

	if (!new_pass->data) {
		return false;
	}
	talloc_keep_secret(new_pass->data);

	return true;
}


/* encode a wkssvc_PasswordBuffer:
 *
 * similar to samr_CryptPasswordEx. Different: 8byte confounder (instead of
 * 16byte), confounder in front of the 516 byte buffer (instead of after that
 * buffer), calling MD5Update() first with session_key and then with confounder
 * (vice versa in samr) - Guenther */

WERROR encode_wkssvc_join_password_buffer(TALLOC_CTX *mem_ctx,
					  const char *pwd,
					  DATA_BLOB *session_key,
					  struct wkssvc_PasswordBuffer **out_pwd_buf)
{
	struct wkssvc_PasswordBuffer *pwd_buf = NULL;
	uint8_t _confounder[8] = {0};
	DATA_BLOB confounder = data_blob_const(_confounder, 8);
	uint8_t pwbuf[516] = {0};
	DATA_BLOB encrypt_pwbuf = data_blob_const(pwbuf, 516);
	int rc;

	pwd_buf = talloc_zero(mem_ctx, struct wkssvc_PasswordBuffer);
	if (pwd_buf == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	encode_pw_buffer(pwbuf, pwd, STR_UNICODE);

	generate_random_buffer(_confounder, sizeof(_confounder));

	rc = samba_gnutls_arcfour_confounded_md5(session_key,
						 &confounder,
						 &encrypt_pwbuf,
						 SAMBA_GNUTLS_ENCRYPT);
	if (rc < 0) {
		ZERO_ARRAY(_confounder);
		TALLOC_FREE(pwd_buf);
		return gnutls_error_to_werror(rc, WERR_CONTENT_BLOCKED);
	}

	memcpy(&pwd_buf->data[0], confounder.data, confounder.length);
	ZERO_ARRAY(_confounder);
	memcpy(&pwd_buf->data[8], encrypt_pwbuf.data, encrypt_pwbuf.length);
	ZERO_ARRAY(pwbuf);

	*out_pwd_buf = pwd_buf;

	return WERR_OK;
}

WERROR decode_wkssvc_join_password_buffer(TALLOC_CTX *mem_ctx,
					  struct wkssvc_PasswordBuffer *pwd_buf,
					  DATA_BLOB *session_key,
					  char **pwd)
{
	uint8_t _confounder[8] = { 0 };
	DATA_BLOB confounder = data_blob_const(_confounder, 8);
	uint8_t pwbuf[516] = {0};
	DATA_BLOB decrypt_pwbuf = data_blob_const(pwbuf, 516);
	bool ok;
	int rc;

	if (pwd_buf == NULL) {
		return WERR_INVALID_PASSWORD;
	}

	*pwd = NULL;

	if (session_key->length != 16) {
		DEBUG(10,("invalid session key\n"));
		return WERR_INVALID_PASSWORD;
	}

	confounder = data_blob_const(&pwd_buf->data[0], 8);
	memcpy(&pwbuf, &pwd_buf->data[8], 516);

	rc = samba_gnutls_arcfour_confounded_md5(session_key,
						 &confounder,
						 &decrypt_pwbuf,
						 SAMBA_GNUTLS_ENCRYPT);
	if (rc < 0) {
		ZERO_ARRAY(_confounder);
		TALLOC_FREE(pwd_buf);
		return gnutls_error_to_werror(rc, WERR_CONTENT_BLOCKED);
	}

	ok = decode_pw_buffer(mem_ctx,
			      decrypt_pwbuf.data,
			      pwd,
			      &decrypt_pwbuf.length,
			      CH_UTF16);
	ZERO_ARRAY(pwbuf);

	if (!ok) {
		return WERR_INVALID_PASSWORD;
	}

	return WERR_OK;
}
