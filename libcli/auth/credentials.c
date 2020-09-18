/*
   Unix SMB/CIFS implementation.

   code to manipulate domain credentials

   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004

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
#include "libcli/auth/libcli_auth.h"
#include "../libcli/security/dom_sid.h"
#include "lib/util/util_str_escape.h"

#ifndef HAVE_GNUTLS_AES_CFB8
#include "lib/crypto/aes.h"
#endif

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

bool netlogon_creds_is_random_challenge(const struct netr_Credential *challenge)
{
	/*
	 * If none of the first 5 bytes of the client challenge is unique, the
	 * server MUST fail session-key negotiation without further processing
	 * of the following steps.
	 */

	if (challenge->data[1] == challenge->data[0] &&
	    challenge->data[2] == challenge->data[0] &&
	    challenge->data[3] == challenge->data[0] &&
	    challenge->data[4] == challenge->data[0])
	{
		return false;
	}

	return true;
}

void netlogon_creds_random_challenge(struct netr_Credential *challenge)
{
	ZERO_STRUCTP(challenge);
	while (!netlogon_creds_is_random_challenge(challenge)) {
		generate_random_buffer(challenge->data, sizeof(challenge->data));
	}
}

static NTSTATUS netlogon_creds_step_crypt(struct netlogon_creds_CredentialState *creds,
					  const struct netr_Credential *in,
					  struct netr_Credential *out)
{
	NTSTATUS status;
	int rc;

	if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		memcpy(out->data, in->data, sizeof(out->data));

		status = netlogon_creds_aes_encrypt(creds,
						    out->data,
						    sizeof(out->data));
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		rc = des_crypt112(out->data, in->data, creds->session_key, SAMBA_GNUTLS_ENCRYPT);
		if (rc != 0) {
			return gnutls_error_to_ntstatus(rc,
							NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		}
	}

	return NT_STATUS_OK;
}

/*
  initialise the credentials state for old-style 64 bit session keys

  this call is made after the netr_ServerReqChallenge call
*/
static NTSTATUS netlogon_creds_init_64bit(struct netlogon_creds_CredentialState *creds,
					 const struct netr_Credential *client_challenge,
					 const struct netr_Credential *server_challenge,
					 const struct samr_Password *machine_password)
{
	uint32_t sum[2];
	uint8_t sum2[8];
	int rc;

	sum[0] = IVAL(client_challenge->data, 0) + IVAL(server_challenge->data, 0);
	sum[1] = IVAL(client_challenge->data, 4) + IVAL(server_challenge->data, 4);

	SIVAL(sum2,0,sum[0]);
	SIVAL(sum2,4,sum[1]);

	ZERO_ARRAY(creds->session_key);

	rc = des_crypt128(creds->session_key, sum2, machine_password->hash);
	if (rc != 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}

	return NT_STATUS_OK;
}

/*
  initialise the credentials state for ADS-style 128 bit session keys

  this call is made after the netr_ServerReqChallenge call
*/
static NTSTATUS netlogon_creds_init_128bit(struct netlogon_creds_CredentialState *creds,
				       const struct netr_Credential *client_challenge,
				       const struct netr_Credential *server_challenge,
				       const struct samr_Password *machine_password)
{
	uint8_t zero[4] = {0};
	uint8_t tmp[gnutls_hash_get_len(GNUTLS_MAC_MD5)];
	gnutls_hash_hd_t hash_hnd = NULL;
	int rc;

	ZERO_ARRAY(creds->session_key);

	rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_MD5);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
	}

	rc = gnutls_hash(hash_hnd, zero, sizeof(zero));
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
	}
	rc = gnutls_hash(hash_hnd, client_challenge->data, 8);
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
	}
	rc = gnutls_hash(hash_hnd, server_challenge->data, 8);
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
	}

	gnutls_hash_deinit(hash_hnd, tmp);

	/* This doesn't require HMAC MD5 RFC2104 as the hash is only 16 bytes */
	rc = gnutls_hmac_fast(GNUTLS_MAC_MD5,
			      machine_password->hash,
			      sizeof(machine_password->hash),
			      tmp,
			      sizeof(tmp),
			      creds->session_key);
	ZERO_ARRAY(tmp);

	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
	}

	return NT_STATUS_OK;
}

/*
  initialise the credentials state for AES/HMAC-SHA256-style 128 bit session keys

  this call is made after the netr_ServerReqChallenge call
*/
static NTSTATUS netlogon_creds_init_hmac_sha256(struct netlogon_creds_CredentialState *creds,
						const struct netr_Credential *client_challenge,
						const struct netr_Credential *server_challenge,
						const struct samr_Password *machine_password)
{
	gnutls_hmac_hd_t hmac_hnd = NULL;
	uint8_t digest[gnutls_hash_get_len(GNUTLS_MAC_SHA256)];
	int rc;

	ZERO_ARRAY(creds->session_key);

	rc = gnutls_hmac_init(&hmac_hnd,
			      GNUTLS_MAC_SHA256,
			      machine_password->hash,
			      sizeof(machine_password->hash));
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	rc = gnutls_hmac(hmac_hnd,
			 client_challenge->data,
			 8);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	rc  = gnutls_hmac(hmac_hnd,
			  server_challenge->data,
			  8);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	gnutls_hmac_deinit(hmac_hnd, digest);

	memcpy(creds->session_key, digest, sizeof(creds->session_key));

	ZERO_ARRAY(digest);

	return NT_STATUS_OK;
}

static NTSTATUS netlogon_creds_first_step(struct netlogon_creds_CredentialState *creds,
					  const struct netr_Credential *client_challenge,
					  const struct netr_Credential *server_challenge)
{
	NTSTATUS status;

	status = netlogon_creds_step_crypt(creds,
					   client_challenge,
					   &creds->client);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = netlogon_creds_step_crypt(creds,
					   server_challenge,
					   &creds->server);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	creds->seed = creds->client;

	return NT_STATUS_OK;
}

/*
  step the credentials to the next element in the chain, updating the
  current client and server credentials and the seed
*/
static NTSTATUS netlogon_creds_step(struct netlogon_creds_CredentialState *creds)
{
	struct netr_Credential time_cred;
	NTSTATUS status;

	DEBUG(5,("\tseed        %08x:%08x\n",
		 IVAL(creds->seed.data, 0), IVAL(creds->seed.data, 4)));

	SIVAL(time_cred.data, 0, IVAL(creds->seed.data, 0) + creds->sequence);
	SIVAL(time_cred.data, 4, IVAL(creds->seed.data, 4));

	DEBUG(5,("\tseed+time   %08x:%08x\n", IVAL(time_cred.data, 0), IVAL(time_cred.data, 4)));

	status = netlogon_creds_step_crypt(creds,
					   &time_cred,
					   &creds->client);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(5,("\tCLIENT      %08x:%08x\n",
		 IVAL(creds->client.data, 0), IVAL(creds->client.data, 4)));

	SIVAL(time_cred.data, 0, IVAL(creds->seed.data, 0) + creds->sequence + 1);
	SIVAL(time_cred.data, 4, IVAL(creds->seed.data, 4));

	DEBUG(5,("\tseed+time+1 %08x:%08x\n",
		 IVAL(time_cred.data, 0), IVAL(time_cred.data, 4)));

	status = netlogon_creds_step_crypt(creds, &time_cred, &creds->server);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(5,("\tSERVER      %08x:%08x\n",
		 IVAL(creds->server.data, 0), IVAL(creds->server.data, 4)));

	creds->seed = time_cred;

	return NT_STATUS_OK;
}

/*
  DES encrypt a 8 byte LMSessionKey buffer using the Netlogon session key
*/
NTSTATUS netlogon_creds_des_encrypt_LMKey(struct netlogon_creds_CredentialState *creds,
					  struct netr_LMSessionKey *key)
{
	int rc;
	struct netr_LMSessionKey tmp;

	rc = des_crypt56_gnutls(tmp.key, key->key, creds->session_key, SAMBA_GNUTLS_ENCRYPT);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}
	*key = tmp;

	return NT_STATUS_OK;
}

/*
  DES decrypt a 8 byte LMSessionKey buffer using the Netlogon session key
*/
NTSTATUS netlogon_creds_des_decrypt_LMKey(struct netlogon_creds_CredentialState *creds,
					  struct netr_LMSessionKey *key)
{
	int rc;
	struct netr_LMSessionKey tmp;

	rc = des_crypt56_gnutls(tmp.key, key->key, creds->session_key, SAMBA_GNUTLS_DECRYPT);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}
	*key = tmp;

	return NT_STATUS_OK;
}

/*
  DES encrypt a 16 byte password buffer using the session key
*/
NTSTATUS netlogon_creds_des_encrypt(struct netlogon_creds_CredentialState *creds,
				    struct samr_Password *pass)
{
	struct samr_Password tmp;
	int rc;

	rc = des_crypt112_16(tmp.hash, pass->hash, creds->session_key, SAMBA_GNUTLS_ENCRYPT);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}
	*pass = tmp;

	return NT_STATUS_OK;
}

/*
  DES decrypt a 16 byte password buffer using the session key
*/
NTSTATUS netlogon_creds_des_decrypt(struct netlogon_creds_CredentialState *creds,
				    struct samr_Password *pass)
{
	struct samr_Password tmp;
	int rc;

	rc = des_crypt112_16(tmp.hash, pass->hash, creds->session_key, SAMBA_GNUTLS_DECRYPT);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}
	*pass = tmp;

	return NT_STATUS_OK;
}

/*
  ARCFOUR encrypt/decrypt a password buffer using the session key
*/
NTSTATUS netlogon_creds_arcfour_crypt(struct netlogon_creds_CredentialState *creds,
				      uint8_t *data,
				      size_t len)
{
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t session_key = {
		.data = creds->session_key,
		.size = sizeof(creds->session_key),
	};
	int rc;

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&session_key,
				NULL);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}
	rc = gnutls_cipher_encrypt(cipher_hnd,
				   data,
				   len);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	return NT_STATUS_OK;
}

/*
  AES encrypt a password buffer using the session key
*/
NTSTATUS netlogon_creds_aes_encrypt(struct netlogon_creds_CredentialState *creds,
				    uint8_t *data,
				    size_t len)
{
#ifdef HAVE_GNUTLS_AES_CFB8
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t key = {
		.data = creds->session_key,
		.size = sizeof(creds->session_key),
	};
	uint32_t iv_size =
		gnutls_cipher_get_iv_size(GNUTLS_CIPHER_AES_128_CFB8);
	uint8_t _iv[iv_size];
	gnutls_datum_t iv = {
		.data = _iv,
		.size = iv_size,
	};
	int rc;

	ZERO_ARRAY(_iv);

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_AES_128_CFB8,
				&key,
				&iv);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	rc = gnutls_cipher_encrypt(cipher_hnd, data, len);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

#else /* NOT HAVE_GNUTLS_AES_CFB8 */
	AES_KEY key;
	uint8_t iv[AES_BLOCK_SIZE] = {0};

	AES_set_encrypt_key(creds->session_key, 128, &key);

	aes_cfb8_encrypt(data, data, len, &key, iv, AES_ENCRYPT);
#endif /* HAVE_GNUTLS_AES_CFB8 */

	return NT_STATUS_OK;
}

/*
  AES decrypt a password buffer using the session key
*/
NTSTATUS netlogon_creds_aes_decrypt(struct netlogon_creds_CredentialState *creds, uint8_t *data, size_t len)
{
#ifdef HAVE_GNUTLS_AES_CFB8
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t key = {
		.data = creds->session_key,
		.size = sizeof(creds->session_key),
	};
	uint32_t iv_size =
		gnutls_cipher_get_iv_size(GNUTLS_CIPHER_AES_128_CFB8);
	uint8_t _iv[iv_size];
	gnutls_datum_t iv = {
		.data = _iv,
		.size = iv_size,
	};
	int rc;

	ZERO_ARRAY(_iv);

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_AES_128_CFB8,
				&key,
				&iv);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	rc = gnutls_cipher_decrypt(cipher_hnd, data, len);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

#else /* NOT HAVE_GNUTLS_AES_CFB8 */
	AES_KEY key;
	uint8_t iv[AES_BLOCK_SIZE] = {0};

	AES_set_encrypt_key(creds->session_key, 128, &key);

	aes_cfb8_encrypt(data, data, len, &key, iv, AES_DECRYPT);
#endif /* HAVE_GNUTLS_AES_CFB8 */

	return NT_STATUS_OK;
}

/*****************************************************************
The above functions are common to the client and server interface
next comes the client specific functions
******************************************************************/

/*
  initialise the credentials chain and return the first client
  credentials
*/

struct netlogon_creds_CredentialState *netlogon_creds_client_init(TALLOC_CTX *mem_ctx,
								  const char *client_account,
								  const char *client_computer_name,
								  uint16_t secure_channel_type,
								  const struct netr_Credential *client_challenge,
								  const struct netr_Credential *server_challenge,
								  const struct samr_Password *machine_password,
								  struct netr_Credential *initial_credential,
								  uint32_t negotiate_flags)
{
	struct netlogon_creds_CredentialState *creds = talloc_zero(mem_ctx, struct netlogon_creds_CredentialState);
	NTSTATUS status;

	if (!creds) {
		return NULL;
	}

	creds->sequence = time(NULL);
	creds->negotiate_flags = negotiate_flags;
	creds->secure_channel_type = secure_channel_type;

	creds->computer_name = talloc_strdup(creds, client_computer_name);
	if (!creds->computer_name) {
		talloc_free(creds);
		return NULL;
	}
	creds->account_name = talloc_strdup(creds, client_account);
	if (!creds->account_name) {
		talloc_free(creds);
		return NULL;
	}

	dump_data_pw("Client chall", client_challenge->data, sizeof(client_challenge->data));
	dump_data_pw("Server chall", server_challenge->data, sizeof(server_challenge->data));
	dump_data_pw("Machine Pass", machine_password->hash, sizeof(machine_password->hash));

	if (negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		status = netlogon_creds_init_hmac_sha256(creds,
							 client_challenge,
							 server_challenge,
							 machine_password);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(creds);
			return NULL;
		}
	} else if (negotiate_flags & NETLOGON_NEG_STRONG_KEYS) {
		status = netlogon_creds_init_128bit(creds,
						    client_challenge,
						    server_challenge,
						    machine_password);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(creds);
			return NULL;
		}
	} else {
		status = netlogon_creds_init_64bit(creds,
						   client_challenge,
						   server_challenge,
						   machine_password);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(creds);
			return NULL;
		}
	}

	status = netlogon_creds_first_step(creds,
					   client_challenge,
					   server_challenge);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(creds);
		return NULL;
	}

	dump_data_pw("Session key", creds->session_key, 16);
	dump_data_pw("Credential ", creds->client.data, 8);

	*initial_credential = creds->client;
	return creds;
}

/*
  initialise the credentials structure with only a session key.  The caller better know what they are doing!
 */

struct netlogon_creds_CredentialState *netlogon_creds_client_init_session_key(TALLOC_CTX *mem_ctx,
									      const uint8_t session_key[16])
{
	struct netlogon_creds_CredentialState *creds;

	creds = talloc_zero(mem_ctx, struct netlogon_creds_CredentialState);
	if (!creds) {
		return NULL;
	}

	memcpy(creds->session_key, session_key, 16);

	return creds;
}

/*
  step the credentials to the next element in the chain, updating the
  current client and server credentials and the seed

  produce the next authenticator in the sequence ready to send to
  the server
*/
NTSTATUS
netlogon_creds_client_authenticator(struct netlogon_creds_CredentialState *creds,
				    struct netr_Authenticator *next)
{
	uint32_t t32n = (uint32_t)time(NULL);
	NTSTATUS status;

	/*
	 * we always increment and ignore an overflow here
	 */
	creds->sequence += 2;

	if (t32n > creds->sequence) {
		/*
		 * we may increment more
		 */
		creds->sequence = t32n;
	} else {
		uint32_t d = creds->sequence - t32n;

		if (d >= INT32_MAX) {
			/*
			 * got an overflow of time_t vs. uint32_t
			 */
			creds->sequence = t32n;
		}
	}

	status = netlogon_creds_step(creds);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	next->cred = creds->client;
	next->timestamp = creds->sequence;

	return NT_STATUS_OK;
}

/*
  check that a credentials reply from a server is correct
*/
bool netlogon_creds_client_check(struct netlogon_creds_CredentialState *creds,
			const struct netr_Credential *received_credentials)
{
	if (!received_credentials ||
	    memcmp(received_credentials->data, creds->server.data, 8) != 0) {
		DEBUG(2,("credentials check failed\n"));
		return false;
	}
	return true;
}


/*****************************************************************
The above functions are common to the client and server interface
next comes the server specific functions
******************************************************************/

/*
  check that a credentials reply from a server is correct
*/
static bool netlogon_creds_server_check_internal(const struct netlogon_creds_CredentialState *creds,
						 const struct netr_Credential *received_credentials)
{
	if (memcmp(received_credentials->data, creds->client.data, 8) != 0) {
		DEBUG(2,("credentials check failed\n"));
		dump_data_pw("client creds", creds->client.data, 8);
		dump_data_pw("calc   creds", received_credentials->data, 8);
		return false;
	}
	return true;
}

/*
  initialise the credentials chain and return the first server
  credentials
*/
struct netlogon_creds_CredentialState *netlogon_creds_server_init(TALLOC_CTX *mem_ctx,
								  const char *client_account,
								  const char *client_computer_name,
								  uint16_t secure_channel_type,
								  const struct netr_Credential *client_challenge,
								  const struct netr_Credential *server_challenge,
								  const struct samr_Password *machine_password,
								  const struct netr_Credential *credentials_in,
								  struct netr_Credential *credentials_out,
								  uint32_t negotiate_flags)
{

	struct netlogon_creds_CredentialState *creds = talloc_zero(mem_ctx, struct netlogon_creds_CredentialState);
	NTSTATUS status;
	bool ok;

	if (!creds) {
		return NULL;
	}

	creds->negotiate_flags = negotiate_flags;
	creds->secure_channel_type = secure_channel_type;

	dump_data_pw("Client chall", client_challenge->data, sizeof(client_challenge->data));
	dump_data_pw("Server chall", server_challenge->data, sizeof(server_challenge->data));
	dump_data_pw("Machine Pass", machine_password->hash, sizeof(machine_password->hash));

	ok = netlogon_creds_is_random_challenge(client_challenge);
	if (!ok) {
		DBG_WARNING("CVE-2020-1472(ZeroLogon): "
			    "non-random client challenge rejected for "
			    "client_account[%s] client_computer_name[%s]\n",
			    log_escape(mem_ctx, client_account),
			    log_escape(mem_ctx, client_computer_name));
		dump_data(DBGLVL_WARNING,
			  client_challenge->data,
			  sizeof(client_challenge->data));
		talloc_free(creds);
		return NULL;
	}

	creds->computer_name = talloc_strdup(creds, client_computer_name);
	if (!creds->computer_name) {
		talloc_free(creds);
		return NULL;
	}
	creds->account_name = talloc_strdup(creds, client_account);
	if (!creds->account_name) {
		talloc_free(creds);
		return NULL;
	}

	if (negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		status = netlogon_creds_init_hmac_sha256(creds,
							 client_challenge,
							 server_challenge,
							 machine_password);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(creds);
			return NULL;
		}
	} else if (negotiate_flags & NETLOGON_NEG_STRONG_KEYS) {
		status = netlogon_creds_init_128bit(creds,
						    client_challenge,
						    server_challenge,
						    machine_password);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(creds);
			return NULL;
		}
	} else {
		status = netlogon_creds_init_64bit(creds,
						   client_challenge,
						   server_challenge,
						   machine_password);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(creds);
			return NULL;
		}
	}

	status = netlogon_creds_first_step(creds,
					   client_challenge,
					   server_challenge);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(creds);
		return NULL;
	}

	dump_data_pw("Session key", creds->session_key, 16);
	dump_data_pw("Client Credential ", creds->client.data, 8);
	dump_data_pw("Server Credential ", creds->server.data, 8);

	dump_data_pw("Credentials in", credentials_in->data, sizeof(credentials_in->data));

	/* And before we leak information about the machine account
	 * password, check that they got the first go right */
	if (!netlogon_creds_server_check_internal(creds, credentials_in)) {
		talloc_free(creds);
		return NULL;
	}

	*credentials_out = creds->server;

	dump_data_pw("Credentials out", credentials_out->data, sizeof(credentials_out->data));

	return creds;
}

NTSTATUS netlogon_creds_server_step_check(struct netlogon_creds_CredentialState *creds,
				 const struct netr_Authenticator *received_authenticator,
				 struct netr_Authenticator *return_authenticator)
{
	NTSTATUS status;

	if (!received_authenticator || !return_authenticator) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!creds) {
		return NT_STATUS_ACCESS_DENIED;
	}

	creds->sequence = received_authenticator->timestamp;
	status = netlogon_creds_step(creds);
	if (!NT_STATUS_IS_OK(status)) {
		ZERO_STRUCTP(return_authenticator);
		return status;
	}

	if (netlogon_creds_server_check_internal(creds, &received_authenticator->cred)) {
		return_authenticator->cred = creds->server;
		return_authenticator->timestamp = 0;
		return NT_STATUS_OK;
	} else {
		ZERO_STRUCTP(return_authenticator);
		return NT_STATUS_ACCESS_DENIED;
	}
}

static NTSTATUS netlogon_creds_crypt_samlogon_validation(struct netlogon_creds_CredentialState *creds,
							 uint16_t validation_level,
							 union netr_Validation *validation,
							 bool do_encrypt)
{
	struct netr_SamBaseInfo *base = NULL;
	NTSTATUS status;

	if (validation == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (validation_level) {
	case 2:
		if (validation->sam2) {
			base = &validation->sam2->base;
		}
		break;
	case 3:
		if (validation->sam3) {
			base = &validation->sam3->base;
		}
		break;
	case 6:
		if (validation->sam6) {
			base = &validation->sam6->base;
		}
		break;
	default:
		/* If we can't find it, we can't very well decrypt it */
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	if (!base) {
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* find and decyrpt the session keys, return in parameters above */
	if (validation_level == 6) {
		/* they aren't encrypted! */
	} else if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		/* Don't crypt an all-zero key, it would give away the NETLOGON pipe session key */
		if (!all_zero(base->key.key, sizeof(base->key.key))) {
			if (do_encrypt) {
				status = netlogon_creds_aes_encrypt(
					creds,
					base->key.key,
					sizeof(base->key.key));
			} else {
				status = netlogon_creds_aes_decrypt(
					creds,
					base->key.key,
					sizeof(base->key.key));
			}
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}

		if (!all_zero(base->LMSessKey.key,
			      sizeof(base->LMSessKey.key))) {
			if (do_encrypt) {
				status = netlogon_creds_aes_encrypt(
					creds,
					base->LMSessKey.key,
					sizeof(base->LMSessKey.key));
			} else {
				status = netlogon_creds_aes_decrypt(
					creds,
					base->LMSessKey.key,
					sizeof(base->LMSessKey.key));
			}
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	} else if (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
		/* Don't crypt an all-zero key, it would give away the NETLOGON pipe session key */
		if (!all_zero(base->key.key, sizeof(base->key.key))) {
			status = netlogon_creds_arcfour_crypt(creds,
							      base->key.key,
							      sizeof(base->key.key));
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}

		if (!all_zero(base->LMSessKey.key,
			      sizeof(base->LMSessKey.key))) {
			status = netlogon_creds_arcfour_crypt(creds,
							      base->LMSessKey.key,
							      sizeof(base->LMSessKey.key));
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	} else {
		/* Don't crypt an all-zero key, it would give away the NETLOGON pipe session key */
		if (!all_zero(base->LMSessKey.key,
			      sizeof(base->LMSessKey.key))) {
			if (do_encrypt) {
				status = netlogon_creds_des_encrypt_LMKey(creds,
									  &base->LMSessKey);
			} else {
				status = netlogon_creds_des_decrypt_LMKey(creds,
									  &base->LMSessKey);
			}
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}

	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_decrypt_samlogon_validation(struct netlogon_creds_CredentialState *creds,
						    uint16_t validation_level,
						    union netr_Validation *validation)
{
	return netlogon_creds_crypt_samlogon_validation(creds,
							validation_level,
							validation,
							false);
}

NTSTATUS netlogon_creds_encrypt_samlogon_validation(struct netlogon_creds_CredentialState *creds,
						    uint16_t validation_level,
						    union netr_Validation *validation)
{
	return netlogon_creds_crypt_samlogon_validation(creds,
							validation_level,
							validation,
							true);
}

static NTSTATUS netlogon_creds_crypt_samlogon_logon(struct netlogon_creds_CredentialState *creds,
						    enum netr_LogonInfoClass level,
						    union netr_LogonLevel *logon,
						    bool do_encrypt)
{
	NTSTATUS status;

	if (logon == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (level) {
	case NetlogonInteractiveInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceInformation:
	case NetlogonServiceTransitiveInformation:
		if (logon->password == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
			uint8_t *h;

			h = logon->password->lmpassword.hash;
			if (!all_zero(h, 16)) {
				if (do_encrypt) {
					status = netlogon_creds_aes_encrypt(
						creds,
						h,
						16);
				} else {
					status = netlogon_creds_aes_decrypt(
						creds,
						h,
						16);
				}
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}

			h = logon->password->ntpassword.hash;
			if (!all_zero(h, 16)) {
				if (do_encrypt) {
					status = netlogon_creds_aes_encrypt(creds,
								   h,
								   16);
				} else {
					status = netlogon_creds_aes_decrypt(creds,
								   h,
								   16);
				}
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}
		} else if (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
			uint8_t *h;

			h = logon->password->lmpassword.hash;
			if (!all_zero(h, 16)) {
				status = netlogon_creds_arcfour_crypt(creds,
								      h,
								      16);
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}

			h = logon->password->ntpassword.hash;
			if (!all_zero(h, 16)) {
				status = netlogon_creds_arcfour_crypt(creds,
								      h,
								      16);
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}
		} else {
			struct samr_Password *p;

			p = &logon->password->lmpassword;
			if (!all_zero(p->hash, 16)) {
				if (do_encrypt) {
					status = netlogon_creds_des_encrypt(creds, p);
				} else {
					status = netlogon_creds_des_decrypt(creds, p);
				}
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}
			p = &logon->password->ntpassword;
			if (!all_zero(p->hash, 16)) {
				if (do_encrypt) {
					status = netlogon_creds_des_encrypt(creds, p);
				} else {
					status = netlogon_creds_des_decrypt(creds, p);
				}
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}
		}
		break;

	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		break;

	case NetlogonGenericInformation:
		if (logon->generic == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
			if (do_encrypt) {
				status = netlogon_creds_aes_encrypt(
					creds,
					logon->generic->data,
					logon->generic->length);
			} else {
				status = netlogon_creds_aes_decrypt(
					creds,
					logon->generic->data,
					logon->generic->length);
			}
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		} else if (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
			status = netlogon_creds_arcfour_crypt(creds,
							      logon->generic->data,
							      logon->generic->length);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		} else {
			/* Using DES to verify kerberos tickets makes no sense */
		}
		break;
	}

	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_decrypt_samlogon_logon(struct netlogon_creds_CredentialState *creds,
					       enum netr_LogonInfoClass level,
					       union netr_LogonLevel *logon)
{
	return netlogon_creds_crypt_samlogon_logon(creds, level, logon, false);
}

NTSTATUS netlogon_creds_encrypt_samlogon_logon(struct netlogon_creds_CredentialState *creds,
					       enum netr_LogonInfoClass level,
					       union netr_LogonLevel *logon)
{
	return netlogon_creds_crypt_samlogon_logon(creds, level, logon, true);
}

union netr_LogonLevel *netlogon_creds_shallow_copy_logon(TALLOC_CTX *mem_ctx,
					enum netr_LogonInfoClass level,
					const union netr_LogonLevel *in)
{
	union netr_LogonLevel *out;

	if (in == NULL) {
		return NULL;
	}

	out = talloc(mem_ctx, union netr_LogonLevel);
	if (out == NULL) {
		return NULL;
	}

	*out = *in;

	switch (level) {
	case NetlogonInteractiveInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceInformation:
	case NetlogonServiceTransitiveInformation:
		if (in->password == NULL) {
			return out;
		}

		out->password = talloc(out, struct netr_PasswordInfo);
		if (out->password == NULL) {
			talloc_free(out);
			return NULL;
		}
		*out->password = *in->password;

		return out;

	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		break;

	case NetlogonGenericInformation:
		if (in->generic == NULL) {
			return out;
		}

		out->generic = talloc(out, struct netr_GenericInfo);
		if (out->generic == NULL) {
			talloc_free(out);
			return NULL;
		}
		*out->generic = *in->generic;

		if (in->generic->data == NULL) {
			return out;
		}

		if (in->generic->length == 0) {
			return out;
		}

		out->generic->data = talloc_memdup(out->generic,
						   in->generic->data,
						   in->generic->length);
		if (out->generic->data == NULL) {
			talloc_free(out);
			return NULL;
		}

		return out;
	}

	return out;
}

/*
  copy a netlogon_creds_CredentialState struct
*/

struct netlogon_creds_CredentialState *netlogon_creds_copy(
	TALLOC_CTX *mem_ctx,
	const struct netlogon_creds_CredentialState *creds_in)
{
	struct netlogon_creds_CredentialState *creds = talloc_zero(mem_ctx, struct netlogon_creds_CredentialState);

	if (!creds) {
		return NULL;
	}

	creds->sequence			= creds_in->sequence;
	creds->negotiate_flags		= creds_in->negotiate_flags;
	creds->secure_channel_type	= creds_in->secure_channel_type;

	creds->computer_name = talloc_strdup(creds, creds_in->computer_name);
	if (!creds->computer_name) {
		talloc_free(creds);
		return NULL;
	}
	creds->account_name = talloc_strdup(creds, creds_in->account_name);
	if (!creds->account_name) {
		talloc_free(creds);
		return NULL;
	}

	if (creds_in->sid) {
		creds->sid = dom_sid_dup(creds, creds_in->sid);
		if (!creds->sid) {
			talloc_free(creds);
			return NULL;
		}
	}

	memcpy(creds->session_key, creds_in->session_key, sizeof(creds->session_key));
	memcpy(creds->seed.data, creds_in->seed.data, sizeof(creds->seed.data));
	memcpy(creds->client.data, creds_in->client.data, sizeof(creds->client.data));
	memcpy(creds->server.data, creds_in->server.data, sizeof(creds->server.data));

	return creds;
}
