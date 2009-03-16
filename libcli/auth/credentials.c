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
#include "auth/auth.h"
#include "../lib/crypto/crypto.h"
#include "libcli/auth/libcli_auth.h"

/*
  initialise the credentials state for old-style 64 bit session keys

  this call is made after the netr_ServerReqChallenge call
*/
static void creds_init_64bit(struct creds_CredentialState *creds,
			     const struct netr_Credential *client_challenge,
			     const struct netr_Credential *server_challenge,
			     const struct samr_Password *machine_password)
{
	uint32_t sum[2];
	uint8_t sum2[8];

	sum[0] = IVAL(client_challenge->data, 0) + IVAL(server_challenge->data, 0);
	sum[1] = IVAL(client_challenge->data, 4) + IVAL(server_challenge->data, 4);

	SIVAL(sum2,0,sum[0]);
	SIVAL(sum2,4,sum[1]);

	ZERO_STRUCT(creds->session_key);

	des_crypt128(creds->session_key, sum2, machine_password->hash);

	des_crypt112(creds->client.data, client_challenge->data, creds->session_key, 1);
	des_crypt112(creds->server.data, server_challenge->data, creds->session_key, 1);

	creds->seed = creds->client;
}

/*
  initialise the credentials state for ADS-style 128 bit session keys

  this call is made after the netr_ServerReqChallenge call
*/
static void creds_init_128bit(struct creds_CredentialState *creds,
			      const struct netr_Credential *client_challenge,
			      const struct netr_Credential *server_challenge,
			      const struct samr_Password *machine_password)
{
	unsigned char zero[4], tmp[16];
	HMACMD5Context ctx;
	struct MD5Context md5;

	ZERO_STRUCT(creds->session_key);

	memset(zero, 0, sizeof(zero));

	hmac_md5_init_rfc2104(machine_password->hash, sizeof(machine_password->hash), &ctx);	
	MD5Init(&md5);
	MD5Update(&md5, zero, sizeof(zero));
	MD5Update(&md5, client_challenge->data, 8);
	MD5Update(&md5, server_challenge->data, 8);
	MD5Final(tmp, &md5);
	hmac_md5_update(tmp, sizeof(tmp), &ctx);
	hmac_md5_final(creds->session_key, &ctx);

	creds->client = *client_challenge;
	creds->server = *server_challenge;

	des_crypt112(creds->client.data, client_challenge->data, creds->session_key, 1);
	des_crypt112(creds->server.data, server_challenge->data, creds->session_key, 1);

	creds->seed = creds->client;
}


/*
  step the credentials to the next element in the chain, updating the
  current client and server credentials and the seed
*/
static void creds_step(struct creds_CredentialState *creds)
{
	struct netr_Credential time_cred;

	DEBUG(5,("\tseed        %08x:%08x\n", 
		 IVAL(creds->seed.data, 0), IVAL(creds->seed.data, 4)));

	SIVAL(time_cred.data, 0, IVAL(creds->seed.data, 0) + creds->sequence);
	SIVAL(time_cred.data, 4, IVAL(creds->seed.data, 4));

	DEBUG(5,("\tseed+time   %08x:%08x\n", IVAL(time_cred.data, 0), IVAL(time_cred.data, 4)));

	des_crypt112(creds->client.data, time_cred.data, creds->session_key, 1);

	DEBUG(5,("\tCLIENT      %08x:%08x\n", 
		 IVAL(creds->client.data, 0), IVAL(creds->client.data, 4)));

	SIVAL(time_cred.data, 0, IVAL(creds->seed.data, 0) + creds->sequence + 1);
	SIVAL(time_cred.data, 4, IVAL(creds->seed.data, 4));

	DEBUG(5,("\tseed+time+1 %08x:%08x\n", 
		 IVAL(time_cred.data, 0), IVAL(time_cred.data, 4)));

	des_crypt112(creds->server.data, time_cred.data, creds->session_key, 1);

	DEBUG(5,("\tSERVER      %08x:%08x\n", 
		 IVAL(creds->server.data, 0), IVAL(creds->server.data, 4)));

	creds->seed = time_cred;
}


/*
  DES encrypt a 8 byte LMSessionKey buffer using the Netlogon session key
*/
void creds_des_encrypt_LMKey(struct creds_CredentialState *creds, struct netr_LMSessionKey *key)
{
	struct netr_LMSessionKey tmp;
	des_crypt56(tmp.key, key->key, creds->session_key, 1);
	*key = tmp;
}

/*
  DES decrypt a 8 byte LMSessionKey buffer using the Netlogon session key
*/
void creds_des_decrypt_LMKey(struct creds_CredentialState *creds, struct netr_LMSessionKey *key)
{
	struct netr_LMSessionKey tmp;
	des_crypt56(tmp.key, key->key, creds->session_key, 0);
	*key = tmp;
}

/*
  DES encrypt a 16 byte password buffer using the session key
*/
void creds_des_encrypt(struct creds_CredentialState *creds, struct samr_Password *pass)
{
	struct samr_Password tmp;
	des_crypt112_16(tmp.hash, pass->hash, creds->session_key, 1);
	*pass = tmp;
}

/*
  DES decrypt a 16 byte password buffer using the session key
*/
void creds_des_decrypt(struct creds_CredentialState *creds, struct samr_Password *pass)
{
	struct samr_Password tmp;
	des_crypt112_16(tmp.hash, pass->hash, creds->session_key, 0);
	*pass = tmp;
}

/*
  ARCFOUR encrypt/decrypt a password buffer using the session key
*/
void creds_arcfour_crypt(struct creds_CredentialState *creds, uint8_t *data, size_t len)
{
	DATA_BLOB session_key = data_blob(creds->session_key, 16);

	arcfour_crypt_blob(data, len, &session_key);

	data_blob_free(&session_key);
}

/*****************************************************************
The above functions are common to the client and server interface
next comes the client specific functions
******************************************************************/

/*
  initialise the credentials chain and return the first client
  credentials
*/
void creds_client_init(struct creds_CredentialState *creds,
		       const struct netr_Credential *client_challenge,
		       const struct netr_Credential *server_challenge,
		       const struct samr_Password *machine_password,
		       struct netr_Credential *initial_credential,
		       uint32_t negotiate_flags)
{
	creds->sequence = time(NULL);
	creds->negotiate_flags = negotiate_flags;

	dump_data_pw("Client chall", client_challenge->data, sizeof(client_challenge->data));
	dump_data_pw("Server chall", server_challenge->data, sizeof(server_challenge->data));
	dump_data_pw("Machine Pass", machine_password->hash, sizeof(machine_password->hash));

	if (negotiate_flags & NETLOGON_NEG_128BIT) {
		creds_init_128bit(creds, client_challenge, server_challenge, machine_password);
	} else {
		creds_init_64bit(creds, client_challenge, server_challenge, machine_password);
	}

	dump_data_pw("Session key", creds->session_key, 16);
	dump_data_pw("Credential ", creds->client.data, 8);

	*initial_credential = creds->client;
}

/*
  step the credentials to the next element in the chain, updating the
  current client and server credentials and the seed

  produce the next authenticator in the sequence ready to send to 
  the server
*/
void creds_client_authenticator(struct creds_CredentialState *creds,
				struct netr_Authenticator *next)
{	
	creds->sequence += 2;
	creds_step(creds);

	next->cred = creds->client;
	next->timestamp = creds->sequence;
}

/*
  check that a credentials reply from a server is correct
*/
bool creds_client_check(struct creds_CredentialState *creds,
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
  initialise the credentials chain and return the first server
  credentials
*/
void creds_server_init(struct creds_CredentialState *creds,
		       const struct netr_Credential *client_challenge,
		       const struct netr_Credential *server_challenge,
		       const struct samr_Password *machine_password,
		       struct netr_Credential *initial_credential,
		       uint32_t negotiate_flags)
{
	if (negotiate_flags & NETLOGON_NEG_128BIT) {
		creds_init_128bit(creds, client_challenge, server_challenge, 
				  machine_password);
	} else {
		creds_init_64bit(creds, client_challenge, server_challenge, 
				 machine_password);
	}

	*initial_credential = creds->server;
	creds->negotiate_flags = negotiate_flags;
}

/*
  check that a credentials reply from a server is correct
*/
bool creds_server_check(const struct creds_CredentialState *creds,
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

NTSTATUS creds_server_step_check(struct creds_CredentialState *creds,
				 struct netr_Authenticator *received_authenticator,
				 struct netr_Authenticator *return_authenticator) 
{
	if (!received_authenticator || !return_authenticator) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!creds) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/* TODO: this may allow the a replay attack on a non-signed
	   connection. Should we check that this is increasing? */
	creds->sequence = received_authenticator->timestamp;
	creds_step(creds);
	if (creds_server_check(creds, &received_authenticator->cred)) {
		return_authenticator->cred = creds->server;
		return_authenticator->timestamp = creds->sequence;
		return NT_STATUS_OK;
	} else {
		ZERO_STRUCTP(return_authenticator);
		return NT_STATUS_ACCESS_DENIED;
	}
}

void creds_decrypt_samlogon(struct creds_CredentialState *creds,
			    uint16_t validation_level,
			    union netr_Validation *validation) 
{
	static const char zeros[16];

	struct netr_SamBaseInfo *base = NULL;
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
		return;
	}

	if (!base) {
		return;
	}

	/* find and decyrpt the session keys, return in parameters above */
	if (validation_level == 6) {
		/* they aren't encrypted! */
	} else if (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
		if (memcmp(base->key.key, zeros,  
			   sizeof(base->key.key)) != 0) {
			creds_arcfour_crypt(creds, 
					    base->key.key, 
					    sizeof(base->key.key));
		}
			
		if (memcmp(base->LMSessKey.key, zeros,  
			   sizeof(base->LMSessKey.key)) != 0) {
			creds_arcfour_crypt(creds, 
					    base->LMSessKey.key, 
					    sizeof(base->LMSessKey.key));
		}
	} else {
		if (memcmp(base->LMSessKey.key, zeros,  
			   sizeof(base->LMSessKey.key)) != 0) {
			creds_des_decrypt_LMKey(creds, 
						&base->LMSessKey);
		}
	}
}	
