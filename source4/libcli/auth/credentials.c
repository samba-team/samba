/* 
   Unix SMB/CIFS implementation.

   code to manipulate domain credentials

   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   
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

/*
  initialise the credentials state 

  this call is made after the netr_ServerReqChallenge call
*/
static void creds_init(struct creds_CredentialState *creds,
		       const struct netr_Credential *client_challenge,
		       const struct netr_Credential *server_challenge,
		       const uint8 machine_password[16])
{
	struct netr_Credential time_cred;
	uint32 sum[2];
	uint8 sum2[8];

	dump_data_pw("Client chall", client_challenge->data, sizeof(client_challenge->data));
	dump_data_pw("Server chall", server_challenge->data, sizeof(server_challenge->data));
	dump_data_pw("Machine Pass", machine_password, 16);

	sum[0] = IVAL(client_challenge->data, 0) + IVAL(server_challenge->data, 0);
	sum[1] = IVAL(client_challenge->data, 4) + IVAL(server_challenge->data, 4);

	SIVAL(sum2,0,sum[0]);
	SIVAL(sum2,4,sum[1]);

	cred_hash1(creds->session_key, sum2, machine_password);

	SIVAL(time_cred.data, 0, IVAL(client_challenge->data, 0));
	SIVAL(time_cred.data, 4, IVAL(client_challenge->data, 4));
	cred_hash2(creds->client.data, time_cred.data, creds->session_key, 1);

	SIVAL(time_cred.data, 0, IVAL(server_challenge->data, 0));
	SIVAL(time_cred.data, 4, IVAL(server_challenge->data, 4));
	cred_hash2(creds->server.data, time_cred.data, creds->session_key, 1);

	creds->seed = creds->client;
}


/*
  step the credentials to the next element in the chain, updating the
  current client and server credentials and the seed
*/
static void creds_step(struct creds_CredentialState *creds)
{
	struct netr_Credential time_cred;

	creds->sequence += 2;

	DEBUG(5,("\tseed        %08x:%08x\n", 
		 IVAL(creds->seed.data, 0), IVAL(creds->seed.data, 4)));

	SIVAL(time_cred.data, 0, IVAL(creds->seed.data, 0) + creds->sequence);
	SIVAL(time_cred.data, 4, IVAL(creds->seed.data, 4));

	DEBUG(5,("\tseed+time   %08x:%08x\n", IVAL(time_cred.data, 0), IVAL(time_cred.data, 4)));

	cred_hash2(creds->client.data, time_cred.data, creds->session_key, 1);

	DEBUG(5,("\tCLIENT      %08x:%08x\n", 
		 IVAL(creds->client.data, 0), IVAL(creds->client.data, 4)));

	SIVAL(time_cred.data, 0, IVAL(creds->seed.data, 0) + creds->sequence + 1);
	SIVAL(time_cred.data, 4, IVAL(creds->seed.data, 4));

	DEBUG(5,("\tseed+time+1 %08x:%08x\n", 
		 IVAL(time_cred.data, 0), IVAL(time_cred.data, 4)));

	cred_hash2(creds->server.data, time_cred.data, creds->session_key, 1);

	DEBUG(5,("\tSERVER      %08x:%08x\n", 
		 IVAL(creds->server.data, 0), IVAL(creds->server.data, 4)));

	creds->seed = time_cred;
}

/*
  DES encrypt a 16 byte password buffer using the session key
*/
void creds_des_encrypt(struct creds_CredentialState *creds, struct netr_Password *pass)
{
	struct netr_Password tmp;
	cred_hash3(tmp.data, pass->data, creds->session_key, 1);
	*pass = tmp;
}

/*
  ARCFOUR encrypt/decrypt a password buffer using the session key
*/
void creds_arcfour_crypt(struct creds_CredentialState *creds, char *data, size_t len)
{
	DATA_BLOB session_key = data_blob(NULL, 16);
	
	memcpy(&session_key.data[0], creds->session_key, 8);
	memset(&session_key.data[8], '\0', 8);

	SamOEMhashBlob(data, len, &session_key);

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
		       const uint8 machine_password[16],
		       struct netr_Credential *initial_credential)
{
	creds_init(creds, client_challenge, server_challenge, machine_password);
	creds->sequence = time(NULL);

	*initial_credential = creds->client;
}

/*
  check that a credentials reply from a server is correct
*/
BOOL creds_client_check(struct creds_CredentialState *creds,
			const struct netr_Credential *received_credentials)
{
	if (!received_credentials || 
	    memcmp(received_credentials->data, creds->server.data, 8) != 0) {
		DEBUG(2,("credentials check failed\n"));
		return False;
	}
	return True;
}

/*
  produce the next authenticator in the sequence ready to send to 
  the server
*/
void creds_client_authenticator(struct creds_CredentialState *creds,
				struct netr_Authenticator *next)
{
	creds_step(creds);

	next->cred = creds->client;
	next->timestamp = creds->sequence;
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
		       const uint8 machine_password[16],
		       struct netr_Credential *initial_credential)
{
	creds_init(creds, client_challenge, server_challenge, machine_password);

	*initial_credential = creds->server;
}

/*
  check that a credentials reply from a server is correct
*/
BOOL creds_server_check(const struct creds_CredentialState *creds,
			const struct netr_Credential *received_credentials)
{
	if (memcmp(received_credentials->data, creds->client.data, 8) != 0) {
		DEBUG(2,("credentials check failed\n"));
		dump_data_pw("client creds", creds->client.data, 8);
		dump_data_pw("calc   creds", received_credentials->data, 8);
		return False;
	}
	return True;
}

