/* 
   Unix SMB/CIFS implementation.

   code to manipulate domain credentials

   Copyright (C) Andrew Tridgell 1997-2003
   
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
  initialise the credentials state and return the initial credentials
  to be sent as part of a netr_ServerAuthenticate*() call.

  this call is made after the netr_ServerReqChallenge call
*/
void creds_init(struct netr_CredentialState *creds,
		const struct netr_Credential *client_challenge,
		const struct netr_Credential *server_challenge,
		const uint8 machine_password[16],
		struct netr_Credential *initial_creds)
{
	struct netr_Credential time_cred;
	uint32 sum[2];
	uint8 sum2[8];

	sum[0] = IVAL(client_challenge->data, 0) + IVAL(server_challenge->data, 0);
	sum[1] = IVAL(client_challenge->data, 4) + IVAL(server_challenge->data, 4);

	SIVAL(sum2,0,sum[0]);
	SIVAL(sum2,4,sum[1]);

	cred_hash1(creds->session_key, sum2, machine_password);

	creds->sequence = 0;

	SIVAL(time_cred.data, 0, IVAL(client_challenge->data, 0));
	SIVAL(time_cred.data, 4, IVAL(client_challenge->data, 4));

	cred_hash2(creds->cred2.data, time_cred.data, creds->session_key);

	creds->cred1 = *server_challenge;

	*initial_creds = creds->cred2;
}


/*
  check that a credentials reply is correct
*/
BOOL creds_check(struct netr_CredentialState *creds,
		 const struct netr_Credential *received_credentials)
{
	struct netr_Credential cred2, time_cred;
	uint32 sequence = creds->sequence?creds->sequence+1:0;

	SIVAL(time_cred.data, 0, IVAL(creds->cred1.data, 0) + sequence);
	SIVAL(time_cred.data, 4, IVAL(creds->cred1.data, 4));
	cred_hash2(cred2.data, time_cred.data, creds->session_key);
	if (memcmp(received_credentials->data, cred2.data, 8) != 0) {
		DEBUG(2,("credentials check failed\n"));
		return False;
	}

	return True;
}

/*
  produce the next authenticator in the sequence ready to send to 
  the server
*/
void creds_authenticator(struct netr_CredentialState *creds,
			 struct netr_Authenticator *next)
{
	struct netr_Credential cred2;
	struct netr_Credential time_cred;

	if (creds->sequence == 0) {
		creds->sequence = time(NULL);
	}

	/* this step size is quite arbitrary - the client can choose
	   any sequence number it likes */
	creds->sequence += 2;

	creds->cred1 = creds->cred2;

	SIVAL(time_cred.data, 0, IVAL(creds->cred2.data, 0) + creds->sequence);
	SIVAL(time_cred.data, 4, IVAL(creds->cred2.data, 4));

	cred_hash2(cred2.data, time_cred.data, creds->session_key);

	creds->cred2 = cred2;

	next->cred = creds->cred2;
	next->timestamp = creds->sequence;
}


/*
  encrypt a 16 byte password buffer using the session key
*/
void creds_encrypt(struct netr_CredentialState *creds, struct netr_Password *pass)
{
	struct netr_Password tmp;
	cred_hash3(tmp.data, pass->data, creds->session_key, 1);
	*pass = tmp;
}
