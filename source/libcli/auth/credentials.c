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
  initialise the credentials state
*/
void creds_init(struct netr_CredentialState *creds,
		const struct netr_Credential *client_challenge,
		const struct netr_Credential *server_challenge,
		const uint8 machine_password[16])
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

	SIVAL(time_cred.data, 0, IVAL(client_challenge->data, 0) + creds->sequence);
	SIVAL(time_cred.data, 4, IVAL(client_challenge->data, 4));

	cred_hash2(creds->client_cred.data, time_cred.data, creds->session_key);

	creds->server_cred = *server_challenge;
}

/*
  check that the credentials reply is correct then generate the next
  set of credentials
*/
BOOL creds_next(struct netr_CredentialState *creds,
		const struct netr_Credential *next)
{
	struct netr_Credential cred2;
	struct netr_Credential time_cred;

	SIVAL(time_cred.data, 0, IVAL(creds->server_cred.data, 0) + creds->sequence);
	SIVAL(time_cred.data, 4, IVAL(creds->server_cred.data, 4));
	cred_hash2(cred2.data, time_cred.data, creds->session_key);
	if (memcmp(next->data, cred2.data, 8) != 0) {
		DEBUG(2,("credentials check failed\n"));
		return False;
	}

	creds->server_cred = creds->client_cred;

	SIVAL(time_cred.data, 0, IVAL(creds->client_cred.data, 0) + creds->sequence);
	SIVAL(time_cred.data, 4, IVAL(creds->client_cred.data, 4));

	cred_hash2(cred2.data, time_cred.data, creds->session_key);

	creds->client_cred = cred2;
	creds->sequence++;
	return True;
}
