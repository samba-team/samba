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

/****************************************************************************
represent a credential as a string
****************************************************************************/
char *credstr(const uchar *cred)
{
	static fstring buf;
	slprintf(buf, sizeof(buf) - 1, "%02X%02X%02X%02X%02X%02X%02X%02X",
		cred[0], cred[1], cred[2], cred[3], 
		cred[4], cred[5], cred[6], cred[7]);
	return buf;
}


/****************************************************************************
  setup the session key. 
Input: 8 byte challenge block
       8 byte server challenge block
      16 byte md4 encrypted password
Output:
      8 byte session key
****************************************************************************/
void cred_session_key(const struct netr_Credential *client_challenge, 
		      const struct netr_Credential *server_challenge, 
		      const uint8  md4_pass[16], 
		      uint8 session_key[8])
{
	uint32 sum[2];
	uint8 sum2[8];

	sum[0] = IVAL(client_challenge->data, 0) + IVAL(server_challenge->data, 0);
	sum[1] = IVAL(client_challenge->data, 4) + IVAL(server_challenge->data, 4);

	SIVAL(sum2,0,sum[0]);
	SIVAL(sum2,4,sum[1]);

	cred_hash1(session_key, sum2, md4_pass);
}


/****************************************************************************
create a credential

Input:
      8 byte sesssion key
      8 byte stored credential
      4 byte timestamp

Output:
      8 byte credential
****************************************************************************/
void cred_create(uchar session_key[8], struct netr_Credential *stor_cred, time_t timestamp, 
		 struct netr_Credential *cred)
{
	struct netr_Credential time_cred;

	SIVAL(time_cred.data, 0, IVAL(stor_cred->data, 0) + timestamp);
	SIVAL(time_cred.data, 4, IVAL(stor_cred->data, 4));

	cred_hash2(cred->data, time_cred.data, session_key);

	/* debug output*/
	DEBUG(4,("cred_create\n"));

	DEBUG(5,("	sess_key : %s\n", credstr(session_key)));
	DEBUG(5,("	stor_cred: %s\n", credstr(stor_cred->data)));
	DEBUG(5,("	timestamp: %x\n", (unsigned)timestamp));
	DEBUG(5,("	timecred : %s\n", credstr(time_cred.data)));
	DEBUG(5,("	calc_cred: %s\n", credstr(cred->data)));
}


/****************************************************************************
  check a supplied credential

Input:
      8 byte received credential
      8 byte sesssion key
      8 byte stored credential
      4 byte timestamp

Output:
      returns 1 if computed credential matches received credential
      returns 0 otherwise
****************************************************************************/
int cred_assert(struct netr_Credential *cred, uchar session_key[8], 
		struct netr_Credential *stored_cred,
		time_t timestamp)
{
	struct netr_Credential cred2;

	cred_create(session_key, stored_cred, timestamp, &cred2);

	/* debug output*/
	DEBUG(4,("cred_assert\n"));

	DEBUG(5,("	challenge : %s\n", credstr(cred->data)));
	DEBUG(5,("	calculated: %s\n", credstr(cred2.data)));

	if (memcmp(cred->data, cred2.data, 8) == 0)
	{
		DEBUG(5, ("credentials check ok\n"));
		return True;
	}
	else
	{
		DEBUG(5, ("credentials check wrong\n"));
		return False;
	}
}


/****************************************************************************
  checks credentials; generates next step in the credential chain
****************************************************************************/
BOOL clnt_deal_with_creds(uchar sess_key[8],
			  struct netr_Authenticator *sto_clnt_cred, 
			  struct netr_Authenticator *rcv_srv_cred)
{
	time_t new_clnt_time;
	uint32 new_cred;

	/* increment client time by one second !?! */
	new_clnt_time = sto_clnt_cred->timestamp + 1;

	/* check that the received server credentials are valid */
	if (!cred_assert(&rcv_srv_cred->cred, sess_key,
			 &sto_clnt_cred->cred, new_clnt_time)) {
		return False;
	}

	/* first 4 bytes of the new seed is old client 4 bytes + clnt time + 1 */
	new_cred = IVAL(sto_clnt_cred->cred.data, 0);
	new_cred += new_clnt_time;

	/* store new seed in client credentials */
	SIVAL(sto_clnt_cred->cred.data, 0, new_cred);

	return True;
}


/****************************************************************************
  checks credentials; generates next step in the credential chain
****************************************************************************/
BOOL deal_with_creds(uchar sess_key[8],
		     struct netr_Authenticator *sto_clnt_cred, 
		     struct netr_Authenticator *rcv_clnt_cred, 
		     struct netr_Authenticator *rtn_srv_cred)
{
	time_t new_clnt_time;
	uint32 new_cred;

	DEBUG(5,("deal_with_creds: %d\n", __LINE__));

	/* check that the received client credentials are valid */
	if (!cred_assert(&rcv_clnt_cred->cred, sess_key,
                    &sto_clnt_cred->cred, rcv_clnt_cred->timestamp))
	{
		return False;
	}

	/* increment client time by one second */
	new_clnt_time = rcv_clnt_cred->timestamp + 1;

	/* first 4 bytes of the new seed is old client 4 bytes + clnt time + 1 */
	new_cred = IVAL(sto_clnt_cred->cred.data, 0);
	new_cred += new_clnt_time;

	DEBUG(5,("deal_with_creds: new_cred[0]=%x\n", new_cred));

	/* doesn't matter that server time is 0 */
	rtn_srv_cred->timestamp = 0;

	DEBUG(5,("deal_with_creds: new_clnt_time=%x\n", (unsigned)new_clnt_time));

	/* create return credentials for inclusion in the reply */
	cred_create(sess_key, &sto_clnt_cred->cred, new_clnt_time,
	            &rtn_srv_cred->cred);
	
	DEBUG(5,("deal_with_creds: clnt_cred=%s\n", credstr(sto_clnt_cred->cred.data)));

	/* store new seed in client credentials */
	SIVAL(sto_clnt_cred->cred.data, 0, new_cred);

	return True;
}
