/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   code to manipulate domain credentials
   Copyright (C) Andrew Tridgell 1997
   
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
/****************************************************************************
  setup the session key. 
Input: 8 byte challenge block
       8 byte server challenge block
      16 byte md4 encrypted password
Output:
      8 byte session key
****************************************************************************/
void cred_session_key(DOM_CHAL *clnt_chal, DOM_CHAL *srv_chal, char *pass, 
		       uint32 session_key[2])
{
	uint32 sum[2];
	char sum2[8];
	char buf[8];
	char netsesskey[8];

	sum[0] = IVAL(clnt_chal->data, 0) + IVAL(srv_chal->data, 0);
	sum[1] = IVAL(clnt_chal->data, 4) + IVAL(srv_chal->data, 4);

	SIVAL(sum2,0,sum[0]);
	SIVAL(sum2,4,sum[1]);

	smbhash(buf, sum2, pass);
	smbhash(netsesskey, buf, pass+9);

	session_key[0] = IVAL(netsesskey, 0);
	session_key[1] = IVAL(netsesskey, 4);

	/* debug output */
	DEBUG(4,("cred_session_key\n"));

	DEBUG(5,("	clnt_chal: %lx %lx\n", clnt_chal->data[0], clnt_chal->data[1]));
	DEBUG(5,("	srv_chal : %lx %lx\n", srv_chal ->data[0], srv_chal ->data[1]));
	DEBUG(5,("	clnt+srv : %lx %lx\n", sum            [0], sum            [1]));
	DEBUG(5,("	sess_key : %lx %lx\n", session_key    [0], session_key    [1]));
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
void cred_create(uint32 session_key[2], DOM_CHAL *stor_cred, UTIME timestamp, 
		 DOM_CHAL *cred)
{
	char key2[7];
	char buf[8];
	char calc_cred[8];
	char timecred[8];
	char netsesskey[8];

	SIVAL(netsesskey, 0, session_key[0]);
	SIVAL(netsesskey, 4, session_key[1]);

	SIVAL(timecred, 0, IVAL(stor_cred, 0) + timestamp.time);
	SIVAL(timecred, 4, IVAL(stor_cred, 4));

	smbhash(buf, timecred, netsesskey);
	memset(key2, 0, 7);
	key2[0] = netsesskey[7];
	smbhash(calc_cred, buf, key2);

	cred->data[0] = IVAL(calc_cred, 0);
	cred->data[1] = IVAL(calc_cred, 4);

	/* debug output*/
	DEBUG(4,("cred_create\n"));

	DEBUG(5,("	sess_key : %lx %lx\n", session_key    [0], session_key    [1]));
	DEBUG(5,("	stor_cred: %lx %lx\n", stor_cred->data[0], stor_cred->data[1]));
	DEBUG(5,("	timecred : %lx %lx\n", IVAL(timecred, 0) , IVAL(timecred, 4) ));
	DEBUG(5,("	calc_cred: %lx %lx\n", cred     ->data[0], cred     ->data[1]));
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
int cred_assert(DOM_CHAL *cred, uint32 session_key[2], DOM_CHAL *stored_cred,
		UTIME timestamp)
{
	DOM_CHAL cred2;

	cred_create(session_key, stored_cred, timestamp, &cred2);

	/* debug output*/
	DEBUG(4,("cred_assert\n"));

	DEBUG(5,("	challenge : %lx %lx\n", cred->data[0], cred->data[1]));
	DEBUG(5,("	calculated: %lx %lx\n", cred2.data[0], cred2.data[1]));

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

