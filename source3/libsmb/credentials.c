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


/****************************************************************************
  setup the session key. 
Input: 8 byte challenge block
       8 byte server challenge block
      16 byte md4 encrypted password
Output:
      8 byte session key
****************************************************************************/
void cred_session_key(char *challenge, char *srv_challenge, char *pass, 
		       char *session_key)
{
	uint32 sum[2];
	char sum2[8];
	char buf[8];

	sum[0] = IVAL(challenge, 0) + IVAL(srv_challenge, 0);
	sum[1] = IVAL(challenge, 4) + IVAL(srv_challenge, 4);

	SIVAL(sum2,0,sum[0]);
	SIVAL(sum2,4,sum[1]);

	E1(pass,sum2,buf);
	E1(pass+9,buf,session_key);
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
void cred_create(char *session_key, char *stored_cred, uint32 time, 
		 char *cred)
{
	char key2[7];
	char buf[8];
	char timecred[8];

	memcpy(timecred, stored_cred, 8);
	SIVAL(timecred, 0, IVAL(stored_cred, 0) + time);

	E1(session_key, timecred, buf);
	memset(key2, 0, 7);
	key2[0] = session_key[7];
	E1(key2, buf, cred);
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
int cred_assert(char *cred, char *session_key, char *stored_cred,
		uint32 time)
{
	char cred2[8];

	cred_create(session_key, stored_cred, time, cred2);

	return memcmp(cred, cred2, 8) == 0;
}

