/* 
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   
   Copyright (C) Stefan (metze) Metzmacher 2002
   
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

#ifdef HAVE_ADS


/* 
translated the ACB_CTRL Flags to UserFlags (userAccountControl) 
*/ 
uint32 ads_acb2uf(uint16 acb)
{
	uint32 uf = 0x00000000;
	
	if (acb & ACB_DISABLED) 	uf |= UF_ACCOUNTDISABLE;
	if (acb & ACB_HOMDIRREQ) 	uf |= UF_HOMEDIR_REQUIRED;
	if (acb & ACB_PWNOTREQ) 	uf |= UF_PASSWD_NOTREQD;	
	if (acb & ACB_TEMPDUP) 		uf |= UF_TEMP_DUPLICATE_ACCOUNT;	
	if (acb & ACB_NORMAL)	 	uf |= UF_NORMAL_ACCOUNT;
	if (acb & ACB_MNS) 		uf |= UF_MNS_LOGON_ACCOUNT;
	if (acb & ACB_DOMTRUST) 	uf |= UF_INTERDOMAIN_TRUST_ACCOUNT;
	if (acb & ACB_WSTRUST) 		uf |= UF_WORKSTATION_TRUST_ACCOUNT;
	if (acb & ACB_SVRTRUST) 	uf |= UF_SERVER_TRUST_ACCOUNT;
	if (acb & ACB_PWNOEXP) 		uf |= UF_DONT_EXPIRE_PASSWD;
	if (acb & ACB_AUTOLOCK) 	uf |= UF_LOCKOUT;

	return uf;
}

/* translated the UserFlags (userAccountControl) to ACB_CTRL Flags */
uint16 ads_uf2acb(uint32 uf)
{
	uint16 acb = 0x0000;
	
	if (uf & UF_ACCOUNTDISABLE) 		acb |= ACB_DISABLED;
	if (uf & UF_HOMEDIR_REQUIRED) 		acb |= ACB_HOMDIRREQ;
	if (uf & UF_PASSWD_NOTREQD) 		acb |= ACB_PWNOTREQ;	
	if (uf & UF_MNS_LOGON_ACCOUNT) 		acb |= ACB_MNS;
	if (uf & UF_DONT_EXPIRE_PASSWD)		acb |= ACB_PWNOEXP;
	if (uf & UF_LOCKOUT) 			acb |= ACB_AUTOLOCK;
	
	switch (uf & UF_ACCOUNT_TYPE_MASK)
	{
		case UF_TEMP_DUPLICATE_ACCOUNT:		acb |= ACB_TEMPDUP;break;	
		case UF_NORMAL_ACCOUNT:	 		acb |= ACB_NORMAL;break;
		case UF_INTERDOMAIN_TRUST_ACCOUNT: 	acb |= ACB_DOMTRUST;break;
		case UF_WORKSTATION_TRUST_ACCOUNT:	acb |= ACB_WSTRUST;break;
		case UF_SERVER_TRUST_ACCOUNT: 		acb |= ACB_SVRTRUST;break;
		/*Fix Me: what should we do here? */
		default: 				acb |= ACB_NORMAL;break;
	}

	return acb;
}

#endif
