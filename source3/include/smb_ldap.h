/* 
   Unix SMB/CIFS implementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau	1998
   Copyright (C) Gerald Carter			2001
   Copyright (C) Shahms King			2001
   Copyright (C) Andrew Bartlett		2002
   Copyright (C) Stefan (metze) Metzmacher	2002
   Copyright (C) Jim McDonough                  2003
    
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

#ifndef SMB_LDAP_H
#define SMB_LDAP_H

#ifdef HAVE_LDAP

#include <lber.h>
#include <ldap.h>

struct smb_ldap_privates {

	/* Former statics */
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	int index;
	
	time_t last_ping;
	/* retrive-once info */
	const char *uri;
	
	BOOL permit_non_unix_accounts;
	
	uint32 low_nua_rid; 
	uint32 high_nua_rid; 

	char *bind_dn;
	char *bind_secret;

	struct smb_ldap_privates *next;
};

#endif
#endif
