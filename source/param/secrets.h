/*
 * Unix SMB/CIFS implementation. 
 * secrets.tdb file format info
 * Copyright (C) Andrew Tridgell              2000
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.  
 */

#ifndef _SECRETS_H
#define _SECRETS_H

/* structure for storing machine account password
   (ie. when samba server is member of a domain */
struct machine_acct_pass {
	uint8_t hash[16];
	time_t mod_time;
};

#define SECRETS_PRIMARY_DOMAIN_DN "cn=Primary Domains"
#define SECRETS_PRINCIPALS_DN "cn=Principals"
#define SECRETS_PRIMARY_DOMAIN_FILTER "(&(flatname=%s)(objectclass=primaryDomain))"
#define SECRETS_PRIMARY_REALM_FILTER "(&(realm=%s)(objectclass=primaryDomain))"
#define SECRETS_KRBTGT_SEARCH "(&((|(realm=%s)(flatname=%s))(samAccountName=krbtgt)))"
#define SECRETS_PRINCIPAL_SEARCH "(&(|(realm=%s)(flatname=%s))(servicePrincipalName=%s))"

#include "param/secrets_proto.h"

#endif /* _SECRETS_H */
