/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Groupname handling
   Copyright (C) Jeremy Allison               1998-2000.
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000.
   Copyright (C) Luke Howard                  2000.
   
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

/* 
 * LDAP implementation of a SURS (sid to uid resolution) table.
 */

#include "includes.h"

#ifdef WITH_NT5LDAP

#include "sids.h"
#include "ldapdb.h"

/******************************************************************
 converts SID + SID_NAME_USE type to a UNIX id.
 ********************************************************************/
BOOL surs_nt5ldap_sam_sid_to_unixid(LDAPDB *hds, DOM_SID * sid, uint32 type,
				    uint32 * id, BOOL create)
{
	if (!ldapdb_lookup_by_sid(hds, sid))
		return False;

	switch (type)
	{
		case RID_TYPE_USER:
			return ldapdb_get_uint32(hds, "uidNumber", id);
		case RID_TYPE_GROUP:
		case RID_TYPE_ALIAS:
			return ldapdb_get_uint32(hds, "gidNumber", id);
		default:
			break;
	}

	return False;
}

/******************************************************************
 converts UNIX gid + SID_NAME_USE type to a SID.  
 ********************************************************************/
BOOL surs_nt5ldap_unixid_to_sam_sid(LDAPDB *hds, uint32 id, uint32 type,
				    DOM_SID * sid, BOOL create)
{
	char *attribute;
	fstring filter;
	char *attrs[] = { "objectSid", NULL };
	BOOL ret;

	switch (type)
	{
		case SID_NAME_USER:
		{
			attribute = "uidNumber";
			break;
		}
		case SID_NAME_ALIAS:
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
		{
			attribute = "gidNumber";
			break;
		}
		default:
		{
			return False;
		}
	}

	slprintf(filter, sizeof(filter) - 1, "(&(objectSid=*)(%s=%d))",
		 attribute, id);
	return ldapdb_search(hds, NULL, filter, attrs, 1)
		&& ldapdb_get_sid(hds, "objectSid", sid);
}

#endif /* WITH_NT5LDAP */
