/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Groupname handling
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000.
   
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

/******************************************************************
 converts SID + SID_NAME_USE type to a UNIX id.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
BOOL surs_sam_sid_to_unixid(DOM_SID *sid, uint32 type, uint32 *id, BOOL create)
{
#ifdef WITH_NT5LDAP
	return surs_nt5ldap_sam_sid_to_unixid(id, type, sid, create);
#endif
#if WITH_SURSTDB
	return surs_tdb_sam_sid_to_unixid(id, type, sid, create);
#endif
	return surs_algdomonly_sam_sid_to_unixid(sid, type, id, create);
}

/******************************************************************
 converts UNIX gid + SID_NAME_USE type to a SID.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
BOOL surs_unixid_to_sam_sid(uint32 id, uint32 type, DOM_SID *sid, BOOL create)
{
#ifdef WITH_NT5LDAP
	return surs_nt5ldap_unixid_to_sam_sid(id, type, sid, create);
#endif
#if WITH_SURSTDB
	return surs_tdb_unixid_to_sam_sid(id, type, sid, create);
#endif
	return surs_algdomonly_unixid_to_sam_sid(id, type, sid, create);
}
