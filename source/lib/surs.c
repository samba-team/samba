/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   SURS - SID to UID Resolution System.
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
#include "surs.h"

extern int DEBUGLEVEL;

/******************************************************************
 converts SID + SID_NAME_USE type to a UNIX id.
 ********************************************************************/
BOOL surs_sam_sid_to_unixid(const SURS_SID_ID *sid, SURS_POSIX_ID *id, BOOL create)
{
#if 0
#ifdef WITH_NT5LDAP
	return surs_nt5ldap_sam_sid_to_unixid(id, sid, create);
#endif
#if WITH_SURSTDB
	return surs_tdb_sam_sid_to_unixid(id, sid, create);
#endif
#endif
	return surs_algdomonly_sam_sid_to_unixid(sid, id, create);
}

/******************************************************************
 converts UNIX id + type to a SID.
 ********************************************************************/
BOOL surs_unixid_to_sam_sid(const SURS_POSIX_ID *id, SURS_SID_ID *sid, BOOL create)
{
#if 0
#ifdef WITH_NT5LDAP
	return surs_nt5ldap_unixid_to_sam_sid(id, sid, create);
#endif
#if WITH_SURSTDB
	return surs_tdb_unixid_to_sam_sid(id, sid, create);
#endif
#endif
	return surs_algdomonly_unixid_to_sam_sid(id, sid, create);
}
