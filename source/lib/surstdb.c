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

/* 
 * tdb implementation of a SURS (sid to uid resolution) table.
 */

#include "includes.h"
#include "sids.h"

extern int DEBUGLEVEL;

/******************************************************************
 converts SID + SID_NAME_USE type to a UNIX id.
 ********************************************************************/
BOOL surs_tdb_sam_sid_to_unixid(DOM_SID *sid, uint32 type, uint32 *id,
				BOOL create)
{
	return False;
}

/******************************************************************
 converts UNIX gid + SID_NAME_USE type to a SID.
 ********************************************************************/
BOOL surs_tdb_unixid_to_sam_sid(uint32 id, uint32 type, DOM_SID *sid,
				BOOL create)
{
	return False;
}

