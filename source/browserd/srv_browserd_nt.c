/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB server routines
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Sean Millichamp                   2000
   
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


/*******************************************************************
 create_brs_info_100
 ********************************************************************/
static void create_brs_info_100(BRS_INFO_100 *inf)
{
	make_brs_info_100(inf);
}

/*******************************************************************
 _brs_query_info
 
 only supports info level 100 at the moment.

 ********************************************************************/
uint32 _brs_query_info( const UNISTR2 *srv_name, uint16 switch_value,
			void *id)
{
	switch (switch_value)
	{
		case 100:
		{
			create_brs_info_100(id);
			return 0x0;
		}
	}
	return NT_STATUS_INVALID_INFO_CLASS;
}
