
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;
extern pstring global_myname;


/*******************************************************************
 create_wks_info_100
 ********************************************************************/
static void create_wks_info_100(WKS_INFO_100 *inf)
{
	pstring my_name;
	pstring domain;

	DEBUG(5,("create_wks_info_100: %d\n", __LINE__));

	pstrcpy (my_name, global_myname);
	strupper(my_name);

	pstrcpy (domain , lp_workgroup());
	strupper(domain);

	make_wks_info_100(inf,
	                  0x000001f4, /* platform id info */
	                  lp_major_announce_version(),
	                  lp_minor_announce_version(),
	                  my_name, domain);
}

/*******************************************************************
 _wks_query_info
 
 only supports info level 100 at the moment.
 ********************************************************************/
uint32 _wks_query_info( const UNISTR2 *srv_name, uint16 switch_value,
			WKS_INFO_100 *wks100)
{
	switch (switch_value)
	{
		case 100:
		{
			create_wks_info_100(wks100);
			return NT_STATUS_NOPROBLEMO;
		}
	}
	return NT_STATUS_INVALID_INFO_CLASS;
}

