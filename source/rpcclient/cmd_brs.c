/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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



#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "rpc_brs.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern FILE* out_hnd;


/****************************************************************************
Browser get info query
****************************************************************************/
void cmd_brs_query_info(struct client_info *info, int argc, char *argv[])
{
	fstring dest_brs;
	BRS_INFO_100 ctr;
	uint32 info_level = 100;

	BOOL res = True;

	bzero(&ctr, sizeof(ctr));

	fstrcpy(dest_brs, "\\\\");
	fstrcat(dest_brs, info->dest_host);
	strupper(dest_brs);

	if (argc > 1)
	{
		info_level = (uint32)strtol(argv[1], (char**)NULL, 10);
	}

	DEBUG(4,("cmd_brs_query_info: server:%s info level: %d\n",
				dest_brs, info_level));

	/* send info level: receive requested info.  hopefully. */
	res = res ? brs_query_info( dest_brs, info_level, &ctr) : False;

	if (res)
	{
		DEBUG(5,("cmd_brs_query_info: query succeeded\n"));

#if 0
		display_brs_info_100(out_hnd, ACTION_HEADER   , &ctr);
		display_brs_info_100(out_hnd, ACTION_ENUMERATE, &ctr);
		display_brs_info_100(out_hnd, ACTION_FOOTER   , &ctr);
#endif

	}
	else
	{
		DEBUG(5,("cmd_brs_query_info: query failed\n"));
	}
}

