/* 
   Unix SMB/Netbios implementation.
   Version 2.1.
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
   Copyright (C) Andrew Tridgell              1994-1999,
   Copyright (C) Jean Francois Micouleau      1998-1999.
   
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
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern FILE* out_hnd;


/****************************************************************************
****************************************************************************/
void cmd_eventlog(struct client_info *info, int argc, char *argv[])
{
	BOOL res1  = True;
	BOOL res = True;
	POLICY_HND hnd;
	uint32 number = 0;
	uint32 flags;
	uint32 offset;
	uint32 num_of_bytes;
	EVENTLOGRECORD ev;
	
	char *journal = NULL;
	
	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	flags = EVENTLOG_READ_SEQUENTIAL|EVENTLOG_READ_BACKWARD;

	if (argc > 1)
	{
		journal = argv[1];
	}

	res = res ? event_open(srv_name, journal, &hnd) : False;
	res1 = res ? event_numofeventlogrec(&hnd, &number) : False;
	
	fprintf(out_hnd, "Number of events: %d\n", number);

	display_eventlog_eventrecord(out_hnd, ACTION_HEADER, &ev);

	for (offset = 0; offset < number && res1; offset++)
	{
		num_of_bytes=0;
	
		/* try once with a empty buffer */
		res1 = res1 ? event_readeventlog(&hnd, number, 
						  flags, offset,
					          &num_of_bytes, &ev) : False;
	
		/* and try again with the correct size */
		res1 = res1 ? event_readeventlog(&hnd, number, 
						  flags, offset,
		                                  &num_of_bytes, &ev) : False;

		display_eventlog_eventrecord(out_hnd, ACTION_ENUMERATE, &ev);
	}

	display_eventlog_eventrecord(out_hnd, ACTION_FOOTER, &ev);
			
	res = res ? event_close(&hnd): False;
}
