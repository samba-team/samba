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

extern struct cli_state *smb_cli;
extern FILE* out_hnd;


/****************************************************************************
****************************************************************************/
void cmd_eventlog(struct client_info *info)
{
	uint16 nt_pipe_fnum;
	BOOL res  = True;
	BOOL res1 = True;
	POLICY_HND hnd;
	uint32 number = 0;
	uint32 flags;
	uint32 offset;
	uint32 num_of_bytes;
	EVENTLOGRECORD ev;
	
	fstring journal;
	fstring temp;
	
	flags=EVENTLOG_READ_SEQUENTIAL|EVENTLOG_READ_BACKWARD;

	while (next_token(NULL, temp, NULL, sizeof(temp)))
	{
		fstrcpy(journal, temp);
	}

	/* open scheduler session. */
	res1 = res1 ? cli_nt_session_open(smb_cli, PIPE_EVENTLOG, &nt_pipe_fnum) : False;

	res1 = res1 ? do_event_open(smb_cli, nt_pipe_fnum, journal, &hnd) : False;

	res = res1 ? do_event_numofeventlogrec(smb_cli, nt_pipe_fnum, &hnd, &number) : False;
	
	fprintf(out_hnd, "Number of events: %d\n", number);

	display_eventlog_eventrecord(out_hnd, ACTION_HEADER, &ev);

	for (offset = 0; offset < number && res; offset++)
	{
		num_of_bytes=0;
	
		/* try once with a empty buffer */
		res = res ? do_event_readeventlog(smb_cli, nt_pipe_fnum, &hnd, number, 
						  flags, offset, &num_of_bytes, &ev) : False;
	
		/* and try again with the correct size */
		res = res ? do_event_readeventlog(smb_cli, nt_pipe_fnum, &hnd, number, 
						  flags, offset, &num_of_bytes, &ev) : False;

		display_eventlog_eventrecord(out_hnd, ACTION_ENUMERATE, &ev);
	}

	display_eventlog_eventrecord(out_hnd, ACTION_FOOTER, &ev);
			
	res1 = res1 ? do_event_close(smb_cli, nt_pipe_fnum, &hnd): False;

	/* close the session */
	cli_nt_session_close(smb_cli, nt_pipe_fnum);
}
