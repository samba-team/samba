/* 
 *  Unix SMB/Netbios implementation.
 *  Version 2.1.
 *  RPC client routines: scheduler service
 *  Copyright (C) Jean Francois Micouleau      1998-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
 *  Copyright (C) Andrew Tridgell              1992-1999.
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

extern int DEBUGLEVEL;

/****************************************************************************
****************************************************************************/
BOOL do_event_open(struct cli_state *cli, uint16 fnum, char *log, POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	EVENTLOG_Q_OPEN q;
	BOOL p = False;
	BOOL valid_pol = False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_eventlog_q_open(&q, log, NULL);

	/* turn parameters into data stream */
	eventlog_io_q_open("", &q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, fnum, EVENTLOG_OPEN, &buf, &rbuf))
	{
		EVENTLOG_R_OPEN r;

		eventlog_io_r_open("", &r, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r.status != 0)
		{
			/* report error code */
			DEBUG(0,("do_event_open: %s\n", get_nt_error_msg(r.status)));
			p = False;
		}

		if (p)
		{
			/*copy handle */
			memcpy(hnd->data, r.pol.data, sizeof(hnd->data));
			valid_pol = True;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return p;
}

/****************************************************************************
****************************************************************************/
BOOL do_event_close(struct cli_state *cli, uint16 fnum, POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	EVENTLOG_Q_CLOSE q;
	BOOL p = False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_eventlog_q_close(&q, hnd);

	/* turn parameters into data stream */
	eventlog_io_q_close("", &q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, fnum, EVENTLOG_CLOSE, &buf, &rbuf))
	{
		EVENTLOG_R_CLOSE r;

		eventlog_io_r_close("", &r, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r.status != 0)
		{
			/* report error code */
			DEBUG(0,("do_event_close: %s\n", get_nt_error_msg(r.status)));
			p = False;
		}

	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return p;
}

/****************************************************************************
****************************************************************************/
BOOL do_event_numofeventlogrec(struct cli_state *cli, uint16 fnum, POLICY_HND *hnd, uint32 *number)
{
	prs_struct rbuf;
	prs_struct buf; 
	EVENTLOG_Q_NUMOFEVENTLOGREC q;
	BOOL p = False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_eventlog_q_numofeventlogrec(&q, hnd);

	/* turn parameters into data stream */
	eventlog_io_q_numofeventlogrec("", &q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, fnum, EVENTLOG_NUMOFEVENTLOGRECORDS, &buf, &rbuf))
	{
		EVENTLOG_R_NUMOFEVENTLOGREC r;

		eventlog_io_r_numofeventlogrec("", &r, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r.status != 0)
		{
			/* report error code */
			DEBUG(0,("do_event_close: %s\n", get_nt_error_msg(r.status)));
			p = False;
		}

		if (p)
		{
			*number=r.number;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return p;
}

/****************************************************************************
****************************************************************************/
BOOL do_event_readeventlog(struct cli_state *cli, uint16 fnum, POLICY_HND *hnd, 
                           uint32 number, uint32 flags, uint32 offset, 
			   uint32 *number_of_bytes, EVENTLOGRECORD *ev)
{
	prs_struct rbuf;
	prs_struct buf; 
	EVENTLOG_Q_READEVENTLOG q;
	EVENTLOG_R_READEVENTLOG r;
	BOOL p = False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_eventlog_q_readeventlog(&q, hnd, flags, offset, *number_of_bytes);

	/* turn parameters into data stream */
	eventlog_io_q_readeventlog("", &q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, fnum, EVENTLOG_READEVENTLOG, &buf, &rbuf))
	{
		r.event=ev;
		eventlog_io_r_readeventlog("", &r, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p)
		{
			*number_of_bytes=r.real_size;		
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return p;
}

