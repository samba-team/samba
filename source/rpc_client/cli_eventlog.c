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
#include "rpc_parse.h"

extern int DEBUGLEVEL;

/****************************************************************************
****************************************************************************/
BOOL event_open(const char* srv_name, const char *log, POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	EVENTLOG_Q_OPEN q;
	BOOL p = False;
	BOOL valid_pol = False;
	
	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_EVENTLOG, &con))
	{
		return False;
	}

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	/* store the parameters */
	make_eventlog_q_open(&q, log, NULL);

	/* turn parameters into data stream */
	eventlog_io_q_open("", &q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, EVENTLOG_OPEN, &buf, &rbuf))
	{
		EVENTLOG_R_OPEN r;

		eventlog_io_r_open("", &r, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r.status != 0)
		{
			/* report error code */
			DEBUG(0,("event_open: %s\n", get_nt_error_msg(r.status)));
			p = False;
		}

		if (p)
		{
			DEBUG(0,("event_open: unk_6 or unk_7 is an access mask\n"));
			/*copy handle */
			memcpy(hnd->data, r.pol.data, sizeof(hnd->data));
			valid_pol = register_policy_hnd(get_global_hnd_cache(), cli_con_sec_ctx(con),
			                                hnd, 0x01) &&
			            set_policy_con(get_global_hnd_cache(), hnd, con, 
			                                 cli_connection_unlink);
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return p;
}

/****************************************************************************
****************************************************************************/
BOOL event_close( POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	EVENTLOG_Q_CLOSE q;
	BOOL p = False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	/* store the parameters */
	make_eventlog_q_close(&q, hnd);

	/* turn parameters into data stream */
	eventlog_io_q_close("", &q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, EVENTLOG_CLOSE, &buf, &rbuf))
	{
		EVENTLOG_R_CLOSE r;

		eventlog_io_r_close("", &r, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r.status != 0)
		{
			/* report error code */
			DEBUG(0,("event_close: %s\n", get_nt_error_msg(r.status)));
			p = False;
		}

	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	close_policy_hnd(get_global_hnd_cache(), hnd);

	return p;
}

/****************************************************************************
****************************************************************************/
BOOL event_numofeventlogrec( POLICY_HND *hnd, uint32 *number)
{
	prs_struct rbuf;
	prs_struct buf; 
	EVENTLOG_Q_NUMOFEVENTLOGREC q;
	BOOL p = False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	/* store the parameters */
	make_eventlog_q_numofeventlogrec(&q, hnd);

	/* turn parameters into data stream */
	eventlog_io_q_numofeventlogrec("", &q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, EVENTLOG_NUMOFEVENTLOGRECORDS, &buf, &rbuf))
	{
		EVENTLOG_R_NUMOFEVENTLOGREC r;

		eventlog_io_r_numofeventlogrec("", &r, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r.status != 0)
		{
			/* report error code */
			DEBUG(0,("event_close: %s\n", get_nt_error_msg(r.status)));
			p = False;
		}

		if (p)
		{
			*number=r.number;
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return p;
}

/****************************************************************************
****************************************************************************/
BOOL event_readeventlog(POLICY_HND *hnd, 
                           uint32 number, uint32 flags, uint32 offset, 
			   uint32 *number_of_bytes, EVENTLOGRECORD *ev)
{
	prs_struct rbuf;
	prs_struct buf; 
	EVENTLOG_Q_READEVENTLOG q;
	EVENTLOG_R_READEVENTLOG r;
	BOOL p = False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	/* store the parameters */
	make_eventlog_q_readeventlog(&q, hnd, flags, offset, *number_of_bytes);

	/* turn parameters into data stream */
	eventlog_io_q_readeventlog("", &q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, EVENTLOG_READEVENTLOG, &buf, &rbuf))
	{
		r.event=ev;
		eventlog_io_r_readeventlog("", &r, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p)
		{
			*number_of_bytes=r.real_size;		
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return p;
}

