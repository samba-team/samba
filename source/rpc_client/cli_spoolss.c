
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;


/****************************************************************************
do a SPOOLSS Enum Printers
****************************************************************************/
BOOL spoolss_enum_printers(uint32 flags, const char *srv_name,
			uint32 level,
			uint32 *count,
			void ***printers)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_ENUMPRINTERS q_o;
	BOOL valid_pol = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_LSARPC, &con))
	{
		return False;
	}

	if (count == NULL || printers == NULL) return False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api SPOOLSS_ENUM_PRINTERS */

	DEBUG(5,("SPOOLSS Enum Printers (Server: %s level: %d)\n",
				srv_name, level));

	make_spoolss_q_enumprinters(&q_o, flags, srv_name, level, 0x50);

	/* turn parameters into data stream */
	spoolss_io_q_enumprinters("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SPOOLSS_ENUMPRINTERS, &buf, &rbuf))
	{
		SPOOL_R_ENUMPRINTERS r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		r_o.level = level; /* i can't believe you have to this */

		spoolss_io_r_enumprinters("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(5,("SPOOLSS_ENUM_PRINTERS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			(*count) = r_o.returned;
			(*printers) = r_o.printer.info;
			valid_pol = True;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	cli_connection_unlink(con);

	return valid_pol;
}

/****************************************************************************
do a SPOOLSS Enum Jobs
****************************************************************************/
uint32 spoolss_enum_jobs( const POLICY_HND *hnd,
			uint32 firstjob,
			uint32 numofjobs,
			uint32 level,
			uint32 *buf_size,
			uint32 *count,
			void ***jobs)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_ENUMJOBS q_o;
	uint32 status = 0x0;

	if (hnd == NULL || count == NULL || jobs == NULL)
	{
		return NT_STATUS_INVALID_PARAMETER;
	}

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api SPOOLSS_ENUMJOBS */

	DEBUG(5,("SPOOLSS Enum Jobs level: %d)\n", level));

	make_spoolss_q_enumjobs(&q_o, hnd,
			firstjob, numofjobs,
			level, *buf_size);

	/* turn parameters into data stream */
	spoolss_io_q_enumjobs("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, SPOOLSS_ENUMJOBS, &buf, &rbuf))
	{
		SPOOL_R_ENUMJOBS r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		r_o.level = level; /* i can't believe you have to this */

		spoolss_io_r_enumjobs("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		status = r_o.status;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(5,("SPOOLSS_ENUM_JOBS: %s\n", get_nt_error_msg(r_o.status)));
			p = status = ERROR_INSUFFICIENT_BUFFER;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			(*count) = r_o.numofjobs;
			(*jobs) = r_o.job.info;
			(*buf_size) = r_o.offered;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return status;
}

/****************************************************************************
do a SPOOLSS Open Printer Ex
****************************************************************************/
BOOL spoolss_open_printer_ex( const char *printername,
			uint32 cbbuf, uint32 devmod, uint32 des_access,
			const char *station, const char *username,
			POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_OPEN_PRINTER_EX q_o;
	BOOL valid_pol = False;
	fstring srv_name;
	char *s;

	struct cli_connection *con = NULL;

	memset(srv_name, 0, sizeof(srv_name));
	fstrcpy(srv_name, printername);

	s = strchr(&srv_name[2], '\\');

	if (s != NULL)
	{
		*s = 0;
	}

	if (!cli_connection_init(srv_name, PIPE_LSARPC, &con))
	{
		return False;
	}

	if (hnd == NULL) return False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api SPOOLSS_OPENPRINTEREX */

	DEBUG(5,("SPOOLSS Open Printer Ex\n"));

	make_spoolss_q_open_printer_ex(&q_o, printername,
	                               cbbuf, devmod, des_access,
	                               station, username);

	/* turn parameters into data stream */
	spoolss_io_q_open_printer_ex("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SPOOLSS_OPENPRINTEREX, &buf, &rbuf))
	{
		SPOOL_R_OPEN_PRINTER_EX r_o;
		BOOL p;

		spoolss_io_r_open_printer_ex("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(5,("SPOOLSS_OPENPRINTEREX: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			memcpy(hnd, r_o.handle.data, sizeof(hnd->data));

			valid_pol = register_policy_hnd(hnd) &&
					    set_policy_con(hnd, con, 
						cli_connection_unlink);
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_pol;
}

/****************************************************************************
do a SPOOL Close
****************************************************************************/
BOOL spoolss_closeprinter(POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_CLOSEPRINTER q_c;
	BOOL valid_close = False;

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api SPOOLSS_CLOSEPRINTER */

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SPOOL Close Printer\n"));

	/* store the parameters */
	make_spoolss_q_closeprinter(&q_c, hnd);

	/* turn parameters into data stream */
	spoolss_io_q_closeprinter("", &q_c, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_hnd_pipe_req(hnd, SPOOLSS_CLOSEPRINTER, &buf, &rbuf))
	{
		SPOOL_R_CLOSEPRINTER r_c;
		BOOL p;

		spoolss_io_r_closeprinter("", &r_c, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(0,("SPOOL_CLOSEPRINTER: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			/* check that the returned policy handle is all zeros */
			uint32 i;
			valid_close = True;

			for (i = 0; i < sizeof(r_c.handle.data); i++)
			{
				if (r_c.handle.data[i] != 0)
				{
					valid_close = False;
					break;
				}
			}	
			if (!valid_close)
			{
				DEBUG(0,("SPOOL_CLOSEPRINTER: non-zero handle returned\n"));
			}
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	close_policy_hnd(hnd);

	return valid_close;
}

