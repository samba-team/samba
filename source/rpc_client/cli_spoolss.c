
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
do a SPOOLSS Open Printer Ex
****************************************************************************/
BOOL spoolss_open_printer_ex(struct cli_state *cli, uint16 fnum,
			char *printername,
			uint32 cbbuf, uint32 devmod, uint32 des_access,
			char *station,
			char *username,
			PRINTER_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_OPEN_PRINTER_EX q_o;
	BOOL valid_pol = False;

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
	if (rpc_api_pipe_req(cli, fnum, SPOOLSS_OPENPRINTEREX, &buf, &rbuf))
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
			valid_pol = True;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_pol;
}

/****************************************************************************
do a SPOOL Close
****************************************************************************/
BOOL spoolss_closeprinter(struct cli_state *cli, uint16 fnum, PRINTER_HND *hnd)
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
	if (rpc_api_pipe_req(cli, fnum, SPOOLSS_CLOSEPRINTER, &buf, &rbuf))
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

	return valid_close;
}

