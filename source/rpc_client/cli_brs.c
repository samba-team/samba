
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
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
do a BRS Query 
****************************************************************************/
BOOL brs_query_info( const char *srv_name, uint32 switch_value,
			void *id)
{
	prs_struct rbuf;
	prs_struct buf; 
	BRS_Q_QUERY_INFO q_o;
	BOOL valid_info = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_BROWSER, &con))
	{
		return False;
	}

	if (id == NULL) return False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api BRS_QUERY_INFO */

	DEBUG(4,("BRS Query Info\n"));

	/* store the parameters */
	make_brs_q_query_info(&q_o, srv_name, switch_value);

	/* turn parameters into data stream */
	brs_io_q_query_info("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, BRS_QUERY_INFO, &buf, &rbuf))
	{
		BRS_R_QUERY_INFO r_o;
		BOOL p;

		r_o.info.id = id;

		brs_io_r_query_info("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("BRS_R_QUERY_INFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_info = True;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	cli_connection_unlink(con);

	return valid_info;
}

