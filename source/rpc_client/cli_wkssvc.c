
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
do a WKS Open Policy
****************************************************************************/
BOOL wks_query_info( char *srv_name, uint32 switch_value,
			WKS_INFO_100 *wks100)
{
	prs_struct rbuf;
	prs_struct buf; 
	WKS_Q_QUERY_INFO q_o;
	BOOL valid_info = False;
	struct cli_connection *con = NULL;

	if (wks100 == NULL) return False;

	if (!cli_connection_init(srv_name, PIPE_WKSSVC, &con))
	{
		return False;
	}

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	/* create and send a MSRPC command with api WKS_QUERY_INFO */

	DEBUG(4,("WKS Query Info\n"));

	/* store the parameters */
	make_wks_q_query_info(&q_o, srv_name, switch_value);

	/* turn parameters into data stream */
	wks_io_q_query_info("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, WKS_QUERY_INFO, &buf, &rbuf))
	{
		WKS_R_QUERY_INFO r_o;
		BOOL p;

		r_o.wks100 = wks100;

		wks_io_r_query_info("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("WKS_R_QUERY_INFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_info = True;
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	cli_connection_unlink(con);

	return valid_info;
}

