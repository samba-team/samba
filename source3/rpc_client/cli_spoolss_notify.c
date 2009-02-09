/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Gerald Carter                2001-2002,
   Copyright (C) Tim Potter                   2000-2002,
   Copyright (C) Andrew Tridgell              1994-2000,
   Copyright (C) Jean-Francois Micouleau      1999-2000.
   Copyright (C) Jeremy Allison                    2005.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

/*
 * SPOOLSS Client RPC's used by servers as the notification
 * back channel.
 */

/*********************************************************************
 This SPOOLSS_REPLY_RRPCN function is used to send a change 
 notification event when the registration **did** use 
 SPOOL_NOTIFY_OPTION_TYPE structure to specify the events to monitor
 Also see cli_spoolss_routereplyprinter()
 *********************************************************************/

WERROR rpccli_spoolss_rrpcn(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, 
			 POLICY_HND *pol, uint32 notify_data_len,
			 SPOOL_NOTIFY_INFO_DATA *notify_data,
			 uint32 change_low, uint32 change_high)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_REPLY_RRPCN q;
	SPOOL_R_REPLY_RRPCN r;
	WERROR result = W_ERROR(ERRgeneral);
	SPOOL_NOTIFY_INFO 	notify_info;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	ZERO_STRUCT(notify_info);

	/* Initialise input parameters */

	notify_info.version = 0x2;
	notify_info.flags   = 0x00020000;	/* ?? */
	notify_info.count   = notify_data_len;
	notify_info.data    = notify_data;

	/* create and send a MSRPC command with api  */
	/* store the parameters */

	make_spoolss_q_reply_rrpcn(&q, pol, change_low, change_high, 
				   &notify_info);

	/* Marshall data and send request */

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_RRPCN,
		q, r,
		qbuf, rbuf,
		spoolss_io_q_reply_rrpcn,
		spoolss_io_r_reply_rrpcn,
		WERR_GENERAL_FAILURE );

	if (r.unknown0 == 0x00080000)
		DEBUG(8,("cli_spoolss_reply_rrpcn: I think the spooler resonded that the notification was ignored.\n"));
	else if ( r.unknown0 != 0x0 )
		DEBUG(8,("cli_spoolss_reply_rrpcn: unknown0 is non-zero [0x%x]\n", r.unknown0));
	
	result = r.status;
	return result;
}

/*********************************************************************
 *********************************************************************/
 
WERROR rpccli_spoolss_rffpcnex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			    POLICY_HND *pol, uint32 flags, uint32 options,
			    const char *localmachine, uint32 printerlocal,
			    SPOOL_NOTIFY_OPTION *option)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_RFFPCNEX q;
	SPOOL_R_RFFPCNEX r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise input parameters */

	make_spoolss_q_rffpcnex(
		&q, pol, flags, options, localmachine, printerlocal,
		option);

	/* Marshall data and send request */

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_RFFPCNEX,
		q, r,
		qbuf, rbuf,
		spoolss_io_q_rffpcnex,
		spoolss_io_r_rffpcnex,
		WERR_GENERAL_FAILURE );

	result = r.status;
	return result;
}
