/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Gerald Carter                2001-2002,
   Copyright (C) Tim Potter                   2000-2002,
   Copyright (C) Andrew Tridgell              1994-2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
   Copyright (C) Jean-Francois Micouleau      1999-2000.

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

#include "includes.h"

/*
 * SPOOLSS Client RPC's used by servers as the notification
 * back channel.
 */

/* Send a ReplyOpenPrinter request.  This rpc is made by the printer
   server to the printer client in response to a rffpcnex request.
   The rrfpcnex request names a printer and a handle (the printerlocal
   value) and this rpc establishes a back-channel over which printer
   notifications are performed. */

WERROR cli_spoolss_reply_open_printer(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				      char *printer, uint32 printerlocal, uint32 type, 
				      POLICY_HND *handle)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_REPLYOPENPRINTER q;
	SPOOL_R_REPLYOPENPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);
	
	/* Initialise input parameters */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	make_spoolss_q_replyopenprinter(&q, printer, printerlocal, type);

	/* Marshall data and send request */

	if (!spoolss_io_q_replyopenprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req (cli, SPOOLSS_REPLYOPENPRINTER, &qbuf, &rbuf)) 
		goto done;
	
	/* Unmarshall response */
	
	if (spoolss_io_r_replyopenprinter("", &r, &rbuf, 0))
		goto done;
		
	/* Return result */

	memcpy(handle, &r.handle, sizeof(r.handle));
	result = r.status;

done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Close a back-channel notification connection */

WERROR cli_spoolss_reply_close_printer(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				       POLICY_HND *handle)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_REPLYCLOSEPRINTER q;
	SPOOL_R_REPLYCLOSEPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);

	/* Initialise input parameters */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	make_spoolss_q_reply_closeprinter(&q, handle);

	/* Marshall data and send request */

	if (!spoolss_io_q_replycloseprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req (cli, SPOOLSS_REPLYCLOSEPRINTER, &qbuf, &rbuf)) 
		goto done;
	
	/* Unmarshall response */
	
	if (spoolss_io_r_replycloseprinter("", &r, &rbuf, 0))
		goto done;
		
	/* Return result */

	result = r.status;
	
done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/*********************************************************************
 This SPOOLSS_ROUTERREPLYPRINTER function is used to send a change 
 notification event when the registration **did not** use 
 SPOOL_NOTIFY_OPTION_TYPE structure to specify the events to monitor.
 Also see cli_spolss_reply_rrpcn()
 *********************************************************************/
 
WERROR cli_spoolss_routerreplyprinter(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				      POLICY_HND *pol, uint32 condition, uint32 change_id)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ROUTERREPLYPRINTER q;
        SPOOL_R_ROUTERREPLYPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);

	/* Initialise input parameters */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	make_spoolss_q_routerreplyprinter(&q, pol, condition, change_id);

	/* Marshall data and send request */

	if (!spoolss_io_q_routerreplyprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req (cli, SPOOLSS_ROUTERREPLYPRINTER, &qbuf, &rbuf)) 
		goto done;
	
	/* Unmarshall response */
	
	if (spoolss_io_r_routerreplyprinter("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}

/*********************************************************************
 This SPOOLSS_REPLY_RRPCN function is used to send a change 
 notification event when the registration **did** use 
 SPOOL_NOTIFY_OPTION_TYPE structure to specify the events to monitor
 Also see cli_spoolss_routereplyprinter()
 *********************************************************************/

WERROR cli_spoolss_reply_rrpcn(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
			       POLICY_HND *pol, uint32 change_low,
			       uint32 change_high, SPOOL_NOTIFY_INFO *info)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_REPLY_RRPCN q;
	SPOOL_R_REPLY_RRPCN r;
	WERROR result = W_ERROR(ERRgeneral);

	/* Initialise input parameters */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	make_spoolss_q_reply_rrpcn(&q, pol, change_low, change_high, info);

	/* Marshall data and send request */

	if (!spoolss_io_q_reply_rrpcn("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_RRPCN, &qbuf, &rbuf)) 
		goto done;
	
	/* Unmarshall response */
	
	if (spoolss_io_r_reply_rrpcn("", &r, &rbuf, 0))
		goto done;

#if 0
	/*
	 * See comments in _spoolss_setprinter() about PRINTER_CHANGE_XXX
	 * events.  --jerry
	 */
	DEBUG(10,("cli_spoolss_reply_rrpcn: PRINTER_MESSAGE flags = 0x%8x\n", info->flags));

	data_len = build_notify_data(mem_ctx, printer, info->flags, &notify_data);
	if (info->flags && (data_len == -1)) {
		DEBUG(0,("cli_spoolss_reply_rrpcn: Failed to build SPOOL_NOTIFY_INFO_DATA [flags == 0x%x] for printer [%s]\n",
			info->flags, info->printer_name));
		result = WERR_NOMEM;
		goto done;
	}
	notify_info.version = 0x2;
	notify_info.flags   = 0x00020000;	/* ?? */
	notify_info.count   = data_len;
	notify_info.data    = notify_data;

	/* create and send a MSRPC command with api  */
	/* store the parameters */

	make_spoolss_q_reply_rrpcn(&q_s, handle, info->low, info->high, &notify_info);

	/* turn parameters into data stream */
	if(!spoolss_io_q_reply_rrpcn("", &q_s,  &buf, 0)) {
		DEBUG(0,("cli_spoolss_reply_rrpcn: Error : failed to marshall SPOOL_Q_REPLY_RRPCN struct.\n"));
		goto done;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, SPOOLSS_RRPCN, &buf, &rbuf)) 
		goto done;


	/* turn data stream into parameters*/
	if(!spoolss_io_r_reply_rrpcn("", &r_s, &rbuf, 0)) {
		DEBUG(0,("cli_spoolss_reply_rrpcn: Error : failed to unmarshall SPOOL_R_REPLY_RRPCN struct.\n"));
		goto done;
	}

#endif

	if (r.unknown0 == 0x00080000) {
		DEBUG(8,("cli_spoolss_reply_rrpcn: I think the spooler resonded that the notification was ignored.\n"));
	}

	result = r.status;

done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);
	
	return result;
}
