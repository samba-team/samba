/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean Francois Micouleau      1998-2000,
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
#if 0
#include "rpc_parse.h"
#include "nterr.h"
#endif
extern pstring global_myname;

struct msg_info_table {
	uint32 msg;
	uint32 field;
	const char *name;
	void (*construct_fn) (int snum, SPOOL_NOTIFY_INFO_DATA *data,
		print_queue_struct *queue,
		NT_PRINTER_INFO_LEVEL *printer, TALLOC_CTX *mem_ctx);
};

struct msg_info_table msg_table[] = {
{ PRINTER_MESSAGE_DRIVER,      PRINTER_NOTIFY_DRIVER_NAME,    "PRINTER_MESSAGE_DRIVER",      spoolss_notify_driver_name  },
{ PRINTER_MESSAGE_ATTRIBUTES,  PRINTER_NOTIFY_ATTRIBUTES,     "PRINTER_MESSAGE_ATTRIBUTES",  spoolss_notify_attributes   },
{ PRINTER_MESSAGE_COMMENT,     PRINTER_NOTIFY_COMMENT,        "PRINTER_MESSAGE_COMMENT",     spoolss_notify_comment      },
{ PRINTER_MESSAGE_LOCATION,    PRINTER_NOTIFY_LOCATION,       "PRINTER_MESSAGE_LOCATION",    spoolss_notify_location     },
{ PRINTER_MESSAGE_PRINTERNAME, PRINTER_NOTIFY_PRINTER_NAME,   "PRINTER_MESSAGE_PRINTERNAME", spoolss_notify_printer_name },
{ PRINTER_MESSAGE_SHARENAME,   PRINTER_NOTIFY_SHARE_NAME,     "PRINTER_MESSAGE_SHARENAME",   spoolss_notify_share_name   },
{ PRINTER_MESSAGE_PORT,        PRINTER_NOTIFY_PORT_NAME,      "PRINTER_MESSAGE_PORT",        spoolss_notify_port_name    },
{ PRINTER_MESSAGE_CJOBS,       PRINTER_NOTIFY_CJOBS,          "PRINTER_MESSAGE_CJOBS",       spoolss_notify_cjobs        },
{ PRINTER_MESSAGE_SEPFILE,     PRINTER_NOTIFY_SEPFILE,        "PRINTER_MESSAGE_SEPFILE",     spoolss_notify_sepfile      },
{ PRINTER_MESSAGE_PARAMS,      PRINTER_NOTIFY_PARAMETERS,     "PRINTER_MESSAGE_PARAMETERS",  spoolss_notify_parameters   },
{ PRINTER_MESSAGE_DATATYPE,    PRINTER_NOTIFY_DATATYPE,       "PRINTER_MESSAGE_DATATYPE",    spoolss_notify_datatype     },
{ PRINTER_MESSAGE_NULL,        0x0,                           "",                            NULL                        },
};

/*********************************************************
 Disconnect from the client machine.
**********************************************************/
BOOL spoolss_disconnect_from_client( struct cli_state *cli)
{
	cli_nt_session_close(cli);
	cli_ulogoff(cli);
	cli_shutdown(cli);

	return True;
}


/*********************************************************
 Connect to the client machine.
**********************************************************/

BOOL spoolss_connect_to_client( struct cli_state *cli, char *remote_machine)
{
	ZERO_STRUCTP(cli);
	if(cli_initialise(cli) == NULL) {
		DEBUG(0,("connect_to_client: unable to initialize client connection.\n"));
		return False;
	}

	if(!resolve_name( remote_machine, &cli->dest_ip, 0x20)) {
		DEBUG(0,("connect_to_client: Can't resolve address for %s\n", remote_machine));
		cli_shutdown(cli);
	return False;
	}

	if (ismyip(cli->dest_ip)) {
		DEBUG(0,("connect_to_client: Machine %s is one of our addresses. Cannot add to ourselves.\n", remote_machine));
		cli_shutdown(cli);
		return False;
	}

	if (!cli_connect(cli, remote_machine, &cli->dest_ip)) {
		DEBUG(0,("connect_to_client: unable to connect to SMB server on machine %s. Error was : %s.\n", remote_machine, cli_errstr(cli) ));
		cli_shutdown(cli);
		return False;
	}
  
	if (!attempt_netbios_session_request(cli, global_myname, remote_machine, &cli->dest_ip)) {
		DEBUG(0,("connect_to_client: machine %s rejected the NetBIOS session request.\n", 
			remote_machine));
		cli_shutdown(cli);
		return False;
	}

	cli->protocol = PROTOCOL_NT1;
    
	if (!cli_negprot(cli)) {
		DEBUG(0,("connect_to_client: machine %s rejected the negotiate protocol. Error was : %s.\n", remote_machine, cli_errstr(cli) ));
		cli_shutdown(cli);
		return False;
	}

	if (cli->protocol != PROTOCOL_NT1) {
		DEBUG(0,("connect_to_client: machine %s didn't negotiate NT protocol.\n", remote_machine));
		cli_shutdown(cli);
		return False;
	}
    
	/*
	 * Do an anonymous session setup.
	 */
    
	if (!cli_session_setup(cli, "", "", 0, "", 0, "")) {
		DEBUG(0,("connect_to_client: machine %s rejected the session setup. Error was : %s.\n", remote_machine, cli_errstr(cli) ));
		cli_shutdown(cli);
		return False;
	}
    
	if (!(cli->sec_mode & NEGOTIATE_SECURITY_USER_LEVEL)) {
		DEBUG(0,("connect_to_client: machine %s isn't in user level security mode\n", remote_machine));
		cli_shutdown(cli);
		return False;
	}
    
	if (!cli_send_tconX(cli, "IPC$", "IPC", "", 1)) {
		DEBUG(0,("connect_to_client: machine %s rejected the tconX on the IPC$ share. Error was : %s.\n", remote_machine, cli_errstr(cli) ));
		cli_shutdown(cli);
		return False;
	}

	/*
	 * Ok - we have an anonymous connection to the IPC$ share.
	 * Now start the NT Domain stuff :-).
	 */

	if(cli_nt_session_open(cli, PIPE_SPOOLSS) == False) {
		DEBUG(0,("connect_to_client: unable to open the domain client session to machine %s. Error was : %s.\n", remote_machine, cli_errstr(cli)));
		cli_nt_session_close(cli);
		cli_ulogoff(cli);
		cli_shutdown(cli);
		return False;
	} 

	return True;
}

/*
 * SPOOLSS Client RPC's used by servers as the notification
 * back channel
 */

 /***************************************************************************
 do a reply open printer
****************************************************************************/

WERROR cli_spoolss_reply_open_printer(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				char *printer, uint32 localprinter, uint32 type, 
				POLICY_HND *handle)
{
	WERROR result = W_ERROR(ERRgeneral);
	
	prs_struct rbuf;
	prs_struct buf; 

	SPOOL_Q_REPLYOPENPRINTER q_s;
	SPOOL_R_REPLYOPENPRINTER r_s;

	prs_init(&buf, 1024, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL );

	/* create and send a MSRPC command with api SPOOLSS_REPLYOPENPRINTER */
	
	/* store the parameters */
	make_spoolss_q_replyopenprinter(&q_s, printer, localprinter, type);

	/* turn parameters into data stream */
	if(!spoolss_io_q_replyopenprinter("", &q_s,  &buf, 0)) {
		DEBUG(0,("cli_spoolss_reply_open_printer: Error : failed to marshall SPOOL_Q_REPLYOPENPRINTER struct.\n"));
		goto done;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, SPOOLSS_REPLYOPENPRINTER, &buf, &rbuf)) 
		goto done;
	
	/* turn data stream into parameters*/
	if(!spoolss_io_r_replyopenprinter("", &r_s, &rbuf, 0)) {
		DEBUG(0,("cli_spoolss_reply_open_printer: Error : failed to unmarshall SPOOL_R_REPLYOPENPRINTER struct.\n"));
		goto done;
	}
	
	memcpy(handle, &r_s.handle, sizeof(r_s.handle));
	result = r_s.status;

done:
	prs_mem_free(&buf);
	prs_mem_free(&rbuf);

	return result;
}

/***************************************************************************
 do a reply open printer
****************************************************************************/

WERROR cli_spoolss_reply_close_printer(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
					POLICY_HND *handle)
{
	WERROR result = W_ERROR(ERRgeneral);
	prs_struct rbuf;
	prs_struct buf; 

	SPOOL_Q_REPLYCLOSEPRINTER q_s;
	SPOOL_R_REPLYCLOSEPRINTER r_s;

	prs_init(&buf, 1024, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL );

	/* create and send a MSRPC command with api  */
	
	/* store the parameters */
	make_spoolss_q_reply_closeprinter(&q_s, handle);

	/* turn parameters into data stream */
	if(!spoolss_io_q_replycloseprinter("", &q_s,  &buf, 0)) {
		DEBUG(0,("cli_spoolss_reply_close_printer: Error : failed to marshall SPOOL_Q_REPLY_CLOSEPRINTER struct.\n"));
		goto done;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, SPOOLSS_REPLYCLOSEPRINTER, &buf, &rbuf))
		goto done;

	/* turn data stream into parameters*/
	if(!spoolss_io_r_replycloseprinter("", &r_s, &rbuf, 0)) {
		DEBUG(0,("cli_spoolss_reply_close_printer: Error : failed to marshall SPOOL_R_REPLY_CLOSEPRINTER struct.\n"));
		goto done;
	}
	

	result = r_s.status;
	
done:
	prs_mem_free(&buf);
	prs_mem_free(&rbuf);

	return result;
}

 
/*********************************************************************
 This SPOOLSS_ROUTERREPLYPRINTER function is used to send a change 
 notification event when the registration **did not** use 
 SPOOL_NOTIFY_OPTION_TYPE structure to specify the events to monitor.
 Also see cli_spolss_reply_rrpcn()
 *********************************************************************/
 
WERROR cli_spoolss_routerreplyprinter (struct cli_state *cli, TALLOC_CTX *mem_ctx,
					POLICY_HND *pol, uint32 condition, uint32 changd_id)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ROUTERREPLYPRINTER q;
        SPOOL_R_ROUTERREPLYPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);


	/* Initialise input parameters */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);


	/* write the request */
	make_spoolss_q_routerreplyprinter(&q, pol, condition, changd_id);

	/* Marshall data and send request */
	if (!spoolss_io_q_routerreplyprinter ("", &q, &qbuf, 0)) {
		DEBUG(0,("cli_spoolss_routerreplyprinter: Unable to marshall SPOOL_Q_ROUTERREPLYPRINTER!\n"));
		goto done;
	}
		
		
	if (!rpc_api_pipe_req (cli, SPOOLSS_ROUTERREPLYPRINTER, &qbuf, &rbuf)) 
		goto done;

	/* Unmarshall response */
	if (!spoolss_io_r_routerreplyprinter ("", &r, &rbuf, 0)) {
		DEBUG(0,("cli_spoolss_routerreplyprinter: Unable to unmarshall SPOOL_R_ROUTERREPLYPRINTER!\n"));
		goto done;
	}
		
	/* Return output parameters */
	result = r.status;

done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}


/**********************************************************************************
 Build the SPOOL_NOTIFY_INFO_DATA entries based upon the flags which have been set
 *********************************************************************************/

static int build_notify_data (TALLOC_CTX *ctx, NT_PRINTER_INFO_LEVEL *printer, uint32 flags, 
			SPOOL_NOTIFY_INFO_DATA **notify_data)
{
	SPOOL_NOTIFY_INFO_DATA *data;
	uint32 idx = 0;
	int i = 0;
	
	while ((msg_table[i].msg != PRINTER_MESSAGE_NULL) && flags)
	{
		if (flags & msg_table[i].msg) 
		{
			DEBUG(10,("build_notify_data: %s set on [%s][%d]\n", msg_table[i].name,
				printer->info_2->printername, idx));
			if ((data=Realloc(*notify_data, (idx+1)*sizeof(SPOOL_NOTIFY_INFO_DATA))) == NULL) {
				DEBUG(0,("build_notify_data: Realloc() failed with size [%d]!\n",
					(idx+1)*sizeof(SPOOL_NOTIFY_INFO_DATA)));
				return -1;
			}
			*notify_data = data;

			/* clear memory */
			memset(*notify_data+idx, 0x0, sizeof(SPOOL_NOTIFY_INFO_DATA));

			/*
			 * 'id' (last param here) is undefined when type == PRINTER_NOTIFY_TYPE
			 * See PRINTER_NOTIFY_INFO_DATA entries in MSDN
			 * --jerry
			 */
			construct_info_data(*notify_data+idx, PRINTER_NOTIFY_TYPE, msg_table[i].field, 0x00);

			msg_table[i].construct_fn(-1, *notify_data+idx, NULL, printer, ctx);
			idx++;
		}
		
		i++;
	}
	
	return idx;
}

/*********************************************************************
 This SPOOLSS_ROUTERREPLYPRINTER function is used to send a change 
 notification event when the registration **did** use 
 SPOOL_NOTIFY_OPTION_TYPE structure to specify the events to monitor
 Also see cli_spoolss_routereplyprinter()
 *********************************************************************/

WERROR cli_spoolss_reply_rrpcn(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
					POLICY_HND *handle, PRINTER_MESSAGE_INFO *info,
					NT_PRINTER_INFO_LEVEL *printer)
{
	prs_struct rbuf;
	prs_struct buf;

	SPOOL_NOTIFY_INFO 	notify_info;
	SPOOL_NOTIFY_INFO_DATA	*notify_data = NULL;
	uint32 			data_len;

	WERROR result = W_ERROR(ERRgeneral);

	SPOOL_Q_REPLY_RRPCN q_s;
	SPOOL_R_REPLY_RRPCN r_s;

	if (!info) {
		DEBUG(5,("cli_spoolss_reply_rrpcn: NULL printer message info pointer!\n"));
		goto done;
	}
		
	prs_init(&buf, 1024, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0,   mem_ctx, UNMARSHALL );

	ZERO_STRUCT(notify_info);

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

	if (r_s.unknown0 == 0x00080000) {
		DEBUG(8,("cli_spoolss_reply_rrpcn: I think the spooler resonded that the notification was ignored.\n"));
	}

	result = r_s.status;

done:
	prs_mem_free(&buf);
	prs_mem_free(&rbuf);
	/*
	 * The memory allocated in this array is talloc'd so we only need
	 * free the array here. JRA.
	 */
	SAFE_FREE(notify_data);
	
	return result;
}

