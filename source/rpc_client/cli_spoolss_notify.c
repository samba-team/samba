/*
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
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
#include "rpc_parse.h"
#include "rpc_client.h"
#include "nterr.h"

extern int DEBUGLEVEL;
extern pstring global_myname;

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
	if(cli_initialise(cli) == False) {
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
    
	if (!(cli->sec_mode & 1)) {
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

/***************************************************************************
 do a reply open printer
****************************************************************************/

BOOL cli_spoolss_reply_open_printer(struct cli_state *cli, char *printer, uint32 localprinter, uint32 type, uint32 *status, POLICY_HND *handle)
{
	prs_struct rbuf;
	prs_struct buf; 

	SPOOL_Q_REPLYOPENPRINTER q_s;
	SPOOL_R_REPLYOPENPRINTER r_s;

	prs_init(&buf , 1024, 4, cli->mem_ctx, False);
	prs_init(&rbuf, 0,    4, cli->mem_ctx, True );

	/* create and send a MSRPC command with api SPOOLSS_REPLYOPENPRINTER */
/*
	DEBUG(4,("cli_spoolss_reply_open_printer: srv:%s acct:%s sc: %d mc: %s clnt %s %x\n",
           cli->srv_name_slash, cli->mach_acct, sec_chan_type, global_myname,
           credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time));
*/
	/* store the parameters */
	make_spoolss_q_replyopenprinter(&q_s, printer, localprinter, type);

	/* turn parameters into data stream */
	if(!spoolss_io_q_replyopenprinter("", &q_s,  &buf, 0)) {
		DEBUG(0,("cli_spoolss_reply_open_printer: Error : failed to marshall NET_Q_SRV_PWSET struct.\n"));
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, SPOOLSS_REPLYOPENPRINTER, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);
	
	/* turn data stream into parameters*/
	if(!spoolss_io_r_replyopenprinter("", &r_s, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}
	
	prs_mem_free(&rbuf);

	memcpy(handle, &r_s.handle, sizeof(r_s.handle));
	*status=r_s.status;

	return True;
}

/***************************************************************************
 do a reply open printer
****************************************************************************/

BOOL cli_spoolss_reply_rrpcn(struct cli_state *cli, POLICY_HND *handle, 
			     uint32 change_low, uint32 change_high, uint32 *status)
{
	prs_struct rbuf;
	prs_struct buf; 

	SPOOL_Q_REPLY_RRPCN q_s;
	SPOOL_R_REPLY_RRPCN r_s;

	prs_init(&buf , 1024, 4, cli->mem_ctx, False);
	prs_init(&rbuf, 0,    4, cli->mem_ctx, True );

	/* create and send a MSRPC command with api  */
/*
	DEBUG(4,("cli_spoolss_reply_open_printer: srv:%s acct:%s sc: %d mc: %s clnt %s %x\n",
           cli->srv_name_slash, cli->mach_acct, sec_chan_type, global_myname,
           credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time));
*/
	/* store the parameters */
	make_spoolss_q_reply_rrpcn(&q_s, handle, change_low, change_high);

	/* turn parameters into data stream */
	if(!spoolss_io_q_reply_rrpcn("", &q_s,  &buf, 0)) {
		DEBUG(0,("cli_spoolss_reply_rrpcn: Error : failed to marshall SPOOL_Q_REPLY_RRPCN struct.\n"));
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, SPOOLSS_RRPCN, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);
	
	/* turn data stream into parameters*/
	if(!spoolss_io_r_reply_rrpcn("", &r_s, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}
	
	prs_mem_free(&rbuf);

	*status=r_s.status;

	return True;
}

/***************************************************************************
 do a reply open printer
****************************************************************************/

BOOL cli_spoolss_reply_close_printer(struct cli_state *cli, POLICY_HND *handle, uint32 *status)
{
	prs_struct rbuf;
	prs_struct buf; 

	SPOOL_Q_REPLYCLOSEPRINTER q_s;
	SPOOL_R_REPLYCLOSEPRINTER r_s;

	prs_init(&buf , 1024, 4, cli->mem_ctx, False);
	prs_init(&rbuf, 0,    4, cli->mem_ctx, True );

	/* create and send a MSRPC command with api  */
/*
	DEBUG(4,("cli_spoolss_reply_open_printer: srv:%s acct:%s sc: %d mc: %s clnt %s %x\n",
           cli->srv_name_slash, cli->mach_acct, sec_chan_type, global_myname,
           credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time));
*/
	/* store the parameters */
	make_spoolss_q_reply_closeprinter(&q_s, handle);

	/* turn parameters into data stream */
	if(!spoolss_io_q_replycloseprinter("", &q_s,  &buf, 0)) {
		DEBUG(0,("cli_spoolss_reply_close_printer: Error : failed to marshall SPOOL_Q_REPLY_CLOSEPRINTER struct.\n"));
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, SPOOLSS_REPLYCLOSEPRINTER, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);
	
	/* turn data stream into parameters*/
	if(!spoolss_io_r_replycloseprinter("", &r_s, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}
	
	prs_mem_free(&rbuf);

	*status=r_s.status;

	return True;
}

