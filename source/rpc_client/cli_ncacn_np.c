/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   DCE/RPC client ncacn_np functions
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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

#define NO_SYSLOG

#include "includes.h"
#include "rpc_parse.h"
#include "rpc_client.h"

/* create new connection.  strictly speaking, one arg should be
 * full dce/rpc format: e.g "ncacn_np:\\server\pipe\pipename" */
static cli_rpc_info *ncacn_np_connect_add(const char *pipe_name,
			     const vuser_key * key,
			     const char *srv_name,
			     const struct ntuser_creds *ntc,
			     BOOL reuse, BOOL *is_new_connection)
{
	return ncacn_np_use_add(pipe_name, NULL, srv_name,
				ntc, reuse, is_new_connection);

}

/****************************************************************************
terminate client connection
****************************************************************************/
static void ncacn_np_connection_free(cli_rpc_info *con_info)
{
	struct ncacn_np *msrpc = (struct ncacn_np*)con_info;
	BOOL closed = False;
	DEBUG(10, ("msrpc smb connection\n"));
	ncacn_np_use_del(msrpc->smb->desthost,
			 msrpc->pipe_name,
			 &msrpc->smb->nt.key, False, &closed);
}

/****************************************************************************
 get nt creds (HACK ALERT!) associated with an msrpc session.
****************************************************************************/
static struct ntdom_info *ncacn_np_conn_get_ntinfo(cli_rpc_info *con_info)
{
	struct ncacn_np *msrpc = (struct ncacn_np*)con_info;
	return &msrpc->smb->nt;
}


/****************************************************************************
get a server name associated with a connection associated with a
policy handle.
****************************************************************************/
static const char *ncacn_np_con_get_srvname(cli_rpc_info *con_info)
{
	struct ncacn_np *msrpc = (struct ncacn_np*)con_info;
	return msrpc->smb->desthost;
}

/****************************************************************************
 write to a pipe
****************************************************************************/
static BOOL ncacn_np_api_write(cli_rpc_info *con_info, prs_struct *data)
{
	struct ncacn_np *msrpc = (struct ncacn_np*)con_info;
	struct cli_state *cli = msrpc->smb;
	int fnum = msrpc->fnum;
	return cli_write(cli, fnum, 0x0008,
			 data->data, 0,
			 prs_data_size(data), prs_data_size(data)) > 0;
}

static BOOL ncacn_np_api_rcv_pdu(struct cli_connection *con,
		cli_rpc_info *con_info, prs_struct *rdata)
{
	struct ncacn_np *msrpc = (struct ncacn_np*)con_info;
	struct cli_state *cli = msrpc->smb;
	int fnum = msrpc->fnum;
	return cli_rcv_pdu(con, cli, fnum, rdata);
}

/* this allows us to detect dead servers. The cli->fd is set to -1 when
   we get an error */
static BOOL ncacn_np_con_ok(cli_rpc_info *con_info)
{
	struct ncacn_np *msrpc = (struct ncacn_np*)con_info;
	struct cli_state *cli;
	if (msrpc == NULL)
		return False;
	cli = msrpc->smb;
	if (cli->fd == -1)
		return False;
	return True;
}


static BOOL ncacn_np_api_send_rcv_pdu(struct cli_connection *con,
		cli_rpc_info *con_info, prs_struct *data,
			  prs_struct *rdata)
{
	struct ncacn_np *msrpc = (struct ncacn_np*)con_info;
	struct ntdom_info *nt = ncacn_np_conn_get_ntinfo(con_info);
	struct cli_state *cli = msrpc->smb;
	int fnum = msrpc->fnum;
	if (cli->fd == -1)
		return False;
	return cli_send_and_rcv_pdu(con, cli, fnum, data,
				    rdata, nt->max_xmit_frag);
}

static cli_connect_fns ncacn_np_fns = 
{
	ncacn_np_connect_add,
	ncacn_np_connection_free,
	ncacn_np_conn_get_ntinfo,
	ncacn_np_con_get_srvname,
	ncacn_np_api_write,
	ncacn_np_api_rcv_pdu,
	ncacn_np_con_ok,
	ncacn_np_api_send_rcv_pdu

};

cli_connect_fns *ncacn_np_get_fns(void)
{
	return &ncacn_np_fns;
}

