/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client generic functions
   Copyright (C) Andrew Tridgell              1994-2000
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

extern int DEBUGLEVEL;

/* create new connection.  strictly speaking, one arg should be
 * full dce/rpc format: e.g "ncalrpc:\\server\pipe\pipename" */
static cli_rpc_info *ncalrpc_connect_add(const char *pipe_name,
			     const vuser_key * key,
			     const char *srv_name,
			     const struct ntuser_creds *ntc,
			     BOOL reuse, BOOL *is_new_connection)
{
	cli_rpc_info *ret;
	become_root(False);
	ret = ncalrpc_l_use_add(pipe_name, key, reuse, is_new_connection);
	/*
	 * XXX - this rebinds on the same pipe,
	 * only necessary, when the loopback connection
	 * was first iniated as a forward
	 */
	*is_new_connection = True;
	unbecome_root(False);
	return ret;
}

/****************************************************************************
terminate client connection
****************************************************************************/
static void ncalrpc_connection_free(cli_rpc_info *con_info)
{
	struct msrpc_local *msrpc = (struct msrpc_local*)con_info;
	BOOL closed = False;
	DEBUG(10, ("msrpc local connection\n"));
	ncalrpc_l_use_del(msrpc->pipe_name,
			  &msrpc->nt.key, False, &closed);
}

/****************************************************************************
 get nt creds (HACK ALERT!) associated with an msrpc session.
****************************************************************************/
static struct ntdom_info *ncalrpc_conn_get_ntinfo(cli_rpc_info *con_info)
{
	struct msrpc_local *msrpc = (struct msrpc_local*)con_info;
	return &msrpc->nt;
}

/****************************************************************************
get a server name associated with a connection associated with a
policy handle.
****************************************************************************/
static const char *ncalrpc_con_get_srvname(cli_rpc_info *con_info)
{
#if NOHACK
	struct msrpc_local *msrpc = (struct msrpc_local*)con_info;
#endif
	return "\\\\.";
}

/****************************************************************************
 write to a pipe
****************************************************************************/
static BOOL ncalrpc_api_write(cli_rpc_info *con_info, prs_struct *data)
{
	struct msrpc_local *msrpc = (struct msrpc_local*)con_info;
	data->offset = prs_data_size(data);
	prs_link(NULL, data, NULL);
	return msrpc_send(msrpc->fd, data);
}

static BOOL ncalrpc_api_rcv_pdu(struct cli_connection *con,
		cli_rpc_info *con_info, prs_struct *rdata)
{
	struct msrpc_local *msrpc = (struct msrpc_local*)con_info;
	BOOL ret;
	ret = msrpc_send(msrpc->fd, NULL);
	ret = msrpc_receive(msrpc->fd, rdata);
	rdata->io = True;
	rdata->offset = 0;
	rdata->start = 0;
	rdata->end = prs_data_size(rdata);
	return ret;
}

/* this allows us to detect dead servers. The cli->fd is set to -1 when
   we get an error */
static BOOL ncalrpc_con_ok(cli_rpc_info *con_info)
{
	struct msrpc_local *msrpc = (struct msrpc_local*)con_info;
	if (msrpc == NULL)
		return False;
	if (msrpc->fd == -1)
		return False;
	return True;
}


static BOOL ncalrpc_api_send_rcv_pdu(struct cli_connection *con,
		cli_rpc_info *con_info, prs_struct *data,
			  prs_struct *rdata)
{
	struct msrpc_local *msrpc = (struct msrpc_local*)con_info;
	BOOL ret;
	data->offset = prs_data_size(data);
	prs_link(NULL, data, NULL);
	ret = msrpc_send(msrpc->fd, data) &&
		msrpc_receive(msrpc->fd, rdata);
	rdata->io = True;
	rdata->offset = 0;
	rdata->start = 0;
	rdata->end = prs_data_size(rdata);
	return ret;
}

static cli_connect_fns ncalrpc_fns = {
	ncalrpc_connect_add,
	ncalrpc_connection_free,
	ncalrpc_conn_get_ntinfo,
	ncalrpc_con_get_srvname,
	ncalrpc_api_write,
	ncalrpc_api_rcv_pdu,
	ncalrpc_con_ok,
	ncalrpc_api_send_rcv_pdu
};

cli_connect_fns *ncalrpc_get_fns(void)
{
	return &ncalrpc_fns;
}
