/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client generic functions
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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

struct user_creds *usr_creds = NULL;

extern int DEBUGLEVEL;
extern pstring scope;
extern pstring global_myname;

enum { MSRPC_NONE, MSRPC_LOCAL, MSRPC_SMB };

struct msrpc_smb
{
	struct cli_state *cli;
	uint16 fnum;
};

struct cli_connection
{
	uint32 num_connections;
	char *srv_name;
	char *pipe_name;
	struct user_creds usr_creds;

	int type;

	union
	{
		struct msrpc_smb *smb;
		struct msrpc_state *local;
		void* cli;
	} msrpc;
};

static struct cli_connection **con_list = NULL;
uint32 num_cons = 0;

void init_connections(void)
{
	con_list = NULL;
	num_cons = 0;

	init_cli_use();
}

static void free_con_array(uint32 num_entries, struct cli_connection **entries)
{
	void(*fn)(void*) = (void(*)(void*))&cli_connection_free;
	free_void_array(num_entries, (void**)entries, *fn);
}

static struct cli_connection* add_con_to_array(uint32 *len,
				struct cli_connection ***array,
				struct cli_connection *con)
{
	return (struct cli_connection*)add_item_to_array(len,
	                     (void***)array, (void*)con);
				
}
void free_connections(void)
{
	free_con_array(num_cons, con_list);
	free_cli_use();

	init_connections();
}

static struct cli_connection *cli_con_get(const char* srv_name,
				const char* pipe_name, BOOL reuse)
{
	struct cli_connection *con = NULL;

	con = (struct cli_connection*)malloc(sizeof(*con));

	if (con == NULL)
	{
		return NULL;
	}

	memset(con, 0, sizeof(*con));
	con->type = MSRPC_NONE;
	copy_user_creds(&con->usr_creds, usr_creds);
	con->usr_creds.reuse = reuse;

	if (srv_name != NULL)
	{
		con->srv_name = strdup(srv_name);
	}
	if (pipe_name != NULL)
	{
		con->pipe_name = strdup(pipe_name);
	}

	if (strequal(srv_name, "\\\\."))
	{
		con->type = MSRPC_LOCAL;
		con->usr_creds.reuse = False;
		con->msrpc.local = msrpc_use_add(&pipe_name[6], &con->usr_creds, False);
	}
	else
	{
		con->type = MSRPC_SMB;
		con->msrpc.smb = malloc(sizeof(*con->msrpc.smb));
		if (con->msrpc.smb == NULL)
		{
			cli_connection_free(con);
		}
		else
		{
			con->msrpc.smb->cli = cli_net_use_add(srv_name, &con->usr_creds.ntc, True, reuse);
			if (con->msrpc.smb->cli != NULL)
			{
				if (!cli_nt_session_open(con->msrpc.smb->cli,
						       pipe_name,
						       &con->msrpc.smb->fnum))
				{
					cli_connection_free(con);
					con->msrpc.cli = NULL;
				}
			}
			else
			{
				cli_connection_free(con);
				con->msrpc.cli = NULL;
			}
		}
	}
		
	if (con->msrpc.cli != NULL)
	{
		RPC_IFACE abstract;
		RPC_IFACE transfer;

		if (!rpc_pipe_bind(con, pipe_name,
				   &abstract, &transfer,
				   global_myname))
		{
			DEBUG(0,("rpc_pipe_bind failed\n"));
			cli_connection_free(con);
			con->msrpc.cli = NULL;
		}
	}

	if (con->msrpc.cli == NULL)
	{
		cli_connection_free(con);
		return NULL;
	}

	add_con_to_array(&num_cons, &con_list, con);
	return con;
}

/****************************************************************************
terminate client connection
****************************************************************************/
void cli_connection_free(struct cli_connection *con)
{
	BOOL closed;
	int i;

	if (con->msrpc.cli != NULL)
	{
		switch (con->type)
		{
			case MSRPC_LOCAL:
			{
				msrpc_use_del(con->srv_name, NULL, False, &closed);
				break;
			}
			case MSRPC_SMB:
			{
				if (con->msrpc.smb->cli != NULL)
				{
					cli_nt_session_close(con->msrpc.smb->cli,
							     con->msrpc.smb->fnum);
				}
				cli_net_use_del(con->srv_name, &con->usr_creds.ntc, False, &closed);
				break;
			}
		}
	}

	if (closed)
	{
		for (i = 0; i < num_cons; i++)
		{
			struct cli_connection *c = con_list[i];
			if (c != NULL &&
			    con != c &&
			    c->msrpc.cli == con->msrpc.cli)
			{
				/* WHOOPS! fnum already open: too bad!!!
				   get rid of all other connections that
				   were using that connection
				 */
				switch (c->type)
				{
					case MSRPC_LOCAL:
					{
						c->msrpc.local = NULL;
						break;
					}
					case MSRPC_SMB:
					{
						c->msrpc.smb->cli = NULL;
						c->msrpc.smb->fnum = 0xffff;
					}
				}
			}
		}
	}

	if (con->msrpc.cli != NULL)
	{
		free(con->msrpc.cli);
	}
	con->msrpc.cli = NULL;

	if (con->srv_name != NULL)
	{
		free(con->srv_name);
		con->srv_name = NULL;
	}
	if (con->pipe_name != NULL)
	{
		free(con->pipe_name);
		con->pipe_name = NULL;
	}

	memset(&con->usr_creds, 0, sizeof(con->usr_creds));

	for (i = 0; i < num_cons; i++)
	{
		if (con == con_list[i])
		{
			con_list[i] = NULL;
		}
	}

	free(con);
}

/****************************************************************************
terminate client state
****************************************************************************/
void cli_connection_unlink(struct cli_connection *con)
{
	if (con != NULL)
	{
		cli_connection_free(con);
	}
	return;
}

/****************************************************************************
init client state
****************************************************************************/
BOOL cli_connection_init(const char* srv_name, const char* pipe_name,
				struct cli_connection **con)
{
	BOOL res = True;
	BOOL reuse = False;

	/*
	 * allocate
	 */

	DEBUG(10,("cli_connection_init: %s %s\n", srv_name, pipe_name));

	*con = cli_con_get(srv_name, pipe_name, reuse);

	if ((*con) == NULL)
	{
		return False;
	}

	return res;
}

/****************************************************************************
obtain client state
****************************************************************************/
BOOL cli_connection_getsrv(const char* srv_name, const char* pipe_name,
				struct cli_connection **con)
{
	int i;
	if (con_list == NULL || num_cons == 0)
	{
		return False;
	}

	for (i = 0; i < num_cons; i++)
	{
		if (con_list[i] != NULL &&
		    strequal(con_list[i]->srv_name , srv_name ) &&
		    strequal(con_list[i]->pipe_name, pipe_name))
		{
			(*con) = con_list[i];
			return True;
		}
	}
	return False;
}

/****************************************************************************
obtain client state
****************************************************************************/
BOOL cli_connection_get(const POLICY_HND *pol, struct cli_connection **con)
{
	return get_policy_con(pol, con);
}

/****************************************************************************
link a child policy handle to a parent one
****************************************************************************/
BOOL cli_pol_link(POLICY_HND *to, const POLICY_HND *from)
{
	struct cli_connection *con = NULL;

	if (!cli_connection_get(from, &con))
	{
		return False;
	}

	return register_policy_hnd(to) && set_policy_con(to, con, NULL);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_get_con_usr_sesskey(struct cli_connection *con, uchar usr_sess_key[16])
{
	char *src_key = NULL;

	if (con == NULL)
	{
		return False;
	}
	switch (con->type)
	{
		case MSRPC_LOCAL:
		{
			src_key = con->msrpc.local->usr.ntc.pwd.sess_key;
			break;
		}
		case MSRPC_SMB:
		{
			src_key = con->msrpc.smb->cli->usr.pwd.sess_key;
			break;
		}
		default:
		{
			return False;
		}
	}
	memcpy(usr_sess_key, src_key, 16);

	return True;
}

/****************************************************************************
 get nt creds associated with an msrpc session.
****************************************************************************/
struct ntuser_creds *cli_conn_get_usercreds(struct cli_connection *con)
{
	switch (con->type)
	{
		case MSRPC_LOCAL:
		{
			return &con->msrpc.local->usr.ntc;
		}
		case MSRPC_SMB:
		{
			return &con->msrpc.smb->cli->usr;
		}
	}
	return NULL;
}

/****************************************************************************
 get nt creds (HACK ALERT!) associated with an msrpc session.
****************************************************************************/
struct ntdom_info * cli_conn_get_ntinfo(struct cli_connection *con)
{
	switch (con->type)
	{
		case MSRPC_LOCAL:
		{
			return &con->msrpc.local->nt;
		}
		case MSRPC_SMB:
		{
			return &con->msrpc.smb->cli->nt;
		}
	}
	return NULL;
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_get_con_sesskey(struct cli_connection *con, uchar sess_key[16])
{
	struct ntdom_info *nt;
	if (con == NULL)
	{
		return False;
	}
	nt = cli_conn_get_ntinfo(con);
	memcpy(sess_key, nt->sess_key, sizeof(nt->sess_key));

	return True;
}

/****************************************************************************
get a server name associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_con_get_srvname(struct cli_connection *con, char *srv_name)
{
	char *desthost = NULL;

	if (con == NULL)
	{
		return False;
	}

	switch (con->type)
	{
		case MSRPC_SMB:
		{
			desthost = con->msrpc.smb->cli->desthost;
			break;
		}
		case MSRPC_LOCAL:
		{
			desthost = con->srv_name;
			break;
		}
	}

	if (strnequal("\\\\", desthost, 2))
	{
		fstrcpy(srv_name, desthost);
	}
	else
	{
		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, desthost);
	}
	
	return True;
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_get_usr_sesskey(const POLICY_HND *pol, uchar usr_sess_key[16])
{
	struct cli_connection *con = NULL;

	if (!cli_connection_get(pol, &con))
	{
		return False;
	}

	return cli_get_con_usr_sesskey(con, usr_sess_key);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_get_sesskey(const POLICY_HND *pol, uchar sess_key[16])
{
	struct cli_connection *con = NULL;

	if (!cli_connection_get(pol, &con))
	{
		return False;
	}

	return cli_get_con_sesskey(con, sess_key);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_get_sesskey_srv(const char* srv_name, uchar sess_key[16])
{
	struct cli_connection *con = NULL;

	if (!cli_connection_getsrv(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

	return cli_get_con_sesskey(con, sess_key);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
void cli_con_gen_next_creds(struct cli_connection *con,
				DOM_CRED *new_clnt_cred)
{
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	gen_next_creds(nt, new_clnt_cred);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
void cli_con_get_cli_cred(struct cli_connection *con,
				DOM_CRED *clnt_cred)
{
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	memcpy(clnt_cred, &nt->clnt_cred, sizeof(*clnt_cred));
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_con_deal_with_creds(struct cli_connection *con,
				DOM_CRED *rcv_srv_cred)
{
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	return clnt_deal_with_creds(nt->sess_key, &nt->clnt_cred, rcv_srv_cred);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_con_set_creds(const char* srv_name, const uchar sess_key[16],
				DOM_CRED *cred)
{
	struct cli_connection *con = NULL;
	struct ntdom_info *nt;

	if (!cli_connection_getsrv(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

	nt = cli_conn_get_ntinfo(con);

	memcpy(nt->sess_key, sess_key, 16);
	memcpy(&nt->clnt_cred, cred, sizeof(*cred));

	return True;
}

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
BOOL rpc_hnd_pipe_req(const POLICY_HND *hnd, uint8 op_num,
                      prs_struct *data, prs_struct *rdata)
{
	struct cli_connection *con = NULL;

	if (!cli_connection_get(hnd, &con))
	{
		return False;
	}

	return rpc_con_pipe_req(con, op_num, data, rdata);
}

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
BOOL rpc_con_pipe_req(struct cli_connection *con, uint8 op_num,
                      prs_struct *data, prs_struct *rdata)
{
	DEBUG(10,("rpc_con_pipe_req: op_num %d offset %d used: %d\n",
			op_num, data->offset, data->data->data_used));
	data->data->margin = 0;
	mem_realloc_data(data->data, data->offset);
	return rpc_api_pipe_req(con, op_num, data, rdata);
}

/****************************************************************************
 write to a pipe
****************************************************************************/
BOOL rpc_api_write(struct cli_connection *con, prs_struct *data)
{
	switch (con->type)
	{
		case MSRPC_SMB:
		{
			struct cli_state *cli = con->msrpc.smb->cli;
			int fnum = con->msrpc.smb->fnum;
			return cli_write(cli, fnum, 0x0008, 
			          data->data->data, 0,
			          data->data->data_used,
			          data->data->data_used) > 0;
		}
		case MSRPC_LOCAL:
		{
			data->offset = data->data->data_size;
			prs_link(NULL, data, NULL);
			return msrpc_send_prs(con->msrpc.local, data);
		}
	}
	return False;
}

BOOL rpc_api_rcv_pdu(struct cli_connection *con, prs_struct *rdata)
{
	switch (con->type)
	{
		case MSRPC_SMB:
		{
			struct cli_state *cli = con->msrpc.smb->cli;
			int fnum = con->msrpc.smb->fnum;
			return cli_rcv_pdu(cli, fnum, rdata);
		}
		case MSRPC_LOCAL:
		{
			BOOL ret;
			ret = msrpc_send_prs(con->msrpc.local, NULL);
			ret = msrpc_receive_prs(con->msrpc.local, rdata);
			rdata->io = True;
			rdata->offset = 0;
			rdata->data->offset.start = 0;
			rdata->data->offset.end = rdata->data->data_used;
			return ret;
		}
	}
	return False;
}

BOOL rpc_api_send_rcv_pdu(struct cli_connection *con, prs_struct *data,
				prs_struct *rdata)
{
	switch (con->type)
	{
		case MSRPC_SMB:
		{
			struct ntdom_info *nt = cli_conn_get_ntinfo(con);
			struct cli_state *cli = con->msrpc.smb->cli;
			int fnum = con->msrpc.smb->fnum;
			return cli_send_and_rcv_pdu(cli, fnum, data, rdata,
			                            nt->max_xmit_frag);
		}
		case MSRPC_LOCAL:
		{
			BOOL ret;
			data->offset = data->data->data_size;
			prs_link(NULL, data, NULL);
			ret = msrpc_send_prs(con->msrpc.local, data) &&
			      msrpc_receive_prs(con->msrpc.local, rdata);
			rdata->io = True;
			rdata->offset = 0;
			rdata->data->offset.start = 0;
			rdata->data->offset.end = rdata->data->data_used;
			return ret;
		}
	}
	return False;
}
