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

struct user_credentials *usr_creds = NULL;

extern int DEBUGLEVEL;
extern pstring scope;
extern pstring global_myname;

struct cli_connection
{
	uint32 num_connections;
	char *srv_name;
	char *pipe_name;
	struct user_credentials usr_creds;
	struct cli_state *cli;
	uint16 fnum;
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

static struct cli_connection *cli_con_getlist(char* servers,
				const char* pipe_name)
{
	struct cli_connection *con = NULL;

	con = (struct cli_connection*)malloc(sizeof(*con));

	if (con == NULL)
	{
		return NULL;
	}

	memset(con, 0, sizeof(*con));

	if (servers != NULL)
	{
		con->srv_name = strdup(servers);
	}
	if (pipe_name != NULL)
	{
		con->pipe_name = strdup(pipe_name);
	}

	con->cli = cli_net_use_addlist(servers, usr_creds);

	if (con->cli == NULL)
	{
		cli_connection_free(con);
		return NULL;
	}
	add_con_to_array(&num_cons, &con_list, con);
	return con;
}

static struct cli_connection *cli_con_get(const char* srv_name,
				const char* pipe_name)
{
	struct cli_connection *con = NULL;

	con = (struct cli_connection*)malloc(sizeof(*con));

	if (con == NULL)
	{
		return NULL;
	}

	memset(con, 0, sizeof(*con));

	if (srv_name != NULL)
	{
		con->srv_name = strdup(srv_name);
	}
	if (pipe_name != NULL)
	{
		con->pipe_name = strdup(pipe_name);
	}

	con->cli = cli_net_use_add(srv_name, usr_creds);

	if (con->cli == NULL)
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

	if (con->cli != NULL)
	{
		cli_nt_session_close(con->cli, con->fnum);
		cli_net_use_del(con->srv_name, &con->usr_creds, False, &closed);
	}

	if (closed)
	{
		for (i = 0; i < num_cons; i++)
		{
			if (con != con_list[i] && con_list[i]->cli == con->cli)
			{
				/* WHOOPS! fnum already open: too bad!!! */
				con_list[i]->cli = NULL;
				con_list[i]->fnum = 0xffff;
			}
		}
	}

	con->cli = NULL;

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
BOOL cli_connection_init_list(char* servers, const char* pipe_name,
				struct cli_connection **con)
{
	BOOL res = True;

	/*
	 * allocate
	 */

	*con = cli_con_getlist(servers, pipe_name);

	if ((*con) == NULL)
	{
		return False;
	}

	res = res ? cli_nt_session_open((*con)->cli, pipe_name,
	                               &(*con)->fnum) : False;

	return res;
}

/****************************************************************************
init client state
****************************************************************************/
BOOL cli_connection_init(const char* srv_name, const char* pipe_name,
				struct cli_connection **con)
{
	BOOL res = True;

	/*
	 * allocate
	 */

	*con = cli_con_get(srv_name, pipe_name);

	if ((*con) == NULL)
	{
		return False;
	}

	res = res ? cli_nt_session_open((*con)->cli, pipe_name,
	                               &(*con)->fnum) : False;

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
BOOL cli_get_con_sesskey(struct cli_connection *con, uchar sess_key[16])
{
	if (con == NULL)
	{
		return False;
	}
	memcpy(sess_key, con->cli->sess_key, sizeof(con->cli->sess_key));

	return True;
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_con_get_srvname(struct cli_connection *con, char *srv_name)
{
	if (con == NULL)
	{
		return False;
	}

	if (strnequal("\\\\", con->cli->desthost, 2))
	{
		fstrcpy(srv_name, con->cli->desthost);
	}
	else
	{
		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, con->cli->desthost);
	}
	
	return True;
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
	gen_next_creds(con->cli, new_clnt_cred);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
void cli_con_get_cli_cred(struct cli_connection *con,
				DOM_CRED *clnt_cred)
{
	memcpy(clnt_cred, &con->cli->clnt_cred, sizeof(*clnt_cred));
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_con_deal_with_creds(struct cli_connection *con,
				DOM_CRED *rcv_srv_cred)
{
	return clnt_deal_with_creds(con->cli->sess_key, &con->cli->clnt_cred,
				rcv_srv_cred);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_con_set_creds(const char* srv_name, const uchar sess_key[16],
				DOM_CRED *cred)
{
	struct cli_connection *con = NULL;

	if (!cli_connection_getsrv(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

	memcpy(con->cli->sess_key, sess_key, 16);
	memcpy(&con->cli->clnt_cred, cred, sizeof(*cred));

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
	return rpc_api_pipe_req(con->cli, con->fnum, op_num, data, rdata);
}
