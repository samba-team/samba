/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   DCE/RPC client generic functions
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

struct user_creds *usr_creds = NULL;
vuser_key *user_key = NULL;

extern int DEBUGLEVEL;

struct cli_connection
{
	char *srv_name;
	char *pipe_name;

	cli_connect_fns *con_fns;
	cli_rpc_info *con_info;

	cli_auth_fns *auth;
	void *auth_info;
	void *auth_creds;
};

static struct cli_connection **con_list = NULL;
static uint32 num_cons = 0;

void init_connections(void)
{
	con_list = NULL;
	num_cons = 0;

	init_cli_use();
}

static void free_con_array(uint32 num_entries,
			   struct cli_connection **entries)
{
	void (*fn) (void *) = (void (*)(void *))&cli_connection_free;
	free_void_array(num_entries, (void **)entries, *fn);
}

static struct cli_connection *add_con_to_array(uint32 *len,
					       struct cli_connection ***array,
					       struct cli_connection *con)
{
	return (struct cli_connection *)add_item_to_array(len,
							  (void ***)array,
							  (void *)con);

}
void free_connections(void)
{
	DEBUG(3, ("free_connections: closing all MSRPC connections\n"));
	free_con_array(num_cons, con_list);
	free_cli_use();

	init_connections();
}

static struct cli_connection *cli_con_get(const char *srv_name,
					  const char *pipe_name,
					  cli_auth_fns * auth,
					  void *auth_creds, BOOL reuse)
{
	struct cli_connection *con = NULL;
	BOOL is_new_connection = False;
	struct ntuser_creds *ntc = NULL;

	con = (struct cli_connection *)malloc(sizeof(*con));

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

	if (usr_creds != NULL)
	{
		ntc = &usr_creds->ntc;
	}

	if (strequal(srv_name, "\\\\."))
	{
		con->con_fns = ncalrpc_get_fns();
	}
	else
	{
		con->con_fns = ncacn_np_get_fns();
	}

	con->con_info = con->con_fns->cli_connect_add(pipe_name, user_key,
						     srv_name, ntc,
						     reuse, &is_new_connection);

	if (con->con_info != NULL)
	{
		if (is_new_connection)
		{
			RPC_IFACE abstract;
			RPC_IFACE transfer;

			con->auth_info = NULL;
			con->auth_creds = auth_creds;

			if (auth != NULL)
			{
				con->auth = auth;
			}
			else
			{
				extern cli_auth_fns cli_noauth_fns;
				con->auth = &cli_noauth_fns;
			}

			if (!rpc_pipe_bind(con, pipe_name, &abstract,
					   &transfer))
			{
				DEBUG(0, ("rpc_pipe_bind failed\n"));
				cli_connection_free(con);
				return NULL;
			}
		}
		else
		{
			con->auth_info = cli_conn_get_auth_creds(con);
			con->auth = cli_conn_get_authfns(con);
			if (con->auth_info != NULL)
			{
				DEBUG(1, ("cli_con_get: TODO: auth reuse\n"));
				cli_connection_free(con);
				return NULL;
			}
			else
			{
				extern cli_auth_fns cli_noauth_fns;
				con->auth = &cli_noauth_fns;
			}
		}
	}

	if (con->con_info == NULL)
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
	BOOL closed = False;
	int i;

	DEBUG(10, ("cli_connection_free: %d\n", __LINE__));

	if (con->con_info != NULL)
	{
		/* this function responsible for disposing of con_info! */
		/* do not call free(con->con_info) here as well!!! */
		con->con_fns->cli_connection_free(con->con_info);
		con->con_info = NULL;
	}

	DEBUG(10, ("cli_connection_free: closed: %s\n", BOOLSTR(closed)));

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

	if (con->auth_info != NULL)
	{
		free(con->auth_info);
		con->auth_info = NULL;
	}

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
BOOL cli_connection_init(const char *srv_name, const char *pipe_name,
			 struct cli_connection **con)
{
	return cli_connection_init_auth(srv_name, pipe_name, con, NULL, NULL);
}

/****************************************************************************
init client state
****************************************************************************/
BOOL cli_connection_init_auth(const char *srv_name, const char *pipe_name,
			      struct cli_connection **con,
			      cli_auth_fns * auth, void *auth_creds)
{
	BOOL reuse = True;

	/*
	 * allocate
	 */

	DEBUG(10, ("cli_connection_init_auth: %s %s\n",
		   srv_name != NULL ? srv_name : "<null>", pipe_name));

	*con = cli_con_get(srv_name, pipe_name, auth, auth_creds, reuse);

	return (*con) != NULL;
}

/****************************************************************************
obtain client state
****************************************************************************/
BOOL cli_connection_getsrv(const char *srv_name, const char *pipe_name,
			   struct cli_connection **con)
{
	int i;
	struct cli_connection *auth_con = NULL;

	if (con_list == NULL || num_cons == 0)
	{
		return False;
	}

	(*con) = NULL;

	for (i = 0; i < num_cons; i++)
	{
		if (con_list[i] != NULL &&
		    strequal(con_list[i]->srv_name, srv_name) &&
		    strequal(con_list[i]->pipe_name, pipe_name))
		{
			extern cli_auth_fns cli_noauth_fns;
			(*con) = con_list[i];
			/* authenticated connections take priority. HACK! */
			if ((*con)->auth != &cli_noauth_fns)
			{
				auth_con = (*con);
			}
		}
	}

	if (auth_con != NULL)
	{
		(*con) = auth_con;
	}

	return (*con) != NULL;
}

/****************************************************************************
obtain client state
****************************************************************************/
BOOL cli_connection_get(const POLICY_HND *pol, struct cli_connection **con)
{
	return get_policy_con(get_global_hnd_cache(), pol, con);
}

/****************************************************************************
link a child policy handle to a parent one
****************************************************************************/
BOOL cli_pol_link(POLICY_HND *to, const POLICY_HND *from)
{
	struct cli_connection *con = NULL;

	if (!cli_connection_get(from, &con))
	{
		DEBUG(0, ("cli_pol_link: no connection\n"));
		return False;
	}

	/* fix this when access masks are actually working! */
	DEBUG(10, ("cli_pol_link: lkclXXXX - MAXIMUM_ALLOWED access_mask\n"));

	return dup_policy_hnd(get_global_hnd_cache(), to, from) &&
		set_policy_con(get_global_hnd_cache(), to, con, NULL);
}

/****************************************************************************
set a user session key associated with a connection 
****************************************************************************/
BOOL cli_get_usr_sesskey(const POLICY_HND *pol, uchar usr_sess_key[16])
{
	struct ntdom_info *nt;
	struct cli_connection *con;
	if (!cli_connection_get(pol, &con))
	{
		return False;
	}
	if (con == NULL)
	{
		DEBUG(0, ("cli_get_usr_sesskey: no connection\n"));
		return False;
	}
	nt = cli_conn_get_ntinfo(con);
	if (nt == NULL)
	{
		DEBUG(0, ("cli_get_usr_sesskey: no ntdom_info\n"));
		return False;
	}

	memcpy(usr_sess_key, nt->usr_sess_key, sizeof(nt->usr_sess_key));

	return True;
}

/****************************************************************************
set a user session key associated with a connection 
****************************************************************************/
BOOL cli_set_con_usr_sesskey(struct cli_connection *con,
			     const uchar usr_sess_key[16])
{
	struct ntdom_info *nt;
	if (con == NULL)
	{
		return False;
	}
	nt = cli_conn_get_ntinfo(con);
	if (nt != NULL)
	{
		memcpy(nt->usr_sess_key, usr_sess_key,
		       sizeof(nt->usr_sess_key));
	}


	return True;
}

/****************************************************************************
 get auth functions associated with an msrpc session.
****************************************************************************/
const vuser_key *cli_con_sec_ctx(struct cli_connection *con)
{
	struct ntdom_info *nt;
	if (con == NULL)
	{
		return False;
	}
	nt = cli_conn_get_ntinfo(con);
	if (nt != NULL && nt->key.vuid != UID_FIELD_INVALID)
	{
		return &nt->key;
	}
	return NULL;
}

/****************************************************************************
 get auth functions associated with an msrpc session.
****************************************************************************/
struct cli_auth_fns *cli_conn_get_authfns(struct cli_connection *con)
{
	return con != NULL ? con->auth : NULL;
}

/****************************************************************************
 get auth info associated with an msrpc session.
****************************************************************************/
void *cli_conn_get_auth_creds(struct cli_connection *con)
{
	return con != NULL ? con->auth_creds : NULL;
}

/****************************************************************************
 get auth info associated with an msrpc session.
****************************************************************************/
void *cli_conn_get_auth_info(struct cli_connection *con)
{
	return con != NULL ? con->auth_info : NULL;
}

/****************************************************************************
 set auth info associated with an msrpc session.
****************************************************************************/
BOOL cli_conn_set_auth_info(struct cli_connection *con, void *auth_info)
{
	con->auth_info = auth_info;
	return auth_info != NULL;
}

/****************************************************************************
 get nt creds (HACK ALERT!) associated with an msrpc session.
****************************************************************************/
struct ntdom_info *cli_conn_get_ntinfo(struct cli_connection *con)
{
	if (con == NULL)
	{
		return NULL;
	}
	if (con->con_info == NULL)
	{
		DEBUG(1, ("cli_conn_get_ntinfo: NULL msrpc (closed)\n"));
		return NULL;
	}

	return con->con_fns->cli_conn_get_ntinfo(con->con_info);
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

	dump_data_pw("sess_key:", sess_key, 16);

	return True;
}

/****************************************************************************
get a server name associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_con_get_srvname(struct cli_connection *con, char *srv_name)
{
	const char *desthost = NULL;

	if (con == NULL)
	{
		return False;
	}

	desthost = con->con_fns->cli_con_get_srvname(con->con_info);

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
BOOL cli_get_sesskey_srv(const char *srv_name, uchar sess_key[16])
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
			    DOM_CRED * new_clnt_cred)
{
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	gen_next_creds(nt, new_clnt_cred);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
void cli_con_get_cli_cred(struct cli_connection *con, DOM_CRED * clnt_cred)
{
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	memcpy(clnt_cred, &nt->clnt_cred, sizeof(*clnt_cred));
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_con_deal_with_creds(struct cli_connection *con,
			     DOM_CRED * rcv_srv_cred)
{
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	return clnt_deal_with_creds(nt->sess_key, &nt->clnt_cred,
				    rcv_srv_cred);
}

/****************************************************************************
get a user session key associated with a connection associated with a
policy handle.
****************************************************************************/
BOOL cli_con_set_creds(const char *srv_name, const uchar sess_key[16],
		       DOM_CRED * cred)
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
BOOL rpc_hnd_ok(const POLICY_HND *hnd)
{
	struct cli_connection *con = NULL;

	return cli_connection_get(hnd, &con) && rpc_con_ok(con);
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

	if (!rpc_con_ok(con))
		return False;

	return rpc_con_pipe_req(con, op_num, data, rdata);
}

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
BOOL rpc_con_pipe_req(struct cli_connection *con, uint8 op_num,
		      prs_struct *data, prs_struct *rdata)
{
	BOOL ret;
	DEBUG(10, ("rpc_con_pipe_req: op_num %d offset %d used: %d\n",
		   op_num, prs_offset(data), prs_data_size(data)));
	prs_dump("in_rpcclient", (int)op_num, data);
	prs_realloc_data(data, data->offset);
	ret = rpc_api_pipe_req(con, op_num, data, rdata);
	prs_dump("out_rpcclient", (int)op_num, rdata);
	return ret;
}

/****************************************************************************
 write a full PDU to a pipe
****************************************************************************/
BOOL rpc_api_write(struct cli_connection *con, prs_struct *data)
{
	return con->con_fns->rpc_api_write(con->con_info, data);
}

/****************************************************************************
 read a full PDU from a pipe
****************************************************************************/
BOOL rpc_api_rcv_pdu(struct cli_connection *con, prs_struct *rdata)
{
	return con->con_fns->rpc_api_rcv_pdu(con,
			con->con_info, rdata);
}

/****************************************************************************
 this allows us to detect dead servers. 
****************************************************************************/
BOOL rpc_con_ok(struct cli_connection *con)
{
	if (!con)
		return False;

	return con->con_fns->rpc_con_ok(con->con_info);
}


/****************************************************************************
 write full PDU to pipe then read full PDU from pipe.
****************************************************************************/
BOOL rpc_api_send_rcv_pdu(struct cli_connection *con, prs_struct *data,
			  prs_struct *rdata)
{
	return con->con_fns->rpc_api_send_rcv_pdu(con,
			con->con_info, data, rdata);
}

/* connection policy state-info */

struct con_info
{
	struct cli_connection *con;
	void (*free_con) (struct cli_connection *);
};

static void free_policy_con(void *dev)
{
	struct con_info *con = (struct con_info *)dev;
	DEBUG(10, ("free policy connection\n"));
	if (con->free_con != NULL)
	{
		con->free_con(con->con);
	}
	free(dev);
}

/****************************************************************************
  set con state
****************************************************************************/
BOOL set_policy_con(struct policy_cache *cache, POLICY_HND *hnd,
		    struct cli_connection *con,
		    void (*free_fn) (struct cli_connection *))
{
	struct con_info *dev = (struct con_info *)malloc(sizeof(*dev));

	if (dev != NULL)
	{
		dev->con = con;
		dev->free_con = free_fn;
		if (set_policy_state(cache, hnd,
				     free_policy_con, (void *)dev))
		{
			DEBUG(5, ("setting policy con\n"));
			return True;
		}
		free(dev);
	}

	DEBUG(3, ("Error setting policy con state\n"));
	return False;
}

/****************************************************************************
  get con state
****************************************************************************/
BOOL get_policy_con(struct policy_cache *cache, const POLICY_HND *hnd,
		    struct cli_connection **con)
{
	struct con_info *dev;
	dev = (struct con_info *)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		DEBUG(5, ("Getting policy con state\n"));
		(*con) = dev->con;
		return True;
	}

	DEBUG(3, ("Error getting policy con state\n"));
	return False;
}
