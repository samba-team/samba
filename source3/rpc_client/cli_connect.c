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

/*
 * MSRPC_NONE:	no connection
 * MSRPC_LOCAL:	local loopback over a UNIX domain socket (not supported)
 * MSRPC_SMB:	network rpc connection
 */
enum { MSRPC_NONE, MSRPC_LOCAL, MSRPC_SMB };

struct cli_connection
{
	uint32 num_connections;
	char *srv_name;
	char *pipe_name;
	struct user_creds usr_creds;

	int type;

	union
	{
		struct ncacn_np *smb;
		struct msrpc_local *local;
		void *cli;
	} msrpc;

	cli_auth_fns *auth;
	void *auth_info;
	void *auth_creds;
};

static struct cli_connection **con_list = NULL;
static uint32 num_cons = 0;

struct user_creds *usr_creds = NULL;
vuser_key *user_key = NULL;

extern int DEBUGLEVEL;
extern pstring global_myname;
cli_auth_fns cli_noauth_fns = 
{
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};




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


static struct cli_connection *add_con_to_array(uint32 * len,
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
	CREDS_NT usr;
        struct ntuser_creds *ntc = NULL;
        vuser_key key;

        con = (struct cli_connection *)malloc(sizeof(*con));

        if (con == NULL)
        {
                return NULL;
        }

        memset(con, 0, sizeof(*con));
        con->type = MSRPC_NONE;

        copy_user_creds(&con->usr_creds, NULL);
        con->usr_creds.reuse = reuse;

        if (srv_name != NULL)
        {
                con->srv_name = strdup(srv_name);
        }
        if (pipe_name != NULL)
        {
                con->pipe_name = strdup(pipe_name);
        }

	/* setup a network RPC connection */
        if (usr_creds != NULL)
        {
                ntc = &usr_creds->ntc;
        }
        con->type = MSRPC_SMB;
        con->msrpc.smb = ncacn_np_use_add(pipe_name, user_key, srv_name,
                                          ntc, reuse,
                                          &is_new_connection);

        if (con->msrpc.smb == NULL)
                return NULL;

        key = con->msrpc.smb->smb->key;
        con->msrpc.smb->smb->key.pid = 0;
        con->msrpc.smb->smb->key.vuid = UID_FIELD_INVALID;
	create_ntc_from_cli_state ( &usr, con->msrpc.smb->smb );
        copy_nt_creds(&con->usr_creds.ntc, &usr);

        if (con->msrpc.cli != NULL)
        {
                if (is_new_connection)
                {
                        con->auth_info = NULL;
                        con->auth_creds = auth_creds;

                        if (auth != NULL)
                        {
                                con->auth = auth;
                        }
                        else
                        {
                                con->auth = &cli_noauth_fns;
                        }

                        if (!rpc_pipe_bind(con->msrpc.smb->smb, pipe_name, global_myname))
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
                                DEBUG(1,("cli_con_get: TODO: auth reuse\n"));
                                cli_connection_free(con);
                                return NULL;
                        }
                        else
                        {
                                con->auth = &cli_noauth_fns;
                        }
                }
        }

        if (con->msrpc.cli == NULL)
        {
                cli_connection_free(con);
                return NULL;
        }

        if (con->type == MSRPC_SMB)
        {
                con->msrpc.smb->smb->key = key;
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
        void *oldcli = NULL;
        int i;

        DEBUG(10, ("cli_connection_free: %d\n", __LINE__));

        if (con->msrpc.cli != NULL)
        {
		/* only currently support type == MSRPC_SMB so this is a little
		   redundant --jerry */
                switch (con->type)
                {
                        case MSRPC_SMB:
                        {
                                DEBUG(10, ("msrpc smb connection\n"));
                                ncacn_np_use_del(con->srv_name,
                                                 con->pipe_name,
                                                 &con->msrpc.smb->smb->key,
                                                 False, &closed);
                                oldcli = con->msrpc.local;
                                con->msrpc.smb = NULL;
                                break;
                        }
                }
        }

        DEBUG(10, ("cli_connection_free: closed: %s\n", BOOLSTR(closed)));

        if (closed)
        {
                for (i = 0; i < num_cons; i++)
                {
                        struct cli_connection *c = con_list[i];
                        if (c != NULL && con != c && c->msrpc.cli == oldcli)
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
                                                c->msrpc.smb = NULL;
                                                break;
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

        if (con->auth_info != NULL)
        {
                free(con->auth_info);
                con->auth_info = NULL;
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
 send a request on an rpc pipe.
 ****************************************************************************/
BOOL rpc_hnd_pipe_req(const POLICY_HND * hnd, uint8 op_num,
                      prs_struct * data, prs_struct * rdata)
{
        struct cli_connection *con = NULL;

#if 0	/* temporary disable by JERRY */
	/* we need this to locate the cli_connection associated
	   with the POLICY_HND */
        if (!cli_connection_get(hnd, &con))
        {
                return False;
        }
#endif	/* temporary disable by JERRY */

	/* always will return False until I fix cli_connection_get()
	   --jerry */
        if (!rpc_con_ok(con)) return False;

        return rpc_con_pipe_req(con, op_num, data, rdata);
}

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
BOOL rpc_con_pipe_req(struct cli_connection *con, uint8 op_num,
                      prs_struct * data, prs_struct * rdata)
{
        BOOL ret;
        DEBUG(10, ("rpc_con_pipe_req: op_num %d offset %d used: %d\n",
                   op_num, data->data_offset, data->buffer_size));
        prs_dump("in_rpcclient", (int)op_num, data);

	/* Why does this use prs->data_offset?  --jerry */
        /* prs_realloc_data(data, data->data_offset); */

        ret = rpc_api_pipe_req(con->msrpc.smb->smb, op_num, data, rdata);
        prs_dump("out_rpcclient", (int)op_num, rdata);
        return ret;
}

/**************************************************************************** 
   this allows us to detect dead servers. The cli->fd is set to -1 when
   we get an error 
*****************************************************************************/
BOOL rpc_con_ok(struct cli_connection *con)
{
        if (!con) return False;

        switch (con->type)
        {
                case MSRPC_SMB:
                        {
                                struct cli_state *cli;
                                if (!con->msrpc.smb) return False;
                                cli = con->msrpc.smb->smb;
                                if (cli->fd == -1) return False;
                                return True;
                        }
                        break;

                case MSRPC_LOCAL:
                        return True;
        }
        return False;
}

