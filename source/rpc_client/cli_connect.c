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

enum
{ MSRPC_NONE, MSRPC_LOCAL, MSRPC_SMB };

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


void free_connections(void)
{
        DEBUG(3, ("free_connections: closing all MSRPC connections\n"));
        free_con_array(num_cons, con_list);
        free_cli_use();

        init_connections();
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
                switch (con->type)
                {
                        case MSRPC_LOCAL:
                        {
                                DEBUG(10, ("msrpc local connection\n"));
                                ncalrpc_l_use_del(con->pipe_name,
                                                  &con->msrpc.local->nt.key,
                                                  False, &closed);
                                oldcli = con->msrpc.local;
                                con->msrpc.local = NULL;
                                break;
                        }
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
