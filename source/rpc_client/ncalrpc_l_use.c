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
#include "rpc_parse.h"

extern int DEBUGLEVEL;

struct ncalrpc_use
{
        struct msrpc_local *cli;
        uint32 num_users;
};

static struct ncalrpc_use **clis = NULL;
static uint32 num_clis = 0;

/****************************************************************************
add a client state to the array
****************************************************************************/
static struct ncalrpc_use *add_cli_to_array(uint32 * len,
                                            struct ncalrpc_use ***array,
                                            struct ncalrpc_use *cli)
{
        int i;
        for (i = 0; i < num_clis; i++)
        {
                if (clis[i] == NULL)
                {
                        clis[i] = cli;
                        return cli;
                }
        }

        return (struct ncalrpc_use *)add_item_to_array(len,
                                                       (void ***)array,
                                                       (void *)cli);

}

/****************************************************************************
terminate client connection
****************************************************************************/
static void ncalrpc_use_free(struct ncalrpc_use *cli)
{
        if (cli->cli != NULL)
        {
                if (cli->cli->initialised)
                {
                        ncalrpc_l_shutdown(cli->cli);
                }
                free(cli->cli);
        }

        free(cli);
}

/****************************************************************************
find client state.  server name, user name, vuid name and password must all
match.
****************************************************************************/
static struct ncalrpc_use *ncalrpc_l_find(const char *pipe_name,
                                          const vuser_key * key, BOOL reuse)
{
        int i;
        vuser_key null_usr;

        if (key == NULL)
        {
                key = &null_usr;
                null_usr.pid = sys_getpid();
                null_usr.vuid = UID_FIELD_INVALID;
        }

        DEBUG(10, ("ncalrpc_l_find: %s [%d,%x]\n",
                   pipe_name, key->pid, key->vuid));

        for (i = 0; i < num_clis; i++)
        {
                char *cli_name = NULL;
                struct ncalrpc_use *c = clis[i];

                if (c == NULL || !c->cli->initialised)
                {
                        continue;
                }

                cli_name = c->cli->pipe_name;

                DEBUG(10, ("ncalrpc_l_find[%d]: %s [%d,%x]\n",
                           i, cli_name,
                           c->cli->nt.key.pid, c->cli->nt.key.vuid));

                if (!strequal(cli_name, pipe_name))
                {
                        continue;
                }
                if (reuse)
                {
                        return c;
                }
                if (key->vuid == c->cli->nt.key.vuid &&
                    key->pid == c->cli->nt.key.pid)
                {
                        return c;
                }
        }

        return NULL;
}

/****************************************************************************
create a new client state from user credentials
****************************************************************************/
static struct ncalrpc_use *ncalrpc_use_get(const char *pipe_name,
                                           const vuser_key * key)
{
        struct ncalrpc_use *cli = (struct ncalrpc_use *)malloc(sizeof(*cli));

        if (cli == NULL)
        {
                return NULL;
        }

        memset(cli, 0, sizeof(*cli));

        cli->cli = ncalrpc_l_initialise(NULL, key);

        if (cli->cli == NULL)
        {
                return NULL;
        }

        return cli;
}


/****************************************************************************
init client state
****************************************************************************/
struct msrpc_local *ncalrpc_l_use_add(const char *pipe_name,
                                      const vuser_key * key,
                                      BOOL reuse, BOOL *is_new)
{
        struct ncalrpc_use *cli;

        DEBUG(10, ("ncalrpc_l_use_add\n"));

        if (strnequal("\\PIPE\\", pipe_name, 6))
        {
                pipe_name = &pipe_name[6];
        }

        cli = ncalrpc_l_find(pipe_name, key, reuse);

        if (cli != NULL)
        {
                cli->num_users++;
                DEBUG(10,
                      ("ncalrpc_l_use_add: num_users: %d\n", cli->num_users));
                (*is_new) = False;
                return cli->cli;
        }

        /*
         * allocate
         */

        cli = ncalrpc_use_get(pipe_name, key);

        /*
         * connect
         */

        if (!ncalrpc_l_establish_connection(cli->cli, pipe_name))
        {
                DEBUG(0, ("ncalrpc_l_use_add: connection failed\n"));
                cli->cli = NULL;
                ncalrpc_use_free(cli);
                return NULL;
        }

        add_cli_to_array(&num_clis, &clis, cli);
        cli->num_users++;

        DEBUG(10, ("ncalrpc_l_use_add: num_users: %d\n", cli->num_users));

        (*is_new) = True;

        return cli->cli;
}

/****************************************************************************
delete a client state
****************************************************************************/
BOOL ncalrpc_l_use_del(const char *pipe_name,
                       const vuser_key * key,
                       BOOL force_close, BOOL *connection_closed)
{
        int i;

        if (strnequal("\\PIPE\\", pipe_name, 6))
        {
                pipe_name = &pipe_name[6];
        }

        DEBUG(10, ("ncalrpc_l_use_del: %s. [%d,%x] force close: %s\n",
                   pipe_name, key->pid, key->vuid, BOOLSTR(force_close)));

        if (connection_closed != NULL)
        {
                *connection_closed = False;
        }

        for (i = 0; i < num_clis; i++)
        {
                char *ncalrpc_name = NULL;

                if (clis[i] == NULL)
                        continue;
                if (clis[i]->cli == NULL)
                        continue;

                ncalrpc_name = clis[i]->cli->pipe_name;

                if (strnequal("\\PIPE\\", pipe_name, 6))
                {
                        ncalrpc_name = &ncalrpc_name[6];
                }

                DEBUG(10, ("connection: %s [%d,%x]", ncalrpc_name,
                           clis[i]->cli->nt.key.pid,
                           clis[i]->cli->nt.key.vuid));

                if (!strequal(ncalrpc_name, pipe_name))
                        continue;

                if (key->pid != clis[i]->cli->nt.key.pid ||
                    key->vuid != clis[i]->cli->nt.key.vuid)
                {
                        continue;
                }
                /* decrement number of users */
                clis[i]->num_users--;

                DEBUG(10, ("idx: %i num_users now: %d\n",
                           i, clis[i]->num_users));

                if (force_close || clis[i]->num_users == 0)
                {
                        ncalrpc_use_free(clis[i]);
                        clis[i] = NULL;
                        if (connection_closed != NULL)
                        {
                                *connection_closed = True;
                        }
                }
                return True;
        }

        return False;
}


