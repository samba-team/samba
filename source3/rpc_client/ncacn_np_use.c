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
#include "trans2.h"

extern int DEBUGLEVEL;
extern pstring global_myname;

struct ncacn_np_use
{
        struct ncacn_np *cli;
        uint32 num_users;
};

static struct ncacn_np_use **msrpcs = NULL;
static uint32 num_msrpcs = 0;

/****************************************************************************
terminate client connection
****************************************************************************/
static void ncacn_np_shutdown(struct ncacn_np *cli)
{
        if (cli != NULL)
        {
                if (cli->smb != NULL)
                {
                        if (cli->smb->initialised)
                        {
                                /* cli_nt_session_close(cli->smb, cli->fnum); JERRY */
                                cli_nt_session_close(cli->smb);
                        }
#if 0  /* commented out by JERRY */
                        cli_net_use_del(cli->smb->desthost,
                                        &cli->smb->usr, False, False);
#endif
                }
        }
}

static BOOL ncacn_np_establish_connection(struct ncacn_np *cli,
                                   const char *srv_name,
                                   const struct ntuser_creds *ntc,
                                   const char *pipe_name,
                                   BOOL reuse)
{
        BOOL new_smb_conn;
        cli->smb = cli_net_use_add(srv_name, ntc,
                                   True, &new_smb_conn);
        if (cli->smb == NULL)
        {
                return False;
        }
        /* if (!cli_nt_session_open(cli->smb, pipe_name, &cli->fnum))  by JERRY */
        if (!cli_nt_session_open(cli->smb, pipe_name))
        {
                cli_net_use_del(srv_name, ntc, False, NULL);
                return False;
        }
        fstrcpy(cli->pipe_name, pipe_name);
        return True;
}



/****************************************************************************
terminate client connection
****************************************************************************/
static void ncacn_np_use_free(struct ncacn_np_use *cli)
{
        if (cli->cli != NULL)
        {
                if (cli->cli->initialised)
                {
                        ncacn_np_shutdown(cli->cli);
                }
                ZERO_STRUCTP(cli->cli);
                free(cli->cli);
        }
        ZERO_STRUCTP(cli);
        free(cli);
}

/****************************************************************************
add a client state to the array
****************************************************************************/
static struct ncacn_np_use *add_ncacn_np_to_array(uint32 * len,
                                                  struct ncacn_np_use
                                                  ***array,
                                                  struct ncacn_np_use *cli)
{
        int i;
        for (i = 0; i < num_msrpcs; i++)
        {
                if (msrpcs[i] == NULL)
                {
                        msrpcs[i] = cli;
                        return cli;
                }
        }

        return (struct ncacn_np_use *)add_item_to_array(len,
                                                        (void ***)array,
                                                        (void *)cli);

}



/****************************************************************************
delete a client state
****************************************************************************/
BOOL ncacn_np_use_del(const char *srv_name, const char *pipe_name,
                      const vuser_key * key,
                      BOOL force_close, BOOL *connection_closed)
{
        int i;
        DEBUG(10, ("ncacn_np_net_use_del: %s. force close: %s ",
                   pipe_name, BOOLSTR(force_close)));
        if (key != NULL)
        {
                DEBUG(10, ("[%d,%x]", key->pid, key->vuid));
        }
        DEBUG(10, ("\n"));

        if (connection_closed != NULL)
        {
                *connection_closed = False;
        }

        if (strnequal("\\PIPE\\", pipe_name, 6))
        {
                pipe_name = &pipe_name[6];
        }

        if (strnequal("\\\\", srv_name, 2))
        {
                srv_name = &srv_name[6];
        }

        for (i = 0; i < num_msrpcs; i++)
        {
                char *ncacn_np_name = NULL;
                char *ncacn_np_srv_name = NULL;
                struct ncacn_np_use *c = msrpcs[i];
                vuser_key k;

                if (c == NULL || c->cli == NULL || c->cli->smb == NULL)
                        continue;

                ncacn_np_name = c->cli->pipe_name;
                ncacn_np_srv_name = c->cli->smb->desthost;

                k = c->cli->smb->key;

                DEBUG(10, ("use_del[%d]: %s %s %s %s [%d,%x]\n",
                           i, ncacn_np_name, ncacn_np_srv_name,
                           c->cli->smb->user_name,
                           c->cli->smb->domain, k.pid, k.vuid));

                if (strnequal("\\PIPE\\", ncacn_np_name, 6))
                {
                        ncacn_np_name = &ncacn_np_name[6];
                }
                if (!strequal(ncacn_np_srv_name, srv_name))
                {
                        continue;
                }
                if (strnequal("\\\\", ncacn_np_srv_name, 2))
                {
                        ncacn_np_srv_name = &ncacn_np_srv_name[6];
                }
                if (!strequal(ncacn_np_name, pipe_name))
                {
                        continue;
                }
                if (key->pid != k.pid || key->vuid != k.vuid)
                {
                        continue;
                }
                /* decrement number of users */
                c->num_users--;
                DEBUG(10, ("idx: %i num_users now: %d\n",
                           i, c->num_users));
                if (force_close || c->num_users == 0)
                {
                        ncacn_np_use_free(c);
                        msrpcs[i] = NULL;
                        if (connection_closed != NULL)
                        {
                                *connection_closed = True;
                        }
                }
                return True;
        }

        return False;
}

/****************************************************************************
find client state.  server name, user name, domain name and password must all
match.
****************************************************************************/
static struct ncacn_np_use *ncacn_np_find(const char *srv_name,
                                          const char *pipe_name,
                                          const vuser_key * key,
                                          const struct ntuser_creds
                                          *usr_creds, BOOL reuse)
{
        int i;
        const char *sv_name = srv_name;

        if (strnequal("\\PIPE\\", pipe_name, 6))
        {
                pipe_name = &pipe_name[6];
        }

        if (strnequal("\\\\", sv_name, 2))
        {
                sv_name = &sv_name[2];
        }

        if (usr_creds != NULL)
        {
                DEBUG(10, ("ncacn_np_find: %s %s %s",
                           srv_name, usr_creds->user_name, usr_creds->domain));
        }
        else
        {
                DEBUG(10,("ncacn_np_find: %s (no creds)\n", srv_name));
        }

        if (key != NULL)
        {
                DEBUG(10, ("[%d,%x]", key->pid, key->vuid));
        }
        DEBUG(10, ("\n"));

        for (i = 0; i < num_msrpcs; i++)
        {
                char *ncacn_np_srv_name = NULL;
                struct ncacn_np_use *c = msrpcs[i];
                vuser_key k;

                char *ncacn_np_name = NULL;

                if (c == NULL || c->cli == NULL || c->cli->smb == NULL ||
                    c->cli->smb->fd == -1 ||
                    !c->cli->initialised)
                {
                        continue;
                }

                ncacn_np_name = c->cli->pipe_name;
                ncacn_np_srv_name = c->cli->smb->desthost;

                k = c->cli->smb->key;

                DEBUG(10, ("ncacn_np_find[%d]: %s %s %s %s [%d,%x]\n",
                           i, ncacn_np_name, ncacn_np_srv_name,
                           c->cli->smb->user_name,
                           c->cli->smb->domain, k.pid, k.vuid));

                if (strnequal("\\\\", ncacn_np_srv_name, 2))
                {
                        ncacn_np_srv_name = &ncacn_np_srv_name[2];
                }

                if (strnequal("\\PIPE\\", ncacn_np_name, 6))
                {
                        ncacn_np_name = &ncacn_np_name[6];
                }

                if (!strequal(ncacn_np_name, pipe_name))
                {
                        continue;
                }
                if (!strequal(ncacn_np_srv_name, sv_name))
                {
                        continue;
                }
                if (key != NULL && (k.pid != key->pid || k.vuid != key->vuid))
                {
                        continue;
                }
                if (usr_creds == NULL)
                {
                        if (reuse)
                        {
                                return c;
                        }
                        else
                        {
                                continue;
                        }
                }
                if (!strequal
                    (usr_creds->user_name, c->cli->smb->user_name))
                {
                        continue;
                }
                if (!reuse
                    && !pwd_compare(&usr_creds->pwd, &c->cli->smb->pwd))
                {
                        DEBUG(100, ("password doesn't match\n"));
                        continue;
                }
                if (usr_creds->domain[0] == 0)
                {
                        return c;
                }
                if (strequal(usr_creds->domain, c->cli->smb->domain))
                {
                        return c;
                }
        }

        return NULL;
}


/****************************************************************************
initialise a msrpcent structure
****************************************************************************/
struct ncacn_np *ncacn_np_initialise(struct ncacn_np *msrpc,
                                     const vuser_key * key)
{
        if (!msrpc)
        {
                msrpc = (struct ncacn_np *)malloc(sizeof(*msrpc));
                if (!msrpc)
                        return NULL;
                ZERO_STRUCTP(msrpc);
        }

        if (msrpc->initialised)
        {
                ncacn_np_shutdown(msrpc);
        }

        ZERO_STRUCTP(msrpc);

        msrpc->fnum = -1;
        msrpc->initialised = 1;

        return msrpc;
}

/****************************************************************************
create a new client state from user credentials
****************************************************************************/
static struct ncacn_np_use *ncacn_np_use_get(const char *pipe_name,
                                             const vuser_key * key)
{
        struct ncacn_np_use *cli =
                (struct ncacn_np_use *)malloc(sizeof(*cli));

        if (cli == NULL)
        {
                return NULL;
        }

        memset(cli, 0, sizeof(*cli));

        cli->cli = ncacn_np_initialise(NULL, key);

        if (cli->cli == NULL)
        {
                return NULL;
        }

        return cli;
}

/****************************************************************************
init client state
****************************************************************************/
struct ncacn_np *ncacn_np_use_add(const char *pipe_name,
                                  const vuser_key * key,
                                  const char *srv_name,
                                  const struct ntuser_creds *ntc,
                                  BOOL reuse, BOOL *is_new_connection)
{
        struct ncacn_np_use *cli;
        DEBUG(10, ("ncacn_np_use_add: %s\n", pipe_name));

        (*is_new_connection) = False;
        cli = ncacn_np_find(srv_name, pipe_name, key, ntc, reuse);

        if (cli != NULL)
        {
                cli->num_users++;
                return cli->cli;
        }

        /*
         * allocate
         */

        (*is_new_connection) = True;

        cli = ncacn_np_use_get(pipe_name, key);

        if (!ncacn_np_establish_connection
            (cli->cli, srv_name, ntc, pipe_name, True))
        {
                DEBUG(0, ("ncacn_np_use_add: connection failed\n"));
                cli->cli = NULL;
                ncacn_np_use_free(cli);
                return NULL;
        }

        if (key != NULL)
        {
                cli->cli->smb->key = *key;
        }
        else
        {
                cli->cli->smb->key.pid = sys_getpid();
                cli->cli->smb->key.vuid = UID_FIELD_INVALID;
        }

        add_ncacn_np_to_array(&num_msrpcs, &msrpcs, cli);
        cli->num_users++;
        return cli->cli;
}



