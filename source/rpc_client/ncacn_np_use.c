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

