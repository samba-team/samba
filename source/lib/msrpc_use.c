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
#include "trans2.h"

extern int DEBUGLEVEL;
extern pstring global_myname;

struct msrpc_use
{
	struct msrpc_smb *cli;
	uint32 num_users;
};

static struct msrpc_use **msrpcs = NULL;
uint32 num_msrpcs = 0;

/****************************************************************************
terminate client connection
****************************************************************************/
static void msrpc_use_free(struct msrpc_use *cli)
{
	if (cli->cli != NULL)
	{
		if (cli->cli->initialised)
		{
			msrpc_shutdown(cli->cli);
		}
		free(cli->cli);
	}

	free(cli);
}

/****************************************************************************
free a client array
****************************************************************************/
static void free_msrpc_array(uint32 num_entries, struct msrpc_use **entries)
{
	void (*fn) (void *) = (void (*)(void *))&msrpc_use_free;
	free_void_array(num_entries, (void **)entries, *fn);
}

/****************************************************************************
add a client state to the array
****************************************************************************/
static struct msrpc_use *add_msrpc_to_array(uint32 * len,
					    struct msrpc_use ***array,
					    struct msrpc_use *cli)
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

	return (struct msrpc_use *)add_item_to_array(len,
						     (void ***)array,
						     (void *)cli);

}

/****************************************************************************
initiate client array
****************************************************************************/
void init_msrpc_use(void)
{
	msrpcs = NULL;
	num_msrpcs = 0;
}

/****************************************************************************
terminate client array
****************************************************************************/
void free_msrpc_use(void)
{
	free_msrpc_array(num_msrpcs, msrpcs);
	init_msrpc_use();
}

/****************************************************************************
find client state.  server name, user name, domain name and password must all
match.
****************************************************************************/
static struct msrpc_use *msrpc_find(const char *pipe_name,
				    const vuser_key * key)
{
	int i;

	DEBUG(10, ("msrpc_find: %s", pipe_name));
	if (key != NULL)
	{
		DEBUG(10, (" [%d, %x]", key->pid, key->vuid));
	}
	DEBUG(10, ("\n"));

	for (i = 0; i < num_msrpcs; i++)
	{
		char *msrpc_name = NULL;
		struct msrpc_use *c = msrpcs[i];
		vuser_key k;

		if (c == NULL)
			continue;

		msrpc_name = c->cli->pipe_name;
		k = c->cli->nt.key;

		DEBUG(10, ("msrpc_find[%d]: %s [%d,%x]\n",
			   i, msrpc_name, k.pid, k.vuid));

		if (strequal(msrpc_name, pipe_name) &&
		    (key == NULL
		     || (k.pid == key->pid && k.vuid == key->vuid)))
		{
			return c;
		}
	}

	return NULL;
}

/****************************************************************************
create a new client state from user credentials
****************************************************************************/
static struct msrpc_use *msrpc_use_get(const char *pipe_name,
				       const vuser_key * key)
{
	struct msrpc_use *cli = (struct msrpc_use *)malloc(sizeof(*cli));

	if (cli == NULL)
	{
		return NULL;
	}

	memset(cli, 0, sizeof(*cli));

	cli->cli = msrpc_initialise(NULL, key);

	if (cli->cli == NULL)
	{
		return NULL;
	}

	return cli;
}

/****************************************************************************
init client state
****************************************************************************/
struct cli_connection *msrpc_use_add(const char *pipe_name,
				     const vuser_key * key, BOOL redir)
{
	struct msrpc_use *cli;
	DEBUG(10,
	      ("msrpc_use_add: %s redir: %s\n", pipe_name, BOOLSTR(redir)));

	cli = msrpc_find(pipe_name, key);

	if (cli != NULL)
	{
		cli->num_users++;
		return cli->cli;
	}

	/* reuse an existing connection requested, and one was not found */
	if (redir)
	{
		DEBUG(0,
		      ("msrpc_use_add: reuse requested, but one not found\n"));
		return False;
	}

	/*
	 * allocate
	 */

	cli = msrpc_use_get(pipe_name, key);
	cli->cli->redirect = redir;

	if (!msrpc_establish_connection(cli->cli, pipe_name))
	{
		DEBUG(0, ("msrpc_use_add: connection failed\n"));
		cli->cli = NULL;
		msrpc_use_free(cli);
		return NULL;
	}

	add_msrpc_to_array(&num_msrpcs, &msrpcs, cli);
	cli->num_users++;

	return cli->cli;
}

/****************************************************************************
delete a client state
****************************************************************************/
BOOL msrpc_use_del(const char *pipe_name,
		   BOOL force_close, BOOL *connection_closed)
{
	int i;

	DEBUG(10, ("msrpc_net_use_del: %s. force close: %s\n",
		   pipe_name, BOOLSTR(force_close)));

	if (connection_closed != NULL)
	{
		*connection_closed = False;
	}

	for (i = 0; i < num_msrpcs; i++)
	{
		char *msrpc_name = NULL;

		if (msrpcs[i] == NULL)
			continue;
		if (msrpcs[i]->cli == NULL)
			continue;

		msrpc_name = msrpcs[i]->cli->pipe_name;

		if (!strequal(msrpc_name, pipe_name))
			continue;

		/* decrement number of users */
		msrpcs[i]->num_users--;

		DEBUG(10, ("idx: %i num_users now: %d\n",
			   i, msrpcs[i]->num_users));

		if (force_close || msrpcs[i]->num_users == 0)
		{
			msrpc_use_free(msrpcs[i]);
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
enumerate client states
****************************************************************************/
void msrpc_net_use_enum(uint32 * num_cons, struct use_info ***use)
{
	int i;

	*num_cons = 0;
	*use = NULL;

	for (i = 0; i < num_msrpcs; i++)
	{
		struct use_info item;

		ZERO_STRUCT(item);

		if (msrpcs[i] == NULL)
			continue;

		item.connected = msrpcs[i]->cli != NULL ? True : False;

		if (item.connected)
		{
			item.srv_name = msrpcs[i]->cli->pipe_name;
			item.key = msrpcs[i]->cli->nt.key;
		}

		add_use_info_to_array(num_cons, use, &item);
	}
}
