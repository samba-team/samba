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

struct ncacn_np_use
{
	struct ncacn_np *cli;
	uint32 num_users;
};

static struct ncacn_np_use **msrpcs = NULL;
uint32 num_msrpcs = 0;

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
				cli_nt_session_close(cli->smb, cli->fnum);
			}
			cli_net_use_del(cli->smb->desthost,
					&cli->smb->usr, False, False);
		}
	}
}

BOOL ncacn_np_establish_connection(struct ncacn_np *cli,
				   const char *srv_name,
				   const struct ntuser_creds *ntc,
				   const char *pipe_name, BOOL redir,
				   BOOL reuse)
{
	BOOL new_smb_conn;
	cli->smb = cli_net_use_add(srv_name, ntc, redir, reuse,
				   &new_smb_conn);
	if (cli->smb == NULL)
	{
		return False;
	}
	if (!cli_nt_session_open(cli->smb, pipe_name, &cli->fnum))
	{
		cli_net_use_del(srv_name, ntc, False, NULL);
		return False;
	}
	fstrcpy(cli->pipe_name, pipe_name);
	dump_data_pw("sess key:", cli->smb->nt.usr_sess_key, 16);
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
free a client array
****************************************************************************/
static void free_ncacn_np_array(uint32 num_entries,
				struct ncacn_np_use **entries)
{
	void (*fn) (void *) = (void (*)(void *))&ncacn_np_use_free;
	free_void_array(num_entries, (void **)entries, *fn);
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
initiate client array
****************************************************************************/
void init_ncacn_np_use(void)
{
	msrpcs = NULL;
	num_msrpcs = 0;
}

/****************************************************************************
terminate client array
****************************************************************************/
void free_ncacn_np_use(void)
{
	free_ncacn_np_array(num_msrpcs, msrpcs);
	init_ncacn_np_use();
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
	struct ntuser_creds null_usr;

	copy_nt_creds(&null_usr, usr_creds);
	usr_creds = &null_usr;

	if (strnequal("\\PIPE\\", pipe_name, 6))
	{
		pipe_name = &pipe_name[6];
	}

	if (strnequal("\\\\", sv_name, 2))
	{
		sv_name = &sv_name[2];
	}

	DEBUG(10, ("cli_find: %s %s %s",
		   srv_name, usr_creds->user_name, usr_creds->domain));

	if (key != NULL)
	{
		DEBUG(10, ("[%d,%x]", key->pid, key->vuid));
	}
	DEBUG(10, ("\n"));

	for (i = 0; i < num_msrpcs; i++)
	{
		char *cli_name = NULL;
		struct ncacn_np_use *c = msrpcs[i];
		vuser_key k;

		char *ncacn_np_name = NULL;

		if (c == NULL || c->cli == NULL || c->cli->smb == NULL ||
		    !c->cli->initialised)
		{
			continue;
		}

		ncacn_np_name = c->cli->pipe_name;
		cli_name = c->cli->smb->desthost;

		DEBUG(10, ("ncacn_np_find[%d]: %s %s %s %s [%d,%x]\n",
			   i, ncacn_np_name, cli_name,
			   c->cli->smb->usr.user_name,
			   c->cli->smb->usr.domain, k.pid, k.vuid));

		k = c->cli->smb->nt.key;

		if (strnequal("\\\\", cli_name, 2))
		{
			cli_name = &cli_name[2];
		}

		if (strnequal("\\PIPE\\", ncacn_np_name, 6))
		{
			ncacn_np_name = &ncacn_np_name[6];
		}

		if (!strequal(ncacn_np_name, pipe_name))
		{
			continue;
		}
		if (!strequal(cli_name, sv_name))
		{
			continue;
		}
		if (!strequal
		    (usr_creds->user_name, c->cli->smb->usr.user_name))
		{
			continue;
		}
		if (key != NULL && (k.pid != key->pid || k.vuid != key->vuid))
		{
			continue;
		}
		if (!reuse
		    && !pwd_compare(&usr_creds->pwd, &c->cli->smb->usr.pwd))
		{
			DEBUG(100, ("password doesn't match\n"));
			continue;
		}
		if (usr_creds->domain[0] == 0)
		{
			return c;
		}
		if (strequal(usr_creds->domain, c->cli->smb->usr.domain))
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
				  BOOL redir,
				  BOOL reuse, BOOL *is_new_connection)
{
	struct ncacn_np_use *cli;
	DEBUG(10, ("ncacn_np_use_add: %s redir: %s\n", pipe_name,
		   BOOLSTR(redir)));

	(*is_new_connection) = False;
	cli = ncacn_np_find(srv_name, pipe_name, key, ntc, reuse);

	if (cli != NULL)
	{
		cli->num_users++;
		return cli->cli;
	}

	/* reuse an existing connection requested, and one was not found */
	if (reuse)
	{
		DEBUG(0,
		      ("ncacn_np_use_add: reuse requested, but one not found\n"));
		return False;
	}

	/*
	 * allocate
	 */

	(*is_new_connection) = True;

	cli = ncacn_np_use_get(pipe_name, key);
	cli->cli->redirect = redir;

	if (!ncacn_np_establish_connection
	    (cli->cli, srv_name, ntc, pipe_name, redir, reuse))
	{
		DEBUG(0, ("ncacn_np_use_add: connection failed\n"));
		cli->cli = NULL;
		ncacn_np_use_free(cli);
		return NULL;
	}

	if (key != NULL)
	{
		cli->cli->smb->nt.key = *key;
	}
	else
	{
		cli->cli->smb->nt.key.pid = getpid();
		cli->cli->smb->nt.key.vuid = UID_FIELD_INVALID;
#if 0
		NET_USER_INFO_3 usr;
		uid_t uid = getuid();
		gid_t gid = getgid();
		char *name = uidtoname(uid);

		ZERO_STRUCT(usr);

		cli->cli->smb->nt.key.pid = getpid();
		cli->cli->smb->nt.key.vuid =
			register_vuid(cli->cli->smb->nt.key.pid, uid, gid,
				      name, name, False, &usr);
#endif
	}

	add_ncacn_np_to_array(&num_msrpcs, &msrpcs, cli);
	cli->num_users++;
	return cli->cli;
}

/****************************************************************************
delete a client state
****************************************************************************/
BOOL ncacn_np_use_del(const char *pipe_name,
		      const vuser_key * key,
		      BOOL force_close, BOOL *connection_closed)
{
	int i;
	DEBUG(10, ("ncacn_np_net_use_del: %s. force close: %s\n",
		   pipe_name, BOOLSTR(force_close)));
	if (connection_closed != NULL)
	{
		*connection_closed = False;
	}

	if (strnequal("\\PIPE\\", pipe_name, 6))
	{
		pipe_name = &pipe_name[6];
	}

	for (i = 0; i < num_msrpcs; i++)
	{
		char *ncacn_np_name = NULL;
		if (msrpcs[i] == NULL)
			continue;
		if (msrpcs[i]->cli == NULL)
			continue;
		ncacn_np_name = msrpcs[i]->cli->pipe_name;
		if (strnequal("\\PIPE\\", pipe_name, 6))
		{
			ncacn_np_name = &ncacn_np_name[6];
		}
		if (!strequal(ncacn_np_name, pipe_name))
			continue;
		if (key->pid != msrpcs[i]->cli->smb->nt.key.pid ||
		    key->vuid != msrpcs[i]->cli->smb->nt.key.vuid)
		{
			continue;
		}
		/* decrement number of users */
		msrpcs[i]->num_users--;
		DEBUG(10, ("idx: %i num_users now: %d\n",
			   i, msrpcs[i]->num_users));
		if (force_close || msrpcs[i]->num_users == 0)
		{
			ncacn_np_use_free(msrpcs[i]);
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
void ncacn_np_use_enum(uint32 * num_cons, struct use_info ***use)
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
			item.key = msrpcs[i]->cli->smb->nt.key;
		}

		add_use_info_to_array(num_cons, use, &item);
	}
}
