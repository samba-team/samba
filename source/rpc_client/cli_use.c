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
#include "trans2.h"

extern int DEBUGLEVEL;
extern pstring scope;
extern pstring global_myname;

struct cli_use
{
	struct cli_state *cli;
	uint32 num_users;
};

static struct cli_use **clis = NULL;
static uint32 num_clis = 0;

/****************************************************************************
terminate client connection
****************************************************************************/
static void cli_use_free(struct cli_use *cli)
{
	if (cli->cli != NULL)
	{
		if (cli->cli->initialised)
		{
			cli_ulogoff(cli->cli);
			cli_shutdown(cli->cli);
		}
		free(cli->cli);
	}

	free(cli);
}

/****************************************************************************
free a client array
****************************************************************************/
static void free_cli_array(uint32 num_entries, struct cli_use **entries)
{
	void (*fn) (void *) = (void (*)(void *))&cli_use_free;
	free_void_array(num_entries, (void **)entries, *fn);
}

/****************************************************************************
add a client state to the array
****************************************************************************/
static struct cli_use *add_cli_to_array(uint32 * len,
					struct cli_use ***array,
					struct cli_use *cli)
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

	return (struct cli_use *)add_item_to_array(len,
						   (void ***)array,
						   (void *)cli);

}

/****************************************************************************
initiate client array
****************************************************************************/
void init_cli_use(void)
{
	clis = NULL;
	num_clis = 0;
}

/****************************************************************************
terminate client array
****************************************************************************/
void free_cli_use(void)
{
	free_cli_array(num_clis, clis);
	init_cli_use();
}

/****************************************************************************
find client state.  server name, user name, domain name and password must all
match.
****************************************************************************/
static struct cli_use *cli_find(const char *srv_name,
				const struct ntuser_creds *usr_creds,
				BOOL reuse)
{
	int i;
	const char *sv_name = srv_name;
	struct ntuser_creds null_usr;

	copy_nt_creds(&null_usr, usr_creds);
	usr_creds = &null_usr;

	if (strnequal("\\\\", sv_name, 2))
	{
		sv_name = &sv_name[2];
	}

	DEBUG(10, ("cli_find: %s %s %s\n",
		   srv_name, usr_creds->user_name, usr_creds->domain));


	for (i = 0; i < num_clis; i++)
	{
		char *cli_name = NULL;
		struct cli_use *c = clis[i];

		if (c == NULL)
			continue;

		cli_name = c->cli->desthost;

		DEBUG(10, ("cli_find[%d]: %s %s %s\n",
			   i, cli_name,
			   c->cli->usr.user_name, c->cli->usr.domain));

		if (strnequal("\\\\", cli_name, 2))
		{
			cli_name = &cli_name[2];
		}

		if (!strequal(cli_name, sv_name))
		{
			continue;
		}
		if (!strequal(usr_creds->user_name, c->cli->usr.user_name))
		{
			continue;
		}
		if (!reuse && !pwd_compare(&usr_creds->pwd, &c->cli->usr.pwd))
		{
			DEBUG(100, ("password doesn't match\n"));
			continue;
		}
		if (usr_creds->domain[0] == 0)
		{
			return c;
		}
		if (strequal(usr_creds->domain, c->cli->usr.domain))
		{
			return c;
		}
	}

	return NULL;
}

/****************************************************************************
create a new client state from user credentials
****************************************************************************/
static struct cli_use *cli_use_get(const char *srv_name,
				   const struct ntuser_creds *usr_creds)
{
	struct cli_use *cli = (struct cli_use *)malloc(sizeof(*cli));

	if (cli == NULL)
	{
		return NULL;
	}

	memset(cli, 0, sizeof(*cli));

	cli->cli = cli_initialise(NULL);

	if (cli->cli == NULL)
	{
		return NULL;
	}

	cli_init_creds(cli->cli, usr_creds);

	return cli;
}

/****************************************************************************
init client state
****************************************************************************/
struct cli_state *cli_net_use_add(const char *srv_name,
				  const struct ntuser_creds *usr_creds,
				  BOOL redir, BOOL reuse, BOOL *is_new)
{
	struct nmb_name calling;
	struct nmb_name called;
	struct in_addr *dest_ip = NULL;
	fstring dest_host;
	struct in_addr ip;

	struct cli_use *cli;

	DEBUG(10, ("cli_net_use_add\n"));

	cli = cli_find(srv_name, usr_creds, reuse);

	if (cli != NULL)
	{
		cli->num_users++;
		DEBUG(10,
		      ("cli_net_use_add: num_users: %d\n", cli->num_users));
		(*is_new) = False;
		return cli->cli;
	}

	/* reuse an existing connection requested, and one was not found */
	if (usr_creds != NULL && reuse && !redir)
	{
		return False;
	}

	/*
	 * allocate
	 */

	cli = cli_use_get(srv_name, usr_creds);
	cli->cli->redirect = redir;

	if (resolve_srv_name(srv_name, dest_host, &ip))
	{
		dest_ip = &ip;
	}
	else
	{
		cli_use_free(cli);
		return NULL;
	}

	make_nmb_name(&called, dns_to_netbios_name(dest_host), 32, scope);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0, scope);

	/*
	 * connect
	 */

	if (!cli_establish_connection(cli->cli,
				      dest_host, dest_ip,
				      &calling, &called,
				      "IPC$", "IPC", False, True))
	{
		DEBUG(0, ("cli_net_use_add: connection failed\n"));
		cli->cli = NULL;
		cli_use_free(cli);
		return NULL;
	}

	add_cli_to_array(&num_clis, &clis, cli);
	cli->num_users++;

	DEBUG(10, ("cli_net_use_add: num_users: %d\n", cli->num_users));

	(*is_new) = True;

	return cli->cli;
}

/****************************************************************************
delete a client state
****************************************************************************/
BOOL cli_net_use_del(const char *srv_name,
		     const struct ntuser_creds *usr_creds,
		     BOOL force_close, BOOL *connection_closed)
{
	int i;
	const char *sv_name = srv_name;

	DEBUG(10, ("cli_net_use_del: %s. %s. %s. force close: %s\n",
		   srv_name,
		   usr_creds->user_name, usr_creds->domain,
		   BOOLSTR(force_close)));

	if (strnequal("\\\\", sv_name, 2))
	{
		sv_name = &sv_name[2];
	}

	if (connection_closed != NULL)
	{
		*connection_closed = False;
	}

	for (i = 0; i < num_clis; i++)
	{
		char *cli_name = NULL;

		if (clis[i] == NULL)
			continue;
		if (clis[i]->cli == NULL)
			continue;

		cli_name = clis[i]->cli->desthost;

		DEBUG(10, ("connection: %s %s %s\n", cli_name,
			   clis[i]->cli->usr.user_name,
			   clis[i]->cli->usr.domain));

		if (strnequal("\\\\", cli_name, 2))
		{
			cli_name = &cli_name[2];
		}

		if (!strequal(cli_name, sv_name))
			continue;

		if (strequal(usr_creds->user_name,
			     clis[i]->cli->usr.user_name) &&
		    strequal(usr_creds->domain, clis[i]->cli->usr.domain))
		{
			/* decrement number of users */
			clis[i]->num_users--;

			DEBUG(10, ("idx: %i num_users now: %d\n",
				   i, clis[i]->num_users));

			if (force_close || clis[i]->num_users == 0)
			{
				cli_use_free(clis[i]);
				clis[i] = NULL;
				if (connection_closed != NULL)
				{
					*connection_closed = True;
				}
			}
			return True;
		}
	}

	return False;
}

/****************************************************************************
enumerate client states
****************************************************************************/
void cli_net_use_enum(uint32 * num_cons, struct use_info ***use)
{
	int i;

	*num_cons = 0;
	*use = NULL;

	for (i = 0; i < num_clis; i++)
	{
		struct use_info item;

		ZERO_STRUCT(item);

		if (clis[i] == NULL)
			continue;

		item.connected = clis[i]->cli != NULL ? True : False;

		if (item.connected)
		{
			item.srv_name = clis[i]->cli->desthost;
			item.user_name = clis[i]->cli->usr.user_name;
			item.key = clis[i]->cli->nt.key;
			item.domain = clis[i]->cli->usr.domain;
		}

		add_use_info_to_array(num_cons, use, &item);
	}
}


/****************************************************************************
wait for keyboard activity, swallowing network packets on all client states.
****************************************************************************/
void cli_use_wait_keyboard(void)
{
	fd_set fds;
	struct timeval timeout;

	while (1)
	{
		int i;
		int maxfd = fileno(stdin);
		FD_ZERO(&fds);
		FD_SET(fileno(stdin), &fds);
		for (i = 0; i < num_clis; i++)
		{
			if (clis[i] != NULL && clis[i]->cli != NULL)
			{
				int fd = clis[i]->cli->fd;
				FD_SET(fd, &fds);
				maxfd = MAX(fd, maxfd);
			}
		}

		timeout.tv_sec = 20;
		timeout.tv_usec = 0;
		sys_select(maxfd + 1, NULL, &fds, &timeout);

		if (FD_ISSET(fileno(stdin), &fds))
			return;

		/* We deliberately use receive_smb instead of
		   client_receive_smb as we want to receive
		   session keepalives and then drop them here.
		 */
		for (i = 0; i < num_clis; i++)
		{
			int fd = clis[i]->cli->fd;
			if (FD_ISSET(fd, &fds))
				receive_smb(fd, clis[i]->cli->inbuf, 0);
		}
	}
}
