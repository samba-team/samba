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
uint32 num_clis = 0;

/****************************************************************************
terminate client connection
****************************************************************************/
static void cli_use_free(struct cli_use *cli)
{
	cli_ulogoff(cli->cli);
	cli_shutdown(cli->cli);
	free(cli->cli);

	free(cli);
}

/****************************************************************************
free a client array
****************************************************************************/
static void free_cli_array(uint32 num_entries, struct cli_use **entries)
{
	void(*fn)(void*) = (void(*)(void*))&cli_use_free;
	free_void_array(num_entries, (void**)entries, *fn);
}

/****************************************************************************
add a client state to the array
****************************************************************************/
static struct cli_use* add_cli_to_array(uint32 *len,
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

	return (struct cli_use*)add_item_to_array(len,
	                     (void***)array, (void*)cli);
				
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
static struct cli_use *cli_find(const char* srv_name,
				const struct user_credentials *usr_creds)
{
	int i;
	const char *sv_name = srv_name;
	if (strnequal("\\\\", sv_name, 2))
	{
		sv_name = &sv_name[2];
	}

	for (i = 0; i < num_clis; i++)
	{
		uchar ntpw[16], clintpw[16];
		char *cli_name = NULL;

		if (clis[i] == NULL) continue;

		cli_name = clis[i]->cli->desthost;
		if (strnequal("\\\\", cli_name, 2))
		{
			cli_name = &cli_name[2];
		}

		if (!strequal(cli_name, sv_name)) continue;

		pwd_get_lm_nt_16(&usr_creds->pwd, NULL, ntpw);
		pwd_get_lm_nt_16(&clis[i]->cli->usr.pwd, NULL, clintpw);

		if (strequal(usr_creds->user_name, clis[i]->cli->usr.user_name) &&
		    strequal(usr_creds->domain, clis[i]->cli->usr.domain) &&
		    memcmp(ntpw, clintpw, 16) == 0)
		{
			return clis[i];
		}
	}

	return NULL;
}

/****************************************************************************
create a new client state from user credentials
****************************************************************************/
static struct cli_use *cli_use_get(const char* srv_name,
				const struct user_credentials *usr_creds)
{
	struct cli_use *cli = (struct cli_use*)malloc(sizeof(*cli));

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

	cli->cli->capabilities |= CAP_NT_SMBS | CAP_STATUS32;
	cli_init_creds(cli->cli, usr_creds);

	cli->cli->use_ntlmv2 = lp_client_ntlmv2();

	return cli;
}

/****************************************************************************
init client state
****************************************************************************/
struct cli_state *cli_net_use_addlist(char* servers,
				const struct user_credentials *usr_creds)
{
	struct cli_use *cli = cli_find(servers, usr_creds); 

	if (cli != NULL)
	{
		cli->num_users++;
		return cli->cli;
	}

	/*
	 * allocate
	 */

	cli = cli_use_get(servers, usr_creds);

	if (cli == NULL)
	{
		return NULL;
	}

	if (!cli_connect_serverlist(cli->cli, servers))
	{
		DEBUG(0,("cli_net_use_addlist: connection failed\n"));
		cli_use_free(cli);
		return NULL;
	}

	cli->cli->ntlmssp_cli_flgs = 0x0;

	add_cli_to_array(&num_clis, &clis, cli);
	cli->num_users++;

	return cli->cli;
}

/****************************************************************************
init client state
****************************************************************************/
struct cli_state *cli_net_use_add(const char* srv_name,
				const struct user_credentials *usr_creds)
{
	struct nmb_name calling;
	struct nmb_name called;
	struct in_addr *dest_ip = NULL;
	fstring dest_host;
	struct in_addr ip;

	struct cli_use *cli = cli_find(srv_name, usr_creds); 

	if (cli != NULL)
	{
		cli->num_users++;
		return cli->cli;
	}

	/*
	 * allocate
	 */

	cli = cli_use_get(srv_name, usr_creds);

	if (resolve_srv_name(srv_name, dest_host, &ip))
	{
		dest_ip = &ip;
	}
	else
	{
		cli_use_free(cli);
		return NULL;
	}

	make_nmb_name(&called , dns_to_netbios_name(dest_host    ), 32, scope);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname),  0, scope);

	/*
	 * connect
	 */

	if (!cli_establish_connection(cli->cli, 
	                          dest_host, dest_ip,
	                          &calling, &called,
	                          "IPC$", "IPC",
	                          False, True))
	{
		DEBUG(0,("cli_net_use_add: connection failed\n"));
		cli_use_free(cli);
		return NULL;
	}

	cli->cli->ntlmssp_cli_flgs = 0x0;

	add_cli_to_array(&num_clis, &clis, cli);
	cli->num_users++;

	return cli->cli;
}

/****************************************************************************
delete a client state
****************************************************************************/
BOOL cli_net_use_del(const char* srv_name,
				const struct user_credentials *usr_creds,
				BOOL force_close,
				BOOL *connection_closed)
{
	int i;
	const char *sv_name = srv_name;

	DEBUG(10,("cli_net_use_del: %s. force close: %s\n",
	           srv_name, BOOLSTR(force_close)));
	dbgflush();

	if (strnequal("\\\\", sv_name, 2))
	{
		sv_name = &sv_name[2];
	}

	*connection_closed = False;

	for (i = 0; i < num_clis; i++)
	{
		char *cli_name = NULL;

		if (clis[i] == NULL) continue;
		if (clis[i]->cli == NULL) continue;

		cli_name = clis[i]->cli->desthost;
		if (strnequal("\\\\", cli_name, 2))
		{
			cli_name = &cli_name[2];
		}

		if (!strequal(cli_name, sv_name)) continue;

		if (strequal(usr_creds->user_name,
                             clis[i]->cli->usr.user_name) &&
		    strequal(usr_creds->domain,
		             clis[i]->cli->usr.domain))
		{
			/* decrement number of users */
			clis[i]->num_users--;

			DEBUG(10,("idx: %i num_users now: %d\n",
				   i, clis[i]->num_users));
			dbgflush();

			if (force_close || clis[i]->num_users == 0)
			{
				cli_use_free(clis[i]);
				clis[i] = NULL;
				*connection_closed = True;
			}
			return True;
		}
	}

	return False;
}

