/* 
   Unix SMB/Netbios implementation.
   Version 2
   SMB agent/socket plugin
   Copyright (C) Andrew Tridgell 1999
   
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

#include "includes.h"
#include "smb.h"

extern int DEBUGLEVEL;

static char packet[BUFFER_SIZE];

/****************************************************************************
terminate sockent connection
****************************************************************************/
static void free_sock(void *sock)
{
	if (sock != NULL)
	{
		struct msrpc_state *n = (struct msrpc_state*)sock;
		msrpc_use_del(n->pipe_name, &n->usr, False, NULL);
	}
}

static struct msrpc_state *init_client_connection(int c)
{
	pstring buf;
	fstring pipe_name;
	struct user_creds usr;
	int rl;
	uint32 len;
	BOOL new_con = False;
	struct msrpc_state *n = NULL;

	CREDS_CMD cmd;
	prs_struct ps;

	ZERO_STRUCT(usr);
	ZERO_STRUCT(cmd);
	cmd.cred = &usr;

	DEBUG(10,("init_client_connection: first request\n"));

	rl = read(c, &buf, sizeof(len));

	if (rl != sizeof(len))
	{
		DEBUG(0,("Unable to read length\n"));
		dump_data(0, buf, sizeof(len));
		return NULL;
	}

	len = IVAL(buf, 0);

	if (len > sizeof(buf))
	{
		DEBUG(0,("length %d too long\n", len));
		return NULL;
	}

	rl = read(c, buf, len);

	if (rl < 0)
	{
		DEBUG(0,("Unable to read from connection\n"));
		return NULL;
	}
	
#ifdef DEBUG_PASSWORD
	dump_data(100, buf, rl);
#endif

 	/* make a static data parsing structure from the api_fd_reply data */
 	prs_create(&ps, buf, len, 4, True);

	if (!creds_io_cmd("creds", &cmd, &ps, 0))
	{
		DEBUG(0,("Unable to parse credentials\n"));
		prs_free_data(&ps);
		return NULL;
	}

 	prs_free_data(&ps);

	if (ps.offset != rl)
	{
		DEBUG(0,("Buffer size %d %d!\n", ps.offset, rl));
		return NULL;
	}

	switch (cmd.command)
	{
		case AGENT_CMD_CON:
		case AGENT_CMD_CON_ANON:
		{
			new_con = True;
			break;
		}
		case AGENT_CMD_CON_REUSE:
		{
			new_con = True;
			break;
		}
		default:
		{
			DEBUG(0,("unknown command %d\n", cmd.command));
			return NULL;
		}
	}

	if (new_con)
	{
		uint32 status = 0;
		n = msrpc_use_add(pipe_name, cmd.pid, &usr, False);

		if (n == NULL)
		{
			DEBUG(0,("Unable to connect to %s\n", pipe_name));
			status = 0x1;
		}
		else
		{
			fstrcpy(n->pipe_name, pipe_name);
			copy_user_creds(&n->usr, &usr);
		}
		
		if (write(c, &status, sizeof(status)) != sizeof(status))
		{
			DEBUG(0,("Could not write connection down pipe.\n"));
			if (n != NULL)
			{
				msrpc_use_del(pipe_name, &usr, False, NULL);
				n = NULL;
			}
		}
	}
	free_user_creds(&usr);
	return n;
}

static BOOL process_cli_sock(struct sock_redir **socks, uint32 num_socks,
				struct sock_redir *sock)
{
	struct msrpc_state *n = (struct msrpc_state*)sock->n;
	if (n == NULL)
	{
		n = init_client_connection(sock->c);
		if (n == NULL)
		{
			return False;
		}
		sock->n = (void*)n;
		sock->s = n->fd;
	}
	else
	{
		if (!receive_smb(sock->c, packet, 0))
		{
			DEBUG(0,("client closed connection\n"));
			return False;
		}

		if (!send_smb(sock->s, packet))
		{
			DEBUG(0,("server is dead\n"));
			return False;
		}			
	}
	return True;
}

static BOOL process_srv_sock(struct sock_redir **socks, uint32 num_socks,
				int fd)
{
	int i;
	if (!receive_smb(fd, packet, 0))
	{
		DEBUG(0,("server closed connection\n"));
		return False;
	}

	DEBUG(10,("process_srv_sock:\tfd:\t%d\n", fd));

	for (i = 0; i < num_socks; i++)
	{
		struct msrpc_state *n;
		if (socks[i] == NULL || socks[i]->n == NULL)
		{
			continue;
		}
		n = (struct msrpc_state*)socks[i]->n;
		DEBUG(10,("list:\tfd:\t%d\n",
		           socks[i]->s));
		if (!send_smb(socks[i]->c, packet))
		{
			DEBUG(0,("client is dead\n"));
			return False;
		}			
		return True;
	}
	return False;
}

static int get_agent_sock(char *pipe_name)
{
	fstring path;
	fstring dir;

	slprintf(dir, sizeof(dir)-1, "/tmp/.msrpc/.%s", pipe_name);
	slprintf(path, sizeof(path)-1, "%s/agent", dir);

	return create_pipe_socket(dir, S_IRUSR|S_IWUSR|S_IXUSR, path, 0);
}

void start_msrpc_agent(char *pipe_name)
{
	struct vagent_ops va =
	{
		free_sock,
		get_agent_sock,
		process_cli_sock,
		process_srv_sock,
		NULL,
		NULL,
		0
	};

	if (fork() == 0)
	{
		/* child */
		va.id = pipe_name;
		start_agent(&va);
	}
}

