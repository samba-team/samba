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

#define SECURITY_MASK 0
#define SECURITY_SET  0

/* this forces non-unicode */
#define CAPABILITY_MASK CAP_UNICODE
#define CAPABILITY_SET  0

/* and non-unicode for the client too */
#define CLI_CAPABILITY_MASK CAP_UNICODE
#define CLI_CAPABILITY_SET  0

static char packet[BUFFER_SIZE];

extern int DEBUGLEVEL;


static uint16 mid_offset = 0x0;

/****************************************************************************
terminate sockent connection
****************************************************************************/
static void free_sock(void *sock)
{
	if (sock != NULL)
	{
		struct cli_state *n = (struct cli_state *)sock;
		cli_net_use_del(n->desthost, &n->usr, False, NULL);
	}
}


static struct cli_state *init_client_connection(int c)
{
	pstring buf;
	struct user_creds usr;
	int rl;
	uint32 len;
	BOOL new_con = False;
	CREDS_CMD cmd;
	prs_struct ps;
	BOOL reuse = False;

	ZERO_STRUCT(usr);
	ZERO_STRUCT(cmd);
	cmd.cred = &usr;

	ZERO_STRUCT(usr);

	DEBUG(10, ("init_client_connection: first request\n"));

	rl = read(c, &buf, sizeof(len));

	if (rl != sizeof(len))
	{
		DEBUG(0, ("Unable to read length\n"));
		dump_data(0, buf, sizeof(len));
		return NULL;
	}

	len = IVAL(buf, 0);

	if (len > sizeof(buf))
	{
		DEBUG(0, ("length %d too long\n", len));
		return NULL;
	}

	rl = read(c, buf, len);

	if (rl < 0)
	{
		DEBUG(0, ("Unable to read from connection\n"));
		return NULL;
	}

#ifdef DEBUG_PASSWORD
	dump_data(100, buf, rl);
#endif
	/* make a static data parsing structure from the api_fd_reply data */
	prs_init(&ps, 0, 4, True);
	prs_append_data(&ps, buf, rl);

	if (!creds_io_cmd("creds", &cmd, &ps, 0))
	{
		DEBUG(0, ("Unable to parse credentials\n"));
		prs_free_data(&ps);
		return NULL;
	}

	prs_free_data(&ps);

	if (ps.offset != rl)
	{
		DEBUG(0, ("Buffer size %d %d!\n", ps.offset, rl));
		return NULL;
	}

	switch (cmd.command)
	{
		case AGENT_CMD_CON:
		{
			new_con = True;
			break;
		}
		case AGENT_CMD_CON_REUSE:
		{
			new_con = True;
			reuse = True;
			break;
		}
		default:
		{
			DEBUG(0, ("unknown command %d\n", cmd.command));
			return NULL;
		}
	}

	if (new_con)
	{
		struct cli_state *n;
		n =
			cli_net_use_add(cmd.name, cmd.key, &usr.ntc, False,
					reuse);

		if (n == NULL)
		{
			DEBUG(0, ("Unable to connect to %s\n", cmd.name));
			return NULL;
		}

		mid_offset += MIN(MAX(n->max_mux, 1), MAX_MAX_MUX_LIMIT);

		if (mid_offset > 0xffff)
		{
			mid_offset = 0x0;
		}
		DEBUG(10, ("new mid offset: %d\n", mid_offset));

		if (write(c, n, sizeof(*n)) < 0)
		{
			DEBUG(0, ("Could not write connection down pipe.\n"));
			cli_net_use_del(cmd.name, &usr.ntc, False, NULL);
			return NULL;
		}
		return n;
	}
	return NULL;
}

static void filter_reply(char *buf, int moff)
{
	int msg_type = CVAL(buf, 0);
	int x;

	if (msg_type != 0x0)
		return;

	/* alter the mid */
	x = SVAL(buf, smb_mid);
	x += moff;

	if (x < 0)
	{
		x += 0x10000;
	}
	if (x > 0xffff)
	{
		x -= 0x10000;
	}

	SCVAL(buf, smb_mid, x);

}

static BOOL process_cli_sock(struct sock_redir **socks, uint32 num_socks,
			     struct sock_redir *sock)
{
	struct cli_state *n = (struct cli_state *)sock->n;
	if (n == NULL)
	{
		n = init_client_connection(sock->c);
		if (n == NULL)
		{
			return False;
		}
		sock->n = (void *)n;
		sock->s_id = mid_offset;
		sock->s = n->fd;
	}
	else
	{
		if (!receive_smb(sock->c, packet, 0))
		{
			DEBUG(0, ("client closed connection\n"));
			return False;
		}

		filter_reply(packet, sock->s_id);
		/* ignore keep-alives */
		if (CVAL(packet, 0) != 0x85)
		{
			if (!send_smb(sock->s, packet))
			{
				DEBUG(0, ("server is dead\n"));
				return False;
			}
		}
	}
	return True;
}

static int get_smbmid(char *buf)
{
	int msg_type = CVAL(buf, 0);

	if (msg_type != 0x0)
	{
		return -1;
	}

	return SVAL(buf, smb_mid);
}

static BOOL process_srv_sock(struct sock_redir **socks, uint32 num_socks,
			     int fd)
{
	int smbmid;
	int i;
	if (!receive_smb(fd, packet, 0))
	{
		DEBUG(0, ("server closed connection\n"));
		return False;
	}

	smbmid = get_smbmid(packet);

	DEBUG(10, ("process_srv_sock:\tfd:\t%d\tmid:\t%d\n", fd, smbmid));

	if (smbmid == -1)
	{
		return True;
	}

	for (i = 0; i < num_socks; i++)
	{
		int moff;
		struct cli_state *n;
		if (socks[i] == NULL || socks[i]->n == NULL)
		{
			continue;
		}
		moff = socks[i]->s_id;
		n = (struct cli_state *)socks[i]->n;
		DEBUG(10, ("list:\tfd:\t%d\tmid:\t%d\tmoff:\t%d\n",
			   socks[i]->s, n->mid, moff));
		if (smbmid != n->mid + moff)
		{
			continue;
		}
		filter_reply(packet, -moff);
		if (!send_smb(socks[i]->c, packet))
		{
			DEBUG(0, ("client is dead\n"));
			return False;
		}
		return True;
	}
	return False;
}

static int get_agent_sock(char *id)
{
	int s;
	fstring path;
	fstring dir;

	slprintf(dir, sizeof(dir) - 1, "/tmp/.smb.%d", getuid());
	slprintf(path, sizeof(path) - 1, "%s/agent", dir);

	s = create_pipe_socket(dir, 0700, path, 0700);

	if (s == -1)
		return -1;
	/* ready to listen */
	if (listen(s, 5) == -1)
	{
		DEBUG(0, ("listen: %s\n", strerror(errno)));
		close(s);
		return -1;
	}
	return s;
}

static void start_smb_agent(void)
{
	struct vagent_ops va = {
		free_sock,
		get_agent_sock,
		process_cli_sock,
		process_srv_sock,
		NULL,
		NULL,
		0
	};

	CatchChild();

	start_agent(&va);
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
	printf("Usage: %s [-D]", pname);

	printf("\nVersion %s\n", VERSION);
	printf("\t-D 		run as a daemon\n");
	printf("\t-h 		usage\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	pstring configfile;
	BOOL is_daemon = False;
	int opt;
	extern pstring debugf;

	TimeInit();

	pstrcpy(configfile, CONFIGFILE);

	while ((opt = getopt(argc, argv, "Dh")) != EOF)
	{
		switch (opt)
		{
			case 'D':
			{
				is_daemon = True;
				break;
			}
			case 'h':
			default:
			{
				usage(argv[0]);
				break;
			}
		}
	}

	slprintf(debugf, sizeof(debugf) - 1, "log.%s", argv[0]);
	setup_logging(argv[0], !is_daemon);

	charset_initialise();

	if (!lp_load(configfile, True, False, False))
	{
		DEBUG(0, ("Unable to load config file\n"));
	}

	if (is_daemon)
	{
		DEBUG(0, ("%s: becoming daemon\n", argv[0]));
		become_daemon();
	}

	start_smb_agent();

	return 0;
}
