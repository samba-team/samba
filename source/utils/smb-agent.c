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


struct sock_redir
{
	int c;
	struct cli_state *s;

};

static uint32 num_socks = 0;
static struct sock_redir **socks = NULL;

/****************************************************************************
terminate sockent connection
****************************************************************************/
static void sock_redir_free(struct sock_redir *sock)
{
	close(sock->c);
	sock->c = -1;
	if (sock->s != NULL)
	{
		cli_net_use_del(sock->s->desthost, &sock->s->usr,
		                False, NULL);
		sock->s = NULL;
	}
	free(sock);
}

/****************************************************************************
free a sockent array
****************************************************************************/
static void free_sock_array(uint32 num_entries, struct sock_redir **entries)
{
	void(*fn)(void*) = (void(*)(void*))&sock_redir_free;
	free_void_array(num_entries, (void**)entries, *fn);
}

/****************************************************************************
add a sockent state to the array
****************************************************************************/
static struct sock_redir* add_sock_to_array(uint32 *len,
				struct sock_redir ***array,
				struct sock_redir *sock)
{
	int i;
	for (i = 0; i < num_socks; i++)
	{
		if (socks[i] == NULL)
		{
			socks[i] = sock;
			return sock;
		}
	}

	return (struct sock_redir*)add_item_to_array(len,
	                     (void***)array, (void*)sock);
				
}

/****************************************************************************
initiate sockent array
****************************************************************************/
void init_sock_redir(void)
{
	socks = NULL;
	num_socks = 0;
}

/****************************************************************************
terminate sockent array
****************************************************************************/
void free_sock_redir(void)
{
	free_sock_array(num_socks, socks);
	init_sock_redir();
}

/****************************************************************************
create a new sockent state from user credentials
****************************************************************************/
static struct sock_redir *sock_redir_get(int fd, struct cli_state *cli)
{
	struct sock_redir *sock = (struct sock_redir*)malloc(sizeof(*sock));

	if (sock == NULL)
	{
		return NULL;
	}

	ZERO_STRUCTP(sock);

	sock->c = fd;
	sock->s = cli;

	return sock;
}

/****************************************************************************
init sock state
****************************************************************************/
static void sock_add(int fd, struct cli_state *cli)
{
	struct sock_redir *sock;
	sock = sock_redir_get(fd, cli);
	if (sock != NULL)
	{
		add_sock_to_array(&num_socks, &socks, sock);
	}
}

/****************************************************************************
delete a sockent state
****************************************************************************/
static BOOL sock_del(int fd)
{
	int i;

	for (i = 0; i < num_socks; i++)
	{
		if (socks[i] == NULL) continue;
		if (socks[i]->c == fd) 
		{
			sock_redir_free(socks[i]);
			socks[i] = NULL;
			return True;
		}
	}

	return False;
}

static struct cli_state *init_client_connection(int c)
{
	pstring buf;
	uchar ntpw[16];
	uchar lmpw[16];
	fstring srv_name;
	struct user_credentials usr;
	char *p = buf;
	int rl;
	uint32 len;
	uint16 version;
	uint16 command;
	BOOL new_con = False;

	ZERO_STRUCT(usr);

	DEBUG(10,("first request\n"));

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
	version = SVAL(p, 0);
	p += 2;
	command = SVAL(p, 0);
	p += 2;

	fstrcpy(srv_name, p);
	p = skip_string(p, 1);
	fstrcpy(usr.user_name, p);
	p = skip_string(p, 1);
	fstrcpy(usr.domain, p);
	p = skip_string(p, 1);

	if (PTR_DIFF(p, buf) < rl)
	{
		memcpy(lmpw, p, 16);
		p += 16;
		memcpy(ntpw, p, 16);
		p += 16;
		pwd_set_lm_nt_16(&usr.pwd, lmpw, ntpw);
	}
	else
	{
		pwd_set_nullpwd(&usr.pwd);
	}

	if (PTR_DIFF(p, buf) != rl)
	{
		DEBUG(0,("Buffer size %d %d!\n",
			PTR_DIFF(p, buf), rl));
		return NULL;
	}

	switch (command)
	{
		case AGENT_CMD_CON:
		{
			new_con = True;
			break;
		}
		case AGENT_CMD_CON_REUSE:
		{
			new_con = True;
			usr.reuse = True;
			break;
		}
		default:
		{
			DEBUG(0,("unknown command %d\n", command));
			return NULL;
		}
	}

	if (new_con)
	{
		struct cli_state *s;
		s = cli_net_use_add(srv_name, &usr, False);

		if (s == NULL)
		{
			DEBUG(0,("Unable to connect to %s\n", srv_name));
			return NULL;
		}
		if (write(c, s, sizeof(*s)) < 0)
		{
			DEBUG(0,("Could not write connection down pipe.\n"));
			cli_net_use_del(srv_name, &usr, False, NULL);
			return NULL;
		}
		return s;
	}
	return NULL;
}

void process_cli_sock(struct sock_redir **sock)
{
	struct cli_state *s = (*sock)->s;
	if (s == NULL)
	{
		s = init_client_connection((*sock)->c);
		if (s == NULL)
		{
			sock_redir_free(*sock);
			*sock = NULL;
			return ;
		}
		(*sock)->s = s;
	}
	else
	{
		if (!receive_smb((*sock)->c, packet, 0))
		{
			DEBUG(0,("client closed connection\n"));
			sock_redir_free(*sock);
			*sock = NULL;
			return;
		}
		/* ignore keep-alives */
		if (CVAL(packet, 0) != 0x85)
		{
			if (!send_smb(s->fd, packet))
			{
				DEBUG(0,("server is dead\n"));
				sock_redir_free(*sock);
				*sock = NULL;
				return;
			}			
		}
	}
}

void process_srv_sock(struct sock_redir **sock)
{
	struct cli_state *s = (*sock)->s;
	if (!receive_smb(s->fd, packet, 0))
	{
		DEBUG(0,("server closed connection\n"));
		sock_redir_free(*sock);
		(*sock) = NULL;
		return;
	}
	if (!send_smb((*sock)->c, packet))
	{
		DEBUG(0,("client is dead\n"));
		sock_redir_free(*sock);
		(*sock) = NULL;
		return;
	}			
}


static void start_agent(void)
{
	int s, c;
	struct sockaddr_un sa;
	fstring path;
	fstring dir;

	CatchChild();

	slprintf(dir, sizeof(dir)-1, "/tmp/.smb.%d", getuid());
	mkdir(dir, S_IRUSR|S_IWUSR|S_IXUSR);

	slprintf(path, sizeof(path)-1, "%s/agent", dir);
	if (chmod(dir, S_IRUSR|S_IWUSR|S_IXUSR) < 0)
	{
		fprintf(stderr, "chmod on %s failed\n", sa.sun_path);
		exit(1);
	}


	/* start listening on unix socket */
	s = socket(AF_UNIX, SOCK_STREAM, 0);

	if (s < 0)
	{
		fprintf(stderr, "socket open failed\n");
		exit(1);
	}

	ZERO_STRUCT(sa);
	sa.sun_family = AF_UNIX;
	safe_strcpy(sa.sun_path, path, sizeof(sa.sun_path)-1);

	if (bind(s, (struct sockaddr*) &sa, sizeof(sa)) < 0)
	{
		fprintf(stderr, "socket bind to %s failed\n", sa.sun_path);
		close(s);
		remove(path);
		exit(1);
	}

	if (s == -1)
	{
		DEBUG(0,("bind failed\n"));
		remove(path);
		exit(1);
	}

	if (listen(s, 5) == -1)
	{
		DEBUG(0,("listen failed\n"));
		remove(path);
	}

	while (1)
	{
		int i;
		fd_set fds;
		int num;
		struct sockaddr_un addr;
		int in_addrlen = sizeof(addr);
		int maxfd = s;
		
		FD_ZERO(&fds);
		FD_SET(s, &fds);

		for (i = 0; i < num_socks; i++)
		{
			if (socks[i] != NULL)
			{
				int fd = socks[i]->c;
				FD_SET(fd, &fds);
				maxfd = MAX(maxfd, fd);

				if (socks[i]->s != NULL)
				{
					fd = socks[i]->s->fd;
					FD_SET(fd, &fds);
					maxfd = MAX(fd, maxfd);
				}
			}
		}

		dbgflush();
		num = sys_select(maxfd+1,&fds,NULL, NULL);

		if (num <= 0)
		{
			continue;
		}

		if (FD_ISSET(s, &fds))
		{
			c = accept(s, (struct sockaddr*)&addr, &in_addrlen);
			if (c != -1)
			{
				sock_add(c, NULL);
			}
		}

		for (i = 0; i < num_socks; i++)
		{
			if (socks[i] == NULL)
			{
				continue;
			}
			if (FD_ISSET(socks[i]->c, &fds))
			{
				process_cli_sock(&socks[i]);
			}
			if (socks[i] == NULL)
			{
				continue;
			}
			if (socks[i]->s == NULL)
			{
				continue;
			}
			if (FD_ISSET(socks[i]->s->fd, &fds))
			{
				process_srv_sock(&socks[i]);
			}
		}
	}
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  printf("Usage: %s [-D]", pname);

  printf("\nVersion %s\n",VERSION);
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

	pstrcpy(configfile,CONFIGFILE);
 
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

	slprintf(debugf, sizeof(debugf)-1, "log.%s", argv[0]);
	setup_logging(argv[0], !is_daemon);
  
	charset_initialise();

	if (!lp_load(configfile,True,False,False))
	{
		DEBUG(0,("Unable to load config file\n"));
	}

	if (is_daemon)
	{
		DEBUG(0,("%s: becoming daemon\n", argv[0]));
		become_daemon();
	}

	start_agent();

	return 0;
}
