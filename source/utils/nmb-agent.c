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

extern int DEBUGLEVEL;

static int ClientNMB = -1;

struct sock_redir
{
	int c;
	int s;
	int c_trn_id;
	int s_trn_id;
	struct nmb_state *n;
	time_t time;

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
	if (sock->n != NULL)
	{
#if 0
		free(sock->n);
#endif
		sock->n = NULL;
	}
#if 0
	free(sock);
#endif
	ZERO_STRUCTP(sock);
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
static struct sock_redir *sock_redir_get(int fd)
{
	struct sock_redir *sock;

	sock = (struct sock_redir*)malloc(sizeof(*sock));

	if (sock == NULL)
	{
		return NULL;
	}

	ZERO_STRUCTP(sock);

	sock->c = fd;
	sock->s = -1;
	sock->n = NULL;
	sock->time = time(NULL);

	DEBUG(10,("sock_redir_get:\tfd:\t%d\t\n", fd));

	return sock;
}

/****************************************************************************
init sock state
****************************************************************************/
static void sock_add(int fd)
{
	struct sock_redir *sock;
	sock = sock_redir_get(fd);
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

static void filter_reply(struct packet_struct *p, int tr_id)
{
	p->packet.nmb.header.name_trn_id = tr_id;
}

static BOOL process_cli_sock(struct sock_redir **sock)
{
	struct packet_struct *p;
	struct nmb_state *nmb;
	static uint16 trn_id = 0x0;

	p = receive_packet((*sock)->c, NMB_SOCK_PACKET, 0);
	if (p == NULL)
	{
		DEBUG(0,("client closed connection\n"));
		return False;
	}

	nmb = (struct nmb_state*)malloc(sizeof(struct nmb_state));
	if (nmb == NULL)
	{
		free(p);
		return False;
	}

	(*sock)->s = ClientNMB;
	(*sock)->n = nmb;
	(*sock)->c_trn_id = p->packet.nmb.header.name_trn_id;
	(*sock)->s_trn_id = trn_id;
	trn_id++;
	if (trn_id > 0xffff)
	{
		trn_id = 0x0;
	}

	DEBUG(10,("new trn_id: %d\n", trn_id));

	filter_reply(p, (*sock)->s_trn_id);

	nmb->ip = p->ip;
	nmb->port = p->port;

	p->fd = ClientNMB;
	p->packet_type = NMB_PACKET;

	if (!send_packet(p))
	{
		DEBUG(0,("server is dead\n"));
		free(p);
		return False;
	}			
	free(p);
	return True;
}

static BOOL process_srv_sock(struct sock_redir *sock)
{
	int nmb_id;
	int tr_id;
	int i;

	struct packet_struct *p;

	p = receive_packet(sock->s, NMB_PACKET, 0);
	if (p == NULL)
	{
		return False;
	}

	if (!p->packet.nmb.header.response)
	{
		free(p);
		return True;
	}

	nmb_id = p->packet.nmb.header.name_trn_id;
	DEBUG(10,("process_srv_sock:\tnmb_id:\t%d\n", nmb_id));

	for (i = 0; i < num_socks; i++)
	{
		if (socks[i] == NULL)
		{
			continue;
		}

		tr_id = socks[i]->s_trn_id;

		DEBUG(10,("list:\tfd:\t%d\tc_trn_id:\t%d\ttr_id:\t%d\n",
			   socks[i]->c,
			   socks[i]->c_trn_id,
			   tr_id));

		if (nmb_id != tr_id)
		{
			continue;
		}

		filter_reply(p, socks[i]->c_trn_id);
		p->fd = socks[i]->c;
		p->packet_type = NMB_SOCK_PACKET;

		if (!send_packet(p))
		{
			DEBUG(0,("client is dead\n"));
			return False;
		}			
		return True;
	}
	return False;
}

static void start_agent(void)
{
	int s, c;
	struct sockaddr_un sa;
	fstring path;
	fstring dir;

	CatchChild();

	slprintf(dir, sizeof(dir)-1, "/tmp/.nmb");
	mkdir(dir, 0777);

	slprintf(path, sizeof(path)-1, "%s/agent", dir);
	if (chmod(dir, 0777) < 0)
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

				fd = socks[i]->s;
				if (fd != -1)
				{
					FD_SET(fd, &fds);
					maxfd = MAX(maxfd, fd);
				}
			}
		}

		dbgflush();
		num = sys_select(maxfd+1,&fds,NULL, NULL);

		if (num <= 0)
		{
			continue;
		}

		DEBUG(10,("select received\n"));

		if (FD_ISSET(s, &fds))
		{
			FD_CLR(s, &fds);
			c = accept(s, (struct sockaddr*)&addr, &in_addrlen);
			if (c != -1)
			{
				sock_add(c);
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
				FD_CLR(socks[i]->c, &fds);
				if (!process_cli_sock(&socks[i]))
				{
					sock_redir_free(socks[i]);
					socks[i] = NULL;
				}
			}
			if (socks[i] == NULL)
			{
				continue;
			}
			if (socks[i]->s == -1)
			{
				continue;
			}
			if (FD_ISSET(socks[i]->s, &fds))
			{
				FD_CLR(socks[i]->s, &fds);
				if (!process_srv_sock(socks[i]))
				{
					sock_redir_free(socks[i]);
					socks[i] = NULL;
				}
			}
		}
	}
}

/**************************************************************************** **
 open the socket communication
 **************************************************************************** */
static BOOL open_sockets(BOOL isdaemon, int port)
{
  /* The sockets opened here will be used to receive broadcast
     packets *only*. Interface specific sockets are opened in
     make_subnet() in namedbsubnet.c. Thus we bind to the
     address "0.0.0.0". The parameter 'socket address' is
     now deprecated.
   */

  if ( isdaemon )
    ClientNMB = open_socket_in(SOCK_DGRAM, port,0,0);
  else
    ClientNMB = 0;
  
  if ( ClientNMB == -1 )
    return( False );

  /* we are never interested in SIGPIPE */
  BlockSignals(True,SIGPIPE);

  set_socket_options( ClientNMB,   "SO_BROADCAST" );

  DEBUG( 3, ( "open_sockets: Broadcast sockets opened.\n" ) );
  return( True );
} /* open_sockets */

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
	int global_nmb_port = NMB_PORT;

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

	if (!open_sockets(True, global_nmb_port))
	{
		return 1;
	}

	start_agent();

	return 0;
}
