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

/****************************************************************************
terminate sockent connection
****************************************************************************/
static void free_sock(void *sock)
{
	if (sock != NULL)
	{
		free(sock);
	}
}

static void filter_reply(struct packet_struct *p, int tr_id)
{
	p->packet.nmb.header.name_trn_id = tr_id;
}

static BOOL process_cli_sock(struct sock_redir **socks,
				uint32 num_socks,
				struct sock_redir *sock)
{
	struct packet_struct *p;
	struct nmb_state *nmb;
	static uint16 trn_id = 0x0;

	p = receive_packet(sock->c, NMB_SOCK_PACKET, 0);
	if (p == NULL)
	{
		DEBUG(0,("client closed connection\n"));
		return False;
	}

	nmb = (struct nmb_state*)malloc(sizeof(struct nmb_state));
	if (nmb == NULL)
	{
		free_packet(p);
		return False;
	}

	sock->s = ClientNMB;
	sock->n = nmb;
	sock->c_id = p->packet.nmb.header.name_trn_id;
	sock->s_id = trn_id;

	trn_id++;
	if (trn_id > 0xffff)
	{
		trn_id = 0x0;
	}

	DEBUG(10,("new trn_id: %d\n", trn_id));

	filter_reply(p, sock->s_id);

	nmb->ip = p->ip;
	nmb->port = p->port;

	p->fd = ClientNMB;
	p->packet_type = NMB_PACKET;

	if (!send_packet(p))
	{
		DEBUG(0,("server is dead\n"));
		free_packet(p);
		return False;
	}			
	free_packet(p);
	return True;
}

static BOOL process_srv_sock(struct sock_redir **socks,
				uint32 num_socks,
				int fd)
{
	int nmb_id;
	int tr_id;
	int i;

	struct packet_struct *p;

	p = receive_packet(fd, NMB_PACKET, 0);
	if (p == NULL)
	{
		return True;
	}

#if 0
	if (!p->packet.nmb.header.response)
	{
		DEBUG(10,("skipping response packet\n"));
		free_packet(p);
		return True;
	}
#endif

	nmb_id = p->packet.nmb.header.name_trn_id;
	DEBUG(10,("process_srv_sock:\tnmb_id:\t%d\n", nmb_id));

	for (i = 0; i < num_socks; i++)
	{
		if (socks[i] == NULL)
		{
			continue;
		}

		tr_id = socks[i]->s_id;

		DEBUG(10,("list:\tfd:\t%d\tc_id:\t%d\ttr_id:\t%d\n",
			   socks[i]->c,
			   socks[i]->c_id,
			   tr_id));

		if (nmb_id != tr_id)
		{
			continue;
		}

		filter_reply(p, socks[i]->c_id);
		p->fd = socks[i]->c;
		p->packet_type = NMB_SOCK_PACKET;

		if (!send_packet(p))
		{
			DEBUG(0,("client is dead\n"));
			return False;
		}			
		return True;
	}
	return True;
}

static int get_agent_sock(char *id)
{
	int s;
	fstring dir;
	fstring path;

	slprintf(dir, sizeof(dir)-1, "/tmp/.nmb");
	slprintf(path, sizeof(path)-1, "%s/agent", dir);

	s = create_pipe_socket(dir, 0777, path, 0777);

	if (s == -1)
		return -1;
		/* ready to listen */
	if (listen(s, 5) == -1) {
		DEBUG(0,("listen: %s\n", strerror(errno)));
		close(s);
		return -1;
	}
	return s;
}

static void start_nmb_agent(void)
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
	
	CatchChild();

	start_agent(&va);
}

/******************************************************************************
 open the socket communication
 *****************************************************************************/
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

	start_nmb_agent();

	return 0;
}
