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

static char *netbiosname;
static char packet[BUFFER_SIZE];

extern int DEBUGLEVEL;

static void agent_reply(char *buf)
{
	int msg_type = CVAL(buf,0);
	int type = CVAL(buf,smb_com);
	unsigned x;

	if (msg_type) return;

	switch (type) {

	case SMBnegprot:
		/* force the security bits */
		x = CVAL(buf, smb_vwv1);
		x = (x | SECURITY_SET) & ~SECURITY_MASK;
		SCVAL(buf, smb_vwv1, x);

		/* force the capabilities */
		x = IVAL(buf,smb_vwv9+1);
		x = (x | CAPABILITY_SET) & ~CAPABILITY_MASK;
		SIVAL(buf, smb_vwv9+1, x);
		break;

	}
}

static void agent_request(char *buf)
{
	int msg_type = CVAL(buf,0);
	int type = CVAL(buf,smb_com);
	pstring name1,name2;
	unsigned x;

	if (msg_type) {
		/* it's a netbios special */
		switch (msg_type) {
		case 0x81:
			/* session request */
			name_extract(buf,4,name1);
			name_extract(buf,4 + name_len(buf + 4),name2);
			DEBUG(0,("sesion_request: %s -> %s\n",
				 name1, name2));
			if (netbiosname) {
				/* replace the destination netbios name */
				name_mangle(netbiosname, buf+4, 0x20);
			}
		}
		return;
	}

	/* it's an ordinary SMB request */
	switch (type) {
	case SMBsesssetupX:
		/* force the client capabilities */
		x = IVAL(buf,smb_vwv11);
		x = (x | CLI_CAPABILITY_SET) & ~CLI_CAPABILITY_MASK;
		SIVAL(buf, smb_vwv11, x);
		break;
	}

}


static void agent_child(int c)
{
	struct cli_state *s = NULL;

	DEBUG(10,("agent_child: %d\n", c));

	while (c != -1)
	{
		fd_set fds;
		int num;
		int maxfd = 0;
		
		FD_ZERO(&fds);
		if (s != NULL)
		{
			FD_SET(s->fd, &fds);
			maxfd = MAX(s->fd, maxfd);
		}
	
		if (c != -1)
		{
			FD_SET(c, &fds);
			maxfd = MAX(c, maxfd);
		}

		num = sys_select(maxfd+1,&fds,NULL, NULL);
		if (num <= 0) continue;
		
		if (c != -1 && FD_ISSET(c, &fds))
		{
			if (s == NULL)
			{
				pstring buf;
				uchar ntpw[16];
				uchar lmpw[16];
				fstring srv_name;
				struct user_credentials usr;
				char *p = buf;
				int rl;
				uint32 len;

				DEBUG(10,("first request\n"));

				rl = read(c, &buf, sizeof(len));

				if (rl != sizeof(len))
				{
					DEBUG(0,("Unable to read length\n"));
					dump_data(0, buf, sizeof(len));
					exit(1);
				}

				len = IVAL(buf, 0);

				if (len > sizeof(buf))
				{
					DEBUG(0,("length %d too long\n", len));
					exit(1);
				}

				rl = read(c, buf, len);

				if (rl < 0)
				{
					DEBUG(0,("Unable to read from connection\n"));
					exit(1);
				}
				
#ifdef DEBUG_PASSWORD
				dump_data(100, buf, rl);
#endif
				fstrcpy(srv_name, p);
				p = skip_string(p, 1);
				fstrcpy(usr.user_name, p);
				p = skip_string(p, 1);
				fstrcpy(usr.domain, p);
				p = skip_string(p, 1);

				if (PTR_DIFF(p, buf) < rl)
				{
					memcpy(ntpw, p, 16);
					p += 16;
					memcpy(lmpw, p, 16);
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
					exit(1);
				}

				s = cli_net_use_add(srv_name, &usr, False);

				if (s == NULL)
				{
					DEBUG(0,("Unable to connect to %s\n", srv_name));
					exit(1);
				}
				if (write(c, s, sizeof(*s)) < 0)
				{
					DEBUG(0,("Could not write ack\n"));
					exit(1);
				}
			}
			else
			{
				if (!receive_smb(c, packet, 0))
				{
					DEBUG(0,("client closed connection\n"));
					exit(0);
				}
				/* ignore keep-alives */
				if (CVAL(packet, 0) != 0x85)
				{
					if (!send_smb(s->fd, packet))
					{
						DEBUG(0,("server is dead\n"));
						exit(1);
					}			
				}
			}
		}
		if (s != NULL && FD_ISSET(s->fd, &fds))
		{
			if (!receive_smb(s->fd, packet, 0))
			{
				DEBUG(0,("server closed connection\n"));
				exit(0);
			}
#if 0
			agent_reply(packet);
#endif
			if (!send_smb(c, packet))
			{
				DEBUG(0,("client is dead\n"));
				cli_shutdown(s);
				free(s);
				exit(1);
			}			
		}
	}
	DEBUG(0,("Connection closed\n"));
	if (s != NULL)
	{
		cli_shutdown(s);
		free(s);
	}
	exit(0);
}


static void start_agent(void)
{
	int s, c;
	struct sockaddr_un sa;
	fstring path;
	slprintf(path, sizeof(path)-1, "/tmp/smb-agent/smb.%d", getuid());

	CatchChild();

	/* start listening on unix socket */
	mkdir("/tmp/smb-agent", 777);

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

	if (chmod(path, S_IRUSR|S_IWUSR|S_ISVTX) < 0)
	{
		fprintf(stderr, "chmod on %s failed\n", sa.sun_path);
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
		fd_set fds;
		int num;
		struct sockaddr_un addr;
		int in_addrlen = sizeof(addr);
		
		FD_ZERO(&fds);
		FD_SET(s, &fds);

		num = sys_select(s+1,&fds,NULL, NULL);
		if (num > 0)
		{
			c = accept(s, (struct sockaddr*)&addr, &in_addrlen);
			if (c != -1) {
				if (fork() == 0)
				{
					close(s);
					agent_child(c);
					exit(0);
				} else {
					close(c);
				}
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
