/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Tim Potter      2000-2001
   
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


/****************************************************************************
 Determine if a file descriptor is in fact a socket.
****************************************************************************/
BOOL is_a_socket(int fd)
{
	int v,l;
	l = sizeof(int);
	return getsockopt(fd, SOL_SOCKET, SO_TYPE, (char *)&v, &l) == 0;
}

enum SOCK_OPT_TYPES {OPT_BOOL,OPT_INT,OPT_ON};

typedef struct smb_socket_option {
	const char *name;
	int level;
	int option;
	int value;
	int opttype;
} smb_socket_option;

static const smb_socket_option socket_options[] = {
  {"SO_KEEPALIVE",      SOL_SOCKET,    SO_KEEPALIVE,    0,                 OPT_BOOL},
  {"SO_REUSEADDR",      SOL_SOCKET,    SO_REUSEADDR,    0,                 OPT_BOOL},
  {"SO_BROADCAST",      SOL_SOCKET,    SO_BROADCAST,    0,                 OPT_BOOL},
#ifdef TCP_NODELAY
  {"TCP_NODELAY",       IPPROTO_TCP,   TCP_NODELAY,     0,                 OPT_BOOL},
#endif
#ifdef IPTOS_LOWDELAY
  {"IPTOS_LOWDELAY",    IPPROTO_IP,    IP_TOS,          IPTOS_LOWDELAY,    OPT_ON},
#endif
#ifdef IPTOS_THROUGHPUT
  {"IPTOS_THROUGHPUT",  IPPROTO_IP,    IP_TOS,          IPTOS_THROUGHPUT,  OPT_ON},
#endif
#ifdef SO_REUSEPORT
  {"SO_REUSEPORT",      SOL_SOCKET,    SO_REUSEPORT,    0,                 OPT_BOOL},
#endif
#ifdef SO_SNDBUF
  {"SO_SNDBUF",         SOL_SOCKET,    SO_SNDBUF,       0,                 OPT_INT},
#endif
#ifdef SO_RCVBUF
  {"SO_RCVBUF",         SOL_SOCKET,    SO_RCVBUF,       0,                 OPT_INT},
#endif
#ifdef SO_SNDLOWAT
  {"SO_SNDLOWAT",       SOL_SOCKET,    SO_SNDLOWAT,     0,                 OPT_INT},
#endif
#ifdef SO_RCVLOWAT
  {"SO_RCVLOWAT",       SOL_SOCKET,    SO_RCVLOWAT,     0,                 OPT_INT},
#endif
#ifdef SO_SNDTIMEO
  {"SO_SNDTIMEO",       SOL_SOCKET,    SO_SNDTIMEO,     0,                 OPT_INT},
#endif
#ifdef SO_RCVTIMEO
  {"SO_RCVTIMEO",       SOL_SOCKET,    SO_RCVTIMEO,     0,                 OPT_INT},
#endif
  {NULL,0,0,0,0}};

/****************************************************************************
 Print socket options.
****************************************************************************/

static void print_socket_options(int s)
{
	int value, vlen = 4;
	const smb_socket_option *p = &socket_options[0];

	for (; p->name != NULL; p++) {
		if (getsockopt(s, p->level, p->option, (void *)&value, &vlen) == -1) {
			DEBUG(5,("Could not test socket option %s.\n", p->name));
		} else {
			DEBUG(5,("socket option %s = %d\n",p->name,value));
		}
	}
 }

/****************************************************************************
 Set user socket options.
****************************************************************************/

void set_socket_options(int fd, const char *options)
{
	fstring tok;

	while (next_token(&options,tok," \t,", sizeof(tok))) {
		int ret=0,i;
		int value = 1;
		char *p;
		BOOL got_value = False;

		if ((p = strchr_m(tok,'='))) {
			*p = 0;
			value = atoi(p+1);
			got_value = True;
		}

		for (i=0;socket_options[i].name;i++)
			if (strequal(socket_options[i].name,tok))
				break;

		if (!socket_options[i].name) {
			DEBUG(0,("Unknown socket option %s\n",tok));
			continue;
		}

		switch (socket_options[i].opttype) {
		case OPT_BOOL:
		case OPT_INT:
			ret = setsockopt(fd,socket_options[i].level,
						socket_options[i].option,(char *)&value,sizeof(int));
			break;

		case OPT_ON:
			if (got_value)
				DEBUG(0,("syntax error - %s does not take a value\n",tok));

			{
				int on = socket_options[i].value;
				ret = setsockopt(fd,socket_options[i].level,
							socket_options[i].option,(char *)&on,sizeof(int));
			}
			break;	  
		}
      
		if (ret != 0)
			DEBUG(0,("Failed to set socket option %s (Error %s)\n",tok, strerror(errno) ));
	}

	print_socket_options(fd);
}

/****************************************************************************
 Read from a socket.
****************************************************************************/

ssize_t read_udp_socket(int fd, char *buf, size_t len, 
			struct in_addr *from_addr, int *from_port)
{
	ssize_t ret;
	struct sockaddr_in sock;
	socklen_t socklen = sizeof(sock);

	ret = (ssize_t)sys_recvfrom(fd,buf,len, 0, (struct sockaddr *)&sock, &socklen);
	if (ret <= 0) {
		DEBUG(2,("read socket failed. ERRNO=%s\n",strerror(errno)));
		return 0;
	}

	if (from_addr) {
		*from_addr = sock.sin_addr;
	}
	if (from_port) {
		*from_port = ntohs(sock.sin_port);
	}

	return ret;
}


/****************************************************************************
  read data from the client, reading exactly N bytes. 
****************************************************************************/
ssize_t read_data(int fd, char *buffer, size_t N)
{
	ssize_t ret;
	size_t total=0;  
 
	if (fd == -1) {
		errno = EIO;
		return -1;
	}

	while (total < N) {
		ret = sys_read(fd,buffer + total,N - total);
		if (ret == 0) {
			return total;
		}
		if (ret == -1) {
			if (total == 0) {
				return -1;
			}
			return total;
		}
		total += ret;
	}
	return (ssize_t)total;
}


/****************************************************************************
 Write data to a fd.
****************************************************************************/
ssize_t write_data(int fd, const char *buffer, size_t N)
{
	size_t total=0;
	ssize_t ret;

	if (fd == -1) {
		errno = EIO;
		return -1;
	}

	while (total < N) {
		ret = sys_write(fd, buffer + total, N - total);
		if (ret == -1) {
			if (total == 0) {
				return -1;
			}
			return total;
		}
		if (ret == 0) {
			return total;
		}

		total += ret;
	}
	return (ssize_t)total;
}


/****************************************************************************
send a keepalive packet (rfc1002)
****************************************************************************/
BOOL send_nbt_keepalive(int sock_fd)
{
	uint8_t buf[4];

	buf[0] = SMBkeepalive;
	buf[1] = buf[2] = buf[3] = 0;

	return write_data(sock_fd,(char *)buf,4) == 4;
}


/****************************************************************************
 Open a socket of the specified type, port, and address for incoming data.
****************************************************************************/
int open_socket_in( int type, int port, int dlevel, uint32_t socket_addr, BOOL rebind )
{
	struct sockaddr_in sock;
	int res;

	memset( (char *)&sock, '\0', sizeof(sock) );

#ifdef HAVE_SOCK_SIN_LEN
	sock.sin_len         = sizeof(sock);
#endif
	sock.sin_port        = htons( port );
	sock.sin_family      = AF_INET;
	sock.sin_addr.s_addr = socket_addr;

	res = socket( AF_INET, type, 0 );
	if( res == -1 ) {
		DEBUG(0,("open_socket_in(): socket() call failed: %s\n", strerror(errno)));
		return -1;
	}

	/* This block sets/clears the SO_REUSEADDR and possibly SO_REUSEPORT. */
	{
		int val = rebind ? 1 : 0;
		setsockopt(res,SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val));
#ifdef SO_REUSEPORT
		setsockopt(res,SOL_SOCKET,SO_REUSEPORT,(char *)&val,sizeof(val));
#endif
	}

	/* now we've got a socket - we need to bind it */
	if( bind( res, (struct sockaddr *)&sock, sizeof(sock) ) == -1 ) {
		DEBUG(0,("bind failed on port %d - %s\n", port, strerror(errno)));
		close( res ); 
		return( -1 ); 
	}

	DEBUG( 10, ( "bind succeeded on port %d\n", port ) );

	return( res );
 }


/****************************************************************************
  create an outgoing socket. timeout is in milliseconds.
  **************************************************************************/
int open_socket_out(int type, struct in_addr *addr, int port, int timeout)
{
	struct sockaddr_in sock_out;
	int res,ret;
	int connect_loop = 250; /* 250 milliseconds */
	int loops = (timeout) / connect_loop;

	/* create a socket to write to */
	res = socket(PF_INET, type, 0);
	if (res == -1) 
	{ DEBUG(0,("socket error\n")); return -1; }
	
	if (type != SOCK_STREAM) return(res);
	
	memset((char *)&sock_out,'\0',sizeof(sock_out));
	putip((char *)&sock_out.sin_addr,(char *)addr);
	
	sock_out.sin_port = htons( port );
	sock_out.sin_family = PF_INET;
	
	/* set it non-blocking */
	set_blocking(res,False);
	
	DEBUG(3,("Connecting to %s at port %d\n",inet_ntoa(*addr),port));
	
	/* and connect it to the destination */
connect_again:
	ret = connect(res,(struct sockaddr *)&sock_out,sizeof(sock_out));
	
	/* Some systems return EAGAIN when they mean EINPROGRESS */
	if (ret < 0 && (errno == EINPROGRESS || errno == EALREADY ||
			errno == EAGAIN) && loops--) {
		msleep(connect_loop);
		goto connect_again;
	}
	
	if (ret < 0 && (errno == EINPROGRESS || errno == EALREADY ||
			errno == EAGAIN)) {
		DEBUG(1,("timeout connecting to %s:%d\n",inet_ntoa(*addr),port));
		close(res);
		return -1;
	}
	
#ifdef EISCONN
	if (ret < 0 && errno == EISCONN) {
		errno = 0;
		ret = 0;
	}
#endif
	
	if (ret < 0) {
		DEBUG(2,("error connecting to %s:%d (%s)\n",
			 inet_ntoa(*addr),port,strerror(errno)));
		close(res);
		return -1;
	}
	
	/* set it blocking again */
	set_blocking(res,True);
	
	return res;
}

/*
  open a connected UDP socket to host on port
*/
int open_udp_socket(const char *host, int port)
{
	int type = SOCK_DGRAM;
	struct sockaddr_in sock_out;
	int res;
	struct in_addr *addr;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("open_udp_socket");
	if (!mem_ctx) {
		return -1;
	}
	addr = interpret_addr2(mem_ctx, host);

	res = socket(PF_INET, type, 0);
	if (res == -1) {
		return -1;
	}

	memset((char *)&sock_out,'\0',sizeof(sock_out));
	putip((char *)&sock_out.sin_addr,(char *)addr);
	sock_out.sin_port = htons(port);
	sock_out.sin_family = PF_INET;
	
	talloc_destroy(mem_ctx);

	if (connect(res,(struct sockaddr *)&sock_out,sizeof(sock_out))) {
		close(res);
		return -1;
	}

	return res;
}


/*******************************************************************
 matchname - determine if host name matches IP address. Used to
 confirm a hostname lookup to prevent spoof attacks
 ******************************************************************/
static BOOL matchname(char *remotehost, struct in_addr addr)
{
	struct hostent *hp;
	int     i;
	
	if ((hp = sys_gethostbyname(remotehost)) == 0) {
		DEBUG(0,("sys_gethostbyname(%s): lookup failure.\n", remotehost));
		return False;
	} 

	/*
	 * Make sure that gethostbyname() returns the "correct" host name.
	 * Unfortunately, gethostbyname("localhost") sometimes yields
	 * "localhost.domain". Since the latter host name comes from the
	 * local DNS, we just have to trust it (all bets are off if the local
	 * DNS is perverted). We always check the address list, though.
	 */
	
	if (strcasecmp(remotehost, hp->h_name)
	    && strcasecmp(remotehost, "localhost")) {
		DEBUG(0,("host name/name mismatch: %s != %s\n",
			 remotehost, hp->h_name));
		return False;
	}
	
	/* Look up the host address in the address list we just got. */
	for (i = 0; hp->h_addr_list[i]; i++) {
		if (memcmp(hp->h_addr_list[i], (char *) & addr, sizeof(addr)) == 0)
			return True;
	}
	
	/*
	 * The host name does not map to the original host address. Perhaps
	 * someone has compromised a name server. More likely someone botched
	 * it, but that could be dangerous, too.
	 */
	
	DEBUG(0,("host name/address mismatch: %s != %s\n",
		 inet_ntoa(addr), hp->h_name));
	return False;
}

 
/*******************************************************************
 return the DNS name of the remote end of a socket
 ******************************************************************/
char *get_socket_name(TALLOC_CTX *mem_ctx, int fd, BOOL force_lookup)
{
	char *name_buf;
	struct hostent *hp;
	struct in_addr addr;
	char *p;

	/* reverse lookups can be *very* expensive, and in many
	   situations won't work because many networks don't link dhcp
	   with dns. To avoid the delay we avoid the lookup if
	   possible */
	if (!lp_hostname_lookups() && (force_lookup == False)) {
		return get_socket_addr(mem_ctx, fd);
	}
	
	p = get_socket_addr(mem_ctx, fd);

	name_buf = talloc_strdup(mem_ctx, "UNKNOWN");
	if (fd == -1) return name_buf;

	addr = *interpret_addr2(mem_ctx, p);
	
	/* Look up the remote host name. */
	if ((hp = gethostbyaddr((char *)&addr.s_addr, sizeof(addr.s_addr), AF_INET)) == 0) {
		DEBUG(1,("Gethostbyaddr failed for %s\n",p));
		name_buf = talloc_strdup(mem_ctx, p);
	} else {
		name_buf = talloc_strdup(mem_ctx, (char *)hp->h_name);
		if (!matchname(name_buf, addr)) {
			DEBUG(0,("Matchname failed on %s %s\n",name_buf,p));
			name_buf = talloc_strdup(mem_ctx, "UNKNOWN");
		}
	}

	alpha_strcpy(name_buf, name_buf, "_-.", strlen(name_buf)+1);
	if (strstr(name_buf,"..")) {
		name_buf = talloc_strdup(mem_ctx, "UNKNOWN");
	}

	return name_buf;
}

/*******************************************************************
 return the IP addr of the remote end of a socket as a string 
 ******************************************************************/
char *get_socket_addr(TALLOC_CTX *mem_ctx, int fd)
{
	struct sockaddr sa;
	struct sockaddr_in *sockin = (struct sockaddr_in *) (&sa);
	int     length = sizeof(sa);

	if (fd == -1 || getpeername(fd, &sa, &length) == -1) {
		return talloc_strdup(mem_ctx, "0.0.0.0");
	}
	
	return talloc_strdup(mem_ctx, (char *)inet_ntoa(sockin->sin_addr));
}



/*******************************************************************
this is like socketpair but uses tcp. It is used by the Samba
regression test code
The function guarantees that nobody else can attach to the socket,
or if they do that this function fails and the socket gets closed
returns 0 on success, -1 on failure
the resulting file descriptors are symmetrical
 ******************************************************************/
static int socketpair_tcp(int fd[2])
{
	int listener;
	struct sockaddr_in sock;
	struct sockaddr_in sock2;
	socklen_t socklen = sizeof(sock);
	int connect_done = 0;
	
	fd[0] = fd[1] = listener = -1;

	memset(&sock, 0, sizeof(sock));
	
	if ((listener = socket(PF_INET, SOCK_STREAM, 0)) == -1) goto failed;

        memset(&sock2, 0, sizeof(sock2));
#ifdef HAVE_SOCK_SIN_LEN
        sock2.sin_len = sizeof(sock2);
#endif
        sock2.sin_family = PF_INET;

        bind(listener, (struct sockaddr *)&sock2, sizeof(sock2));

	if (listen(listener, 1) != 0) goto failed;

	if (getsockname(listener, (struct sockaddr *)&sock, &socklen) != 0) goto failed;

	if ((fd[1] = socket(PF_INET, SOCK_STREAM, 0)) == -1) goto failed;

	set_blocking(fd[1], 0);

	sock.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(fd[1],(struct sockaddr *)&sock,sizeof(sock)) == -1) {
		if (errno != EINPROGRESS) goto failed;
	} else {
		connect_done = 1;
	}

	if ((fd[0] = accept(listener, (struct sockaddr *)&sock, &socklen)) == -1) goto failed;

	close(listener);
	if (connect_done == 0) {
		if (connect(fd[1],(struct sockaddr *)&sock,sizeof(sock)) != 0
		    && errno != EISCONN) goto failed;
	}

	set_blocking(fd[1], 1);

	/* all OK! */
	return 0;

 failed:
	if (fd[0] != -1) close(fd[0]);
	if (fd[1] != -1) close(fd[1]);
	if (listener != -1) close(listener);
	return -1;
}


/*******************************************************************
run a program on a local tcp socket, this is used to launch smbd
when regression testing
the return value is a socket which is attached to a subprocess
running "prog". stdin and stdout are attached. stderr is left
attached to the original stderr
 ******************************************************************/
int sock_exec(const char *prog)
{
	int fd[2];
	if (socketpair_tcp(fd) != 0) {
		DEBUG(0,("socketpair_tcp failed (%s)\n", strerror(errno)));
		return -1;
	}
	if (fork() == 0) {
		close(fd[0]);
		close(0);
		close(1);
		dup(fd[1]);
		dup(fd[1]);
		exit(system(prog));
	}
	close(fd[1]);
	return fd[0];
}


/*
  determine if a packet is pending for receive on a socket
*/
BOOL socket_pending(int fd)
{
	fd_set fds;
	int selrtn;
	struct timeval timeout;

	FD_ZERO(&fds);
	FD_SET(fd,&fds);
	
	/* immediate timeout */
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	/* yes, this is supposed to be a normal select not a sys_select() */
	selrtn = select(fd+1,&fds,NULL,NULL,&timeout);
		
	if (selrtn == 1) {
		/* the fd is readable */
		return True;
	}

	return False;
}
