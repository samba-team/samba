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
#include "system/network.h"


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
}


/****************************************************************************
 Check the timeout. 
****************************************************************************/
static BOOL timeout_until(struct timeval *timeout,
			  const struct timeval *endtime)
{
	struct timeval now;

	GetTimeOfDay(&now);

	if ((now.tv_sec > endtime->tv_sec) ||
	    ((now.tv_sec == endtime->tv_sec) &&
	     (now.tv_usec > endtime->tv_usec)))
		return False;

	timeout->tv_sec = endtime->tv_sec - now.tv_sec;
	timeout->tv_usec = endtime->tv_usec - now.tv_usec;
	return True;
}


/****************************************************************************
 Read data from the client, reading exactly N bytes, with timeout. 
****************************************************************************/
ssize_t read_data_until(int fd,char *buffer,size_t N,
			const struct timeval *endtime)
{
	ssize_t ret;
	size_t total=0;  
 
	while (total < N) {

		if (endtime != NULL) {
			fd_set r_fds;
			struct timeval timeout;
			int res;

			FD_ZERO(&r_fds);
			FD_SET(fd, &r_fds);

			if (!timeout_until(&timeout, endtime))
				return -1;

			res = sys_select(fd+1, &r_fds, NULL, NULL, &timeout);
			if (res <= 0)
				return -1;
		}

		ret = sys_read(fd,buffer + total,N - total);

		if (ret == 0) {
			DEBUG(10,("read_data: read of %d returned 0. Error = %s\n", (int)(N - total), strerror(errno) ));
			return 0;
		}

		if (ret == -1) {
			DEBUG(0,("read_data: read failure for %d. Error = %s\n", (int)(N - total), strerror(errno) ));
			return -1;
		}
		total += ret;
	}
	return (ssize_t)total;
}


/****************************************************************************
 Write data to a fd with timeout.
****************************************************************************/
ssize_t write_data_until(int fd,char *buffer,size_t N,
			 const struct timeval *endtime)
{
	size_t total=0;
	ssize_t ret;

	while (total < N) {

		if (endtime != NULL) {
			fd_set w_fds;
			struct timeval timeout;
			int res;

			FD_ZERO(&w_fds);
			FD_SET(fd, &w_fds);

			if (!timeout_until(&timeout, endtime))
				return -1;

			res = sys_select(fd+1, NULL, &w_fds, NULL, &timeout);
			if (res <= 0)
				return -1;
		}

		ret = sys_write(fd,buffer + total,N - total);

		if (ret == -1) {
			DEBUG(0,("write_data: write failure. Error = %s\n", strerror(errno) ));
			return -1;
		}
		if (ret == 0)
			return total;

		total += ret;
	}
	return (ssize_t)total;
}



/****************************************************************************
  create an outgoing socket. timeout is in milliseconds.
  **************************************************************************/
int open_socket_out(int type, struct ipv4_addr *addr, int port, int timeout)
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
	
	DEBUG(3,("Connecting to %s at port %d\n", sys_inet_ntoa(*addr),port));
	
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
		DEBUG(1,("timeout connecting to %s:%d\n", sys_inet_ntoa(*addr),port));
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
			 sys_inet_ntoa(*addr),port,strerror(errno)));
		close(res);
		return -1;
	}
	
	/* set it blocking again */
	set_blocking(res,True);
	
	return res;
}

