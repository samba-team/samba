/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB msrpcent generic functions
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

extern int DEBUGLEVEL;

/****************************************************************************
recv an smb
****************************************************************************/
BOOL msrpc_receive(struct msrpc_state *msrpc)
{
	return receive_smb(msrpc->fd,msrpc->inbuf,0);
}

/****************************************************************************
  send an smb to a fd and re-establish if necessary
****************************************************************************/
BOOL msrpc_send(struct msrpc_state *msrpc, BOOL show)
{
	size_t len;
	size_t nwritten=0;
	ssize_t ret;

	len = smb_len(msrpc->outbuf) + 4;

	dump_data(10, msrpc->outbuf, len);

	while (nwritten < len)
	{
		ret = write_socket(msrpc->fd,msrpc->outbuf+nwritten,len - nwritten);
		if (ret <= 0)
		{
			DEBUG(0,("Error writing %d bytes to msrpcent. %d. Exiting\n",
				 len,ret));
			return False;
		}
		nwritten += ret;
	}
	
	return True;
}



/****************************************************************************
open the msrpcent sockets
****************************************************************************/
BOOL msrpc_connect(struct msrpc_state *msrpc, const char *pipe_name)
{
	fstring path;
	slprintf(path, sizeof(path)-1, "/tmp/.msrpc/%s", pipe_name);

	fstrcpy(msrpc->pipe_name, pipe_name);
	
	msrpc->fd = open_pipe_sock(path);

	if (msrpc->fd == -1)
	{
		return False;
	}

	return True;
}


/****************************************************************************
initialise a msrpcent structure
****************************************************************************/
void msrpc_init_creds(struct msrpc_state *msrpc, const struct user_credentials *usr)
{
	copy_user_creds(&msrpc->usr, usr);
}

/****************************************************************************
close the socket descriptor
****************************************************************************/
void msrpc_close_socket(struct msrpc_state *msrpc)
{
	if (msrpc->fd != -1) 
	{
		close(msrpc->fd);
	}
	msrpc->fd = -1;
}


/****************************************************************************
set socket options on a open connection
****************************************************************************/
void msrpc_sockopt(struct msrpc_state *msrpc, char *options)
{
	set_socket_options(msrpc->fd, options);
}


static int msrpc_init_redirect(struct msrpc_state *msrpc,
				const char* pipe_name, 
				const struct user_credentials *usr)
{
	int sock;
	struct msrpc_state msrpc_redir;
	fstring path;

	pstring data;
	uint32 len;
	char *p;
	char *in = msrpc->inbuf;
	char *out = msrpc->outbuf;

	slprintf(path, sizeof(path)-1, "/tmp/.msrpc/.%s/agent", pipe_name);

	sock = open_pipe_sock(path);

	if (sock < 0)
	{
		return sock;
	}

	ZERO_STRUCT(data);

	p = &data[4];
	SSVAL(p, 0, 0);
	p += 2;

	SSVAL(p, 0, usr->reuse ? AGENT_CMD_CON_REUSE : AGENT_CMD_CON);
	p += 2;

	safe_strcpy(p, pipe_name, 16);
	p = skip_string(p, 1);
	safe_strcpy(p, usr != NULL ? usr->user_name : "", 16);
	p = skip_string(p, 1);
	safe_strcpy(p, usr != NULL ? usr->domain : "", 16);
	p = skip_string(p, 1);

	if (usr != NULL && !pwd_is_nullpwd(&usr->pwd))
	{
		uchar lm16[16];
		uchar nt16[16];

		pwd_get_lm_nt_16(&usr->pwd, lm16, nt16);
		memcpy(p, lm16, 16);
		p += 16;
		memcpy(p, nt16, 16);
		p += 16;
	}

	len = PTR_DIFF(p, data);
	SIVAL(data, 0, len);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("data len: %d\n", len));
	dump_data(100, data, len);
#endif

	if (write(sock, data, len) <= 0)
	{
		DEBUG(0,("write failed\n"));
		close(sock);
		return False;
	}

	len = read(sock, &msrpc_redir, sizeof(msrpc_redir));

	if (len != sizeof(msrpc_redir))
	{
		DEBUG(0,("read failed\n"));
		close(sock);
		return False;
	}
	
	memcpy(msrpc, &msrpc_redir, sizeof(msrpc_redir));
	msrpc->inbuf = in;
	msrpc->outbuf = out;
	msrpc->fd = sock;
	msrpc->usr.reuse = False;

	return sock;
}

BOOL msrpc_connect_auth(struct msrpc_state *msrpc,
				const char* pipename,
				const struct user_credentials *usr)
{
	ZERO_STRUCTP(msrpc);
	if (!msrpc_initialise(msrpc))
	{
		DEBUG(0,("unable to initialise msrpcent connection.\n"));
		return False;
	}

	msrpc_init_creds(msrpc, usr);

	if (!msrpc_establish_connection(msrpc, pipename))
	{
		msrpc_shutdown(msrpc);
		return False;
	}

	return True;
}

/****************************************************************************
initialise a msrpcent structure
****************************************************************************/
struct msrpc_state *msrpc_initialise(struct msrpc_state *msrpc)
{
	if (!msrpc) {
		msrpc = (struct msrpc_state *)malloc(sizeof(*msrpc));
		if (!msrpc)
			return NULL;
		ZERO_STRUCTP(msrpc);
	}

	if (msrpc->initialised) {
		msrpc_shutdown(msrpc);
	}

	ZERO_STRUCTP(msrpc);

	msrpc->fd = -1;
	msrpc->outbuf = (char *)malloc(CLI_BUFFER_SIZE+4);
	msrpc->inbuf = (char *)malloc(CLI_BUFFER_SIZE+4);
	if (!msrpc->outbuf || !msrpc->inbuf)
	{
		return False;
	}

	msrpc->initialised = 1;
	msrpc_init_creds(msrpc, NULL);

	return msrpc;
}


/****************************************************************************
shutdown a msrpcent structure
****************************************************************************/
void msrpc_shutdown(struct msrpc_state *msrpc)
{
	DEBUG(10,("msrpc_shutdown\n"));
	if (msrpc->outbuf)
	{
		free(msrpc->outbuf);
	}
	if (msrpc->inbuf)
	{
		free(msrpc->inbuf);
	}
	msrpc_close_socket(msrpc);
	memset(msrpc, 0, sizeof(*msrpc));
}

/****************************************************************************
establishes a connection right up to doing tconX, reading in a password.
****************************************************************************/
BOOL msrpc_establish_connection(struct msrpc_state *msrpc,
		const char *pipe_name)
{
	DEBUG(5,("msrpc_establish_connection: connecting to %s (%s) - %s\n",
		          pipe_name,
	              msrpc->usr.user_name, msrpc->usr.domain));

	/* establish connection */

	if ((!msrpc->initialised))
	{
		return False;
	}

	if (msrpc->fd == -1 && msrpc->redirect)
	{
		if (msrpc_init_redirect(msrpc, pipe_name, &msrpc->usr))
		{
			DEBUG(10,("msrpc_establish_connection: redirected OK\n"));
			return True;
		}
		else
		{
			DEBUG(10,("redirect FAILED\n"));
			return False;
		}
	}
	if (msrpc->fd == -1)
	{
		if (!msrpc_connect(msrpc, pipe_name))
		{
			DEBUG(1,("msrpc_establish_connection: failed %s)\n",
				pipe_name));
					  
			return False;
		}
	}

	return True;
}

