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
BOOL msrpc_send_prs(struct msrpc_state *msrpc, prs_struct *ps)
{
	size_t len = ps != NULL ? prs_buf_len(ps) : 0;

	DEBUG(10,("msrpc_send_prs: len %d\n", len));
	dbgflush();

	_smb_setlen(msrpc->outbuf, len);
	if (len != 0 && !prs_buf_copy(&msrpc->outbuf[4], ps, 0, len))
	{
		return False;
	}

	if (msrpc_send(msrpc, True))
	{
		prs_free_data(ps);
		return True;
	}
	return False;
}

/****************************************************************************
  receive msrpc packet
****************************************************************************/
BOOL msrpc_receive_prs(struct msrpc_state *msrpc, prs_struct *ps)
{
	int len;
	char *data;

	if (!msrpc_receive(msrpc))
	{
		return False;
	}

	len = smb_len(msrpc->inbuf);

	dump_data(10, msrpc->inbuf, len+4);

	DEBUG(10,("msrpc_receive_prs: len %d\n", len));

	prs_init(ps, len, 4, False);
	ps->offset = len;
	data = prs_data(ps, 0);
	if (data == NULL || len <= 0)
	{
		return False;
	}

	memcpy(data, smb_base(msrpc->inbuf), len);

	return True;
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
void msrpc_init_creds(struct msrpc_state *msrpc, const struct user_creds *usr)
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


static BOOL msrpc_authenticate(struct msrpc_state *msrpc,
				const struct user_creds *usr)
{
	struct msrpc_state msrpc_redir;

	int sock = msrpc->fd;
	char *data;
	prs_struct ps;
	uint32 len;
	char *in = msrpc->inbuf;
	char *out = msrpc->outbuf;
	uint16 command;

	command = usr != NULL ? AGENT_CMD_CON : AGENT_CMD_CON_ANON;

	if (!create_user_creds(&ps, msrpc->pipe_name, 0x0, command, usr))
	{
		DEBUG(0,("could not parse credentials\n"));
		close(sock);
		return False;
	}

	len = ps.offset;
	data = prs_data(&ps, 0);

	SIVAL(data, 0, len);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("data len: %d\n", len));
	dump_data(100, data, len);
#endif

	if (write(sock, data, len) <= 0)
	{
		DEBUG(0,("write failed\n"));
		return False;
	}

	if (msrpc->redirect)
	{
		len = read(sock, &msrpc_redir, sizeof(msrpc_redir));

		if (len != sizeof(msrpc_redir))
		{
			DEBUG(0,("read failed\n"));
			return False;
		}
		
		memcpy(msrpc, &msrpc_redir, sizeof(msrpc_redir));
		msrpc->inbuf = in;
		msrpc->outbuf = out;
		msrpc->fd = sock;
		msrpc->usr.reuse = False;
	}
	else
	{
		uint32 status;
		len = read(sock, &status, sizeof(status));

		return len == sizeof(status) && status == 0x0;
	}
	return True;
}

static BOOL msrpc_init_redirect(struct msrpc_state *msrpc,
				const char* pipe_name,
				const struct user_creds *usr)
{
	int sock;
	fstring path;

	slprintf(path, sizeof(path)-1, "/tmp/.msrpc/.%s/agent", pipe_name);

	sock = open_pipe_sock(path);

	if (sock < 0)
	{
		return False;
	}

	msrpc->fd = sock;

	if (!msrpc_authenticate(msrpc, usr))
	{
		DEBUG(0,("authenticate failed\n"));
		close(msrpc->fd);
		msrpc->fd = -1;
		return False;
	}

	return True;
}

BOOL msrpc_connect_auth(struct msrpc_state *msrpc,
				const char* pipename,
				const struct user_creds *usr)
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
	              msrpc->usr.ntc.user_name, msrpc->usr.ntc.domain));

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

	if (!msrpc_authenticate(msrpc, &msrpc->usr))
	{
		DEBUG(0,("authenticate failed\n"));
		close(msrpc->fd);
		msrpc->fd = -1;
		return False;
	}

	return True;
}

