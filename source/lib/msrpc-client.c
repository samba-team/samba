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
#include "rpc_parse.h"

extern int DEBUGLEVEL;

/****************************************************************************
  read an msrpc pdu from a fd. 
  The timeout is in milliseconds. 
****************************************************************************/
BOOL receive_msrpc(int fd, prs_struct *data, unsigned int timeout)
{
  	BOOL ok;
  	size_t len;
  	RPC_HDR hdr;

	prs_init(data, 16, 4, True);

	if (timeout > 0)
	{
		ok = (read_with_timeout(fd,data->data,16,16,timeout) == 16);
	}
	else 
	{
		ok = (read_data(fd,data->data,16) == 16);
	}

	if (!ok)
	{
		prs_free_data(data);
		return False;
	}

	if (!smb_io_rpc_hdr("hdr", &hdr, data, 0))
	{
		prs_free_data(data);
		return False;
	}

	len = hdr.frag_len - 16;
	if (len > 0)
	{
		size_t ret;
		prs_realloc_data(data, hdr.frag_len);
		ret = read_data(fd, data->data + 16, len);
		if (ret != len)
		{
			prs_free_data(data);
			return False;
		}
		data->start = 0;
		data->offset = hdr.frag_len;
		data->end = hdr.frag_len;
		return True;
	}

	prs_free_data(data);
	return False;
}

/****************************************************************************
  send an smb to a fd and re-establish if necessary
****************************************************************************/
BOOL msrpc_send(int fd, prs_struct *ps)
{
	size_t len = ps != NULL ? prs_buf_len(ps) : 0;
	size_t nwritten=0;
	ssize_t ret;
	char *outbuf = ps->data;

	DEBUG(10,("msrpc_send_prs: data: %p len %d\n", outbuf, len));
	dbgflush();

	if (outbuf == NULL)
	{
		return True;
	}
	dump_data(10, outbuf, len);

	while (nwritten < len)
	{
		ret = write_socket(fd,outbuf+nwritten,len - nwritten);
		if (ret <= 0)
		{
			DEBUG(0,("Error writing %d msrpc bytes. %d.\n",
				 len,ret));
			prs_free_data(ps);
			return False;
		}
		nwritten += ret;
	}
	
	prs_free_data(ps);
	return True;
}

/****************************************************************************
  receive msrpc packet
****************************************************************************/
BOOL msrpc_receive(int fd, prs_struct *ps)
{
	int len;

	DEBUG(10,("msrpc_receive: %d\n", __LINE__));

	if (!receive_msrpc(fd, ps, 0))
	{
		return False;
	}

	len = prs_buf_len(ps);

	if (ps->data == NULL || len <= 0)
	{
		return False;
	}

	dump_data(10, ps->data, len);

	DEBUG(10,("msrpc_receive: len %d\n", len));

	prs_debug_out(ps, "msrpc_receive_prs", 200);

	return True;
}

/****************************************************************************
open the msrpcent sockets
****************************************************************************/
BOOL msrpc_connect(struct msrpc_state *msrpc, const char *pipe_name)
{
	fstring path;
	slprintf(path, sizeof(path)-1, "%s/.msrpc/%s", LOCKDIR, pipe_name);

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
#if 0
	msrpc->nt.ntlmssp_cli_flgs = usr->ntc.ntlmssp_flags;
#endif
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
				const vuser_key *key,
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

	if (!create_user_creds(&ps, msrpc->pipe_name, 0x0, command,
	                        key, usr))
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
				const vuser_key *key,
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

	if (!msrpc_authenticate(msrpc, key, usr))
	{
		DEBUG(0,("authenticate failed\n"));
		close(msrpc->fd);
		msrpc->fd = -1;
		return False;
	}

	return True;
}

BOOL msrpc_connect_auth(struct msrpc_state *msrpc,
				const vuser_key *key,
				const char* pipename,
				const struct user_creds *usr)
{
	ZERO_STRUCTP(msrpc);
	if (!msrpc_initialise(msrpc, key))
	{
		DEBUG(0,("unable to initialise msrpcent connection.\n"));
		return False;
	}

	msrpc_init_creds(msrpc, usr);

	if (!msrpc_establish_connection(msrpc, key, pipename))
	{
		msrpc_shutdown(msrpc);
		return False;
	}

	return True;
}

/****************************************************************************
initialise a msrpcent structure
****************************************************************************/
struct msrpc_state *msrpc_initialise(struct msrpc_state *msrpc,
				const vuser_key *key)
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
	msrpc->nt.key.vuid = UID_FIELD_INVALID;

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
				const vuser_key *key,
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
		if (msrpc_init_redirect(msrpc, key, pipe_name, &msrpc->usr))
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

	if (!msrpc_authenticate(msrpc, key, &msrpc->usr))
	{
		DEBUG(0,("authenticate failed\n"));
		close(msrpc->fd);
		msrpc->fd = -1;
		return False;
	}

	return True;
}

