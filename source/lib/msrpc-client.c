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
BOOL receive_msrpc(int fd, prs_struct * data, unsigned int timeout)
{
	BOOL ok;
	size_t len;
	RPC_HDR hdr;

	prs_init(data, 16, 4, True);

	if (timeout > 0)
	{
		ok = (read_with_timeout(fd, data->data, 16, 16, timeout) ==
		      16);
	}
	else
	{
		ok = (read_data(fd, data->data, 16) == 16);
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
BOOL msrpc_send(int fd, prs_struct * ps)
{
	size_t len;
	ssize_t ret;
	char *outbuf;

	/* if there is no data then say success */
	if (!ps || !ps->data) return True;

	DEBUG(10, ("ncalrpc_l_send_prs: data: %p len %d\n", outbuf, len));
	dbgflush();

	len = prs_buf_len(ps);
	outbuf = ps->data;

	dump_data(10, outbuf, len);

	ret = write_socket(fd, outbuf, len);
	prs_free_data(ps);

	return (ret == len);
}

/****************************************************************************
  receive msrpc packet
****************************************************************************/
BOOL msrpc_receive(int fd, prs_struct * ps)
{
	int len;

	DEBUG(10, ("ncalrpc_l_receive: %d\n", __LINE__));

	if (!receive_msrpc(fd, ps, 0))
	{
		DEBUG(1,("msrpc_receive: failed\n"));
		return False;
	}

	len = prs_buf_len(ps);

	if (ps->data == NULL || len <= 0)
	{
		DEBUG(10, ("ncalrpc_l_receive: no data\n"));
		return False;
	}

	dump_data(10, ps->data, len);

	DEBUG(10, ("ncalrpc_l_receive: len %d\n", len));

	prs_debug_out(ps, "ncalrpc_l_receive_prs", 200);

	return True;
}

/****************************************************************************
open the msrpcent sockets
****************************************************************************/
BOOL ncalrpc_l_connect(struct msrpc_local *msrpc, const char *pipe_name)
{
	fstring path;
	fstring pname;
	fstrcpy(pname, pipe_name);
	strlower(pname);
	slprintf(path, sizeof(path) - 1, "%s/.msrpc/%s", LOCKDIR, pname);

	fstrcpy(msrpc->pipe_name, pipe_name);

	msrpc->fd = open_pipe_sock(path);

	if (msrpc->fd == -1)
	{
		return False;
	}

	return True;
}


/****************************************************************************
close the socket descriptor
****************************************************************************/
void ncalrpc_l_close_socket(struct msrpc_local *msrpc)
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
void ncalrpc_l_sockopt(struct msrpc_local *msrpc, char *options)
{
	set_socket_options(msrpc->fd, options);
}


static BOOL ncalrpc_l_authenticate(struct msrpc_local *msrpc)
{
	int sock = msrpc->fd;
	uint32 len;
	char *data;
	prs_struct ps;
	uint32 status;

	char *in = msrpc->inbuf;
	char *out = msrpc->outbuf;

	uint16 command;

	command = AGENT_CMD_CON;

	if (!create_user_creds(&ps, msrpc->pipe_name, 0x0, command,
			       &msrpc->nt.key, NULL))
	{
		DEBUG(0, ("could not parse credentials\n"));
		close(sock);
		return False;
	}

	len = ps.offset;
	data = prs_data(&ps, 0);

	SIVAL(data, 0, len);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("data len: %d\n", len));
	dump_data(100, data, len);
#endif

	if (write_socket(sock, data, len) <= 0)
	{
		DEBUG(0, ("write failed\n"));
		return False;
	}
	len = read_data(sock, (char*)&status, sizeof(status));

	return len == sizeof(status) && status == 0x0;
}

BOOL ncalrpc_l_connect_auth(struct msrpc_local *msrpc,
			    const vuser_key * key, const char *pipename)
{
	ZERO_STRUCTP(msrpc);
	if (!ncalrpc_l_initialise(msrpc, key))
	{
		DEBUG(0, ("unable to initialise ncalrpc_l connection.\n"));
		return False;
	}

	if (!ncalrpc_l_establish_connection(msrpc, pipename))
	{
		ncalrpc_l_shutdown(msrpc);
		return False;
	}

	return True;
}

/****************************************************************************
initialise a msrpcent structure
****************************************************************************/
struct msrpc_local *ncalrpc_l_initialise(struct msrpc_local *msrpc,
					 const vuser_key * key)
{
	if (!msrpc)
	{
		msrpc = (struct msrpc_local *)malloc(sizeof(*msrpc));
		if (!msrpc)
			return NULL;
		ZERO_STRUCTP(msrpc);
	}

	if (msrpc->initialised)
	{
		ncalrpc_l_shutdown(msrpc);
	}

	ZERO_STRUCTP(msrpc);

	msrpc->fd = -1;
	msrpc->outbuf = (char *)malloc(CLI_BUFFER_SIZE + 4);
	msrpc->inbuf = (char *)malloc(CLI_BUFFER_SIZE + 4);
	if (!msrpc->outbuf || !msrpc->inbuf)
	{
		return False;
	}

	msrpc->initialised = 1;

	if (key != NULL)
	{
		msrpc->nt.key = *key;
	}
	else
	{
		NET_USER_INFO_3 usr;
		uid_t uid = getuid();
		gid_t gid = getgid();
		char *name = uidtoname(uid);

		ZERO_STRUCT(usr);

		msrpc->nt.key.pid = getpid();
		msrpc->nt.key.vuid = register_vuid(msrpc->nt.key.pid,
						   uid, gid,
						   name, name, False, &usr);
	}

	return msrpc;
}


/****************************************************************************
shutdown a msrpcent structure
****************************************************************************/
void ncalrpc_l_shutdown(struct msrpc_local *msrpc)
{
	DEBUG(10, ("msrpc_shutdown\n"));
	if (msrpc->outbuf)
	{
		free(msrpc->outbuf);
	}
	if (msrpc->inbuf)
	{
		free(msrpc->inbuf);
	}
	ncalrpc_l_close_socket(msrpc);
	memset(msrpc, 0, sizeof(*msrpc));
}

/****************************************************************************
establishes a connection right up to doing tconX, reading in a password.
****************************************************************************/
BOOL ncalrpc_l_establish_connection(struct msrpc_local *msrpc,
				    const char *pipe_name)
{
	if (strnequal("\\PIPE\\", pipe_name, 6))
	{
		pipe_name = &pipe_name[6];
	}

	DEBUG(5, ("ncalrpc_l_establish_connection: connecting to %s\n",
		  pipe_name));

	/* establish connection */

	if (!msrpc->initialised)
	{
		return False;
	}

	if (msrpc->fd == -1)
	{
		if (!ncalrpc_l_connect(msrpc, pipe_name))
		{
			DEBUG(1,
			      ("ncalrpc_l_establish_connection: failed %s)\n",
			       pipe_name));

			return False;
		}
	}

	if (!ncalrpc_l_authenticate(msrpc))
	{
		DEBUG(0, ("authenticate failed\n"));
		close(msrpc->fd);
		msrpc->fd = -1;
		return False;
	}

	return True;
}
