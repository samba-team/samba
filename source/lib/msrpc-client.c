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
	size_t len = ps != NULL ? prs_buf_len(ps) : 0;
	size_t nwritten = 0;
	ssize_t ret;
	char *outbuf = ps->data;

	DEBUG(10, ("ncalrpc_l_send_prs: data: %p len %d\n", outbuf, len));
	dbgflush();

	if (outbuf == NULL)
	{
		return True;
	}
	dump_data(10, outbuf, len);

	while (nwritten < len)
	{
		ret = write_socket(fd, outbuf + nwritten, len - nwritten);
		if (ret <= 0)
		{
			DEBUG(0, ("Error writing %d msrpc bytes. %d.\n",
				  len, ret));
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
BOOL msrpc_receive(int fd, prs_struct * ps)
{
	int len;

	DEBUG(10, ("ncalrpc_l_receive: %d\n", __LINE__));

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
	slprintf(path, sizeof(path) - 1, "%s/.msrpc/%s", LOCKDIR, pipe_name);

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

	if (write(sock, data, len) <= 0)
	{
		DEBUG(0, ("write failed\n"));
		return False;
	}
	if (msrpc->redirect)
	{
		struct msrpc_local msrpc_redir;
		len = read(sock, &msrpc_redir, sizeof(msrpc_redir));

		if (len != sizeof(msrpc_redir))
		{
			DEBUG(0, ("read failed\n"));
			return False;
		}

		memcpy(msrpc, &msrpc_redir, sizeof(msrpc_redir));
		msrpc->inbuf = in;
		msrpc->outbuf = out;
		msrpc->fd = sock;
	}
	else
	{
		uint32 status;
		len = read(sock, &status, sizeof(status));

		return len == sizeof(status) && status == 0x0;
	}
	return True;
}

static BOOL ncalrpc_l_init_redirect(struct msrpc_local *msrpc,
				    const char *pipe_name)
{
	int sock;
	fstring path;

	slprintf(path, sizeof(path) - 1, "/tmp/.msrpc/.%s/agent", pipe_name);

	sock = open_pipe_sock(path);

	if (sock < 0)
	{
		return False;
	}

	msrpc->fd = sock;

	if (!ncalrpc_l_authenticate(msrpc))
	{
		DEBUG(0, ("authenticate failed\n"));
		close(msrpc->fd);
		msrpc->fd = -1;
		return False;
	}

	return True;
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

	if (msrpc->fd == -1 && msrpc->redirect)
	{
		if (ncalrpc_l_init_redirect(msrpc, pipe_name))
		{
			DEBUG(10,
			      ("ncalrpc_l_establish_connection: redirected OK\n"));
			return True;
		}
		else
		{
			DEBUG(10,
			      ("redirect failed, attempt direct connection\n"));
			msrpc->redirect = False;
		}
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


#if 0
static struct cli_connection *cli_con_get(const char *srv_name,
					  const char *pipe_name,
					  cli_auth_fns * auth,
					  void *auth_creds, BOOL reuse)
{
	struct cli_connection *con = NULL;

	con = (struct cli_connection *)malloc(sizeof(*con));

	if (con == NULL)
	{
		return NULL;
	}

	memset(con, 0, sizeof(*con));
	con->type = MSRPC_NONE;

	copy_user_creds(&con->usr_creds, usr_creds);
	con->usr_creds.reuse = reuse;

	if (srv_name != NULL)
	{
		con->srv_name = strdup(srv_name);
	}
	if (pipe_name != NULL)
	{
		con->pipe_name = strdup(pipe_name);
	}

	con->auth_info = NULL;
	con->auth_creds = auth_creds;

	if (auth != NULL)
	{
		con->auth = auth;
	}
	else
	{
		extern cli_auth_fns cli_noauth_fns;
		con->auth = &cli_noauth_fns;
	}

	if (strequal(srv_name, "\\\\."))
	{
		become_root(False);
		con->type = MSRPC_LOCAL;
		con->usr_creds.reuse = False;
		con->msrpc.local = ncalrpc_l_add(&pipe_name[6], user_key,
						 False);
		unbecome_root(False);
	}
	else
	{
		con->type = MSRPC_SMB;
		con->msrpc.smb = malloc(sizeof(*con->msrpc.smb));
		if (con->msrpc.smb == NULL)
		{
			cli_connection_free(con);
			return NULL;
		}
		else
		{
			con->msrpc.smb->cli =
				cli_net_use_add(srv_name, user_key,
						&con->usr_creds.ntc,
						True, reuse);
			if (con->msrpc.smb->cli != NULL)
			{
				if (!cli_nt_session_open(con->msrpc.smb->cli,
							 pipe_name,
							 &con->msrpc.smb->
							 fnum))
				{
					cli_connection_free(con);
					return NULL;
				}
				dump_data_pw("sess key:",
					     con->msrpc.smb->cli->nt.
					     usr_sess_key, 16);
			}
			else
			{
				cli_connection_free(con);
				return NULL;
			}
		}
	}

	if (con->msrpc.cli != NULL)
	{
		RPC_IFACE abstract;
		RPC_IFACE transfer;

		if (!rpc_pipe_bind(con, pipe_name, &abstract, &transfer))
		{
			DEBUG(0, ("rpc_pipe_bind failed\n"));
			cli_connection_free(con);
			return NULL;
		}
	}

	if (con->msrpc.cli == NULL)
	{
		cli_connection_free(con);
		return NULL;
	}

	add_con_to_array(&num_cons, &con_list, con);
	return con;
}

/****************************************************************************
terminate client state
****************************************************************************/
void cli_connection_unlink(struct cli_connection *con)
{
	if (con != NULL)
	{
		cli_connection_free(con);
	}
	return;
}

/****************************************************************************
init client state
****************************************************************************/
BOOL cli_connection_init(const char *srv_name, const char *pipe_name,
			 struct cli_connection **con)
{
	return cli_connection_init_auth(srv_name, pipe_name, con, NULL, NULL);
}

/****************************************************************************
init client state
****************************************************************************/
BOOL cli_connection_init_auth(const char *srv_name, const char *pipe_name,
			      struct cli_connection **con,
			      cli_auth_fns * auth, void *auth_creds)
{
	BOOL res = True;
	BOOL reuse = False;

	/*
	 * allocate
	 */

	DEBUG(10, ("cli_connection_init_auth: %s %s\n",
		   srv_name != NULL ? srv_name : "<null>", pipe_name));

	*con = cli_con_get(srv_name, pipe_name, auth, auth_creds, reuse);

	if ((*con) == NULL)
	{
		return False;
	}

	return res;
}

#endif
