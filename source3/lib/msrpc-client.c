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
open the msrpcent sockets
****************************************************************************/
static BOOL ncalrpc_l_connect(struct msrpc_local *msrpc, const char *pipe_name)
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
  read an msrpc pdu from a fd. 
  The timeout is in milliseconds. 
****************************************************************************/
BOOL receive_msrpc(int fd, prs_struct *data, unsigned int timeout)
{
  	BOOL ok;
  	size_t len;
  	RPC_HDR hdr;

	prs_init(data, 0, 4, True);

	ok = prs_read(data, fd, 16, timeout);

	if (!ok)
	{
		prs_mem_free(data);
		return False;
	}

	if (!smb_io_rpc_hdr("hdr", &hdr, data, 0))
	{
		prs_mem_free(data);
		return False;
	}

	len = hdr.frag_len - 16;
	if (len > 0)
	{
		ok = prs_read(data, fd, hdr.frag_len, 0);
		if (!ok)
		{
			prs_mem_free(data);
			return False;
		}
		data->data_offset = hdr.frag_len;
		return True;
	}

	prs_mem_free(data);
	return False;
}

/****************************************************************************
  send an smb to a fd and re-establish if necessary
****************************************************************************/
BOOL msrpc_send(int fd, prs_struct *ps)
{
	size_t len = ps != NULL ? ps->buffer_size : 0;
	size_t nwritten=0;
	ssize_t ret;
	char *outbuf = ps->data_p;

	DEBUG(10,("msrpc_send_prs: data: %p len %d\n", outbuf, len));
	dbgflush();

	dump_data(10, outbuf, len);

	while (nwritten < len)
	{
		ret = write_socket(fd,outbuf+nwritten,len - nwritten);
		if (ret <= 0)
		{
			DEBUG(0,("Error writing %d msrpc bytes. %d.\n",
				 len,ret));
			prs_mem_free(ps);
			return False;
		}
		nwritten += ret;
	}
	
	prs_mem_free(ps);
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

	len = ps->buffer_size;

	if (ps->data_p == NULL || len <= 0)
	{
		return False;
	}

	dump_data(10, ps->data_p, len);

	DEBUG(10,("msrpc_receive: len %d\n", len));

	return True;
}

/****************************************************************************
close the socket descriptor
****************************************************************************/
static void ncalrpc_l_close_socket(struct msrpc_local *msrpc)
{
        if (msrpc->fd != -1)
        {
                close(msrpc->fd);
        }
        msrpc->fd = -1;
}

static BOOL ncalrpc_l_authenticate(struct msrpc_local *msrpc)
{
        int sock = msrpc->fd;
        uint32 len;
        char *data;
        prs_struct ps;
        uint32 status;

        uint16 command;

        command = AGENT_CMD_CON;

        if (!create_user_creds(&ps, msrpc->pipe_name, 0x0, command,
                               msrpc->nt.key.pid, NULL))
        {
                DEBUG(0, ("could not parse credentials\n"));
                close(sock);
                return False;
        }

        len = ps.data_offset;
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
#if 0
                uid_t uid = getuid();
                gid_t gid = getgid();
                char *name = uidtoname(uid);
#endif

                ZERO_STRUCT(usr);

                msrpc->nt.key.pid = sys_getpid();

#if 0	/* comment ou by JERRY */
                msrpc->nt.key.vuid = register_vuid(msrpc->nt.key.pid,
                                                   uid, gid,
                                                   name, name, False, &usr);
#endif /* comment ou by JERRY */
        }

        return msrpc;
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

	if (!create_user_creds(&ps, msrpc->pipe_name, 0x0, command,
	                        msrpc->pid, usr))
	{
		DEBUG(0,("could not parse credentials\n"));
		close(sock);
		return False;
	}

	len = ps.data_offset;
	data = ps.data_p;

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
				uint32 pid,
				const char* pipename,
				const struct user_creds *usr)
{
	ZERO_STRUCTP(msrpc);
	if (!msrpc_initialise(msrpc, pid))
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
struct msrpc_state *msrpc_initialise(struct msrpc_state *msrpc, uint32 pid)
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
	msrpc->pid = pid;

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


