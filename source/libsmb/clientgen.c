/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client generic functions
   Copyright (C) Andrew Tridgell 1994-1998
   
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

/****************************************************************************
 Change the port number used to call on.
****************************************************************************/

int cli_set_port(struct cli_state *cli, int port)
{
	cli->port = port;
	return port;
}

/****************************************************************************
 Recv an smb.
****************************************************************************/

BOOL cli_receive_smb(struct cli_state *cli)
{
	extern int smb_read_error;
	BOOL ret;

	/* fd == -1 causes segfaults -- Tom (tom@ninja.nl) */
	if (cli->fd == -1)
		return False; 

 again:
	ret = client_receive_smb(cli->fd,cli->inbuf,abs(cli->timeout));
	
	if (ret) {
		/* it might be an oplock break request */
		if (!(CVAL(cli->inbuf, smb_flg) & FLAG_REPLY) &&
		    CVAL(cli->inbuf,smb_com) == SMBlockingX &&
		    SVAL(cli->inbuf,smb_vwv6) == 0 &&
		    SVAL(cli->inbuf,smb_vwv7) == 0) {
			if (cli->oplock_handler) {
				int fnum = SVAL(cli->inbuf,smb_vwv2);
				unsigned char level = CVAL(cli->inbuf,smb_vwv3+1);
				if (!cli->oplock_handler(cli, fnum, level)) return False;
			}
			/* try to prevent loops */
			SCVAL(cli->inbuf,smb_com,0xFF);
			goto again;
		}
	}

        /* If the server is not responding, note that now */
	if (!ret) {
		cli->smb_rw_error = smb_read_error;
		close(cli->fd);
		cli->fd = -1;
	}

	return ret;
}

/****************************************************************************
 Send an smb to a fd.
****************************************************************************/

BOOL cli_send_smb(struct cli_state *cli)
{
	size_t len;
	size_t nwritten=0;
	ssize_t ret;

	/* fd == -1 causes segfaults -- Tom (tom@ninja.nl) */
	if (cli->fd == -1)
		return False;

	len = smb_len(cli->outbuf) + 4;

	while (nwritten < len) {
		ret = write_socket(cli->fd,cli->outbuf+nwritten,len - nwritten);
		if (ret <= 0) {
                        close(cli->fd);
                        cli->fd = -1;
			cli->smb_rw_error = WRITE_ERROR;
			DEBUG(0,("Error writing %d bytes to client. %d (%s)\n",
				 (int)len,(int)ret, strerror(errno) ));
			return False;
		}
		nwritten += ret;
	}
	
	return True;
}

/****************************************************************************
 Setup basics in a outgoing packet.
****************************************************************************/

void cli_setup_packet(struct cli_state *cli)
{
        cli->rap_error = 0;
	SSVAL(cli->outbuf,smb_pid,cli->pid);
	SSVAL(cli->outbuf,smb_uid,cli->vuid);
	SSVAL(cli->outbuf,smb_mid,cli->mid);
	if (cli->protocol > PROTOCOL_CORE) {
		uint16 flags2;
		SCVAL(cli->outbuf,smb_flg,0x8);
		flags2 = FLAGS2_LONG_PATH_COMPONENTS;
		if (cli->capabilities & CAP_UNICODE) {
			flags2 |= FLAGS2_UNICODE_STRINGS;
		}
		if (cli->capabilities & CAP_STATUS32) {
			flags2 |= FLAGS2_32_BIT_ERROR_CODES;
		}
		SSVAL(cli->outbuf,smb_flg2, flags2);
	}
}

/****************************************************************************
 Setup the bcc length of the packet from a pointer to the end of the data.
****************************************************************************/

void cli_setup_bcc(struct cli_state *cli, void *p)
{
	set_message_bcc(cli->outbuf, PTR_DIFF(p, smb_buf(cli->outbuf)));
}

/****************************************************************************
 Initialise a client structure.
****************************************************************************/

void cli_init_creds(struct cli_state *cli, const struct ntuser_creds *usr)
{
        /* copy_nt_creds(&cli->usr, usr); */
	safe_strcpy(cli->domain   , usr->domain   , sizeof(usr->domain   )-1);
	safe_strcpy(cli->user_name, usr->user_name, sizeof(usr->user_name)-1);
	memcpy(&cli->pwd, &usr->pwd, sizeof(usr->pwd));
        cli->ntlmssp_flags = usr->ntlmssp_flags;
        cli->ntlmssp_cli_flgs = usr != NULL ? usr->ntlmssp_flags : 0;

        DEBUG(10,("cli_init_creds: user %s domain %s flgs: %x\nntlmssp_cli_flgs:%x\n",
               cli->user_name, cli->domain,
               cli->ntlmssp_flags,cli->ntlmssp_cli_flgs));
}

/****************************************************************************
 Initialise a client structure.
****************************************************************************/

struct cli_state *cli_initialise(struct cli_state *cli)
{
        BOOL alloced_cli = False;

	/* Check the effective uid - make sure we are not setuid */
	if (is_setuid_root()) {
		DEBUG(0,("libsmb based programs must *NOT* be setuid root.\n"));
		return NULL;
	}

	if (!cli) {
		cli = (struct cli_state *)malloc(sizeof(*cli));
		if (!cli)
			return NULL;
		ZERO_STRUCTP(cli);
                alloced_cli = True;
	}

	if (cli->initialised)
		cli_close_connection(cli);

	ZERO_STRUCTP(cli);

	cli->port = 0;
	cli->fd = -1;
	cli->cnum = -1;
	cli->pid = (uint16)sys_getpid();
	cli->mid = 1;
	cli->vuid = UID_FIELD_INVALID;
	cli->protocol = PROTOCOL_NT1;
	cli->timeout = 20000; /* Timeout is in milliseconds. */
	cli->bufsize = CLI_BUFFER_SIZE+4;
	cli->max_xmit = cli->bufsize;
	cli->outbuf = (char *)malloc(cli->bufsize);
	cli->inbuf = (char *)malloc(cli->bufsize);
	cli->oplock_handler = cli_oplock_ack;
	/* Set the CLI_FORCE_DOSERR environment variable to test
	   client routines using DOS errors instead of STATUS32
	   ones.  This intended only as a temporary hack. */	
	if (getenv("CLI_FORCE_DOSERR"))
		cli->force_dos_errors = True;

	if (!cli->outbuf || !cli->inbuf)
                goto error;

	if ((cli->mem_ctx = talloc_init()) == NULL)
                goto error;

	memset(cli->outbuf, 0, cli->bufsize);
	memset(cli->inbuf, 0, cli->bufsize);

	cli->nt_pipe_fnum = 0;

	cli->initialised = 1;
	cli->allocated = alloced_cli;

	return cli;

        /* Clean up after malloc() error */

 error:

        SAFE_FREE(cli->inbuf);
        SAFE_FREE(cli->outbuf);

        if (alloced_cli)
                SAFE_FREE(cli);

        return NULL;
}

/****************************************************************************
 Close a client connection and free the memory without destroying cli itself.
****************************************************************************/

void cli_close_connection(struct cli_state *cli)
{
	SAFE_FREE(cli->outbuf);
	SAFE_FREE(cli->inbuf);

	if (cli->mem_ctx) {
		talloc_destroy(cli->mem_ctx);
		cli->mem_ctx = NULL;
	}

#ifdef WITH_SSL
	if (cli->fd != -1)
		sslutil_disconnect(cli->fd);
#endif /* WITH_SSL */
	if (cli->fd != -1) 
		close(cli->fd);
	cli->fd = -1;
	cli->smb_rw_error = 0;
}

/****************************************************************************
 Shutdown a client structure.
****************************************************************************/

void cli_shutdown(struct cli_state *cli)
{
	BOOL allocated = cli->allocated;
	cli_close_connection(cli);
	ZERO_STRUCTP(cli);
	if (allocated)
		SAFE_FREE(cli);
}

/****************************************************************************
 Set socket options on a open connection.
****************************************************************************/

void cli_sockopt(struct cli_state *cli, char *options)
{
	set_socket_options(cli->fd, options);
}

/****************************************************************************
 Set the PID to use for smb messages. Return the old pid.
****************************************************************************/

uint16 cli_setpid(struct cli_state *cli, uint16 pid)
{
	uint16 ret = cli->pid;
	cli->pid = pid;
	return ret;
}

/****************************************************************************
 Send a keepalive packet to the server.
****************************************************************************/

BOOL cli_send_keepalive(struct cli_state *cli)
{
        if (cli->fd == -1) {
                DEBUG(3, ("cli_send_keepalive: fd == -1\n"));
                return False;
        }
        if (!send_keepalive(cli->fd)) {
                close(cli->fd);
                cli->fd = -1;
                DEBUG(0,("Error sending keepalive packet to client. (%s)\n",
					strerror(errno) ));
                return False;
        }
        return True;
}
