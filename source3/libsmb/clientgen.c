/* 
   Unix SMB/CIFS implementation.
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
 Change the timeout (in milliseconds).
****************************************************************************/

unsigned int cli_set_timeout(struct cli_state *cli, unsigned int timeout)
{
	unsigned int old_timeout = cli->timeout;
	cli->timeout = timeout;
	return old_timeout;
}

/****************************************************************************
 Change the port number used to call on.
****************************************************************************/

int cli_set_port(struct cli_state *cli, int port)
{
	cli->port = port;
	return port;
}

/****************************************************************************
 Read an smb from a fd ignoring all keepalive packets. Note that the buffer 
 *MUST* be of size BUFFER_SIZE+SAFETY_MARGIN.
 The timeout is in milliseconds

 This is exactly the same as receive_smb except that it never returns
 a session keepalive packet (just as receive_smb used to do).
 receive_smb was changed to return keepalives as the oplock processing means this call
 should never go into a blocking read.
****************************************************************************/

static BOOL client_receive_smb(int fd,char *buffer, unsigned int timeout)
{
	BOOL ret;

	for(;;) {
		ret = receive_smb_raw(fd, buffer, timeout);

		if (!ret) {
			DEBUG(10,("client_receive_smb failed\n"));
			show_msg(buffer);
			return ret;
		}

		/* Ignore session keepalive packets. */
		if(CVAL(buffer,0) != SMBkeepalive)
			break;
	}
	show_msg(buffer);
	return ret;
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
	ret = client_receive_smb(cli->fd,cli->inbuf,cli->timeout);
	
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
		return ret;
	}

	if (!cli_check_sign_mac(cli, True)) {
		DEBUG(0, ("SMB Signature verification failed on incoming packet!\n"));
		cli->smb_rw_error = READ_BAD_SIG;
		close(cli->fd);
		cli->fd = -1;
		return False;
	};
	return True;
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

	cli_calculate_sign_mac(cli);

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
	/* Increment the mid so we can tell between responses. */
	cli->mid++;
	if (!cli->mid)
		cli->mid++;
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
		if (cli->capabilities & CAP_UNICODE)
			flags2 |= FLAGS2_UNICODE_STRINGS;
		if (cli->capabilities & CAP_STATUS32)
			flags2 |= FLAGS2_32_BIT_ERROR_CODES;
		if (cli->use_spnego)
			flags2 |= FLAGS2_EXTENDED_SECURITY;
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
 Initialise credentials of a client structure.
****************************************************************************/

void cli_init_creds(struct cli_state *cli, const struct ntuser_creds *usr)
{
        /* copy_nt_creds(&cli->usr, usr); */
	fstrcpy(cli->domain   , usr->domain);
	fstrcpy(cli->user_name, usr->user_name);
	memcpy(&cli->pwd, &usr->pwd, sizeof(usr->pwd));

        DEBUG(10,("cli_init_creds: user %s domain %s\n",
               cli->user_name, cli->domain));
}

/****************************************************************************
 Set the signing state (used from the command line).
****************************************************************************/

void cli_setup_signing_state(struct cli_state *cli, int signing_state)
{
	if (signing_state == Undefined)
		return;

	if (signing_state == False) {
		cli->sign_info.allow_smb_signing = False;
		cli->sign_info.mandatory_signing = False;
		return;
	}

	cli->sign_info.allow_smb_signing = True;

	if (signing_state == Required) 
		cli->sign_info.mandatory_signing = True;
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
	cli->outbuf = (char *)malloc(cli->bufsize+SAFETY_MARGIN);
	cli->inbuf = (char *)malloc(cli->bufsize+SAFETY_MARGIN);
	cli->oplock_handler = cli_oplock_ack;

	cli->use_spnego = lp_client_use_spnego();

	cli->capabilities = CAP_UNICODE | CAP_STATUS32;

	/* Set the CLI_FORCE_DOSERR environment variable to test
	   client routines using DOS errors instead of STATUS32
	   ones.  This intended only as a temporary hack. */	
	if (getenv("CLI_FORCE_DOSERR"))
		cli->force_dos_errors = True;

	if (lp_client_signing()) 
		cli->sign_info.allow_smb_signing = True;

	if (lp_client_signing() == Required) 
		cli->sign_info.mandatory_signing = True;
                                   
	if (!cli->outbuf || !cli->inbuf)
                goto error;

	if ((cli->mem_ctx = talloc_init("cli based talloc")) == NULL)
                goto error;

	memset(cli->outbuf, 0, cli->bufsize);
	memset(cli->inbuf, 0, cli->bufsize);


#if defined(DEVELOPER)
	/* just because we over-allocate, doesn't mean it's right to use it */
	clobber_region(FUNCTION_MACRO, __LINE__, cli->outbuf+cli->bufsize, SAFETY_MARGIN);
	clobber_region(FUNCTION_MACRO, __LINE__, cli->inbuf+cli->bufsize, SAFETY_MARGIN);
#endif

	/* initialise signing */
	cli_null_set_signing(cli);

	cli->nt_pipe_fnum = 0;
	cli->saved_netlogon_pipe_fnum = 0;

	cli->initialised = 1;
	cli->allocated = alloced_cli;

	cli->pipe_idx = -1;

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
close the session
****************************************************************************/

void cli_nt_session_close(struct cli_state *cli)
{
	if (cli->ntlmssp_pipe_state) {
		ntlmssp_end(&cli->ntlmssp_pipe_state);
	}

	if (cli->nt_pipe_fnum != 0)
		cli_close(cli, cli->nt_pipe_fnum);

	cli->nt_pipe_fnum = 0;
	cli->pipe_idx = -1;
}

/****************************************************************************
close the NETLOGON session holding the session key for NETSEC
****************************************************************************/

void cli_nt_netlogon_netsec_session_close(struct cli_state *cli)
{
	if (cli->saved_netlogon_pipe_fnum != 0) {
		cli_close(cli, cli->saved_netlogon_pipe_fnum);
		cli->saved_netlogon_pipe_fnum = 0;
	}
}

/****************************************************************************
 Close a client connection and free the memory without destroying cli itself.
****************************************************************************/

void cli_close_connection(struct cli_state *cli)
{
	/*
	 * tell our peer to free his resources.  Wihtout this, when an
	 * application attempts to do a graceful shutdown and calls
	 * smbc_free_context() to clean up all connections, some connections
	 * can remain active on the peer end, until some (long) timeout period
	 * later.  This tree disconnect forces the peer to clean up, since the
	 * connection will be going away.
	 *
	 * Also, do not do tree disconnect when cli->smb_rw_error is DO_NOT_DO_TDIS
	 * the only user for this so far is smbmount which passes opened connection
	 * down to kernel's smbfs module.
	 */
	if ( (cli->cnum != (uint16)-1) && (cli->smb_rw_error != DO_NOT_DO_TDIS ) )
		cli_tdis(cli);
        
	cli_nt_session_close(cli);
	cli_nt_netlogon_netsec_session_close(cli);

	SAFE_FREE(cli->outbuf);
	SAFE_FREE(cli->inbuf);

	cli_free_signing_context(cli);
	data_blob_free(&cli->secblob);
	data_blob_free(&cli->user_session_key);

	if (cli->ntlmssp_pipe_state) 
		ntlmssp_end(&cli->ntlmssp_pipe_state);

	if (cli->mem_ctx) {
		talloc_destroy(cli->mem_ctx);
		cli->mem_ctx = NULL;
	}

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
		free(cli);
}

/****************************************************************************
 Set socket options on a open connection.
****************************************************************************/

void cli_sockopt(struct cli_state *cli, const char *options)
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
Send a keepalive packet to the server
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
                DEBUG(0,("Error sending keepalive packet to client.\n"));
                return False;
        }
        return True;
}
