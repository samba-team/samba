/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client generic functions
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
#include "nterr.h"
#include "trans2.h"

extern int DEBUGLEVEL;

static void cli_process_oplock(struct cli_state *cli);

/* 
 * Change the port number used to call on 
 */
int cli_set_port(struct cli_state *cli, int port)
{
	if (port > 0)
	  cli->port = port;

	return cli->port;
}

/****************************************************************************
recv an smb
****************************************************************************/
BOOL cli_receive_smb(struct cli_state *cli)
{
	BOOL ret;
 again:
	/* there might have been an error on the socket */
	if (cli->fd == -1) return False;

	ret = client_receive_smb(cli->fd,cli->inbuf,cli->timeout);
	
	if (ret) {
		/* it might be an oplock break request */
		if (!(CVAL(cli->inbuf, smb_flg) & FLAG_REPLY) &&
		    CVAL(cli->inbuf,smb_com) == SMBlockingX &&
		    SVAL(cli->inbuf,smb_vwv6) == 0 &&
		    SVAL(cli->inbuf,smb_vwv7) == 0) {
			if (cli->use_oplocks) cli_process_oplock(cli);
			/* try to prevent loops */
			CVAL(cli->inbuf,smb_com) = 0xFF;
			goto again;
		}
	}

	/* if the server is not responding, then note that now */
	if (!ret) {
		close(cli->fd);
		cli->fd = -1;
	}

	return ret;
}

/****************************************************************************
  send an smb to a fd and re-establish if necessary
****************************************************************************/
BOOL cli_send_smb(struct cli_state *cli)
{
	size_t len;
	size_t nwritten=0;
	ssize_t ret;
	BOOL reestablished=False;

	/* there might have been an error on the socket */
	if (cli->fd == -1) return False;

	len = smb_len(cli->outbuf) + 4;

	while (nwritten < len) {
		ret = write_socket(cli->fd,cli->outbuf+nwritten,len - nwritten);
		if (ret <= 0 && errno == EPIPE && !reestablished) {
			if (cli_reestablish_connection(cli)) {
				reestablished = True;
				nwritten=0;
				continue;
			}
		}
		if (ret <= 0) {
			close(cli->fd);
			cli->fd = -1;
			DEBUG(0,("Error writing %d bytes to client. %d\n",
				 (int)len,(int)ret));
			return False;
		}
		nwritten += ret;
	}
	
	return True;
}

/****************************************************************************
setup basics in a outgoing packet
****************************************************************************/
void cli_setup_packet(struct cli_state *cli)
{
	uint16 flgs2 = 0;
	flgs2 |= FLAGS2_LONG_PATH_COMPONENTS;
	flgs2 |= FLAGS2_32_BIT_ERROR_CODES;
	flgs2 |= FLAGS2_EXT_SEC;
#if 0
	flgs2 |= FLAGS2_UNICODE_STRINGS;
#endif

        cli->rap_error = 0;
        cli->nt_error = 0;
	SSVAL(cli->outbuf,smb_pid,cli->pid);
	SSVAL(cli->outbuf,smb_uid,cli->vuid);
	SSVAL(cli->outbuf,smb_mid,cli->mid);

	if (cli->protocol > PROTOCOL_CORE)
	{
		SCVAL(cli->outbuf,smb_flg,0x8);
		SSVAL(cli->outbuf,smb_flg2,flgs2);
	}
}

/****************************************************************************
process an oplock break request from the server
****************************************************************************/
static void cli_process_oplock(struct cli_state *cli)
{
	char *oldbuf = cli->outbuf;
	pstring buf;
	int fnum;

	fnum = SVAL(cli->inbuf,smb_vwv2);

	/* damn, we really need to keep a record of open files so we
	   can detect a oplock break and a close crossing on the
	   wire. for now this swallows the errors */
	if (fnum == 0) return;

	cli->outbuf = buf;

        memset(buf,'\0',smb_size);
        set_message(buf,8,0,True);

        CVAL(buf,smb_com) = SMBlockingX;
	SSVAL(buf,smb_tid, cli->cnum);
        cli_setup_packet(cli);
	SSVAL(buf,smb_vwv0,0xFF);
	SSVAL(buf,smb_vwv1,0);
	SSVAL(buf,smb_vwv2,fnum);
	SSVAL(buf,smb_vwv3,2); /* oplock break ack */
	SIVAL(buf,smb_vwv4,0); /* timoeut */
	SSVAL(buf,smb_vwv6,0); /* unlockcount */
	SSVAL(buf,smb_vwv7,0); /* lockcount */

        cli_send_smb(cli);	

	cli->outbuf = oldbuf;
}

/****************************************************************************
  return a description of an SMB error
****************************************************************************/
void cli_safe_smb_errstr(struct cli_state *cli, char *msg, size_t len)
{
	smb_safe_errstr(cli->inbuf, msg, len);
}

/****************************************************************************
  return a description of an SMB error
****************************************************************************/
void cli_safe_errstr(struct cli_state *cli, char *err_msg, size_t msglen)
{   
	uint8 errclass;
	uint32 errnum;

	/*  
	 * Errors are of three kinds - smb errors,
	 * dealt with by cli_smb_errstr, NT errors,
	 * whose code is in cli.nt_error, and rap
	 * errors, whose error code is in cli.rap_error.
	 */ 

	cli_error(cli, &errclass, &errnum);

	if (errclass != 0)
	{
		cli_safe_smb_errstr(cli, err_msg, msglen);
	}
	else if (cli->nt_error)
	{
		/*
		 * Was it an NT error ?
		 */

		(void)get_safe_nt_error_msg(cli->nt_error, err_msg, msglen);
	}
	else
	{
		/*
		 * Must have been a rap error.
		 */
		(void)get_safe_rap_errstr(cli->rap_error, err_msg, msglen);
	}
}





/****************************************************************************
initialise a client structure
****************************************************************************/
void cli_init_creds(struct cli_state *cli, const struct ntuser_creds *usr)
{
	copy_nt_creds(&cli->usr, usr);
	cli->nt.ntlmssp_cli_flgs = usr != NULL ? usr->ntlmssp_flags : 0;
	DEBUG(10,("cli_init_creds: ntlmssp_flgs: %x\n", 
	           cli->nt.ntlmssp_cli_flgs));
}

/****************************************************************************
initialise a client structure
****************************************************************************/
struct cli_state *cli_initialise(struct cli_state *cli)
{
	if (!cli) {
		cli = (struct cli_state *)malloc(sizeof(*cli));
		if (!cli)
			return NULL;
		ZERO_STRUCTP(cli);
	}

	if (cli->initialised) {
		cli_shutdown(cli);
	}

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
	if (!cli->outbuf || !cli->inbuf)
	{
		return False;
	}

	cli->initialised = 1;
	cli->capabilities = CAP_DFS | CAP_NT_SMBS | CAP_STATUS32;
	cli->use_ntlmv2 = lp_client_ntlmv2();

	cli_init_creds(cli, NULL);

	return cli;
}

/****************************************************************************
close the socket descriptor
****************************************************************************/
void cli_close_socket(struct cli_state *cli)
{
#ifdef WITH_SSL
	if (cli->fd != -1)
	{
		sslutil_disconnect(cli->fd);
	}
#endif /* WITH_SSL */
	if (cli->fd != -1) 
	{
		close(cli->fd);
	}
	cli->fd = -1;
}

/****************************************************************************
shutdown a client structure
****************************************************************************/
void cli_shutdown(struct cli_state *cli)
{
	DEBUG(10,("cli_shutdown\n"));
	if (cli->outbuf)
	{
		free(cli->outbuf);
	}
	if (cli->inbuf)
	{
		free(cli->inbuf);
	}
	cli_close_socket(cli);
	memset(cli, 0, sizeof(*cli));
}


/****************************************************************************
set socket options on a open connection
****************************************************************************/
void cli_sockopt(struct cli_state *cli, char *options)
{
	set_socket_options(cli->fd, options);
}

/****************************************************************************
set the PID to use for smb messages. Return the old pid.
****************************************************************************/
uint16 cli_setpid(struct cli_state *cli, uint16 pid)
{
	uint16 ret = cli->pid;
	cli->pid = pid;
	return ret;
}

