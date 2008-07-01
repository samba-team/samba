/* 
   Unix SMB/CIFS implementation.
   SMB client generic functions
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2007.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

/*******************************************************************
 Setup the word count and byte count for a client smb message.
********************************************************************/

int cli_set_message(char *buf,int num_words,int num_bytes,bool zero)
{
	if (zero && (num_words || num_bytes)) {
		memset(buf + smb_size,'\0',num_words*2 + num_bytes);
	}
	SCVAL(buf,smb_wct,num_words);
	SSVAL(buf,smb_vwv + num_words*SIZEOFWORD,num_bytes);
	smb_setlen(buf,smb_size + num_words*2 + num_bytes - 4);
	return (smb_size + num_words*2 + num_bytes);
}

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
 Read an smb from a fd ignoring all keepalive packets.
 The timeout is in milliseconds

 This is exactly the same as receive_smb except that it never returns
 a session keepalive packet (just as receive_smb used to do).
 receive_smb was changed to return keepalives as the oplock processing means this call
 should never go into a blocking read.
****************************************************************************/

static ssize_t client_receive_smb(struct cli_state *cli, size_t maxlen)
{
	size_t len;

	for(;;) {
		NTSTATUS status;

		set_smb_read_error(&cli->smb_rw_error, SMB_READ_OK);

		status = receive_smb_raw(cli->fd, cli->inbuf, cli->bufsize,
					cli->timeout, maxlen, &len);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10,("client_receive_smb failed\n"));
			show_msg(cli->inbuf);

			if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)) {
				set_smb_read_error(&cli->smb_rw_error,
						   SMB_READ_EOF);
				return -1;
			}

			if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
				set_smb_read_error(&cli->smb_rw_error,
						   SMB_READ_TIMEOUT);
				return -1;
			}

			set_smb_read_error(&cli->smb_rw_error, SMB_READ_ERROR);
			return -1;
		}

		/*
		 * I don't believe len can be < 0 with NT_STATUS_OK
		 * returned above, but this check doesn't hurt. JRA.
		 */

		if ((ssize_t)len < 0) {
			return len;
		}

		/* Ignore session keepalive packets. */
		if(CVAL(cli->inbuf,0) != SMBkeepalive) {
			break;
		}
	}

	if (cli_encryption_on(cli)) {
		NTSTATUS status = cli_decrypt_message(cli);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("SMB decryption failed on incoming packet! Error %s\n",
				nt_errstr(status)));
			cli->smb_rw_error = SMB_READ_BAD_DECRYPT;
			return -1;
		}
	}

	show_msg(cli->inbuf);
	return len;
}

/****************************************************************************
 Recv an smb.
****************************************************************************/

bool cli_receive_smb(struct cli_state *cli)
{
	ssize_t len;

	/* fd == -1 causes segfaults -- Tom (tom@ninja.nl) */
	if (cli->fd == -1)
		return false; 

 again:
	len = client_receive_smb(cli, 0);
	
	if (len > 0) {
		/* it might be an oplock break request */
		if (!(CVAL(cli->inbuf, smb_flg) & FLAG_REPLY) &&
		    CVAL(cli->inbuf,smb_com) == SMBlockingX &&
		    SVAL(cli->inbuf,smb_vwv6) == 0 &&
		    SVAL(cli->inbuf,smb_vwv7) == 0) {
			if (cli->oplock_handler) {
				int fnum = SVAL(cli->inbuf,smb_vwv2);
				unsigned char level = CVAL(cli->inbuf,smb_vwv3+1);
				if (!cli->oplock_handler(cli, fnum, level)) {
					return false;
				}
			}
			/* try to prevent loops */
			SCVAL(cli->inbuf,smb_com,0xFF);
			goto again;
		}
	}

	/* If the server is not responding, note that now */
	if (len < 0) {
                DEBUG(0, ("Receiving SMB: Server stopped responding\n"));
		close(cli->fd);
		cli->fd = -1;
		return false;
	}

	if (!cli_check_sign_mac(cli, cli->inbuf)) {
		/*
		 * If we get a signature failure in sessionsetup, then
		 * the server sometimes just reflects the sent signature
		 * back to us. Detect this and allow the upper layer to
		 * retrieve the correct Windows error message.
		 */
		if (CVAL(cli->outbuf,smb_com) == SMBsesssetupX &&
			(smb_len(cli->inbuf) > (smb_ss_field + 8 - 4)) &&
			(SVAL(cli->inbuf,smb_flg2) & FLAGS2_SMB_SECURITY_SIGNATURES) &&
			memcmp(&cli->outbuf[smb_ss_field],&cli->inbuf[smb_ss_field],8) == 0 &&
			cli_is_error(cli)) {

			/*
			 * Reflected signature on login error. 
			 * Set bad sig but don't close fd.
			 */
			cli->smb_rw_error = SMB_READ_BAD_SIG;
			return true;
		}

		DEBUG(0, ("SMB Signature verification failed on incoming packet!\n"));
		cli->smb_rw_error = SMB_READ_BAD_SIG;
		close(cli->fd);
		cli->fd = -1;
		return false;
	};
	return true;
}

/****************************************************************************
 Read the data portion of a readX smb.
 The timeout is in milliseconds
****************************************************************************/

ssize_t cli_receive_smb_data(struct cli_state *cli, char *buffer, size_t len)
{
	NTSTATUS status;

	set_smb_read_error(&cli->smb_rw_error, SMB_READ_OK);

	status = read_socket_with_timeout(
		cli->fd, buffer, len, len, cli->timeout, NULL);
	if (NT_STATUS_IS_OK(status)) {
		return len;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)) {
		set_smb_read_error(&cli->smb_rw_error, SMB_READ_EOF);
		return -1;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		set_smb_read_error(&cli->smb_rw_error, SMB_READ_TIMEOUT);
		return -1;
	}

	set_smb_read_error(&cli->smb_rw_error, SMB_READ_ERROR);
	return -1;
}

static ssize_t write_socket(int fd, const char *buf, size_t len)
{
        ssize_t ret=0;

        DEBUG(6,("write_socket(%d,%d)\n",fd,(int)len));
        ret = write_data(fd,buf,len);

        DEBUG(6,("write_socket(%d,%d) wrote %d\n",fd,(int)len,(int)ret));
        if(ret <= 0)
                DEBUG(0,("write_socket: Error writing %d bytes to socket %d: ERRNO = %s\n",
                        (int)len, fd, strerror(errno) ));

        return(ret);
}

/****************************************************************************
 Send an smb to a fd.
****************************************************************************/

bool cli_send_smb(struct cli_state *cli)
{
	size_t len;
	size_t nwritten=0;
	ssize_t ret;
	char *buf_out = cli->outbuf;
	bool enc_on = cli_encryption_on(cli);

	/* fd == -1 causes segfaults -- Tom (tom@ninja.nl) */
	if (cli->fd == -1)
		return false;

	cli_calculate_sign_mac(cli, cli->outbuf);

	if (enc_on) {
		NTSTATUS status = cli_encrypt_message(cli, cli->outbuf,
						      &buf_out);
		if (!NT_STATUS_IS_OK(status)) {
			close(cli->fd);
			cli->fd = -1;
			cli->smb_rw_error = SMB_WRITE_ERROR;
			DEBUG(0,("Error in encrypting client message. Error %s\n",
				nt_errstr(status) ));
			return false;
		}
	}

	len = smb_len(buf_out) + 4;

	while (nwritten < len) {
		ret = write_socket(cli->fd,buf_out+nwritten,len - nwritten);
		if (ret <= 0) {
			if (enc_on) {
				cli_free_enc_buffer(cli, buf_out);
			}
			close(cli->fd);
			cli->fd = -1;
			cli->smb_rw_error = SMB_WRITE_ERROR;
			DEBUG(0,("Error writing %d bytes to client. %d (%s)\n",
				(int)len,(int)ret, strerror(errno) ));
			return false;
		}
		nwritten += ret;
	}

	if (enc_on) {
		cli_free_enc_buffer(cli, buf_out);
	}

	/* Increment the mid so we can tell between responses. */
	cli->mid++;
	if (!cli->mid)
		cli->mid++;
	return true;
}

/****************************************************************************
 Send a "direct" writeX smb to a fd.
****************************************************************************/

bool cli_send_smb_direct_writeX(struct cli_state *cli,
				const char *p,
				size_t extradata)
{
	/* First length to send is the offset to the data. */
	size_t len = SVAL(cli->outbuf,smb_vwv11) + 4;
	size_t nwritten=0;
	ssize_t ret;

	/* fd == -1 causes segfaults -- Tom (tom@ninja.nl) */
	if (cli->fd == -1) {
		return false;
	}

	if (client_is_signing_on(cli)) {
		DEBUG(0,("cli_send_smb_large: cannot send signed packet.\n"));
		return false;
	}

	while (nwritten < len) {
		ret = write_socket(cli->fd,cli->outbuf+nwritten,len - nwritten);
		if (ret <= 0) {
			close(cli->fd);
			cli->fd = -1;
			cli->smb_rw_error = SMB_WRITE_ERROR;
			DEBUG(0,("Error writing %d bytes to client. %d (%s)\n",
				(int)len,(int)ret, strerror(errno) ));
			return false;
		}
		nwritten += ret;
	}

	/* Now write the extra data. */
	nwritten=0;
	while (nwritten < extradata) {
		ret = write_socket(cli->fd,p+nwritten,extradata - nwritten);
		if (ret <= 0) {
			close(cli->fd);
			cli->fd = -1;
			cli->smb_rw_error = SMB_WRITE_ERROR;
			DEBUG(0,("Error writing %d extradata "
				"bytes to client. %d (%s)\n",
				(int)extradata,(int)ret, strerror(errno) ));
			return false;
		}
		nwritten += ret;
	}

	/* Increment the mid so we can tell between responses. */
	cli->mid++;
	if (!cli->mid)
		cli->mid++;
	return true;
}

/****************************************************************************
 Setup basics in a outgoing packet.
****************************************************************************/

void cli_setup_packet_buf(struct cli_state *cli, char *buf)
{
	uint16 flags2;
	cli->rap_error = 0;
	SIVAL(buf,smb_rcls,0);
	SSVAL(buf,smb_pid,cli->pid);
	memset(buf+smb_pidhigh, 0, 12);
	SSVAL(buf,smb_uid,cli->vuid);
	SSVAL(buf,smb_mid,cli->mid);

	if (cli->protocol <= PROTOCOL_CORE) {
		return;
	}

	if (cli->case_sensitive) {
		SCVAL(buf,smb_flg,0x0);
	} else {
		/* Default setting, case insensitive. */
		SCVAL(buf,smb_flg,0x8);
	}
	flags2 = FLAGS2_LONG_PATH_COMPONENTS;
	if (cli->capabilities & CAP_UNICODE)
		flags2 |= FLAGS2_UNICODE_STRINGS;
	if ((cli->capabilities & CAP_DFS) && cli->dfsroot)
		flags2 |= FLAGS2_DFS_PATHNAMES;
	if (cli->capabilities & CAP_STATUS32)
		flags2 |= FLAGS2_32_BIT_ERROR_CODES;
	if (cli->use_spnego)
		flags2 |= FLAGS2_EXTENDED_SECURITY;
	SSVAL(buf,smb_flg2, flags2);
}

void cli_setup_packet(struct cli_state *cli)
{
	cli_setup_packet_buf(cli, cli->outbuf);
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

void cli_init_creds(struct cli_state *cli, const char *username, const char *domain, const char *password)
{
	fstrcpy(cli->domain, domain);
	fstrcpy(cli->user_name, username);
	pwd_set_cleartext(&cli->pwd, password);
	if (!*username) {
		cli->pwd.null_pwd = true;
	}

        DEBUG(10,("cli_init_creds: user %s domain %s\n", cli->user_name, cli->domain));
}

/****************************************************************************
 Set the signing state (used from the command line).
****************************************************************************/

void cli_setup_signing_state(struct cli_state *cli, int signing_state)
{
	if (signing_state == Undefined)
		return;

	if (signing_state == false) {
		cli->sign_info.allow_smb_signing = false;
		cli->sign_info.mandatory_signing = false;
		return;
	}

	cli->sign_info.allow_smb_signing = true;

	if (signing_state == Required) 
		cli->sign_info.mandatory_signing = true;
}

/****************************************************************************
 Initialise a client structure. Always returns a malloc'ed struct.
****************************************************************************/

struct cli_state *cli_initialise(void)
{
	struct cli_state *cli = NULL;

	/* Check the effective uid - make sure we are not setuid */
	if (is_setuid_root()) {
		DEBUG(0,("libsmb based programs must *NOT* be setuid root.\n"));
		return NULL;
	}

	cli = talloc(NULL, struct cli_state);
	if (!cli) {
		return NULL;
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
	cli->outbuf = (char *)SMB_MALLOC(cli->bufsize+SAFETY_MARGIN);
	cli->inbuf = (char *)SMB_MALLOC(cli->bufsize+SAFETY_MARGIN);
	cli->oplock_handler = cli_oplock_ack;
	cli->case_sensitive = false;
	cli->smb_rw_error = SMB_READ_OK;

	cli->use_spnego = lp_client_use_spnego();

	cli->capabilities = CAP_UNICODE | CAP_STATUS32 | CAP_DFS;

	/* Set the CLI_FORCE_DOSERR environment variable to test
	   client routines using DOS errors instead of STATUS32
	   ones.  This intended only as a temporary hack. */	
	if (getenv("CLI_FORCE_DOSERR"))
		cli->force_dos_errors = true;

	if (lp_client_signing()) 
		cli->sign_info.allow_smb_signing = true;

	if (lp_client_signing() == Required) 
		cli->sign_info.mandatory_signing = true;
                                   
	if (!cli->outbuf || !cli->inbuf)
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

	cli->initialised = 1;

	return cli;

        /* Clean up after malloc() error */

 error:

        SAFE_FREE(cli->inbuf);
        SAFE_FREE(cli->outbuf);
	SAFE_FREE(cli);
        return NULL;
}

/****************************************************************************
 External interface.
 Close an open named pipe over SMB. Free any authentication data.
 Returns false if the cli_close call failed.
 ****************************************************************************/

bool cli_rpc_pipe_close(struct rpc_pipe_client *cli)
{
	bool ret;

	if (!cli) {
		return false;
	}

	ret = cli_close(cli->cli, cli->fnum);

	if (!ret) {
		DEBUG(1,("cli_rpc_pipe_close: cli_close failed on pipe %s, "
                         "fnum 0x%x "
                         "to machine %s.  Error was %s\n",
                         cli->pipe_name,
                         (int) cli->fnum,
                         cli->cli->desthost,
                         cli_errstr(cli->cli)));
	}

	if (cli->auth.cli_auth_data_free_func) {
		(*cli->auth.cli_auth_data_free_func)(&cli->auth);
	}

	DEBUG(10,("cli_rpc_pipe_close: closed pipe %s to machine %s\n",
		cli->pipe_name, cli->cli->desthost ));

	DLIST_REMOVE(cli->cli->pipe_list, cli);
	talloc_destroy(cli->mem_ctx);
	return ret;
}

/****************************************************************************
 Close all pipes open on this session.
****************************************************************************/

void cli_nt_pipes_close(struct cli_state *cli)
{
	struct rpc_pipe_client *cp, *next;

	for (cp = cli->pipe_list; cp; cp = next) {
		next = cp->next;
		cli_rpc_pipe_close(cp);
	}
}

/****************************************************************************
 Shutdown a client structure.
****************************************************************************/

void cli_shutdown(struct cli_state *cli)
{
	cli_nt_pipes_close(cli);

	/*
	 * tell our peer to free his resources.  Wihtout this, when an
	 * application attempts to do a graceful shutdown and calls
	 * smbc_free_context() to clean up all connections, some connections
	 * can remain active on the peer end, until some (long) timeout period
	 * later.  This tree disconnect forces the peer to clean up, since the
	 * connection will be going away.
	 *
	 * Also, do not do tree disconnect when cli->smb_rw_error is SMB_DO_NOT_DO_TDIS
	 * the only user for this so far is smbmount which passes opened connection
	 * down to kernel's smbfs module.
	 */
	if ( (cli->cnum != (uint16)-1) && (cli->smb_rw_error != SMB_DO_NOT_DO_TDIS ) ) {
		cli_tdis(cli);
	}
        
	SAFE_FREE(cli->outbuf);
	SAFE_FREE(cli->inbuf);

	cli_free_signing_context(cli);
	data_blob_free(&cli->secblob);
	data_blob_free(&cli->user_session_key);

	if (cli->fd != -1) {
		close(cli->fd);
	}
	cli->fd = -1;
	cli->smb_rw_error = SMB_READ_OK;

	TALLOC_FREE(cli);
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
 Set the case sensitivity flag on the packets. Returns old state.
****************************************************************************/

bool cli_set_case_sensitive(struct cli_state *cli, bool case_sensitive)
{
	bool ret = cli->case_sensitive;
	cli->case_sensitive = case_sensitive;
	return ret;
}

/****************************************************************************
Send a keepalive packet to the server
****************************************************************************/

bool cli_send_keepalive(struct cli_state *cli)
{
        if (cli->fd == -1) {
                DEBUG(3, ("cli_send_keepalive: fd == -1\n"));
                return false;
        }
        if (!send_keepalive(cli->fd)) {
                close(cli->fd);
                cli->fd = -1;
                DEBUG(0,("Error sending keepalive packet to client.\n"));
                return false;
        }
        return true;
}

/****************************************************************************
 Send/receive a SMBecho command: ping the server
****************************************************************************/

bool cli_echo(struct cli_state *cli, uint16 num_echos,
	      unsigned char *data, size_t length)
{
	char *p;
	int i;

	SMB_ASSERT(length < 1024);

	memset(cli->outbuf,'\0',smb_size);
	cli_set_message(cli->outbuf,1,length,true);
	SCVAL(cli->outbuf,smb_com,SMBecho);
	SSVAL(cli->outbuf,smb_tid,65535);
	SSVAL(cli->outbuf,smb_vwv0,num_echos);
	cli_setup_packet(cli);
	p = smb_buf(cli->outbuf);
	memcpy(p, data, length);
	p += length;

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);

	for (i=0; i<num_echos; i++) {
		if (!cli_receive_smb(cli)) {
			return false;
		}

		if (cli_is_error(cli)) {
			return false;
		}
	}

	return true;
}
