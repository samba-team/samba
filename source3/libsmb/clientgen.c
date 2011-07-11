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
#include "libsmb/libsmb.h"
#include "../lib/util/tevent_ntstatus.h"
#include "smb_signing.h"
#include "async_smb.h"

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
 convenience routine to find if we negotiated ucs2
****************************************************************************/

bool cli_ucs2(struct cli_state *cli)
{
	return ((cli->capabilities & CAP_UNICODE) != 0);
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

/****************************************************************************
 Initialize Domain, user or password.
****************************************************************************/

NTSTATUS cli_set_domain(struct cli_state *cli, const char *domain)
{
	TALLOC_FREE(cli->domain);
	cli->domain = talloc_strdup(cli, domain ? domain : "");
	if (cli->domain == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_set_username(struct cli_state *cli, const char *username)
{
	TALLOC_FREE(cli->user_name);
	cli->user_name = talloc_strdup(cli, username ? username : "");
	if (cli->user_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_set_password(struct cli_state *cli, const char *password)
{
	TALLOC_FREE(cli->password);

	/* Password can be NULL. */
	if (password) {
		cli->password = talloc_strdup(cli, password);
		if (cli->password == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		/* Use zero NTLMSSP hashes and session key. */
		cli->password = NULL;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Initialise credentials of a client structure.
****************************************************************************/

NTSTATUS cli_init_creds(struct cli_state *cli, const char *username, const char *domain, const char *password)
{
	NTSTATUS status = cli_set_username(cli, username);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = cli_set_domain(cli, domain);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	DEBUG(10,("cli_init_creds: user %s domain %s\n", cli->user_name, cli->domain));

	return cli_set_password(cli, password);
}

/****************************************************************************
 Initialise a client structure. Always returns a talloc'ed struct.
 Set the signing state (used from the command line).
****************************************************************************/

struct cli_state *cli_initialise_ex(int signing_state)
{
	struct cli_state *cli = NULL;
	bool allow_smb_signing = false;
	bool mandatory_signing = false;

	/* Check the effective uid - make sure we are not setuid */
	if (is_setuid_root()) {
		DEBUG(0,("libsmb based programs must *NOT* be setuid root.\n"));
		return NULL;
	}

	cli = talloc_zero(NULL, struct cli_state);
	if (!cli) {
		return NULL;
	}

	cli->dfs_mountpoint = talloc_strdup(cli, "");
	if (!cli->dfs_mountpoint) {
		goto error;
	}
	cli->fd = -1;
	cli->raw_status = NT_STATUS_INTERNAL_ERROR;
	cli->cnum = -1;
	cli->pid = (uint16)sys_getpid();
	cli->mid = 1;
	cli->vuid = UID_FIELD_INVALID;
	cli->protocol = PROTOCOL_NT1;
	cli->timeout = 20000; /* Timeout is in milliseconds. */
	cli->max_xmit = CLI_BUFFER_SIZE+4;
	cli->oplock_handler = cli_oplock_ack;
	cli->case_sensitive = false;

	cli->use_spnego = lp_client_use_spnego();

	cli->capabilities = CAP_UNICODE | CAP_STATUS32 | CAP_DFS;

	/* Set the CLI_FORCE_DOSERR environment variable to test
	   client routines using DOS errors instead of STATUS32
	   ones.  This intended only as a temporary hack. */	
	if (getenv("CLI_FORCE_DOSERR"))
		cli->force_dos_errors = true;

	if (lp_client_signing()) {
		allow_smb_signing = true;
	}

	if (lp_client_signing() == Required) {
		mandatory_signing = true;
	}

	if (signing_state != Undefined) {
		allow_smb_signing = true;
	}

	if (signing_state == false) {
		allow_smb_signing = false;
		mandatory_signing = false;
	}

	if (signing_state == Required) {
		mandatory_signing = true;
	}

	/* initialise signing */
	cli->signing_state = smb_signing_init(cli,
					      allow_smb_signing,
					      mandatory_signing);
	if (!cli->signing_state) {
		goto error;
	}

	cli->outgoing = tevent_queue_create(cli, "cli_outgoing");
	if (cli->outgoing == NULL) {
		goto error;
	}
	cli->pending = NULL;

	cli->initialised = 1;

	return cli;

        /* Clean up after malloc() error */

 error:

	TALLOC_FREE(cli);
        return NULL;
}

struct cli_state *cli_initialise(void)
{
	return cli_initialise_ex(Undefined);
}

/****************************************************************************
 Close all pipes open on this session.
****************************************************************************/

void cli_nt_pipes_close(struct cli_state *cli)
{
	while (cli->pipe_list != NULL) {
		/*
		 * No TALLOC_FREE here!
		 */
		talloc_free(cli->pipe_list);
	}
}

/****************************************************************************
 Shutdown a client structure.
****************************************************************************/

static void _cli_shutdown(struct cli_state *cli)
{
	cli_nt_pipes_close(cli);

	/*
	 * tell our peer to free his resources.  Wihtout this, when an
	 * application attempts to do a graceful shutdown and calls
	 * smbc_free_context() to clean up all connections, some connections
	 * can remain active on the peer end, until some (long) timeout period
	 * later.  This tree disconnect forces the peer to clean up, since the
	 * connection will be going away.
	 */
	if (cli->cnum != (uint16)-1) {
		cli_tdis(cli);
	}
        
	data_blob_free(&cli->secblob);
	data_blob_free(&cli->user_session_key);

	if (cli->fd != -1) {
		close(cli->fd);
	}
	cli->fd = -1;

	/*
	 * Need to free pending first, they remove themselves
	 */
	while (cli->pending) {
		talloc_free(cli->pending[0]);
	}
	TALLOC_FREE(cli);
}

void cli_shutdown(struct cli_state *cli)
{
	struct cli_state *cli_head;
	if (cli == NULL) {
		return;
	}
	DLIST_HEAD(cli, cli_head);
	if (cli_head == cli) {
		/*
		 * head of a DFS list, shutdown all subsidiary DFS
		 * connections.
		 */
		struct cli_state *p, *next;

		for (p = cli_head->next; p; p = next) {
			next = p->next;
			DLIST_REMOVE(cli_head, p);
			_cli_shutdown(p);
		}
	} else {
		DLIST_REMOVE(cli_head, cli);
	}

	_cli_shutdown(cli);
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

struct cli_echo_state {
	uint16_t vwv[1];
	DATA_BLOB data;
	int num_echos;
};

static void cli_echo_done(struct tevent_req *subreq);

struct tevent_req *cli_echo_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				 struct cli_state *cli, uint16_t num_echos,
				 DATA_BLOB data)
{
	struct tevent_req *req, *subreq;
	struct cli_echo_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_echo_state);
	if (req == NULL) {
		return NULL;
	}
	SSVAL(state->vwv, 0, num_echos);
	state->data = data;
	state->num_echos = num_echos;

	subreq = cli_smb_send(state, ev, cli, SMBecho, 0, 1, state->vwv,
			      data.length, data.data);
	if (subreq == NULL) {
		goto fail;
	}
	tevent_req_set_callback(subreq, cli_echo_done, req);
	return req;
 fail:
	TALLOC_FREE(req);
	return NULL;
}

static void cli_echo_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_echo_state *state = tevent_req_data(
		req, struct cli_echo_state);
	NTSTATUS status;
	uint32_t num_bytes;
	uint8_t *bytes;
	uint8_t *inbuf;

	status = cli_smb_recv(subreq, state, &inbuf, 0, NULL, NULL,
			      &num_bytes, &bytes);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	if ((num_bytes != state->data.length)
	    || (memcmp(bytes, state->data.data, num_bytes) != 0)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	state->num_echos -=1;
	if (state->num_echos == 0) {
		tevent_req_done(req);
		return;
	}

	if (!cli_smb_req_set_pending(subreq)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
}

/**
 * Get the result out from an echo request
 * @param[in] req	The async_req from cli_echo_send
 * @retval Did the server reply correctly?
 */

NTSTATUS cli_echo_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/**
 * @brief Send/Receive SMBEcho requests
 * @param[in] mem_ctx	The memory context to put the async_req on
 * @param[in] ev	The event context that will call us back
 * @param[in] cli	The connection to send the echo to
 * @param[in] num_echos	How many times do we want to get the reply?
 * @param[in] data	The data we want to get back
 * @retval Did the server reply correctly?
 */

NTSTATUS cli_echo(struct cli_state *cli, uint16_t num_echos, DATA_BLOB data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_echo_send(frame, ev, cli, num_echos, data);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_echo_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/**
 * Is the SMB command able to hold an AND_X successor
 * @param[in] cmd	The SMB command in question
 * @retval Can we add a chained request after "cmd"?
 */
bool is_andx_req(uint8_t cmd)
{
	switch (cmd) {
	case SMBtconX:
	case SMBlockingX:
	case SMBopenX:
	case SMBreadX:
	case SMBwriteX:
	case SMBsesssetupX:
	case SMBulogoffX:
	case SMBntcreateX:
		return true;
		break;
	default:
		break;
	}

	return false;
}

NTSTATUS cli_smb(TALLOC_CTX *mem_ctx, struct cli_state *cli,
		 uint8_t smb_command, uint8_t additional_flags,
		 uint8_t wct, uint16_t *vwv,
		 uint32_t num_bytes, const uint8_t *bytes,
		 struct tevent_req **result_parent,
		 uint8_t min_wct, uint8_t *pwct, uint16_t **pvwv,
		 uint32_t *pnum_bytes, uint8_t **pbytes)
{
        struct tevent_context *ev;
        struct tevent_req *req = NULL;
        NTSTATUS status = NT_STATUS_NO_MEMORY;

        if (cli_has_async_calls(cli)) {
                return NT_STATUS_INVALID_PARAMETER;
        }
        ev = tevent_context_init(mem_ctx);
        if (ev == NULL) {
                goto fail;
        }
        req = cli_smb_send(mem_ctx, ev, cli, smb_command, additional_flags,
			   wct, vwv, num_bytes, bytes);
        if (req == NULL) {
                goto fail;
        }
        if (!tevent_req_poll_ntstatus(req, ev, &status)) {
                goto fail;
        }
        status = cli_smb_recv(req, NULL, NULL, min_wct, pwct, pvwv,
			      pnum_bytes, pbytes);
fail:
        TALLOC_FREE(ev);
	if (NT_STATUS_IS_OK(status) && (result_parent != NULL)) {
		*result_parent = req;
	}
        return status;
}
