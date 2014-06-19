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
#include "../libcli/smb/smb_signing.h"
#include "../libcli/smb/smb_seal.h"
#include "async_smb.h"
#include "../libcli/smb/smbXcli_base.h"
#include "../librpc/ndr/libndr.h"
#include "../include/client.h"

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
 Set the 'backup_intent' flag.
****************************************************************************/

bool cli_set_backup_intent(struct cli_state *cli, bool flag)
{
	bool old_state = cli->backup_intent;
	cli->backup_intent = flag;
	return old_state;
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

struct GUID cli_state_client_guid;

struct cli_state *cli_state_create(TALLOC_CTX *mem_ctx,
				   int fd,
				   const char *remote_name,
				   const char *remote_realm,
				   int signing_state, int flags)
{
	struct cli_state *cli = NULL;
	bool use_spnego = lp_client_use_spnego();
	bool force_dos_errors = false;
	bool force_ascii = false;
	bool use_level_II_oplocks = false;
	uint32_t smb1_capabilities = 0;
	uint32_t smb2_capabilities = 0;
	struct GUID client_guid;

	if (!GUID_all_zero(&cli_state_client_guid)) {
		client_guid = cli_state_client_guid;
	} else {
		client_guid = GUID_random();
	}

	/* Check the effective uid - make sure we are not setuid */
	if (is_setuid_root()) {
		DEBUG(0,("libsmb based programs must *NOT* be setuid root.\n"));
		return NULL;
	}

	cli = talloc_zero(mem_ctx, struct cli_state);
	if (!cli) {
		return NULL;
	}

	cli->server_domain = talloc_strdup(cli, "");
	if (!cli->server_domain) {
		goto error;
	}
	cli->server_os = talloc_strdup(cli, "");
	if (!cli->server_os) {
		goto error;
	}
	cli->server_type = talloc_strdup(cli, "");
	if (!cli->server_type) {
		goto error;
	}

	cli->dfs_mountpoint = talloc_strdup(cli, "");
	if (!cli->dfs_mountpoint) {
		goto error;
	}
	cli->raw_status = NT_STATUS_INTERNAL_ERROR;
	cli->map_dos_errors = true; /* remove this */
	cli->timeout = CLIENT_TIMEOUT;

	/* Set the CLI_FORCE_DOSERR environment variable to test
	   client routines using DOS errors instead of STATUS32
	   ones.  This intended only as a temporary hack. */	
	if (getenv("CLI_FORCE_DOSERR")) {
		force_dos_errors = true;
	}
	if (flags & CLI_FULL_CONNECTION_FORCE_DOS_ERRORS) {
		force_dos_errors = true;
	}

	if (getenv("CLI_FORCE_ASCII")) {
		force_ascii = true;
	}
	if (!lp_unicode()) {
		force_ascii = true;
	}
	if (flags & CLI_FULL_CONNECTION_FORCE_ASCII) {
		force_ascii = true;
	}

	if (flags & CLI_FULL_CONNECTION_DONT_SPNEGO) {
		use_spnego = false;
	} else if (flags & CLI_FULL_CONNECTION_USE_KERBEROS) {
		cli->use_kerberos = true;
	}
	if ((flags & CLI_FULL_CONNECTION_FALLBACK_AFTER_KERBEROS) &&
	     cli->use_kerberos) {
		cli->fallback_after_kerberos = true;
	}

	if (flags & CLI_FULL_CONNECTION_USE_CCACHE) {
		cli->use_ccache = true;
	}

	if (flags & CLI_FULL_CONNECTION_USE_NT_HASH) {
		cli->pw_nt_hash = true;
	}

	if (flags & CLI_FULL_CONNECTION_OPLOCKS) {
		cli->use_oplocks = true;
	}
	if (flags & CLI_FULL_CONNECTION_LEVEL_II_OPLOCKS) {
		use_level_II_oplocks = true;
	}

	if (signing_state == SMB_SIGNING_DEFAULT) {
		signing_state = lp_client_signing();
	}

	smb1_capabilities = 0;
	smb1_capabilities |= CAP_LARGE_FILES;
	smb1_capabilities |= CAP_NT_SMBS | CAP_RPC_REMOTE_APIS;
	smb1_capabilities |= CAP_LOCK_AND_READ | CAP_NT_FIND;
	smb1_capabilities |= CAP_DFS | CAP_W2K_SMBS;
	smb1_capabilities |= CAP_LARGE_READX|CAP_LARGE_WRITEX;
	smb1_capabilities |= CAP_LWIO;

	if (!force_dos_errors) {
		smb1_capabilities |= CAP_STATUS32;
	}

	if (!force_ascii) {
		smb1_capabilities |= CAP_UNICODE;
	}

	if (use_spnego) {
		smb1_capabilities |= CAP_EXTENDED_SECURITY;
	}

	if (use_level_II_oplocks) {
		smb1_capabilities |= CAP_LEVEL_II_OPLOCKS;
	}

	smb2_capabilities = SMB2_CAP_ALL;

	if (remote_realm) {
		cli->remote_realm = talloc_strdup(cli, remote_realm);
		if (cli->remote_realm == NULL) {
			goto error;
		}
	}

	cli->conn = smbXcli_conn_create(cli, fd, remote_name,
					signing_state,
					smb1_capabilities,
					&client_guid,
					smb2_capabilities);
	if (cli->conn == NULL) {
		goto error;
	}

	cli->smb1.pid = (uint16_t)getpid();
	cli->smb1.vc_num = cli->smb1.pid;
	cli->smb1.tcon = smbXcli_tcon_create(cli);
	if (cli->smb1.tcon == NULL) {
		goto error;
	}
	smb1cli_tcon_set_id(cli->smb1.tcon, UINT16_MAX);
	cli->smb1.session = smbXcli_session_create(cli, cli->conn);
	if (cli->smb1.session == NULL) {
		goto error;
	}

	cli->initialised = 1;
	return cli;

        /* Clean up after malloc() error */

 error:

	TALLOC_FREE(cli);
        return NULL;
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
	if (cli_state_has_tcon(cli)) {
		cli_tdis(cli);
	}

	smbXcli_conn_disconnect(cli->conn, NT_STATUS_OK);

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

const char *cli_state_remote_realm(struct cli_state *cli)
{
	return cli->remote_realm;
}

uint16_t cli_state_get_vc_num(struct cli_state *cli)
{
	return cli->smb1.vc_num;
}

/****************************************************************************
 Set the PID to use for smb messages. Return the old pid.
****************************************************************************/

uint16 cli_setpid(struct cli_state *cli, uint16 pid)
{
	uint16_t ret = cli->smb1.pid;
	cli->smb1.pid = pid;
	return ret;
}

uint16_t cli_getpid(struct cli_state *cli)
{
	return cli->smb1.pid;
}

bool cli_state_has_tcon(struct cli_state *cli)
{
	uint16_t tid = cli_state_get_tid(cli);

	if (tid == UINT16_MAX) {
		return false;
	}

	return true;
}

uint16_t cli_state_get_tid(struct cli_state *cli)
{
	return smb1cli_tcon_current_id(cli->smb1.tcon);
}

uint16_t cli_state_set_tid(struct cli_state *cli, uint16_t tid)
{
	uint16_t ret = smb1cli_tcon_current_id(cli->smb1.tcon);
	smb1cli_tcon_set_id(cli->smb1.tcon, tid);
	return ret;
}

uint16_t cli_state_get_uid(struct cli_state *cli)
{
	return smb1cli_session_current_id(cli->smb1.session);
}

uint16_t cli_state_set_uid(struct cli_state *cli, uint16_t uid)
{
	uint16_t ret = smb1cli_session_current_id(cli->smb1.session);
	smb1cli_session_set_id(cli->smb1.session, uid);
	return ret;
}

/****************************************************************************
 Set the case sensitivity flag on the packets. Returns old state.
****************************************************************************/

bool cli_set_case_sensitive(struct cli_state *cli, bool case_sensitive)
{
	bool ret;
	uint32_t fs_attrs;
	struct smbXcli_tcon *tcon;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		tcon = cli->smb2.tcon;
	} else {
		tcon = cli->smb1.tcon;
	}

	fs_attrs = smbXcli_tcon_get_fs_attributes(tcon);
	if (fs_attrs & FILE_CASE_SENSITIVE_SEARCH) {
		ret = true;
	} else {
		ret = false;
	}
	if (case_sensitive) {
		fs_attrs |= FILE_CASE_SENSITIVE_SEARCH;
	} else {
		fs_attrs &= ~FILE_CASE_SENSITIVE_SEARCH;
	}
	smbXcli_tcon_set_fs_attributes(tcon, fs_attrs);

	return ret;
}

uint32_t cli_state_available_size(struct cli_state *cli, uint32_t ofs)
{
	uint32_t ret = smb1cli_conn_max_xmit(cli->conn);

	if (ofs >= ret) {
		return 0;
	}

	ret -= ofs;

	return ret;
}

time_t cli_state_server_time(struct cli_state *cli)
{
	NTTIME nt;
	time_t t;

	nt = smbXcli_conn_server_system_time(cli->conn);
	t = nt_time_to_unix(nt);

	return t;
}

struct cli_echo_state {
	bool is_smb2;
};

static void cli_echo_done(struct tevent_req *subreq);

struct tevent_req *cli_echo_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				 struct cli_state *cli, uint16_t num_echos,
				 DATA_BLOB data)
{
	struct tevent_req *req, *subreq;
	struct cli_echo_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_echo_state);
	if (req == NULL) {
		return NULL;
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		state->is_smb2 = true;
		subreq = smb2cli_echo_send(state, ev,
					   cli->conn,
					   cli->timeout);
	} else {
		subreq = smb1cli_echo_send(state, ev,
					   cli->conn,
					   cli->timeout,
					   num_echos,
					   data);
	}
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_echo_done, req);

	return req;
}

static void cli_echo_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_echo_state *state = tevent_req_data(
		req, struct cli_echo_state);
	NTSTATUS status;

	if (state->is_smb2) {
		status = smb2cli_echo_recv(subreq);
	} else {
		status = smb1cli_echo_recv(subreq);
	}
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
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
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
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

        if (smbXcli_conn_has_async_calls(cli->conn)) {
                return NT_STATUS_INVALID_PARAMETER;
        }
        ev = samba_tevent_context_init(mem_ctx);
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
