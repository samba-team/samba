/*
   Unix SMB/CIFS implementation.
   client connect/disconnect routines
   Copyright (C) Andrew Tridgell                  1994-1998
   Copyright (C) Gerald (Jerry) Carter            2004
   Copyright (C) Jeremy Allison                   2007-2009

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
#include "libsmb/clirap.h"
#include "msdfs.h"
#include "trans2.h"
#include "libsmb/nmblib.h"
#include "../libcli/smb/smbXcli_base.h"
#include "auth/credentials/credentials.h"

/********************************************************************
 Important point.

 DFS paths are *always* of the form \server\share\<pathname> (the \ characters
 are not C escaped here).

 - but if we're using POSIX paths then <pathname> may contain
   '/' separators, not '\\' separators. So cope with '\\' or '/'
   as a separator when looking at the pathname part.... JRA.
********************************************************************/

/********************************************************************
 Ensure a connection is encrypted.
********************************************************************/

NTSTATUS cli_cm_force_encryption_creds(struct cli_state *c,
				       struct cli_credentials *creds,
				       const char *sharename)
{
	uint16_t major, minor;
	uint32_t caplow, caphigh;
	NTSTATUS status;
	bool temp_ipc = false;

	if (smbXcli_conn_protocol(c->conn) >= PROTOCOL_SMB2_02) {
		status = smb2cli_session_encryption_on(c->smb2.session);
		if (NT_STATUS_EQUAL(status,NT_STATUS_NOT_SUPPORTED)) {
			d_printf("Encryption required and "
				"server doesn't support "
				"SMB3 encryption - failing connect\n");
		} else if (!NT_STATUS_IS_OK(status)) {
			d_printf("Encryption required and "
				"setup failed with error %s.\n",
				nt_errstr(status));
		}
		return status;
	}

	if (!SERVER_HAS_UNIX_CIFS(c)) {
		d_printf("Encryption required and "
			"server that doesn't support "
			"UNIX extensions - failing connect\n");
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (c->smb1.tcon == NULL) {
		status = cli_tree_connect_creds(c, "IPC$", "IPC", creds);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Encryption required and "
				"can't connect to IPC$ to check "
				"UNIX CIFS extensions.\n");
			return NT_STATUS_UNKNOWN_REVISION;
		}
		temp_ipc = true;
	}

	status = cli_unix_extensions_version(c, &major, &minor, &caplow,
					     &caphigh);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Encryption required and "
			"can't get UNIX CIFS extensions "
			"version from server.\n");
		if (temp_ipc) {
			cli_tdis(c);
		}
		return NT_STATUS_UNKNOWN_REVISION;
	}

	if (!(caplow & CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP)) {
		d_printf("Encryption required and "
			"share %s doesn't support "
			"encryption.\n", sharename);
		if (temp_ipc) {
			cli_tdis(c);
		}
		return NT_STATUS_UNSUPPORTED_COMPRESSION;
	}

	status = cli_smb1_setup_encryption(c, creds);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Encryption required and "
			"setup failed with error %s.\n",
			nt_errstr(status));
		if (temp_ipc) {
			cli_tdis(c);
		}
		return status;
	}

	if (temp_ipc) {
		cli_tdis(c);
	}
	return NT_STATUS_OK;
}

/********************************************************************
 Return a connection to a server.
********************************************************************/

static NTSTATUS do_connect(TALLOC_CTX *ctx,
					const char *server,
					const char *share,
					const struct user_auth_info *auth_info,
					bool force_encrypt,
					int max_protocol,
					const struct sockaddr_storage *dest_ss,
					int port,
					int name_type,
					struct cli_state **pcli)
{
	struct cli_state *c = NULL;
	char *servicename;
	char *sharename;
	char *newserver, *newshare;
	NTSTATUS status;
	int flags = 0;
	enum protocol_types protocol = PROTOCOL_NONE;
	int signing_state = get_cmdline_auth_info_signing_state(auth_info);
	struct cli_credentials *creds = NULL;

	if (force_encrypt) {
		signing_state = SMB_SIGNING_REQUIRED;
	}

	/* make a copy so we don't modify the global string 'service' */
	servicename = talloc_strdup(ctx,share);
	if (!servicename) {
		return NT_STATUS_NO_MEMORY;
	}
	sharename = servicename;
	if (*sharename == '\\') {
		sharename += 2;
		if (server == NULL) {
			server = sharename;
		}
		sharename = strchr_m(sharename,'\\');
		if (!sharename) {
			return NT_STATUS_NO_MEMORY;
		}
		*sharename = 0;
		sharename++;
	}
	if (server == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = cli_connect_nb(
		server, dest_ss, port, name_type, NULL,
		signing_state,
		flags, &c);

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			DBG_ERR("NetBIOS support disabled, unable to connect");
		}

		DBG_WARNING("Connection to %s failed (Error %s)\n",
			    server,
			    nt_errstr(status));
		return status;
	}

	if (max_protocol == 0) {
		max_protocol = PROTOCOL_LATEST;
	}
	DEBUG(4,(" session request ok\n"));

	status = smbXcli_negprot(c->conn, c->timeout,
				 lp_client_min_protocol(),
				 max_protocol);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("protocol negotiation failed: %s\n",
			 nt_errstr(status));
		cli_shutdown(c);
		return status;
	}
	protocol = smbXcli_conn_protocol(c->conn);
	DEBUG(4,(" negotiated dialect[%s] against server[%s]\n",
		 smb_protocol_types_string(protocol),
		 smbXcli_conn_remote_name(c->conn)));

	if (protocol >= PROTOCOL_SMB2_02) {
		/* Ensure we ask for some initial credits. */
		smb2cli_conn_set_max_credits(c->conn, DEFAULT_SMB2_MAX_CREDITS);
	}

	creds = get_cmdline_auth_info_creds(auth_info);

	status = cli_session_setup_creds(c, creds);
	if (!NT_STATUS_IS_OK(status)) {
		/* If a password was not supplied then
		 * try again with a null username. */
		if (force_encrypt || smbXcli_conn_signing_mandatory(c->conn) ||
			cli_credentials_authentication_requested(creds) ||
			cli_credentials_is_anonymous(creds) ||
			!NT_STATUS_IS_OK(status = cli_session_setup_anon(c)))
		{
			d_printf("session setup failed: %s\n",
				 nt_errstr(status));
			if (NT_STATUS_EQUAL(status,
					    NT_STATUS_MORE_PROCESSING_REQUIRED))
				d_printf("did you forget to run kinit?\n");
			cli_shutdown(c);
			return status;
		}
		d_printf("Anonymous login successful\n");
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("cli_init_creds() failed: %s\n", nt_errstr(status)));
		cli_shutdown(c);
		return status;
	}

	DEBUG(4,(" session setup ok\n"));

	if (force_encrypt) {
		status = cli_cm_force_encryption_creds(c,
						       creds,
						       sharename);
		if (!NT_STATUS_IS_OK(status)) {
			cli_shutdown(c);
			return status;
		}
	}

	/* here's the fun part....to support 'msdfs proxy' shares
	   (on Samba or windows) we have to issues a TRANS_GET_DFS_REFERRAL
	   here before trying to connect to the original share.
	   cli_check_msdfs_proxy() will fail if it is a normal share. */

	if (smbXcli_conn_dfs_supported(c->conn) &&
			cli_check_msdfs_proxy(ctx, c, sharename,
				&newserver, &newshare,
				force_encrypt, creds)) {
		cli_shutdown(c);
		return do_connect(ctx, newserver,
				newshare, auth_info,
				force_encrypt, max_protocol,
				NULL, port, name_type, pcli);
	}

	/* must be a normal share */

	status = cli_tree_connect_creds(c, sharename, "?????", creds);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("tree connect failed: %s\n", nt_errstr(status));
		cli_shutdown(c);
		return status;
	}

	DEBUG(4,(" tconx ok\n"));
	*pcli = c;
	return NT_STATUS_OK;
}

/****************************************************************************
****************************************************************************/

static void cli_set_mntpoint(struct cli_state *cli, const char *mnt)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *name = clean_name(frame, mnt);
	if (!name) {
		TALLOC_FREE(frame);
		return;
	}
	TALLOC_FREE(cli->dfs_mountpoint);
	cli->dfs_mountpoint = talloc_strdup(cli, name);
	TALLOC_FREE(frame);
}

/********************************************************************
 Add a new connection to the list.
 referring_cli == NULL means a new initial connection.
********************************************************************/

static NTSTATUS cli_cm_connect(TALLOC_CTX *ctx,
			       struct cli_state *referring_cli,
			       const char *server,
			       const char *share,
			       const struct user_auth_info *auth_info,
			       bool force_encrypt,
			       int max_protocol,
			       const struct sockaddr_storage *dest_ss,
			       int port,
			       int name_type,
			       struct cli_state **pcli)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;

	status = do_connect(ctx, server, share,
				auth_info,
				force_encrypt, max_protocol,
				dest_ss, port, name_type, &cli);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * This can't happen, this test is to satisfy static
	 * checkers (clang)
	 */
	if (cli == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Enter into the list. */
	if (referring_cli) {
		DLIST_ADD_END(referring_cli, cli);
	}

	if (referring_cli && referring_cli->requested_posix_capabilities) {
		uint16_t major, minor;
		uint32_t caplow, caphigh;
		status = cli_unix_extensions_version(cli, &major, &minor,
						     &caplow, &caphigh);
		if (NT_STATUS_IS_OK(status)) {
			cli_set_unix_extensions_capabilities(cli,
					major, minor,
					caplow, caphigh);
		}
	}

	*pcli = cli;
	return NT_STATUS_OK;
}

/********************************************************************
 Return a connection to a server on a particular share.
********************************************************************/

static struct cli_state *cli_cm_find(struct cli_state *cli,
				const char *server,
				const char *share)
{
	struct cli_state *p;

	if (cli == NULL) {
		return NULL;
	}

	/* Search to the start of the list. */
	for (p = cli; p; p = DLIST_PREV(p)) {
		const char *remote_name =
			smbXcli_conn_remote_name(p->conn);

		if (strequal(server, remote_name) &&
				strequal(share,p->share)) {
			return p;
		}
	}

	/* Search to the end of the list. */
	for (p = cli->next; p; p = p->next) {
		const char *remote_name =
			smbXcli_conn_remote_name(p->conn);

		if (strequal(server, remote_name) &&
				strequal(share,p->share)) {
			return p;
		}
	}

	return NULL;
}

/****************************************************************************
 Open a client connection to a \\server\share.
****************************************************************************/

NTSTATUS cli_cm_open(TALLOC_CTX *ctx,
				struct cli_state *referring_cli,
				const char *server,
				const char *share,
				const struct user_auth_info *auth_info,
				bool force_encrypt,
				int max_protocol,
				const struct sockaddr_storage *dest_ss,
				int port,
				int name_type,
				struct cli_state **pcli)
{
	/* Try to reuse an existing connection in this list. */
	struct cli_state *c = cli_cm_find(referring_cli, server, share);
	NTSTATUS status;

	if (c) {
		*pcli = c;
		return NT_STATUS_OK;
	}

	if (auth_info == NULL) {
		/* Can't do a new connection
		 * without auth info. */
		d_printf("cli_cm_open() Unable to open connection [\\%s\\%s] "
			"without auth info\n",
			server, share );
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = cli_cm_connect(ctx,
				referring_cli,
				server,
				share,
				auth_info,
				force_encrypt,
				max_protocol,
				dest_ss,
				port,
				name_type,
				&c);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	*pcli = c;
	return NT_STATUS_OK;
}

/****************************************************************************
****************************************************************************/

void cli_cm_display(struct cli_state *cli)
{
	int i;

	for (i=0; cli; cli = cli->next,i++ ) {
		d_printf("%d:\tserver=%s, share=%s\n",
			i, smbXcli_conn_remote_name(cli->conn), cli->share);
	}
}

/****************************************************************************
****************************************************************************/

/****************************************************************************
****************************************************************************/

#if 0
void cli_cm_set_credentials(struct user_auth_info *auth_info)
{
	SAFE_FREE(cm_creds.username);
	cm_creds.username = SMB_STRDUP(get_cmdline_auth_info_username(
					       auth_info));

	if (get_cmdline_auth_info_got_pass(auth_info)) {
		cm_set_password(get_cmdline_auth_info_password(auth_info));
	}

	cm_creds.use_kerberos = get_cmdline_auth_info_use_kerberos(auth_info);
	cm_creds.fallback_after_kerberos = false;
	cm_creds.signing_state = get_cmdline_auth_info_signing_state(auth_info);
}
#endif

/**********************************************************************
 split a dfs path into the server, share name, and extrapath components
**********************************************************************/

static bool split_dfs_path(TALLOC_CTX *ctx,
				const char *nodepath,
				char **pp_server,
				char **pp_share,
				char **pp_extrapath)
{
	char *p, *q;
	char *path;

	*pp_server = NULL;
	*pp_share = NULL;
	*pp_extrapath = NULL;

	path = talloc_strdup(ctx, nodepath);
	if (!path) {
		goto fail;
	}

	if ( path[0] != '\\' ) {
		goto fail;
	}

	p = strchr_m( path + 1, '\\' );
	if ( !p ) {
		goto fail;
	}

	*p = '\0';
	p++;

	/* Look for any extra/deep path */
	q = strchr_m(p, '\\');
	if (q != NULL) {
		*q = '\0';
		q++;
		*pp_extrapath = talloc_strdup(ctx, q);
	} else {
		*pp_extrapath = talloc_strdup(ctx, "");
	}
	if (*pp_extrapath == NULL) {
		goto fail;
	}

	*pp_share = talloc_strdup(ctx, p);
	if (*pp_share == NULL) {
		goto fail;
	}

	*pp_server = talloc_strdup(ctx, &path[1]);
	if (*pp_server == NULL) {
		goto fail;
	}

	TALLOC_FREE(path);
	return true;

fail:
	TALLOC_FREE(*pp_share);
	TALLOC_FREE(*pp_extrapath);
	TALLOC_FREE(path);
	return false;
}

/****************************************************************************
 Return the original path truncated at the directory component before
 the first wildcard character. Trust the caller to provide a NULL
 terminated string
****************************************************************************/

static char *clean_path(TALLOC_CTX *ctx, const char *path)
{
	size_t len;
	char *p1, *p2, *p;
	char *path_out;

	/* No absolute paths. */
	while (IS_DIRECTORY_SEP(*path)) {
		path++;
	}

	path_out = talloc_strdup(ctx, path);
	if (!path_out) {
		return NULL;
	}

	p1 = strchr_m(path_out, '*');
	p2 = strchr_m(path_out, '?');

	if (p1 || p2) {
		if (p1 && p2) {
			p = MIN(p1,p2);
		} else if (!p1) {
			p = p2;
		} else {
			p = p1;
		}
		*p = '\0';

		/* Now go back to the start of this component. */
		p1 = strrchr_m(path_out, '/');
		p2 = strrchr_m(path_out, '\\');
		p = MAX(p1,p2);
		if (p) {
			*p = '\0';
		}
	}

	/* Strip any trailing separator */

	len = strlen(path_out);
	if ( (len > 0) && IS_DIRECTORY_SEP(path_out[len-1])) {
		path_out[len-1] = '\0';
	}

	return path_out;
}

/****************************************************************************
****************************************************************************/

static char *cli_dfs_make_full_path(TALLOC_CTX *ctx,
					struct cli_state *cli,
					const char *dir)
{
	char path_sep = '\\';

	/* Ensure the extrapath doesn't start with a separator. */
	while (IS_DIRECTORY_SEP(*dir)) {
		dir++;
	}

	if (cli->requested_posix_capabilities & CIFS_UNIX_POSIX_PATHNAMES_CAP) {
		path_sep = '/';
	}
	return talloc_asprintf(ctx, "%c%s%c%s%c%s",
			path_sep,
			smbXcli_conn_remote_name(cli->conn),
			path_sep,
			cli->share,
			path_sep,
			dir);
}

/********************************************************************
 check for dfs referral
********************************************************************/

static bool cli_dfs_check_error(struct cli_state *cli, NTSTATUS expected,
				NTSTATUS status)
{
	/* only deal with DS when we negotiated NT_STATUS codes and UNICODE */

	if (!(smbXcli_conn_use_unicode(cli->conn))) {
		return false;
	}
	if (!(smb1cli_conn_capabilities(cli->conn) & CAP_STATUS32)) {
		return false;
	}
	if (NT_STATUS_EQUAL(status, expected)) {
		return true;
	}
	return false;
}

/********************************************************************
 Get the dfs referral link.
********************************************************************/

NTSTATUS cli_dfs_get_referral_ex(TALLOC_CTX *ctx,
			struct cli_state *cli,
			const char *path,
			uint16_t max_referral_level,
			struct client_dfs_referral **refs,
			size_t *num_refs,
			size_t *consumed)
{
	unsigned int param_len = 0;
	uint16_t recv_flags2;
	uint8_t *param = NULL;
	uint8_t *rdata = NULL;
	char *p;
	char *endp;
	smb_ucs2_t *path_ucs;
	char *consumed_path = NULL;
	uint16_t consumed_ucs;
	uint16_t num_referrals;
	struct client_dfs_referral *referrals = NULL;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	*num_refs = 0;
	*refs = NULL;

	param = talloc_array(talloc_tos(), uint8_t, 2);
	if (!param) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	SSVAL(param, 0, max_referral_level);

	param = trans2_bytes_push_str(param, smbXcli_conn_use_unicode(cli->conn),
				      path, strlen(path)+1,
				      NULL);
	if (!param) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	param_len = talloc_get_size(param);
	path_ucs = (smb_ucs2_t *)&param[2];

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		DATA_BLOB in_input_buffer;
		DATA_BLOB in_output_buffer = data_blob_null;
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;

		in_input_buffer.data = param;
		in_input_buffer.length = param_len;

		status = smb2cli_ioctl(cli->conn,
				       cli->timeout,
				       cli->smb2.session,
				       cli->smb2.tcon,
				       UINT64_MAX, /* in_fid_persistent */
				       UINT64_MAX, /* in_fid_volatile */
				       FSCTL_DFS_GET_REFERRALS,
				       0, /* in_max_input_length */
				       &in_input_buffer,
				       CLI_BUFFER_SIZE, /* in_max_output_length */
				       &in_output_buffer,
				       SMB2_IOCTL_FLAG_IS_FSCTL,
				       talloc_tos(),
				       &out_input_buffer,
				       &out_output_buffer);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		if (out_output_buffer.length < 4) {
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			goto out;
		}

		recv_flags2 = FLAGS2_UNICODE_STRINGS;
		rdata = out_output_buffer.data;
		endp = (char *)rdata + out_output_buffer.length;
	} else {
		unsigned int data_len = 0;
		uint16_t setup[1];

		SSVAL(setup, 0, TRANSACT2_GET_DFS_REFERRAL);

		status = cli_trans(talloc_tos(), cli, SMBtrans2,
				   NULL, 0xffff, 0, 0,
				   setup, 1, 0,
				   param, param_len, 2,
				   NULL, 0, CLI_BUFFER_SIZE,
				   &recv_flags2,
				   NULL, 0, NULL, /* rsetup */
				   NULL, 0, NULL,
				   &rdata, 4, &data_len);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		endp = (char *)rdata + data_len;
	}

	consumed_ucs  = SVAL(rdata, 0);
	num_referrals = SVAL(rdata, 2);

	/* consumed_ucs is the number of bytes
	 * of the UCS2 path consumed not counting any
	 * terminating null. We need to convert
	 * back to unix charset and count again
	 * to get the number of bytes consumed from
	 * the incoming path. */

	errno = 0;
	if (pull_string_talloc(talloc_tos(),
			NULL,
			0,
			&consumed_path,
			path_ucs,
			consumed_ucs,
			STR_UNICODE) == 0) {
		if (errno != 0) {
			status = map_nt_error_from_unix(errno);
		} else {
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		goto out;
	}
	if (consumed_path == NULL) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}
	*consumed = strlen(consumed_path);

	if (num_referrals != 0) {
		uint16_t ref_version;
		uint16_t ref_size;
		int i;
		uint16_t node_offset;

		referrals = talloc_array(ctx, struct client_dfs_referral,
					 num_referrals);

		if (!referrals) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		/* start at the referrals array */

		p = (char *)rdata+8;
		for (i=0; i<num_referrals && p < endp; i++) {
			if (p + 18 > endp) {
				goto out;
			}
			ref_version = SVAL(p, 0);
			ref_size    = SVAL(p, 2);
			node_offset = SVAL(p, 16);

			if (ref_version != 3) {
				p += ref_size;
				continue;
			}

			referrals[i].proximity = SVAL(p, 8);
			referrals[i].ttl       = SVAL(p, 10);

			if (p + node_offset > endp) {
				status = NT_STATUS_INVALID_NETWORK_RESPONSE;
				goto out;
			}
			pull_string_talloc(referrals,
					   (const char *)rdata,
					   recv_flags2,
					   &referrals[i].dfspath,
					   p+node_offset,
					   PTR_DIFF(endp, p+node_offset),
					   STR_TERMINATE|STR_UNICODE);

			if (!referrals[i].dfspath) {
				status = map_nt_error_from_unix(errno);
				goto out;
			}
			p += ref_size;
		}
		if (i < num_referrals) {
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			goto out;
		}
	}

	*num_refs = num_referrals;
	*refs = referrals;

  out:

	TALLOC_FREE(frame);
	return status;
}

NTSTATUS cli_dfs_get_referral(TALLOC_CTX *ctx,
			struct cli_state *cli,
			const char *path,
			struct client_dfs_referral **refs,
			size_t *num_refs,
			size_t *consumed)
{
	return cli_dfs_get_referral_ex(ctx,
				cli,
				path,
				3,
				refs, /* Max referral level we want */
				num_refs,
				consumed);
}

/********************************************************************
********************************************************************/
struct cli_dfs_path_split {
	char *server;
	char *share;
	char *extrapath;
};

NTSTATUS cli_resolve_path(TALLOC_CTX *ctx,
			  const char *mountpt,
			  const struct user_auth_info *dfs_auth_info,
			  struct cli_state *rootcli,
			  const char *path,
			  struct cli_state **targetcli,
			  char **pp_targetpath)
{
	struct client_dfs_referral *refs = NULL;
	size_t num_refs = 0;
	size_t consumed = 0;
	struct cli_state *cli_ipc = NULL;
	char *dfs_path = NULL;
	char *cleanpath = NULL;
	char *extrapath = NULL;
	int pathlen;
	struct cli_state *newcli = NULL;
	struct cli_state *ccli = NULL;
	size_t count = 0;
	char *newpath = NULL;
	char *newmount = NULL;
	char *ppath = NULL;
	SMB_STRUCT_STAT sbuf;
	uint32_t attributes;
	NTSTATUS status;
	struct smbXcli_tcon *root_tcon = NULL;
	struct smbXcli_tcon *target_tcon = NULL;
	struct cli_dfs_path_split *dfs_refs = NULL;

	if ( !rootcli || !path || !targetcli ) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Don't do anything if this is not a DFS root. */

	if (smbXcli_conn_protocol(rootcli->conn) >= PROTOCOL_SMB2_02) {
		root_tcon = rootcli->smb2.tcon;
	} else {
		root_tcon = rootcli->smb1.tcon;
	}

	/*
	 * Avoid more than one leading directory separator
	 */
	while (IS_DIRECTORY_SEP(path[0]) && IS_DIRECTORY_SEP(path[1])) {
		path++;
	}

	if (!smbXcli_tcon_is_dfs_share(root_tcon)) {
		*targetcli = rootcli;
		*pp_targetpath = talloc_strdup(ctx, path);
		if (!*pp_targetpath) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}

	*targetcli = NULL;

	/* Send a trans2_query_path_info to check for a referral. */

	cleanpath = clean_path(ctx, path);
	if (!cleanpath) {
		return NT_STATUS_NO_MEMORY;
	}

	dfs_path = cli_dfs_make_full_path(ctx, rootcli, cleanpath);
	if (!dfs_path) {
		return NT_STATUS_NO_MEMORY;
	}

	status = cli_qpathinfo_basic( rootcli, dfs_path, &sbuf, &attributes);
	if (NT_STATUS_IS_OK(status)) {
		/* This is an ordinary path, just return it. */
		*targetcli = rootcli;
		*pp_targetpath = talloc_strdup(ctx, path);
		if (!*pp_targetpath) {
			return NT_STATUS_NO_MEMORY;
		}
		goto done;
	}

	/* Special case where client asked for a path that does not exist */

	if (cli_dfs_check_error(rootcli, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				status)) {
		*targetcli = rootcli;
		*pp_targetpath = talloc_strdup(ctx, path);
		if (!*pp_targetpath) {
			return NT_STATUS_NO_MEMORY;
		}
		goto done;
	}

	/* We got an error, check for DFS referral. */

	if (!cli_dfs_check_error(rootcli, NT_STATUS_PATH_NOT_COVERED,
				 status)) {
		return status;
	}

	/* Check for the referral. */

	status = cli_cm_open(ctx,
			     rootcli,
			     smbXcli_conn_remote_name(rootcli->conn),
			     "IPC$",
			     dfs_auth_info,
			     cli_state_is_encryption_on(rootcli),
			     smbXcli_conn_protocol(rootcli->conn),
			     NULL, /* dest_ss not needed, we reuse the transport */
			     0,
			     0x20,
			     &cli_ipc);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = cli_dfs_get_referral(ctx, cli_ipc, dfs_path, &refs,
				      &num_refs, &consumed);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!num_refs || !refs[0].dfspath) {
		return NT_STATUS_NOT_FOUND;
	}

	/*
	 * Bug#10123 - DFS referal entries can be provided in a random order,
	 * so check the connection cache for each item to avoid unnecessary
	 * reconnections.
	 */
	dfs_refs = talloc_array(ctx, struct cli_dfs_path_split, num_refs);
	if (dfs_refs == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (count = 0; count < num_refs; count++) {
		if (!split_dfs_path(dfs_refs, refs[count].dfspath,
				    &dfs_refs[count].server,
				    &dfs_refs[count].share,
				    &dfs_refs[count].extrapath)) {
			TALLOC_FREE(dfs_refs);
			return NT_STATUS_NOT_FOUND;
		}

		ccli = cli_cm_find(rootcli, dfs_refs[count].server,
				   dfs_refs[count].share);
		if (ccli != NULL) {
			extrapath = dfs_refs[count].extrapath;
			*targetcli = ccli;
			break;
		}
	}

	/*
	 * If no cached connection was found, then connect to the first live
	 * referral server in the list.
	 */
	for (count = 0; (ccli == NULL) && (count < num_refs); count++) {
		/* Connect to the target server & share */
		status = cli_cm_connect(ctx, rootcli,
				dfs_refs[count].server,
				dfs_refs[count].share,
				dfs_auth_info,
				cli_state_is_encryption_on(rootcli),
				smbXcli_conn_protocol(rootcli->conn),
				NULL, /* dest_ss */
				0, /* port */
				0x20,
				targetcli);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Unable to follow dfs referral [\\%s\\%s]\n",
				 dfs_refs[count].server,
				 dfs_refs[count].share);
			continue;
		} else {
			extrapath = dfs_refs[count].extrapath;
			break;
		}
	}

	/* No available referral server for the connection */
	if (*targetcli == NULL) {
		TALLOC_FREE(dfs_refs);
		return status;
	}

	/* Make sure to recreate the original string including any wildcards. */

	dfs_path = cli_dfs_make_full_path(ctx, rootcli, path);
	if (!dfs_path) {
		TALLOC_FREE(dfs_refs);
		return NT_STATUS_NO_MEMORY;
	}
	pathlen = strlen(dfs_path);
	consumed = MIN(pathlen, consumed);
	*pp_targetpath = talloc_strdup(ctx, &dfs_path[consumed]);
	if (!*pp_targetpath) {
		TALLOC_FREE(dfs_refs);
		return NT_STATUS_NO_MEMORY;
	}
	dfs_path[consumed] = '\0';

	/*
 	 * *pp_targetpath is now the unconsumed part of the path.
 	 * dfs_path is now the consumed part of the path
	 * (in \server\share\path format).
 	 */

	if (extrapath && strlen(extrapath) > 0) {
		/* EMC Celerra NAS version 5.6.50 (at least) doesn't appear to */
		/* put the trailing \ on the path, so to be save we put one in if needed */
		if (extrapath[strlen(extrapath)-1] != '\\' && **pp_targetpath != '\\') {
			*pp_targetpath = talloc_asprintf(ctx,
						  "%s\\%s",
						  extrapath,
						  *pp_targetpath);
		} else {
			*pp_targetpath = talloc_asprintf(ctx,
						  "%s%s",
						  extrapath,
						  *pp_targetpath);
		}
		if (!*pp_targetpath) {
			TALLOC_FREE(dfs_refs);
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* parse out the consumed mount path */
	/* trim off the \server\share\ */

	ppath = dfs_path;

	if (*ppath != '\\') {
		d_printf("cli_resolve_path: "
			"dfs_path (%s) not in correct format.\n",
			dfs_path );
		TALLOC_FREE(dfs_refs);
		return NT_STATUS_NOT_FOUND;
	}

	ppath++; /* Now pointing at start of server name. */

	if ((ppath = strchr_m( dfs_path, '\\' )) == NULL) {
		TALLOC_FREE(dfs_refs);
		return NT_STATUS_NOT_FOUND;
	}

	ppath++; /* Now pointing at start of share name. */

	if ((ppath = strchr_m( ppath+1, '\\' )) == NULL) {
		TALLOC_FREE(dfs_refs);
		return NT_STATUS_NOT_FOUND;
	}

	ppath++; /* Now pointing at path component. */

	newmount = talloc_asprintf(ctx, "%s\\%s", mountpt, ppath );
	if (!newmount) {
		TALLOC_FREE(dfs_refs);
		return NT_STATUS_NOT_FOUND;
	}

	cli_set_mntpoint(*targetcli, newmount);

	/* Check for another dfs referral, note that we are not
	   checking for loops here. */

	if (!strequal(*pp_targetpath, "\\") && !strequal(*pp_targetpath, "/")) {
		status = cli_resolve_path(ctx,
					  newmount,
					  dfs_auth_info,
					  *targetcli,
					  *pp_targetpath,
					  &newcli,
					  &newpath);
		if (NT_STATUS_IS_OK(status)) {
			/*
			 * When cli_resolve_path returns true here it's always
 			 * returning the complete path in newpath, so we're done
 			 * here.
 			 */
			*targetcli = newcli;
			*pp_targetpath = newpath;
			TALLOC_FREE(dfs_refs);
			return status;
		}
	}

  done:

	if (smbXcli_conn_protocol((*targetcli)->conn) >= PROTOCOL_SMB2_02) {
		target_tcon = (*targetcli)->smb2.tcon;
	} else {
		target_tcon = (*targetcli)->smb1.tcon;
	}

	/* If returning true ensure we return a dfs root full path. */
	if (smbXcli_tcon_is_dfs_share(target_tcon)) {
		dfs_path = talloc_strdup(ctx, *pp_targetpath);
		if (!dfs_path) {
			TALLOC_FREE(dfs_refs);
			return NT_STATUS_NO_MEMORY;
		}
		*pp_targetpath = cli_dfs_make_full_path(ctx, *targetcli, dfs_path);
		if (*pp_targetpath == NULL) {
			TALLOC_FREE(dfs_refs);
			return NT_STATUS_NO_MEMORY;
		}
	}

	TALLOC_FREE(dfs_refs);
	return NT_STATUS_OK;
}

/********************************************************************
********************************************************************/

bool cli_check_msdfs_proxy(TALLOC_CTX *ctx,
				struct cli_state *cli,
				const char *sharename,
				char **pp_newserver,
				char **pp_newshare,
				bool force_encrypt,
				struct cli_credentials *creds)
{
	struct client_dfs_referral *refs = NULL;
	size_t num_refs = 0;
	size_t consumed = 0;
	char *fullpath = NULL;
	bool res;
	struct smbXcli_tcon *orig_tcon = NULL;
	char *newextrapath = NULL;
	NTSTATUS status;
	const char *remote_name;

	if (!cli || !sharename) {
		return false;
	}

	remote_name = smbXcli_conn_remote_name(cli->conn);

	/* special case.  never check for a referral on the IPC$ share */

	if (strequal(sharename, "IPC$")) {
		return false;
	}

	/* send a trans2_query_path_info to check for a referral */

	fullpath = talloc_asprintf(ctx, "\\%s\\%s", remote_name, sharename);
	if (!fullpath) {
		return false;
	}

	/* Store tcon state. */
	if (cli_state_has_tcon(cli)) {
		orig_tcon = cli_state_save_tcon(cli);
		if (orig_tcon == NULL) {
			return false;
		}
	}

	/* check for the referral */

	if (!NT_STATUS_IS_OK(cli_tree_connect(cli, "IPC$", "IPC", NULL))) {
		cli_state_restore_tcon(cli, orig_tcon);
		return false;
	}

	if (force_encrypt) {
		status = cli_cm_force_encryption_creds(cli, creds, "IPC$");
		if (!NT_STATUS_IS_OK(status)) {
			cli_tdis(cli);
			cli_state_restore_tcon(cli, orig_tcon);
			return false;
		}
	}

	status = cli_dfs_get_referral(ctx, cli, fullpath, &refs,
				      &num_refs, &consumed);
	res = NT_STATUS_IS_OK(status);

	status = cli_tdis(cli);

	cli_state_restore_tcon(cli, orig_tcon);

	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (!res || !num_refs) {
		return false;
	}

	if (!refs[0].dfspath) {
		return false;
	}

	if (!split_dfs_path(ctx, refs[0].dfspath, pp_newserver,
			    pp_newshare, &newextrapath)) {
		return false;
	}

	/* check that this is not a self-referral */

	if (strequal(remote_name, *pp_newserver) &&
			strequal(sharename, *pp_newshare)) {
		return false;
	}

	return true;
}
