/*
   Unix SMB/CIFS implementation.
   SMB client password change routine
   Copyright (C) Andrew Tridgell 1994-1998

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
#include "../librpc/gen_ndr/ndr_samr.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_client/cli_samr.h"
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "libsmb/clirap.h"
#include "libsmb/nmblib.h"
#include "../libcli/smb/smbXcli_base.h"

/*************************************************************
 Change a password on a remote machine using IPC calls.
*************************************************************/

NTSTATUS remote_password_change(const char *remote_machine,
				const char *domain, const char *user_name,
				const char *old_passwd, const char *new_passwd,
				char **err_str)
{
	struct cli_state *cli = NULL;
	struct cli_credentials *creds = NULL;
	struct rpc_pipe_client *pipe_hnd = NULL;
	NTSTATUS status;
	NTSTATUS result;
	bool pass_must_change = False;
	struct smb_transports ts =
		smb_transports_parse("client smb transports",
				     lp_client_smb_transports());

	*err_str = NULL;

	result = cli_connect_nb(talloc_tos(),
				remote_machine,
				NULL,
				&ts,
				0x20,
				NULL,
				SMB_SIGNING_IPC_DEFAULT,
				0,
				&cli);
	if (!NT_STATUS_IS_OK(result)) {
		if (NT_STATUS_EQUAL(result, NT_STATUS_NOT_SUPPORTED)) {
			if (asprintf(err_str, "Unable to connect to SMB server on "
				"machine %s. NetBIOS support disabled\n",
				remote_machine) == -1) {
				*err_str = NULL;
			}
		} else {
			if (asprintf(err_str, "Unable to connect to SMB server on "
				 "machine %s. Error was : %s.\n",
				 remote_machine, nt_errstr(result))==-1) {
				*err_str = NULL;
			}
		}
		return result;
	}

	creds = cli_session_creds_init(cli,
				       user_name,
				       domain,
				       NULL, /* realm */
				       old_passwd,
				       false, /* use_kerberos */
				       false, /* fallback_after_kerberos */
				       false, /* use_ccache */
				       false); /* password_is_nt_hash */
	SMB_ASSERT(creds != NULL);

	result = smbXcli_negprot(cli->conn,
				 cli->timeout,
				 lp_client_ipc_min_protocol(),
				 lp_client_ipc_max_protocol(),
				 NULL,
				 NULL,
				 NULL);

	if (!NT_STATUS_IS_OK(result)) {
		if (asprintf(err_str, "machine %s rejected the negotiate "
			 "protocol. Error was : %s.\n",
			 remote_machine, nt_errstr(result)) == -1) {
			*err_str = NULL;
		}
		cli_shutdown(cli);
		return result;
	}

	/* Given things like SMB signing, restrict anonymous and the like,
	   try an authenticated connection first */
	result = cli_session_setup_creds(cli, creds);

	if (!NT_STATUS_IS_OK(result)) {

		/* Password must change or Password expired are the only valid
		 * error conditions here from where we can proceed, the rest like
		 * account locked out or logon failure will lead to errors later
		 * anyway */

		if (!NT_STATUS_EQUAL(result, NT_STATUS_PASSWORD_MUST_CHANGE) &&
		    !NT_STATUS_EQUAL(result, NT_STATUS_PASSWORD_EXPIRED)) {
			if (asprintf(err_str, "Could not connect to machine %s: "
				 "%s\n", remote_machine, nt_errstr(result)) == -1) {
				*err_str = NULL;
			}
			cli_shutdown(cli);
			return result;
		}

		pass_must_change = True;

		/*
		 * We should connect as the anonymous user here, in case
		 * the server has "must change password" checked...
		 * Thanks to <Nicholas.S.Jenkins@cdc.com> for this fix.
		 */

		result = cli_session_setup_anon(cli);

		if (!NT_STATUS_IS_OK(result)) {
			if (asprintf(err_str, "machine %s rejected the session "
				 "setup. Error was : %s.\n",
				 remote_machine, nt_errstr(result)) == -1) {
				*err_str = NULL;
			}
			cli_shutdown(cli);
			return result;
		}
	}

	result = cli_tree_connect(cli, "IPC$", "IPC", NULL);
	if (!NT_STATUS_IS_OK(result)) {
		if (asprintf(err_str, "machine %s rejected the tconX on the "
			     "IPC$ share. Error was : %s.\n",
			     remote_machine, nt_errstr(result))) {
			*err_str = NULL;
		}
		cli_shutdown(cli);
		return result;
	}

	/* Try not to give the password away too easily */

	if (!pass_must_change) {
		const struct sockaddr_storage *remote_sockaddr =
			smbXcli_conn_remote_sockaddr(cli->conn);

		result = cli_rpc_pipe_open_with_creds(cli,
						      &ndr_table_samr,
						      NCACN_NP,
						      DCERPC_AUTH_TYPE_NTLMSSP,
						      DCERPC_AUTH_LEVEL_PRIVACY,
						      NULL, /* target_service */
						      remote_machine,
						      remote_sockaddr,
						      creds,
						      &pipe_hnd);
	} else {
		/*
		 * If the user password must be changed the ntlmssp bind will
		 * fail the same way as the session setup above did. The
		 * difference is that with a pipe bind we don't get a good
		 * error message, the result will be that the rpc call below
		 * will just fail. So we do it anonymously, there's no other
		 * way.
		 */
		result = cli_rpc_pipe_open_noauth(
			cli, &ndr_table_samr, &pipe_hnd);
	}

	if (!NT_STATUS_IS_OK(result)) {
		if (lp_client_lanman_auth()) {
			/* Use the old RAP method. */
			result = cli_oem_change_password(cli,
							 user_name,
							 new_passwd,
							 old_passwd);
			if (!NT_STATUS_IS_OK(result)) {
				if (asprintf(err_str, "machine %s rejected the "
					 "password change: Error was : %s.\n",
					 remote_machine, nt_errstr(result)) == -1) {
					*err_str = NULL;
				}
				cli_shutdown(cli);
				return result;
			}
		} else {
			if (asprintf(err_str, "SAMR connection to machine %s "
				 "failed. Error was %s, but LANMAN password "
				 "changes are disabled\n",
				 remote_machine, nt_errstr(result)) == -1) {
				*err_str = NULL;
			}
			cli_shutdown(cli);
			return result;
		}
	}

	status = dcerpc_samr_chgpasswd_user4(pipe_hnd->binding_handle,
					     talloc_tos(),
					     pipe_hnd->srv_name_slash,
					     user_name,
					     old_passwd,
					     new_passwd,
					     &result);
	if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(result)) {
		/* All good, password successfully changed. */
		cli_shutdown(cli);
		return NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,
				    NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
			/* DO NOT FALLBACK TO RC4 */
			if (lp_weak_crypto() == SAMBA_WEAK_CRYPTO_DISALLOWED) {
				cli_shutdown(cli);
				return NT_STATUS_STRONG_CRYPTO_NOT_SUPPORTED;
			}
		}
	} else {
		if (!NT_STATUS_IS_OK(result)) {
			int rc = asprintf(
				err_str,
				"machine %s rejected to change the password "
				"with error: %s\n",
				remote_machine,
				get_friendly_nt_error_msg(result));
			if (rc <= 0) {
				*err_str = NULL;
			}
			cli_shutdown(cli);
			return result;
		}
	}

	result = rpccli_samr_chgpasswd_user2(pipe_hnd, talloc_tos(),
					     user_name, new_passwd, old_passwd);
	if (NT_STATUS_IS_OK(result)) {
		/* Great - it all worked! */
		cli_shutdown(cli);
		return NT_STATUS_OK;
	}

	if (!(NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED) ||
	      NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)))
	{
		/* it failed, but for reasons such as wrong password, too short etc ... */

		if (asprintf(err_str, "machine %s rejected the password change: "
			 "Error was : %s.\n",
			 remote_machine, get_friendly_nt_error_msg(result)) == -1) {
			*err_str = NULL;
		}
		cli_shutdown(cli);
		return result;
	}

	/* OK, that failed, so try again... */
	TALLOC_FREE(pipe_hnd);

	/* OK, this is ugly, but... try an anonymous pipe. */
	result = cli_rpc_pipe_open_noauth(cli, &ndr_table_samr,
					  &pipe_hnd);

	if ( NT_STATUS_IS_OK(result) &&
		(NT_STATUS_IS_OK(result = rpccli_samr_chgpasswd_user2(
					 pipe_hnd, talloc_tos(), user_name,
					 new_passwd, old_passwd)))) {
		/* Great - it all worked! */
		cli_shutdown(cli);
		return NT_STATUS_OK;
	} else {
		if (!(NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED)
		      || NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL))) {
			/* it failed, but again it was due to things like new password too short */

			if (asprintf(err_str, "machine %s rejected the "
				 "(anonymous) password change: Error was : "
				 "%s.\n", remote_machine,
				 get_friendly_nt_error_msg(result)) == -1) {
				*err_str = NULL;
			}
			cli_shutdown(cli);
			return result;
		}

		/* We have failed to change the user's password, and we think the server
		   just might not support SAMR password changes, so fall back */

		if (!lp_client_lanman_auth()) {
			if (asprintf(err_str, "SAMR connection to machine %s "
				 "failed. Error was %s, but LANMAN password "
				 "changes are disabled\n",
				remote_machine, nt_errstr(result)) == -1) {
				*err_str = NULL;
			}
			cli_shutdown(cli);
			return NT_STATUS_UNSUCCESSFUL;
		}

		/* Use the old RAP method. */
		result = cli_oem_change_password(cli,
						 user_name,
						 new_passwd,
						 old_passwd);
		if (NT_STATUS_IS_OK(result)) {
			/* SAMR failed, but the old LanMan protocol worked! */

			cli_shutdown(cli);
			return NT_STATUS_OK;
		}

		if (asprintf(err_str,
			     "machine %s rejected the password "
			     "change: Error was : %s.\n",
			     remote_machine,
			     nt_errstr(result)) == -1)
		{
			*err_str = NULL;
		}
		cli_shutdown(cli);
		return result;
	}
}
