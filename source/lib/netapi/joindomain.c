/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Join Support
 *  Copyright (C) Guenther Deschner 2007
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "lib/netapi/joindomain.h"

extern const char *opt_user_name;
extern const char *opt_workgroup;
extern const char *opt_password;

static WERROR NetJoinDomainLocal(TALLOC_CTX *mem_ctx,
				 const char *server_name,
				 const char *domain_name,
				 const char *account_ou,
				 const char *Account,
				 const char *password,
				 uint32_t join_flags)
{
	return WERR_NOT_SUPPORTED;
}

static WERROR NetJoinDomainRemote(TALLOC_CTX *mem_ctx,
				  const char *server_name,
				  const char *domain_name,
				  const char *account_ou,
				  const char *Account,
				  const char *password,
				  uint32_t join_flags)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	struct wkssvc_PasswordBuffer encrypted_password;
	NTSTATUS status;
	WERROR werr;
	unsigned int old_timeout = 0;

	ZERO_STRUCT(encrypted_password);

	status = cli_full_connection(&cli, NULL, server_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     opt_user_name, opt_workgroup,
				     opt_password, 0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	old_timeout = cli_set_timeout(cli, 60000);

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_WKSSVC,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	};

	if (password) {
		encode_wkssvc_join_password_buffer(mem_ctx,
						   password,
						   &cli->user_session_key,
						   &encrypted_password);
	}

	old_timeout = cli_set_timeout(cli, 60000);

	status = rpccli_wkssvc_NetrJoinDomain2(pipe_cli, mem_ctx,
					       server_name, domain_name,
					       account_ou, Account,
					       &encrypted_password,
					       join_flags, &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (cli) {
		cli_set_timeout(cli, old_timeout);
		cli_shutdown(cli);
	}

	return werr;
}

WERROR NetJoinDomain(const char *server_name,
		     const char *domain_name,
		     const char *account_ou,
		     const char *Account,
		     const char *password,
		     uint32_t join_flags)
{
	TALLOC_CTX *mem_ctx = NULL;
	WERROR werr;

	mem_ctx = talloc_init("NetJoinDomain");
	if (!mem_ctx) {
		werr = WERR_NOMEM;
		goto done;
	}

	if (!domain_name) {
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	if (!server_name || is_myname_or_ipaddr(server_name)) {

		const char *dc = NULL;

		/* FIXME: DsGetDcName */
		if (server_name == NULL) {
			dc = domain_name;
		} else {
			dc = domain_name;
		}

		werr = NetJoinDomainLocal(mem_ctx,
					  dc,
					  domain_name,
					  account_ou,
					  Account,
					  password,
					  join_flags);

		goto done;
	}

	werr = NetJoinDomainRemote(mem_ctx,
				   server_name,
				   domain_name,
				   account_ou,
				   Account,
				   password,
				   join_flags);
done:
	TALLOC_FREE(mem_ctx);

	return werr;
}

WERROR NetUnjoinDomain(const char *server_name,
		       const char *account,
		       const char *password,
		       uint32_t unjoin_flags)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	struct wkssvc_PasswordBuffer encrypted_password;
	NTSTATUS status;
	WERROR werr;
	unsigned int old_timeout = 0;

	ZERO_STRUCT(encrypted_password);

	mem_ctx = talloc_init("NetUnjoinDomain");
	if (!mem_ctx) {
		werr = WERR_NOMEM;
		goto done;
	}

	if (!server_name || is_myname_or_ipaddr(server_name)) {
		werr = WERR_NOT_SUPPORTED;
		goto done;
	}

	status = cli_full_connection(&cli, NULL, server_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     opt_user_name, opt_workgroup,
				     opt_password, 0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	old_timeout = cli_set_timeout(cli, 60000);

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_WKSSVC,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	};

	if (password) {
		encode_wkssvc_join_password_buffer(mem_ctx,
						   password,
						   &cli->user_session_key,
						   &encrypted_password);
	}

	old_timeout = cli_set_timeout(cli, 60000);

	status = rpccli_wkssvc_NetrUnjoinDomain2(pipe_cli, mem_ctx,
						 server_name,
						 account,
						 &encrypted_password,
						 unjoin_flags,
						 &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (cli) {
		cli_set_timeout(cli, old_timeout);
		cli_shutdown(cli);
	}
	TALLOC_FREE(mem_ctx);

	return werr;
}

WERROR NetGetJoinInformation(const char *server_name,
			     const char **name_buffer,
			     uint16_t *name_type)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;

	mem_ctx = talloc_init("NetGetJoinInformation");
	if (!mem_ctx) {
		werr = WERR_NOMEM;
		goto done;
	}

	status = cli_full_connection(&cli, NULL, server_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     opt_user_name, opt_workgroup,
				     opt_password, 0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_WKSSVC,
					    &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	};

	status = rpccli_wkssvc_NetrGetJoinInformation(pipe_cli, mem_ctx,
						      server_name,
						      name_buffer,
						      (enum wkssvc_NetJoinStatus *)name_type,
						      &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (cli) {
		cli_shutdown(cli);
	}
	TALLOC_FREE(mem_ctx);

	return werr;
}
