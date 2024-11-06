/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Tim Potter 2000-2001
   Copyright (C) Martin Pool 2003

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
#include "../libcli/auth/netlogon_creds_cli.h"
#include "rpcclient.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/ndr_lsa_c.h"
#include "rpc_client/cli_lsarpc.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "rpc_client/cli_netlogon.h"
#include "../libcli/smbreadline/smbreadline.h"
#include "../libcli/security/security.h"
#include "passdb.h"
#include "libsmb/libsmb.h"
#include "auth/gensec/gensec.h"
#include "../libcli/smb/smbXcli_base.h"
#include "messages.h"
#include "cmdline_contexts.h"
#include "../librpc/gen_ndr/ndr_samr.h"
#include "lib/cmdline/cmdline.h"
#include "lib/param/param.h"

enum pipe_auth_type_spnego {
	PIPE_AUTH_TYPE_SPNEGO_NONE = 0,
	PIPE_AUTH_TYPE_SPNEGO_NTLMSSP,
	PIPE_AUTH_TYPE_SPNEGO_KRB5
};

static unsigned int timeout = 10000;

struct messaging_context *rpcclient_msg_ctx;
struct netlogon_creds_cli_context *rpcclient_netlogon_creds;
static const char *rpcclient_netlogon_domain;

/* List to hold groups of commands.
 *
 * Commands are defined in a list of arrays: arrays are easy to
 * statically declare, and lists are easier to dynamically extend.
 */

static struct cmd_list {
	struct cmd_list *prev, *next;
	struct cmd_set *cmd_set;
} *cmd_list;

/****************************************************************************
handle completion of commands for readline
****************************************************************************/
static char **completion_fn(const char *text, int start, int end)
{
#define MAX_COMPLETIONS 1000
	char **matches;
	size_t i, count=0;
	struct cmd_list *commands = cmd_list;

#if 0	/* JERRY */
	/* FIXME!!!  -- what to do when completing argument? */
	/* for words not at the start of the line fallback
	   to filename completion */
	if (start)
		return NULL;
#endif

	/* make sure we have a list of valid commands */
	if (!commands) {
		return NULL;
	}

	matches = SMB_MALLOC_ARRAY(char *, MAX_COMPLETIONS);
	if (!matches) {
		return NULL;
	}

	matches[count++] = SMB_STRDUP(text);
	if (!matches[0]) {
		SAFE_FREE(matches);
		return NULL;
	}

	while (commands && count < MAX_COMPLETIONS-1) {
		if (!commands->cmd_set) {
			break;
		}

		for (i=0; commands->cmd_set[i].name; i++) {
			if ((strncmp(text, commands->cmd_set[i].name, strlen(text)) == 0) &&
				(( commands->cmd_set[i].returntype == RPC_RTYPE_NTSTATUS &&
                        commands->cmd_set[i].ntfn ) ||
                      ( commands->cmd_set[i].returntype == RPC_RTYPE_WERROR &&
                        commands->cmd_set[i].wfn))) {
				matches[count] = SMB_STRDUP(commands->cmd_set[i].name);
				if (!matches[count]) {
					for (i = 0; i < count; i++) {
						SAFE_FREE(matches[count]);
					}
					SAFE_FREE(matches);
					return NULL;
				}
				count++;
			}
		}
		commands = commands->next;
	}

	if (count == 2) {
		SAFE_FREE(matches[0]);
		matches[0] = SMB_STRDUP(matches[1]);
	}
	matches[count] = NULL;
	return matches;
}

static char *next_command (char **cmdstr)
{
	char *command;
	char			*p;

	if (!cmdstr || !(*cmdstr))
		return NULL;

	p = strchr_m(*cmdstr, ';');
	if (p)
		*p = '\0';
	command = SMB_STRDUP(*cmdstr);
	if (p)
		*cmdstr = p + 1;
	else
		*cmdstr = NULL;

	return command;
}

static void binding_get_auth_info(
	const struct dcerpc_binding *b,
	enum dcerpc_AuthType *_auth_type,
	enum dcerpc_AuthLevel *_auth_level,
	enum credentials_use_kerberos *_krb5_state)
{
	uint32_t bflags = dcerpc_binding_get_flags(b);
	enum dcerpc_AuthLevel auth_level = DCERPC_AUTH_LEVEL_NONE;
	enum dcerpc_AuthType auth_type = DCERPC_AUTH_TYPE_NONE;
	enum credentials_use_kerberos krb5_state = CRED_USE_KERBEROS_DESIRED;

	if (_krb5_state != NULL) {
		krb5_state = *_krb5_state;
	}

	if (bflags & DCERPC_CONNECT) {
		auth_level = DCERPC_AUTH_LEVEL_CONNECT;
	}
	if (bflags & DCERPC_PACKET) {
		auth_level = DCERPC_AUTH_LEVEL_PACKET;
	}
	if (bflags & DCERPC_SIGN) {
		auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	}
	if (bflags & DCERPC_SEAL) {
		auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	}

	if (bflags & DCERPC_SCHANNEL) {
		auth_type = DCERPC_AUTH_TYPE_SCHANNEL;
	}

	if ((auth_level != DCERPC_AUTH_LEVEL_NONE) &&
	    (auth_type == DCERPC_AUTH_TYPE_NONE)) {
		auth_type = (krb5_state == CRED_USE_KERBEROS_REQUIRED) ?
			DCERPC_AUTH_TYPE_KRB5 : DCERPC_AUTH_TYPE_NTLMSSP;
	}

	if (bflags & DCERPC_AUTH_SPNEGO) {
		auth_type = DCERPC_AUTH_TYPE_SPNEGO;

		if (bflags & DCERPC_AUTH_NTLM) {
			krb5_state = CRED_USE_KERBEROS_DISABLED;
		}
		if (bflags & DCERPC_AUTH_KRB5) {
			krb5_state = CRED_USE_KERBEROS_REQUIRED;
		}
	}

	if (auth_type != DCERPC_AUTH_TYPE_NONE) {
		/* If nothing is requested then default to integrity */
		if (auth_level == DCERPC_AUTH_LEVEL_NONE) {
			auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
		}
	}

	if (_auth_type != NULL) {
		*_auth_type = auth_type;
	}
	if (_auth_level != NULL) {
		*_auth_level = auth_level;
	}
	if (_krb5_state != NULL) {
		*_krb5_state = krb5_state;
	}
}

/* List the available commands on a given pipe */

static NTSTATUS cmd_listcommands(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				 int argc, const char **argv)
{
	struct cmd_list *tmp;
        struct cmd_set *tmp_set;
	int i;

        /* Usage */

        if (argc != 2) {
                printf("Usage: %s <pipe>\n", argv[0]);
                return NT_STATUS_OK;
        }

        /* Help on one command */

	for (tmp = cmd_list; tmp; tmp = tmp->next)
	{
		tmp_set = tmp->cmd_set;

		if (!strcasecmp_m(argv[1], tmp_set->name))
		{
			printf("Available commands on the %s pipe:\n\n", tmp_set->name);

			i = 0;
			tmp_set++;
			while(tmp_set->name) {
				printf("%30s", tmp_set->name);
                                tmp_set++;
				i++;
				if (i%3 == 0)
					printf("\n");
			}

			/* drop out of the loop */
			break;
		}
        }
	printf("\n\n");

	return NT_STATUS_OK;
}

/* Display help on commands */

static NTSTATUS cmd_help(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                         int argc, const char **argv)
{
	struct cmd_list *tmp;
        struct cmd_set *tmp_set;

        /* Usage */

        if (argc > 2) {
                printf("Usage: %s [command]\n", argv[0]);
                return NT_STATUS_OK;
        }

        /* Help on one command */

        if (argc == 2) {
                for (tmp = cmd_list; tmp; tmp = tmp->next) {

                        tmp_set = tmp->cmd_set;

                        while(tmp_set->name) {
                                if (strequal(argv[1], tmp_set->name)) {
                                        if (tmp_set->usage &&
                                            tmp_set->usage[0])
                                                printf("%s\n", tmp_set->usage);
                                        else
                                                printf("No help for %s\n", tmp_set->name);

                                        return NT_STATUS_OK;
                                }

                                tmp_set++;
                        }
                }

                printf("No such command: %s\n", argv[1]);
                return NT_STATUS_OK;
        }

        /* List all commands */

	for (tmp = cmd_list; tmp; tmp = tmp->next) {

		tmp_set = tmp->cmd_set;

		while(tmp_set->name) {

			printf("%15s\t\t%s\n", tmp_set->name,
			       tmp_set->description ? tmp_set->description:
			       "");

			tmp_set++;
		}
	}

	return NT_STATUS_OK;
}

/* Change the debug level */

static NTSTATUS cmd_debuglevel(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                               int argc, const char **argv)
{
	if (argc > 2) {
		printf("Usage: %s [debuglevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2) {
		struct loadparm_context *lp_ctx = samba_cmdline_get_lp_ctx();
		lpcfg_set_cmdline(lp_ctx, "log level", argv[1]);
	}

	printf("debuglevel is %d\n", DEBUGLEVEL);

	return NT_STATUS_OK;
}

static NTSTATUS cmd_quit(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                         int argc, const char **argv)
{
	exit(0);
	return NT_STATUS_OK; /* NOTREACHED */
}

static NTSTATUS cmd_set_ss_level(struct dcerpc_binding *binding)
{
	struct cmd_list *tmp;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	/* Close any existing connections not at this level. */

	binding_get_auth_info(binding, &auth_type, &auth_level, NULL);

	for (tmp = cmd_list; tmp; tmp = tmp->next) {
        	struct cmd_set *tmp_set;

		for (tmp_set = tmp->cmd_set; tmp_set->name; tmp_set++) {
			struct dcerpc_binding_handle *tmp_b = NULL;
			enum dcerpc_AuthType tmp_auth_type;
			enum dcerpc_AuthLevel tmp_auth_level;

			if (tmp_set->rpc_pipe == NULL) {
				continue;
			}

			tmp_b = tmp_set->rpc_pipe->binding_handle;
			dcerpc_binding_handle_auth_info(tmp_b,
							&tmp_auth_type,
							&tmp_auth_level);

			if (tmp_auth_type != auth_type ||
			    tmp_auth_level != auth_level)
			{
				TALLOC_FREE(tmp_set->rpc_pipe);
			}
		}
	}
	return NT_STATUS_OK;
}

static NTSTATUS cmd_set_transport(struct dcerpc_binding *b)
{
	enum dcerpc_transport_t t = dcerpc_binding_get_transport(b);
	struct cmd_list *tmp;

	/* Close any existing connections not at this level. */

	for (tmp = cmd_list; tmp; tmp = tmp->next) {
		struct cmd_set *tmp_set;

		for (tmp_set = tmp->cmd_set; tmp_set->name; tmp_set++) {
			struct dcerpc_binding_handle *tmp_b = NULL;
			enum dcerpc_transport_t tmp_t;

			if (tmp_set->rpc_pipe == NULL) {
				continue;
			}

			tmp_b = tmp_set->rpc_pipe->binding_handle;
			tmp_t = dcerpc_binding_handle_get_transport(tmp_b);
			if (tmp_t != t) {
				TALLOC_FREE(tmp_set->rpc_pipe);
			}
		}
	}
	return NT_STATUS_OK;
}

static NTSTATUS binding_reset_auth(struct dcerpc_binding *b)
{
	NTSTATUS status = dcerpc_binding_set_flags(
		b,
		0,
		DCERPC_PACKET|
		DCERPC_CONNECT|
		DCERPC_SIGN|
		DCERPC_SEAL|
		DCERPC_SCHANNEL|
		DCERPC_AUTH_SPNEGO|
		DCERPC_AUTH_KRB5|
		DCERPC_AUTH_NTLM);
	return status;
}

static NTSTATUS binding_set_auth(
	struct dcerpc_binding *b, const char *level, const char *type)
{
	NTSTATUS status;

	status = binding_reset_auth(b);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (level != NULL) {
		status = dcerpc_binding_set_string_option(b, level, level);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (strequal(type, "SPNEGO")) {
		status = dcerpc_binding_set_string_option(
			b, "spnego", "spnego");
		return status;
	}
	if (strequal(type, "NTLMSSP")) {
		status = dcerpc_binding_set_string_option(b, "ntlm", "ntlm");
		return status;
	}
	if (strequal(type, "NTLMSSP_SPNEGO")) {
		status = dcerpc_binding_set_string_option(
			b, "spnego", "spnego");
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		status = dcerpc_binding_set_string_option(b, "ntlm", "ntlm");
		return status;
	}
	if (strequal(type, "KRB5")) {
		status = dcerpc_binding_set_string_option(b, "krb5", "krb5");
		return status;
	}
	if (strequal(type, "KRB5_SPNEGO")) {
		status = dcerpc_binding_set_string_option(
			b, "spnego", "spnego");
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		status = dcerpc_binding_set_string_option(b, "krb5", "krb5");
		return status;
	}
	if (strequal(type, "SCHANNEL")) {
		status = dcerpc_binding_set_string_option(
			b, "schannel", "schannel");
		return status;
	}

	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS cmd_set_auth(
	struct dcerpc_binding *binding,
	const char *level,
	const char *display,
	int argc,
	const char **argv)
{
	const char *p = "[KRB5|KRB5_SPNEGO|NTLMSSP|NTLMSSP_SPNEGO|SCHANNEL]";
	const char *type = "NTLMSSP";
	NTSTATUS status;

	if (argc > 2) {
		printf("Usage: %s %s\n", argv[0], p);
		return NT_STATUS_OK;
	}

	if (argc == 2) {
		type = argv[1];
	}

	status = binding_set_auth(binding, level, type);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Usage: %s %s\n", argv[0], p);
		return status;
	}

	d_printf("Setting %s - %s: %s\n", type, display, nt_errstr(status));

	status = cmd_set_ss_level(binding);
	return status;
}

static NTSTATUS cmd_sign(
	struct dcerpc_binding *binding,
	TALLOC_CTX *mem_ctx,
	int argc,
	const char **argv)
{
	NTSTATUS status = cmd_set_auth(binding, "sign", "sign", argc, argv);
	return status;
}

static NTSTATUS cmd_seal(
	struct dcerpc_binding *binding,
	TALLOC_CTX *mem_ctx,
	int argc,
	const char **argv)
{
	NTSTATUS status = cmd_set_auth(
		binding, "seal", "sign and seal", argc, argv);
	return status;
}

static NTSTATUS cmd_packet(
	struct dcerpc_binding *binding,
	TALLOC_CTX *mem_ctx,
	int argc,
	const char **argv)
{
	NTSTATUS status = cmd_set_auth(
		binding, "packet", "packet", argc, argv);
	return status;
}

static NTSTATUS cmd_timeout(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			    int argc, const char **argv)
{
	if (argc > 2) {
		printf("Usage: %s timeout\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2) {
		timeout = atoi(argv[1]);
	}

	printf("timeout is %d\n", timeout);

	return NT_STATUS_OK;
}


static NTSTATUS cmd_none(
	struct dcerpc_binding *binding,
	TALLOC_CTX *mem_ctx,
	int argc,
	const char **argv)
{
	NTSTATUS status = binding_reset_auth(binding);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = cmd_set_ss_level(binding);
	return status;
}

static NTSTATUS cmd_schannel(
	struct dcerpc_binding *binding,
	TALLOC_CTX *mem_ctx,
	int argc,
	const char **_argv)
{
	const char *argv[] = { "schannel", "SCHANNEL" };
	NTSTATUS status = cmd_set_auth(
		binding, "seal", "sign and seal", 2, argv);
	return status;
}

static NTSTATUS cmd_schannel_sign(
	struct dcerpc_binding *binding,
	TALLOC_CTX *mem_ctx,
	int argc,
	const char **_argv)
{
	const char *argv[] = { "schannel_sign", "SCHANNEL" };
	NTSTATUS status = cmd_set_auth(binding, "sign", "sign only", 2, argv);
	return status;
}

static NTSTATUS cmd_choose_transport(
	struct dcerpc_binding *binding,
	TALLOC_CTX *mem_ctx,
	int argc,
	const char **argv)
{
	NTSTATUS status;
	enum dcerpc_transport_t transport;

	if (argc != 2) {
		printf("Usage: %s [NCACN_NP|NCACN_IP_TCP]\n", argv[0]);
		return NT_STATUS_OK;
	}

	transport = dcerpc_transport_by_name(argv[1]);
	if (transport == NCA_UNKNOWN) {
		printf("transport type %s unknown\n", argv[1]);
		return NT_STATUS_NOT_SUPPORTED;
	}
	if (!((transport == NCACN_IP_TCP) ||
	      (transport == NCACN_NP) ||
	      (transport == NCALRPC))) {
		printf("transport %s not supported\n", argv[1]);
		return NT_STATUS_NOT_SUPPORTED;
	}

	status = dcerpc_binding_set_transport(binding, transport);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = cmd_set_transport(binding);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	printf("default transport is now: %s\n", argv[1]);

	return NT_STATUS_OK;
}

/* Built in rpcclient commands */

static struct cmd_set rpcclient_commands[] = {

	{
		.name = "GENERAL OPTIONS",
	},

	{
		.name               = "help",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_help,
		.description        = "Get help on commands",
		.usage              = "[command]",
	},
	{
		.name               = "?",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_help,
		.description        = "Get help on commands",
		.usage              = "[command]",
	},
	{
		.name               = "debuglevel",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_debuglevel,
		.description        = "Set debug level",
		.usage              = "level",
	},
	{
		.name               = "debug",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_debuglevel,
		.description        = "Set debug level",
		.usage              = "level",
	},
	{
		.name               = "list",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_listcommands,
		.description        = "List available commands on <pipe>",
		.usage              = "pipe",
	},
	{
		.name               = "exit",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_quit,
		.description        = "Exit program",
		.usage              = "",
	},
	{
		.name               = "quit",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_quit,
		.description        = "Exit program",
		.usage              = "",
	},
	{
		.name               = "sign",
		.returntype         = RPC_RTYPE_BINDING,
		.bfn                = cmd_sign,
		.description        = "Force RPC pipe connections to be signed",
		.usage              = "",
	},
	{
		.name               = "seal",
		.returntype         = RPC_RTYPE_BINDING,
		.bfn                = cmd_seal,
		.description        = "Force RPC pipe connections to be sealed",
		.usage              = "",
	},
	{
		.name               = "packet",
		.returntype         = RPC_RTYPE_BINDING,
		.bfn                = cmd_packet,
		.description        = "Force RPC pipe connections with packet authentication level",
		.usage              = "",
	},
	{
		.name               = "schannel",
		.returntype         = RPC_RTYPE_BINDING,
		.bfn                = cmd_schannel,
		.description        = "Force RPC pipe connections to be sealed with 'schannel'. "
				      "Assumes valid machine account to this domain controller.",
		.usage              = "",
	},
	{
		.name               = "schannelsign",
		.returntype         = RPC_RTYPE_BINDING,
		.bfn                = cmd_schannel_sign,
		.description        = "Force RPC pipe connections to be signed (not sealed) with "
				      "'schannel'.  Assumes valid machine account to this domain "
				      "controller.",
		.usage              = "",
	},
	{
		.name               = "timeout",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_timeout,
		.description        = "Set timeout (in milliseconds) for RPC operations",
		.usage              = "",
	},
	{
		.name               = "transport",
		.returntype         = RPC_RTYPE_BINDING,
		.bfn                = cmd_choose_transport,
		.description        = "Choose ncacn transport for RPC operations",
		.usage              = "",
	},
	{
		.name               = "none",
		.returntype         = RPC_RTYPE_BINDING,
		.bfn                = cmd_none,
		.description        = "Force RPC pipe connections to have no special properties",
		.usage              = "",
	},

	{ .name = NULL, },
};

static struct cmd_set separator_command[] = {
	{
		.name               = "---------------",
		.returntype         = MAX_RPC_RETURN_TYPE,
		.description        = "----------------------"
	},
	{ .name = NULL, },
};


/* Various pipe commands */

extern struct cmd_set lsarpc_commands[];
extern struct cmd_set samr_commands[];
extern struct cmd_set spoolss_commands[];
extern struct cmd_set iremotewinspool_commands[];
extern struct cmd_set netlogon_commands[];
extern struct cmd_set srvsvc_commands[];
extern struct cmd_set dfs_commands[];
extern struct cmd_set ds_commands[];
extern struct cmd_set echo_commands[];
extern struct cmd_set epmapper_commands[];
extern struct cmd_set shutdown_commands[];
extern struct cmd_set wkssvc_commands[];
extern struct cmd_set ntsvcs_commands[];
extern struct cmd_set drsuapi_commands[];
extern struct cmd_set eventlog_commands[];
extern struct cmd_set winreg_commands[];
extern struct cmd_set fss_commands[];
extern struct cmd_set witness_commands[];
extern struct cmd_set clusapi_commands[];
extern struct cmd_set spotlight_commands[];
extern struct cmd_set unixinfo_commands[];

static struct cmd_set *rpcclient_command_list[] = {
	rpcclient_commands,
	lsarpc_commands,
	ds_commands,
	samr_commands,
	spoolss_commands,
	iremotewinspool_commands,
	netlogon_commands,
	srvsvc_commands,
	dfs_commands,
	echo_commands,
	epmapper_commands,
	shutdown_commands,
	wkssvc_commands,
	ntsvcs_commands,
	drsuapi_commands,
	eventlog_commands,
	winreg_commands,
	fss_commands,
	witness_commands,
	clusapi_commands,
	spotlight_commands,
	unixinfo_commands,
	NULL
};

static void add_command_set(struct cmd_set *cmd_set)
{
	struct cmd_list *entry;

	if (!(entry = SMB_MALLOC_P(struct cmd_list))) {
		DEBUG(0, ("out of memory\n"));
		return;
	}

	ZERO_STRUCTP(entry);

	entry->cmd_set = cmd_set;
	DLIST_ADD(cmd_list, entry);
}

static NTSTATUS rpccli_ncalrpc_connect(
	const struct ndr_interface_table *iface,
	TALLOC_CTX *mem_ctx,
	struct rpc_pipe_client **prpccli)
{
	struct rpc_pipe_client *rpccli = NULL;
	struct pipe_auth_data *auth = NULL;
	NTSTATUS status;

	status = rpc_pipe_open_ncalrpc(mem_ctx, iface, &rpccli);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_pipe_open_ncalrpc failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	status = rpccli_ncalrpc_bind_data(rpccli, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpccli_ncalrpc_bind_data failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	status = rpc_pipe_bind(rpccli, auth);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_pipe_bind failed: %s\n", nt_errstr(status));
		goto fail;
	}

	*prpccli = rpccli;
	return NT_STATUS_OK;
fail:
	TALLOC_FREE(rpccli);
	return status;
}
/**
 * Call an rpcclient function, passing an argv array.
 *
 * @param cmd Command to run, as a single string.
 **/
static NTSTATUS do_cmd(struct cli_state *cli,
		       struct cli_credentials *creds,
		       struct cmd_set *cmd_entry,
		       struct dcerpc_binding *binding,
		       int argc, const char **argv)
{
	NTSTATUS ntresult;
	WERROR wresult;
	enum dcerpc_transport_t transport;

	TALLOC_CTX *mem_ctx = talloc_stackframe();
	const char *remote_name = NULL;
	const struct sockaddr_storage *remote_sockaddr = NULL;
	struct sockaddr_storage remote_ss = {
		.ss_family = AF_UNSPEC,
	};

	transport = dcerpc_binding_get_transport(binding);

	if (cli != NULL) {
		remote_name = smbXcli_conn_remote_name(cli->conn);
		remote_sockaddr = smbXcli_conn_remote_sockaddr(cli->conn);
	} else {
		const char *remote_host =
			dcerpc_binding_get_string_option(binding, "host");
		remote_name = dcerpc_binding_get_string_option(
				binding, "target_hostname");

		if (remote_host != NULL) {
			bool ok = interpret_string_addr(
				&remote_ss, remote_host, 0);
			if (ok) {
				remote_sockaddr = &remote_ss;
			}
		}
	}

	/* Open pipe */

	if ((cmd_entry->table != NULL) && (cmd_entry->rpc_pipe == NULL)) {
		if (transport == NCALRPC) {
			ntresult = rpccli_ncalrpc_connect(
				cmd_entry->table, cli, &cmd_entry->rpc_pipe);
			if (!NT_STATUS_IS_OK(ntresult)) {
				TALLOC_FREE(mem_ctx);
				return ntresult;
			}
		} else {
			enum dcerpc_AuthType auth_type;
			enum dcerpc_AuthLevel auth_level;
			enum credentials_use_kerberos krb5_state =
				cli_credentials_get_kerberos_state(creds);

			binding_get_auth_info(
				binding, &auth_type, &auth_level, &krb5_state);

			switch (auth_type) {
			case DCERPC_AUTH_TYPE_NONE:
				ntresult = cli_rpc_pipe_open_noauth_transport(
					cli, transport,
					cmd_entry->table,
					remote_name,
					remote_sockaddr,
					&cmd_entry->rpc_pipe);
				break;
			case DCERPC_AUTH_TYPE_SPNEGO:
			case DCERPC_AUTH_TYPE_NTLMSSP:
			case DCERPC_AUTH_TYPE_KRB5:
				cli_credentials_set_kerberos_state(creds,
								   krb5_state,
								   CRED_SPECIFIED);

				ntresult = cli_rpc_pipe_open_with_creds(
					cli, cmd_entry->table,
					transport,
					auth_type,
					auth_level,
					NULL, /* target_service */
					remote_name,
					remote_sockaddr,
					creds,
					&cmd_entry->rpc_pipe);
				break;
			case DCERPC_AUTH_TYPE_SCHANNEL:
				TALLOC_FREE(rpcclient_netlogon_creds);
				ntresult = cli_rpc_pipe_open_schannel(
					cli, rpcclient_msg_ctx,
					cmd_entry->table,
					transport,
					rpcclient_netlogon_domain,
					remote_name,
					remote_sockaddr,
					&cmd_entry->rpc_pipe,
					rpcclient_msg_ctx,
					&rpcclient_netlogon_creds);
				break;
			default:
				DEBUG(0, ("Could not initialise %s. Invalid "
					  "auth type %u\n",
					  cmd_entry->table->name,
					  auth_type ));
				talloc_free(mem_ctx);
				return NT_STATUS_UNSUCCESSFUL;
			}
			if (!NT_STATUS_IS_OK(ntresult)) {
				DBG_ERR("Could not initialise %s. "
					"Error was %s\n",
					cmd_entry->table->name,
					nt_errstr(ntresult));
				talloc_free(mem_ctx);
				return ntresult;
			}

			if (rpcclient_netlogon_creds == NULL &&
			    cmd_entry->use_netlogon_creds) {
				const char *dc_name =
					cmd_entry->rpc_pipe->desthost;
				const char *domain = rpcclient_netlogon_domain;
				struct cli_credentials *trust_creds = NULL;

				ntresult = pdb_get_trust_credentials(
					domain,
					NULL,
					mem_ctx,
					&trust_creds);
				if (!NT_STATUS_IS_OK(ntresult)) {
					DBG_ERR("Failed to fetch trust "
						"credentials for "
						"%s to connect to %s: %s\n",
						domain,
						cmd_entry->table->name,
						nt_errstr(ntresult));
					TALLOC_FREE(cmd_entry->rpc_pipe);
					talloc_free(mem_ctx);
					return ntresult;
				}

				ntresult = rpccli_create_netlogon_creds_ctx(
					trust_creds,
					dc_name,
					rpcclient_msg_ctx,
					rpcclient_msg_ctx,
					&rpcclient_netlogon_creds);
				if (!NT_STATUS_IS_OK(ntresult)) {
					DBG_ERR("Could not initialise "
						"credentials for %s.\n",
						cmd_entry->table->name);
					TALLOC_FREE(cmd_entry->rpc_pipe);
					TALLOC_FREE(mem_ctx);
					return ntresult;
				}

				ntresult = rpccli_setup_netlogon_creds(
					cli,
					NCACN_NP,
					remote_name,
					remote_sockaddr,
					rpcclient_netlogon_creds,
					false, /* force_reauth */
					trust_creds);
				TALLOC_FREE(trust_creds);
				if (!NT_STATUS_IS_OK(ntresult)) {
					DBG_ERR("Could not initialise "
						"credentials for %s.\n",
						cmd_entry->table->name);
					TALLOC_FREE(cmd_entry->rpc_pipe);
					TALLOC_FREE(rpcclient_netlogon_creds);
					TALLOC_FREE(mem_ctx);
					return ntresult;
				}
			}
		}
	}

	/* Set timeout for new connections */
	if (cmd_entry->rpc_pipe) {
		rpccli_set_timeout(cmd_entry->rpc_pipe, timeout);
	}

	/* Run command */

	if ( cmd_entry->returntype == RPC_RTYPE_NTSTATUS ) {
		ntresult = cmd_entry->ntfn(cmd_entry->rpc_pipe, mem_ctx, argc, argv);
		if (!NT_STATUS_IS_OK(ntresult)) {
			printf("result was %s\n", nt_errstr(ntresult));
		}
	} else if (cmd_entry->returntype == RPC_RTYPE_BINDING) {
		ntresult = cmd_entry->bfn(binding, mem_ctx, argc, argv);
		if (!NT_STATUS_IS_OK(ntresult)) {
			printf("result was %s\n", nt_errstr(ntresult));
		}
	} else {
		wresult = cmd_entry->wfn(cmd_entry->rpc_pipe, mem_ctx, argc, argv);
		/* print out the DOS error */
		if (!W_ERROR_IS_OK(wresult)) {
			printf( "result was %s\n", win_errstr(wresult));
		}
		ntresult = W_ERROR_IS_OK(wresult)?NT_STATUS_OK:NT_STATUS_UNSUCCESSFUL;
	}

	/* Cleanup */

	talloc_free(mem_ctx);

	return ntresult;
}


/**
 * Process a command entered at the prompt or as part of -c
 *
 * @returns The NTSTATUS from running the command.
 **/
static NTSTATUS process_cmd(struct cli_credentials *creds,
			    struct cli_state *cli,
			    struct dcerpc_binding *binding,
			    char *cmd)
{
	struct cmd_list *temp_list;
	NTSTATUS result = NT_STATUS_OK;
	int ret;
	int argc;
	const char **argv = NULL;

	if ((ret = poptParseArgvString(cmd, &argc, &argv)) != 0) {
		fprintf(stderr, "rpcclient: %s\n", poptStrerror(ret));
		return NT_STATUS_UNSUCCESSFUL;
	}


	/* Walk through a dlist of arrays of commands. */
	for (temp_list = cmd_list; temp_list; temp_list = temp_list->next) {
		struct cmd_set *set = temp_list->cmd_set;

		while (set->name != NULL) {
			if (!strequal(argv[0], set->name)) {
				set += 1;
				continue;
			}

			if (((set->returntype == RPC_RTYPE_NTSTATUS) &&
			     (set->ntfn == NULL)) ||
			    ((set->returntype == RPC_RTYPE_WERROR) &&
			     (set->wfn == NULL)) ||
			    ((set->returntype == RPC_RTYPE_BINDING) &&
			     (set->bfn == NULL))) {
				fprintf (stderr, "Invalid command\n");
				goto out_free;
			}

			result = do_cmd(
				cli, creds, set, binding, argc, argv);
			goto out_free;
		}
	}

	if (argv[0]) {
		printf("command not found: %s\n", argv[0]);
	}

out_free:
/* moved to do_cmd()
	if (!NT_STATUS_IS_OK(result)) {
		printf("result was %s\n", nt_errstr(result));
	}
*/

	/* NOTE: popt allocates the whole argv, including the
	 * strings, as a single block.  So a single free is
	 * enough to release it -- we don't free the
	 * individual strings.  rtfm. */
	free(argv);

	return result;
}


/* Main function */

 int main(int argc, char *argv[])
{
	const char **const_argv = discard_const_p(const char *, argv);
	int 			opt;
	static char		*cmdstr = NULL;
	const char *server;
	struct cli_state	*cli = NULL;
	static char 		*opt_ipaddr=NULL;
	struct cmd_set 		**cmd_set;
	struct sockaddr_storage server_ss;
	NTSTATUS 		nt_status;
	static int		opt_port = 0;
	int result = 0;
	TALLOC_CTX *frame = talloc_stackframe();
	uint32_t flags = CLI_FULL_CONNECTION_IPC;
	struct dcerpc_binding *binding = NULL;
	enum dcerpc_transport_t transport;
	const char *binding_string = NULL;
	const char *host;
	struct cli_credentials *creds = NULL;
	struct loadparm_context *lp_ctx = NULL;
	bool ok;

	/* make sure the vars that get altered (4th field) are in
	   a fixed location or certain compilers complain */
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"command",	'c', POPT_ARG_STRING,	&cmdstr, 'c', "Execute semicolon separated cmds", "COMMANDS"},
		{"dest-ip", 'I', POPT_ARG_STRING,   &opt_ipaddr, 'I', "Specify destination IP address", "IP"},
		{"port", 'p', POPT_ARG_INT,   &opt_port, 'p', "Specify port number", "PORT"},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_LEGACY_S3
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	smb_init_locale();

	zero_sockaddr(&server_ss);

	setlinebuf(stdout);

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
	}
	lp_ctx = samba_cmdline_get_lp_ctx();
	lpcfg_set_cmdline(lp_ctx, "log level", "0");

	/* Parse options */
	pc = samba_popt_get_context(getprogname(),
				    argc,
				    const_argv,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		exit(1);
	}

	poptSetOtherOptionHelp(pc, "[OPTION...] BINDING-STRING|HOST\nOptions:");

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
		goto done;
	}

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {

		case 'I':
			if (!interpret_string_addr(&server_ss,
						opt_ipaddr,
						AI_NUMERICHOST)) {
				fprintf(stderr, "%s not a valid IP address\n",
					opt_ipaddr);
				result = 1;
				goto done;
			}
			break;
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}

	/* Get server as remaining unparsed argument.  Print usage if more
	   than one unparsed argument is present. */

	server = talloc_strdup(frame, poptGetArg(pc));

	if (!server || poptGetArg(pc)) {
		poptPrintHelp(pc, stderr, 0);
		result = 1;
		goto done;
	}

	poptFreeContext(pc);
	samba_cmdline_burn(argc, argv);

	rpcclient_msg_ctx = cmdline_messaging_context(get_dyn_CONFIGFILE());
	creds = samba_cmdline_get_creds();

	/*
	 * Get password
	 * from stdin if necessary
	 */

	if ((server[0] == '/' && server[1] == '/') ||
			(server[0] == '\\' && server[1] ==  '\\')) {
		server += 2;
	}

	nt_status = dcerpc_parse_binding(frame, server, &binding);

	if (!NT_STATUS_IS_OK(nt_status)) {

		binding_string = talloc_asprintf(frame, "ncacn_np:%s",
						 strip_hostname(server));
		if (!binding_string) {
			result = 1;
			goto done;
		}

		nt_status = dcerpc_parse_binding(frame, binding_string, &binding);
		if (!NT_STATUS_IS_OK(nt_status)) {
			result = -1;
			goto done;
		}
	}

	transport = dcerpc_binding_get_transport(binding);

	if (transport == NCA_UNKNOWN) {
		transport = NCACN_NP;
		nt_status = dcerpc_binding_set_transport(binding, transport);
		if (!NT_STATUS_IS_OK(nt_status)) {
			result = -1;
			goto done;
		}
	}

	host = dcerpc_binding_get_string_option(binding, "host");

	rpcclient_netlogon_domain = cli_credentials_get_domain(creds);
	if (rpcclient_netlogon_domain == NULL ||
	    rpcclient_netlogon_domain[0] == '\0')
	{
		rpcclient_netlogon_domain = lp_workgroup();
	}

	if (transport == NCACN_NP) {
		nt_status = cli_full_connection_creds(frame,
						      &cli,
						      lp_netbios_name(),
						      host,
						      opt_ipaddr ? &server_ss
								 : NULL,
						      opt_port,
						      "IPC$",
						      "IPC",
						      creds,
						      flags);

		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("Cannot connect to server.  Error was %s\n",
				  nt_errstr(nt_status)));
			result = 1;
			goto done;
		}

		/* Load command lists */
		cli_set_timeout(cli, timeout);
	}

#if 0	/* COMMENT OUT FOR TESTING */
	memset(cmdline_auth_info.password,'X',sizeof(cmdline_auth_info.password));
#endif

	cmd_set = rpcclient_command_list;

	while(*cmd_set) {
		add_command_set(*cmd_set);
		add_command_set(separator_command);
		cmd_set++;
	}

       /* Do anything specified with -c */
        if (cmdstr && cmdstr[0]) {
                char    *cmd;
                char    *p = cmdstr;

		result = 0;

                while((cmd=next_command(&p)) != NULL) {
                        NTSTATUS cmd_result = process_cmd(creds,
							  cli,
							  binding,
							  cmd);
			SAFE_FREE(cmd);
			result = NT_STATUS_IS_ERR(cmd_result);
                }

		goto done;
        }

	/* Loop around accepting commands */

	while(1) {
		char *line = NULL;

		line = smb_readline("rpcclient $> ", NULL, completion_fn);

		if (line == NULL) {
			printf("\n");
			break;
		}

		if (line[0] != '\n')
			process_cmd(creds,
				    cli,
				    binding,
				    line);
		SAFE_FREE(line);
	}

done:
	if (cli != NULL) {
		cli_shutdown(cli);
	}
	netlogon_creds_cli_close_global_db();
	TALLOC_FREE(rpcclient_msg_ctx);
	TALLOC_FREE(frame);
	return result;
}
