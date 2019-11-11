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
#include "popt_common_cmdline.h"
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

enum pipe_auth_type_spnego {
	PIPE_AUTH_TYPE_SPNEGO_NONE = 0,
	PIPE_AUTH_TYPE_SPNEGO_NTLMSSP,
	PIPE_AUTH_TYPE_SPNEGO_KRB5
};

static enum dcerpc_AuthType pipe_default_auth_type = DCERPC_AUTH_TYPE_NONE;
static enum pipe_auth_type_spnego pipe_default_auth_spnego_type = 0;
static enum dcerpc_AuthLevel pipe_default_auth_level = DCERPC_AUTH_LEVEL_NONE;
static unsigned int timeout = 0;
static enum dcerpc_transport_t default_transport = NCACN_NP;

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
		lp_set_cmdline("log level", argv[1]);
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

static NTSTATUS cmd_set_ss_level(void)
{
	struct cmd_list *tmp;

	/* Close any existing connections not at this level. */

	for (tmp = cmd_list; tmp; tmp = tmp->next) {
        	struct cmd_set *tmp_set;

		for (tmp_set = tmp->cmd_set; tmp_set->name; tmp_set++) {
			if (tmp_set->rpc_pipe == NULL) {
				continue;
			}

			if ((tmp_set->rpc_pipe->auth->auth_type
			     != pipe_default_auth_type)
			    || (tmp_set->rpc_pipe->auth->auth_level
				!= pipe_default_auth_level)) {
				TALLOC_FREE(tmp_set->rpc_pipe);
				tmp_set->rpc_pipe = NULL;
			}
		}
	}
	return NT_STATUS_OK;
}

static NTSTATUS cmd_set_transport(void)
{
	struct cmd_list *tmp;

	/* Close any existing connections not at this level. */

	for (tmp = cmd_list; tmp; tmp = tmp->next) {
		struct cmd_set *tmp_set;

		for (tmp_set = tmp->cmd_set; tmp_set->name; tmp_set++) {
			if (tmp_set->rpc_pipe == NULL) {
				continue;
			}

			if (tmp_set->rpc_pipe->transport->transport != default_transport) {
				TALLOC_FREE(tmp_set->rpc_pipe);
				tmp_set->rpc_pipe = NULL;
			}
		}
	}
	return NT_STATUS_OK;
}

static NTSTATUS cmd_sign(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                         int argc, const char **argv)
{
	const char *p = "[KRB5|KRB5_SPNEGO|NTLMSSP|NTLMSSP_SPNEGO|SCHANNEL]";
	const char *type = "NTLMSSP";

	pipe_default_auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;

	if (argc > 2) {
		printf("Usage: %s %s\n", argv[0], p);
		return NT_STATUS_OK;
	}

	if (argc == 2) {
		type = argv[1];
		if (strequal(type, "KRB5")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_KRB5;
		} else if (strequal(type, "KRB5_SPNEGO")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_SPNEGO;
			pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_KRB5;
		} else if (strequal(type, "NTLMSSP")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
		} else if (strequal(type, "NTLMSSP_SPNEGO")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_SPNEGO;
			pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_NTLMSSP;
		} else if (strequal(type, "SCHANNEL")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_SCHANNEL;
		} else {
			printf("unknown type %s\n", type);
			printf("Usage: %s %s\n", argv[0], p);
			return NT_STATUS_INVALID_LEVEL;
		}
	}

	d_printf("Setting %s - sign\n", type);

	return cmd_set_ss_level();
}

static NTSTATUS cmd_seal(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                         int argc, const char **argv)
{
	const char *p = "[KRB5|KRB5_SPNEGO|NTLMSSP|NTLMSSP_SPNEGO|SCHANNEL]";
	const char *type = "NTLMSSP";

	pipe_default_auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;

	if (argc > 2) {
		printf("Usage: %s %s\n", argv[0], p);
		return NT_STATUS_OK;
	}

	if (argc == 2) {
		type = argv[1];
		if (strequal(type, "KRB5")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_KRB5;
		} else if (strequal(type, "KRB5_SPNEGO")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_SPNEGO;
			pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_KRB5;
		} else if (strequal(type, "NTLMSSP")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
		} else if (strequal(type, "NTLMSSP_SPNEGO")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_SPNEGO;
			pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_NTLMSSP;
		} else if (strequal(type, "SCHANNEL")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_SCHANNEL;
		} else {
			printf("unknown type %s\n", type);
			printf("Usage: %s %s\n", argv[0], p);
			return NT_STATUS_INVALID_LEVEL;
		}
	}

	d_printf("Setting %s - sign and seal\n", type);

	return cmd_set_ss_level();
}

static NTSTATUS cmd_packet(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			   int argc, const char **argv)
{
	const char *p = "[KRB5|KRB5_SPNEGO|NTLMSSP|NTLMSSP_SPNEGO|SCHANNEL]";
	const char *type = "NTLMSSP";

	pipe_default_auth_level = DCERPC_AUTH_LEVEL_PACKET;
	pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;

	if (argc > 2) {
		printf("Usage: %s %s\n", argv[0], p);
		return NT_STATUS_OK;
	}

	if (argc == 2) {
		type = argv[1];
		if (strequal(type, "KRB5")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_KRB5;
		} else if (strequal(type, "KRB5_SPNEGO")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_SPNEGO;
			pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_KRB5;
		} else if (strequal(type, "NTLMSSP")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
		} else if (strequal(type, "NTLMSSP_SPNEGO")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_SPNEGO;
			pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_NTLMSSP;
		} else if (strequal(type, "SCHANNEL")) {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_SCHANNEL;
		} else {
			printf("unknown type %s\n", type);
			printf("Usage: %s %s\n", argv[0], p);
			return NT_STATUS_INVALID_LEVEL;
		}
	}

	d_printf("Setting %s - packet\n", type);

	return cmd_set_ss_level();
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


static NTSTATUS cmd_none(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                         int argc, const char **argv)
{
	pipe_default_auth_level = DCERPC_AUTH_LEVEL_NONE;
	pipe_default_auth_type = DCERPC_AUTH_TYPE_NONE;
	pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_NONE;

	return cmd_set_ss_level();
}

static NTSTATUS cmd_schannel(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			     int argc, const char **argv)
{
	d_printf("Setting schannel - sign and seal\n");
	pipe_default_auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	pipe_default_auth_type = DCERPC_AUTH_TYPE_SCHANNEL;

	return cmd_set_ss_level();
}

static NTSTATUS cmd_schannel_sign(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			     int argc, const char **argv)
{
	d_printf("Setting schannel - sign only\n");
	pipe_default_auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	pipe_default_auth_type = DCERPC_AUTH_TYPE_SCHANNEL;

	return cmd_set_ss_level();
}

static NTSTATUS cmd_choose_transport(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				     int argc, const char **argv)
{
	NTSTATUS status;

	if (argc != 2) {
		printf("Usage: %s [NCACN_NP|NCACN_IP_TCP]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (strequal(argv[1], "NCACN_NP")) {
		default_transport = NCACN_NP;
	} else if (strequal(argv[1], "NCACN_IP_TCP")) {
		default_transport = NCACN_IP_TCP;
	} else {
		printf("transport type: %s unknown or not supported\n",	argv[1]);
		return NT_STATUS_NOT_SUPPORTED;
	}

	status = cmd_set_transport();
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
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Get help on commands",
		.usage              = "[command]",
	},
	{
		.name               = "?",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_help,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Get help on commands",
		.usage              = "[command]",
	},
	{
		.name               = "debuglevel",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_debuglevel,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Set debug level",
		.usage              = "level",
	},
	{
		.name               = "debug",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_debuglevel,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Set debug level",
		.usage              = "level",
	},
	{
		.name               = "list",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_listcommands,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "List available commands on <pipe>",
		.usage              = "pipe",
	},
	{
		.name               = "exit",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_quit,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Exit program",
		.usage              = "",
	},
	{
		.name               = "quit",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_quit,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Exit program",
		.usage              = "",
	},
	{
		.name               = "sign",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_sign,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Force RPC pipe connections to be signed",
		.usage              = "",
	},
	{
		.name               = "seal",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_seal,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Force RPC pipe connections to be sealed",
		.usage              = "",
	},
	{
		.name               = "packet",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_packet,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Force RPC pipe connections with packet authentication level",
		.usage              = "",
	},
	{
		.name               = "schannel",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_schannel,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Force RPC pipe connections to be sealed with 'schannel'. "
				      "Assumes valid machine account to this domain controller.",
		.usage              = "",
	},
	{
		.name               = "schannelsign",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_schannel_sign,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Force RPC pipe connections to be signed (not sealed) with "
				      "'schannel'.  Assumes valid machine account to this domain "
				      "controller.",
		.usage              = "",
	},
	{
		.name               = "timeout",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_timeout,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Set timeout (in milliseconds) for RPC operations",
		.usage              = "",
	},
	{
		.name               = "transport",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_choose_transport,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
		.description        = "Choose ncacn transport for RPC operations",
		.usage              = "",
	},
	{
		.name               = "none",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_none,
		.wfn                = NULL,
		.table              = NULL,
		.rpc_pipe           = NULL,
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


/**
 * Call an rpcclient function, passing an argv array.
 *
 * @param cmd Command to run, as a single string.
 **/
static NTSTATUS do_cmd(struct cli_state *cli,
		       struct user_auth_info *auth_info,
		       struct cmd_set *cmd_entry,
		       struct dcerpc_binding *binding,
		       int argc, const char **argv)
{
	NTSTATUS ntresult;
	WERROR wresult;

	TALLOC_CTX *mem_ctx;

	/* Create mem_ctx */

	if (!(mem_ctx = talloc_stackframe())) {
		DEBUG(0, ("talloc_init() failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Open pipe */

	if ((cmd_entry->table != NULL) && (cmd_entry->rpc_pipe == NULL)) {
		struct cli_credentials *creds =
			get_cmdline_auth_info_creds(auth_info);
		enum credentials_use_kerberos krb5_state =
			cli_credentials_get_kerberos_state(creds);

		switch (pipe_default_auth_type) {
		case DCERPC_AUTH_TYPE_NONE:
			ntresult = cli_rpc_pipe_open_noauth_transport(
				cli, default_transport,
				cmd_entry->table,
				&cmd_entry->rpc_pipe);
			break;
		case DCERPC_AUTH_TYPE_SPNEGO:
			switch (pipe_default_auth_spnego_type) {
			case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
				krb5_state = CRED_DONT_USE_KERBEROS;
				break;
			case PIPE_AUTH_TYPE_SPNEGO_KRB5:
				krb5_state = CRED_MUST_USE_KERBEROS;
				break;
			case PIPE_AUTH_TYPE_SPNEGO_NONE:
				krb5_state = CRED_AUTO_USE_KERBEROS;
				break;
			}
			FALL_THROUGH;
		case DCERPC_AUTH_TYPE_NTLMSSP:
		case DCERPC_AUTH_TYPE_KRB5:
			if (krb5_state != CRED_AUTO_USE_KERBEROS) {
				cli_credentials_set_kerberos_state(creds,
								   krb5_state);
			}
			ntresult = cli_rpc_pipe_open_with_creds(
				cli, cmd_entry->table,
				default_transport,
				pipe_default_auth_type,
				pipe_default_auth_level,
				smbXcli_conn_remote_name(cli->conn),
				creds,
				&cmd_entry->rpc_pipe);
			break;
		case DCERPC_AUTH_TYPE_SCHANNEL:
			TALLOC_FREE(rpcclient_netlogon_creds);
			ntresult = cli_rpc_pipe_open_schannel(
				cli, rpcclient_msg_ctx,
				cmd_entry->table,
				default_transport,
				rpcclient_netlogon_domain,
				&cmd_entry->rpc_pipe,
				rpcclient_msg_ctx,
				&rpcclient_netlogon_creds);
			break;
		default:
			DEBUG(0, ("Could not initialise %s. Invalid "
				  "auth type %u\n",
				  cmd_entry->table->name,
				  pipe_default_auth_type ));
			talloc_free(mem_ctx);
			return NT_STATUS_UNSUCCESSFUL;
		}
		if (!NT_STATUS_IS_OK(ntresult)) {
			DEBUG(0, ("Could not initialise %s. Error was %s\n",
				  cmd_entry->table->name,
				  nt_errstr(ntresult) ));
			talloc_free(mem_ctx);
			return ntresult;
		}

		if (rpcclient_netlogon_creds == NULL && cmd_entry->use_netlogon_creds) {
			const char *dc_name = cmd_entry->rpc_pipe->desthost;
			const char *domain = rpcclient_netlogon_domain;
			struct cli_credentials *trust_creds = NULL;

			ntresult = pdb_get_trust_credentials(domain, NULL,
							     mem_ctx, &trust_creds);
			if (!NT_STATUS_IS_OK(ntresult)) {
				DEBUG(0, ("Failed to fetch trust credentials for "
					  "%s to connect to %s: %s\n",
					  domain, cmd_entry->table->name,
					  nt_errstr(ntresult)));
				TALLOC_FREE(cmd_entry->rpc_pipe);
				talloc_free(mem_ctx);
				return ntresult;
			}

			ntresult = rpccli_create_netlogon_creds_ctx(trust_creds,
							dc_name,
							rpcclient_msg_ctx,
							rpcclient_msg_ctx,
							&rpcclient_netlogon_creds);
			if (!NT_STATUS_IS_OK(ntresult)) {
				DEBUG(0, ("Could not initialise credentials for %s.\n",
					  cmd_entry->table->name));
				TALLOC_FREE(cmd_entry->rpc_pipe);
				TALLOC_FREE(mem_ctx);
				return ntresult;
			}

			ntresult = rpccli_setup_netlogon_creds(
				cli,
				NCACN_NP,
				rpcclient_netlogon_creds,
				false, /* force_reauth */
				trust_creds);
			TALLOC_FREE(trust_creds);
			if (!NT_STATUS_IS_OK(ntresult)) {
				DEBUG(0, ("Could not initialise credentials for %s.\n",
					  cmd_entry->table->name));
				TALLOC_FREE(cmd_entry->rpc_pipe);
				TALLOC_FREE(rpcclient_netlogon_creds);
				TALLOC_FREE(mem_ctx);
				return ntresult;
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
static NTSTATUS process_cmd(struct user_auth_info *auth_info,
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
		struct cmd_set *temp_set = temp_list->cmd_set;

		while (temp_set->name) {
			if (strequal(argv[0], temp_set->name)) {
				if (!(temp_set->returntype == RPC_RTYPE_NTSTATUS && temp_set->ntfn ) &&
                         !(temp_set->returntype == RPC_RTYPE_WERROR && temp_set->wfn )) {
					fprintf (stderr, "Invalid command\n");
					goto out_free;
				}

				result = do_cmd(cli, auth_info, temp_set,
						binding, argc, argv);

				goto out_free;
			}
			temp_set++;
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
	uint32_t flags = 0;
	struct dcerpc_binding *binding = NULL;
	enum dcerpc_transport_t transport;
	uint32_t bflags = 0;
	const char *binding_string = NULL;
	const char *host;
	int signing_state = SMB_SIGNING_IPC_DEFAULT;

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
		POPT_TABLEEND
	};

	smb_init_locale();

	zero_sockaddr(&server_ss);

	setlinebuf(stdout);

	/* the following functions are part of the Samba debugging
	   facilities.  See lib/debug.c */
	setup_logging("rpcclient", DEBUG_STDOUT);
	lp_set_cmdline("log level", "0");

	/* Parse options */

	pc = poptGetContext("rpcclient", argc, const_argv,
			    long_options, 0);

	poptSetOtherOptionHelp(pc, "[OPTION...] <server>\nOptions:");

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
		}
	}

	/* Get server as remaining unparsed argument.  Print usage if more
	   than one unparsed argument is present. */

	server = poptGetArg(pc);

	if (!server || poptGetArg(pc)) {
		poptPrintHelp(pc, stderr, 0);
		result = 1;
		goto done;
	}

	poptFreeContext(pc);
	popt_burn_cmdline_password(argc, argv);

	rpcclient_msg_ctx = cmdline_messaging_context(get_dyn_CONFIGFILE());

	if (!init_names()) {
		result = 1;
		goto done;
	}

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
		nt_status = dcerpc_binding_set_transport(binding, NCACN_NP);
		if (!NT_STATUS_IS_OK(nt_status)) {
			result = -1;
			goto done;
		}
	}

	host = dcerpc_binding_get_string_option(binding, "host");

	bflags = dcerpc_binding_get_flags(binding);
	if (bflags & DCERPC_CONNECT) {
		pipe_default_auth_level = DCERPC_AUTH_LEVEL_CONNECT;
		pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
	}
	if (bflags & DCERPC_PACKET) {
		pipe_default_auth_level = DCERPC_AUTH_LEVEL_PACKET;
		pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
	}
	if (bflags & DCERPC_SIGN) {
		pipe_default_auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
		pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
	}
	if (bflags & DCERPC_SEAL) {
		pipe_default_auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
		pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
	}
	if (bflags & DCERPC_AUTH_SPNEGO) {
		pipe_default_auth_type = DCERPC_AUTH_TYPE_SPNEGO;
		pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_NTLMSSP;
	}
	if (bflags & DCERPC_AUTH_NTLM) {
		if (pipe_default_auth_type == DCERPC_AUTH_TYPE_SPNEGO) {
			pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_NTLMSSP;
		} else {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
		}
	}
	if (bflags & DCERPC_AUTH_KRB5) {
		if (pipe_default_auth_type == DCERPC_AUTH_TYPE_SPNEGO) {
			pipe_default_auth_spnego_type = PIPE_AUTH_TYPE_SPNEGO_KRB5;
		} else {
			pipe_default_auth_type = DCERPC_AUTH_TYPE_KRB5;
		}
	}
	if (pipe_default_auth_type != DCERPC_AUTH_TYPE_NONE) {
		/* If nothing is requested then default to integrity */
		if (pipe_default_auth_level == DCERPC_AUTH_LEVEL_NONE) {
			pipe_default_auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
		}
	}

	signing_state = get_cmdline_auth_info_signing_state(
			popt_get_cmdline_auth_info());
	switch (signing_state) {
	case SMB_SIGNING_OFF:
		lp_set_cmdline("client ipc signing", "no");
		break;
	case SMB_SIGNING_REQUIRED:
		lp_set_cmdline("client ipc signing", "required");
		break;
	}

	rpcclient_netlogon_domain = get_cmdline_auth_info_domain(
			popt_get_cmdline_auth_info());
	if (rpcclient_netlogon_domain == NULL ||
	    rpcclient_netlogon_domain[0] == '\0')
	{
		rpcclient_netlogon_domain = lp_workgroup();
	}

	nt_status = cli_full_connection_creds(&cli, lp_netbios_name(), host,
					opt_ipaddr ? &server_ss : NULL, opt_port,
					"IPC$", "IPC",
					get_cmdline_auth_info_creds(
						popt_get_cmdline_auth_info()),
					flags,
					SMB_SIGNING_IPC_DEFAULT);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("Cannot connect to server.  Error was %s\n", nt_errstr(nt_status)));
		result = 1;
		goto done;
	}

	if (get_cmdline_auth_info_smb_encrypt(popt_get_cmdline_auth_info())) {
		nt_status = cli_cm_force_encryption_creds(cli,
					get_cmdline_auth_info_creds(
						popt_get_cmdline_auth_info()),
					"IPC$");
		if (!NT_STATUS_IS_OK(nt_status)) {
			result = 1;
			goto done;
		}
	}

#if 0	/* COMMENT OUT FOR TESTING */
	memset(cmdline_auth_info.password,'X',sizeof(cmdline_auth_info.password));
#endif

	/* Load command lists */

	timeout = 10000;
	cli_set_timeout(cli, timeout);

	cmd_set = rpcclient_command_list;

	while(*cmd_set) {
		add_command_set(*cmd_set);
		add_command_set(separator_command);
		cmd_set++;
	}

	default_transport = dcerpc_binding_get_transport(binding);

       /* Do anything specified with -c */
        if (cmdstr && cmdstr[0]) {
                char    *cmd;
                char    *p = cmdstr;

		result = 0;

                while((cmd=next_command(&p)) != NULL) {
                        NTSTATUS cmd_result = process_cmd(
						popt_get_cmdline_auth_info(),
						cli, binding, cmd);
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
			process_cmd(popt_get_cmdline_auth_info(), cli,
				binding, line);
		SAFE_FREE(line);
	}

done:
	if (cli != NULL) {
		cli_shutdown(cli);
	}
	popt_free_cmdline_auth_info();
	netlogon_creds_cli_close_global_db();
	TALLOC_FREE(rpcclient_msg_ctx);
	TALLOC_FREE(frame);
	return result;
}
