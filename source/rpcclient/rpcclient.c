/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Tim Potter 2000-2001
   Copyright (C) Martin Pool 2003

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

#include "includes.h"
#include "rpcclient.h"

DOM_SID domain_sid;


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
#define MAX_COMPLETIONS 100
	char **matches;
	int i, count=0;
	struct cmd_list *commands = cmd_list;

#if 0	/* JERRY */
	/* FIXME!!!  -- what to do when completing argument? */
	/* for words not at the start of the line fallback 
	   to filename completion */
	if (start) 
		return NULL;
#endif

	/* make sure we have a list of valid commands */
	if (!commands) 
		return NULL;

	matches = (char **)malloc(sizeof(matches[0])*MAX_COMPLETIONS);
	if (!matches) return NULL;

	matches[count++] = strdup(text);
	if (!matches[0]) return NULL;

	while (commands && count < MAX_COMPLETIONS-1) 
	{
		if (!commands->cmd_set)
			break;
		
		for (i=0; commands->cmd_set[i].name; i++)
		{
			if ((strncmp(text, commands->cmd_set[i].name, strlen(text)) == 0) &&
				(( commands->cmd_set[i].returntype == RPC_RTYPE_NTSTATUS &&
                        commands->cmd_set[i].ntfn ) || 
                      ( commands->cmd_set[i].returntype == RPC_RTYPE_WERROR &&
                        commands->cmd_set[i].wfn)))
			{
				matches[count] = strdup(commands->cmd_set[i].name);
				if (!matches[count]) 
					return NULL;
				count++;
			}
		}
		
		commands = commands->next;
		
	}

	if (count == 2) {
		SAFE_FREE(matches[0]);
		matches[0] = strdup(matches[1]);
	}
	matches[count] = NULL;
	return matches;
}

static char* next_command (char** cmdstr)
{
	static pstring 		command;
	char			*p;
	
	if (!cmdstr || !(*cmdstr))
		return NULL;
	
	p = strchr_m(*cmdstr, ';');
	if (p)
		*p = '\0';
	pstrcpy(command, *cmdstr);
	if (p)
		*cmdstr = p + 1;
	else
		*cmdstr = NULL;
	
	return command;
}

/* Fetch the SID for this computer */

static void fetch_machine_sid(struct cli_state *cli)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_OK;
	uint32 info_class = 5;
	char *domain_name = NULL;
	static BOOL got_domain_sid;
	TALLOC_CTX *mem_ctx;
	DOM_SID *dom_sid = NULL;

	if (got_domain_sid) return;

	if (!(mem_ctx=talloc_init("fetch_machine_sid")))
	{
		DEBUG(0,("fetch_machine_sid: talloc_init returned NULL!\n"));
		goto error;
	}


	if (!cli_nt_session_open (cli, PI_LSARPC)) {
		fprintf(stderr, "could not initialise lsa pipe\n");
		goto error;
	}
	
	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto error;
	}

	result = cli_lsa_query_info_policy(cli, mem_ctx, &pol, info_class, 
					   &domain_name, &dom_sid);
	if (!NT_STATUS_IS_OK(result)) {
		goto error;
	}

	got_domain_sid = True;
	sid_copy( &domain_sid, dom_sid );

	cli_lsa_close(cli, mem_ctx, &pol);
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return;

 error:
	fprintf(stderr, "could not obtain sid for domain %s\n", cli->domain);

	if (!NT_STATUS_IS_OK(result)) {
		fprintf(stderr, "error: %s\n", nt_errstr(result));
	}

	exit(1);
}

/* List the available commands on a given pipe */

static NTSTATUS cmd_listcommands(struct cli_state *cli, TALLOC_CTX *mem_ctx,
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
		
		if (!StrCaseCmp(argv[1], tmp_set->name))
		{
			printf("Available commands on the %s pipe:\n\n", tmp_set->name);

			i = 0;
			tmp_set++;
			while(tmp_set->name) {
				printf("%20s", tmp_set->name);
                                tmp_set++;
				i++;
				if (i%4 == 0)
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

static NTSTATUS cmd_help(struct cli_state *cli, TALLOC_CTX *mem_ctx,
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

static NTSTATUS cmd_debuglevel(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                               int argc, const char **argv)
{
	if (argc > 2) {
		printf("Usage: %s [debuglevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2) {
		DEBUGLEVEL = atoi(argv[1]);
	}

	printf("debuglevel is %d\n", DEBUGLEVEL);

	return NT_STATUS_OK;
}

static NTSTATUS cmd_quit(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                         int argc, const char **argv)
{
	exit(0);
	return NT_STATUS_OK; /* NOTREACHED */
}

static NTSTATUS cmd_sign(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                         int argc, const char **argv)
{
	if (cli->pipe_auth_flags == (AUTH_PIPE_NTLMSSP|AUTH_PIPE_SIGN)) {
		return NT_STATUS_OK;
	} else {
		/* still have session, just need to use it again */
		cli->pipe_auth_flags = AUTH_PIPE_NTLMSSP;
		cli->pipe_auth_flags |= AUTH_PIPE_SIGN;
		if (cli->nt_pipe_fnum != 0)
			cli_nt_session_close(cli);
	}

	return NT_STATUS_OK; 
}

static NTSTATUS cmd_seal(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                         int argc, const char **argv)
{
	if (cli->pipe_auth_flags == (AUTH_PIPE_NTLMSSP|AUTH_PIPE_SIGN|AUTH_PIPE_SEAL)) {
		return NT_STATUS_OK;
	} else {
		/* still have session, just need to use it again */
		cli->pipe_auth_flags = AUTH_PIPE_NTLMSSP;
		cli->pipe_auth_flags |= AUTH_PIPE_SIGN;
		cli->pipe_auth_flags |= AUTH_PIPE_SEAL;
		if (cli->nt_pipe_fnum != 0)
			cli_nt_session_close(cli);
	}
	return NT_STATUS_OK; 
}

static NTSTATUS cmd_none(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                         int argc, const char **argv)
{
	if (cli->pipe_auth_flags == 0) {
		return NT_STATUS_OK;
	} else {
		/* still have session, just need to use it again */
		cli->pipe_auth_flags = 0;
		if (cli->nt_pipe_fnum != 0)
			cli_nt_session_close(cli);
	}
	cli->pipe_auth_flags = 0;

	return NT_STATUS_OK; 
}

static NTSTATUS setup_schannel(struct cli_state *cli, int pipe_auth_flags,
			       int argc, const char **argv)
{
	NTSTATUS ret;
	static uchar zeros[16];
	uchar trust_password[16];
	uint32 sec_channel_type;
	if (argc == 2) {
		strhex_to_str((char *)cli->auth_info.sess_key,
			      strlen(argv[1]), 
			      argv[1]);
		memcpy(cli->sess_key, cli->auth_info.sess_key, sizeof(cli->sess_key));

		cli->pipe_auth_flags = pipe_auth_flags;
		return NT_STATUS_OK;
	}

	/* Cleanup */

	if ((memcmp(cli->auth_info.sess_key, zeros, sizeof(cli->auth_info.sess_key)) != 0)) {
		if (cli->pipe_auth_flags == pipe_auth_flags) {
			/* already in this mode nothing to do */
			return NT_STATUS_OK;
		} else {
			/* schannel is setup, just need to use it again with new flags */
			cli->pipe_auth_flags = pipe_auth_flags;

			if (cli->nt_pipe_fnum != 0)
				cli_nt_session_close(cli);
			return NT_STATUS_OK;
		}
	}
	
	if (cli->nt_pipe_fnum != 0)
		cli_nt_session_close(cli);

	if (!secrets_fetch_trust_account_password(lp_workgroup(),
						  trust_password,
						  NULL, &sec_channel_type)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ret = cli_nt_setup_netsec(cli, sec_channel_type, pipe_auth_flags, trust_password);
	if (NT_STATUS_IS_OK(ret)) {
		char *hex_session_key;
		hex_encode(cli->auth_info.sess_key,
			   sizeof(cli->auth_info.sess_key),
			   &hex_session_key);
		printf("Got Session key: %s\n", hex_session_key);
		SAFE_FREE(hex_session_key);
	}
	return ret;
}


static NTSTATUS cmd_schannel(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			     int argc, const char **argv)
{
	d_printf("Setting schannel - sign and seal\n");
	return setup_schannel(cli, AUTH_PIPE_NETSEC | AUTH_PIPE_SIGN | AUTH_PIPE_SEAL, 
			      argc, argv);
}

static NTSTATUS cmd_schannel_sign(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			     int argc, const char **argv)
{
	d_printf("Setting schannel - sign only\n");
	return setup_schannel(cli, AUTH_PIPE_NETSEC | AUTH_PIPE_SIGN, 
			      argc, argv);
}


/* Built in rpcclient commands */

static struct cmd_set rpcclient_commands[] = {

	{ "GENERAL OPTIONS" },

	{ "help", RPC_RTYPE_NTSTATUS, cmd_help, NULL, 	  -1,	"Get help on commands", "[command]" },
	{ "?", 	RPC_RTYPE_NTSTATUS, cmd_help, NULL,	  -1,	"Get help on commands", "[command]" },
	{ "debuglevel", RPC_RTYPE_NTSTATUS, cmd_debuglevel, NULL,   -1,	"Set debug level", "level" },
	{ "list",	RPC_RTYPE_NTSTATUS, cmd_listcommands, NULL, -1,	"List available commands on <pipe>", "pipe" },
	{ "exit", RPC_RTYPE_NTSTATUS, cmd_quit, NULL,   -1,	"Exit program", "" },
	{ "quit", RPC_RTYPE_NTSTATUS, cmd_quit, NULL,	  -1,	"Exit program", "" },
	{ "sign", RPC_RTYPE_NTSTATUS, cmd_sign, NULL,	  -1,	"Force RPC pipe connections to be signed", "" },
	{ "seal", RPC_RTYPE_NTSTATUS, cmd_seal, NULL,	  -1,	"Force RPC pipe connections to be sealed", "" },
	{ "schannel", RPC_RTYPE_NTSTATUS, cmd_schannel, NULL,	  -1,	"Force RPC pipe connections to be sealed with 'schannel' (NETSEC).  Assumes valid machine account to this domain controller.", "" },
	{ "schannelsign", RPC_RTYPE_NTSTATUS, cmd_schannel_sign, NULL,	  -1,	"Force RPC pipe connections to be signed (not sealed) with 'schannel' (NETSEC).  Assumes valid machine account to this domain controller.", "" },
	{ "none", RPC_RTYPE_NTSTATUS, cmd_none, NULL,	  -1,	"Force RPC pipe connections to have no special properties", "" },

	{ NULL }
};

static struct cmd_set separator_command[] = {
	{ "---------------", MAX_RPC_RETURN_TYPE, NULL, NULL,	-1,	"----------------------" },
	{ NULL }
};


/* Various pipe commands */

extern struct cmd_set lsarpc_commands[];
extern struct cmd_set samr_commands[];
extern struct cmd_set spoolss_commands[];
extern struct cmd_set netlogon_commands[];
extern struct cmd_set srvsvc_commands[];
extern struct cmd_set dfs_commands[];
extern struct cmd_set reg_commands[];
extern struct cmd_set ds_commands[];
extern struct cmd_set echo_commands[];
extern struct cmd_set shutdown_commands[];

static struct cmd_set *rpcclient_command_list[] = {
	rpcclient_commands,
	lsarpc_commands,
	ds_commands,
	samr_commands,
	spoolss_commands,
	netlogon_commands,
	srvsvc_commands,
	dfs_commands,
	reg_commands,
	echo_commands,
	shutdown_commands,
	NULL
};

static void add_command_set(struct cmd_set *cmd_set)
{
	struct cmd_list *entry;

	if (!(entry = (struct cmd_list *)malloc(sizeof(struct cmd_list)))) {
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
		       struct cmd_set *cmd_entry,
		       int argc, char **argv)
{
	NTSTATUS ntresult;
	WERROR wresult;
	uchar trust_password[16];
	
	TALLOC_CTX *mem_ctx;

	/* Create mem_ctx */

	if (!(mem_ctx = talloc_init("do_cmd"))) {
		DEBUG(0, ("talloc_init() failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Open pipe */

	if (cmd_entry->pipe_idx != -1
	    && cmd_entry->pipe_idx != cli->pipe_idx) {
		if (cli->nt_pipe_fnum != 0)
			cli_nt_session_close(cli);
		
		if (!cli_nt_session_open(cli, cmd_entry->pipe_idx)) {
			DEBUG(0, ("Could not initialise %s\n",
				  get_pipe_name_from_index(cmd_entry->pipe_idx)));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	/* some of the DsXXX commands use the netlogon pipe */

	if (lp_client_schannel() && (cmd_entry->pipe_idx == PI_NETLOGON) && !(cli->pipe_auth_flags & AUTH_PIPE_NETSEC)) {
		uint32 neg_flags = NETLOGON_NEG_AUTH2_FLAGS;
		uint32 sec_channel_type;
	
		if (!secrets_fetch_trust_account_password(lp_workgroup(),
							  trust_password,
							  NULL, &sec_channel_type)) {
			return NT_STATUS_UNSUCCESSFUL;
		}
		
		ntresult = cli_nt_setup_creds(cli, sec_channel_type, 
					      trust_password,
					      &neg_flags, 2);
		if (!NT_STATUS_IS_OK(ntresult)) {
			ZERO_STRUCT(cli->auth_info.sess_key);
			printf("nt_setup_creds failed with %s\n", nt_errstr(ntresult));
			return ntresult;
		}
		
	}

     /* Run command */

     if ( cmd_entry->returntype == RPC_RTYPE_NTSTATUS ) {
          ntresult = cmd_entry->ntfn(cli, mem_ctx, argc, (const char **) argv);
          if (!NT_STATUS_IS_OK(ntresult)) {
              printf("result was %s\n", nt_errstr(ntresult));
          }
     } else {
          wresult = cmd_entry->wfn( cli, mem_ctx, argc, (const char **) argv);
          /* print out the DOS error */
          if (!W_ERROR_IS_OK(wresult)) {
                  printf( "result was %s\n", dos_errstr(wresult));
          }
          ntresult = W_ERROR_IS_OK(wresult)?NT_STATUS_OK:NT_STATUS_UNSUCCESSFUL;
     }
            

	/* Cleanup */

	talloc_destroy(mem_ctx);

	return ntresult;
}


/**
 * Process a command entered at the prompt or as part of -c
 *
 * @returns The NTSTATUS from running the command.
 **/
static NTSTATUS process_cmd(struct cli_state *cli, char *cmd)
{
	struct cmd_list *temp_list;
	NTSTATUS result = NT_STATUS_OK;
	int ret;
	int argc;
	char **argv = NULL;

	if ((ret = poptParseArgvString(cmd, &argc, (const char ***) &argv)) != 0) {
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

				result = do_cmd(cli, temp_set, argc, argv);

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

	if (argv) {
		/* NOTE: popt allocates the whole argv, including the
		 * strings, as a single block.  So a single free is
		 * enough to release it -- we don't free the
		 * individual strings.  rtfm. */
		free(argv);
	}
	
	return result;
}


/* Main function */

 int main(int argc, char *argv[])
{
	BOOL 			interactive = True;
	int 			opt;
	static char		*cmdstr = NULL;
	const char *server;
	struct cli_state	*cli;
	static char 		*opt_ipaddr=NULL;
	struct cmd_set 		**cmd_set;
	struct in_addr 		server_ip;
	NTSTATUS 		nt_status;

	/* make sure the vars that get altered (4th field) are in
	   a fixed location or certain compilers complain */
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"command",	'c', POPT_ARG_STRING,	&cmdstr, 'c', "Execute semicolon separated cmds", "COMMANDS"},
		{"dest-ip", 'I', POPT_ARG_STRING,   &opt_ipaddr, 'I', "Specify destination IP address", "IP"},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_TABLEEND
	};

	ZERO_STRUCT(server_ip);

	setlinebuf(stdout);

	/* the following functions are part of the Samba debugging
	   facilities.  See lib/debug.c */
	setup_logging("rpcclient", interactive);
	if (!interactive) 
		reopen_logs();
	
	/* Load smb.conf file */

	if (!lp_load(dyn_CONFIGFILE,True,False,False))
		fprintf(stderr, "Can't load %s\n", dyn_CONFIGFILE);

	/* Parse options */

	pc = poptGetContext("rpcclient", argc, (const char **) argv,
			    long_options, 0);

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
		return 0;
	}
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {

		case 'I':
		        if ( (server_ip.s_addr=inet_addr(opt_ipaddr)) == INADDR_NONE ) {
				fprintf(stderr, "%s not a valid IP address\n",
					opt_ipaddr);
				return 1;
			}
		}
	}

	/* Get server as remaining unparsed argument.  Print usage if more
	   than one unparsed argument is present. */

	server = poptGetArg(pc);
	
	if (!server || poptGetArg(pc)) {
		poptPrintHelp(pc, stderr, 0);
		return 1;
	}

	poptFreeContext(pc);

	load_interfaces();

	if (!init_names())
		return 1;

	/*
	 * Get password
	 * from stdin if necessary
	 */

	if (!cmdline_auth_info.got_pass) {
		char *pass = getpass("Password:");
		if (pass) {
			pstrcpy(cmdline_auth_info.password, pass);
		}
	}
	
	nt_status = cli_full_connection(&cli, global_myname(), server, 
					opt_ipaddr ? &server_ip : NULL, 0,
					"IPC$", "IPC",  
					cmdline_auth_info.username, 
					lp_workgroup(),
					cmdline_auth_info.password, 
					cmdline_auth_info.use_kerberos ? CLI_FULL_CONNECTION_USE_KERBEROS : 0,
					cmdline_auth_info.signing_state,NULL);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("Cannot connect to server.  Error was %s\n", nt_errstr(nt_status)));
		return 1;
	}

	memset(cmdline_auth_info.password,'X',sizeof(cmdline_auth_info.password));

	/* Load command lists */

	cmd_set = rpcclient_command_list;

	while(*cmd_set) {
		add_command_set(*cmd_set);
		add_command_set(separator_command);
		cmd_set++;
	}

	fetch_machine_sid(cli);
 
       /* Do anything specified with -c */
        if (cmdstr && cmdstr[0]) {
                char    *cmd;
                char    *p = cmdstr;
		int result = 0;
 
                while((cmd=next_command(&p)) != NULL) {
                        NTSTATUS cmd_result = process_cmd(cli, cmd);
			result = NT_STATUS_IS_ERR(cmd_result);
                }
		
		cli_shutdown(cli);
                return result;
        }

	/* Loop around accepting commands */

	while(1) {
		pstring prompt;
		char *line;

		slprintf(prompt, sizeof(prompt) - 1, "rpcclient $> ");

		line = smb_readline(prompt, NULL, completion_fn);

		if (line == NULL)
			break;

		if (line[0] != '\n')
			process_cmd(cli, line);
	}
	
	cli_shutdown(cli);
	return 0;
}
