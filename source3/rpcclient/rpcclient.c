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
static char **completion_fn(char *text, int start, int end)
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
				commands->cmd_set[i].fn) 
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

/***********************************************************************
 * read in username/password credentials from a file
 */
static void read_authfile (
	char *filename, 
	char* username, 
	char* password, 
	char* domain
)
{
	FILE *auth;
        fstring buf;
        uint16 len = 0;
	char *ptr, *val, *param;
                               
	if ((auth=sys_fopen(filename, "r")) == NULL)
	{
		printf ("ERROR: Unable to open credentials file!\n");
		return;
	}
                                
	while (!feof(auth))
	{  
		/* get a line from the file */
		if (!fgets (buf, sizeof(buf), auth))
			continue;
		
		len = strlen(buf);
		
		/* skip empty lines */			
		if ((len) && (buf[len-1]=='\n'))
		{
			buf[len-1] = '\0';
			len--;
		}	
		if (len == 0)
			continue;
					
		/* break up the line into parameter & value.
		   will need to eat a little whitespace possibly */
		param = buf;
		if (!(ptr = strchr_m(buf, '=')))
			continue;
		val = ptr+1;
		*ptr = '\0';
					
		/* eat leading white space */
		while ((*val!='\0') && ((*val==' ') || (*val=='\t')))
			val++;
					
		if (strwicmp("password", param) == 0)
			fstrcpy (password, val);
		else if (strwicmp("username", param) == 0)
			fstrcpy (username, val);
		else if (strwicmp("domain", param) == 0)
			fstrcpy (domain, val);
						
		memset(buf, 0, sizeof(buf));
	}
	fclose(auth);
	
	return;
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


/**
 * Find default username from environment variables.
 *
 * @param username fstring to receive username; not touched if none is
 * known.
 **/
static void get_username (char *username)
{
        if (getenv("USER"))
                fstrcpy(username,getenv("USER"));
 
        if (*username == 0 && getenv("LOGNAME"))
                fstrcpy(username,getenv("LOGNAME"));
 
        if (*username == 0) {
                fstrcpy(username,"GUEST");
        }

	return;
}

/* Fetch the SID for this computer */

static void fetch_machine_sid(struct cli_state *cli)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_OK;
	uint32 info_class = 5;
	fstring domain_name;
	static BOOL got_domain_sid;
	TALLOC_CTX *mem_ctx;

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
					   domain_name, &domain_sid);
	if (!NT_STATUS_IS_OK(result)) {
		goto error;
	}

	got_domain_sid = True;

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

/* Built in rpcclient commands */

static struct cmd_set rpcclient_commands[] = {

	{ "GENERAL OPTIONS" },

	{ "help", 	cmd_help, 	  -1,	"Get help on commands", "[command]" },
	{ "?", 		cmd_help, 	  -1,	"Get help on commands", "[command]" },
	{ "debuglevel", cmd_debuglevel,   -1,	"Set debug level", "level" },
	{ "list",	cmd_listcommands, -1,	"List available commands on <pipe>", "pipe" },
	{ "exit", 	cmd_quit, 	  -1,	"Exit program", "" },
	{ "quit", 	cmd_quit, 	  -1,	"Exit program", "" },

	{ NULL }
};

static struct cmd_set separator_command[] = {
	{ "---------------", NULL,	-1,	"----------------------" },
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
	NTSTATUS result;
	
	TALLOC_CTX *mem_ctx;

	/* Create mem_ctx */

	if (!(mem_ctx = talloc_init("do_cmd"))) {
		DEBUG(0, ("talloc_init() failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Open pipe */

	if (cmd_entry->pipe_idx != -1)
		if (!cli_nt_session_open(cli, cmd_entry->pipe_idx)) {
			DEBUG(0, ("Could not initialize pipe\n"));
			return NT_STATUS_UNSUCCESSFUL;
		}

	/* Run command */

	result = cmd_entry->fn(cli, mem_ctx, argc, (const char **) argv);

	/* Cleanup */

	if (cmd_entry->pipe_idx != -1)
		cli_nt_session_close(cli);

	talloc_destroy(mem_ctx);

	return result;
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
				if (!temp_set->fn) {
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
	if (!NT_STATUS_IS_OK(result)) {
		printf("result was %s\n", nt_errstr(result));
	}

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
	static int		got_pass = 0;
	BOOL 			interactive = True;
	int 			opt;
	static char		*cmdstr = "";
	const char *server;
	struct cli_state	*cli;
	fstring 		password="",
				username="",
		domain="";
	static char 		*opt_authfile=NULL,
				*opt_username=NULL,
				*opt_domain=NULL,
 	                        *opt_logfile=NULL,
	                        *opt_ipaddr=NULL;
	pstring 		logfile;
	struct cmd_set 		**cmd_set;
	struct in_addr 		server_ip;
	NTSTATUS 		nt_status;

	/* make sure the vars that get altered (4th field) are in
	   a fixed location or certain compilers complain */
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"authfile",	'A', POPT_ARG_STRING,	&opt_authfile, 'A', "File containing user credentials", "AUTHFILE"},
		{"nopass",	'N', POPT_ARG_NONE,	&got_pass, 'N', "Don't ask for a password"},
		{"user", 'U', POPT_ARG_STRING,	&opt_username, 'U', "Set the network username", "USER"},
		{"workgroup", 'W', POPT_ARG_STRING, 	&opt_domain, 'W', "Set the domain name for user account", "DOMAIN"},
		{"command",	'c', POPT_ARG_STRING,	&cmdstr, 'c', "Execute semicolon separated cmds", "COMMANDS"},
		{"logfile",	'l', POPT_ARG_STRING,	&opt_logfile, 'l', "Logfile to use instead of stdout", "LOGFILE" },
		{"dest-ip", 'I', POPT_ARG_STRING,   &opt_ipaddr, 'I', "Specify destination IP address", "IP"},
		{ NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_debug },
		{ NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_configfile },
		{ NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_version},
		{ NULL }
	};

	setlinebuf(stdout);

	/* Parse options */

	pc = poptGetContext("rpcclient", argc, (const char **) argv,
			    long_options, 0);

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
		return 0;
	}
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'A':
			/* only get the username, password, and domain from the file */
			read_authfile (opt_authfile, username, password, domain);
			if (strlen (password))
				got_pass = 1;
			break;
			
		case 'l':
			slprintf(logfile, sizeof(logfile) - 1, "%s.client", 
				 opt_logfile);
			lp_set_logfile(logfile);
			interactive = False;
			break;
			
		case 'U': {
			char *lp;

			fstrcpy(username,opt_username);

			if ((lp=strchr_m(username,'%'))) {
				*lp = 0;
				fstrcpy(password,lp+1);
				got_pass = 1;
				memset(strchr_m(opt_username,'%') + 1, 'X',
				       strlen(password));
			}
			break;
		}
		case 'I':
		        if ( (server_ip.s_addr=inet_addr(opt_ipaddr)) == INADDR_NONE ) {
				fprintf(stderr, "%s not a valid IP address\n",
					opt_ipaddr);
				return 1;
			}
		case 'W':
			fstrcpy(domain, opt_domain);
			break;
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

	/* the following functions are part of the Samba debugging
	   facilities.  See lib/debug.c */
	setup_logging("rpcclient", interactive);
	if (!interactive) 
		reopen_logs();
	
	/* Load smb.conf file */

	if (!lp_load(dyn_CONFIGFILE,True,False,False))
		fprintf(stderr, "Can't load %s\n", dyn_CONFIGFILE);

	load_interfaces();

	if (!init_names())
		return 1;

	/* Resolve the IP address */

	if (!opt_ipaddr && !resolve_name(server, &server_ip, 0x20))  {
		fprintf(stderr, "Unable to resolve %s\n", server);
		return 1;
	}
	
	/*
	 * Get password
	 * from stdin if necessary
	 */

	if (!got_pass) {
		char *pass = getpass("Password:");
		if (pass) {
			fstrcpy(password, pass);
		}
	}
	
	if (!strlen(username) && !got_pass)
		get_username(username);
		
	nt_status = cli_full_connection(&cli, global_myname(), server, 
					&server_ip, 0,
					"IPC$", "IPC",  
					username, domain,
					password, 0, NULL);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("Cannot connect to server.  Error was %s\n", nt_errstr(nt_status)));
		return 1;
	}

	memset(password,'X',sizeof(password));

	/* Load command lists */

	cmd_set = rpcclient_command_list;

	while(*cmd_set) {
		add_command_set(*cmd_set);
		add_command_set(separator_command);
		cmd_set++;
	}

	fetch_machine_sid(cli);
 
       /* Do anything specified with -c */
        if (cmdstr[0]) {
                char    *cmd;
                char    *p = cmdstr;
 
                while((cmd=next_command(&p)) != NULL) {
                        process_cmd(cli, cmd);
                }
		
		cli_shutdown(cli);
                return 0;
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
