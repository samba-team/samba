/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Tim Potter 2000-2001

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

/* List to hold groups of commands */

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
	*cmdstr = p;
	
	return command;
}

static void get_username (char *username)
{
        if (getenv("USER"))
                pstrcpy(username,getenv("USER"));
 
        if (*username == 0 && getenv("LOGNAME"))
                pstrcpy(username,getenv("LOGNAME"));
 
        if (*username == 0) {
                pstrcpy(username,"GUEST");
        }

	return;
}

/* Fetch the SID for this computer */

void fetch_machine_sid(struct cli_state *cli)
{
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_OK;
	uint32 info_class = 5;
	fstring domain_name;
	static BOOL got_domain_sid;
	TALLOC_CTX *mem_ctx;

	if (got_domain_sid) return;

	if (!(mem_ctx=talloc_init()))
	{
		DEBUG(0,("fetch_domain_sid: talloc_init returned NULL!\n"));
		goto error;
	}


	if (!cli_nt_session_open (cli, PIPE_LSARPC)) {
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
                         int argc, char **argv)
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
                         int argc, char **argv)
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
                               int argc, char **argv)
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
                         int argc, char **argv)
{
	exit(0);
	return NT_STATUS_OK; /* NOTREACHED */
}

/* Build in rpcclient commands */

static struct cmd_set rpcclient_commands[] = {

	{ "GENERAL OPTIONS" },

	{ "help", 	cmd_help, 	NULL,	"Get help on commands", "[command]" },
	{ "?", 		cmd_help, 	NULL,	"Get help on commands", "[command]" },
	{ "debuglevel", cmd_debuglevel, NULL,	"Set debug level", "level" },
	{ "list",	cmd_listcommands, NULL,	"List available commands on <pipe>", "pipe" },
	{ "exit", 	cmd_quit, 	NULL,	"Exit program", "" },
	{ "quit", 	cmd_quit, 	NULL,	"Exit program", "" },

	{ NULL }
};

static struct cmd_set separator_command[] = {
	{ "---------------", NULL,	NULL,	"----------------------" },
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

static struct cmd_set *rpcclient_command_list[] = {
	rpcclient_commands,
	lsarpc_commands,
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

static NTSTATUS do_cmd(struct cli_state *cli, struct cmd_set *cmd_entry, 
                       char *cmd)
{
	char *p = cmd, **argv = NULL;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	pstring buf;
	int argc = 0, i;

	/* Count number of arguments first time through the loop then
	   allocate memory and strdup them. */

 again:
	while(next_token(&p, buf, " ", sizeof(buf))) {
		if (argv) {
			argv[argc] = strdup(buf);
		}
		
		argc++;
	}
				
	if (!argv) {

		/* Create argument list */

		argv = (char **)malloc(sizeof(char *) * argc);
                memset(argv, 0, sizeof(char *) * argc);

		if (!argv) {
			fprintf(stderr, "out of memory\n");
			result = NT_STATUS_NO_MEMORY;
                        goto done;
		}
					
		p = cmd;
		argc = 0;
					
		goto again;
	}

	/* Call the function */

	if (cmd_entry->fn) {
                TALLOC_CTX *mem_ctx;

                /* Create mem_ctx */

                if (!(mem_ctx = talloc_init())) {
                        DEBUG(0, ("talloc_init() failed\n"));
                        goto done;
                }

                /* Open pipe */

                if (cmd_entry->pipe)
                        if (!cli_nt_session_open(cli, cmd_entry->pipe)) {
                                DEBUG(0, ("Could not initialise %s\n",
                                          cmd_entry->pipe));
                                goto done;
                        }

                /* Run command */

                result = cmd_entry->fn(cli, mem_ctx, argc, argv);

                /* Cleanup */

                if (cmd_entry->pipe)
                        cli_nt_session_close(cli);

                talloc_destroy(mem_ctx);

	} else {
		fprintf (stderr, "Invalid command\n");
                goto done;
        }

 done:
						
	/* Cleanup */

        if (argv) {
                for (i = 0; i < argc; i++)
                        SAFE_FREE(argv[i]);
	
                SAFE_FREE(argv);
        }
	
	return result;
}

/* Process a command entered at the prompt or as part of -c */

static NTSTATUS process_cmd(struct cli_state *cli, char *cmd)
{
	struct cmd_list *temp_list;
	BOOL found = False;
	pstring buf;
	char *p = cmd;
	NTSTATUS result = NT_STATUS_OK;
	int len = 0;

	if (cmd[strlen(cmd) - 1] == '\n')
		cmd[strlen(cmd) - 1] = '\0';

	if (!next_token(&p, buf, " ", sizeof(buf))) {
		return NT_STATUS_OK;
	}

        /* strip the trainly \n if it exsists */
	len = strlen(buf);
	if (buf[len-1] == '\n')
		buf[len-1] = '\0';

	/* Search for matching commands */

	for (temp_list = cmd_list; temp_list; temp_list = temp_list->next) {
		struct cmd_set *temp_set = temp_list->cmd_set;

		while(temp_set->name) {
			if (strequal(buf, temp_set->name)) {
                                found = True;
				result = do_cmd(cli, temp_set, cmd);

				goto done;
			}
			temp_set++;
		}
	}

 done:
	if (!found && buf[0]) {
		printf("command not found: %s\n", buf);
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(result)) {
		printf("result was %s\n", nt_errstr(result));
	}

	return result;
}


/* Print usage information */
static void usage(void)
{
	printf("Usage: rpcclient server [options]\n");

	printf("\t-A or --authfile authfile          file containing user credentials\n");
	printf("\t-c or --command \"command string\"   execute semicolon separated cmds\n");
	printf("\t-d or --debug debuglevel           set the debuglevel\n");
	printf("\t-l or --logfile logfile            logfile to use instead of stdout\n");
	printf("\t-h or --help                       Print this help message.\n");
	printf("\t-N or --nopass                     don't ask for a password\n");
	printf("\t-s or --conf configfile            specify an alternative config file\n");
	printf("\t-U or --user username              set the network username\n");
	printf("\t-W or --workgroup domain           set the domain name for user account\n");
	printf("\n");
}

/* Main function */

 int main(int argc, char *argv[])
{
	extern char 		*optarg;
	extern int 		optind;
	extern pstring 		global_myname;
	static int		got_pass = 0;
	BOOL 			interactive = True;
	int 			opt;
	int 			olddebug;
	static char		*cmdstr = "";
	struct cli_state	*cli;
	fstring 		password="",
				username="",
				domain="",
				server="";
	static char 		*opt_authfile=NULL,
				*opt_username=NULL,
				*opt_domain=NULL,
				*opt_configfile=NULL,
				*opt_logfile=NULL;
	static int		opt_debuglevel;
	pstring 		logfile;
	struct cmd_set 		**cmd_set;
	struct in_addr 		server_ip;
	NTSTATUS 		nt_status;
	extern BOOL 		AllowDebugChange;

	/* make sure the vars that get altered (4th field) are in
	   a fixed location or certain compilers complain */
	poptContext pc;
	struct poptOption long_options[] = {
		{"authfile",	'A', POPT_ARG_STRING,	&opt_authfile, 'A'},
		{"conf",        's', POPT_ARG_STRING, 	&opt_configfile, 's'},
		{"nopass",	'N', POPT_ARG_NONE,	&got_pass},
		{"debug",       'd', POPT_ARG_INT,	&opt_debuglevel, 'd'},
		{"debuglevel",  'd', POPT_ARG_INT,	&opt_debuglevel, 'd'},
		{"user",        'U', POPT_ARG_STRING,	&opt_username, 'U'},
		{"workgroup",   'W', POPT_ARG_STRING, 	&opt_domain, 'W'},
		{"command",	'c', POPT_ARG_STRING,	&cmdstr},
		{"logfile",	'l', POPT_ARG_STRING,	&opt_logfile, 'l'},
		{"help",        'h', POPT_ARG_NONE,	0, 'h'},
		{ 0, 0, 0, 0}
	};


	setlinebuf(stdout);

	DEBUGLEVEL = 1;
	AllowDebugChange = False;

	/* Parse options */

	if (argc == 1) {
		usage();
		return 0;
	}
	
	if (strncmp("//", argv[1], 2) == 0 || strncmp("\\\\", argv[1], 2) == 0)
		argv[1] += 2;

	pstrcpy(server, argv[1]);

	argv++;
	argc--;

	pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'A':
			/* only get the username, password, and domain from the file */
			read_authfile (opt_authfile, username,
				       password, domain);
			if (strlen (password))
				got_pass = 1;
			break;

		case 'l':
			slprintf(logfile, sizeof(logfile) - 1, "%s.client", 
				 opt_logfile);
			lp_set_logfile(logfile);
			interactive = False;
 			break;

		case 's':
			pstrcpy(dyn_CONFIGFILE, opt_configfile);
			break;

		case 'd':
			DEBUGLEVEL = opt_debuglevel;
			break;

		case 'U': {
			char *lp;
			pstrcpy(username,opt_username);
			if ((lp=strchr_m(username,'%'))) {
				*lp = 0;
				pstrcpy(password,lp+1);
				got_pass = 1;
				memset(strchr_m(opt_username,'%')+1,'X',strlen(password));
			}
			break;
		}
		
		case 'W':
			pstrcpy(domain, opt_domain);
			break;
			
		case 'h':
		default:
			usage();
			exit(1);
		}
	}

	poptFreeContext(pc);

	/* the following functions are part of the Samba debugging
	   facilities.  See lib/debug.c */
	setup_logging("rpcclient", interactive);
	if (!interactive) 
		reopen_logs();
	
	/* Load smb.conf file */
	/* FIXME!  How to get this DEBUGLEVEL to last over lp_load()? */
	olddebug = DEBUGLEVEL;
	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "Can't load %s\n", dyn_CONFIGFILE);
	}
	DEBUGLEVEL = olddebug;

	load_interfaces();

	get_myname((*global_myname)?NULL:global_myname);
	strupper(global_myname);

	/* Resolve the IP address */

	if (!resolve_name(server, &server_ip, 0x20))  {
		DEBUG(1,("Unable to resolve %s\n", server));
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
		
	nt_status = cli_full_connection(&cli, global_myname, server, 
					&server_ip, 0,
					"IPC$", "IPC",  
					username, domain,
					password, strlen(password));
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1,("Cannot connect to server.  Error was %s\n", nt_errstr(nt_status)));
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
