/* 
   Unix SMB/Netbios implementation.
   Version 2.2
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
		if (!(ptr = strchr(buf, '=')))
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
	BOOL next_cmd = False;
	
	if (!cmdstr || !(*cmdstr))
		return NULL;
	
	printf("cmd = %s\n", *cmdstr);
	
	p = strchr(*cmdstr, ';');
	if (p) {
		next_cmd = True;
		*p = '\0';
	}
	pstrcpy(command, *cmdstr);
	*cmdstr = p;		
	if (next_cmd) 
		p++;
		
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
		DEBUG(0,("fetch_machine_sid: talloc_init returned NULL!\n"));
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
		fprintf(stderr, "error: %s\n", get_nt_error_msg(result));
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
	char **argv = NULL;
	const char *p = cmd;
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
	const char *p = cmd;
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
		printf("result was %s\n", get_nt_error_msg(result));
	}

	return result;
}


/* Print usage information */
static void usage(void)
{
	printf("Usage: rpcclient [options] server\n");
	printf("Version: %s\n", VERSION);

	printf("\t-A authfile           file containing user credentials\n");
	printf("\t-c \"command string\"   execute semicolon separated cmds\n");
	printf("\t-d debuglevel         set the debuglevel\n");
	printf("\t-l logfile            name of logfile to use as opposed to stdout\n");
	printf("\t-h                    Print this help message.\n");
	printf("\t-N                    don't ask for a password\n");
	printf("\t-s configfile         specify an alternative config file\n");
	printf("\t-U username           set the network username\n");
	printf("\t-W domain             set the domain name for user account\n");
	printf("\n");
}

/* Main function */

int main(int argc, char *argv[])
{
	extern char 		*optarg;
	extern int 		optind;
	extern pstring 		global_myname;
	BOOL 			got_pass = False;
	BOOL 			interactive = True;
	int 			opt;
	int 			olddebug;
	pstring 		cmdstr = "", 
				servicesf = CONFIGFILE;
	fstring 		password,
				username,
				domain,
				server;
	struct cli_state	*cli;
	pstring			logfile;
	struct cmd_set **cmd_set;
	struct in_addr 		server_ip;
	NTSTATUS 		nt_status;
	extern BOOL AllowDebugChange;

	setlinebuf(stdout);

	DEBUGLEVEL = 1;
	AllowDebugChange = False;

	/* Parse options */

	if (argc == 1) {
		usage();
		return 0;
	}

        /*
	 * M. Sweet: getopt() behaves slightly differently on various
	 * platforms.  The following loop ensures that the System V,
	 * BSD, and Linux (glibc) implementations work similarly to
	 * allow the server name anywhere on the command-line.
	 */

	pstrcpy(server, "");

        while (argc > optind) {
		while ((opt = getopt(argc, argv, "A:s:Nd:U:W:c:l:h")) != EOF) {
			switch (opt) {
			case 'A':
				/* only get the username, password, and domain from the file */
				read_authfile (optarg, username, password, domain);
				if (strlen (password))
					got_pass = True;
				break;

			case 'c':
				pstrcpy(cmdstr, optarg);
				break;

			case 'd':
				DEBUGLEVEL = atoi(optarg);
				break;

			case 'l':
				slprintf(logfile, sizeof(logfile) - 1, "%s.client", optarg);
				lp_set_logfile(logfile);
				interactive = False;
				break;

			case 'N':
				got_pass = True;
				break;

			case 's':
				pstrcpy(servicesf, optarg);
				break;

			case 'U': {
				char *lp;
				pstrcpy(username,optarg);
				if ((lp=strchr(username,'%'))) {
					*lp = 0;
					pstrcpy(password,lp+1);
					got_pass = True;
					memset(strchr(optarg,'%')+1,'X',strlen(password));
				}
				break;
			}

			case 'W':
				pstrcpy(domain, optarg);
				break;

			case 'h':
			default:
				usage();
				return 1;
			}
		}

		if (argc > optind) {
			if (strncmp("//", argv[optind], 2) == 0 ||
			    strncmp("\\\\", argv[optind], 2) == 0)
			{
				argv[optind] += 2;
			}

			pstrcpy(server, argv[optind]);
			optind ++;
		}
	}

	if (!server[0]) {
		usage();
		return 1;
	}

	/* the following functions are part of the Samba debugging
	   facilities.  See lib/debug.c */
	setup_logging("rpcclient", interactive);
	if (!interactive) 
		reopen_logs();
	
	TimeInit();
	charset_initialise();

	/* Load smb.conf file */
	/* FIXME!  How to get this DEBUGLEVEL to last over lp_load()? */
	olddebug = DEBUGLEVEL;
	if (!lp_load(servicesf,True,False,False)) {
		fprintf(stderr, "Can't load %s\n", servicesf);
	}
	DEBUGLEVEL = olddebug;

	codepage_initialise(lp_client_code_page());

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
