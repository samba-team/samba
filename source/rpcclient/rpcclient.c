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
	
	if (!cmdstr || !(*cmdstr))
		return NULL;
	
	p = strchr(*cmdstr, ';');
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
		fprintf(stderr, "error: %s\n", get_nt_error_msg(result));
	}

	exit(1);
}

/* Initialise client credentials for authenticated pipe access */

void init_rpcclient_creds(struct ntuser_creds *creds, char* username,
			  char* domain, char* password)
{
	ZERO_STRUCTP(creds);

	if (lp_encrypted_passwords()) {
		pwd_make_lm_nt_16(&creds->pwd, password);
	} else {
		pwd_set_cleartext(&creds->pwd, password);
	}

	fstrcpy(creds->user_name, username);
	fstrcpy(creds->domain, domain);

	if (! *username) {
		creds->pwd.null_pwd = True;
	}
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
		printf("result was %s\n", get_nt_error_msg(result));
	}

	return result;
}

/************************************************************************/
struct cli_state *setup_connection(struct cli_state *cli, char *system_name,
				   struct ntuser_creds *creds)
{
	struct in_addr dest_ip;
	struct nmb_name calling, called;
	fstring dest_host;
	extern pstring global_myname;
	struct ntuser_creds anon;

	/* Initialise cli_state information */
	if (!cli_initialise(cli)) {
		return NULL;
	}

	if (!creds) {
		ZERO_STRUCT(anon);
		anon.pwd.null_pwd = 1;
		creds = &anon;
	}

	cli_init_creds(cli, creds);

	/* Establish a SMB connection */
	if (!resolve_srv_name(system_name, dest_host, &dest_ip)) {
                fprintf(stderr, "Could not resolve %s\n", dest_host);
		return NULL;
	}

	make_nmb_name(&called, dns_to_netbios_name(dest_host), 0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	if (!cli_establish_connection(cli, dest_host, &dest_ip, &calling, 
				      &called, "IPC$", "IPC", False, True)) {
                fprintf(stderr, "Error establishing IPC$ connection\n");
		return NULL;
	}
	
	return cli;
}


/* Print usage information */
static void usage(void)
{
	printf("Usage: rpcclient [options] server\n");

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
	struct ntuser_creds	creds;
	struct cli_state	cli;
	fstring 		password,
				username,
				domain,
				server;
	pstring			logfile;
	struct cmd_set **cmd_set;

	setlinebuf(stdout);

	DEBUGLEVEL = 1;

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
			exit(1);
		}
	}

	argv += optind;
	argc -= optind;

	/* Parse options */
	if (argc == 0) {
		usage();
		return 0;
	}
	
	if (strncmp("//", argv[0], 2) == 0 || strncmp("\\\\", argv[0], 2) == 0)
		argv[0] += 2;

	pstrcpy(server, argv[0]);

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
	
	/*
	 * initialize the credentials struct.  Get password
	 * from stdin if necessary
	 */
	if (!strlen(username) && !got_pass)
		get_username(username);
		
	if (!got_pass) {
		init_rpcclient_creds (&creds, username, domain, "");
		pwd_read(&creds.pwd, "Enter Password: ", lp_encrypted_passwords());
	}
	else {
		init_rpcclient_creds (&creds, username, domain, password);
	}
	memset(password,'X',sizeof(password));

	/* open a connection to the specified server */
	ZERO_STRUCTP (&cli);
	if (!setup_connection (&cli, server, &creds)) {
		return 1;
	}
	
	/* There are no pointers in ntuser_creds struct so zero it out */

	ZERO_STRUCTP (&creds);
	
	/* Load command lists */

	cmd_set = rpcclient_command_list;

	while(*cmd_set) {
		add_command_set(*cmd_set);
		add_command_set(separator_command);
		cmd_set++;
	}

	fetch_machine_sid(&cli);
 
       /* Do anything specified with -c */
        if (cmdstr[0]) {
                char    *cmd;
                char    *p = cmdstr;
 
                while((cmd=next_command(&p)) != NULL) {
                        process_cmd(&cli, cmd);
                }
 
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
			process_cmd(&cli, line);
	}

	return 0;
}
