/* 
   Unix SMB/CIFS implementation.
   VFS module tester

   Copyright (C) Simo Sorce 2002
   Copyright (C) Eric Lorimer 2002

   Most of this code was ripped off of rpcclient.
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
#include "vfstest.h"

/* List to hold groups of commands */
static struct cmd_list {
	struct cmd_list *prev, *next;
	struct cmd_set *cmd_set;
} *cmd_list;

TALLOC_CTX *global_ctx;

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


/* Display help on commands */
static NTSTATUS cmd_help(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
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
static NTSTATUS cmd_debuglevel(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, char **argv)
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

static NTSTATUS cmd_freemem(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	/* Cleanup */
	talloc_destroy(global_ctx);
	global_ctx = NULL;
	vfs->data = NULL;
	vfs->data_size = NULL;
}

static NTSTATUS cmd_quit(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	/* Cleanup */
	talloc_destroy(global_ctx);

	exit(0);
	return NT_STATUS_OK; /* NOTREACHED */
}

static struct cmd_set vfstest_commands[] = {

	{ "GENERAL OPTIONS" },

	{ "help", 	cmd_help, 	"Get help on commands", "[command]" },
	{ "?", 		cmd_help, 	"Get help on commands", "[command]" },
	{ "debuglevel", cmd_debuglevel, "Set debug level", "level" },
	{ "freemem",	cmd_freemem,	"Free currently allocated buffers", "freemem" },
	{ "exit", 	cmd_quit, 	"Exit program", "" },
	{ "quit", 	cmd_quit, 	"Exit program", "" },

	{ NULL }
};

static struct cmd_set separator_command[] = {
	{ "---------------", NULL,	"----------------------" },
	{ NULL }
};


extern struct cmd_set vfs_commands[];
static struct cmd_set *vfstest_command_list[] = {
	vfstest_commands,
	vfs_commands,
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

static NTSTATUS do_cmd(struct vfs_state *vfs, struct cmd_set *cmd_entry, char *cmd)
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

		if (global_ctx == NULL) {
			/* Create mem_ctx */
			if (!(global_ctx = talloc_init())) {
		       		DEBUG(0, ("talloc_init() failed\n"));
				goto done;
			}
		}

		/* Run command */
		result = cmd_entry->fn(vfs, global_ctx, argc, argv);

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
static NTSTATUS process_cmd(struct vfs_state *vfs, char *cmd)
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
				result = do_cmd(vfs, temp_set, cmd);

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

void exit_server(char *reason)
{
	DEBUG(3,("Server exit (%s)\n", (reason ? reason : "")));
	exit(0);
}

static int server_fd = -1;
int last_message = -1;

int smbd_server_fd(void)
{
		return server_fd;
}

BOOL reload_services(BOOL test)
{
	return True;
}

/* Print usage information */
static void usage(void)
{
	printf("Usage: vfstest [options]\n");

	printf("\t-c or --command \"command string\"   execute semicolon separated cmds\n");
	printf("\t-d or --debug debuglevel	   set the debuglevel\n");
	printf("\t-l or --logfile logfile	    logfile to use instead of stdout\n");
	printf("\t-h or --help		       Print this help message.\n");
	printf("\n");
}

/* Main function */

int main(int argc, char *argv[])
{
	extern pstring 		global_myname;
	static int		got_pass = 0;
	BOOL 			interactive = True;
	int 			opt;
	int 			olddebug;
	static char		*cmdstr = "";
	const char *server;
	struct cli_state	*cli;
	fstring 		password="",
				username="",
				domain="";
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
	static struct vfs_state vfs;
	int i;


	/* make sure the vars that get altered (4th field) are in
	   a fixed location or certain compilers complain */
	poptContext pc;
	struct poptOption long_options[] = {
/*		{"conf",	's', POPT_ARG_STRING, 	&opt_configfile, 's'},*/
		{"debug",       'd', POPT_ARG_INT,	&opt_debuglevel, 'd'},
		{"debuglevel",  'd', POPT_ARG_INT,	&opt_debuglevel, 'd'},
/*		{"user",	'U', POPT_ARG_STRING,	&opt_username, 'U'},*/
		{"command",	'c', POPT_ARG_STRING,	&cmdstr},
		{"logfile",	'l', POPT_ARG_STRING,	&opt_logfile, 'l'},
		{"help",	'h', POPT_ARG_NONE,	0, 'h'},
		{ 0, 0, 0, 0}
	};


	setlinebuf(stdout);

	DEBUGLEVEL = 1;
	AllowDebugChange = False;

	pc = poptGetContext("vfstest", argc, (const char **) argv,
			    long_options, 0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'l':
			slprintf(logfile, sizeof(logfile) - 1, "%s.client", 
				 opt_logfile);
			lp_set_logfile(logfile);
			interactive = False;
			break;
			
		case 'd':
			DEBUGLEVEL = opt_debuglevel;
			break;
			
			/*
		case 'U': {
			char *lp;

			pstrcpy(username,opt_username);

			if ((lp=strchr_m(username,'%'))) {
				*lp = 0;
				pstrcpy(password,lp+1);
				got_pass = 1;
				memset(strchr_m(opt_username,'%') + 1, 'X',
				       strlen(password));
			}
			break;
		}
		*/
			
		case 'h':
		default:
			usage();
			exit(1);
		}
	}


	poptFreeContext(pc);

	/* the following functions are part of the Samba debugging
	   facilities.  See lib/debug.c */
	setup_logging("vfstest", interactive);
	if (!interactive) 
		reopen_logs();
	
	/* Load command lists */

	cmd_set = vfstest_command_list;

	while(*cmd_set) {
		add_command_set(*cmd_set);
		add_command_set(separator_command);
		cmd_set++;
	}

	/* some basic initialization stuff */
	vfs.conn = (struct connection_struct *)malloc(sizeof(struct connection_struct));
	vfs.conn->user = "vfstest";
	for (i=0; i < 1024; i++)
		vfs.files[i] = NULL;

       /* Do anything specified with -c */
	if (cmdstr[0]) {
		char    *cmd;
		char    *p = cmdstr;
 
		while((cmd=next_command(&p)) != NULL) {
			process_cmd(&vfs, cmd);
		}
		
		return 0;
	}

	/* Initialize VFS */
	vfs.conn->vfs_private = NULL;
	smbd_vfs_init(vfs.conn);

	/* Loop around accepting commands */

	while(1) {
		pstring prompt;
		char *line;

		slprintf(prompt, sizeof(prompt) - 1, "vfstest $> ");

		line = smb_readline(prompt, NULL, completion_fn);

		if (line == NULL)
			break;

		if (line[0] != '\n')
			process_cmd(&vfs, line);
	}
	
	free(vfs.conn);
	return 0;
}
