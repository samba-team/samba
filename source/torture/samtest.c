/* 
   Unix SMB/CIFS implementation.
   SAM module tester

   Copyright (C) 2002 Jelmer Vernooij

   Parts of the code stolen from vfstest by Simo Sorce and Eric Lorimer
   Parts of the code stolen from rpcclient by Tim Potter

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
#include "samtest.h"

struct func_entry {
	char *name;
	int (*fn)(struct connection_struct *conn, const char *path);
};

/* List to hold groups of commands */
static struct cmd_list {
	struct cmd_list *prev, *next;
	struct cmd_set *cmd_set;
} *cmd_list;

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

/* Load specified configuration file */
static NTSTATUS cmd_conf(struct samtest_state *sam, TALLOC_CTX *mem_ctx,
						 int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: %s <smb.conf>\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (!lp_load(argv[1], False, True, False)) {
		printf("Error loading \"%s\"\n", argv[1]);
		return NT_STATUS_OK;
	}

	printf("\"%s\" successfully loaded\n", argv[1]);
	return NT_STATUS_OK;
}

/* Display help on commands */
static NTSTATUS cmd_help(struct samtest_state *st, TALLOC_CTX *mem_ctx,
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

			printf("%20s\t%s\n", tmp_set->name,
			       tmp_set->description ? tmp_set->description:
			       "");

			tmp_set++;
		}
	}

	return NT_STATUS_OK;
}

/* Change the debug level */
static NTSTATUS cmd_debuglevel(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
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

static NTSTATUS cmd_quit(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	/* Cleanup */
	talloc_destroy(mem_ctx);

	exit(0);
	return NT_STATUS_OK; /* NOTREACHED */
}

static struct cmd_set samtest_commands[] = {

	{ "GENERAL OPTIONS" },

	{ "help", 	cmd_help, 	"Get help on commands", "" },
	{ "?", 		cmd_help, 	"Get help on commands", "" },
	{ "conf",   cmd_conf,   "Load smb configuration file", "conf <smb.conf>" },
	{ "debuglevel", cmd_debuglevel, "Set debug level", "" },
	{ "exit", 	cmd_quit, 	"Exit program", "" },
	{ "quit", 	cmd_quit, 	"Exit program", "" },

	{ NULL }
};

static struct cmd_set separator_command[] = {
	{ "---------------", NULL,	"----------------------" },
	{ NULL }
};


/*extern struct cmd_set sam_commands[];*/
extern struct cmd_set sam_general_commands[];
extern struct cmd_set sam_domain_commands[];
extern struct cmd_set sam_account_commands[];
extern struct cmd_set sam_group_commands[];
static struct cmd_set *samtest_command_list[] = {
	samtest_commands,
	sam_general_commands,
	sam_domain_commands,
	sam_account_commands,
	sam_group_commands,
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

static NTSTATUS do_cmd(struct samtest_state *st, struct cmd_set *cmd_entry, char *cmd)
{
	char *p = cmd, **argv = NULL;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx = NULL;
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

		if (mem_ctx == NULL) {
			/* Create mem_ctx */
			if (!(mem_ctx = talloc_init("do_cmd"))) {
		       		DEBUG(0, ("talloc_init() failed\n"));
				goto done;
			}
		}

		/* Run command */
		result = cmd_entry->fn(st, mem_ctx, argc, argv);

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
static NTSTATUS process_cmd(struct samtest_state *st, char *cmd)
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
				result = do_cmd(st, temp_set, cmd);

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

/* Main function */

int main(int argc, char *argv[])
{
	BOOL 			interactive = True;
	int 			opt;
	static char		*cmdstr = NULL;
	struct cmd_set 		**cmd_set;
	struct samtest_state st;

	/* make sure the vars that get altered (4th field) are in
	   a fixed location or certain compilers complain */
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"command",	'e', POPT_ARG_STRING,	&cmdstr, 'e', "Execute semicolon seperated cmds"},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	ZERO_STRUCT(st);

	st.token = get_system_token();

	setlinebuf(stdout);

	DEBUGLEVEL = 1;

	pc = poptGetContext("samtest", argc, (const char **) argv,
			    long_options, 0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'l':
			slprintf(logfile, sizeof(logfile) - 1, "%s.client", 
				 opt_logfile);
			lp_set_logfile(logfile);
			interactive = False;
			break;
		}
	}

	if (!lp_load(config_file,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", config_file);
		exit(1);
	}

	poptFreeContext(pc);

	/* the following functions are part of the Samba debugging
	   facilities.  See lib/debug.c */
	setup_logging("samtest", interactive);
	if (!interactive) 
		reopen_logs();
	
	/* Load command lists */

	cmd_set = samtest_command_list;

	while(*cmd_set) {
		add_command_set(*cmd_set);
		add_command_set(separator_command);
		cmd_set++;
	}

       /* Do anything specified with -c */
	if (cmdstr && cmdstr[0]) {
		char    *cmd;
		char    *p = cmdstr;
 
		while((cmd=next_command(&p)) != NULL) {
			process_cmd(&st, cmd);
		}
		
		return 0;
	}

	/* Loop around accepting commands */

	while(1) {
		pstring prompt;
		char *line;

		slprintf(prompt, sizeof(prompt) - 1, "samtest $> ");

		line = smb_readline(prompt, NULL, NULL);

		if (line == NULL)
			break;

		if (line[0] != '\n')
			process_cmd(&st, line);
	}
	
	return 0;
}
