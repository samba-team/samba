/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   RPC pipe client

   Copyright (C) Tim Potter 2000

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

extern int DEBUGLEVEL;
	
pstring password;
pstring username;
pstring workgroup;
pstring server;

/* Various pipe commands */

extern struct cmd_set lsarpc_commands[];
extern struct cmd_set samr_commands[];
extern struct cmd_set spoolss_commands[];

/* Initialise client credentials for authenticated pipe access */

void init_rpcclient_creds(struct ntuser_creds *creds)
{
	ZERO_STRUCTP(creds);
	
	if (lp_encrypted_passwords()) {
		pwd_make_lm_nt_16(&creds->pwd, password);
	} else {
		pwd_set_cleartext(&creds->pwd, password);
	}

	fstrcpy(creds->user_name, username);
	fstrcpy(creds->domain, workgroup);
}

/* List to hold groups of commands */

static struct cmd_list {
	struct cmd_list *prev, *next;
	struct cmd_set *cmd_set;
} *cmd_list;

static uint32 cmd_help(int argc, char **argv)
{
	struct cmd_list *temp_list;

	for (temp_list = cmd_list; temp_list; temp_list = temp_list->next) {
		struct cmd_set *temp_set = temp_list->cmd_set;

		while(temp_set->name) {
			printf("%s\t%s\n", temp_set->name,
			       temp_set->description);
			temp_set++;
		}
	}

	return 0;
}

static uint32 cmd_debuglevel(int argc, char **argv)
{
	if (argc > 2) {
		printf("Usage: %s [debuglevel]\n", argv[0]);
		return NT_STATUS_NOPROBLEMO;
	}

	if (argc == 2) {
		DEBUGLEVEL = atoi(argv[1]);
	}

	printf("debuglevel is %d\n", DEBUGLEVEL);

	return NT_STATUS_NOPROBLEMO;
}

/* Build in rpcclient commands */

static struct cmd_set rpcclient_commands[] = {
	{ "help", cmd_help, "Print list of commands" },
	{ "debuglevel", cmd_debuglevel, "Set debug level" },
	{ "?", cmd_help, "Print list of commands" },

	{ NULL, NULL, NULL }
};

void add_command_set(struct cmd_set *cmd_set)
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

static uint32 do_cmd(struct cmd_set *cmd_entry, char *cmd)
{
	char *p = cmd, **argv = NULL;
	uint32 result;
	pstring buf;
	int argc = 1, i;

	next_token(&p, buf, " ", sizeof(buf));

	/* Count number of arguments first time through the loop then
	   allocate memory and strdup them. */

 again:
	while(next_token(NULL, buf, " ", sizeof(buf))) {
		if (argv) {
			argv[argc] = strdup(buf);
		}
		
		argc++;
	}
				
	if (!argv) {

		/* Create argument list */

		argv = (char **)malloc(sizeof(char *) * argc);

		if (!argv) {
			fprintf(stderr, "out of memoryx\n");
			return 0;
		}
					
		p = cmd;
		next_token(&p, buf, " ", sizeof(buf));
		argv[0] = strdup(buf);
		argc = 1;
					
		goto again;
	}

	/* Call the function */

	result = cmd_entry->fn(argc, argv);
				
	/* Cleanup */

	for (i = 0; i < argc; i++) {
		free(argv[i]);
	}
	
	free(argv);
	
	return result;
}

/* Process a command entered at the prompt or as part of -c */

static uint32 process_cmd(char *cmd)
{
	struct cmd_list *temp_list;
	BOOL found = False;
	pstring buf;
	char *p = cmd;
	uint32 result;

	if (!next_token(&p, buf, " ", sizeof(buf))) {
		return 0;
	}

	/* Search for matching commands */

	for (temp_list = cmd_list; temp_list; temp_list = temp_list->next) {
		struct cmd_set *temp_set = temp_list->cmd_set;

		while(temp_set->name) {
			if (strequal(buf, temp_set->name)) {
				found = True;
				result = do_cmd(temp_set, cmd);
				goto done;
			}
			temp_set++;
		}
	}

 done:
	if (!found && buf[0]) {
		printf("command not found: %s\n", buf);
		return 0;
	}

	if (result != 0) {
		printf("result was %s\n", get_nt_error_msg(result));
	}

	return result;
}

/* Print usage information */

static void usage(char *pname)
{
	printf("Usage: %s server [options]\n", pname);

	printf("\t-N                    don't ask for a password\n");
	printf("\t-d debuglevel         set the debuglevel\n");
	printf("\t-h                    Print this help message.\n");
	printf("\t-U username           set the network username\n");
	printf("\t-W workgroup          set the workgroup name\n");
	printf("\t-c command string     execute semicolon separated cmds\n");
	printf("\n");
}

/* Main function */

 int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	struct in_addr dest_ip;
	BOOL got_pass = False;
	BOOL have_ip = False;
	int opt;
	pstring cmdstr = "", servicesf = CONFIGFILE;
	extern FILE *dbf;

	setlinebuf(stdout);
	dbf = stderr;

	setup_logging(argv[0], True);

#ifdef HAVE_LIBREADLINE
	/* Allow conditional parsing of the ~/.inputrc file. */
	rl_readline_name = "rpcclient";
#endif    
	
	DEBUGLEVEL = 2;

	/* Load smb.conf file */

	if (!lp_load(servicesf,True,False,False)) {
		fprintf(stderr, "Can't load %s\n", servicesf);
	}

	codepage_initialise(lp_client_code_page());
	charset_initialise();
	load_interfaces();

	TimeInit();

	/* Parse options */

	if (argc < 2) {
		usage(argv[0]);
		return 0;
	}

	pstrcpy(server, argv[1]);

	argv++;
	argc--;

	while ((opt = getopt(argc, argv, "s:Nd:I:U:W:c:")) != EOF) {
		switch (opt) {
		case 's':
			pstrcpy(servicesf, optarg);
			break;
		case 'N':
			got_pass = True;
			break;
		case 'd':
			DEBUGLEVEL = atoi(optarg);
			break;
		case 'I':
			dest_ip = *interpret_addr2(optarg);
			have_ip = True;
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
			pstrcpy(workgroup, optarg);
			break;
		case 'c':
			pstrcpy(cmdstr, optarg);
			got_pass = True;
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	/* Load command lists */

	add_command_set(rpcclient_commands);
	add_command_set(lsarpc_commands);
	add_command_set(samr_commands);
	add_command_set(spoolss_commands);

	/* Do anything specified with -c */

	if (cmdstr[0]) {
		pstring cmd;
		char *p = cmdstr;
		uint32 result;

		while(next_token(&p, cmd, ";", sizeof(pstring))) {
			result = process_cmd(cmd);
		}

		return 0;
	}

	/* Loop around accepting commands */

	while(1) {
		pstring prompt, cmd;
		uint32 result;

		ZERO_STRUCT(cmd);
		
		slprintf(prompt, sizeof(prompt) - 1, "rpcclient> ");

#if HAVE_READLINE
		cmd = readline(prompt);
#else
		printf("%s", prompt);

		if (!fgets(cmd, sizeof(cmd) - 1, stdin)) {
			break;
		}

		cmd[strlen(cmd) - 1] = '\0';
#endif
		result = process_cmd(cmd);
	}

	return 0;
}
