/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1998
   
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

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "rpc_parse.h"
#include "rpc_client.h"

#ifndef REGISTER
#define REGISTER 0
#endif

extern pstring debugf;
extern pstring global_myname;

extern pstring user_socket_options;

/* found in rpc_client/cli_connect.c */
extern struct user_creds *usr_creds;


extern int DEBUGLEVEL;


#define CNV_LANG(s) dos2unix_format(s,False)
#define CNV_INPUT(s) unix2dos_format(s,True)

static int process_tok(fstring tok);
static uint32 cmd_help(struct client_info *info, int argc, char *argv[]);
static uint32 cmd_quit(struct client_info *info, int argc, char *argv[]);
static uint32 cmd_set(struct client_info *info, int argc, char *argv[]);
static uint32 cmd_use(struct client_info *info, int argc, char *argv[]);

static struct user_creds usr;

struct client_info cli_info;

char **cmd_argv = NULL;
uint32 cmd_argc = 0;

FILE *out_hnd;


static void cmd_set_free(struct command_set *item)
{
	if (item != NULL)
	{
		safe_free(item->name);
	}
	safe_free(item);
}

static struct command_set *cmd_set_dup(const struct command_set *from)
{
	if (from != NULL)
	{
		struct command_set *copy =
			(struct command_set
			 *)malloc(sizeof(struct command_set));
		if (copy != NULL)
		{
			memcpy(copy, from, sizeof(struct command_set));
			if (from->name != NULL)
			{
				copy->name = strdup(from->name);
			}
		}
		return copy;
	}
	return NULL;
}

void free_cmd_set_array(uint32 num_entries, struct command_set **entries)
{
	void (*fn) (void *) = (void (*)(void *))&cmd_set_free;
	free_void_array(num_entries, (void **)entries, *fn);
}

struct command_set *add_cmd_set_to_array(uint32 *len,
					 struct command_set ***array,
					 const struct command_set *cmd)
{
	void *(*fn) (const void *) = (void *(*)(const void *))&cmd_set_dup;
	return (struct command_set *)add_copy_to_array(len,
						       (void ***)array,
						       (const void *)cmd, *fn,
						       False);

}

static struct command_set **commands = NULL;
static uint32 num_commands = 0;

/****************************************************************************
 add in individual command-sets.
 ****************************************************************************/
void add_command_set(const struct command_set *cmds)
{
	while (cmds->fn != NULL)
	{
		add_cmd_set_to_array(&num_commands, &commands, cmds);
		cmds++;
	}
}

/****************************************************************************
 This defines the commands supported by this client
 ****************************************************************************/
static struct command_set general_commands[] = {
	/*
	 * maintenance
	 */

	{
	 "set",
	 cmd_set,
	 "run rpcclient inside rpcclient (change options etc.)",
	 {NULL, NULL}
	},

	{
	 "use",
	 cmd_use,
	 "net use and net view",
	 {NULL, NULL}
	},

	/*
	 * bye bye
	 */

	{
	 "quit",
	 cmd_quit,
	 "logoff the server",
	 {NULL, NULL}
	},
	{
	 "q",
	 cmd_quit,
	 "logoff the server",
	 {NULL, NULL}
	},
	{
	 "exit",
	 cmd_quit,
	 "logoff the server",
	 {NULL, NULL}
	},
	{
	 "bye",
	 cmd_quit,
	 "logoff the server",
	 {NULL, NULL}
	},

	/*
	 * eek!
	 */

	{
	 "help",
	 cmd_help,
	 "[command] give help on a command",
	 {NULL, NULL}
	},
	{
	 "?",
	 cmd_help,
	 "[command] give help on a command",
	 {NULL, NULL}
	},

	/*
	 * shell
	 */

	{
	 "!",
	 NULL,
	 "run a shell command on the local system",
	 {NULL, NULL}
	},

	/*
	 * oop!
	 */

	{
	 "",
	 NULL,
	 NULL,
	 {NULL, NULL}
	}
};


/****************************************************************************
do a (presumably graceful) quit...
****************************************************************************/
static uint32 cmd_quit(struct client_info *info, int argc, char *argv[])
{
#ifdef MEM_MAN
	{
		extern FILE *dbf;
		smb_mem_write_status(dbf);
		smb_mem_write_errors(dbf);
		smb_mem_write_verbose(dbf);
		dbgflush();
	}
#endif

	free_connections();
	exit(0);
}

/****************************************************************************
help
****************************************************************************/
static uint32 cmd_help(struct client_info *info, int argc, char *argv[])
{
	int i = 0, j = 0;

	if (argc > 1)
	{
		if ((i = process_tok(argv[1])) >= 0)
		{
			fprintf(out_hnd, "HELP %s:\n\t%s\n\n",
				commands[i]->name, commands[i]->description);
		}
	}
	else
	{
		for (i = 0; i < num_commands; i++)
		{
			fprintf(out_hnd, "%-15s", commands[i]->name);
			j++;
			if (j == 5)
			{
				fprintf(out_hnd, "\n");
				j = 0;
			}
		}
		if (j != 0)
		{
			fprintf(out_hnd, "\n");
		}
	}
	return 0;
}

/*******************************************************************
  lookup a command string in the list of commands, including 
  abbreviations
  ******************************************************************/
static int process_tok(char *tok)
{
	int i = 0, matches = 0;
	int cmd = 0;
	int tok_len = strlen(tok);

	for (i = 0; i < num_commands; i++)
	{
		if (strequal(commands[i]->name, tok))
		{
			matches = 1;
			cmd = i;
			break;
		}
		else if (strnequal(commands[i]->name, tok, tok_len))
		{
			matches++;
			cmd = i;
		}
	}

	if (matches == 0)
		return (-1);
	else if (matches == 1)
		return (cmd);
	else
		return (-2);
}

/****************************************************************************
  turn command line into command argument array
****************************************************************************/
static BOOL get_cmd_args(char *line)
{
	char *ptr = line;
	pstring tok;
	cmd_argc = 0;
	cmd_argv = NULL;

	/* get the first part of the command */
	if (!next_token(&ptr, tok, NULL, sizeof(tok)))
	{
		return False;
	}

	do
	{
		add_chars_to_array(&cmd_argc, &cmd_argv, tok);
	}
	while (next_token(NULL, tok, NULL, sizeof(tok)));

	add_chars_to_array(&cmd_argc, &cmd_argv, NULL);

	return True;
}

/* command options mask */
static uint32 cmd_set_options = 0xffffffff;

/****************************************************************************
  process commands from the client
****************************************************************************/
static uint32 do_command(struct client_info *info, char *line)
{
	uint32 status = 0x0;
	int i;

	if (!get_cmd_args(line))
		return False;

	if (cmd_argc == 0)
	{
		return False;
	}
	
	i = process_tok(cmd_argv[0]);
	if (i >= 0)
	{
		int argc = ((int)cmd_argc)-1;
		char **argv = cmd_argv;
		optind = 0;

		status = commands[i]->fn(info, argc, argv);
	}
	else if (i == -2)
	{
		fprintf(out_hnd, "%s: command abbreviation ambiguous\n",
			CNV_LANG(cmd_argv[0]));
	}
	else
	{
		fprintf(out_hnd, "%s: command not found\n",
			CNV_LANG(cmd_argv[0]));
	}

	free_char_array(cmd_argc, cmd_argv);

	return status;
}


/****************************************************************************
  process commands from the client
****************************************************************************/
static uint32 process(struct client_info *info, char *cmd_str)
{
	uint32 status = 0;
	pstring line;
	char *cmd = cmd_str;

	if (cmd != NULL)
	{
		while (cmd[0] != '\0')
		{
			char *p;

			if ((p = strchr(cmd, ';')) == 0)
			{
				strncpy(line, cmd, 999);
				line[1000] = '\0';
				cmd += strlen(cmd);
			}
			else
			{
				if (p - cmd > 999)
					p = cmd + 999;
				strncpy(line, cmd, p - cmd);
				line[p - cmd] = '\0';
				cmd = p + 1;
			}

			/* input language code to internal one */
			CNV_INPUT(line);

			status = do_command(info, line);
			if (status == 0x0)
			{
				continue;
			}
		}
	}
	else
	{
		while (!feof(stdin))
		{
#ifdef HAVE_LIBREADLINE
			char *ret_line;
#endif
			pstring pline;
			BOOL at_sym = False;
			pline[0] = 0;
			safe_strcat(pline, "[", sizeof(pline) - 1);
			if (usr.ntc.domain[0] != 0)
			{
				safe_strcat(pline, usr.ntc.domain,
					    sizeof(pline) - 1);
				safe_strcat(pline, "\\", sizeof(pline) - 1);
				at_sym = True;
			}
			if (usr.ntc.user_name[0] != 0)
			{
				safe_strcat(pline, usr.ntc.user_name,
					    sizeof(pline) - 1);
				at_sym = True;
			}
			if (at_sym)
			{
				safe_strcat(pline, "@", sizeof(pline) - 1);
			}

			safe_strcat(pline, cli_info.dest_host,
				    sizeof(pline) - 1);
			safe_strcat(pline, "]$ ", sizeof(pline) - 1);

#ifndef HAVE_LIBREADLINE

			/* display a prompt */
			fprintf(out_hnd, "%s", CNV_LANG(pline));
			fflush(out_hnd);

			cli_use_wait_keyboard();

			/* and get a response */
			if (!fgets(line, 1000, stdin))
			{
				break;
			}

#else /* HAVE_LIBREADLINE */

			if (!(ret_line = readline(pline)))
				break;
			safe_free(ret_line);

			/* Copy read line to samba buffer */

			pstrcpy(line, rl_line_buffer);

			/* Add to history */

			if (strlen(line) > 0)
				add_history(line);
#endif
			/* input language code to internal one */
			CNV_INPUT(line);

			/* special case - first char is ! */
			if (*line == '!')
			{
				system(line + 1);
				continue;
			}

			fprintf(out_hnd, "%s\n", line);

			status = do_command(info, line);
			if (status == 0x0)
			{
				continue;
			}
		}
	}
	return status;
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
	fprintf(out_hnd,
		"Usage: %s [\\server] [password] [-U user] -[W domain] [-l log] ",
		pname);

	fprintf(out_hnd, "\nVersion %s\n", VERSION);
	fprintf(out_hnd, "\t-d debuglevel         set the debuglevel\n");
	fprintf(out_hnd,
		"\t-S <\\>server         Server to connect to (\\. or . for localhost)\n");
	fprintf(out_hnd,
		"\t-l log basename.      Basename for log/debug files\n");
	fprintf(out_hnd,
		"\t-n netbios name.      Use this name as my netbios name\n");
	fprintf(out_hnd,
		"\t-N                    don't ask for a password\n");
	fprintf(out_hnd,
		"\t-m max protocol       set the max protocol level\n");
	fprintf(out_hnd,
		"\t-I dest IP            use this IP to connect to\n");
	fprintf(out_hnd,
		"\t-E                    write messages to stderr instead of stdout\n");
	fprintf(out_hnd,
		"\t-U username           set the network username\n");
	fprintf(out_hnd,
		"\t-U username%%pass      set the network username and password\n");
	fprintf(out_hnd, "\t-W domain             set the domain name\n");
	fprintf(out_hnd,
		"\t-c 'command string'   execute semicolon separated commands\n");
	fprintf(out_hnd,
		"\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n");
	fprintf(out_hnd, "\n");
}

#ifdef HAVE_LIBREADLINE

/****************************************************************************
GNU readline completion functions
****************************************************************************/

/* Complete an rpcclient command */

static char *complete_cmd(char *text, int state)
{
	static int cmd_index;
	char *name;

	/* Initialise */

	if (state == 0)
	{
		cmd_index = 0;
	}

	/* Return the next name which partially matches the list of commands */

	while ((cmd_index < num_commands)
	       && (strlen(name = commands[cmd_index++]->name) > 0))
	{
		if (strncmp(name, text, strlen(text)) == 0)
		{
			return strdup(name);
		}
	}

	return NULL;
}

/* Main completion function */

static char **completion_fn(char *text, int start, int end)
{
	pstring cmd_partial;
	int cmd_index;
	int num_words;

	int i;
	char lastch = ' ';

	(void)get_cmd_args(rl_line_buffer);

	safe_strcpy(cmd_partial, rl_line_buffer,
		    MAX(sizeof(cmd_partial), end) - 1);

	/* Complete rpcclient command */

	if (start == 0)
	{
		return completion_matches(text, complete_cmd);
	}

	/* Count # of words in command */

	num_words = 0;
	for (i = 0; i <= end; i++)
	{
		if ((rl_line_buffer[i] != ' ') && (lastch == ' '))
		{
			num_words++;
		}
		lastch = rl_line_buffer[i];
	}

	if (rl_line_buffer[end] == ' ')
		num_words++;

	/* Work out which command we are completing for */

	for (cmd_index = 0; cmd_index < num_commands; cmd_index++)
	{

		/* Check each command in array */

		if (strncmp(rl_line_buffer, commands[cmd_index]->name,
			    strlen(commands[cmd_index]->name)) == 0)
		{

			/* Call appropriate completion function */

			if (num_words == 2 || num_words == 3)
			{
				char *(*fn) (char *, int);
				fn =
					commands[cmd_index]->compl_args
					[num_words - 2];
				if (fn != NULL)
				{
					return completion_matches(text, fn);
				}
			}
		}
	}

	/* Eeek! */

	return NULL;
}

/* To avoid filename completion being activated when no valid
   completions are found, we assign this stub completion function
   to the rl_completion_entry_function variable. */

static char *complete_cmd_null(char *text, int state)
{
	return NULL;
}

#endif /* HAVE_LIBREADLINE */

static void set_user_password(struct ntuser_creds *u,
			      BOOL got_pass, char *password)
{
	/* set the password cache info */
	if (got_pass)
	{
		if (password == NULL)
		{
			DEBUG(10, ("set_user_password: NULL pwd\n"));
			pwd_set_nullpwd(&(u->pwd));
		}
		else
		{
			/* generate 16 byte hashes */
			DEBUG(10, ("set_user_password: generate\n"));
			pwd_make_lm_nt_16(&(u->pwd), password);
		}
	}
	else
	{
		DEBUG(10, ("set_user_password: read\n"));
		pwd_read(&(u->pwd), "Enter Password:", True);
	}
}

static uint32 cmd_use(struct client_info *info, int argc, char *argv[])
{
	int opt;
	BOOL net_use = False;
	BOOL net_use_add = True;
	BOOL force_close = False;
	fstring dest_host;
	fstring srv_name;
	BOOL null_pwd = False;
	BOOL got_pwd = False;
	pstring password;


	if (usr_creds != NULL)
	{
		copy_nt_creds(&usr.ntc, &usr_creds->ntc);
	}
	else
	{
		copy_nt_creds(&usr.ntc, NULL);
	}

	pstrcpy(dest_host, cli_info.dest_host);
	pstrcpy(usr.ntc.user_name, optarg);
	info->reuse = False;

	if (argc <= 1)
	{
		report(out_hnd,
		       "net [\\\\Server] [-U user%%pass] [-W domain] [-d] [-f]\n");
		report(out_hnd, "    -d     Deletes a connection\n");
		report(out_hnd, "    -f     Forcibly deletes a connection\n");
		report(out_hnd, "net -u     Shows all connections\n");
		return 0;
	}

	if (argc > 1 && (*argv[1] != '-'))
	{
		if (strnequal("\\\\", argv[1], 2) ||
		    strnequal("//", argv[1], 2))
		{
			pstrcpy(dest_host, argv[1] + 2);
		}
		argc--;
		argv++;
	}

	while ((opt = getopt(argc, argv, "udU:W:")) != EOF)
	{
		switch (opt)
		{
			case 'u':
			{
				net_use = True;
				break;
			}

			case 'U':
			{
				char *lp;
				pstrcpy(usr.ntc.user_name, optarg);
				if ((lp = strchr(usr.ntc.user_name, '%')))
				{
					*lp = 0;
					pstrcpy(password, lp + 1);
					memset(strchr(optarg, '%') + 1, 'X',
					       strlen(password));
					got_pwd = True;
				}
				if (usr.ntc.user_name[0] == 0
				    && password[0] == 0)
				{
					null_pwd = True;
				}
				break;
			}

			case 'N':
			{
				null_pwd = True;
			}
			case 'W':
			{
				pstrcpy(usr.ntc.domain, optarg);
				break;
			}

			case 'd':
			{
				net_use_add = False;
				break;
			}

			case 'f':
			{
				force_close = True;
				break;
			}

			default:
			{
				report(out_hnd,
				       "net -S \\server [-U user%%pass] [-W domain] [-d] [-f]\n");
				report(out_hnd, "net -u\n");
				break;
			}
		}
	}

	if (strnequal("\\\\", dest_host, 2))
	{
		fstrcpy(srv_name, dest_host);
	}
	else
	{
		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, dest_host);
	}
	strupper(srv_name);

	if (net_use)
	{
		int i;
		uint32 num_uses;
		struct use_info **use;
		cli_net_use_enum(&num_uses, &use);

		if (num_uses == 0)
		{
			report(out_hnd, "No connections\n");
		}
		else
		{
			report(out_hnd, "Connections:\n");

			for (i = 0; i < num_uses; i++)
			{
				if (use[i] != NULL && use[i]->connected)
				{
					report(out_hnd, "Server:\t%s\t",
					       use[i]->srv_name);
					report(out_hnd, "Key:\t[%d,%x]\t",
					       use[i]->key.pid,
					       use[i]->key.vuid);
					report(out_hnd, "User:\t%s\t",
					       use[i]->user_name);
					report(out_hnd, "Domain:\t%s\n",
					       use[i]->domain);
				}
			}
		}
	}
	else if (net_use_add)
	{
		BOOL isnew;
		if (null_pwd)
		{
			set_user_password(&usr.ntc, True, NULL);
		}
		else
		{
			set_user_password(&usr.ntc, got_pwd, password);
		}

		/* paranoia: destroy the local copy of the password */
		ZERO_STRUCT(password);

		report(out_hnd, "Server:\t%s:\tUser:\t%s\tDomain:\t%s\n",
		       srv_name, usr.ntc.user_name, usr.ntc.domain);
		report(out_hnd, "Connection:\t");

		if (cli_net_use_add(srv_name, &usr.ntc, 
				    info->reuse, &isnew) != NULL)
		{
			report(out_hnd, "OK\n");
		}
		else
		{
			report(out_hnd, "FAILED\n");
		}
	}
	else
	{
		BOOL closed;
		report(out_hnd, "Server:\t%s:\tUser:\t%s\tDomain:\t%s\n",
		       srv_name, usr.ntc.user_name, usr.ntc.domain);
		report(out_hnd, "Connection:\t");

		if (!cli_net_use_del(srv_name, &usr.ntc,
				     force_close, &closed))
		{
			report(out_hnd, ": Does not exist\n");
		}
		else if (force_close && closed)
		{
			report(out_hnd, ": Forcibly terminated\n");
		}
		else if (closed)
		{
			report(out_hnd, ": Terminated\n");
		}
		else
		{
			report(out_hnd, ": Unlinked\n");
		}
	}

	/* paranoia: destroy the local copy of the password */
	ZERO_STRUCT(password);

	return 0;
}

/******************************************************************
   allow or disallow automatic connections.  rpctorture, because it
   does not reestablish connections after sys_fork(), fails unless the
   connection is established AFTER the sys_fork()
 ******************************************************************/
static BOOL auto_connect = True;
void cmd_set_no_autoconnect(void)
{
	auto_connect = False;
}

#define CMD_STR 0x1
#define CMD_DBF 0x2
#define CMD_SVC 0x4
#define CMD_TERM 0x8
#define CMD_PASS 0x10
#define CMD_USER 0x20
#define CMD_NOPW 0x40
#define CMD_DBLV 0x80
#define CMD_HELP 0x100
#define CMD_SOCK 0x200
#define CMD_IFACE 0x400
#define CMD_DOM 0x800
#define CMD_IP 0x1000
#define CMD_HOST 0x2000
#define CMD_NAME 0x4000
#define CMD_DBG 0x8000
#define CMD_SCOPE 0x10000
#define CMD_INTER 0x20000

static uint32 cmd_set(struct client_info *info, int argc, char *argv[])
{
	BOOL interactive = True;
	char *cmd_str = NULL;
	int opt;
	extern FILE *dbf;
	extern char *optarg;
	static pstring servicesf = CONFIGFILE;
	pstring term_code;
	pstring password;	/* local copy only, if one is entered */
	fstring srv_name;

	password[0] = 0;
	usr_creds = &usr;
	info->reuse = False;
#ifdef KANJI
	pstrcpy(term_code, KANJI);
#else /* KANJI */
	*term_code = 0;
#endif /* KANJI */

	if (argc > 1 && (*argv[1] != '-'))
	{
		if (strnequal("\\\\", argv[1], 2) ||
		    strnequal("//", argv[1], 2))
		{
			cmd_set_options |= CMD_HOST;
			pstrcpy(cli_info.dest_host, argv[1] + 2);
			strupper(cli_info.dest_host);
		}
		argc--;
		argv++;
	}
	if (argc > 1 && (*argv[1] != '-'))
	{
		cmd_set_options |= CMD_PASS;
		pstrcpy(password, argv[1]);
		memset(argv[1], 'X', strlen(argv[1]));
		argc--;
		argv++;
	}

	while ((opt = getopt(argc, argv,
			     "Rs:O:M:S:i:Nn:d:l:hI:EB:U:L:t:m:W:T:D:c:")) !=
	       EOF)
	{
		switch (opt)
		{
			case 'R':
			{
				info->reuse = True;
				break;
			}

			case 'm':
			{
				/* FIXME ... max_protocol seems to be funny here */

				int max_protocol = 0;
				max_protocol =
					interpret_protocol(optarg,
							   max_protocol);
				fprintf(stderr,
					"max protocol not currently supported\n");
				break;
			}

			case 'O':
			{
				cmd_set_options |= CMD_SOCK;
				pstrcpy(user_socket_options, optarg);
				break;
			}

			case 'S':
			{
				cmd_set_options |= CMD_HOST;
				pstrcpy(cli_info.dest_host, optarg);
				strupper(cli_info.dest_host);
				break;
			}

			case 'U':
			{
				char *lp;
				cmd_set_options |= CMD_USER;
				pstrcpy(usr.ntc.user_name, optarg);
				if ((lp = strchr(usr.ntc.user_name, '%')))
				{
					*lp = 0;
					pstrcpy(password, lp + 1);
					cmd_set_options |= CMD_PASS;
					memset(strchr(optarg, '%') + 1, 'X',
					       strlen(password));
				}
				if (usr.ntc.user_name[0] == 0
				    && password[0] == 0)
				{
					cmd_set_options |= CMD_NOPW;
				}
				break;
			}

			case 'W':
			{
				cmd_set_options |= CMD_DOM;
				pstrcpy(usr.ntc.domain, optarg);
				break;
			}

			case 'E':
			{
				cmd_set_options |= CMD_DBG;
				dbf = stderr;
				break;
			}

			case 'I':
			{
				cmd_set_options |= CMD_IP;
				cli_info.dest_ip = *interpret_addr2(optarg);
				if (zero_ip(cli_info.dest_ip))
				{
					free_connections();
					exit(1);
				}
				break;
			}

			case 'n':
			{
				cmd_set_options |= CMD_NAME;
				fstrcpy(global_myname, optarg);
				break;
			}

			case 'N':
			{
				cmd_set_options |= CMD_NOPW | CMD_PASS;
				break;
			}

			case 'd':
			{
				cmd_set_options |= CMD_DBLV;
				if (*optarg == 'A')
					DEBUGLEVEL = 10000;
				else
					DEBUGLEVEL = atoi(optarg);
				break;
			}

			case 'l':
			{
				cmd_set_options |= CMD_INTER;
				slprintf(debugf, sizeof(debugf) - 1,
					 "%s.client", optarg);
				interactive = False;
				break;
			}

			case 'c':
			{
				cmd_set_options |= CMD_STR;
				cmd_str = optarg;
				break;
			}

			case 'h':
			{
				cmd_set_options |= CMD_HELP;
				usage(argv[0]);
				break;
			}

			case 's':
			{
				cmd_set_options |= CMD_SVC;
				pstrcpy(servicesf, optarg);
				break;
			}

			case 't':
			{
				cmd_set_options |= CMD_TERM;
				pstrcpy(term_code, optarg);
				break;
			}

			default:
			{
				cmd_set_options |= CMD_HELP;
				usage(argv[0]);
				break;
			}
		}
	}

	if (IS_BITS_SET_ALL(cmd_set_options, CMD_INTER))
	{
		setup_logging(debugf, interactive);
		if (!interactive)
			reopen_logs();
	}

	strupper(global_myname);
	fstrcpy(cli_info.myhostname, global_myname);

	if (IS_BITS_SET_ALL(cmd_set_options, CMD_SVC))
	{
		if (!lp_load(servicesf, True, False, False))
		{
			fprintf(stderr,
				"Can't load %s - run testparm to debug it\n",
				servicesf);
		}

	}

	if (IS_BITS_SET_ALL(cmd_set_options, CMD_INTER))
	{
		load_interfaces();
	}

	DEBUG(10, ("cmd_set: options: %x\n", cmd_set_options));

	if (IS_BITS_SET_ALL(cmd_set_options, CMD_HELP))
	{
		return 0;
	}

	if (IS_BITS_SET_ALL(cmd_set_options, CMD_NOPW))
	{
		set_user_password(&usr.ntc, True, NULL);
	}
	else
	{
		set_user_password(&usr.ntc,
				  IS_BITS_SET_ALL(cmd_set_options, CMD_PASS),
				  password);
	}

	/* paranoia: destroy the local copy of the password */
	ZERO_STRUCT(password);

	if (strcmp(cli_info.dest_host, "*") == 0) {
		/* special case - we want the PDC */
		struct in_addr ip;
		if (!resolve_srv_name(cli_info.dest_host, cli_info.dest_host, &ip)) {
			report(out_hnd, "ERROR: Failed to find the PDC\n");
			return 1;
		}
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, cli_info.dest_host);
	strupper(srv_name);


	if (auto_connect && !strequal(srv_name, "\\\\."))
	{
		BOOL isnew;
		report(out_hnd, "Server:\t%s:\tUser:\t%s\tDomain:\t%s\n",
		       srv_name, usr.ntc.user_name, usr.ntc.domain);
		report(out_hnd, "Connection:\t");

		if (cli_net_use_add(srv_name, &usr.ntc, info->reuse,
					&isnew)
		    != NULL)
		{
			report(out_hnd, "OK\n");
		}
		else
		{
			report(out_hnd, "FAILED\n");
		}
		usr_creds = NULL;
	}
	if (cmd_str != NULL)
	{
		return process(&cli_info, cmd_str);
	}

	return 0;
}

static void read_user_env(struct ntuser_creds *u)
{
	pstring password;

	password[0] = 0;

	if (getenv("USER"))
	{
		char *p;
		pstrcpy(u->user_name, getenv("USER"));

		/* modification to support userid%passwd syntax in the USER var
		   25.Aug.97, jdblair@uab.edu */

		if ((p = strchr(u->user_name, '%')))
		{
			*p = 0;
			pstrcpy(password, p + 1);
			memset(strchr(getenv("USER"), '%') + 1, 'X',
			       strlen(password));
		}
		strupper(u->user_name);
	}

	/* modification to support PASSWD environmental var
	   25.Aug.97, jdblair@uab.edu */
	if (getenv("PASSWD"))
	{
		pstrcpy(password, getenv("PASSWD"));
	}

	if (*u->user_name == 0 && getenv("LOGNAME"))
	{
		pstrcpy(u->user_name, getenv("LOGNAME"));
		strupper(u->user_name);
	}

	set_user_password(u, True, password);

	/* paranoia: destroy the local copy of the password */
	ZERO_STRUCT(password);
}

static void readline_init(void)
{
#ifdef HAVE_LIBREADLINE
	/* Initialise GNU Readline */ rl_readline_name = "rpcclient";
	rl_attempted_completion_function = completion_fn;
	rl_completion_entry_function = (Function *) complete_cmd_null;

	/* Initialise history list */

	using_history();

#else
	int x;
	x = 0;			/* stop compiler warnings */
#endif /* HAVE_LIBREADLINE */
}

/****************************************************************************
  main program
****************************************************************************/
int command_main(int argc, char *argv[])
{
	uint32 status;
	mode_t myumask = 0755;
	char progname[255], path[255], *s;
	pstring msg;

	DEBUGLEVEL = 2;

	charset_initialise();
	add_command_set(general_commands);

	copy_user_creds(&usr, NULL);

	usr_creds = &usr;
	usr.ptr_ntc = 1;

	out_hnd = stdout;

	strncpy(path, argv[0], 255);
	for (s = strtok(path, "/"); s; s = strtok(NULL, "/"))
		fstrcpy(progname, s);

	slprintf(debugf, sizeof(debugf) - 1,
		 "%s/log.%s", LOGFILEBASE, progname);

	pstrcpy(usr.ntc.domain, "");
	pstrcpy(usr.ntc.user_name, "");

	pstrcpy(cli_info.myhostname, "");
	pstrcpy(cli_info.dest_host, "");
	cli_info.dest_ip.s_addr = 0;

	ZERO_STRUCT(cli_info.dom.level3_sid);
	ZERO_STRUCT(cli_info.dom.level5_sid);
	fstrcpy(cli_info.dom.level3_dom, "");
	fstrcpy(cli_info.dom.level5_dom, "");

	readline_init();
	TimeInit();
	init_connections();

	myumask = umask(0);
	umask(myumask);

	if (!get_myname(global_myname))
	{
		fprintf(stderr, "Failed to get my hostname.\n");
	}

	if (argc < 2)
	{
		usage(argv[0]);
		free_connections();
		exit(1);
	}

	read_user_env(&usr.ntc);

	cmd_set_options &= ~CMD_HELP;
	cmd_set_options &= ~CMD_STR;
	cmd_set_options &= ~CMD_NOPW;
	cmd_set_options &= ~CMD_USER;
	cmd_set_options &= ~CMD_PASS;

	codepage_initialise(lp_client_code_page());

	status = cmd_set(&cli_info, argc, argv);

	if (IS_BITS_SET_SOME(cmd_set_options, CMD_HELP|CMD_STR))
	{
		free_connections();
		get_safe_nt_error_msg(status, msg, sizeof(msg));

		report(out_hnd, "Exit Status: %s\n", msg);
		/* unix only has 8 bit error codes - blergh */
		exit(status & 0xFF);
	}

	DEBUG(3, ("%s client started (version %s)\n",
		  timestring(False), VERSION));

	status = process(&cli_info, NULL);

	free_connections();

	free_cmd_set_array(num_commands, commands);
	num_commands = 0;
	commands = NULL;
	
	get_safe_nt_error_msg(status, msg, sizeof(msg));
	report(out_hnd, "Exit Status: %s\n", msg);

	return status;
}
