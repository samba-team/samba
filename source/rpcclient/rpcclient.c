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

#ifndef REGISTER
#define REGISTER 0
#endif

extern pstring debugf;
extern pstring scope;
extern pstring global_myname;

extern pstring user_socket_options;


extern int DEBUGLEVEL;


#define CNV_LANG(s) dos2unix_format(s,False)
#define CNV_INPUT(s) unix2dos_format(s,True)

static int process_tok(fstring tok);
static void cmd_help(struct client_info *info, int argc, char *argv[]);
static void cmd_quit(struct client_info *info, int argc, char *argv[]);
static void cmd_set (struct client_info *info, int argc, char *argv[]);
static void cmd_net (struct client_info *info, int argc, char *argv[]);

static struct user_creds usr;

static struct client_info cli_info;

static char  **cmd_argv = NULL;
static uint32 cmd_argc = 0;

FILE *out_hnd;

#define COMPL_NONE 0
#define COMPL_REGKEY 1
#define COMPL_SAMUSR 3
#define COMPL_SAMGRP 4
#define COMPL_SAMALS 5
#define COMPL_SVCLST 6
#define COMPL_PRTLST 7

/****************************************************************************
 This defines the commands supported by this client
 ****************************************************************************/
struct command_set commands[] = 
{
	/*
	 * eventlog
	 */

	{
		"eventlog",
		cmd_eventlog,
		"list the events",
		{COMPL_NONE, COMPL_NONE}
	},

	/*
	 * service control
	 */

	{
		"svcenum",
		cmd_svc_enum,
		"[-i] Lists Services Manager",
		{COMPL_NONE, COMPL_NONE}
	},

	{
		"svcinfo",
		cmd_svc_info,
		"<service> Service Information",
		{COMPL_SVCLST, COMPL_NONE}
	},

	{
		"svcstart",
		cmd_svc_start,
		"<service> [arg 0] [arg 1] ... Start Service",
		{COMPL_SVCLST, COMPL_NONE}
	},

	{
		"svcset",
		cmd_svc_set,
		"<service> Test Set Service",
		{COMPL_SVCLST, COMPL_NONE}
	},

	{
		"svcstop",
		cmd_svc_stop,
		"<service> Stop Service",
		{COMPL_SVCLST, COMPL_NONE}
	},

	/*
	 * scheduler
	 */

	{
		"at",
		cmd_at,
		"Scheduler control (at /? for syntax)",
		{COMPL_NONE, COMPL_NONE}
	},

	/*
	 * registry
	 */

	{
		"regenum",
		cmd_reg_enum,
		"<keyname> Registry Enumeration (keys, values)",
		{COMPL_REGKEY, COMPL_NONE}
	},
	{
		"regdeletekey",
		cmd_reg_delete_key,
		"<keyname> Registry Key Delete",
		{COMPL_REGKEY, COMPL_NONE}
	},
	{
		"regcreatekey",
		cmd_reg_create_key,
		"<keyname> [keyclass] Registry Key Create",
		{COMPL_REGKEY, COMPL_NONE}
	},
	{
		"shutdown",
		cmd_reg_shutdown,
		"[-m message] [-t timeout] [-r or --reboot] [-f or --force-close] Remote Shutdown",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"regqueryval",
		cmd_reg_query_info,
		"<valname> Registry Value Query",
		{COMPL_REGKEY, COMPL_NONE}
	},
	{
		"regquerykey",
		cmd_reg_query_key,
		"<keyname> Registry Key Query",
		{COMPL_REGKEY, COMPL_NONE}
	},
	{
		"regdeleteval",
		cmd_reg_delete_val,
		"<valname> Registry Value Delete",
		{COMPL_REGKEY, COMPL_REGKEY}
	},
	{
		"regcreateval",
		cmd_reg_create_val,
		"<valname> <valtype> <value> Registry Key Create",
		{COMPL_REGKEY, COMPL_NONE}
	},
	{
		"reggetsec",
		cmd_reg_get_key_sec,
		"<keyname> Registry Key Security",
		{COMPL_REGKEY, COMPL_NONE}
	},
	{
		"regtestsec",
		cmd_reg_test_key_sec,
		"<keyname> Test Registry Key Security",
		{COMPL_REGKEY, COMPL_NONE}
	},

	/*
	 * printer testing
	 */

	{
		"spoolenum",
		cmd_spoolss_enum_printers,
		"Enumerate Printers",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"spooljobs",
		cmd_spoolss_enum_jobs,
		"<printer name> Enumerate Printer Jobs",
		{COMPL_PRTLST, COMPL_NONE}
	},
	{
		"spoolopen",
		cmd_spoolss_open_printer_ex,
		"<printer name> Spool Printer Open Test",
		{COMPL_PRTLST, COMPL_NONE}
	},
	/*
	 * server
	 */
	{
		"time",
		cmd_time,
		"Display remote time",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"brsinfo",
		cmd_brs_query_info,
		"Browser Query Info",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"wksinfo",
		cmd_wks_query_info,
		"Workstation Query Info",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"srvinfo",
		cmd_srv_query_info,
		"Server Query Info",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"srvsessions",
		cmd_srv_enum_sess,
		"List sessions on a server",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"srvshares",
		cmd_srv_enum_shares,
		"List shares on a server",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"srvtransports",
		cmd_srv_enum_tprt,
		"List transports on a server",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"srvconnections",
		cmd_srv_enum_conn,
		"List connections on a server",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"srvfiles",
		cmd_srv_enum_files,
		"List files on a server",
		{COMPL_NONE, COMPL_NONE}
	},

	/*
	 * lsa
	 */

	{
		"lsaquery",
		cmd_lsa_query_info,
		"Query Info Policy (domain member or server)",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"lsaenumdomains",
		cmd_lsa_enum_trust_dom,
		"Enumerate Trusted Domains",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"lookupsids",
		cmd_lsa_lookup_sids,
		"Resolve names from SIDs",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"lookupnames",
		cmd_lsa_lookup_names,
		"Resolve SIDs from names",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"querysecret",
		cmd_lsa_query_secret,
		"LSA Query Secret (developer use)",
		{COMPL_NONE, COMPL_NONE}
	},

	/*
	 * netlogon
	 */

	{
		"ntlogin",
		cmd_netlogon_login_test,
		"[[DOMAIN\\]username] [password] NT Domain login test",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"domtrust",
		cmd_netlogon_domain_test,
		"<domain> NT Inter-Domain test",
		{COMPL_NONE, COMPL_NONE}
	},

	/*
	 * sam
	 */

	{
		"lookupdomain",
		cmd_sam_lookup_domain,
		"Obtain SID for a local domain",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"samlookupnames",
		cmd_sam_lookup_names,
		"Lookup Names in SAM",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"enumusers",
		cmd_sam_enum_users,
		"SAM User Database Query (experimental!)",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"addgroupmem",
		cmd_sam_add_groupmem,
		"<group rid> [user] [user] ... SAM Add Domain Group Member",
		{COMPL_SAMGRP, COMPL_SAMUSR}
	},

	{
		"addaliasmem",
		cmd_sam_add_aliasmem,
		"<alias rid> [member sid1] [member sid2] ... SAM Add Domain Alias Member",
		{COMPL_SAMALS, COMPL_NONE}
	},
	{
		"delgroupmem",
		cmd_sam_del_groupmem,
		"<group rid> [user] [user] ... SAM Delete Domain Group Member",
		{COMPL_SAMGRP, COMPL_SAMUSR}
	},
	{
		"delaliasmem",
		cmd_sam_del_aliasmem,
		"<alias rid> [member sid1] [member sid2] ... SAM Delete Domain Alias Member",
		{COMPL_SAMALS, COMPL_NONE}
	},
	{
		"creategroup",
		cmd_sam_create_dom_group,
		"SAM Create Domain Group",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"createalias",
		cmd_sam_create_dom_alias,
		"SAM Create Domain Alias",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"createuser",
		cmd_sam_create_dom_user,
		"<username> SAM Create Domain User",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"delgroup",
		cmd_sam_delete_dom_group,
		"SAM Delete Domain Group",
		{COMPL_SAMGRP, COMPL_NONE}
	},
	{
		"delalias",
		cmd_sam_delete_dom_alias,
		"SAM Delete Domain Alias",
		{COMPL_SAMALS, COMPL_NONE}
	},
	{
		"ntpass",
		cmd_sam_ntchange_pwd,
		"NT SAM Password Change",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"samuserset2",
		cmd_sam_set_userinfo2,
		"<username> [-s acb_bits] SAM User Set Info 2 (experimental!)",
		{COMPL_SAMUSR, COMPL_NONE}
	},
	{
		"samuserset",
		cmd_sam_set_userinfo,
		"<username> [-p password] SAM User Set Info (experimental!)",
		{COMPL_SAMUSR, COMPL_NONE}
	},
	{
		"samuser",
		cmd_sam_query_user,
		"<username> [-g] [-u] [-a] SAM User Query (experimental!)",
		{COMPL_SAMUSR, COMPL_NONE}
	},
	{
		"samgroup",
		cmd_sam_query_group,
		"<groupname> SAM Group Query (experimental!)",
		{COMPL_SAMGRP, COMPL_NONE}
	},
	{
		"samalias",
		cmd_sam_query_alias,
		"<aliasname> SAM Alias Query",
		{COMPL_SAMALS, COMPL_NONE}
	},
	{
		"samaliasmem",
		cmd_sam_query_aliasmem,
		"<aliasname> SAM Alias Members",
		{COMPL_SAMALS, COMPL_NONE}
	},
	{
		"samgroupmem",
		cmd_sam_query_groupmem,
		"SAM Group Members",
		{COMPL_SAMGRP, COMPL_NONE}
	},
	{
		"samtest",
		cmd_sam_test      ,
		"SAM User Encrypted RPC test (experimental!)",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"enumaliases",
		cmd_sam_enum_aliases,
		"SAM Aliases Database Query (experimental!)",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"enumdomains",
		cmd_sam_enum_domains,
		"SAM Domains Database Query (experimental!)",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"enumgroups",
		cmd_sam_enum_groups,
		"SAM Group Database Query (experimental!)",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"dominfo",
		cmd_sam_query_dominfo,
		"SAM Query Domain Info",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"dispinfo",
		cmd_sam_query_dispinfo,
		"SAM Query Display Info",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"samsync",
		cmd_sam_sync,
		"SAM Synchronization Test (experimental)",
		{COMPL_NONE, COMPL_NONE}
	},

	/* maintenance */

	{
		"set",
		cmd_set,
		"run rpcclient inside rpcclient (change options etc.)",
		{COMPL_NONE, COMPL_NONE}
	},

	{
		"net",
		cmd_net,
		"net use and net view",
		{COMPL_NONE, COMPL_NONE}
	},
	/*
	 * bye bye
	 */

	{
		"quit",
		cmd_quit,
		"logoff the server",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"q",
		cmd_quit,
		"logoff the server",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"exit",
		cmd_quit,
		"logoff the server",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"bye",
		cmd_quit,
		"logoff the server",
		{COMPL_NONE, COMPL_NONE}
	},

	/*
	 * eek!
	 */

	{
		"help",
		cmd_help,
		"[command] give help on a command",
		{COMPL_NONE, COMPL_NONE}
	},
	{
		"?",
		cmd_help,
		"[command] give help on a command",
		{COMPL_NONE, COMPL_NONE}
	},

	/*
	 * shell
	 */

	{
		"!",
		NULL,
		"run a shell command on the local system",
		{COMPL_NONE, COMPL_NONE}
	},

	/*
	 * oop!
	 */

	{
		"",
		NULL,
		NULL,
		{COMPL_NONE, COMPL_NONE}
	}
};


/****************************************************************************
do a (presumably graceful) quit...
****************************************************************************/
static void cmd_quit(struct client_info *info, int argc, char *argv[])
{
#ifdef MEM_MAN
	{
		extern FILE* dbf;
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
static void cmd_help(struct client_info *info, int argc, char *argv[])
{
  int i=0,j;

  if (argc > 1)
    {
      if ((i = process_tok(argv[1])) >= 0)
	fprintf(out_hnd, "HELP %s:\n\t%s\n\n",commands[i].name,commands[i].description);		    
    }
  else
    while (commands[i].description)
      {
	for (j=0; commands[i].description && (j<5); j++) {
	  fprintf(out_hnd, "%-15s",commands[i].name);
	  i++;
	}
	fprintf(out_hnd, "\n");
      }
}

/*******************************************************************
  lookup a command string in the list of commands, including 
  abbreviations
  ******************************************************************/
static int process_tok(char *tok)
{
  int i = 0, matches = 0;
  int cmd=0;
  int tok_len = strlen(tok);
  
  while (commands[i].fn != NULL)
    {
      if (strequal(commands[i].name,tok))
	{
	  matches = 1;
	  cmd = i;
	  break;
	}
      else if (strnequal(commands[i].name, tok, tok_len))
	{
	  matches++;
	  cmd = i;
	}
      i++;
    }
  
  if (matches == 0)
    return(-1);
  else if (matches == 1)
    return(cmd);
  else
    return(-2);
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
	if (!next_token(&ptr,tok,NULL, sizeof(tok)))
	{
		return False;
	}

	do
	{
		add_chars_to_array(&cmd_argc, &cmd_argv, tok);

	} while (next_token(NULL, tok, NULL, sizeof(tok)));

	return True;
}

/* command options mask */
static uint32 cmd_set_options = 0xffffffff;

/****************************************************************************
  process commands from the client
****************************************************************************/
static BOOL do_command(struct client_info *info, char *line)
{
	int i;

	if (!get_cmd_args(line)) return False;

	if (cmd_argc == 0)
	{
		return False;
	}

	cmd_set_options = 0x0;

	if ((i = process_tok(cmd_argv[0])) >= 0)
	{
		int argc = (int)cmd_argc;
		char **argv = cmd_argv;
		optind = 0;

		commands[i].fn(info, argc, argv);
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

	return True;
}


/****************************************************************************
  process commands from the client
****************************************************************************/
static BOOL process( struct client_info *info, char *cmd_str)
{
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
				if (p - cmd > 999) p = cmd + 999;
				strncpy(line, cmd, p - cmd);
				line[p - cmd] = '\0';
				cmd = p + 1;
			}

			/* input language code to internal one */
			CNV_INPUT (line);

			if (!do_command(info, line)) continue;
		}
	}
	else while (!feof(stdin))
	{
	        pstring pline;
		BOOL at_sym = False;
		pline[0] = 0;
		safe_strcat(pline, "[", sizeof(pline)-1);
		if (usr.ntc.domain[0] != 0)
		{
			safe_strcat(pline, usr.ntc.domain, sizeof(pline)-1);
			safe_strcat(pline, "\\", sizeof(pline)-1);
			at_sym = True;
		}
		if (usr.ntc.user_name[0] != 0)
		{
			safe_strcat(pline, usr.ntc.user_name, sizeof(pline)-1);
			at_sym = True;
		}
		if (at_sym)
		{
			safe_strcat(pline, "@", sizeof(pline)-1);
		}
	
		safe_strcat(pline, cli_info.dest_host, sizeof(pline)-1);
		safe_strcat(pline, "]$ ", sizeof(pline)-1);

#ifndef HAVE_LIBREADLINE

		/* display a prompt */
		fprintf(out_hnd, "%s", CNV_LANG(pline));
		fflush(out_hnd);

		cli_use_wait_keyboard();

		/* and get a response */
		if (!fgets(line,1000,stdin))
		{
			break;
		}

#else /* HAVE_LIBREADLINE */

		if (!readline(pline))
		    break;

		/* Copy read line to samba buffer */

		pstrcpy(line, rl_line_buffer);

		/* Add to history */

		if (strlen(line) > 0) 
		    add_history(line);
#endif
		/* input language code to internal one */
		CNV_INPUT (line);

		/* special case - first char is ! */
		if (*line == '!')
		{
			system(line + 1);
			continue;
		}

		fprintf(out_hnd, "%s\n", line);

		if (!do_command(info, line)) continue;
	}

	return(True);
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  fprintf(out_hnd, "Usage: %s [password] [-S server] [-U user] -[W domain] [-l log] ",
	   pname);

  fprintf(out_hnd, "\nVersion %s\n",VERSION);
  fprintf(out_hnd, "\t-d debuglevel         set the debuglevel\n");
  fprintf(out_hnd, "\t-S server             connect to \\\\server\\IPC$ \n");
  fprintf(out_hnd, "\t-l log basename.      Basename for log/debug files\n");
  fprintf(out_hnd, "\t-n netbios name.      Use this name as my netbios name\n");
  fprintf(out_hnd, "\t-N                    don't ask for a password\n");
  fprintf(out_hnd, "\t-m max protocol       set the max protocol level\n");
  fprintf(out_hnd, "\t-I dest IP            use this IP to connect to\n");
  fprintf(out_hnd, "\t-E                    write messages to stderr instead of stdout\n");
  fprintf(out_hnd, "\t-U username           set the network username\n");
  fprintf(out_hnd, "\t-U username%%pass      set the network username and password\n");
  fprintf(out_hnd, "\t-W domain             set the domain name\n");
  fprintf(out_hnd, "\t-c 'command string'   execute semicolon separated commands\n");
  fprintf(out_hnd, "\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n");
  fprintf(out_hnd, "\n");
}

#ifdef HAVE_LIBREADLINE

/****************************************************************************
GNU readline completion functions
****************************************************************************/

/* Complete a remote registry enum */

static uint32 reg_list_len = 0;
static char **reg_name = NULL;

static void reg_init(int val, const char *full_keyname, int num)
{
	switch (val)
	{
		case 0:
		{
			free_char_array(reg_list_len, reg_name);
			reg_list_len = 0;
			reg_name = NULL;
			break;
		}
		default:
		{
			break;
		}
	}
}

static void reg_key_list(const char *full_name,
				const char *name, time_t key_mod_time)
{
	fstring key_name;
	slprintf(key_name, sizeof(key_name)-1, "%s\\", name);
	add_chars_to_array(&reg_list_len, &reg_name, key_name);
}

static void reg_val_list(const char *full_name,
				const char* name,
				uint32 type,
				const BUFFER2 *value)
{
	add_chars_to_array(&reg_list_len, &reg_name, name);
}

static char *complete_regenum(char *text, int state)
{
	pstring full_keyname;
	static uint32 i = 0;
    
	if (state == 0)
	{
		fstring srv_name;
		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, cli_info.dest_host);
		strupper(srv_name);

		if (cmd_argc >= 2 && cmd_argv != NULL && cmd_argv[1] != NULL)
		{
			char *sep;
			split_server_keyname(srv_name, full_keyname,
			                     cmd_argv[1]);

			sep = strrchr(full_keyname, '\\');
			if (sep != NULL)
			{
				*sep = 0;
			}
		}

		/* Iterate all keys / values */
		if (!msrpc_reg_enum_key(srv_name, full_keyname,
		                   reg_init, reg_key_list, reg_val_list))
		{
			return NULL;
		}

		i = 0;
    	}

	for (; i < reg_list_len; i++)
	{
		if (text == NULL || text[0] == 0 ||
		    strnequal(text, reg_name[i], strlen(text)))
		{
			char *name = strdup(reg_name[i]);
			i++;
			return name;
		}
	}
	
	return NULL;
}


static char *complete_samenum_usr(char *text, int state)
{
	static uint32 i = 0;
	static uint32 num_usrs = 0;
	static struct acct_info *sam = NULL;
    
	if (state == 0)
	{
		fstring srv_name;
		fstring domain;
		fstring sid;
		DOM_SID sid1;
		sid_copy(&sid1, &cli_info.dom.level5_sid);
		sid_to_string(sid, &sid1);
		fstrcpy(domain, cli_info.dom.level5_dom);

		if (sid1.num_auths == 0)
		{
			return NULL;
		}

		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, cli_info.dest_host);
		strupper(srv_name);

		free(sam);
		sam = NULL;
		num_usrs = 0;

		/* Iterate all users */
		if (msrpc_sam_enum_users(srv_name, domain, &sid1, 
		                   &sam, &num_usrs,
		                   NULL, NULL, NULL, NULL) == 0)
		{
			return NULL;
		}

		i = 0;
    	}

	for (; i < num_usrs; i++)
	{
		char *usr_name = sam[i].acct_name;
		if (text == NULL || text[0] == 0 ||
		    strnequal(text, usr_name, strlen(text)))
		{
			char *name = strdup(usr_name);
			i++;
			return name;
		}
	}
	
	return NULL;
}

static char *complete_samenum_als(char *text, int state)
{
	static uint32 i = 0;
	static uint32 num_als = 0;
	static struct acct_info *sam = NULL;
    
	if (state == 0)
	{
		fstring srv_name;
		fstring domain;
		fstring sid;
		DOM_SID sid1;
		sid_copy(&sid1, &cli_info.dom.level5_sid);
		sid_to_string(sid, &sid1);
		fstrcpy(domain, cli_info.dom.level5_dom);

		if (sid1.num_auths == 0)
		{
			return NULL;
		}

		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, cli_info.dest_host);
		strupper(srv_name);

		free(sam);
		sam = NULL;
		num_als = 0;

		/* Iterate all aliases */
		if (msrpc_sam_enum_aliases(srv_name, domain, &sid1, 
		                   &sam, &num_als,
		                   NULL, NULL, NULL) == 0)
		{
			return NULL;
		}

		i = 0;
    	}

	for (; i < num_als; i++)
	{
		char *als_name = sam[i].acct_name;
		if (text == NULL || text[0] == 0 ||
		    strnequal(text, als_name, strlen(text)))
		{
			char *name = strdup(als_name);
			i++;
			return name;
		}
	}
	
	return NULL;
}

static char *complete_samenum_grp(char *text, int state)
{
	static uint32 i = 0;
	static uint32 num_grps = 0;
	static struct acct_info *sam = NULL;
    
	if (state == 0)
	{
		fstring srv_name;
		fstring domain;
		fstring sid;
		DOM_SID sid1;
		sid_copy(&sid1, &cli_info.dom.level5_sid);
		sid_to_string(sid, &sid1);
		fstrcpy(domain, cli_info.dom.level5_dom);

		if (sid1.num_auths == 0)
		{
			return NULL;
		}

		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, cli_info.dest_host);
		strupper(srv_name);

		free(sam);
		sam = NULL;
		num_grps = 0;

		/* Iterate all groups */
		if (msrpc_sam_enum_groups(srv_name,
		                   domain, &sid1, 
		                   &sam, &num_grps,
		                   NULL, NULL, NULL) == 0)
		{
			return NULL;
		}

		i = 0;
    	}

	for (; i < num_grps; i++)
	{
		char *grp_name = sam[i].acct_name;
		if (text == NULL || text[0] == 0 ||
		    strnequal(text, grp_name, strlen(text)))
		{
			char *name = strdup(grp_name);
			i++;
			return name;
		}
	}
	
	return NULL;
}

static char *complete_svcenum(char *text, int state)
{
	static uint32 i = 0;
	static uint32 num_svcs = 0;
	static ENUM_SRVC_STATUS *svc = NULL;
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, cli_info.dest_host);
	strupper(srv_name);

    
	if (state == 0)
	{
		free(svc);
		svc = NULL;
		num_svcs = 0;

		/* Iterate all users */
		if (msrpc_svc_enum(srv_name, &svc, &num_svcs,
		                   NULL, NULL) == 0)
		{
			return NULL;
		}

		i = 0;
    	}

	for (; i < num_svcs; i++)
	{
		fstring svc_name;
		unistr_to_ascii(svc_name, svc[i].uni_srvc_name.buffer,
			sizeof(svc_name)-1);

		if (text == NULL || text[0] == 0 ||
		    strnequal(text, svc_name, strlen(text)))
		{
			char *name = strdup(svc_name);
			i++;
			return name;
		}
	}
	
	return NULL;
}

static char *complete_printersenum(char *text, int state)
{
	static uint32 i = 0;
	static uint32 num = 0;
	static PRINTER_INFO_1 **ctr = NULL;
    
	if (state == 0)
	{
		fstring srv_name;
		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, cli_info.dest_host);
		strupper(srv_name);

		free_print1_array(num, ctr);
		ctr = NULL;
		num = 0;

		/* Iterate all users */
		if (!msrpc_spoolss_enum_printers(srv_name,
		                   1, &num, (void***)&ctr,
		                   NULL))
		{
			return NULL;
		}

		i = 0;
    	}

	for (; i < num; i++)
	{
		fstring name;
		unistr_to_ascii(name, ctr[i]->name.buffer,
			sizeof(name)-1);

		if (text == NULL || text[0] == 0 ||
		    strnequal(text, name, strlen(text)))
		{
			char *copy = strdup(name);
			i++;
			return copy;
		}
	}
	
	return NULL;
}

/* Complete an rpcclient command */

static char *complete_cmd(char *text, int state)
{
    static int cmd_index;
    char *name;

    /* Initialise */

    if (state == 0) {
	cmd_index = 0;
    }

    /* Return the next name which partially matches the list of commands */
    
    while (strlen(name = commands[cmd_index++].name) > 0) {
	if (strncmp(name, text, strlen(text)) == 0) {
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
	            MAX(sizeof(cmd_partial),end)-1);

    /* Complete rpcclient command */

    if (start == 0)
	{
	return completion_matches(text, complete_cmd);
    }

    /* Count # of words in command */
    
    num_words = 0;
    for (i = 0; i <= end; i++) {
	if ((rl_line_buffer[i] != ' ') && (lastch == ' '))
	{
		num_words++;
	}
	lastch = rl_line_buffer[i];
    }
    
    if (rl_line_buffer[end] == ' ')
	num_words++;

    /* Work out which command we are completing for */

    for (cmd_index = 0; strcmp(commands[cmd_index].name, "") != 0; 
	 cmd_index++) {
	
	/* Check each command in array */
	
	if (strncmp(rl_line_buffer, commands[cmd_index].name,
		    strlen(commands[cmd_index].name)) == 0) {
	    
	    /* Call appropriate completion function */

      if (num_words == 2 || num_words == 3)
      {
        switch (commands[cmd_index].compl_args[num_words - 2])
        {

        case COMPL_SAMGRP:
          return completion_matches(text, complete_samenum_grp);

        case COMPL_SAMALS:
          return completion_matches(text, complete_samenum_als);

        case COMPL_SAMUSR:
          return completion_matches(text, complete_samenum_usr);

        case COMPL_SVCLST:
          return completion_matches(text, complete_svcenum);

        case COMPL_PRTLST:
          return completion_matches(text, complete_printersenum);

        case COMPL_REGKEY:
          return completion_matches(text, complete_regenum);

        default:
            /* An invalid completion type */
            break;
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
			DEBUG(10,("set_user_password: NULL pwd\n"));
			pwd_set_nullpwd(&(u->pwd));
		}
		else
		{
			/* generate 16 byte hashes */
			DEBUG(10,("set_user_password: generate\n"));
			pwd_make_lm_nt_16(&(u->pwd), password);
		}
	}
	else 
	{
		DEBUG(10,("set_user_password: read\n"));
		pwd_read(&(u->pwd), "Enter Password:", True);
	}
}

static void cmd_net(struct client_info *info, int argc, char *argv[])
{
	int opt;
	BOOL net_use = False;
	BOOL net_use_add = True;
	BOOL force_close = False;
	struct ntuser_creds u;
	fstring dest_host;
	fstring srv_name;
	BOOL null_pwd = False;
	BOOL got_pwd = False;
	pstring password;
	extern struct user_creds *usr_creds;

	copy_nt_creds(&u, &usr_creds->ntc);

	pstrcpy(dest_host, cli_info.dest_host);
	pstrcpy(u.user_name,optarg);
	info->reuse = False;

	if (argc <= 1)
	{
		report(out_hnd, "net -S \\server [-U user%%pass] [-W domain] [-d] [-f]\n");
		report(out_hnd, "net -u\n");
	}

	while ((opt = getopt(argc, argv, "udS:U:W:")) != EOF)
	{
		switch (opt)
		{
			case 'u':
			{
				net_use = True;
				break;
			}

			case 'S':
			{
				pstrcpy(dest_host, optarg);
				break;
			}

			case 'U':
			{
				char *lp;
				pstrcpy(u.user_name,optarg);
				if ((lp=strchr(u.user_name,'%')))
				{
					*lp = 0;
					pstrcpy(password,lp+1);
					memset(strchr(optarg,'%')+1,'X',
					       strlen(password));
					got_pwd = True;
				}
				if (u.user_name[0] == 0 && password[0] == 0)
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
				pstrcpy(u.domain,optarg);
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
				report(out_hnd, "net -S \\server [-U user%%pass] [-W domain] [-d] [-f]\n");
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
		if (null_pwd)
		{
			set_user_password(&u, True, NULL);
		}
		else
		{
			set_user_password(&u, got_pwd, password);
		}

		/* paranoia: destroy the local copy of the password */
		bzero(password, sizeof(password)); 

		report(out_hnd, "Server:\t%s:\tUser:\t%s\tDomain:\t%s\n",
		                 srv_name, u.user_name, u.domain);
		report(out_hnd, "Connection:\t");

		if (cli_net_use_add(srv_name, &u, True, info->reuse) != NULL)
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
		                 srv_name, u.user_name, u.domain);
		report(out_hnd, "Connection:\t");

		if (!cli_net_use_del(srv_name, &u, force_close, &closed))
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
	bzero(password, sizeof(password)); 
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

static void cmd_set(struct client_info *info, int argc, char *argv[])
{
	BOOL interactive = True;
	char *cmd_str = NULL;
	int opt;
	extern FILE *dbf;
	extern char *optarg;
	static pstring servicesf = CONFIGFILE;
	pstring term_code;
	pstring password; /* local copy only, if one is entered */
	extern struct user_creds *usr_creds;

	password[0] = 0;
	usr_creds = &usr;
	info->reuse = False;
#ifdef KANJI
	pstrcpy(term_code, KANJI);
#else /* KANJI */
	*term_code = 0;
#endif /* KANJI */

	if (argc > 1 && *argv[1] != '-')
	{
		if (argc > 1 && (*argv[1] != '-'))
		{
			cmd_set_options |= CMD_PASS;
			pstrcpy(password,argv[1]);  
			memset(argv[1],'X',strlen(argv[1]));
			argc--;
			argv++;
		}
	}

	while ((opt = getopt(argc, argv, "Rs:B:O:M:S:i:Nn:d:l:hI:EB:U:L:t:m:W:T:D:c:")) != EOF)
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
				max_protocol = interpret_protocol(optarg,max_protocol);
				fprintf(stderr, "max protocol not currently supported\n");
				break;
			}

			case 'O':
			{
				cmd_set_options |= CMD_SOCK;
				pstrcpy(user_socket_options,optarg);
				break;	
			}

			case 'S':
			{
				cmd_set_options |= CMD_HOST;
				pstrcpy(cli_info.dest_host,optarg);
				strupper(cli_info.dest_host);
				break;
			}

			case 'B':
			{
				cmd_set_options |= CMD_IFACE;
				iface_set_default(NULL,optarg,NULL);
				break;
			}

			case 'i':
			{
				cmd_set_options |= CMD_SCOPE;
				pstrcpy(scope, optarg);
				break;
			}

			case 'U':
			{
				char *lp;
				cmd_set_options |= CMD_USER;
				pstrcpy(usr.ntc.user_name,optarg);
				if ((lp=strchr(usr.ntc.user_name,'%')))
				{
					*lp = 0;
					pstrcpy(password,lp+1);
					cmd_set_options |= CMD_PASS;
					memset(strchr(optarg,'%')+1,'X',strlen(password));
				}
				if (usr.ntc.user_name[0] == 0 && password[0] == 0)
				{
					cmd_set_options |= CMD_NOPW;
				}
				break;
			}

			case 'W':
			{
				cmd_set_options |= CMD_DOM;
				pstrcpy(usr.ntc.domain,optarg);
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
				slprintf(debugf, sizeof(debugf)-1,
				         "%s.client", optarg);
				interactive = False;
				break;
			}

			case 'c':
			{
				cmd_set_options |= CMD_STR | CMD_PASS;
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
		reopen_logs();
	}

	strupper(global_myname);
	fstrcpy(cli_info.myhostname, global_myname);

	if (IS_BITS_SET_ALL(cmd_set_options, CMD_SVC))
	{
		if (!lp_load(servicesf,True, False, False))
		{
			fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
		}

	}

	if (IS_BITS_SET_ALL(cmd_set_options, CMD_INTER))
	{
		load_interfaces();
	}

	DEBUG(10,("cmd_set: options: %x\n", cmd_set_options));

	if (IS_BITS_SET_ALL(cmd_set_options, CMD_HELP))
	{
		return;
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
	bzero(password, sizeof(password)); 

	if (cmd_str != NULL)
	{
		process(&cli_info, cmd_str);
	}
}

static void read_user_env(struct ntuser_creds *u)
{
	pstring password;

	password[0] = 0;

	if (getenv("USER"))
	{
		char *p;
		pstrcpy(u->user_name,getenv("USER"));

		/* modification to support userid%passwd syntax in the USER var
		25.Aug.97, jdblair@uab.edu */

		if ((p=strchr(u->user_name,'%')))
		{
			*p = 0;
			pstrcpy(password,p+1);
			memset(strchr(getenv("USER"),'%')+1,'X',strlen(password));
		}
		strupper(u->user_name);
	}

	/* modification to support PASSWD environmental var
	   25.Aug.97, jdblair@uab.edu */
	if (getenv("PASSWD"))
	{
		pstrcpy(password,getenv("PASSWD"));
	}

	if (*u->user_name == 0 && getenv("LOGNAME"))
	{
		pstrcpy(u->user_name,getenv("LOGNAME"));
		strupper(u->user_name);
	}

	set_user_password(u, True, password);

	/* paranoia: destroy the local copy of the password */
	bzero(password, sizeof(password)); 
}

void readline_init(void)
{
#ifdef HAVE_LIBREADLINE

	/* Initialise GNU Readline */
	
	rl_readline_name = "rpcclient";
	rl_attempted_completion_function = completion_fn;
	rl_completion_entry_function = (Function *)complete_cmd_null;
	
	/* Initialise history list */
	
	using_history();

#else
	int x;
	x = 0; /* stop compiler warnings */
#endif /* HAVE_LIBREADLINE */
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	extern struct user_creds *usr_creds;
	mode_t myumask = 0755;

	DEBUGLEVEL = 2;

	copy_user_creds(&usr, NULL);

	usr_creds = &usr;
	usr.ptr_ntc = 1;

	out_hnd = stdout;
	fstrcpy(debugf, argv[0]);

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
	charset_initialise();
	init_connections();

	myumask = umask(0);
	umask(myumask);

	if (!get_myname(global_myname, NULL))
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
	cmd_set_options &= ~CMD_NOPW;
	cmd_set_options &= ~CMD_USER;
	cmd_set_options &= ~CMD_PASS;

	codepage_initialise(lp_client_code_page());

	cmd_set(&cli_info, argc, argv);

	if (IS_BITS_SET_ALL(cmd_set_options, CMD_HELP))
	{
		free_connections();
		exit(0);
	}

	DEBUG(3,("%s client started (version %s)\n",timestring(),VERSION));

	process(&cli_info, NULL);

	free_connections();

	return(0);
}
