/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1997
   
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

extern pstring myname;
extern pstring scope;

extern pstring user_socket_options;


extern pstring debugf;
extern int DEBUGLEVEL;


extern file_info def_finfo;

#define CNV_LANG(s) dos2unix_format(s,False)
#define CNV_INPUT(s) unix2dos_format(s,True)

extern int coding_system;

static int process_tok(fstring tok);
static void cmd_help(struct client_info *info);
static void cmd_quit(struct client_info *info);

extern struct cli_state *smb_cli;
extern int smb_tidx;

extern struct cli_state *ipc_cli;
extern int ipc_tidx;

static BOOL setup_term_code (char *code)
{
    int new;
    new = interpret_coding_system (code, UNKNOWN_CODE);
    if (new != UNKNOWN_CODE)
	{
		coding_system = new;
		return True;
    }
    return False;

}


/****************************************************************************
 This defines the commands supported by this client
 ****************************************************************************/
struct
{
  char *name;
  void (*fn)(struct client_info*);
  char *description;
} commands[] = 
{
  {"ntlogin",    cmd_nt_login_test,    "<username> NT Domain login test"},
  {"nltest",     cmd_nltest,           "<server> Net Logon Test"},
  {"lsaquery",   cmd_lsa_query_info,   "<server> Query Info Policy"},
  {"samquery",   cmd_sam_query_users,  "SAM User Database Query"},
  {"message",    cmd_send_message,"<username/workgroup> Send a message"},
  {"shares",     cmd_list_shares, "List shares on a server"},
  {"servers",    cmd_list_servers,"[<workgroup>] [<type, hex>] List known browse servers"},
  {"workgroups", cmd_list_wgps,   "[<workgroup>] [<type, hex>] List known browse workgroup"},
  {"ls",         cmd_dir,         "<mask> list the contents of the current directory"},
  {"dir",        cmd_dir,         "<mask> list the contents of the current directory"},
  {"lcd",        cmd_lcd,         "[directory] change/report the local current working directory"},
  {"cd",         cmd_cd,          "[directory] change/report the remote directory"},
  {"pwd",        cmd_pwd,         "show current remote directory (same as 'cd' with no args)"},
  {"get",        cmd_get,         "<remote name> [local name] get a file"},
  {"mget",       cmd_mget,        "<mask> get all the matching files"},
  {"put",        cmd_put,         "<local name> [remote name] put a file"},
  {"mput",       cmd_mput,        "<mask> put all matching files"},
  {"rename",     cmd_rename,      "<src> <dest> rename some files"},
  {"more",       cmd_more,        "<remote name> view a remote file with your pager"},  
  {"mask",       cmd_select,      "<mask> mask all filenames against this"},
  {"del",        cmd_del,         "<mask> delete all matching files"},
  {"rm",         cmd_del,         "<mask> delete all matching files"},
  {"mkdir",      cmd_mkdir,       "<directory> make a directory"},
  {"md",         cmd_mkdir,       "<directory> make a directory"},
  {"rmdir",      cmd_rmdir,       "<directory> remove a directory"},
  {"rd",         cmd_rmdir,       "<directory> remove a directory"},
  {"pq",         cmd_p_queue_2,   "enumerate the print queue"},
  {"prompt",     cmd_prompt,      "toggle prompting for filenames for mget and mput"},  
  {"recurse",    cmd_recurse,     "toggle directory recursion for mget and mput"},  
  {"translate",  cmd_translate,   "toggle text translation for printing"},  
  {"lowercase",  cmd_lowercase,   "toggle lowercasing of filenames for get"},  
  {"print",      cmd_print,       "<file name> print a file"},
  {"print_mode", cmd_printmode,   "<graphics or text> set the print mode"},
  {"queue",      cmd_queue,       "show the print queue"},
  {"qinfo",      cmd_qinfo,       "show print queue information"},
  {"cancel",     cmd_cancel,      "<jobid> cancel a print queue entry"},
  {"stat",       cmd_stat,        "<file> get info on a file (experimental!)"},
  {"quit",       cmd_quit,        "logoff the server"},
  {"q",          cmd_quit,        "logoff the server"},
  {"exit",       cmd_quit,        "logoff the server"},
  {"newer",      cmd_newer,       "<file> only mget files newer than the specified local file"},
  {"archive",    cmd_archive,     "<level>\n0=ignore archive bit\n1=only get archive files\n2=only get archive files and reset archive bit\n3=get all files and reset archive bit"},
  {"tar",        cmd_tar,         "tar <c|x>[IXbgNa] current directory to/from <file name>" },
  {"blocksize",  cmd_block,       "blocksize <number> (default 20)" },
  {"tarmode",    cmd_tarmode,
     "<full|inc|reset|noreset> tar's behaviour towards archive bits" },
  {"setmode",    cmd_setmode,     "filename <setmode string> change modes of file"},
  {"help",       cmd_help,        "[command] give help on a command"},
  {"?",          cmd_help,        "[command] give help on a command"},
  {"!",          NULL,            "run a shell command on the local system"},
  {"",           NULL,            NULL}
};


/****************************************************************************
do a (presumably graceful) quit...
****************************************************************************/
static void cmd_quit(struct client_info *info)
{
	client_smb_stop();
	client_ipc_stop();
#if 0
	client_nt_stop();
#endif
	exit(0);
}

/****************************************************************************
help
****************************************************************************/
static void cmd_help(struct client_info *info)
{
  int i=0,j;
  fstring buf;

  if (next_token(NULL,buf,NULL))
    {
      if ((i = process_tok(buf)) >= 0)
	DEBUG(0,("HELP %s:\n\t%s\n\n",commands[i].name,commands[i].description));		    
    }
  else
    while (commands[i].description)
      {
	for (j=0; commands[i].description && (j<5); j++) {
	  DEBUG(0,("%-15s",commands[i].name));
	  i++;
	}
	DEBUG(0,("\n"));
      }
}

/*******************************************************************
  lookup a command string in the list of commands, including 
  abbreviations
  ******************************************************************/
static int process_tok(fstring tok)
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
      else if (strnequal(commands[i].name, tok, tok_len+1))
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
wait for keyboard activity, swallowing network packets
****************************************************************************/
#ifdef CLIX
static char wait_keyboard(struct cli_state *cli, int t_idx)
#else
static void wait_keyboard(struct cli_state *cli, int t_idx)
#endif
{
  fd_set fds;
  int selrtn;
  struct timeval timeout;
  
  while (1) 
    {
      FD_ZERO(&fds);
      FD_SET(cli->fd,&fds);
#ifndef CLIX
      FD_SET(fileno(stdin),&fds);
#endif

      timeout.tv_sec = 20;
      timeout.tv_usec = 0;
#ifdef CLIX
      timeout.tv_sec = 0;
#endif
      selrtn = sys_select(&fds,&timeout);
      
#ifndef CLIX
      if (FD_ISSET(fileno(stdin),&fds))
  	return;
#else
      {
	char ch;
	int readret;

    set_blocking(fileno(stdin), False);	
	readret = read_data( fileno(stdin), &ch, 1);
	set_blocking(fileno(stdin), True);
	if (readret == -1)
	  {
	    if (errno != EAGAIN)
	      {
		/* should crash here */
		DEBUG(1,("readchar stdin failed\n"));
	      }
	  }
	else if (readret != 0)
	  {
	    return ch;
	  }
      }
#endif
      if (FD_ISSET(cli->fd,&fds))
  	receive_smb(cli->fd,cli->inbuf,0);
      
	client_check_connection();
  }
}


/****************************************************************************
  process commands from the client
****************************************************************************/
static BOOL process( struct client_info *info, char *cmd_str)
{
  extern FILE *dbf;
  pstring line;
  char *cmd = cmd_str;

  if (cmd[0] != '\0') while (cmd[0] != '\0')
    {
      char *p;
      fstring tok;
      int i;

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
      
      /* and get the first part of the command */
      {
	char *ptr = line;
	if (!next_token(&ptr,tok,NULL)) continue;
      }

      if ((i = process_tok(tok)) >= 0)
	commands[i].fn(info);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n", CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n", CNV_LANG(tok)));
    }
  else while (!feof(stdin))
    {
      fstring tok;
      int i;

      /* display a prompt */
      DEBUG(0,("smb: %s> ", CNV_LANG(info->cur_dir)));
      fflush(dbf);

#ifdef CLIX
      line[0] = wait_keyboard(&smb_cli, smb_tidx);
      /* this might not be such a good idea... */
      if ( line[0] == EOF)
	break;
#else
      wait_keyboard(smb_cli, smb_tidx);
#endif
  
      /* and get a response */
#ifdef CLIX
      fgets( &line[1],999, stdin);
#else
      if (!fgets(line,1000,stdin))
	break;
#endif

      /* input language code to internal one */
      CNV_INPUT (line);

      /* special case - first char is ! */
      if (*line == '!')
	{
	  system(line + 1);
	  continue;
	}
      
      /* and get the first part of the command */
      {
	char *ptr = line;
	if (!next_token(&ptr,tok,NULL)) continue;
      }

      if ((i = process_tok(tok)) >= 0)
	commands[i].fn(info);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n", CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n", CNV_LANG(tok)));
    }
  
  return(True);
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  DEBUG(0,("Usage: %s service <password> [-p port] [-d debuglevel] [-l log] ",
	   pname));

  DEBUG(0,("\nVersion %s\n",VERSION));
  DEBUG(0,("\t-p port               listen on the specified port\n"));
  DEBUG(0,("\t-d debuglevel         set the debuglevel\n"));
  DEBUG(0,("\t-l log basename.      Basename for log/debug files\n"));
  DEBUG(0,("\t-n netbios name.      Use this name as my netbios name\n"));
  DEBUG(0,("\t-N                    don't ask for a password\n"));
  DEBUG(0,("\t-P                    connect to service as a printer\n"));
  DEBUG(0,("\t-M host               send a winpopup message to the host\n"));
  DEBUG(0,("\t-m max protocol       set the max protocol level\n"));
  DEBUG(0,("\t-L host               get a list of shares available on a host\n"));
  DEBUG(0,("\t-I dest IP            use this IP to connect to\n"));
  DEBUG(0,("\t-E                    write messages to stderr instead of stdout\n"));
  DEBUG(0,("\t-U username           set the network username\n"));
  DEBUG(0,("\t-W workgroup          set the workgroup name\n"));
  DEBUG(0,("\t-c command string     execute semicolon separated commands\n"));
  DEBUG(0,("\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n"));
  DEBUG(0,("\t-T<c|x>IXgbNa          command line tar\n"));
  DEBUG(0,("\t-D directory          start from directory\n"));
  DEBUG(0,("\n"));
}

enum client_action
{
	CLIENT_NONE,
	CLIENT_MESSAGE,
	CLIENT_QUERY,
	CLIENT_IPC,
	CLIENT_TAR,
	CLIENT_SVC
};

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	char *pname = argv[0];
	int port = SMB_PORT;
	int opt;
	extern FILE *dbf;
	extern char *optarg;
	extern int optind;
	static pstring servicesf = CONFIGFILE;
	pstring term_code;
	char *p;
	BOOL got_pass = False;
	char *cmd_str="";
	int myumask = 0755;
	enum client_action cli_action = CLIENT_NONE;
	int ret = 0;

	struct client_info cli_info;

	pstring password;
	pstring tmp;

	client_smb_init();
	client_ipc_init();
#if 0
	client_nt_init();
#endif

#ifdef KANJI
	strcpy(term_code, KANJI);
#else /* KANJI */
	*term_code = 0;
#endif /* KANJI */

	DEBUGLEVEL = 2;

	cli_info.put_total_size = 0;
	cli_info.put_total_time_ms = 0;
	cli_info.get_total_size = 0;
	cli_info.get_total_time_ms = 0;

	cli_info.dir_total = 0;
	cli_info.newer_than = 0;
	cli_info.archive_level = 0;
	cli_info.print_mode = 1;

	cli_info.translation = False;
	cli_info.recurse_dir = False;
	cli_info.lowercase = False;
	cli_info.prompt = True;
	cli_info.abort_mget = True;

	cli_info.dest_ip.s_addr = 0;
	cli_info.name_type = 0x20;

	strcpy(cli_info.cur_dir , "\\");
	strcpy(cli_info.file_sel, "");
	strcpy(cli_info.base_dir, "");
	strcpy(cli_info.workgroup, "");
	strcpy(cli_info.username, "");
	strcpy(cli_info.myhostname, "");
	strcpy(cli_info.dest_host, "");

	strcpy(cli_info.svc_type, "A:");
	strcpy(cli_info.share, "");
	strcpy(cli_info.service, "");

	strcpy(cli_info.dom.level3_sid, "");
	strcpy(cli_info.dom.level3_dom, "");
	strcpy(cli_info.dom.level5_sid, "");
	strcpy(cli_info.dom.level5_dom, "");

	cli_info.dom.lsarpc_fnum   = 0xffff;
	cli_info.dom.samr_fnum     = 0xffff;
	cli_info.dom.netlogon_fnum = 0xffff;

	cli_info.tar.blocksize = 20;
	cli_info.tar.attrib = aDIR | aSYSTEM | aHIDDEN;
	cli_info.tar.inc = False;
	cli_info.tar.reset = False;
	cli_info.tar.excl = True;
	cli_info.tar.type = '\0';
	cli_info.tar.cliplist = NULL;
	cli_info.tar.clipn = 0;
	cli_info.tar.tp = 0;
	cli_info.tar.buf_size = 0;
	cli_info.tar.num_files = 0;
	cli_info.tar.bytes_written = 0;
	cli_info.tar.buf = NULL;
	cli_info.tar.handle = 0;

	setup_logging(pname,True);

	TimeInit();
	charset_initialise();

	myumask = umask(0);
	umask(myumask);

	if (getenv("USER"))
	{
		strcpy(cli_info.username,getenv("USER"));

		/* modification to support userid%passwd syntax in the USER var
		25.Aug.97, jdblair@uab.edu */

		if ((p=strchr(cli_info.username,'%')))
		{
			*p = 0;
			strcpy(password,p+1);
			got_pass = True;
			memset(strchr(getenv("USER"),'%')+1,'X',strlen(password));
		}
		strupper(cli_info.username);
	}

	password[0] = 0;

	/* modification to support PASSWD environmental var
	   25.Aug.97, jdblair@uab.edu */
	if (getenv("PASSWD"))
	{
		strcpy(password,getenv("PASSWD"));
	}

	if (*cli_info.username == 0 && getenv("LOGNAME"))
	{
		strcpy(cli_info.username,getenv("LOGNAME"));
		strupper(cli_info.username);
	}

	if (argc < 2)
	{
		usage(pname);
		exit(1);
	}

	if (*argv[1] != '-')
	{

		strcpy(cli_info.service, argv[1]);  
		/* Convert any '/' characters in the service name to '\' characters */
		string_replace( cli_info.service, '/','\\');
		argc--;
		argv++;

		if (count_chars(cli_info.service,'\\') < 3)
		{
			usage(pname);
			printf("\n%s: Not enough '\\' characters in service\n", cli_info.service);
			exit(1);
		}

		/*
		if (count_chars(cli_info.service,'\\') > 3)
		{
			usage(pname);
			printf("\n%s: Too many '\\' characters in service\n", cli_info.service);
			exit(1);
		}
		*/

		if (argc > 1 && (*argv[1] != '-'))
		{
			got_pass = True;
			strcpy(password,argv[1]);  
			memset(argv[1],'X',strlen(argv[1]));
			argc--;
			argv++;
		}
	}

	while ((opt = getopt(argc, argv,"s:B:O:M:S:i:Nn:d:Pp:l:hI:EB:U:L:t:m:W:T:D:c:")) != EOF)
	{
		switch (opt)
		{
			case 'm':
			{
				int max_protocol = interpret_protocol(optarg,max_protocol);
				DEBUG(0,("max protocol not currently supported\n"));
				break;
			}

			case 'O':
			{
				strcpy(user_socket_options,optarg);
				break;	
			}

			case 'S':
			{
				strcpy(cli_info.dest_host,optarg);
				strupper(cli_info.dest_host);
				cli_action = CLIENT_IPC;
				break;
			}

			case 'M':
			{
				cli_info.name_type = 0x03; /* messages sent to NetBIOS name type 0x3 */
				strcpy(cli_info.dest_host,optarg);
				strupper(cli_info.dest_host);
				cli_action = CLIENT_MESSAGE;
				break;
			}

			case 'B':
			{
				iface_set_default(NULL,optarg,NULL);
				break;
			}

			case 'D':
			{
				strcpy(cli_info.base_dir,optarg);
				break;
			}

			case 'T':
			{
				if (tar_parseargs(&cli_info, argc, argv, optarg, optind))
				{
					cli_action = CLIENT_TAR;
				}
				break;
			}

			case 'i':
			{
				strcpy(scope, optarg);
				break;
			}

			case 'L':
			{
				got_pass = True;
				cli_action = CLIENT_QUERY;
				strcpy(cli_info.dest_host,optarg);
				break;
			}

			case 'U':
			{
				char *lp;
				strcpy(cli_info.username,optarg);
				if ((lp=strchr(cli_info.username,'%')))
				{
					*lp = 0;
					strcpy(password,lp+1);
					got_pass = True;
					memset(strchr(optarg,'%')+1,'X',strlen(password));
				}
				break;
			}

			case 'W':
			{
				strcpy(cli_info.workgroup,optarg);
				break;
			}

			case 'E':
			{
				dbf = stderr;
				break;
			}

			case 'I':
			{
				cli_info.dest_ip = *interpret_addr2(optarg);
				if (zero_ip(cli_info.dest_ip))
				{
					exit(1);
				}
				break;
			}
			case 'n':
			{
				strcpy(myname,optarg);
				break;
			}

			case 'N':
			{
				got_pass = True;
				break;
			}

			case 'P':
			{
				strcpy(cli_info.svc_type, "LPT1:");
				break;
			}

			case 'd':
			{
				if (*optarg == 'A')
					DEBUGLEVEL = 10000;
				else
					DEBUGLEVEL = atoi(optarg);
				break;
			}

			case 'l':
			{
				sprintf(debugf,"%s.client",optarg);
				break;
			}

			case 'p':
			{
				port = atoi(optarg);
				break;
			}

			case 'c':
			{
				cmd_str = optarg;
				got_pass = True;
				break;
			}

			case 'h':
			{
				usage(pname);
				exit(0);
				break;
			}

			case 's':
			{
				strcpy(servicesf, optarg);
				break;
			}

			case 't':
			{
				strcpy(term_code, optarg);
				break;
			}

			default:
			{
				usage(pname);
				exit(1);
				break;
			}
		}
	}

	if (cli_action == CLIENT_NONE)
	{
		usage(pname);
		exit(1);
	}

	DEBUG(3,("%s client started (version %s)\n",timestring(),VERSION));

	if(!get_myname(cli_info.myhostname, NULL))
	{
		DEBUG(0,("Failed to get my hostname.\n"));
	}

	if (!lp_load(servicesf,True))
	{
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
	}

	codepage_initialise(lp_client_code_page());

	if(lp_client_code_page() == KANJI_CODEPAGE)
	{
		if (!setup_term_code (term_code))
		{
			DEBUG(0, ("%s: unknown terminal code name\n", optarg));
			usage (pname);
			exit (1);
		}
	}

	if (*cli_info.workgroup == 0) strcpy(cli_info.workgroup,lp_workgroup());

	load_interfaces();
	get_myname((*myname)?NULL:myname,NULL);  
	strupper(myname);

	if (cli_action == CLIENT_IPC || cli_action == CLIENT_QUERY)
	{
		strcpy(cli_info.share, "IPC$");
		strcpy(cli_info.svc_type, "IPC");
	}
	else
	{
		/* extract destination host (if there isn't one) and share from service */
		pstrcpy(tmp, cli_info.service);
		p = strtok(tmp, "\\/");
		if (cli_info.dest_host[0] == 0)
		{
			strcpy(cli_info.dest_host, p);
		}
		p = strtok(NULL, "\\/");
		strcpy(cli_info.share, p);

		if (cli_info.dest_host[0] == 0)
		{
			DEBUG(0,("Could not get host name from service %s\n", cli_info.service));
			return 1;
		}

		if (cli_info.share[0] == 0)
		{
			DEBUG(0,("Could not get share name from service %s\n", cli_info.service));
			return 1;
		}
	}

	fstrcpy(cli_info.mach_acct, cli_info.myhostname);
	strupper(cli_info.mach_acct);
	strcat(cli_info.mach_acct, "$");

	/* establish connections.  nothing to stop these being re-established */
	if (!got_pass) password[0] = 0;

	client_smb_connect(&cli_info, cli_info.username, password, cli_info.workgroup);
	client_ipc_connect(&cli_info, NULL             , NULL    , cli_info.workgroup);
#if 0
	client_nt_connect (&cli_info, cli_info.username, password, cli_info.workgroup);
#endif

	DEBUG(5,("cli_ipc_connect: ipc_cli->fd:%d\n", ipc_cli->fd));

	ret = 0;

	switch (cli_action)
	{
		case CLIENT_QUERY:
		{
			client_browse_host(ipc_cli, ipc_tidx, cli_info.workgroup, True);
			break;
		}
		case CLIENT_MESSAGE:
		{
			client_send_message(ipc_cli, ipc_tidx, cli_info.username, cli_info.dest_host);
			break;
		}

		case CLIENT_TAR:
		{
			cli_info.recurse_dir = True;

			if (*cli_info.base_dir)
			{
				do_cd(smb_cli, smb_tidx, &cli_info, cli_info.base_dir);
			}

			ret = process_tar(&cli_info);

			break;
		}

		case CLIENT_IPC:
		case CLIENT_SVC:
		{
			if (*cli_info.base_dir)
			{
				do_cd(smb_cli, smb_tidx, &cli_info, cli_info.base_dir);
			}
			ret = process(&cli_info, cmd_str) ? 0 : 1;
			break;
		}

		default:
		{
			DEBUG(0,("unknown client action requested\n"));
			ret = 1;
			break;
		}
	}

	client_smb_stop();
	client_ipc_stop();
#if 0
	client_nt_stop();
#endif
	return(0);
}
