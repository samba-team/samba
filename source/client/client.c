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


#define SEPARATORS " \t\n\r"

extern file_info def_finfo;

#define USENMB

#define CNV_LANG(s) dos2unix_format(s,False)
#define CNV_INPUT(s) unix2dos_format(s,True)

extern int coding_system;

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
send a message
****************************************************************************/
static void send_message(struct cli_state *cli, char *username, char *dest_host)
{
  int total_len;
  char message[2000];
  int l;
  char c;

  printf("Type your message, ending it with a Control-D\n");

      for (l=0; l < sizeof(message) && (c = fgetc(stdin)) != EOF; l++)
	{
	  if (c == '\n')
	    message[l++] = '\r';
	  message[l] = c;   
	}
    if (!cli_send_message(cli, username, dest_host, message, &total_len))
    {
	  printf("send_message failed (%s)\n", cli_errstr(cli));
	  return;
	}      

  if (total_len >= 1600)
    printf("the message was truncated to 1600 bytes ");
  else
    printf("sent %d bytes ",total_len);

}



/****************************************************************************
print browse connection on a host
****************************************************************************/
static void print_server(char *sname, uint32 type, char *comment)
{
	fstring typestr;
	*typestr=0;

	if (type == SV_TYPE_ALL)
	{
		strcpy(typestr, "All");
	}
	else
	{
		int i;
		typestr[0] = 0;
		for (i = 0; i < 32; i++)
		{
			if (IS_BITS_SET(type, 1 << i))
			{
				switch (1 << i)
				{
					case SV_TYPE_WORKSTATION      : strcat(typestr, "Wk " ); break;
					case SV_TYPE_SERVER           : strcat(typestr, "Sv " ); break;
					case SV_TYPE_SQLSERVER        : strcat(typestr, "Sql "); break;
					case SV_TYPE_DOMAIN_CTRL      : strcat(typestr, "PDC "); break;
					case SV_TYPE_DOMAIN_BAKCTRL   : strcat(typestr, "BDC "); break;
					case SV_TYPE_TIME_SOURCE      : strcat(typestr, "Tim "); break;
					case SV_TYPE_AFP              : strcat(typestr, "AFP "); break;
					case SV_TYPE_NOVELL           : strcat(typestr, "Nov "); break;
					case SV_TYPE_DOMAIN_MEMBER    : strcat(typestr, "Dom "); break;
					case SV_TYPE_PRINTQ_SERVER    : strcat(typestr, "PrQ "); break;
					case SV_TYPE_DIALIN_SERVER    : strcat(typestr, "Din "); break;
					case SV_TYPE_SERVER_UNIX      : strcat(typestr, "Unx "); break;
					case SV_TYPE_NT               : strcat(typestr, "NT " ); break;
					case SV_TYPE_WFW              : strcat(typestr, "Wfw "); break;
					case SV_TYPE_SERVER_MFPN      : strcat(typestr, "Mfp "); break;
					case SV_TYPE_SERVER_NT        : strcat(typestr, "SNT "); break;
					case SV_TYPE_POTENTIAL_BROWSER: strcat(typestr, "PtB "); break;
					case SV_TYPE_BACKUP_BROWSER   : strcat(typestr, "BMB "); break;
					case SV_TYPE_MASTER_BROWSER   : strcat(typestr, "LMB "); break;
					case SV_TYPE_DOMAIN_MASTER    : strcat(typestr, "DMB "); break;
					case SV_TYPE_SERVER_OSF       : strcat(typestr, "OSF "); break;
					case SV_TYPE_SERVER_VMS       : strcat(typestr, "VMS "); break;
					case SV_TYPE_WIN95_PLUS       : strcat(typestr, "W95 "); break;
					case SV_TYPE_ALTERNATE_XPORT  : strcat(typestr, "Xpt "); break;
					case SV_TYPE_LOCAL_LIST_ONLY  : strcat(typestr, "Dom "); break;
					case SV_TYPE_DOMAIN_ENUM      : strcat(typestr, "Loc "); break;
				}
			}
		}
		i = strlen(typestr)-1;
		if (typestr[i] == ' ') typestr[i] = 0;

	}

	printf("\t%-15.15s%-20s %s\n", sname, typestr, comment);
}


/****************************************************************************
print browse connection on a host
****************************************************************************/
static void print_share(char *sname, uint32 type, char *comment)
{
	fstring typestr;
	*typestr=0;

	switch (type)
	{
		case STYPE_DISKTREE: strcpy(typestr,"Disk"); break;
		case STYPE_PRINTQ  : strcpy(typestr,"Printer"); break;	      
		case STYPE_DEVICE  : strcpy(typestr,"Device"); break;
		case STYPE_IPC     : strcpy(typestr,"IPC"); break;      
		default            : strcpy(typestr,"????"); break;      
	}

	printf("\t%-15.15s%-10.10s%s\n", sname, typestr, comment);
}


/****************************************************************************
try and browse available connections on a host
****************************************************************************/
static void browse_host(struct cli_state *cli, char *workgroup, BOOL sort)
{
	int count = 0;
	BOOL long_share_name = False;
	
	printf("\n\tSharename      Type      Comment\n");
	printf(  "\t---------      ----      -------\n");

	count = cli_NetShareEnum(cli, sort, &long_share_name, print_share);

	if (count == 0)
	{
		printf("\tNo shares available on this host\n");
	}

	if (long_share_name)
	{
		printf("\nNOTE: There were share names longer than 8 chars.\nOn older clients these may not be accessible or may give browsing errors\n");
	}

	printf("\n");
	printf("\tWorkgroup      Type                 Master\n");
	printf("\t---------      ----                 ------\n");

	cli_NetServerEnum(cli, workgroup, SV_TYPE_DOMAIN_ENUM, print_server);

	printf("\n");
	printf("\tServer         Type                 Comment\n");
	printf("\t------         ----                 -------\n");
	
	cli_NetServerEnum(cli, workgroup, SV_TYPE_ALL, print_server);
}


/* This defines the commands supported by this client */
struct
{
  char *name;
  void (*fn)();
  char *description;
} commands[] = 
{
#ifdef NTDOMAIN
  {"ntlogin",    cmd_nt_login_test,    "<username> NT Domain login"},
  {"lsaquery",   cmd_lsa_query_info,   "<server> Query Info Policy"},
  {"samrid",     cmd_sam_query_users,  "<server> SAM User Info lookup"},
#endif
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
help
****************************************************************************/
void cmd_help(struct cli_state *cli, struct client_info *info)
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

/****************************************************************************
wait for keyboard activity, swallowing network packets
****************************************************************************/
#ifdef CLIX
static char wait_keyboard(struct cli_state *cli)
#else
static void wait_keyboard(struct cli_state *cli)
#endif
{
  fd_set fds;
  int selrtn;
  struct timeval timeout;
  
#ifdef CLIX
  int delay = 0;
#endif
  
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
      
#ifdef CLIX
      delay++;
      if (delay > 100000)
	{
	  delay = 0;
	  cli_chkpath(cli, "\\");
	}
#else
      cli_chkpath(cli, "\\");
#endif
    }  
}


/****************************************************************************
  process commands from the client
****************************************************************************/
static BOOL process(struct cli_state *cli, struct client_info *info,
				char *cmd_str)
{
  extern FILE *dbf;
  pstring line;
  char *cmd;

  if (*info->base_dir) do_cd(cli, info, info->base_dir);

  cmd = cmd_str;
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
	commands[i].fn(cli, info);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n", CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n", CNV_LANG(tok)));
    }
  else while (!feof(stdin))
    {
      fstring tok;
      int i;

      bzero(cli->outbuf,smb_size);

      /* display a prompt */
      DEBUG(0,("smb: %s> ", CNV_LANG(info->cur_dir)));
      fflush(dbf);

#ifdef CLIX
      line[0] = wait_keyboard(cli);
      /* this might not be such a good idea... */
      if ( line[0] == EOF)
	break;
#else
      wait_keyboard(cli);
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
	commands[i].fn(cli, info);
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
	BOOL message = False;
	BOOL query_host = False;
	BOOL nt_domain_logon = False;
	BOOL anonymous = False;
	static pstring servicesf = CONFIGFILE;
	pstring term_code;
	char *p;
	BOOL got_pass = False;
	char *cmd_str="";
	int myumask = 0755;

	struct cli_state smb_cli;
	struct client_info cli_info;

	int name_type = 0x20;

	pstring password;

	pstring service;
	pstring share;
	fstring svc_type;
	pstring tmp;

	strcpy(svc_type, "A:");

	bzero(&smb_cli, sizeof(smb_cli));

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

	strcpy(cli_info.cur_dir , "\\");
	strcpy(cli_info.file_sel, "");
	strcpy(cli_info.base_dir, "");
	strcpy(cli_info.workgroup, "");
	strcpy(cli_info.username, "");
	strcpy(cli_info.myhostname, "");
	strcpy(cli_info.dest_host, "");

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

		strcpy(service, argv[1]);  
		/* Convert any '/' characters in the service name to '\' characters */
		string_replace( service, '/','\\');
		argc--;
		argv++;

		if (count_chars(service,'\\') < 3)
		{
			usage(pname);
			printf("\n%s: Not enough '\\' characters in service\n",service);
			exit(1);
		}

		/*
		if (count_chars(service,'\\') > 3)
		{
			usage(pname);
			printf("\n%s: Too many '\\' characters in service\n",service);
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
				nt_domain_logon = True;
				break;
			}

			case 'M':
			{
				name_type = 0x03; /* messages sent to NetBIOS name type 0x3 */
				strcpy(cli_info.dest_host,optarg);
				strupper(cli_info.dest_host);
				message = True;
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
				if (!tar_parseargs(&cli_info, argc, argv, optarg, optind))
				{
					usage(pname);
					exit(1);
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
				query_host = True;
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
				strcpy(svc_type, "LPT1:");
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

	if (!cli_info.tar.type && !nt_domain_logon && !query_host && !*service && !message)
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

	if (query_host)
	{
		strupper(service);

		if (!cli_establish_connection(&smb_cli, cli_info.dest_host, name_type, &cli_info.dest_ip,
		     cli_info.myhostname,
		     got_pass ? NULL : "Enter Password:",
		     cli_info.username, password, cli_info.workgroup,
		     "IPC$", "IPC",
		     False, True, False))
		{
			cli_shutdown(&smb_cli);
			return 1;
		}

		browse_host(&smb_cli, cli_info.workgroup, True);

		cli_shutdown(&smb_cli);

		return 0;
	}

	if (message)
	{
		int ret = 0;
		if (!cli_establish_connection(&smb_cli, cli_info.dest_host, name_type, &cli_info.dest_ip,
		     cli_info.myhostname,
		     got_pass ? NULL : "Enter Password:",
		     cli_info.username, password, cli_info.workgroup,
		     service, svc_type,
		     False, False, True))
		{
			cli_shutdown(&smb_cli);
			return 1;
		}

		send_message(&smb_cli, cli_info.username, cli_info.dest_host);

		cli_shutdown(&smb_cli);

		return(ret);
	}
#ifdef NTDOMAIN
	if (nt_domain_logon)
	{
		fstrcpy(cli_info.mach_acct, cli_info.myhostname);
		strlower(cli_info.mach_acct);
		strcat(cli_info.mach_acct, "$");

		DEBUG(5,("NT Domain Logon[%s].  Host:%s Mac-acct:%s\n",
			cli_info.workgroup, cli_info.dest_host, cli_info.mach_acct));

		strcpy(share, "IPC$");
		strcpy(svc_type, "IPC");
	}
	else
#endif
	{
		/* extract destination host (if there isn't one) and share from service */
		pstrcpy(tmp, service);
		p = strtok(tmp, "\\/");
		if (cli_info.dest_host[0] == 0)
		{
			strcpy(cli_info.dest_host, p);
		}
		p = strtok(NULL, "\\/");
		strcpy(share, p);

		if (cli_info.dest_host[0] == 0)
		{
			DEBUG(0,("Could not get host name from service %s\n", service));
			return 1;
		}

		if (share[0] == 0)
		{
			DEBUG(0,("Could not get share name from service %s\n", service));
			return 1;
		}
	}

	if (cli_info.tar.type)
	{
		int ret = 0;
		cli_info.recurse_dir = True;

		if (!cli_establish_connection(&smb_cli, cli_info.dest_host, name_type, &cli_info.dest_ip,
		     cli_info.myhostname,
		     got_pass ? NULL : "Enter Password:",
		     cli_info.username, password, cli_info.workgroup,
		     service, svc_type,
		     False, True, True))
		{
			cli_shutdown(&smb_cli);
			return 1;
		}

		bzero(smb_cli.outbuf,smb_size);
		if (*cli_info.base_dir)
		{
			do_cd(&smb_cli, &cli_info, cli_info.base_dir);
		}
		ret = process_tar(&smb_cli, &cli_info);

		cli_shutdown(&smb_cli);
		return ret;
	}

	if (cli_info.username[0] == 0)
	{
		anonymous = True;
	}

	if (!cli_establish_connection(&smb_cli, cli_info.dest_host, name_type, &cli_info.dest_ip,
		   cli_info.myhostname,
		   (got_pass || anonymous) ? NULL : "Enter Password:",
		   cli_info.username, !anonymous ? password : NULL, cli_info.workgroup,
	       share, svc_type,
	       False, True, !anonymous))
	{
		cli_shutdown(&smb_cli);
		return 1;
	}

	if (!process(&smb_cli, &cli_info, cmd_str))
	{
		cli_shutdown(&smb_cli);
		return 1;
	}

	cli_shutdown(&smb_cli);

	return(0);
}
