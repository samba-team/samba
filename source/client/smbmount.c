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

#include <linux/version.h>
#define LVERSION(major,minor,patch) (((((major)<<8)+(minor))<<8)+(patch))
#if LINUX_VERSION_CODE < LVERSION(2,1,70)
#error this code will only compile on versions of linux after 2.1.70
#endif

#include "includes.h"
#include <linux/smb_fs.h>
static struct smb_conn_opt conn_options;

#ifndef REGISTER
#define REGISTER 0
#endif

/* Uncomment this to allow debug the smbmount daemon */
#define SMBFS_DEBUG 1

pstring cur_dir = "\\";
pstring cd_path = "";
extern pstring service;
extern pstring desthost;
extern pstring myname;
extern pstring myhostname;
extern pstring password;
extern pstring username;
extern pstring workgroup;
char *cmdstr="";
extern BOOL got_pass;
extern BOOL connect_as_printer;
extern BOOL connect_as_ipc;
extern struct in_addr ipzero;

extern BOOL doencrypt;

extern pstring user_socket_options;

/* 30 second timeout on most commands */
#define CLIENT_TIMEOUT (30*1000)
#define SHORT_TIMEOUT (5*1000)

/* value for unused fid field in trans2 secondary request */
#define FID_UNUSED (0xFFFF)

extern int name_type;

extern int max_protocol;
int port = SMB_PORT;


time_t newer_than = 0;
int archive_level = 0;

extern pstring debugf;
extern int DEBUGLEVEL;

BOOL translation = False;

extern int cnum;
extern int mid;
extern int pid;
extern int tid;
extern int gid;
extern int uid;

extern BOOL have_ip;
extern int max_xmit;

/* clitar bits insert */
extern int blocksize;
extern BOOL tar_inc;
extern BOOL tar_reset;
/* clitar bits end */
 

int myumask = 0755;

extern pstring scope;

BOOL prompt = True;

int printmode = 1;

BOOL recurse = False;
BOOL lowercase = False;

struct in_addr dest_ip;

#define SEPARATORS " \t\n\r"

BOOL abort_mget = True;

extern int Protocol;

extern BOOL readbraw_supported ;
extern BOOL writebraw_supported;

pstring fileselection = "";

extern file_info def_finfo;

/* timing globals */
int get_total_size = 0;
int get_total_time_ms = 0;
int put_total_size = 0;
int put_total_time_ms = 0;

/* totals globals */
int dir_total = 0;

extern int Client;

#define USENMB

#define CNV_LANG(s) dos_to_unix(s,False)
#define CNV_INPUT(s) unix_to_dos(s,True)

/****************************************************************************
check for existance of a dir
****************************************************************************/
static BOOL chkpath(char *path,BOOL report)
{
  pstring path2;
  pstring inbuf,outbuf;
  char *p;

  pstrcpy(path2,path);
  trim_string(path2,NULL,"\\");
  if (!*path2) *path2 = '\\';

  bzero(outbuf,smb_size);
  set_message(outbuf,0,4 + strlen(path2),True);
  SCVAL(outbuf,smb_com,SMBchkpth);
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  p = smb_buf(outbuf);
  *p++ = 4;
  pstrcpy(p,path2);

#if 0
  {
	  /* this little bit of code can be used to extract NT error codes.
	     Just feed a bunch of "cd foo" commands to smbclient then watch
	     in netmon (tridge) */
	  static int code=0;
	  SIVAL(outbuf, smb_rcls, code | 0xC0000000);
	  SSVAL(outbuf, smb_flg2, SVAL(outbuf, smb_flg2) | (1<<14));
	  code++;
  }
#endif

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (report && CVAL(inbuf,smb_rcls) != 0)
    DEBUG(2,("chkpath: %s\n",smb_errstr(inbuf)));

  return(CVAL(inbuf,smb_rcls) == 0);
}

static void
daemonize(void)
{
	int i;
	if ((i = fork()) < 0)
	{
		DEBUG(0, ("could not fork\n"));
	}
	if (i > 0)
	{
		/* parent simply exits */
		exit(0);
	}
	setsid();
	chdir("/");
}

static void
close_our_files(void)
{
	int i;
	for (i = 0; i < NR_OPEN; i++) {
		if (i == Client) {
			continue;
		}
		close(i);
	}
}

static void
usr1_handler(int x)
{
	return;
}

/*
 * Send a login and store the connection options. This is a separate
 * function to keep clientutil.c independent of linux kernel changes.
 */
static BOOL mount_send_login(char *inbuf, char *outbuf)
{
  struct connection_options opt;
  int res = cli_send_login(inbuf, outbuf, True, True, &opt);

  if (!res)
    return res;

  conn_options.protocol = opt.protocol;
  conn_options.case_handling = CASE_LOWER;
  conn_options.max_xmit = opt.max_xmit;
  conn_options.server_uid = opt.server_uid;
  conn_options.tid = opt.tid;
  conn_options.secmode = opt.sec_mode;
  conn_options.maxmux = opt.max_mux;
  conn_options.maxvcs = opt.max_vcs;
  conn_options.rawmode = opt.rawmode;
  conn_options.sesskey = opt.sesskey;
  conn_options.maxraw = opt.maxraw;
  conn_options.capabilities = opt.capabilities;
  conn_options.serverzone = opt.serverzone;

  return True;
}

/*
 * Call the smbfs ioctl to install a connection socket,
 * then wait for a signal to reconnect. Note that we do
 * not exit after open_sockets() or send_login() errors,
 * as the smbfs mount would then have no way to recover.
 */
static void
send_fs_socket(char *mount_point, char *inbuf, char *outbuf)
{
	int fd, closed = 0, res = 1;

	while (1)
	{
		if ((fd = open(mount_point, O_RDONLY)) < 0)
		{
			DEBUG(0, ("smbmount: can't open %s\n", mount_point));
			break;
		}		

		/*
		 * Call the ioctl even if we couldn't get a socket ...
		 * there's no point in making smbfs wait for a timeout.
		 */
		conn_options.fd = -1;
		if (res)
			conn_options.fd = Client;
		res = ioctl(fd, SMB_IOC_NEWCONN, &conn_options);
		if (res != 0)
		{
			DEBUG(0, ("smbmount: ioctl failed, res=%d\n", res));
		}

		close_sockets();
		close(fd);
		/*
		 * Close all open files if we haven't done so yet.
		 */
#ifndef SMBFS_DEBUG
		if (!closed)
		{
			closed = 1;
			close_our_files();
		}
#endif

		/*
		 * Wait for a signal from smbfs ...
		 */
		signal(SIGUSR1, &usr1_handler);
		pause();
		DEBUG(0, ("smbmount: got signal, getting new socket\n"));

		res = cli_open_sockets(port);
		if (!res)
		{
			DEBUG(0, ("smbmount: can't open sockets\n"));
			continue;
		}

		res = mount_send_login(inbuf, outbuf);
		if (!res)
		{
			DEBUG(0, ("smbmount: login failed\n"));
		}
	}
	DEBUG(0, ("smbmount: exit\n"));
	exit(1);
}

/****************************************************************************
mount smbfs
****************************************************************************/
static void cmd_mount(char *inbuf,char *outbuf)
{
	pstring mpoint;
	pstring share_name;
	pstring mount_command;
	fstring buf;
	int retval;
	char mount_point[MAXPATHLEN+1];

	if (!next_token(NULL, mpoint, NULL))
	{
		DEBUG(0,("You must supply a mount point\n"));
		return;
	}

	memset(mount_point, 0, sizeof(mount_point));

	if (realpath(mpoint, mount_point) == NULL)
	{
		DEBUG(0, ("Could not resolve mount point\n"));
		return;
	}

	/*
	 * Build the service name to report on the Unix side,
	 * converting '\' to '/' and ' ' to '_'.
	 */
	pstrcpy(share_name, service);  
	string_replace(share_name, '\\', '/');
	string_replace(share_name, ' ', '_');

	slprintf(mount_command, sizeof(mount_command)-1,"smbmnt %s -s %s", mount_point, share_name);

	while(next_token(NULL, buf, NULL))
	{
		pstrcat(mount_command, " ");
		pstrcat(mount_command, buf);
	}

	DEBUG(3, ("mount command: %s\n", mount_command));

	/*
	 * Create the background process before trying the mount.
	 * (We delay closing files to allow diagnostic messages.)
	 */
	daemonize();

	/* The parent has exited here, the child handles the connection: */
	if ((retval = system(mount_command)) != 0)
	{
		DEBUG(0,("mount failed\n"));
		exit(1);
	}
	send_fs_socket(mount_point, inbuf, outbuf);
}	


/* This defines the commands supported by this client */
struct
{
  char *name;
  void (*fn)();
  char *description;
} commands[] = 
{
  {"mount", cmd_mount, "<mount-point options> mount an smbfs file system"},
  {"",NULL,NULL}
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
help
****************************************************************************/
void cmd_help(char *dum_in, char *dum_out)
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
static char wait_keyboard(char *buffer)
#else
static void wait_keyboard(char *buffer)
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
      extern int Client;
      FD_ZERO(&fds);
      FD_SET(Client,&fds);
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

      /* We deliberately use receive_smb instead of
         client_receive_smb as we want to receive
         session keepalives and then drop them here.
       */
      if (FD_ISSET(Client,&fds))
  	receive_smb(Client,buffer,0);
      
#ifdef CLIX
      delay++;
      if (delay > 100000)
	{
	  delay = 0;
	  chkpath("\\",False);
	}
#else
      chkpath("\\",False);
#endif
    }  
}


/****************************************************************************
  process commands from the client
****************************************************************************/
static BOOL process(char *base_directory)
{
  extern FILE *dbf;
  pstring line;
  char *cmd;

  char *InBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  char *OutBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return(False);
  
  bzero(OutBuffer,smb_size);

  if (!mount_send_login(InBuffer,OutBuffer))
    return(False);

  cmd = cmdstr;
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
	commands[i].fn(InBuffer,OutBuffer);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n",CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n",CNV_LANG(tok)));
    }
  else while (!feof(stdin))
    {
      fstring tok;
      int i;

      bzero(OutBuffer,smb_size);

      /* display a prompt */
      DEBUG(0,("smb: %s> ", CNV_LANG(cur_dir)));
      fflush(dbf);

#ifdef CLIX
      line[0] = wait_keyboard(InBuffer);
      /* this might not be such a good idea... */
      if ( line[0] == EOF)
	break;
#else
      wait_keyboard(InBuffer);
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
	commands[i].fn(InBuffer,OutBuffer);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n",CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n",CNV_LANG(tok)));
    }
  
  cli_send_logout(InBuffer,OutBuffer);
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
  DEBUG(0,("\t-p port               connect to the specified port\n"));
  DEBUG(0,("\t-d debuglevel         set the debuglevel\n"));
  DEBUG(0,("\t-l log basename.      Basename for log/debug files\n"));
  DEBUG(0,("\t-n netbios name.      Use this name as my netbios name\n"));
  DEBUG(0,("\t-N                    don't ask for a password\n"));
  DEBUG(0,("\t-m max protocol       set the max protocol level\n"));
  DEBUG(0,("\t-I dest IP            use this IP to connect to\n"));
  DEBUG(0,("\t-E                    write messages to stderr instead of stdout\n"));
  DEBUG(0,("\t-U username           set the network username\n"));
  DEBUG(0,("\t-W workgroup          set the workgroup name\n"));
  DEBUG(0,("\t-c command string     execute semicolon separated commands\n"));
  DEBUG(0,("\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n"));
  DEBUG(0,("\t-D directory          start from directory\n"));
  DEBUG(0,("\n"));
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
  fstring base_directory;
  char *pname = argv[0];
  int opt;
  extern FILE *dbf;
  extern char *optarg;
  extern int optind;
  pstring query_host;
  BOOL nt_domain_logon = False;
  static pstring servicesf = CONFIGFILE;
  pstring term_code;
  char *p;

#ifdef KANJI
  pstrcpy(term_code, KANJI);
#else /* KANJI */
  *term_code = 0;
#endif /* KANJI */

  *query_host = 0;
  *base_directory = 0;

  DEBUGLEVEL = 2;

  setup_logging(pname,True);

  TimeInit();
  charset_initialise();

  pid = getpid();
  uid = getuid();
  gid = getgid();
  mid = pid + 100;
  myumask = umask(0);
  umask(myumask);

  if (getenv("USER"))
  {
    pstrcpy(username,getenv("USER"));

    /* modification to support userid%passwd syntax in the USER var
       25.Aug.97, jdblair@uab.edu */

    if ((p=strchr(username,'%')))
    {
      *p = 0;
      pstrcpy(password,p+1);
      got_pass = True;
      memset(strchr(getenv("USER"),'%')+1,'X',strlen(password));
    }
    strupper(username);
  }

 /* modification to support PASSWD environmental var
  25.Aug.97, jdblair@uab.edu */

  if (getenv("PASSWD"))
    pstrcpy(password,getenv("PASSWD"));

  if (*username == 0 && getenv("LOGNAME"))
    {
      pstrcpy(username,getenv("LOGNAME"));
      strupper(username);
    }

  if (argc < 2)
    {
      usage(pname);
      exit(1);
    }
  
  if (*argv[1] != '-')
    {

      pstrcpy(service, argv[1]);  
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

      if (argc > 1 && (*argv[1] != '-'))
	{
	  got_pass = True;
	  pstrcpy(password,argv[1]);  
	  memset(argv[1],'X',strlen(argv[1]));
	  argc--;
	  argv++;
	}
    }

  while ((opt = 
	  getopt(argc, argv,"s:B:O:M:S:i:Nn:d:Pp:l:hI:EB:U:L:t:m:W:T:D:c:")) != EOF)
    switch (opt)
      {
      case 'm':
	max_protocol = interpret_protocol(optarg,max_protocol);
	break;
      case 'O':
	pstrcpy(user_socket_options,optarg);
	break;	
      case 'S':
	pstrcpy(desthost,optarg);
	strupper(desthost);
	nt_domain_logon = True;
	break;
      case 'B':
	iface_set_default(NULL,optarg,NULL);
	break;
      case 'D':
	pstrcpy(base_directory,optarg);
	break;
      case 'i':
	pstrcpy(scope,optarg);
	break;
      case 'U':
	{
	  char *lp;
	pstrcpy(username,optarg);
	if ((lp=strchr(username,'%')))
	  {
	    *lp = 0;
	    pstrcpy(password,lp+1);
	    got_pass = True;
	    memset(strchr(optarg,'%')+1,'X',strlen(password));
	  }
	}
	    
	break;
      case 'W':
	pstrcpy(workgroup,optarg);
	break;
      case 'E':
	dbf = stderr;
	break;
      case 'I':
	{
	  dest_ip = *interpret_addr2(optarg);
	  if (zero_ip(dest_ip)) exit(1);
	  have_ip = True;
	}
	break;
      case 'n':
	pstrcpy(myname,optarg);
	break;
      case 'N':
	got_pass = True;
	break;
      case 'd':
	if (*optarg == 'A')
	  DEBUGLEVEL = 10000;
	else
	  DEBUGLEVEL = atoi(optarg);
	break;
      case 'l':
	slprintf(debugf,sizeof(debugf)-1,"%s.client",optarg);
	break;
      case 'p':
	port = atoi(optarg);
	break;
      case 'c':
	cmdstr = optarg;
	got_pass = True;
	break;
      case 'h':
	usage(pname);
	exit(0);
	break;
      case 's':
	pstrcpy(servicesf, optarg);
	break;
      case 't':
        pstrcpy(term_code, optarg);
	break;
      default:
	usage(pname);
	exit(1);
      }

  if (!*query_host && !*service)
    {
      usage(pname);
      exit(1);
    }


  DEBUG(3,("%s client started (version %s)\n",timestring(),VERSION));

  if(!get_myname(myhostname,NULL))
  {
    DEBUG(0,("Failed to get my hostname.\n"));
  }

  if (!lp_load(servicesf,True)) {
    fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
  }

  codepage_initialise(lp_client_code_page());

  interpret_coding_system(term_code);

  if (*workgroup == 0)
    pstrcpy(workgroup,lp_workgroup());

  load_interfaces();
  get_myname((*myname)?NULL:myname,NULL);  
  strupper(myname);

#ifdef NTDOMAIN

	if (nt_domain_logon)
	{
		int ret = 0;
		slprintf(service,sizeof(service), "\\\\%s\\IPC$",query_host);
		strupper(service);
		connect_as_ipc = True;

		DEBUG(5,("NT Domain Logon.  Service: %s\n", service));

		if (cli_open_sockets(port))
		{
			if (!cli_send_login(NULL,NULL,True,True,NULL)) return(1);

			do_nt_login(desthost, myhostname, Client, cnum);

			cli_send_logout();
			close_sockets();
		}

		return(ret);
	}
#endif 

  if (cli_open_sockets(port))
    {
      if (!process(base_directory))
	{
	  close_sockets();
	  return(1);
	}
      close_sockets();
    }
  else
    return(1);

  return(0);
}
