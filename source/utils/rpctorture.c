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

extern pstring scope;
extern pstring global_myname;

extern pstring user_socket_options;


extern pstring debugf;
extern int DEBUGLEVEL;


extern file_info def_finfo;

#define CNV_LANG(s) dos2unix_format(s,False)
#define CNV_INPUT(s) unix2dos_format(s,True)

static struct cli_state smbcli;
struct cli_state *smb_cli = &smbcli;

FILE *out_hnd;

static pstring user_name; /* local copy only, if one is entered */
static pstring password; /* local copy only, if one is entered */
static pstring domain; /* local copy only, if one is entered */
BOOL got_pass = False;

static struct nmb_name calling;
static struct nmb_name called;

static void get_passwd(void)
{
	/* set the password cache info */
	if (got_pass)
	{
		if (password[0] == 0)
		{
			pwd_set_nullpwd(&(smb_cli->pwd));
		}
		else
		{
			pwd_make_lm_nt_16(&(smb_cli->pwd), password); /* generate 16 byte hashes */
		}
	}
	else 
	{
		char *pwd = getpass("Enter Password:");
		safe_strcpy(password, pwd, sizeof(password));
		pwd_make_lm_nt_16(&(smb_cli->pwd), password); /* generate 16 byte hashes */
		got_pass = True;
	}
}

/****************************************************************************
initialise smb client structure
****************************************************************************/
void rpcclient_init(void)
{
	bzero(smb_cli, sizeof(smb_cli));
	cli_initialise(smb_cli);
	smb_cli->capabilities |= CAP_NT_SMBS;
	smb_cli->capabilities |= CAP_STATUS32;

	pstrcpy(smb_cli->user_name, user_name);

	get_passwd();

	if (*domain == 0)
	{
		pstrcpy(smb_cli->domain,lp_workgroup());
	}
	else
	{
		pstrcpy(smb_cli->domain, domain);
	}

	strupper(smb_cli->domain);
}

/****************************************************************************
make smb client connection
****************************************************************************/
static BOOL rpcclient_connect(struct client_info *info)
{
	rpcclient_init();

	smb_cli->use_ntlmv2 = lp_client_ntlmv2();

	if (!cli_establish_connection(smb_cli, 
	                          info->dest_host, &info->dest_ip, 
	                          &calling, &called,
	                          info->share, info->svc_type,
	                          False, True))
	{
		DEBUG(0,("rpcclient_connect: connection failed\n"));
		cli_shutdown(smb_cli);
		return False;
	}

	return True;
}

/****************************************************************************
stop the smb connection(s?)
****************************************************************************/
static void rpcclient_stop(void)
{
	cli_shutdown(smb_cli);
}

/****************************************************************************
  log in as an nt user, log out again. 
****************************************************************************/
void run_enums_test(int num_ops, struct client_info *cli_info)
{
	pstring cmd;
	int i;

	/* establish connections.  nothing to stop these being re-established. */
	rpcclient_connect(cli_info);

	DEBUG(5,("rpcclient_connect: smb_cli->fd:%d\n", smb_cli->fd));
	if (smb_cli->fd <= 0)
	{
		fprintf(out_hnd, "warning: connection could not be established to %s<%02x>\n",
		                 cli_info->dest_host, cli_info->name_type);
		return;
	}
	
	for (i = 0; i < num_ops; i++)
	{
		set_first_token("");
		cmd_srv_enum_sess(cli_info);
		set_first_token("");
		cmd_srv_enum_shares(cli_info);
		set_first_token("");
		cmd_srv_enum_files(cli_info);

		if (password[0] != 0)
		{
			slprintf(cmd, sizeof(cmd)-1, "1");
			set_first_token(cmd);
		}
		else
		{
			set_first_token("");
		}
		cmd_srv_enum_conn(cli_info);
	}

	rpcclient_stop();

}

/****************************************************************************
  log in as an nt user, log out again. 
****************************************************************************/
void run_ntlogin_test(int num_ops, struct client_info *cli_info)
{
	pstring cmd;
	int i;

	/* establish connections.  nothing to stop these being re-established. */
	rpcclient_connect(cli_info);

	DEBUG(5,("rpcclient_connect: smb_cli->fd:%d\n", smb_cli->fd));
	if (smb_cli->fd <= 0)
	{
		fprintf(out_hnd, "warning: connection could not be established to %s<%02x>\n",
		                 cli_info->dest_host, cli_info->name_type);
		return;
	}
	
	for (i = 0; i < num_ops; i++)
	{
		slprintf(cmd, sizeof(cmd)-1, "%s %s", smb_cli->user_name, password);
		set_first_token(cmd);

		cmd_netlogon_login_test(cli_info);
	}

	rpcclient_stop();

}

/* generate a random buffer */
static void rand_buf(char *buf, int len)
{
	while (len--) {
		*buf = sys_random();
		buf++;
	}
}

/****************************************************************************
do a random rpc command
****************************************************************************/
BOOL do_random_rpc(struct cli_state *cli, uint16 nt_pipe_fnum, int max_len)
{
	prs_struct rbuf;
	prs_struct buf; 
	uint8 opcode;
	int param_len;
	BOOL response = False;

	if ((sys_random() % 20) == 0)
	{
		param_len = (sys_random() % 256) + 4;
	}
	else
	{
		param_len = (sys_random() % max_len) + 4;
	}

	prs_init(&buf , param_len, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0        , 4, SAFETY_MARGIN, True );

	opcode = sys_random() % 256;

	/* turn parameters into data stream */
	rand_buf(mem_data(buf.data, 0), param_len);
	buf.offset = param_len;

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, nt_pipe_fnum, opcode, &buf, &rbuf))
	{
		response = rbuf.offset != 0;

		if (response)
		{
			DEBUG(0,("response! opcode: 0x%x\n", opcode));
			DEBUG(0,("request: length %d\n", param_len));
			dump_data(0, mem_data(buf.data , 0), MIN(param_len, 128));
			DEBUG(0,("response: length %d\n", rbuf.data->offset.end));
			dump_data(0, mem_data(rbuf.data, 0), rbuf.data->offset.end);
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return response;
}


/* send random IPC commands */
static void random_rpc_pipe_enc(char *pipe_name, struct client_info *cli_info,
		int numops)
{
	uint16 nt_pipe_fnum;
	int i;

	DEBUG(0,("starting random rpc test on %s (encryped)\n", pipe_name));

	/* establish connections.  nothing to stop these being re-established. */
	if (!rpcclient_connect(cli_info))
	{
		DEBUG(0,("random rpc test: connection failed\n"));
		return;
	}

	cli_nt_set_ntlmssp_flgs(smb_cli,
				    NTLMSSP_NEGOTIATE_UNICODE |
				    NTLMSSP_NEGOTIATE_OEM |
				    NTLMSSP_NEGOTIATE_SIGN |
				    NTLMSSP_NEGOTIATE_SEAL |
				    NTLMSSP_NEGOTIATE_LM_KEY |
				    NTLMSSP_NEGOTIATE_NTLM |
				    NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
				    NTLMSSP_NEGOTIATE_00001000 |
				    NTLMSSP_NEGOTIATE_00002000);

	for (i = 1; i <= numops * 100; i++)
	{
		/* open session.  */
		cli_nt_session_open(smb_cli, pipe_name, &nt_pipe_fnum);

		do_random_rpc(smb_cli, nt_pipe_fnum, 1024);
		if (i % 500 == 0)
		{
			DEBUG(0,("calls: %i\n", i));
		}

		/* close the session */
		cli_nt_session_close(smb_cli, nt_pipe_fnum);
	}

	/* close the rpc pipe */
	rpcclient_stop();

	DEBUG(0,("finished random rpc test on %s\n", pipe_name));
}

/* send random IPC commands */
static void random_rpc_pipe(char *pipe_name, struct client_info *cli_info,
		int numops)
{
	uint16 nt_pipe_fnum;
	int i;

	DEBUG(0,("starting random rpc test on %s\n", pipe_name));

	/* establish connections.  nothing to stop these being re-established. */
	if (!rpcclient_connect(cli_info))
	{
		DEBUG(0,("random rpc test: connection failed\n"));
		return;
	}

	/* open session.  */
	if (!cli_nt_session_open(smb_cli, pipe_name, &nt_pipe_fnum))
	{
		DEBUG(0,("random rpc test: session open failed\n"));
		return;
	}

	for (i = 1; i <= numops * 100; i++)
	{
		do_random_rpc(smb_cli, nt_pipe_fnum, 8192);
		if (i % 500 == 0)
		{
			DEBUG(0,("calls: %i\n", i));
		}
	}

	/* close the session */
	cli_nt_session_close(smb_cli, nt_pipe_fnum);

	/* close the rpc pipe */
	rpcclient_stop();

	DEBUG(0,("finished random rpc test on %s\n", pipe_name));
}

static void run_randomrpc(int numops, struct client_info *cli_info)
{
	char *pipes[] =
	{
		PIPE_SAMR     ,
		PIPE_WINREG   ,
		PIPE_SRVSVC   ,
		PIPE_WKSSVC   ,
		PIPE_NETLOGON ,
		PIPE_NTSVCS   ,
		PIPE_LSARPC   ,
		NULL
	};

	int i = 0;

	while (pipes[i] != NULL)
	{
		random_rpc_pipe(pipes[i], cli_info, numops);
#if 0
		random_rpc_pipe_enc(pipes[i], cli_info, numops);
#endif

		i++;
	}
}


static void run_samhandles(int numops, struct client_info *cli_info)
{
	uint16 nt_pipe_fnum;
	int i;
	int count = 0;
	int failed = 0;
	int retry = 500;
	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, cli_info->dest_host);
	strupper(srv_name);

	DEBUG(0,("starting sam handle test\n"));

	/* establish connections.  nothing to stop these being re-established. */
	while (retry > 0 && !rpcclient_connect(cli_info))
	{
		retry--;
	}

	if (retry == 0)
	{
		DEBUG(0,("samhandle test: connection failed\n"));
		return;
	}

	/* open session.  */
	if (!cli_nt_session_open(smb_cli, PIPE_SAMR, &nt_pipe_fnum))
	{
		DEBUG(0,("samhandle test: session open failed\n"));
		return;
	}

	for (i = 1; i <= numops * 100; i++)
	{
		POLICY_HND pol;
		POLICY_HND dom;
		if (!samr_connect(smb_cli, nt_pipe_fnum, srv_name, 0x20, &pol))
		{
			failed++;
		}
/*
		if (!samr_open_domain(smb_cli, nt_pipe_fnum, srv_name, 0x00000020, &pol))
		{
			DEBUG(0,("samhandle domain open test (%i): failed\n", i));
		}
 */
		if (i % 500 == 0)
		{
			DEBUG(0,("calls: %i\n", i));
		}
		count++;
	}

	/* close the session */
	cli_nt_session_close(smb_cli, nt_pipe_fnum);

	/* close the rpc pipe */
	rpcclient_stop();

	DEBUG(0,("finished samhandle test.  count: %d failed: %d\n", count, failed));
}


static void run_lsahandles(int numops, struct client_info *cli_info)
{
	uint16 nt_pipe_fnum;
	int i;
	int count = 0;
	int failed = 0;
	int retry = 500;
	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, cli_info->myhostname);
	strupper(srv_name);

	DEBUG(0,("starting lsa handle test\n"));

	/* establish connections.  nothing to stop these being re-established. */
	while (retry > 0 && !rpcclient_connect(cli_info))
	{
		retry--;
	}

	if (retry == 0)
	{
		DEBUG(0,("lsahandle test: connection failed\n"));
		return;
	}
	for (i = 1; i <= numops * 100; i++)
	{
		extern struct cli_state *rpc_smb_cli;
		rpc_smb_cli = smb_cli;
		POLICY_HND pol;
		if (!lsa_open_policy(srv_name, &pol, False))
		{
			failed++;
		}
		if (i % 500 == 0)
		{
			DEBUG(0,("calls: %i\n", i));
		}
		count++;
	}

	/* close the rpc pipe */
	rpcclient_stop();

	DEBUG(0,("finished lsahandle test.  count: %d failed: %d\n", count, failed));
}


static void run_pipegobble(int numops, struct client_info *cli_info, char *pipe_name)
{
	uint16 nt_pipe_fnum;
	int i;
	int count = 0;
	int failed = 0;
	int retry = 500;
	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, cli_info->myhostname);
	strupper(srv_name);

	DEBUG(0,("starting pipe gobble test (%s)\n", pipe_name));

	/* establish connections.  nothing to stop these being re-established. */
	while (retry > 0 && !rpcclient_connect(cli_info))
	{
		retry--;
	}

	if (retry == 0)
	{
		DEBUG(0,("pipe gobble test: connection failed\n"));
		return;
	}
	for (i = 1; i <= numops * 100; i++)
	{
		/* open session.  */
		if (!cli_nt_session_open(smb_cli, pipe_name, &nt_pipe_fnum))
		{
			DEBUG(0,("pipe gobble test: session open failed\n"));
		}

		if (i % 500 == 0)
		{
			DEBUG(0,("calls: %i\n", i));
		}
		count++;
	}

	rpcclient_stop();

	DEBUG(0,("finished pipe gobble test (%s).  count: %d failed: %d\n",
	          pipe_name, count, failed));
}


static void run_handles(int numops, struct client_info *cli_info)
{
	run_lsahandles(numops, cli_info);
	run_samhandles(numops, cli_info);
}

static void run_pipegobbler(int numops, struct client_info *cli_info)
{
	run_pipegobble(numops, cli_info, PIPE_SAMR);
	run_pipegobble(numops, cli_info, PIPE_LSARPC);
}

/****************************************************************************
make tcp connection
****************************************************************************/
static void run_tcpconnect(int numops, struct client_info *info)
{
	int i;
	int failed = 0;

	for (i = 0; i < numops; i++)
	{
		rpcclient_init();

		if (!cli_connect(smb_cli, info->dest_host, &info->dest_ip))
		{
			failed++;
		}
		cli_shutdown(smb_cli);
	}

	DEBUG(0,("tcp connections: count: %d failed: %d\n", numops, failed));
}

/****************************************************************************
  runs n simultaneous functions.
****************************************************************************/
static void create_procs(int nprocs, int numops, 
		struct client_info *cli_info,
		void (*fn)(int, struct client_info *))
{
	int i, status;

	for (i=0;i<nprocs;i++)
	{
		if (fork() == 0)
		{
			int mypid = getpid();
			sys_srandom(mypid ^ time(NULL));
			fn(numops, cli_info);
			dbgflush();
			_exit(0);
		}
	}

	for (i=0;i<nprocs;i++)
	{
		waitpid(0, &status, 0);
	}
}


/****************************************************************************
usage on the program - OUT OF DATE!
****************************************************************************/
static void usage(char *pname)
{
  fprintf(out_hnd, "Usage: %s service <password> [-d debuglevel] [-l log] ",
	   pname);

  fprintf(out_hnd, "\nVersion %s\n",VERSION);
  fprintf(out_hnd, "\t-d debuglevel         set the debuglevel\n");
  fprintf(out_hnd, "\t-l log basename.      Basename for log/debug files\n");
  fprintf(out_hnd, "\t-n netbios name.      Use this name as my netbios name\n");
  fprintf(out_hnd, "\t-m max protocol       set the max protocol level\n");
  fprintf(out_hnd, "\t-I dest IP            use this IP to connect to\n");
  fprintf(out_hnd, "\t-E                    write messages to stderr instead of stdout\n");
  fprintf(out_hnd, "\t-U username           set the network username\n");
  fprintf(out_hnd, "\t-W workgroup          set the workgroup name\n");
  fprintf(out_hnd, "\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n");
  fprintf(out_hnd, "\t-N processes          number of processes\n");
  fprintf(out_hnd, "\t-o operations         number of operations\n");
  fprintf(out_hnd, "\n");
}

enum client_action
{
	CLIENT_NONE,
	CLIENT_IPC,
	CLIENT_SVC
};

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	char *pname = argv[0];
	int opt;
	extern FILE *dbf;
	extern char *optarg;
	extern int optind;
	static pstring servicesf = CONFIGFILE;
	pstring term_code;
	char *cmd_str="";
	mode_t myumask = 0755;
	enum client_action cli_action = CLIENT_NONE;
	int nprocs = 1;
	int numops = 100;

	struct client_info cli_info;

	out_hnd = stdout;

#ifdef KANJI
	pstrcpy(term_code, KANJI);
#else /* KANJI */
	*term_code = 0;
#endif /* KANJI */

	if (!lp_load(servicesf,True, False, False))
	{
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
	}

	codepage_initialise(lp_client_code_page());

	DEBUGLEVEL = 0;

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

	pstrcpy(cli_info.cur_dir , "\\");
	pstrcpy(cli_info.file_sel, "");
	pstrcpy(cli_info.base_dir, "");
	pstrcpy(cli_info.myhostname, "");
	pstrcpy(cli_info.dest_host, "");

	pstrcpy(cli_info.svc_type, "A:");
	pstrcpy(cli_info.share, "");
	pstrcpy(cli_info.service, "");

	ZERO_STRUCT(cli_info.dom.level3_sid);
	pstrcpy(cli_info.dom.level3_dom, "");
	ZERO_STRUCT(cli_info.dom.level5_sid);
	pstrcpy(cli_info.dom.level5_dom, "");


	setup_logging(pname, True);

	TimeInit();
	charset_initialise();

	myumask = umask(0);
	umask(myumask);

	if (!get_myname(global_myname, NULL))
	{
		fprintf(stderr, "Failed to get my hostname.\n");
	}

	password[0] = 0;

	if (argc < 2)
	{
		usage(pname);
		exit(1);
	}

	if (*argv[1] != '-')
	{
		pstrcpy(cli_info.service, argv[1]);  
		/* Convert any '/' characters in the service name to '\' characters */
		string_replace( cli_info.service, '/','\\');
		argc--;
		argv++;

		DEBUG(1,("service: %s\n", cli_info.service));

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
			pstrcpy(password,argv[1]);  
			memset(argv[1],'X',strlen(argv[1]));
			argc--;
			argv++;
		}

		cli_action = CLIENT_SVC;
	}

	while ((opt = getopt(argc, argv,"s:B:O:M:S:i:N:o:n:d:l:hI:EB:U:L:t:m:W:T:D:c:")) != EOF)
	{
		switch (opt)
		{
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
				pstrcpy(user_socket_options,optarg);
				break;	
			}

			case 'S':
			{
				pstrcpy(cli_info.dest_host,optarg);
				strupper(cli_info.dest_host);
				cli_action = CLIENT_IPC;
				break;
			}

			case 'B':
			{
				iface_set_default(NULL,optarg,NULL);
				break;
			}

			case 'i':
			{
				pstrcpy(scope, optarg);
				break;
			}

			case 'U':
			{
				char *lp;
				pstrcpy(user_name,optarg);
				if ((lp=strchr(user_name,'%')))
				{
					*lp = 0;
					pstrcpy(password,lp+1);
					got_pass = True;
					memset(strchr(optarg,'%')+1,'X',strlen(password));
				}
				break;
			}

			case 'W':
			{
				pstrcpy(domain,optarg);
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

			case 'N':
			{
				nprocs = atoi(optarg);
				break;
			}

			case 'o':
			{
				numops = atoi(optarg);
				break;
			}

			case 'n':
			{
				fstrcpy(global_myname, optarg);
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
				slprintf(debugf, sizeof(debugf)-1,
				         "%s.client",optarg);
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
				pstrcpy(servicesf, optarg);
				break;
			}

			case 't':
			{
				pstrcpy(term_code, optarg);
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

	strupper(global_myname);
	fstrcpy(cli_info.myhostname, global_myname);

	DEBUG(3,("%s client started (version %s)\n",timestring(),VERSION));

	load_interfaces();

	if (cli_action == CLIENT_IPC)
	{
		pstrcpy(cli_info.share, "IPC$");
		pstrcpy(cli_info.svc_type, "IPC");
	}

	fstrcpy(cli_info.mach_acct, cli_info.myhostname);
	strupper(cli_info.mach_acct);
	fstrcat(cli_info.mach_acct, "$");

	make_nmb_name(&called , dns_to_netbios_name(cli_info.dest_host ), cli_info.name_type, scope);
	make_nmb_name(&calling, dns_to_netbios_name(cli_info.myhostname), 0x0               , scope);

	get_passwd();
/*
	create_procs(nprocs, numops, &cli_info, run_enums_test);

	if (password[0] != 0)
	{
		create_procs(nprocs, numops, &cli_info, run_ntlogin_test);
	}
*/

/*
	create_procs(nprocs, numops, &cli_info, run_randomrpc);
	create_procs(nprocs, numops, &cli_info, run_pipegobbler);
	create_procs(nprocs, numops, &cli_info, run_tcpconnect);
*/
	create_procs(nprocs, numops, &cli_info, run_handles);

	fflush(out_hnd);

	return(0);
}
