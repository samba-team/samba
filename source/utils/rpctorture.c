/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   RPC Torture client
   Copyright (C) Andrew Tridgell              1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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

extern int DEBUGLEVEL;

static int numops = 2;
static int nprocs = 1;

extern FILE* out_hnd;

/****************************************************************************
  log in as an nt user, log out again. 
****************************************************************************/
void run_enums_test(struct client_info *info, int argc, char *argv[])
{
	int i;

	/* establish connections.  nothing to stop these being re-established. */
	for (i = 0; i < numops; i++)
	{
		cmd_srv_enum_sess(info, argc, argv);
		cmd_srv_enum_shares(info, argc, argv);
		cmd_srv_enum_files(info, argc, argv);
		cmd_srv_enum_conn(info, argc, argv);
	}
}

/****************************************************************************
  log in as an nt user, log out again. 
****************************************************************************/
void run_ntlogin_test(struct client_info *info, int argc, char *argv[])
{
	int i;

	for (i = 0; i < numops; i++)
	{
		cmd_netlogon_login_test(info, argc, argv);
	}
}

#if 0
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
static void random_rpc_pipe_enc(char *pipe_name, struct client_info *info, int argc, char *argv[],
		int numops)
{
	uint16 nt_pipe_fnum;
	int i;

	DEBUG(0,("starting random rpc test on %s (encryped)\n", pipe_name));

	/* establish connections.  nothing to stop these being re-established. */
	if (!rpcclient_connect(info))
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

	for (i = 1; i <= numops ; i++)
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
static void random_rpc_pipe(char *pipe_name, struct client_info *info, int argc, char *argv[],
		int numops)
{
	uint16 nt_pipe_fnum;
	int i;

	DEBUG(0,("starting random rpc test on %s\n", pipe_name));

	/* establish connections.  nothing to stop these being re-established. */
	if (!rpcclient_connect(info))
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

	for (i = 1; i <= numops ; i++)
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

static void run_randomrpc(struct client_info *info, int argc, char *argv[])
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
		random_rpc_pipe(pipes[i], info, numops);
#if 0
		random_rpc_pipe_enc(pipes[i], info, numops);
#endif

		i++;
	}
}

#endif

static void run_samhandles(struct client_info *info, int argc, char *argv[])
{
	int i;
	int count = 0;
	int failed = 0;
	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(0,("starting sam handle test\n"));

	for (i = 1; i <= numops ; i++)
	{
		POLICY_HND pol;
		if (!samr_connect(srv_name, 0x20, &pol))
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

	DEBUG(0,("finished samhandle test.  count: %d failed: %d\n", count, failed));
}


static void run_lsahandles(struct client_info *info, int argc, char *argv[])
{
	int i;
	int count = 0;
	int failed = 0;
	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->myhostname);
	strupper(srv_name);

	DEBUG(0,("starting lsa handle test\n"));

	/* establish connections.  nothing to stop these being re-established. */
	for (i = 1; i <= numops; i++)
	{
		POLICY_HND pol;
		if (!lsa_open_policy(srv_name, &pol, False, 0x02000000))
		{
			failed++;
		}
		if (i % 500 == 0)
		{
			DEBUG(0,("calls: %i\n", i));
		}
		count++;
	}

	DEBUG(0,("finished lsahandle test.  count: %d failed: %d\n", count, failed));
}


#if 0
static void run_pipegobble(struct client_info *info, int argc, char *argv[], char *pipe_name)
{
	uint16 nt_pipe_fnum;
	int i;
	int count = 0;
	int failed = 0;
	int retry = 500;
	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->myhostname);
	strupper(srv_name);

	DEBUG(0,("starting pipe gobble test (%s)\n", pipe_name));

	/* establish connections.  nothing to stop these being re-established. */
	while (retry > 0 && !rpcclient_connect(info))
	{
		retry--;
	}

	if (retry == 0)
	{
		DEBUG(0,("pipe gobble test: connection failed\n"));
		return;
	}
	for (i = 1; i <= numops ; i++)
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

static void run_pipegobbler(struct client_info *info, int argc, char *argv[])
{
	run_pipegobble(numops, info, PIPE_SAMR);
	run_pipegobble(numops, info, PIPE_LSARPC);
}


static void run_handles(struct client_info *info, int argc, char *argv[])
{
	run_lsahandles(numops, info);
	run_samhandles(numops, info);
}

/****************************************************************************
make tcp connection
****************************************************************************/
static void run_tcpconnect(struct client_info *info)
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

#endif

static void run_torture_set(struct client_info *info, int *argc, char **argv[])
{
	int opt;
	int skiparg = 0;
	int i;
	extern int optind;

	while ((opt = getopt(*argc, *argv,"N:o:")) != EOF)
	{
		switch (opt)
		{
			case 'N':
			{
				nprocs = atoi(optarg);
				skiparg+=2;
				break;
			}

			case 'o':
			{
				numops = atoi(optarg);
				skiparg+=2;
				break;
			}
		}
	}

	report(out_hnd,"Num Operations: %d. Num Processes: %d\n",
			numops, nprocs);

	optind = 0;

	/* remove the already-used arguments! */
	for (i = 0; i < skiparg; i++)
	{
		int arg = 1+i;
		DEBUG(10,("freeing arg %d - %s\n", arg, (*argv)[arg]));
		safe_free((*argv)[arg]);
		(*argv)[arg] = NULL;
	}
	/* shift-down the arguments */
	for (i = 0; i < skiparg; i++)
	{
		int arg = 1+i;
		DEBUG(10,("skipping arg %d - %s\n", arg, (*argv)[arg]));
		(*argv)[arg] = (*argv)[arg+skiparg];
	}
	for (i = (*argc)-skiparg; i < (*argc); i++)
	{
		/* zero the last arguments */
		(*argv)[i] = NULL;
	}
	(*argc) -= skiparg;
}

static void cmd_torture_set(struct client_info *info, int argc, char *argv[])
{
	run_torture_set(info, &argc, &argv);
}

/****************************************************************************
  runs n simultaneous functions.
****************************************************************************/
static void create_procs(int num_procs,
		struct client_info *info, int argc, char *argv[],
		void (*fn)(struct client_info *, int, char *[]))
{
	int i, status;

	run_torture_set(info, &argc, &argv);

	for (i=0;i<num_procs;i++)
	{
		if (fork() == 0)
		{
			int mypid = getpid();
			sys_srandom(mypid ^ time(NULL));
			fn(info, argc, argv);
			dbgflush();
			_exit(0);
		}
	}

	for (i=0;i<nprocs;i++)
	{
		waitpid(0, &status, 0);
	}
}

#define CMD_PROC_WRAP(cmd_fn_name, run_fn_name) \
static void cmd_fn_name(struct client_info *info, int argc, char *argv[]) \
{ \
	create_procs(nprocs, info, argc, argv, run_fn_name); \
}

CMD_PROC_WRAP(cmd_enums_test, run_enums_test)
CMD_PROC_WRAP(cmd_lsa_handles_test, run_lsahandles)
CMD_PROC_WRAP(cmd_sam_handles_test, run_samhandles)
CMD_PROC_WRAP(cmd_login_test, run_ntlogin_test)

struct command_set tor_commands[] =
{
	{
		"setenv",
		cmd_torture_set,
		"Sets default for Num ops (-o) and Num Process (-N)",
		{NULL, NULL}
	},
	{
		"samhandles",
		cmd_sam_handles_test,
		"SamrConnect - Handles test",
		{NULL, NULL}
	},
	{
		"lsahandles",
		cmd_lsa_handles_test,
		"LsarOpenPolicy - Handles test",
		{NULL, NULL}
	},
	{
		"logintest",
		cmd_login_test,
		"NT User Login",
		{NULL, NULL}
	},
	{
		"enumtest",
		cmd_enums_test,
		"NetShareEnum, NetConnectionEnum, NetFileEnum, NetSessionEnum",
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
 This defines the commands supported by this client
 ****************************************************************************/

 int main(int argc, char *argv[])
{
	add_command_set(tor_commands);
	return command_main(argc, argv);
}
