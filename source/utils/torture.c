/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997
   
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

static struct cli_state cli;
static fstring host, workgroup, share, password, username, myname;
static char *sockops="";


static struct timeval tp1,tp2;

static void start_timer()
{
	gettimeofday(&tp1,NULL);
}

static double end_timer()
{
	gettimeofday(&tp2,NULL);
	return((tp2.tv_sec - tp1.tv_sec) + 
	       (tp2.tv_usec - tp1.tv_usec)*1.0e-6);
}


static int open_connection(void)
{
	if (!cli_initialise(&cli) || !cli_connect(&cli, host, NULL)) {
		printf("Failed to connect with %s\n", host);
	}

	if (!cli_session_request(&cli, host, 0x20, myname)) {
		printf("%s rejected the session\n",host);
		cli_shutdown(&cli);
		return -1;
	}

	if (!cli_negprot(&cli)) {
		printf("%s rejected the negprot (%s)\n",host, cli_errstr(&cli));
		cli_shutdown(&cli);
		return -1;
	}

	if (!cli_session_setup(&cli, username, password, strlen(password),
			       "", 0, workgroup)) {
		printf("%s rejected the sessionsetup (%s)\n", host, cli_errstr(&cli));
		cli_shutdown(&cli);
		return -1;
	}

	if (!cli_send_tconX(&cli, share, "A:", password, strlen(password)+1)) {
		printf("%s refused tree connect (%s)\n", host, cli_errstr(&cli));
		cli_shutdown(&cli);
		return -1;
	}

	return 0;
}



static void close_connection(void)
{
	if (!cli_tdis(&cli)) {
		printf("tdis failed (%s)\n", cli_errstr(&cli));
	}

	cli_shutdown(&cli);
}




static BOOL wait_lock(int fnum, uint32 offset, uint32 len)
{
	while (!cli_lock(&cli, fnum, offset, len, -1)) {
		int eclass, num;
		cli_error(&cli, &eclass, &num);
		if (eclass != ERRDOS || num != ERRlock) {
			printf("lock failed (%s)\n", 
			       cli_errstr(&cli));
			return False;
		}
	}
	return True;
}


static int rw_torture(int numops)
{
	char *lockfname = "\\torture.lck";
	fstring fname;
	int fnum;
	int fnum2;
	int pid2, pid = getpid();
	int i;

	fnum2 = cli_open(&cli, lockfname, O_RDWR | O_CREAT | O_EXCL, 
			 DENY_NONE);
	if (fnum2 == -1)
		fnum2 = cli_open(&cli, lockfname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open of %s failed (%s)\n", lockfname, cli_errstr(&cli));
		return -1;
	}


	for (i=0;i<numops;i++) {
		unsigned n = (unsigned)random()%10;
		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}
		sprintf(fname,"\\torture.%u", n);

		if (!wait_lock(fnum2, n*sizeof(int), sizeof(int))) {
			return -1;
		}

		fnum = cli_open(&cli, fname, O_RDWR | O_CREAT | O_TRUNC, DENY_ALL);
		if (fnum == -1) {
			printf("open failed (%s)\n", cli_errstr(&cli));
			break;
		}

		if (cli_write(&cli, fnum, (char *)&pid, 0, sizeof(pid)) != sizeof(pid)) {
			printf("write failed (%s)\n", cli_errstr(&cli));
		}

		pid2 = 0;

		if (cli_read(&cli, fnum, (char *)&pid2, 0, sizeof(pid)) != sizeof(pid)) {
			printf("read failed (%s)\n", cli_errstr(&cli));
		}

		if (pid2 != pid) {
			printf("data corruption!\n");
		}

		if (!cli_close(&cli, fnum)) {
			printf("close failed (%s)\n", cli_errstr(&cli));
		}

		if (!cli_unlink(&cli, fname)) {
			printf("unlink failed (%s)\n", cli_errstr(&cli));
		}

		if (!cli_unlock(&cli, fnum2, n*sizeof(int), sizeof(int), -1)) {
			printf("unlock failed (%s)\n", cli_errstr(&cli));
		}
	}

	printf("%d\n", i);

	return 0;
}

static void usage(void)
{
	printf("Usage: smbtorture \\\\server\\share <options>\n");

	printf("\t-U user%%pass\n");
	printf("\t-N numprocs\n");
	printf("\t-n my_netbios_name\n");
	printf("\t-W workgroup\n");
	printf("\t-o num_operations\n");
	printf("\t-O socket_options\n");
	printf("\n");

	exit(1);
}



static void run_torture(int numops)
{
	if (open_connection() == 0) {
		cli_sockopt(&cli, sockops);

		printf("pid %d OK\n", getpid());

		rw_torture(numops);

		close_connection();
	}
}


static void create_procs(int nprocs, int numops)
{
	int i, status;

	for (i=0;i<nprocs;i++) {
		if (fork() == 0) {
			int mypid = getpid();
			srandom(mypid ^ time(NULL));
			run_torture(numops);
			_exit(0);
		}
	}

	for (i=0;i<nprocs;i++)
		waitpid(0, &status, 0);
}



/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	int nprocs=1, numops=100;
	int opt;
	char *p;
	int gotpass = 0;
	extern char *optarg;
	extern int optind;
	extern FILE *dbf;

	dbf = stdout;

	charset_initialise();

	if (argc < 2) {
		usage();
	}

	if (strncmp(argv[1], "\\\\", 2)) {
		usage();
	}

	fstrcpy(host, &argv[1][2]);
	p = strchr(&host[2],'\\');
	if (!p) {
		usage();
	}
	*p = 0;
	fstrcpy(share, p+1);

	get_myname(myname,NULL);

	if (*username == 0 && getenv("LOGNAME")) {
	  strcpy(username,getenv("LOGNAME"));
	}

	argc--;
	argv++;


	while ((opt = getopt(argc, argv, "hW:U:n:N:O:o:")) != EOF) {
		switch (opt) {
		case 'W':
			fstrcpy(workgroup,optarg);
			break;
		case 'N':
			nprocs = atoi(optarg);
			break;
		case 'o':
			numops = atoi(optarg);
			break;
		case 'O':
			sockops = optarg;
			break;
		case 'n':
			fstrcpy(myname, optarg);
			break;
		case 'U':
			strcpy(username,optarg);
			p = strchr(username,'%');
			if (p) {
				*p = 0;
				strcpy(password, p+1);
				gotpass = 1;
			}
			break;
		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			usage();
		}
	}


	while (!gotpass) {
		p = getpass("Password:");
		if (p) {
			strcpy(password, p);
			gotpass = 1;
		}
	}

	printf("host=%s share=%s user=%s myname=%s\n", 
	       host, share, username, myname);

	start_timer();
	create_procs(nprocs, numops);
	printf("rw_torture: %g secs\n", end_timer());

	return(0);
}


