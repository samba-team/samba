/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-1998
   
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

static fstring host, workgroup, share, password, username, myname;
static int max_protocol = PROTOCOL_NT1;
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


static BOOL open_connection(struct cli_state *c)
{
	if (!cli_initialise(c) || !cli_connect(c, host, NULL)) {
		printf("Failed to connect with %s\n", host);
		return False;
	}

	if (!cli_session_request(c, host, 0x20, myname)) {
		printf("%s rejected the session\n",host);
		cli_shutdown(c);
		return False;
	}

	c->protocol = max_protocol;

	if (!cli_negprot(c)) {
		printf("%s rejected the negprot (%s)\n",host, cli_errstr(c));
		cli_shutdown(c);
		return False;
	}

	if (!cli_session_setup(c, username, password, strlen(password),
			       "", 0, workgroup)) {
		printf("%s rejected the sessionsetup (%s)\n", host, cli_errstr(c));
		cli_shutdown(c);
		return False;
	}

	if (!cli_send_tconX(c, share, "A:", password, strlen(password)+1)) {
		printf("%s refused tree connect (%s)\n", host, cli_errstr(c));
		cli_shutdown(c);
		return False;
	}

	return True;
}



static void close_connection(struct cli_state *c)
{
	if (!cli_tdis(c)) {
		printf("tdis failed (%s)\n", cli_errstr(c));
	}

	cli_shutdown(c);
}


static BOOL wait_lock(struct cli_state *c, int fnum, uint32 offset, uint32 len)
{
	while (!cli_lock(c, fnum, offset, len, -1)) {
		int eclass, num;
		cli_error(c, &eclass, &num);
		if (eclass != ERRDOS || num != ERRlock) {
			printf("lock failed (%s)\n", 
			       cli_errstr(c));
			return False;
		}
	}
	return True;
}


static BOOL rw_torture(struct cli_state *c, int numops)
{
	char *lockfname = "\\torture.lck";
	fstring fname;
	int fnum;
	int fnum2;
	int pid2, pid = getpid();
	int i;

	fnum2 = cli_open(c, lockfname, O_RDWR | O_CREAT | O_EXCL, 
			 DENY_NONE);
	if (fnum2 == -1)
		fnum2 = cli_open(c, lockfname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open of %s failed (%s)\n", lockfname, cli_errstr(c));
		return False;
	}


	for (i=0;i<numops;i++) {
		unsigned n = (unsigned)random()%10;
		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}
		slprintf(fname,sizeof(fstring)-1,"\\torture.%u", n);

		if (!wait_lock(c, fnum2, n*sizeof(int), sizeof(int))) {
			return False;
		}

		fnum = cli_open(c, fname, O_RDWR | O_CREAT | O_TRUNC, DENY_ALL);
		if (fnum == -1) {
			printf("open failed (%s)\n", cli_errstr(c));
			break;
		}

		if (cli_write(c, fnum, (char *)&pid, 0, sizeof(pid)) != sizeof(pid)) {
			printf("write failed (%s)\n", cli_errstr(c));
		}

		pid2 = 0;

		if (cli_read(c, fnum, (char *)&pid2, 0, sizeof(pid)) != sizeof(pid)) {
			printf("read failed (%s)\n", cli_errstr(c));
		}

		if (pid2 != pid) {
			printf("data corruption!\n");
		}

		if (!cli_close(c, fnum)) {
			printf("close failed (%s)\n", cli_errstr(c));
		}

		if (!cli_unlink(c, fname)) {
			printf("unlink failed (%s)\n", cli_errstr(c));
		}

		if (!cli_unlock(c, fnum2, n*sizeof(int), sizeof(int), -1)) {
			printf("unlock failed (%s)\n", cli_errstr(c));
		}
	}

	cli_close(c, fnum2);
	cli_unlink(c, lockfname);

	printf("%d\n", i);

	return True;
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
	printf("\t-m maximum protocol\n");
	printf("\n");

	exit(1);
}



static void run_torture(int numops)
{
	static struct cli_state cli;

	if (open_connection(&cli)) {
		cli_sockopt(&cli, sockops);

		printf("pid %d OK\n", getpid());

		rw_torture(&cli, numops);

		close_connection(&cli);
	}
}

/*
  This test checks for two things:

  1) correct support for retaining locks over a close (ie. the server
     must not use posix semantics)
  2) support for lock timeouts
 */
static void run_locktest1(void)
{
	static struct cli_state cli1, cli2;
	char *fname = "\\locktest.lck";
	int fnum1, fnum2, fnum3;
	time_t t1, t2;

	if (!open_connection(&cli1) || !open_connection(&cli2)) {
		return;
	}
	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	printf("starting locktest1\n");

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return;
	}
	fnum2 = cli_open(&cli1, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open2 of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return;
	}
	fnum3 = cli_open(&cli2, fname, O_RDWR, DENY_NONE);
	if (fnum3 == -1) {
		printf("open3 of %s failed (%s)\n", fname, cli_errstr(&cli2));
		return;
	}

	if (!cli_lock(&cli1, fnum1, 0, 4, 0)) {
		printf("lock1 failed (%s)\n", cli_errstr(&cli1));
		return;
	}


	if (cli_lock(&cli2, fnum3, 0, 4, 0)) {
		printf("lock2 succeeded! This is a locking bug\n");
		return;
	} else {
		int eclass, num;
		cli_error(&cli2, &eclass, &num);
		if (eclass != ERRDOS || num != ERRlock) {
			printf("error should have been ERRDOS/ERRlock (%s)\n", 
			       cli_errstr(&cli2));
			return;
		}
	}


	printf("Testing lock timeouts\n");
	t1 = time(NULL);
	if (cli_lock(&cli2, fnum3, 0, 4, 10*1000)) {
		printf("lock3 succeeded! This is a locking bug\n");
		return;
	} else {
		int eclass, num;
		cli_error(&cli2, &eclass, &num);
		if (eclass != ERRDOS || num != ERRlock) {
			printf("error should have been ERRDOS/ERRlock (%s)\n", 
			       cli_errstr(&cli2));
			return;
		}
	}
	t2 = time(NULL);

	if (t2 - t1 < 5) {
		printf("error: This server appears not to support timed lock requests\n");
	}

	if (!cli_close(&cli1, fnum2)) {
		printf("close1 failed (%s)\n", cli_errstr(&cli1));
		return;
	}

	if (cli_lock(&cli2, fnum3, 0, 4, 0)) {
		printf("lock4 succeeded! This is a locking bug\n");
		return;
	} else {
		int eclass, num;
		cli_error(&cli2, &eclass, &num);
		if (eclass != ERRDOS || num != ERRlock) {
			printf("error should have been ERRDOS/ERRlock (%s)\n", 
			       cli_errstr(&cli2));
			return;
		}
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli1));
		return;
	}

	if (!cli_close(&cli2, fnum3)) {
		printf("close3 failed (%s)\n", cli_errstr(&cli2));
		return;
	}

	if (!cli_unlink(&cli1, fname)) {
		printf("unlink failed (%s)\n", cli_errstr(&cli1));
		return;
	}


	close_connection(&cli1);
	close_connection(&cli2);

	printf("Passed locktest1\n");
}


/*
  This test checks that 

  1) the server supports multiple locking contexts on the one SMB
  connection, distinguished by PID.  

  2) the server correctly fails overlapping locks made by the same PID (this
     goes against POSIX behaviour, which is why it is tricky to implement)

  3) the server denies unlock requests by an incorrect client PID
*/
static void run_locktest2(void)
{
	static struct cli_state cli;
	char *fname = "\\locktest.lck";
	int fnum1, fnum2, fnum3;

	if (!open_connection(&cli)) {
		return;
	}

	cli_sockopt(&cli, sockops);

	printf("starting locktest2\n");

	cli_unlink(&cli, fname);

	cli_setpid(&cli, 1);

	fnum1 = cli_open(&cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli));
		return;
	}

	fnum2 = cli_open(&cli, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open2 of %s failed (%s)\n", fname, cli_errstr(&cli));
		return;
	}

	cli_setpid(&cli, 2);

	fnum3 = cli_open(&cli, fname, O_RDWR, DENY_NONE);
	if (fnum3 == -1) {
		printf("open3 of %s failed (%s)\n", fname, cli_errstr(&cli));
		return;
	}

	cli_setpid(&cli, 1);

	if (!cli_lock(&cli, fnum1, 0, 4, 0)) {
		printf("lock1 failed (%s)\n", cli_errstr(&cli));
		return;
	}

	if (cli_lock(&cli, fnum2, 0, 4, 0)) {
		printf("lock2 succeeded! This is a locking bug\n");
	} else {
		int eclass, num;
		cli_error(&cli, &eclass, &num);
		if (eclass != ERRDOS || num != ERRlock) {
			printf("error should have been ERRDOS/ERRlock (%s)\n", 
			       cli_errstr(&cli));
			return;
		}
	}

	cli_setpid(&cli, 2);

	if (cli_unlock(&cli, fnum1, 0, 4, 0)) {
		printf("unlock1 succeeded! This is a locking bug\n");
	}

	if (cli_lock(&cli, fnum3, 0, 4, 0)) {
		printf("lock3 succeeded! This is a locking bug\n");
	} else {
		int eclass, num;
		cli_error(&cli, &eclass, &num);
		if (eclass != ERRDOS || num != ERRlock) {
			printf("error should have been ERRDOS/ERRlock (%s)\n", 
			       cli_errstr(&cli));
			return;
		}
	}

	cli_setpid(&cli, 1);

	if (!cli_close(&cli, fnum1)) {
		printf("close1 failed (%s)\n", cli_errstr(&cli));
		return;
	}

	if (!cli_close(&cli, fnum2)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli));
		return;
	}

	if (!cli_close(&cli, fnum3)) {
		printf("close3 failed (%s)\n", cli_errstr(&cli));
		return;
	}

	close_connection(&cli);

	printf("locktest2 finished\n");
}


/*
  This test checks that 

  1) the server supports the full offset range in lock requests
*/
static void run_locktest3(int numops)
{
	static struct cli_state cli1, cli2;
	char *fname = "\\locktest.lck";
	int fnum1, fnum2, i;
	uint32 offset;

#define NEXT_OFFSET offset += (~(uint32)0) / numops

	if (!open_connection(&cli1) || !open_connection(&cli2)) {
		return;
	}
	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	printf("starting locktest3\n");

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return;
	}
	fnum2 = cli_open(&cli2, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open2 of %s failed (%s)\n", fname, cli_errstr(&cli2));
		return;
	}

	for (offset=i=0;i<numops;i++) {
		NEXT_OFFSET;
		if (!cli_lock(&cli1, fnum1, offset-1, 1, 0)) {
			printf("lock1 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1));
			return;
		}

		if (!cli_lock(&cli2, fnum2, offset-2, 1, 0)) {
			printf("lock2 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1));
			return;
		}
	}

	for (offset=i=0;i<numops;i++) {
		NEXT_OFFSET;

		if (cli_lock(&cli1, fnum1, offset-2, 1, 0)) {
			printf("error: lock1 %d succeeded!\n", i);
			return;
		}

		if (cli_lock(&cli2, fnum2, offset-1, 1, 0)) {
			printf("error: lock2 %d succeeded!\n", i);
			return;
		}

		if (cli_lock(&cli1, fnum1, offset-1, 1, 0)) {
			printf("error: lock3 %d succeeded!\n", i);
			return;
		}

		if (cli_lock(&cli2, fnum2, offset-2, 1, 0)) {
			printf("error: lock4 %d succeeded!\n", i);
			return;
		}
	}

	for (offset=i=0;i<numops;i++) {
		NEXT_OFFSET;

		if (!cli_unlock(&cli1, fnum1, offset-1, 1, 0)) {
			printf("unlock1 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1));
			return;
		}

		if (!cli_unlock(&cli2, fnum2, offset-2, 1, 0)) {
			printf("unlock2 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1));
			return;
		}
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("close1 failed (%s)\n", cli_errstr(&cli1));
	}

	if (!cli_close(&cli2, fnum2)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli2));
	}

	if (!cli_unlink(&cli1, fname)) {
		printf("unlink failed (%s)\n", cli_errstr(&cli1));
		return;
	}

	close_connection(&cli1);
	close_connection(&cli2);

	printf("finished locktest3\n");
}


/*
  This test checks that 

  1) the server does not allow an unlink on a file that is open
*/
static void run_unlinktest(void)
{
	static struct cli_state cli;
	char *fname = "\\unlink.tst";
	int fnum;

	if (!open_connection(&cli)) {
		return;
	}

	cli_sockopt(&cli, sockops);

	printf("starting unlink test\n");

	cli_unlink(&cli, fname);

	cli_setpid(&cli, 1);

	fnum = cli_open(&cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli));
		return;
	}

	if (cli_unlink(&cli, fname)) {
		printf("error: server allowed unlink on an open file\n");
	}

	cli_close(&cli, fnum);
	cli_unlink(&cli, fname);

	close_connection(&cli);

	printf("unlink test finished\n");
}



static void browse_callback(char *sname, uint32 stype, char *comment)
{
	printf("\t%20.20s %08x %s\n", sname, stype, comment);
}


/*
  This test checks the browse list code

*/
static void run_browsetest(void)
{
	static struct cli_state cli;

	printf("starting browse test\n");

	if (!open_connection(&cli)) {
		return;
	}

	printf("domain list:\n");
	cli_NetServerEnum(&cli, workgroup, 
			  SV_TYPE_DOMAIN_ENUM,
			  browse_callback);

	printf("machine list:\n");
	cli_NetServerEnum(&cli, workgroup, 
			  SV_TYPE_ALL,
			  browse_callback);

	close_connection(&cli);

	printf("browse test finished\n");
}


/*
  This checks how the getatr calls works
*/
static void run_attrtest(void)
{
	static struct cli_state cli;
	int fnum;
	time_t t, t2;
	char *fname = "\\attrib.tst";

	printf("starting attrib test\n");

	if (!open_connection(&cli)) {
		return;
	}

	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_close(&cli, fnum);
	if (!cli_getatr(&cli, fname, NULL, NULL, &t)) {
		printf("getatr failed (%s)\n", cli_errstr(&cli));
	}

	if (abs(t - time(NULL)) > 2) {
		printf("ERROR: SMBgetatr bug. time is %s",
		       ctime(&t));
		t = time(NULL);
	}

	t2 = t-60*60*24; /* 1 day ago */

	if (!cli_setatr(&cli, fname, 0, t2)) {
		printf("setatr failed (%s)\n", cli_errstr(&cli));
	}

	if (!cli_getatr(&cli, fname, NULL, NULL, &t)) {
		printf("getatr failed (%s)\n", cli_errstr(&cli));
	}

	if (t != t2) {
		printf("ERROR: getatr/setatr bug. times are\n%s",
		       ctime(&t));
		printf("%s", ctime(&t2));
	}

	cli_unlink(&cli, fname);

	close_connection(&cli);

	printf("attrib test finished\n");
}


/*
  This checks a couple of trans2 calls
*/
static void run_trans2test(void)
{
	static struct cli_state cli;
	int fnum;
	uint32 size;
	time_t c_time, a_time, m_time, w_time, m_time2;
	char *fname = "\\trans2.tst";
	char *dname = "\\trans2";
	char *fname2 = "\\trans2\\trans2.tst";

	printf("starting trans2 test\n");

	if (!open_connection(&cli)) {
		return;
	}

	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	if (!cli_qfileinfo(&cli, fnum, &c_time, &a_time, &m_time, &size)) {
		printf("ERROR: qfileinfo failed (%s)\n", cli_errstr(&cli));
	}
	cli_close(&cli, fnum);

	sleep(2);

	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_close(&cli, fnum);

	if (!cli_qpathinfo(&cli, fname, &c_time, &a_time, &m_time, &size)) {
		printf("ERROR: qpathinfo failed (%s)\n", cli_errstr(&cli));
	} else {
		if (c_time != m_time) {
			printf("create time=%s", ctime(&c_time));
			printf("modify time=%s", ctime(&m_time));
			printf("This system appears to have sticky create times\n");
		}
		if (a_time % (60*60) == 0) {
			printf("access time=%s", ctime(&a_time));
			printf("This system appears to set a midnight access time\n");
		}

		if (abs(m_time - time(NULL)) > 60*60*24*7) {
			printf("ERROR: totally incorrect times - maybe word reversed?\n");
		}
	}


	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_close(&cli, fnum);
	if (!cli_qpathinfo2(&cli, fname, &c_time, &a_time, &m_time, 
			    &w_time, &size)) {
		printf("ERROR: qpathinfo2 failed (%s)\n", cli_errstr(&cli));
	} else {
		if (w_time < 60*60*24*2) {
			printf("write time=%s", ctime(&w_time));
			printf("This system appears to set a initial 0 write time\n");
		}
	}

	cli_unlink(&cli, fname);


	/* check if the server updates the directory modification time
           when creating a new file */
	if (!cli_mkdir(&cli, dname)) {
		printf("ERROR: mkdir failed (%s)\n", cli_errstr(&cli));
	}
	sleep(3);
	if (!cli_qpathinfo2(&cli, "\\trans2\\", &c_time, &a_time, &m_time, 
			    &w_time, &size)) {
		printf("ERROR: qpathinfo2 failed (%s)\n", cli_errstr(&cli));
	}

	fnum = cli_open(&cli, fname2, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_write(&cli, fnum,  (char *)&fnum, 0, sizeof(fnum));
	cli_close(&cli, fnum);
	if (!cli_qpathinfo2(&cli, "\\trans2\\", &c_time, &a_time, &m_time2, 
			    &w_time, &size)) {
		printf("ERROR: qpathinfo2 failed (%s)\n", cli_errstr(&cli));
	} else {
		if (m_time2 == m_time)
			printf("This system does not update directory modification times\n");
	}
	cli_unlink(&cli, fname2);
	cli_rmdir(&cli, dname);


	close_connection(&cli);

	printf("trans2 test finished\n");
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
	  pstrcpy(username,getenv("LOGNAME"));
	}

	argc--;
	argv++;


	while ((opt = getopt(argc, argv, "hW:U:n:N:O:o:m:")) != EOF) {
		switch (opt) {
		case 'W':
			fstrcpy(workgroup,optarg);
			break;
		case 'm':
			max_protocol = interpret_protocol(optarg, max_protocol);
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
			pstrcpy(username,optarg);
			p = strchr(username,'%');
			if (p) {
				*p = 0;
				pstrcpy(password, p+1);
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
			pstrcpy(password, p);
			gotpass = 1;
		}
	}

	printf("host=%s share=%s user=%s myname=%s\n", 
	       host, share, username, myname);

	start_timer();
	create_procs(nprocs, numops);
	printf("rw_torture: %g secs\n", end_timer());

	run_locktest1();
	run_locktest2();
	run_locktest3(numops);
	run_unlinktest();
	run_browsetest();
	run_attrtest();
	run_trans2test();

	return(0);
}


