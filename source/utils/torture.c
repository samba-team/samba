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

#define NO_SYSLOG

#include "includes.h"

extern int DEBUGLEVEL;
extern pstring debugf;

static fstring host, workgroup, share, password, username, myname;
static int max_protocol = PROTOCOL_NT1;
static char *sockops="";


static struct timeval tp1,tp2;

static void start_timer(void)
{
	gettimeofday(&tp1,NULL);
}

static double end_timer(void)
{
	gettimeofday(&tp2,NULL);
	return((tp2.tv_sec - tp1.tv_sec) + 
	       (tp2.tv_usec - tp1.tv_usec)*1.0e-6);
}

#define FAILED_NO_ERROR            0
#define FAILED_TCP_CONNECT         1
#define FAILED_SESSION_REQ         2
#define FAILED_SMB_SESS_SETUP      3
#define FAILED_SMB_TCON            4
#define FAILED_SMB_NEGPROT         5
#define FAILED_CLI_STATE_INIT      6
#define NUM_ERR_STATES             7

static char *smb_messages[] =
{
	"No errors in connection",
	"TCP connection         ",
	"NetBIOS Session Request",
	"SMB Session Setup      ",
	"SMB Tcon               ",
	"SMB Negprot            ",
	"Client initialisation  "
};

static int open_connection(struct cli_state *c)
{
	struct nmb_name called, calling;

	ZERO_STRUCTP(c);

	make_nmb_name(&calling, myname, 0x0, "");
	make_nmb_name(&called , host, 0x20, "");

	if (!cli_initialise(c))
	{
		DEBUG(0,("Failed to connect with %s\n", host));
		return FAILED_CLI_STATE_INIT;
	}

	if (!cli_connect(c, host, NULL)) {
		DEBUG(0,("Failed to connect with %s\n", host));
		return FAILED_TCP_CONNECT;
	}

	if (!cli_session_request(c, &calling, &called)) {
		cli_shutdown(c);
		DEBUG(0,("%s rejected the session\n",host));
		return FAILED_SESSION_REQ;
	}

	if (!cli_negprot(c)) {
		DEBUG(0,("%s rejected the negprot (%s)\n",host, cli_errstr(c)));
		cli_shutdown(c);
		return FAILED_SMB_NEGPROT;
	}

	if (!cli_session_setup(c, username, 
			       password, strlen(password),
			       password, strlen(password),
			       workgroup)) {
		DEBUG(0,("%s rejected the sessionsetup (%s)\n", host, cli_errstr(c)));
		cli_shutdown(c);
		return FAILED_SMB_SESS_SETUP;
	}

	if (!cli_send_tconX(c, share, "?????",
			    password, strlen(password)+1)) {
		DEBUG(0,("%s refused tree connect (%s)\n", host, cli_errstr(c)));
		cli_shutdown(c);
		return FAILED_SMB_TCON;
	}

	return FAILED_NO_ERROR;
}


static void close_connection(struct cli_state *c)
{
	if (!cli_tdis(c)) {
		DEBUG(0,("tdis failed (%s)\n", cli_errstr(c)));
	}

	cli_shutdown(c);
}


/* check if the server produced the expected error code */
static BOOL check_error(struct cli_state *c, 
			uint8 eclass, uint32 ecode, uint32 nterr)
{
	uint8 class;
	uint32 num;
	int eno;
	eno = cli_error(c, &class, &num);
	if ((eclass != class || ecode != num) &&
	    num != (nterr&0xFFFFFF)) {
		DEBUG(0,("unexpected error code class=%d code=%d\n", 
			 (int)class, (int)num));
		DEBUG(0,(" expected %d/%d %d\n", 
		       (int)eclass, (int)ecode, (int)nterr));
		return False;
	}
	return True;
}


static BOOL wait_lock(struct cli_state *c, int fnum, uint32 offset, uint32 len)
{
	while (!cli_lock(c, fnum, offset, len, -1)) {
		if (!check_error(c, ERRDOS, ERRlock, 0)) return False;
	}
	return True;
}


static BOOL rw_torture(struct cli_state *c, int numops)
{
	char *lockfname = "\\torture.lck";
	fstring fname;
	int fnum;
	int fnum2;
	int pid2, pid = sys_getpid();
	int i, j;
	char buf[1024];

	fnum2 = cli_open(c, lockfname, O_RDWR | O_CREAT | O_EXCL, 
			 DENY_NONE);
	if (fnum2 == -1)
		fnum2 = cli_open(c, lockfname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		DEBUG(0,("open of %s failed (%s)\n", lockfname, cli_errstr(c)));
		return False;
	}


	for (i=0;i<numops;i++) {
		unsigned n = (unsigned)sys_random()%10;
		if (i % 10 == 0) {
			DEBUG(0,("%d\r", i));
		}
		slprintf(fname, sizeof(fstring) - 1, "\\torture.%u", n);

		if (!wait_lock(c, fnum2, n*sizeof(int), sizeof(int))) {
			return False;
		}

		fnum = cli_open(c, fname, O_RDWR | O_CREAT | O_TRUNC, DENY_ALL);
		if (fnum == -1) {
			DEBUG(0,("open failed (%s)\n", cli_errstr(c)));
			break;
		}

		if (cli_write(c, fnum, 0, (char *)&pid, 0, sizeof(pid), 0) != sizeof(pid)) {
			DEBUG(0,("write failed (%s)\n", cli_errstr(c)));
		}

		for (j=0;j<50;j++) {
			if (cli_write(c, fnum, 0, (char *)buf, 
				      sizeof(pid)+(j*sizeof(buf)), 
				      sizeof(buf), 0) != sizeof(buf)) {
				DEBUG(0,("write failed (%s)\n", cli_errstr(c)));
			}
		}

		pid2 = 0;

		if (cli_read(c, fnum, (char *)&pid2, 0, sizeof(pid), True) != sizeof(pid)) {
			DEBUG(0,("read failed (%s)\n", cli_errstr(c)));
		}

		if (pid2 != pid) {
			DEBUG(0,("data corruption!\n"));
		}

		if (!cli_close(c, fnum)) {
			DEBUG(0,("close failed (%s)\n", cli_errstr(c)));
		}

		if (!cli_unlink(c, fname)) {
			DEBUG(0,("unlink failed (%s)\n", cli_errstr(c)));
		}

		if (!cli_unlock(c, fnum2, n*sizeof(int), sizeof(int), -1)) {
			DEBUG(0,("unlock failed (%s)\n", cli_errstr(c)));
		}
	}

	cli_close(c, fnum2);
	cli_unlink(c, lockfname);

	DEBUG(0,("%d\n", i));

	return True;
}

static void usage(void)
{
	printf("Usage: smbtorture //server/share <options>\n");

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

	if (open_connection(&cli) == 0)
	{
		cli_sockopt(&cli, sockops);

		DEBUG(0,("pid %d OK\n", sys_getpid()));

		rw_torture(&cli, numops);

		close_connection(&cli);
	}
	else
	{
		DEBUG(0,("pid %d failed\n", sys_getpid()));
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
	char *fname = "\\lockt1.lck";
	int fnum1, fnum2, fnum3;
	time_t t1, t2;

	if (open_connection(&cli1) != 0 || open_connection(&cli2) != 0) {
		return;
	}
	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	DEBUG(0,("starting locktest1\n"));

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		DEBUG(0,("open of %s failed (%s)\n", fname, cli_errstr(&cli1)));
		return;
	}
	fnum2 = cli_open(&cli1, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		DEBUG(0,("open2 of %s failed (%s)\n", fname, cli_errstr(&cli1)));
		return;
	}
	fnum3 = cli_open(&cli2, fname, O_RDWR, DENY_NONE);
	if (fnum3 == -1) {
		DEBUG(0,("open3 of %s failed (%s)\n", fname, cli_errstr(&cli2)));
		return;
	}

	if (!cli_lock(&cli1, fnum1, 0, 4, 0)) {
		DEBUG(0,("lock1 failed (%s)\n", cli_errstr(&cli1)));
		return;
	}


	if (cli_lock(&cli2, fnum3, 0, 4, 0)) {
		DEBUG(0,("lock2 succeeded! This is a locking bug\n"));
		return;
	} else {
		if (!check_error(&cli2, ERRDOS, ERRlock, 0)) return;
	}


	DEBUG(0,("Testing lock timeouts\n"));
	t1 = time(NULL);
	if (cli_lock(&cli2, fnum3, 0, 4, 10*1000)) {
		DEBUG(0,("lock3 succeeded! This is a locking bug\n"));
		return;
	} else {
		if (!check_error(&cli2, ERRDOS, ERRlock, 0)) return;
	}
	t2 = time(NULL);

	if (t2 - t1 < 5) {
		DEBUG(0,("error: This server appears not to support timed lock requests\n"));
	}

	if (!cli_close(&cli1, fnum2)) {
		DEBUG(0,("close1 failed (%s)\n", cli_errstr(&cli1)));
		return;
	}

	if (cli_lock(&cli2, fnum3, 0, 4, 0)) {
		DEBUG(0,("lock4 succeeded! This is a locking bug\n"));
		return;
	} else {
		if (!check_error(&cli2, ERRDOS, ERRlock, 0)) return;
	}

	if (!cli_close(&cli1, fnum1)) {
		DEBUG(0,("close2 failed (%s)\n", cli_errstr(&cli1)));
		return;
	}

	if (!cli_close(&cli2, fnum3)) {
		DEBUG(0,("close3 failed (%s)\n", cli_errstr(&cli2)));
		return;
	}

	if (!cli_unlink(&cli1, fname)) {
		DEBUG(0,("unlink failed (%s)\n", cli_errstr(&cli1)));
		return;
	}


	close_connection(&cli1);
	close_connection(&cli2);

	DEBUG(0,("Passed locktest1\n"));
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
	char *fname = "\\lockt2.lck";
	int fnum1, fnum2, fnum3;

	if (open_connection(&cli) != 0) {
		return;
	}

	cli_sockopt(&cli, sockops);

	DEBUG(0,("starting locktest2\n"));

	cli_unlink(&cli, fname);

	cli_setpid(&cli, 1);

	fnum1 = cli_open(&cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		DEBUG(0,("open of %s failed (%s)\n", fname, cli_errstr(&cli)));
		return;
	}

	fnum2 = cli_open(&cli, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		DEBUG(0,("open2 of %s failed (%s)\n", fname, cli_errstr(&cli)));
		return;
	}

	cli_setpid(&cli, 2);

	fnum3 = cli_open(&cli, fname, O_RDWR, DENY_NONE);
	if (fnum3 == -1) {
		DEBUG(0,("open3 of %s failed (%s)\n", fname, cli_errstr(&cli)));
		return;
	}

	cli_setpid(&cli, 1);

	if (!cli_lock(&cli, fnum1, 0, 4, 0)) {
		DEBUG(0,("lock1 failed (%s)\n", cli_errstr(&cli)));
		return;
	}

	if (cli_lock(&cli, fnum2, 0, 4, 0)) {
		DEBUG(0,("lock2 succeeded! This is a locking bug\n"));
	} else {
		if (!check_error(&cli, ERRDOS, ERRlock, 0)) return;
	}

	cli_setpid(&cli, 2);

	if (cli_unlock(&cli, fnum1, 0, 4, 0)) {
		DEBUG(0,("unlock1 succeeded! This is a locking bug\n"));
	}

	if (cli_lock(&cli, fnum3, 0, 4, 0)) {
		DEBUG(0,("lock3 succeeded! This is a locking bug\n"));
	} else {
		if (!check_error(&cli, ERRDOS, ERRlock, 0)) return;
	}

	cli_setpid(&cli, 1);

	if (!cli_close(&cli, fnum1)) {
		DEBUG(0,("close1 failed (%s)\n", cli_errstr(&cli)));
		return;
	}

	if (!cli_close(&cli, fnum2)) {
		DEBUG(0,("close2 failed (%s)\n", cli_errstr(&cli)));
		return;
	}

	if (!cli_close(&cli, fnum3)) {
		DEBUG(0,("close3 failed (%s)\n", cli_errstr(&cli)));
		return;
	}

	close_connection(&cli);

	DEBUG(0,("locktest2 finished\n"));
}


/*
  This test checks that 

  1) the server supports the full offset range in lock requests
*/
static void run_locktest3(int numops)
{
	static struct cli_state cli1, cli2;
	char *fname = "\\lockt3.lck";
	int fnum1, fnum2, i;
	uint32 offset;

#define NEXT_OFFSET offset += (~(uint32)0) / numops

	if (open_connection(&cli1) != 0 || open_connection(&cli2) != 0) {
		return;
	}
	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	DEBUG(0,("starting locktest3\n"));

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		DEBUG(0,("open of %s failed (%s)\n", fname, cli_errstr(&cli1)));
		return;
	}
	fnum2 = cli_open(&cli2, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		DEBUG(0,("open2 of %s failed (%s)\n", fname, cli_errstr(&cli2)));
		return;
	}

	for (offset=i=0;i<numops;i++) {
		NEXT_OFFSET;
		if (!cli_lock(&cli1, fnum1, offset-1, 1, 0)) {
			DEBUG(0,("lock1 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1)));
			return;
		}

		if (!cli_lock(&cli2, fnum2, offset-2, 1, 0)) {
			DEBUG(0,("lock2 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1)));
			return;
		}
	}

	for (offset=i=0;i<numops;i++) {
		NEXT_OFFSET;

		if (cli_lock(&cli1, fnum1, offset-2, 1, 0)) {
			DEBUG(0,("error: lock1 %d succeeded!\n", i));
			return;
		}

		if (cli_lock(&cli2, fnum2, offset-1, 1, 0)) {
			DEBUG(0,("error: lock2 %d succeeded!\n", i));
			return;
		}

		if (cli_lock(&cli1, fnum1, offset-1, 1, 0)) {
			DEBUG(0,("error: lock3 %d succeeded!\n", i));
			return;
		}

		if (cli_lock(&cli2, fnum2, offset-2, 1, 0)) {
			DEBUG(0,("error: lock4 %d succeeded!\n", i));
			return;
		}
	}

	for (offset=i=0;i<numops;i++) {
		NEXT_OFFSET;

		if (!cli_unlock(&cli1, fnum1, offset-1, 1, 0)) {
			DEBUG(0,("unlock1 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1)));
			return;
		}

		if (!cli_unlock(&cli2, fnum2, offset-2, 1, 0)) {
			DEBUG(0,("unlock2 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1)));
			return;
		}
	}

	if (!cli_close(&cli1, fnum1)) {
		DEBUG(0,("close1 failed (%s)\n", cli_errstr(&cli1)));
	}

	if (!cli_close(&cli2, fnum2)) {
		DEBUG(0,("close2 failed (%s)\n", cli_errstr(&cli2)));
	}

	if (!cli_unlink(&cli1, fname)) {
		DEBUG(0,("unlink failed (%s)\n", cli_errstr(&cli1)));
		return;
	}

	close_connection(&cli1);
	close_connection(&cli2);

	DEBUG(0,("finished locktest3\n"));
}


/*
test whether fnums and tids open on one VC are available on another (a major
security hole)
*/
static void run_fdpasstest(void)
{
	static struct cli_state cli1, cli2;
	char *fname = "\\fdpass.tst";
	int fnum1;
	pstring buf;

	if (open_connection(&cli1) != 0 || open_connection(&cli2) != 0) {
		return;
	}
	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	DEBUG(0,("starting fdpasstest\n"));

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		DEBUG(0,("open of %s failed (%s)\n", fname, cli_errstr(&cli1)));
		return;
	}

	if (cli_write(&cli1, fnum1, 0, "hello world\n", 0, 13, 0) != 13) {
		DEBUG(0,("write failed (%s)\n", cli_errstr(&cli1)));
		return;
	}

	cli2.vuid = cli1.vuid;
	cli2.cnum = cli1.cnum;
	cli2.pid = cli1.pid;


	if (cli_read(&cli2, fnum1, buf, 0, 13, True) == 13) {
		DEBUG(0,("read succeeded! nasty security hole [%s]\n",
		       buf));
		return;
	}

	cli_close(&cli1, fnum1);
	cli_unlink(&cli1, fname);

	close_connection(&cli1);
	close_connection(&cli2);

	DEBUG(0,("finished fdpasstest\n"));
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

	if (open_connection(&cli) != 0) {
		return;
	}

	cli_sockopt(&cli, sockops);

	DEBUG(0,("starting unlink test\n"));

	cli_unlink(&cli, fname);

	cli_setpid(&cli, 1);

	fnum = cli_open(&cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		DEBUG(0,("open of %s failed (%s)\n", fname, cli_errstr(&cli)));
		return;
	}

	if (cli_unlink(&cli, fname)) {
		DEBUG(0,("error: server allowed unlink on an open file\n"));
	}

	cli_close(&cli, fnum);
	cli_unlink(&cli, fname);

	close_connection(&cli);

	DEBUG(0,("unlink test finished\n"));
}


/*
test how many open files this server supports on the one socket
*/
static void run_maxfidtest(int n)
{
	static struct cli_state cli;
	char *template = "\\maxfid.%d.%d";
	fstring fname;
	int fnum;
	int retries=4;

	srandom(sys_getpid());

	while (open_connection(&cli) != 0 && retries--) msleep(random() % 2000);

	if (retries <= 0) {
		DEBUG(0,("failed to connect\n"));
		return;
	}

	cli_sockopt(&cli, sockops);

	DEBUG(0,("starting maxfid test\n"));

	fnum = 0;
	while (1) {
		slprintf(fname,sizeof(fname)-1,template, fnum,sys_getpid());
		if (cli_open(&cli, fname, 
			     O_RDWR|O_CREAT|O_TRUNC, DENY_NONE) ==
		    -1) {
			DEBUG(0,("open of %s failed (%s)\n", 
			       fname, cli_errstr(&cli)));
			DEBUG(0,("maximum fnum is %d\n", fnum));
			break;
		}
		fnum++;
	}

	DEBUG(0,("cleaning up\n"));
	while (fnum > n) {
		fnum--;
		slprintf(fname,sizeof(fname)-1,template, fnum,sys_getpid());
		if (cli_unlink(&cli, fname)) {
			DEBUG(0,("unlink of %s failed (%s)\n", 
			       fname, cli_errstr(&cli)));
		}
	}

	DEBUG(0,("maxfid test finished\n"));
	close_connection(&cli);
}

/* generate a random buffer */
static void rand_buf(char *buf, int len)
{
	while (len--) {
		*buf = sys_random();
		buf++;
	}
}

#define TORT_BUFFER_SIZE 1024

/* send random IPC commands */
static void run_randomipc(int numops)
{
	char *rparam = NULL;
	char *rdata = NULL;
	int rdrcnt,rprcnt;
	char param[TORT_BUFFER_SIZE];
	int api, param_len, i;
	int reconnect_count = 500;
	static struct cli_state cli;

	DEBUG(0,("starting random ipc test\n"));

	while (reconnect_count > 0 && open_connection(&cli) != 0)
	{
		DEBUG(0,("connection failed: retrying %d\n", reconnect_count));
		msleep(sys_random() % 5000);
		reconnect_count--;
	}

	if (reconnect_count == 0)
	{
		return;
	}

	for (i=0;i<numops * 100;i++)
	{
		api = sys_random() % 500;
		if ((sys_random() % 10) == 0)
		{
			param_len = (sys_random() % TORT_BUFFER_SIZE);
		}
		else
		{
			param_len = (sys_random() % 64);
		}

		rand_buf(param, param_len);
  
		SSVAL(param,0,api); 

		cli_api(&cli,
			param, param_len, 8,  
			NULL, 0, BUFFER_SIZE, 
			&rparam, &rprcnt,
			&rdata, &rdrcnt);
	}

	close_connection(&cli);

	DEBUG(0,("finished random ipc test\n"));
}

/* send random IPC commands */
static void run_randomipc_nowait(int numops)
{
	char param[TORT_BUFFER_SIZE];
	int api, param_len, i;
	int reconnect_count = 500;
	static struct cli_state cli;

	DEBUG(0,("start random ipc test no waiting for SMBtrans response\n"));

	while (reconnect_count > 0 && open_connection(&cli) != 0)
	{
		DEBUG(0,("connection failed: retrying %d\n", reconnect_count));
		msleep(sys_random() % 5000);
		reconnect_count--;
	}

	if (reconnect_count == 0)
	{
		return;
	}

	for (i=0;i<numops * 100;i++)
	{
		api = sys_random() % 500;
		if ((sys_random() % 10) == 0)
		{
			param_len = (sys_random() % TORT_BUFFER_SIZE);
		}
		else
		{
			param_len = (sys_random() % 64);
		}

		rand_buf(param, param_len);
  
		SSVAL(param,0,api); 

		cli_send_trans(&cli,SMBtrans,
			PIPE_LANMAN,strlen(PIPE_LANMAN), /* Name, length */
			0,0,                             /* fid, flags */
			NULL,0,0,                /* Setup, length, max */

			param, param_len, 8,  
			NULL, 0, BUFFER_SIZE);
	}

	close_connection(&cli);

	DEBUG(0,("finished random ipc test\n"));
}



static void browse_callback(const char *sname, uint32 stype, 
			    const char *comment)
{
	DEBUG(0,("\t%20.20s %08x %s\n", sname, stype, comment));
}



/*
  This test checks the browse list code

*/
static void run_browsetest(void)
{
	static struct cli_state cli;

	DEBUG(0,("starting browse test\n"));

	if (open_connection(&cli) != 0) {
		return;
	}

	DEBUG(0,("domain list:\n"));
	cli_NetServerEnum(&cli, workgroup, 
			  SV_TYPE_DOMAIN_ENUM,
			  browse_callback);

	DEBUG(0,("machine list:\n"));
	cli_NetServerEnum(&cli, workgroup, 
			  SV_TYPE_ALL,
			  browse_callback);

	close_connection(&cli);

	DEBUG(0,("browse test finished\n"));
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

	DEBUG(0,("starting attrib test\n"));

	if (open_connection(&cli) != 0) {
		return;
	}

	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_close(&cli, fnum);
	if (!cli_getatr(&cli, fname, NULL, NULL, &t)) {
		DEBUG(0,("getatr failed (%s)\n", cli_errstr(&cli)));
	}

	if (abs(t - time(NULL)) > 2) {
		DEBUG(0,("ERROR: SMBgetatr bug. time is %s",
		       ctime(&t)));
		t = time(NULL);
	}

	t2 = t-60*60*24; /* 1 day ago */

	if (!cli_setatr(&cli, fname, 0, t2)) {
		DEBUG(0,("setatr failed (%s)\n", cli_errstr(&cli)));
	}

	if (!cli_getatr(&cli, fname, NULL, NULL, &t)) {
		DEBUG(0,("getatr failed (%s)\n", cli_errstr(&cli)));
	}

	if (t != t2) {
		DEBUG(0,("ERROR: getatr/setatr bug. times are\n%s",
		       ctime(&t)));
		DEBUG(0,("%s", ctime(&t2)));
	}

	cli_unlink(&cli, fname);

	close_connection(&cli);

	DEBUG(0,("attrib test finished\n"));
}


/*
  This checks a couple of trans2 calls
*/
static void run_trans2test(void)
{
	static struct cli_state cli;
	int fnum;
	size_t size;
	time_t c_time, a_time, m_time, w_time, m_time2;
	char *fname = "\\trans2.tst";
	char *dname = "\\trans2";
	char *fname2 = "\\trans2\\trans2.tst";

	DEBUG(0,("starting trans2 test\n"));

	if (open_connection(&cli) != 0) {
		return;
	}

	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	if (!cli_qfileinfo(&cli, fnum, NULL, &size, &c_time, &a_time, &m_time,
			   NULL, NULL)) {
		DEBUG(0,("ERROR: qfileinfo failed (%s)\n", cli_errstr(&cli)));
	}
	cli_close(&cli, fnum);

	sleep(2);

	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_close(&cli, fnum);

	if (!cli_qpathinfo(&cli, fname, &c_time, &a_time, &m_time, &size, NULL)) {
		DEBUG(0,("ERROR: qpathinfo failed (%s)\n", cli_errstr(&cli)));
	} else {
		if (c_time != m_time) {
			DEBUG(0,("create time=%s", ctime(&c_time)));
			DEBUG(0,("modify time=%s", ctime(&m_time)));
			DEBUG(0,("This system appears to have sticky create times\n"));
		}
		if (a_time % (60*60) == 0) {
			DEBUG(0,("access time=%s", ctime(&a_time)));
			DEBUG(0,("This system appears to set a midnight access time\n"));
		}

		if (abs(m_time - time(NULL)) > 60*60*24*7) {
			DEBUG(0,("ERROR: totally incorrect times - maybe word reversed?\n"));
		}
	}


	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_close(&cli, fnum);
	if (!cli_qpathinfo2(&cli, fname, &c_time, &a_time, &m_time, 
			    &w_time, &size, NULL, NULL)) {
		DEBUG(0,("ERROR: qpathinfo2 failed (%s)\n", cli_errstr(&cli)));
	} else {
		if (w_time < 60*60*24*2) {
			DEBUG(0,("write time=%s", ctime(&w_time)));
			DEBUG(0,("This system appears to set a initial 0 write time\n"));
		}
	}

	cli_unlink(&cli, fname);


	/* check if the server updates the directory modification time
           when creating a new file */
	if (!cli_mkdir(&cli, dname)) {
		DEBUG(0,("ERROR: mkdir failed (%s)\n", cli_errstr(&cli)));
	}
	sleep(3);
	if (!cli_qpathinfo2(&cli, "\\trans2\\", &c_time, &a_time, &m_time, 
			    &w_time, &size, NULL, NULL)) {
		DEBUG(0,("ERROR: qpathinfo2 failed (%s)\n", cli_errstr(&cli)));
	}

	fnum = cli_open(&cli, fname2, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_write(&cli, fnum,  0, (char *)&fnum, 0, sizeof(fnum), 0);
	cli_close(&cli, fnum);
	if (!cli_qpathinfo2(&cli, "\\trans2\\", &c_time, &a_time, &m_time2, 
			    &w_time, &size, NULL, NULL)) {
		DEBUG(0,("ERROR: qpathinfo2 failed (%s)\n", cli_errstr(&cli)));
	} else {
		if (m_time2 == m_time)
			DEBUG(0,("This system does not update directory modification times\n"));
	}
	cli_unlink(&cli, fname2);
	cli_rmdir(&cli, dname);


	close_connection(&cli);

	DEBUG(0,("trans2 test finished\n"));
}


static void run_connection(int numops)
{
	struct cli_state c;
	int count = 0;
	int failed[NUM_ERR_STATES];
	int i;

	DEBUG(0,("Connection test starts:\n"));

	for (i = 0; i < NUM_ERR_STATES; i++)
	{
		failed[i] = 0;
	}

	for (i = 0; i < numops; i++)
	{
		int err;
		DEBUG(0,("Connection test %d %d\n", i, numops));
		if ((err = open_connection(&c)))
		{
			failed[err]++;
		}
		count++;
	}

	{
		int failtotal = 0;

		for (i = 0, failtotal = 0; i < NUM_ERR_STATES; i++)
		{
			failtotal += failed[i];
		}
		DEBUG(0,("Connection test results: count %d success %d\n", count, count-failtotal));
	}
	for (i = 0; i < NUM_ERR_STATES; i++)
	{
		DEBUG(0,("%s: failed: %d\n", smb_messages[i], failed[i]));
	}
}

static void create_procs(int nprocs, int numops, void (*fn)(int ))
{
	int i, status;

	for (i=0;i<nprocs;i++)
	{
		if (sys_fork() == 0)
		{
			int mypid = sys_getpid();
			sys_srandom(mypid ^ time(NULL));

			if (!dbg_interactive())
			{
				slprintf(debugf, sizeof(debugf), "./log.torture.%d", mypid);
				reopen_logs();
			}

			fn(numops);
			dbgflush();
			_exit(0);
		}
	}

	for (i=0;i<nprocs;i++)
	{
		waitpid(0, &status, 0);
	}
}



#define DEBUG_INTERACTIVE True

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
	extern BOOL append_log;
	extern BOOL timestamp_log;

	DEBUGLEVEL = 0;
	pstrcpy(debugf,"./log.torture");
	setup_logging(argv[0], DEBUG_INTERACTIVE);
	append_log = True;
	timestamp_log = False;

	charset_initialise();

	if (argc < 2) {
		usage();
	}

        for(p = argv[1]; *p; p++)
          if(*p == '\\')
            *p = '/';
 
	if (strncmp(argv[1], "//", 2)) {
		usage();
	}

	fstrcpy(host, &argv[1][2]);
	p = strchr(&host[2],'/');
	if (!p) {
		usage();
	}
	*p = 0;
	fstrcpy(share, p+1);

	get_myname(myname);

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

	printf("host=%s share=%s user=%s myname=%s procs=%d ops=%d\n", 
	       host, share, username, myname, nprocs, numops);

	create_procs(nprocs, numops, run_randomipc);
/*
	create_procs(nprocs, numops, run_randomipc_nowait);

	create_procs(nprocs, numops, run_connection);

	run_fdpasstest();
	run_locktest1();
	run_locktest2();
	run_locktest3(numops);
	run_unlinktest();
	run_browsetest();
	run_attrtest();
	run_trans2test();

	create_procs(nprocs, numops, run_maxfidtest);



	start_timer();
	create_procs(nprocs, numops, run_torture);
	printf("rw_torture: %g secs\n", end_timer());
*/
	dbgflush();

	return(0);
}


