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

static fstring host, workgroup, share, password, username, myname;
static int max_protocol = PROTOCOL_NT1;
static char *sockops="TCP_NODELAY";
static int nprocs=1, numops=100;
static int procnum; /* records process count number when forking */
static struct cli_state current_cli;
static fstring randomfname;
static BOOL use_oplocks;
static BOOL use_level_II_oplocks;
BOOL torture_showall = False;

static double create_procs(BOOL (*fn)(int), BOOL *result);


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


/* return a pointer to a anonymous shared memory segment of size "size"
   which will persist across fork() but will disappear when all processes
   exit 

   The memory is not zeroed 

   This function uses system5 shared memory. It takes advantage of a property
   that the memory is not destroyed if it is attached when the id is removed
   */
static void *shm_setup(int size)
{
	int shmid;
	void *ret;

	shmid = shmget(IPC_PRIVATE, size, SHM_R | SHM_W);
	if (shmid == -1) {
		printf("can't get shared memory\n");
		exit(1);
	}
	ret = (void *)shmat(shmid, 0, 0);
	if (!ret || ret == (void *)-1) {
		printf("can't attach to shared memory\n");
		return NULL;
	}
	/* the following releases the ipc, but note that this process
	   and all its children will still have access to the memory, its
	   just that the shmid is no longer valid for other shm calls. This
	   means we don't leave behind lots of shm segments after we exit 

	   See Stevens "advanced programming in unix env" for details
	   */
	shmctl(shmid, IPC_RMID, 0);
	
	return ret;
}


static BOOL open_nbt_connection(struct cli_state *c)
{
	struct nmb_name called, calling;
	struct in_addr ip;

	ZERO_STRUCTP(c);

	make_nmb_name(&calling, myname, 0x0);
	make_nmb_name(&called , host, 0x20);

        zero_ip(&ip);

	if (!cli_initialise(c) || !cli_connect(c, host, &ip)) {
		printf("Failed to connect with %s\n", host);
		return False;
	}

	c->timeout = 120000; /* set a really long timeout (2 minutes) */
	if (use_oplocks) c->use_oplocks = True;
	if (use_level_II_oplocks) c->use_level_II_oplocks = True;

	if (!cli_session_request(c, &calling, &called)) {
		printf("%s rejected the session\n",host);
		cli_shutdown(c);
		return False;
	}

	return True;
}

BOOL torture_open_connection(struct cli_state *c)
{
	ZERO_STRUCTP(c);

	if (!open_nbt_connection(c)) {
		return False;
	}

	if (!cli_negprot(c)) {
		printf("%s rejected the negprot (%s)\n",host, cli_errstr(c));
		cli_shutdown(c);
		return False;
	}

	if (!cli_session_setup(c, username, 
			       password, strlen(password),
			       password, strlen(password),
			       workgroup)) {
		printf("%s rejected the sessionsetup (%s)\n", host, cli_errstr(c));
		cli_shutdown(c);
		return False;
	}

	if (!cli_send_tconX(c, share, "?????",
			    password, strlen(password)+1)) {
		printf("%s refused tree connect (%s)\n", host, cli_errstr(c));
		cli_shutdown(c);
		return False;
	}

	return True;
}


BOOL torture_close_connection(struct cli_state *c)
{
	BOOL ret = True;
	if (!cli_tdis(c)) {
		printf("tdis failed (%s)\n", cli_errstr(c));
		ret = False;
	}

        cli_shutdown(c);

	return ret;
}


/* check if the server produced the expected error code */
static BOOL check_error(int line, struct cli_state *c, 
			uint8 eclass, uint32 ecode, NTSTATUS nterr)
{
        if (cli_is_dos_error(c)) {
                uint8 class;
                uint32 num;

                /* Check DOS error */

                cli_dos_error(c, &class, &num);

                if (eclass != class || ecode != num) {
                        printf("unexpected error code class=%d code=%d\n", 
                               (int)class, (int)num);
                        printf(" expected %d/%d %s (line=%d)\n", 
                               (int)eclass, (int)ecode, get_nt_error_msg(nterr), line);
                        return False;
                }

        } else {
                NTSTATUS status;

                /* Check NT error */

                status = cli_nt_error(c);

                if (NT_STATUS_V(nterr) != NT_STATUS_V(status)) {
                        printf("unexpected error code %s\n", get_nt_error_msg(status));
                        printf(" expected %s (line=%d)\n", get_nt_error_msg(nterr), line);
                        return False;
                }
        }

	return True;
}


static BOOL wait_lock(struct cli_state *c, int fnum, uint32 offset, uint32 len)
{
	while (!cli_lock(c, fnum, offset, len, -1, WRITE_LOCK)) {
		if (!check_error(__LINE__, c, ERRDOS, ERRlock, NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}
	return True;
}


static BOOL rw_torture(struct cli_state *c)
{
	char *lockfname = "\\torture.lck";
	fstring fname;
	int fnum;
	int fnum2;
	pid_t pid2, pid = getpid();
	int i, j;
	char buf[1024];
	BOOL correct = True;

	fnum2 = cli_open(c, lockfname, O_RDWR | O_CREAT | O_EXCL, 
			 DENY_NONE);
	if (fnum2 == -1)
		fnum2 = cli_open(c, lockfname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open of %s failed (%s)\n", lockfname, cli_errstr(c));
		return False;
	}


	for (i=0;i<numops;i++) {
		unsigned n = (unsigned)sys_random()%10;
		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}
		slprintf(fname, sizeof(fstring) - 1, "\\torture.%u", n);

		if (!wait_lock(c, fnum2, n*sizeof(int), sizeof(int))) {
			return False;
		}

		fnum = cli_open(c, fname, O_RDWR | O_CREAT | O_TRUNC, DENY_ALL);
		if (fnum == -1) {
			printf("open failed (%s)\n", cli_errstr(c));
			correct = False;
			break;
		}

		if (cli_write(c, fnum, 0, (char *)&pid, 0, sizeof(pid)) != sizeof(pid)) {
			printf("write failed (%s)\n", cli_errstr(c));
			correct = False;
		}

		for (j=0;j<50;j++) {
			if (cli_write(c, fnum, 0, (char *)buf, 
				      sizeof(pid)+(j*sizeof(buf)), 
				      sizeof(buf)) != sizeof(buf)) {
				printf("write failed (%s)\n", cli_errstr(c));
				correct = False;
			}
		}

		pid2 = 0;

		if (cli_read(c, fnum, (char *)&pid2, 0, sizeof(pid)) != sizeof(pid)) {
			printf("read failed (%s)\n", cli_errstr(c));
			correct = False;
		}

		if (pid2 != pid) {
			printf("data corruption!\n");
			correct = False;
		}

		if (!cli_close(c, fnum)) {
			printf("close failed (%s)\n", cli_errstr(c));
			correct = False;
		}

		if (!cli_unlink(c, fname)) {
			printf("unlink failed (%s)\n", cli_errstr(c));
			correct = False;
		}

		if (!cli_unlock(c, fnum2, n*sizeof(int), sizeof(int))) {
			printf("unlock failed (%s)\n", cli_errstr(c));
			correct = False;
		}
	}

	cli_close(c, fnum2);
	cli_unlink(c, lockfname);

	printf("%d\n", i);

	return correct;
}

static BOOL run_torture(int dummy)
{
	struct cli_state cli;
        BOOL ret;

	cli = current_cli;

	cli_sockopt(&cli, sockops);

	ret = rw_torture(&cli);
	
	if (!torture_close_connection(&cli)) {
		ret = False;
	}

	return ret;
}

static BOOL rw_torture3(struct cli_state *c, char *lockfname)
{
	int fnum = -1;
	int i = 0;
	char buf[131072];
	char buf_rd[131072];
	unsigned count;
	unsigned countprev = 0;
	ssize_t sent = 0;
	BOOL correct = True;

	srandom(1);
	for (i = 0; i < sizeof(buf); i += sizeof(uint32))
	{
		SIVAL(buf, i, sys_random());
	}

	if (procnum == 0)
	{
		fnum = cli_open(c, lockfname, O_RDWR | O_CREAT | O_EXCL, 
				 DENY_NONE);
		if (fnum == -1) {
			printf("first open read/write of %s failed (%s)\n",
					lockfname, cli_errstr(c));
			return False;
		}
	}
	else
	{
		for (i = 0; i < 500 && fnum == -1; i++)
		{
			fnum = cli_open(c, lockfname, O_RDONLY, 
					 DENY_NONE);
			msleep(10);
		}
		if (fnum == -1) {
			printf("second open read-only of %s failed (%s)\n",
					lockfname, cli_errstr(c));
			return False;
		}
	}

	i = 0;
	for (count = 0; count < sizeof(buf); count += sent)
	{
		if (count >= countprev) {
			printf("%d %8d\r", i, count);
			fflush(stdout);
			i++;
			countprev += (sizeof(buf) / 20);
		}

		if (procnum == 0)
		{
			sent = ((unsigned)sys_random()%(20))+ 1;
			if (sent > sizeof(buf) - count)
			{
				sent = sizeof(buf) - count;
			}

			if (cli_write(c, fnum, 0, buf+count, count, (size_t)sent) != sent) {
				printf("write failed (%s)\n", cli_errstr(c));
				correct = False;
			}
		}
		else
		{
			sent = cli_read(c, fnum, buf_rd+count, count,
						  sizeof(buf)-count);
			if (sent < 0)
			{
				printf("read failed offset:%d size:%d (%s)\n",
						count, sizeof(buf)-count,
						cli_errstr(c));
				correct = False;
				sent = 0;
			}
			if (sent > 0)
			{
				if (memcmp(buf_rd+count, buf+count, sent) != 0)
				{
					printf("read/write compare failed\n");
					printf("offset: %d req %d recvd %d\n",
						count, sizeof(buf)-count, sent);
					correct = False;
					break;
				}
			}
		}

	}

	if (!cli_close(c, fnum)) {
		printf("close failed (%s)\n", cli_errstr(c));
		correct = False;
	}

	return correct;
}

static BOOL rw_torture2(struct cli_state *c1, struct cli_state *c2)
{
	char *lockfname = "\\torture2.lck";
	int fnum1;
	int fnum2;
	int i;
	uchar buf[131072];
	uchar buf_rd[131072];
	BOOL correct = True;
	ssize_t bytes_read;

	if (!cli_unlink(c1, lockfname)) {
		printf("unlink failed (%s) (normal, this file should not exist)\n", cli_errstr(c1));
	}

	fnum1 = cli_open(c1, lockfname, O_RDWR | O_CREAT | O_EXCL, 
			 DENY_NONE);
	if (fnum1 == -1) {
		printf("first open read/write of %s failed (%s)\n",
				lockfname, cli_errstr(c1));
		return False;
	}
	fnum2 = cli_open(c2, lockfname, O_RDONLY, 
			 DENY_NONE);
	if (fnum2 == -1) {
		printf("second open read-only of %s failed (%s)\n",
				lockfname, cli_errstr(c2));
		cli_close(c1, fnum1);
		return False;
	}

	for (i=0;i<numops;i++)
	{
		size_t buf_size = ((unsigned)sys_random()%(sizeof(buf)-1))+ 1;
		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}

		generate_random_buffer(buf, buf_size, False);

		if (cli_write(c1, fnum1, 0, buf, 0, buf_size) != buf_size) {
			printf("write failed (%s)\n", cli_errstr(c1));
			correct = False;
		}

		if ((bytes_read = cli_read(c2, fnum2, buf_rd, 0, buf_size)) != buf_size) {
			printf("read failed (%s)\n", cli_errstr(c2));
			printf("read %d, expected %d\n", bytes_read, buf_size); 
			correct = False;
		}

		if (memcmp(buf_rd, buf, buf_size) != 0)
		{
			printf("read/write compare failed\n");
			correct = False;
		}
	}

	if (!cli_close(c2, fnum2)) {
		printf("close failed (%s)\n", cli_errstr(c2));
		correct = False;
	}
	if (!cli_close(c1, fnum1)) {
		printf("close failed (%s)\n", cli_errstr(c1));
		correct = False;
	}

	if (!cli_unlink(c1, lockfname)) {
		printf("unlink failed (%s)\n", cli_errstr(c1));
		correct = False;
	}

	return correct;
}

static BOOL run_readwritetest(int dummy)
{
	static struct cli_state cli1, cli2;
	BOOL test1, test2;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}
	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	printf("starting readwritetest\n");

	test1 = rw_torture2(&cli1, &cli2);
	printf("Passed readwritetest v1: %s\n", BOOLSTR(test1));

	test2 = rw_torture2(&cli1, &cli1);
	printf("Passed readwritetest v2: %s\n", BOOLSTR(test2));

	if (!torture_close_connection(&cli1)) {
		test1 = False;
	}

	if (!torture_close_connection(&cli2)) {
		test2 = False;
	}

	return (test1 && test2);
}

static BOOL run_readwritemulti(int dummy)
{
	static struct cli_state cli;
	BOOL test;

	cli = current_cli;

	cli_sockopt(&cli, sockops);

	printf("run_readwritemulti: fname %s\n", randomfname);
	test = rw_torture3(&cli, randomfname);

	if (!torture_close_connection(&cli)) {
		test = False;
	}
	
	return test;
}

static BOOL run_readwritelarge(int dummy)
{
	static struct cli_state cli1;
	int fnum1;
	char *lockfname = "\\large.dat";
	size_t fsize;
	char buf[0x10000];
	BOOL correct = True;
 
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	cli_sockopt(&cli1, sockops);
	memset(buf,'\0',sizeof(buf));
	
	cli1.max_xmit = 0x11000;
	
	printf("starting readwritelarge\n");
 
	cli_unlink(&cli1, lockfname);

	fnum1 = cli_open(&cli1, lockfname, O_RDWR | O_CREAT | O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open read/write of %s failed (%s)\n", lockfname, cli_errstr(&cli1));
		return False;
	}
   
	cli_write(&cli1, fnum1, 0, buf, 0, sizeof(buf));

	if (!cli_close(&cli1, fnum1)) {
		printf("close failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}

	if (!cli_qpathinfo(&cli1, lockfname, NULL, NULL, NULL, &fsize, NULL)) {
		printf("qpathinfo failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}

	if (fsize == sizeof(buf))
		printf("readwritelarge test 1 succeeded (size = %x)\n", fsize);
	else {
		printf("readwritelarge test 1 failed (size = %x)\n", fsize);
		correct = False;
	}

	if (!cli_unlink(&cli1, lockfname)) {
		printf("unlink failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}

	fnum1 = cli_open(&cli1, lockfname, O_RDWR | O_CREAT | O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open read/write of %s failed (%s)\n", lockfname, cli_errstr(&cli1));
		return False;
	}
	
	cli_smbwrite(&cli1, fnum1, buf, 0, sizeof(buf));
	
	if (!cli_close(&cli1, fnum1)) {
		printf("close failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}
	
	if (!torture_close_connection(&cli1)) {
		correct = False;
	}
	return correct;
	}

int line_count = 0;

/* run a test that simulates an approximate netbench client load */
static BOOL run_netbench(int client)
{
	struct cli_state cli;
	int i;
	fstring fname;
	pstring line;
	char cname[20];
	FILE *f;
	char *params[20];
	BOOL correct = True;

	cli = current_cli;

	cli_sockopt(&cli, sockops);

	nb_setup(&cli);

	slprintf(cname,sizeof(fname), "CLIENT%d", client);

	f = fopen("client.txt", "r");

	if (!f) {
		perror("client.txt");
		return False;
	}

	while (fgets(line, sizeof(line)-1, f)) {
		line_count++;

		line[strlen(line)-1] = 0;

		/* printf("[%d] %s\n", line_count, line); */

		all_string_sub(line,"CLIENT1", cname, sizeof(line));
		
		for (i=0;i<20;i++) params[i] = "";

		/* parse the command parameters */
		params[0] = strtok(line," ");
		i = 0;
		while (params[i]) params[++i] = strtok(NULL," ");

		params[i] = "";

		if (i < 2) continue;

		if (strcmp(params[1],"REQUEST") == 0) {
			if (!strcmp(params[0],"SMBopenX")) {
				fstrcpy(fname, params[5]);
			} else if (!strcmp(params[0],"SMBclose")) {
				nb_close(atoi(params[3]));
			} else if (!strcmp(params[0],"SMBmkdir")) {
				nb_mkdir(params[3]);
			} else if (!strcmp(params[0],"CREATE")) {
				nb_create(params[3], atoi(params[5]));
			} else if (!strcmp(params[0],"SMBrmdir")) {
				nb_rmdir(params[3]);
			} else if (!strcmp(params[0],"SMBunlink")) {
				fstrcpy(fname, params[3]);
			} else if (!strcmp(params[0],"SMBmv")) {
				nb_rename(params[3], params[5]);
			} else if (!strcmp(params[0],"SMBgetatr")) {
				fstrcpy(fname, params[3]);
			} else if (!strcmp(params[0],"SMBwrite")) {
				nb_write(atoi(params[3]), 
					 atoi(params[5]), atoi(params[7]));
			} else if (!strcmp(params[0],"SMBwritebraw")) {
				nb_write(atoi(params[3]), 
					 atoi(params[7]), atoi(params[5]));
			} else if (!strcmp(params[0],"SMBreadbraw")) {
				nb_read(atoi(params[3]), 
					 atoi(params[7]), atoi(params[5]));
			} else if (!strcmp(params[0],"SMBread")) {
				nb_read(atoi(params[3]), 
					 atoi(params[5]), atoi(params[7]));
			}
		} else {
			if (!strcmp(params[0],"SMBopenX")) {
				if (!strncmp(params[2], "ERR", 3)) continue;
				nb_open(fname, atoi(params[3]), atoi(params[5]));
			} else if (!strcmp(params[0],"SMBgetatr")) {
				if (!strncmp(params[2], "ERR", 3)) continue;
				nb_stat(fname, atoi(params[3]));
			} else if (!strcmp(params[0],"SMBunlink")) {
				if (!strncmp(params[2], "ERR", 3)) continue;
				nb_unlink(fname);
			}
		}
	}
	fclose(f);

	slprintf(fname,sizeof(fname), "CLIENTS/CLIENT%d", client);
	rmdir(fname);
	rmdir("CLIENTS");

	printf("+");	

	if (!torture_close_connection(&cli)) {
		correct = False;
	}
	
	return correct;
}


/* run a test that simulates an approximate netbench w9X client load */
static BOOL run_nbw95(int dummy)
{
	double t;
	BOOL correct = True;
	t = create_procs(run_netbench, &correct);
	/* to produce a netbench result we scale accoding to the
           netbench measured throughput for the run that produced the
           sniff that was used to produce client.txt. That run used 2
           clients and ran for 660 seconds to produce a result of
           4MBit/sec. */
	printf("Throughput %g MB/sec (NB=%g MB/sec  %g MBit/sec)\n", 
	       132*nprocs/t, 0.5*0.5*nprocs*660/t, 2*nprocs*660/t);
	return correct;
}

/* run a test that simulates an approximate netbench wNT client load */
static BOOL run_nbwnt(int dummy)
{
	double t;
	BOOL correct = True;
	t = create_procs(run_netbench, &correct);
	printf("Throughput %g MB/sec (NB=%g MB/sec  %g MBit/sec)\n", 
	       132*nprocs/t, 0.5*0.5*nprocs*660/t, 2*nprocs*660/t);
	return correct;
}



/*
  This test checks for two things:

  1) correct support for retaining locks over a close (ie. the server
     must not use posix semantics)
  2) support for lock timeouts
 */
static BOOL run_locktest1(int dummy)
{
	static struct cli_state cli1, cli2;
	char *fname = "\\lockt1.lck";
	int fnum1, fnum2, fnum3;
	time_t t1, t2;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}
	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	printf("starting locktest1\n");

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	fnum2 = cli_open(&cli1, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open2 of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	fnum3 = cli_open(&cli2, fname, O_RDWR, DENY_NONE);
	if (fnum3 == -1) {
		printf("open3 of %s failed (%s)\n", fname, cli_errstr(&cli2));
		return False;
	}

	if (!cli_lock(&cli1, fnum1, 0, 4, 0, WRITE_LOCK)) {
		printf("lock1 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}


	if (cli_lock(&cli2, fnum3, 0, 4, 0, WRITE_LOCK)) {
		printf("lock2 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__LINE__, &cli2, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}


	printf("Testing lock timeouts\n");
	t1 = time(NULL);
	if (cli_lock(&cli2, fnum3, 0, 4, 10*1000, WRITE_LOCK)) {
		printf("lock3 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__LINE__, &cli2, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}
	t2 = time(NULL);

	if (t2 - t1 < 5) {
		printf("error: This server appears not to support timed lock requests\n");
	}

	if (!cli_close(&cli1, fnum2)) {
		printf("close1 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (cli_lock(&cli2, fnum3, 0, 4, 0, WRITE_LOCK)) {
		printf("lock4 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__LINE__, &cli2, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (!cli_close(&cli2, fnum3)) {
		printf("close3 failed (%s)\n", cli_errstr(&cli2));
		return False;
	}

	if (!cli_unlink(&cli1, fname)) {
		printf("unlink failed (%s)\n", cli_errstr(&cli1));
		return False;
	}


	if (!torture_close_connection(&cli1)) {
		return False;
	}

	if (!torture_close_connection(&cli2)) {
		return False;
	}

	printf("Passed locktest1\n");
	return True;
}

/*
 checks for correct tconX support
 */
static BOOL run_tcon_test(int dummy)
{
	static struct cli_state cli1;
	char *fname = "\\tcontest.tmp";
	int fnum1;
	uint16 cnum;
	char buf[4];

	if (!torture_open_connection(&cli1)) {
		return False;
	}
	cli_sockopt(&cli1, sockops);

	printf("starting tcontest\n");

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1)
	{
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	cnum = cli1.cnum;

	if (cli_write(&cli1, fnum1, 0, buf, 130, 4) != 4)
	{
		printf("write failed (%s)", cli_errstr(&cli1));
		return False;
	}

	if (!cli_send_tconX(&cli1, share, "?????",
			    password, strlen(password)+1)) {
		printf("%s refused 2nd tree connect (%s)\n", host,
		           cli_errstr(&cli1));
		cli_shutdown(&cli1);
		return False;
	}

	if (cli_write(&cli1, fnum1, 0, buf, 130, 4) == 4)
	{
		printf("write succeeded (%s)", cli_errstr(&cli1));
		return False;
	}

	if (cli_close(&cli1, fnum1)) {
		printf("close2 succeeded (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (!cli_tdis(&cli1)) {
		printf("tdis failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	cli1.cnum = cnum;

	if (!cli_close(&cli1, fnum1)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (!torture_close_connection(&cli1)) {
		return False;
	}

	printf("Passed tcontest\n");
	return True;
}


/*
  This test checks that 

  1) the server supports multiple locking contexts on the one SMB
  connection, distinguished by PID.  

  2) the server correctly fails overlapping locks made by the same PID (this
     goes against POSIX behaviour, which is why it is tricky to implement)

  3) the server denies unlock requests by an incorrect client PID
*/
static BOOL run_locktest2(int dummy)
{
	static struct cli_state cli;
	char *fname = "\\lockt2.lck";
	int fnum1, fnum2, fnum3;
	BOOL correct = True;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	cli_sockopt(&cli, sockops);

	printf("starting locktest2\n");

	cli_unlink(&cli, fname);

	cli_setpid(&cli, 1);

	fnum1 = cli_open(&cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli));
		return False;
	}

	fnum2 = cli_open(&cli, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open2 of %s failed (%s)\n", fname, cli_errstr(&cli));
		return False;
	}

	cli_setpid(&cli, 2);

	fnum3 = cli_open(&cli, fname, O_RDWR, DENY_NONE);
	if (fnum3 == -1) {
		printf("open3 of %s failed (%s)\n", fname, cli_errstr(&cli));
		return False;
	}

	cli_setpid(&cli, 1);

	if (!cli_lock(&cli, fnum1, 0, 4, 0, WRITE_LOCK)) {
		printf("lock1 failed (%s)\n", cli_errstr(&cli));
		return False;
	}

	if (cli_lock(&cli, fnum1, 0, 4, 0, WRITE_LOCK)) {
		printf("WRITE lock1 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, &cli, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (cli_lock(&cli, fnum2, 0, 4, 0, WRITE_LOCK)) {
		printf("WRITE lock2 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, &cli, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (cli_lock(&cli, fnum2, 0, 4, 0, READ_LOCK)) {
		printf("READ lock2 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, &cli, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (!cli_lock(&cli, fnum1, 100, 4, 0, WRITE_LOCK)) {
		printf("lock at 100 failed (%s)\n", cli_errstr(&cli));
	}
	cli_setpid(&cli, 2);
	if (cli_unlock(&cli, fnum1, 100, 4)) {
		printf("unlock at 100 succeeded! This is a locking bug\n");
		correct = False;
	}

	if (cli_unlock(&cli, fnum1, 0, 4)) {
		printf("unlock1 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, &cli, 
				 ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (cli_unlock(&cli, fnum1, 0, 8)) {
		printf("unlock2 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, &cli, 
				 ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (cli_lock(&cli, fnum3, 0, 4, 0, WRITE_LOCK)) {
		printf("lock3 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, &cli, ERRDOS, ERRlock, NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	cli_setpid(&cli, 1);

	if (!cli_close(&cli, fnum1)) {
		printf("close1 failed (%s)\n", cli_errstr(&cli));
		return False;
	}

	if (!cli_close(&cli, fnum2)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli));
		return False;
	}

	if (!cli_close(&cli, fnum3)) {
		printf("close3 failed (%s)\n", cli_errstr(&cli));
		return False;
	}

	if (!torture_close_connection(&cli)) {
		correct = False;
	}

	printf("locktest2 finished\n");

	return correct;
}


/*
  This test checks that 

  1) the server supports the full offset range in lock requests
*/
static BOOL run_locktest3(int dummy)
{
	static struct cli_state cli1, cli2;
	char *fname = "\\lockt3.lck";
	int fnum1, fnum2, i;
	uint32 offset;
	BOOL correct = True;

#define NEXT_OFFSET offset += (~(uint32)0) / numops

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}
	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	printf("starting locktest3\n");

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	fnum2 = cli_open(&cli2, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open2 of %s failed (%s)\n", fname, cli_errstr(&cli2));
		return False;
	}

	for (offset=i=0;i<numops;i++) {
		NEXT_OFFSET;
		if (!cli_lock(&cli1, fnum1, offset-1, 1, 0, WRITE_LOCK)) {
			printf("lock1 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1));
			return False;
		}

		if (!cli_lock(&cli2, fnum2, offset-2, 1, 0, WRITE_LOCK)) {
			printf("lock2 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1));
			return False;
		}
	}

	for (offset=i=0;i<numops;i++) {
		NEXT_OFFSET;

		if (cli_lock(&cli1, fnum1, offset-2, 1, 0, WRITE_LOCK)) {
			printf("error: lock1 %d succeeded!\n", i);
			return False;
		}

		if (cli_lock(&cli2, fnum2, offset-1, 1, 0, WRITE_LOCK)) {
			printf("error: lock2 %d succeeded!\n", i);
			return False;
		}

		if (cli_lock(&cli1, fnum1, offset-1, 1, 0, WRITE_LOCK)) {
			printf("error: lock3 %d succeeded!\n", i);
			return False;
		}

		if (cli_lock(&cli2, fnum2, offset-2, 1, 0, WRITE_LOCK)) {
			printf("error: lock4 %d succeeded!\n", i);
			return False;
		}
	}

	for (offset=i=0;i<numops;i++) {
		NEXT_OFFSET;

		if (!cli_unlock(&cli1, fnum1, offset-1, 1)) {
			printf("unlock1 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1));
			return False;
		}

		if (!cli_unlock(&cli2, fnum2, offset-2, 1)) {
			printf("unlock2 %d failed (%s)\n", 
			       i,
			       cli_errstr(&cli1));
			return False;
		}
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("close1 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (!cli_close(&cli2, fnum2)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli2));
		return False;
	}

	if (!cli_unlink(&cli1, fname)) {
		printf("unlink failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (!torture_close_connection(&cli1)) {
		correct = False;
	}
	
	if (!torture_close_connection(&cli2)) {
		correct = False;
	}

	printf("finished locktest3\n");

	return correct;
}

#define EXPECTED(ret, v) if ((ret) != (v)) { \
        printf("** "); correct = False; \
        }

/*
  looks at overlapping locks
*/
static BOOL run_locktest4(int dummy)
{
	static struct cli_state cli1, cli2;
	char *fname = "\\lockt4.lck";
	int fnum1, fnum2, f;
	BOOL ret;
	char buf[1000];
	BOOL correct = True;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}

	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	printf("starting locktest4\n");

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	fnum2 = cli_open(&cli2, fname, O_RDWR, DENY_NONE);

	memset(buf, 0, sizeof(buf));

	if (cli_write(&cli1, fnum1, 0, buf, 0, sizeof(buf)) != sizeof(buf)) {
		printf("Failed to create file\n");
		correct = False;
		goto fail;
	}

	ret = cli_lock(&cli1, fnum1, 0, 4, 0, WRITE_LOCK) &&
	      cli_lock(&cli1, fnum1, 2, 4, 0, WRITE_LOCK);
	EXPECTED(ret, False);
	printf("the same process %s set overlapping write locks\n", ret?"can":"cannot");
	    
	ret = cli_lock(&cli1, fnum1, 10, 4, 0, READ_LOCK) &&
	      cli_lock(&cli1, fnum1, 12, 4, 0, READ_LOCK);
	EXPECTED(ret, True);
	printf("the same process %s set overlapping read locks\n", ret?"can":"cannot");

	ret = cli_lock(&cli1, fnum1, 20, 4, 0, WRITE_LOCK) &&
	      cli_lock(&cli2, fnum2, 22, 4, 0, WRITE_LOCK);
	EXPECTED(ret, False);
	printf("a different connection %s set overlapping write locks\n", ret?"can":"cannot");
	    
	ret = cli_lock(&cli1, fnum1, 30, 4, 0, READ_LOCK) &&
	      cli_lock(&cli2, fnum2, 32, 4, 0, READ_LOCK);
	EXPECTED(ret, True);
	printf("a different connection %s set overlapping read locks\n", ret?"can":"cannot");
	
	ret = (cli_setpid(&cli1, 1), cli_lock(&cli1, fnum1, 40, 4, 0, WRITE_LOCK)) &&
	      (cli_setpid(&cli1, 2), cli_lock(&cli1, fnum1, 42, 4, 0, WRITE_LOCK));
	EXPECTED(ret, False);
	printf("a different pid %s set overlapping write locks\n", ret?"can":"cannot");
	    
	ret = (cli_setpid(&cli1, 1), cli_lock(&cli1, fnum1, 50, 4, 0, READ_LOCK)) &&
	      (cli_setpid(&cli1, 2), cli_lock(&cli1, fnum1, 52, 4, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("a different pid %s set overlapping read locks\n", ret?"can":"cannot");

	ret = cli_lock(&cli1, fnum1, 60, 4, 0, READ_LOCK) &&
	      cli_lock(&cli1, fnum1, 60, 4, 0, READ_LOCK);
	EXPECTED(ret, True);
	printf("the same process %s set the same read lock twice\n", ret?"can":"cannot");

	ret = cli_lock(&cli1, fnum1, 70, 4, 0, WRITE_LOCK) &&
	      cli_lock(&cli1, fnum1, 70, 4, 0, WRITE_LOCK);
	EXPECTED(ret, False);
	printf("the same process %s set the same write lock twice\n", ret?"can":"cannot");

	ret = cli_lock(&cli1, fnum1, 80, 4, 0, READ_LOCK) &&
	      cli_lock(&cli1, fnum1, 80, 4, 0, WRITE_LOCK);
	EXPECTED(ret, False);
	printf("the same process %s overlay a read lock with a write lock\n", ret?"can":"cannot");

	ret = cli_lock(&cli1, fnum1, 90, 4, 0, WRITE_LOCK) &&
	      cli_lock(&cli1, fnum1, 90, 4, 0, READ_LOCK);
	EXPECTED(ret, True);
	printf("the same process %s overlay a write lock with a read lock\n", ret?"can":"cannot");

	ret = (cli_setpid(&cli1, 1), cli_lock(&cli1, fnum1, 100, 4, 0, WRITE_LOCK)) &&
	      (cli_setpid(&cli1, 2), cli_lock(&cli1, fnum1, 100, 4, 0, READ_LOCK));
	EXPECTED(ret, False);
	printf("a different pid %s overlay a write lock with a read lock\n", ret?"can":"cannot");

	ret = cli_lock(&cli1, fnum1, 110, 4, 0, READ_LOCK) &&
	      cli_lock(&cli1, fnum1, 112, 4, 0, READ_LOCK) &&
	      cli_unlock(&cli1, fnum1, 110, 6);
	EXPECTED(ret, False);
	printf("the same process %s coalesce read locks\n", ret?"can":"cannot");


	ret = cli_lock(&cli1, fnum1, 120, 4, 0, WRITE_LOCK) &&
	      (cli_read(&cli2, fnum2, buf, 120, 4) == 4);
	EXPECTED(ret, False);
	printf("this server %s strict write locking\n", ret?"doesn't do":"does");

	ret = cli_lock(&cli1, fnum1, 130, 4, 0, READ_LOCK) &&
	      (cli_write(&cli2, fnum2, 0, buf, 130, 4) == 4);
	EXPECTED(ret, False);
	printf("this server %s strict read locking\n", ret?"doesn't do":"does");


	ret = cli_lock(&cli1, fnum1, 140, 4, 0, READ_LOCK) &&
	      cli_lock(&cli1, fnum1, 140, 4, 0, READ_LOCK) &&
	      cli_unlock(&cli1, fnum1, 140, 4) &&
	      cli_unlock(&cli1, fnum1, 140, 4);
	EXPECTED(ret, True);
	printf("this server %s do recursive read locking\n", ret?"does":"doesn't");


	ret = cli_lock(&cli1, fnum1, 150, 4, 0, WRITE_LOCK) &&
	      cli_lock(&cli1, fnum1, 150, 4, 0, READ_LOCK) &&
	      cli_unlock(&cli1, fnum1, 150, 4) &&
	      (cli_read(&cli2, fnum2, buf, 150, 4) == 4) &&
	      !(cli_write(&cli2, fnum2, 0, buf, 150, 4) == 4) &&
	      cli_unlock(&cli1, fnum1, 150, 4);
	EXPECTED(ret, True);
	printf("this server %s do recursive lock overlays\n", ret?"does":"doesn't");

	ret = cli_lock(&cli1, fnum1, 160, 4, 0, READ_LOCK) &&
	      cli_unlock(&cli1, fnum1, 160, 4) &&
	      (cli_write(&cli2, fnum2, 0, buf, 160, 4) == 4) &&		
	      (cli_read(&cli2, fnum2, buf, 160, 4) == 4);		
	EXPECTED(ret, True);
	printf("the same process %s remove a read lock using write locking\n", ret?"can":"cannot");

	ret = cli_lock(&cli1, fnum1, 170, 4, 0, WRITE_LOCK) &&
	      cli_unlock(&cli1, fnum1, 170, 4) &&
	      (cli_write(&cli2, fnum2, 0, buf, 170, 4) == 4) &&		
	      (cli_read(&cli2, fnum2, buf, 170, 4) == 4);		
	EXPECTED(ret, True);
	printf("the same process %s remove a write lock using read locking\n", ret?"can":"cannot");

	ret = cli_lock(&cli1, fnum1, 190, 4, 0, WRITE_LOCK) &&
	      cli_lock(&cli1, fnum1, 190, 4, 0, READ_LOCK) &&
	      cli_unlock(&cli1, fnum1, 190, 4) &&
	      !(cli_write(&cli2, fnum2, 0, buf, 190, 4) == 4) &&		
	      (cli_read(&cli2, fnum2, buf, 190, 4) == 4);		
	EXPECTED(ret, True);
	printf("the same process %s remove the first lock first\n", ret?"does":"doesn't");

	cli_close(&cli1, fnum1);
	cli_close(&cli2, fnum2);
	fnum1 = cli_open(&cli1, fname, O_RDWR, DENY_NONE);
	f = cli_open(&cli1, fname, O_RDWR, DENY_NONE);
	ret = cli_lock(&cli1, fnum1, 0, 8, 0, READ_LOCK) &&
	      cli_lock(&cli1, f, 0, 1, 0, READ_LOCK) &&
	      cli_close(&cli1, fnum1) &&
	      ((fnum1 = cli_open(&cli1, fname, O_RDWR, DENY_NONE)) != -1) &&
	      cli_lock(&cli1, fnum1, 7, 1, 0, WRITE_LOCK);
        cli_close(&cli1, f);
	EXPECTED(ret, True);
	printf("the server %s have the NT byte range lock bug\n", !ret?"does":"doesn't");
	
 fail:
	cli_close(&cli1, fnum1);
	cli_close(&cli2, fnum2);
	cli_unlink(&cli1, fname);
	torture_close_connection(&cli1);
	torture_close_connection(&cli2);

	printf("finished locktest4\n");
	return correct;
}

/*
  looks at lock upgrade/downgrade.
*/
static BOOL run_locktest5(int dummy)
{
	static struct cli_state cli1, cli2;
	char *fname = "\\lockt5.lck";
	int fnum1, fnum2, fnum3;
	BOOL ret;
	char buf[1000];
	BOOL correct = True;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}

	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	printf("starting locktest5\n");

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	fnum2 = cli_open(&cli2, fname, O_RDWR, DENY_NONE);
	fnum3 = cli_open(&cli1, fname, O_RDWR, DENY_NONE);

	memset(buf, 0, sizeof(buf));

	if (cli_write(&cli1, fnum1, 0, buf, 0, sizeof(buf)) != sizeof(buf)) {
		printf("Failed to create file\n");
		correct = False;
		goto fail;
	}

	/* Check for NT bug... */
	ret = cli_lock(&cli1, fnum1, 0, 8, 0, READ_LOCK) &&
		  cli_lock(&cli1, fnum3, 0, 1, 0, READ_LOCK);
	cli_close(&cli1, fnum1);
	fnum1 = cli_open(&cli1, fname, O_RDWR, DENY_NONE);
	ret = cli_lock(&cli1, fnum1, 7, 1, 0, WRITE_LOCK);
	EXPECTED(ret, True);
	printf("this server %s the NT locking bug\n", ret ? "doesn't have" : "has");
	cli_close(&cli1, fnum1);
	fnum1 = cli_open(&cli1, fname, O_RDWR, DENY_NONE);
	cli_unlock(&cli1, fnum3, 0, 1);

	ret = cli_lock(&cli1, fnum1, 0, 4, 0, WRITE_LOCK) &&
	      cli_lock(&cli1, fnum1, 1, 1, 0, READ_LOCK);
	EXPECTED(ret, True);
	printf("the same process %s overlay a write with a read lock\n", ret?"can":"cannot");

	ret = cli_lock(&cli2, fnum2, 0, 4, 0, READ_LOCK);
	EXPECTED(ret, False);

	printf("a different processs %s get a read lock on the first process lock stack\n", ret?"can":"cannot");

	/* Unlock the process 2 lock. */
	cli_unlock(&cli2, fnum2, 0, 4);

	ret = cli_lock(&cli1, fnum3, 0, 4, 0, READ_LOCK);
	EXPECTED(ret, False);

	printf("the same processs on a different fnum %s get a read lock\n", ret?"can":"cannot");

	/* Unlock the process 1 fnum3 lock. */
	cli_unlock(&cli1, fnum3, 0, 4);

	/* Stack 2 more locks here. */
	ret = cli_lock(&cli1, fnum1, 0, 4, 0, READ_LOCK) &&
		  cli_lock(&cli1, fnum1, 0, 4, 0, READ_LOCK);

	EXPECTED(ret, True);
	printf("the same process %s stack read locks\n", ret?"can":"cannot");

	/* Unlock the first process lock, then check this was the WRITE lock that was
		removed. */

	ret = cli_unlock(&cli1, fnum1, 0, 4) &&
			cli_lock(&cli2, fnum2, 0, 4, 0, READ_LOCK);

	EXPECTED(ret, True);
	printf("the first unlock removes the %s lock\n", ret?"WRITE":"READ");

	/* Unlock the process 2 lock. */
	cli_unlock(&cli2, fnum2, 0, 4);

	/* We should have 3 stacked locks here. Ensure we need to do 3 unlocks. */

	ret = cli_unlock(&cli1, fnum1, 1, 1) &&
		  cli_unlock(&cli1, fnum1, 0, 4) &&
		  cli_unlock(&cli1, fnum1, 0, 4);

	EXPECTED(ret, True);
	printf("the same process %s unlock the stack of 4 locks\n", ret?"can":"cannot"); 

	/* Ensure the next unlock fails. */
	ret = cli_unlock(&cli1, fnum1, 0, 4);
	EXPECTED(ret, False);
	printf("the same process %s count the lock stack\n", !ret?"can":"cannot"); 

	/* Ensure connection 2 can get a write lock. */
	ret = cli_lock(&cli2, fnum2, 0, 4, 0, WRITE_LOCK);
	EXPECTED(ret, True);

	printf("a different processs %s get a write lock on the unlocked stack\n", ret?"can":"cannot");


 fail:
	cli_close(&cli1, fnum1);
	cli_close(&cli2, fnum2);
	cli_unlink(&cli1, fname);
	if (!torture_close_connection(&cli1)) {
		correct = False;
	}
	if (!torture_close_connection(&cli2)) {
		correct = False;
	}

	printf("finished locktest5\n");
       
	return correct;
}

/*
test whether fnums and tids open on one VC are available on another (a major
security hole)
*/
static BOOL run_fdpasstest(int dummy)
{
	static struct cli_state cli1, cli2, cli3;
	char *fname = "\\fdpass.tst";
	int fnum1;
	pstring buf;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}
	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	printf("starting fdpasstest\n");

	cli_unlink(&cli1, fname);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	if (cli_write(&cli1, fnum1, 0, "hello world\n", 0, 13) != 13) {
		printf("write failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	cli3 = cli2;
	cli3.vuid = cli1.vuid;
	cli3.cnum = cli1.cnum;
	cli3.pid = cli1.pid;

	if (cli_read(&cli3, fnum1, buf, 0, 13) == 13) {
		printf("read succeeded! nasty security hole [%s]\n",
		       buf);
		return False;
	}

	cli_close(&cli1, fnum1);
	cli_unlink(&cli1, fname);

	torture_close_connection(&cli1);
	torture_close_connection(&cli2);

	printf("finished fdpasstest\n");
	return True;
}


/*
  This test checks that 

  1) the server does not allow an unlink on a file that is open
*/
static BOOL run_unlinktest(int dummy)
{
	static struct cli_state cli;
	char *fname = "\\unlink.tst";
	int fnum;
	BOOL correct = True;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	cli_sockopt(&cli, sockops);

	printf("starting unlink test\n");

	cli_unlink(&cli, fname);

	cli_setpid(&cli, 1);

	fnum = cli_open(&cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli));
		return False;
	}

	if (cli_unlink(&cli, fname)) {
		printf("error: server allowed unlink on an open file\n");
		correct = False;
	} else {
		correct = check_error(__LINE__, &cli, ERRDOS, ERRbadshare, 
				      NT_STATUS_SHARING_VIOLATION);
	}

	cli_close(&cli, fnum);
	cli_unlink(&cli, fname);

	if (!torture_close_connection(&cli)) {
		correct = False;
	}

	printf("unlink test finished\n");
	
	return correct;
}


/*
test how many open files this server supports on the one socket
*/
static BOOL run_maxfidtest(int dummy)
{
	static struct cli_state cli;
	char *template = "\\maxfid.%d.%d";
	fstring fname;
	int fnums[0x11000], i;
	int retries=4;
	BOOL correct = True;

	cli = current_cli;

	if (retries <= 0) {
		printf("failed to connect\n");
		return False;
	}

	cli_sockopt(&cli, sockops);

	for (i=0; i<0x11000; i++) {
		slprintf(fname,sizeof(fname)-1,template, i,(int)getpid());
		if ((fnums[i] = cli_open(&cli, fname, 
					O_RDWR|O_CREAT|O_TRUNC, DENY_NONE)) ==
		    -1) {
			printf("open of %s failed (%s)\n", 
			       fname, cli_errstr(&cli));
			printf("maximum fnum is %d\n", i);
			break;
		}
		printf("%6d\r", i);
	}
	printf("%6d\n", i);
	i--;

	printf("cleaning up\n");
	for (;i>=0;i--) {
		slprintf(fname,sizeof(fname)-1,template, i,(int)getpid());
		cli_close(&cli, fnums[i]);
		if (!cli_unlink(&cli, fname)) {
			printf("unlink of %s failed (%s)\n", 
			       fname, cli_errstr(&cli));
			correct = False;
		}
		printf("%6d\r", i);
	}
	printf("%6d\n", 0);

	printf("maxfid test finished\n");
	if (!torture_close_connection(&cli)) {
		correct = False;
	}
	return correct;
}

/* generate a random buffer */
static void rand_buf(char *buf, int len)
{
	while (len--) {
		*buf = (char)sys_random();
		buf++;
	}
}

/* send smb negprot commands, not reading the response */
static BOOL run_negprot_nowait(int dummy)
{
	int i;
	static struct cli_state cli;
	BOOL correct = True;

	printf("starting negprot nowait test\n");

	if (!open_nbt_connection(&cli)) {
		return False;
	}

	for (i=0;i<50000;i++) {
		cli_negprot_send(&cli);
	}

	if (!torture_close_connection(&cli)) {
		correct = False;
	}

	printf("finished negprot nowait test\n");

	return correct;
}


/* send random IPC commands */
static BOOL run_randomipc(int dummy)
{
	char *rparam = NULL;
	char *rdata = NULL;
	int rdrcnt,rprcnt;
	pstring param;
	int api, param_len, i;
	static struct cli_state cli;
	BOOL correct = True;
	int count = 50000;

	printf("starting random ipc test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	for (i=0;i<count;i++) {
		api = sys_random() % 500;
		param_len = (sys_random() % 64);

		rand_buf(param, param_len);
  
		SSVAL(param,0,api); 

		cli_api(&cli, 
			param, param_len, 8,  
			NULL, 0, BUFFER_SIZE, 
			&rparam, &rprcnt,     
			&rdata, &rdrcnt);
		if (i % 100 == 0) {
			printf("%d/%d\r", i,count);
		}
	}
	printf("%d/%d\n", i, count);

	if (!torture_close_connection(&cli)) {
		correct = False;
	}

	printf("finished random ipc test\n");

	return correct;
}



static void browse_callback(const char *sname, uint32 stype, 
			    const char *comment, void *state)
{
	printf("\t%20.20s %08x %s\n", sname, stype, comment);
}



/*
  This test checks the browse list code

*/
static BOOL run_browsetest(int dummy)
{
	static struct cli_state cli;
	BOOL correct = True;

	printf("starting browse test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	printf("domain list:\n");
	cli_NetServerEnum(&cli, cli.server_domain, 
			  SV_TYPE_DOMAIN_ENUM,
			  browse_callback, NULL);

	printf("machine list:\n");
	cli_NetServerEnum(&cli, cli.server_domain, 
			  SV_TYPE_ALL,
			  browse_callback, NULL);

	if (!torture_close_connection(&cli)) {
		correct = False;
	}

	printf("browse test finished\n");

	return correct;

}


/*
  This checks how the getatr calls works
*/
static BOOL run_attrtest(int dummy)
{
	static struct cli_state cli;
	int fnum;
	time_t t, t2;
	char *fname = "\\attrib.tst";
	BOOL correct = True;

	printf("starting attrib test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_close(&cli, fnum);
	if (!cli_getatr(&cli, fname, NULL, NULL, &t)) {
		printf("getatr failed (%s)\n", cli_errstr(&cli));
		correct = False;
	}

	if (abs(t - time(NULL)) > 2) {
		printf("ERROR: SMBgetatr bug. time is %s",
		       ctime(&t));
		t = time(NULL);
		correct = True;
	}

	t2 = t-60*60*24; /* 1 day ago */

	if (!cli_setatr(&cli, fname, 0, t2)) {
		printf("setatr failed (%s)\n", cli_errstr(&cli));
		correct = True;
	}

	if (!cli_getatr(&cli, fname, NULL, NULL, &t)) {
		printf("getatr failed (%s)\n", cli_errstr(&cli));
		correct = True;
	}

	if (t != t2) {
		printf("ERROR: getatr/setatr bug. times are\n%s",
		       ctime(&t));
		printf("%s", ctime(&t2));
		correct = True;
	}

	cli_unlink(&cli, fname);

	if (!torture_close_connection(&cli)) {
		correct = False;
	}

	printf("attrib test finished\n");

	return correct;
}


/*
  This checks a couple of trans2 calls
*/
static BOOL run_trans2test(int dummy)
{
	static struct cli_state cli;
	int fnum;
	size_t size;
	time_t c_time, a_time, m_time, w_time, m_time2;
	char *fname = "\\trans2.tst";
	char *dname = "\\trans2";
	char *fname2 = "\\trans2\\trans2.tst";
	BOOL correct = True;

	printf("starting trans2 test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	if (!cli_qfileinfo(&cli, fnum, NULL, &size, &c_time, &a_time, &m_time,
			   NULL, NULL)) {
		printf("ERROR: qfileinfo failed (%s)\n", cli_errstr(&cli));
		correct = False;
	}
	cli_close(&cli, fnum);

	sleep(2);

	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli));
		return False;
	}
	cli_close(&cli, fnum);

	if (!cli_qpathinfo(&cli, fname, &c_time, &a_time, &m_time, &size, NULL)) {
		printf("ERROR: qpathinfo failed (%s)\n", cli_errstr(&cli));
		correct = False;
	} else {
		if (c_time != m_time) {
			printf("create time=%s", ctime(&c_time));
			printf("modify time=%s", ctime(&m_time));
			printf("This system appears to have sticky create times\n");
			correct = False;
		}
		if (a_time % (60*60) == 0) {
			printf("access time=%s", ctime(&a_time));
			printf("This system appears to set a midnight access time\n");
			correct = False;
		}

		if (abs(m_time - time(NULL)) > 60*60*24*7) {
			printf("ERROR: totally incorrect times - maybe word reversed? mtime=%s", ctime(&m_time));
			correct = False;
		}
	}


	cli_unlink(&cli, fname);
	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_close(&cli, fnum);
	if (!cli_qpathinfo2(&cli, fname, &c_time, &a_time, &m_time, 
			    &w_time, &size, NULL, NULL)) {
		printf("ERROR: qpathinfo2 failed (%s)\n", cli_errstr(&cli));
		correct = False;
	} else {
		if (w_time < 60*60*24*2) {
			printf("write time=%s", ctime(&w_time));
			printf("This system appears to set a initial 0 write time\n");
			correct = False;
		}
	}

	cli_unlink(&cli, fname);


	/* check if the server updates the directory modification time
           when creating a new file */
	if (!cli_mkdir(&cli, dname)) {
		printf("ERROR: mkdir failed (%s)\n", cli_errstr(&cli));
		correct = False;
	}
	sleep(3);
	if (!cli_qpathinfo2(&cli, "\\trans2\\", &c_time, &a_time, &m_time, 
			    &w_time, &size, NULL, NULL)) {
		printf("ERROR: qpathinfo2 failed (%s)\n", cli_errstr(&cli));
		correct = False;
	}

	fnum = cli_open(&cli, fname2, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	cli_write(&cli, fnum,  0, (char *)&fnum, 0, sizeof(fnum));
	cli_close(&cli, fnum);
	if (!cli_qpathinfo2(&cli, "\\trans2\\", &c_time, &a_time, &m_time2, 
			    &w_time, &size, NULL, NULL)) {
		printf("ERROR: qpathinfo2 failed (%s)\n", cli_errstr(&cli));
		correct = False;
	} else {
		if (m_time2 == m_time) {
			printf("This system does not update directory modification times\n");
			correct = False;
		}
	}
	cli_unlink(&cli, fname2);
	cli_rmdir(&cli, dname);

	if (!torture_close_connection(&cli)) {
		correct = False;
	}

	printf("trans2 test finished\n");

	return correct;
}

/*
  This checks new W2K calls.
*/

static BOOL new_trans(struct cli_state *pcli, int fnum, int level)
{
	char buf[4096];
	BOOL correct = True;

	memset(buf, 0xff, sizeof(buf));

	if (!cli_qfileinfo_test(pcli, fnum, level, buf)) {
		printf("ERROR: qfileinfo (%d) failed (%s)\n", level, cli_errstr(pcli));
		correct = False;
	} else {
		printf("qfileinfo: level %d\n", level);
		dump_data(0, buf, 256);
		printf("\n");
	}
	return correct;
}

static BOOL run_w2ktest(int dummy)
{
	static struct cli_state cli;
	int fnum;
	char *fname = "\\w2ktest\\w2k.tst";
	int level;
	BOOL correct = True;

	printf("starting w2k test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	fnum = cli_open(&cli, fname, 
			O_RDWR | O_CREAT , DENY_NONE);

	for (level = 1004; level < 1040; level++) {
		new_trans(&cli, fnum, level);
	}

	cli_close(&cli, fnum);

	if (!torture_close_connection(&cli)) {
		correct = False;
	}

	printf("w2k test finished\n");
	
	return correct;
}


/*
  this is a harness for some oplock tests
 */
static BOOL run_oplock1(int dummy)
{
	static struct cli_state cli1;
	char *fname = "\\lockt1.lck";
	int fnum1;
	BOOL correct = True;

	printf("starting oplock test 1\n");

	if (!torture_open_connection(&cli1)) {
		return False;
	}

	cli_unlink(&cli1, fname);

	cli_sockopt(&cli1, sockops);

	cli1.use_oplocks = True;

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	cli1.use_oplocks = False;

	cli_unlink(&cli1, fname);
	cli_unlink(&cli1, fname);

	if (!cli_close(&cli1, fnum1)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (!cli_unlink(&cli1, fname)) {
		printf("unlink failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (!torture_close_connection(&cli1)) {
		correct = False;
	}

	printf("finished oplock test 1\n");

	return correct;
}

static BOOL run_oplock2(int dummy)
{
	static struct cli_state cli1, cli2;
	char *fname = "\\lockt2.lck";
	int fnum1, fnum2;
	int saved_use_oplocks = use_oplocks;
	char buf[4];
	BOOL correct = True;
	volatile BOOL *shared_correct;

	shared_correct = (volatile BOOL *)shm_setup(sizeof(BOOL));
	*shared_correct = True;

	use_level_II_oplocks = True;
	use_oplocks = True;

	printf("starting oplock test 2\n");

	if (!torture_open_connection(&cli1)) {
		use_level_II_oplocks = False;
		use_oplocks = saved_use_oplocks;
		return False;
	}

	cli1.use_oplocks = True;
	cli1.use_level_II_oplocks = True;

	if (!torture_open_connection(&cli2)) {
		use_level_II_oplocks = False;
		use_oplocks = saved_use_oplocks;
		return False;
	}

	cli2.use_oplocks = True;
	cli2.use_level_II_oplocks = True;

	cli_unlink(&cli1, fname);

	cli_sockopt(&cli1, sockops);
	cli_sockopt(&cli2, sockops);

	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	/* Don't need the globals any more. */
	use_level_II_oplocks = False;
	use_oplocks = saved_use_oplocks;

	if (fork() == 0) {
		/* Child code */
		fnum2 = cli_open(&cli2, fname, O_RDWR, DENY_NONE);
		if (fnum2 == -1) {
			printf("second open of %s failed (%s)\n", fname, cli_errstr(&cli1));
			*shared_correct = False;
			exit(0);
		}

		sleep(2);

		if (!cli_close(&cli2, fnum2)) {
			printf("close2 failed (%s)\n", cli_errstr(&cli1));
			*shared_correct = False;
		}

		exit(0);
	}

	sleep(2);

	/* Ensure cli1 processes the break. */

	if (cli_read(&cli1, fnum1, buf, 0, 4) != 4) {
		printf("read on fnum1 failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}

	/* Should now be at level II. */
	/* Test if sending a write locks causes a break to none. */

	if (!cli_lock(&cli1, fnum1, 0, 4, 0, READ_LOCK)) {
		printf("lock failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}

	cli_unlock(&cli1, fnum1, 0, 4);

	sleep(2);

	if (!cli_lock(&cli1, fnum1, 0, 4, 0, WRITE_LOCK)) {
		printf("lock failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}

	cli_unlock(&cli1, fnum1, 0, 4);

	sleep(2);

	cli_read(&cli1, fnum1, buf, 0, 4);

#if 0
	if (cli_write(&cli1, fnum1, 0, buf, 0, 4) != 4) {
		printf("write on fnum1 failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}
#endif

	if (!cli_close(&cli1, fnum1)) {
		printf("close1 failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}

	sleep(4);

	if (!cli_unlink(&cli1, fname)) {
		printf("unlink failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}

	if (!torture_close_connection(&cli1)) {
		correct = False;
	}

	if (!*shared_correct) {
		correct = False;
	}

	printf("finished oplock test 2\n");

	return correct;
}

/* handler for oplock 3 tests */
static BOOL oplock3_handler(struct cli_state *cli, int fnum, unsigned char level)
{
	printf("got oplock break fnum=%d level=%d\n",
	       fnum, level);
	return cli_oplock_ack(cli, fnum, level);
}

static BOOL run_oplock3(int dummy)
{
	static struct cli_state cli;
	char *fname = "\\oplockt3.dat";
	int fnum;
	char buf[4] = "abcd";
	BOOL correct = True;
	volatile BOOL *shared_correct;

	shared_correct = (volatile BOOL *)shm_setup(sizeof(BOOL));
	*shared_correct = True;

	printf("starting oplock test 3\n");

	if (fork() == 0) {
		/* Child code */
		use_oplocks = True;
		use_level_II_oplocks = True;
		if (!torture_open_connection(&cli)) {
			*shared_correct = False;
			exit(0);
		} 
		sleep(2);
		/* try to trigger a oplock break in parent */
		fnum = cli_open(&cli, fname, O_RDWR, DENY_NONE);
		cli_write(&cli, fnum, 0, buf, 0, 4);
		exit(0);
	}

	/* parent code */
	use_oplocks = True;
	use_level_II_oplocks = True;
	if (!torture_open_connection(&cli)) { 
		return False;
	}
	cli_oplock_handler(&cli, oplock3_handler);
	fnum = cli_open(&cli, fname, O_RDWR|O_CREAT, DENY_NONE);
	cli_write(&cli, fnum, 0, buf, 0, 4);
	cli_close(&cli, fnum);
	fnum = cli_open(&cli, fname, O_RDWR, DENY_NONE);
	cli.timeout = 20000;
	cli_receive_smb(&cli);
	printf("finished oplock test 3\n");

	return (correct && *shared_correct);

/* What are we looking for here?  What's sucess and what's FAILURE? */
}



/*
  Test delete on close semantics.
 */
static BOOL run_deletetest(int dummy)
{
	static struct cli_state cli1;
	static struct cli_state cli2;
	char *fname = "\\delete.file";
	int fnum1, fnum2;
	BOOL correct = True;
	
	printf("starting delete test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	
	cli_sockopt(&cli1, sockops);

	/* Test 1 - this should *NOT* delete the file on close. */
	
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);
	
	fnum1 = cli_nt_create_full(&cli1, fname, GENERIC_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
				   FILE_SHARE_DELETE, FILE_OVERWRITE_IF, 
				   DELETE_ON_CLOSE_FLAG);
	
	if (fnum1 == -1) {
		printf("[1] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_close(&cli1, fnum1)) {
		printf("[1] close failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	fnum1 = cli_open(&cli1, fname, O_RDWR, DENY_NONE);
	if (fnum1 == -1) {
		printf("[1] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_close(&cli1, fnum1)) {
		printf("[1] close failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	printf("first delete on close test succeeded.\n");
	
	/* Test 2 - this should delete the file on close. */
	
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);
	
	fnum1 = cli_nt_create_full(&cli1, fname, GENERIC_ALL_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, 
				   FILE_OVERWRITE_IF, 0);
	
	if (fnum1 == -1) {
		printf("[2] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_nt_delete_on_close(&cli1, fnum1, True)) {
		printf("[2] setting delete_on_close failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_close(&cli1, fnum1)) {
		printf("[2] close failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	fnum1 = cli_open(&cli1, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("[2] open of %s succeeded should have been deleted on close !\n", fname);
		if (!cli_close(&cli1, fnum1)) {
			printf("[2] close failed (%s)\n", cli_errstr(&cli1));
			correct = False;
		}
		cli_unlink(&cli1, fname);
	} else
		printf("second delete on close test succeeded.\n");
	
	/* Test 3 - ... */
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);

	fnum1 = cli_nt_create_full(&cli1, fname, GENERIC_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
				   FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0);

	if (fnum1 == -1) {
		printf("[3] open - 1 of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	/* This should fail with a sharing violation - open for delete is only compatible
	   with SHARE_DELETE. */

	fnum2 = cli_nt_create_full(&cli1, fname, GENERIC_READ_ACCESS, FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, 0);

	if (fnum2 != -1) {
		printf("[3] open  - 2 of %s succeeded - should have failed.\n", fname);
		return False;
	}

	/* This should succeed. */

	fnum2 = cli_nt_create_full(&cli1, fname, GENERIC_READ_ACCESS, FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN, 0);

	if (fnum2 == -1) {
		printf("[3] open  - 2 of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	if (!cli_nt_delete_on_close(&cli1, fnum1, True)) {
		printf("[3] setting delete_on_close failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_close(&cli1, fnum1)) {
		printf("[3] close 1 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_close(&cli1, fnum2)) {
		printf("[3] close 2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	/* This should fail - file should no longer be there. */

	fnum1 = cli_open(&cli1, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("[3] open of %s succeeded should have been deleted on close !\n", fname);
		if (!cli_close(&cli1, fnum1)) {
			printf("[3] close failed (%s)\n", cli_errstr(&cli1));
		}
		cli_unlink(&cli1, fname);
		correct = False;
	} else
		printf("third delete on close test succeeded.\n");

	/* Test 4 ... */
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);

	fnum1 = cli_nt_create_full(&cli1, fname, FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0);
								
	if (fnum1 == -1) {
		printf("[4] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	/* This should succeed. */
	fnum2 = cli_nt_create_full(&cli1, fname, GENERIC_READ_ACCESS,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN, 0);
	if (fnum2 == -1) {
		printf("[4] open  - 2 of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_close(&cli1, fnum2)) {
		printf("[4] close - 1 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_nt_delete_on_close(&cli1, fnum1, True)) {
		printf("[4] setting delete_on_close failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	/* This should fail - no more opens once delete on close set. */
	fnum2 = cli_nt_create_full(&cli1, fname, GENERIC_READ_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN, 0);
	if (fnum2 != -1) {
		printf("[4] open  - 3 of %s succeeded ! Should have failed.\n", fname );
		return False;
	} else
		printf("fourth delete on close test succeeded.\n");
	
	if (!cli_close(&cli1, fnum1)) {
		printf("[4] close - 2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	/* Test 5 ... */
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);
	
	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		printf("[5] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	/* This should fail - only allowed on NT opens with DELETE access. */

	if (cli_nt_delete_on_close(&cli1, fnum1, True)) {
		printf("[5] setting delete_on_close on OpenX file succeeded - should fail !\n");
		return False;
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("[5] close - 2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	printf("fifth delete on close test succeeded.\n");
	
	/* Test 6 ... */
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);
	
	fnum1 = cli_nt_create_full(&cli1, fname, FILE_READ_DATA|FILE_WRITE_DATA,
				   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
				   FILE_OVERWRITE_IF, 0);
	
	if (fnum1 == -1) {
		printf("[6] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	
	/* This should fail - only allowed on NT opens with DELETE access. */
	
	if (cli_nt_delete_on_close(&cli1, fnum1, True)) {
		printf("[6] setting delete_on_close on file with no delete access succeeded - should fail !\n");
		return False;
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("[6] close - 2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	printf("sixth delete on close test succeeded.\n");
	
	/* Test 7 ... */
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);
	
	fnum1 = cli_nt_create_full(&cli1, fname, FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, 0);
								
	if (fnum1 == -1) {
		printf("[7] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	if (!cli_nt_delete_on_close(&cli1, fnum1, True)) {
		printf("[7] setting delete_on_close on file failed !\n");
		return False;
	}
	
	if (!cli_nt_delete_on_close(&cli1, fnum1, False)) {
		printf("[7] unsetting delete_on_close on file failed !\n");
		return False;
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("[7] close - 2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	/* This next open should succeed - we reset the flag. */
	
	fnum1 = cli_open(&cli1, fname, O_RDONLY, DENY_NONE);
	if (fnum1 == -1) {
		printf("[5] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("[7] close - 2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	printf("seventh delete on close test succeeded.\n");
	
	/* Test 7 ... */
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);
	
	if (!torture_open_connection(&cli2)) {
		printf("[8] failed to open second connection.\n");
		return False;
	}

	cli_sockopt(&cli1, sockops);
	
	fnum1 = cli_nt_create_full(&cli1, fname, FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OVERWRITE_IF, 0);
	
	if (fnum1 == -1) {
		printf("[8] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	fnum2 = cli_nt_create_full(&cli2, fname, FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN, 0);
	
	if (fnum2 == -1) {
		printf("[8] open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	if (!cli_nt_delete_on_close(&cli1, fnum1, True)) {
		printf("[8] setting delete_on_close on file failed !\n");
		return False;
	}
	
	if (!cli_close(&cli1, fnum1)) {
		printf("[8] close - 1 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (!cli_close(&cli2, fnum2)) {
		printf("[8] close - 2 failed (%s)\n", cli_errstr(&cli2));
		return False;
	}

	/* This should fail.. */
	fnum1 = cli_open(&cli1, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("[8] open of %s succeeded should have been deleted on close !\n", fname);
		if (!cli_close(&cli1, fnum1)) {
			printf("[8] close failed (%s)\n", cli_errstr(&cli1));
		}
		cli_unlink(&cli1, fname);
		correct = False;
	} else
		printf("eighth delete on close test succeeded.\n");

	printf("finished delete test\n");
	
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);
	
	if (!torture_close_connection(&cli1)) {
		correct = False;
	}
	if (!torture_close_connection(&cli2)) {
		correct = False;
	}
	return correct;
}

/*
  Test open mode returns on read-only files.
 */
static BOOL run_opentest(int dummy)
{
	static struct cli_state cli1;
	char *fname = "\\readonly.file";
	int fnum1, fnum2;
	char buf[20];
	size_t fsize;
	BOOL correct = True;
	char *tmp_path;

	printf("starting open test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	
	cli_setatr(&cli1, fname, 0, 0);
	cli_unlink(&cli1, fname);
	
	cli_sockopt(&cli1, sockops);
	
	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_setatr(&cli1, fname, aRONLY, 0)) {
		printf("cli_setatr failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	fnum1 = cli_open(&cli1, fname, O_RDONLY, DENY_WRITE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	
	/* This will fail - but the error should be ERRnoaccess, not ERRbadshare. */
	fnum2 = cli_open(&cli1, fname, O_RDWR, DENY_ALL);
	
        if (check_error(__LINE__, &cli1, ERRDOS, ERRnoaccess, 
			NT_STATUS_ACCESS_DENIED)) {
		printf("correct error code ERRDOS/ERRnoaccess returned\n");
	}
	
	printf("finished open test 1\n");
	
	cli_close(&cli1, fnum1);
	
	/* Now try not readonly and ensure ERRbadshare is returned. */
	
	cli_setatr(&cli1, fname, 0, 0);
	
	fnum1 = cli_open(&cli1, fname, O_RDONLY, DENY_WRITE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	
	/* This will fail - but the error should be ERRshare. */
	fnum2 = cli_open(&cli1, fname, O_RDWR, DENY_ALL);
	
	if (check_error(__LINE__, &cli1, ERRDOS, ERRbadshare, 
			NT_STATUS_SHARING_VIOLATION)) {
		printf("correct error code ERRDOS/ERRbadshare returned\n");
	}
	
	if (!cli_close(&cli1, fnum1)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	cli_unlink(&cli1, fname);
	
	printf("finished open test 2\n");
	
	/* Test truncate open disposition on file opened for read. */
	
	fnum1 = cli_open(&cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("(3) open (1) of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	
	/* write 20 bytes. */
	
	memset(buf, '\0', 20);

	if (cli_write(&cli1, fnum1, 0, buf, 0, 20) != 20) {
		printf("write failed (%s)\n", cli_errstr(&cli1));
		correct = False;
	}

	if (!cli_close(&cli1, fnum1)) {
		printf("(3) close1 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	/* Ensure size == 20. */
	if (!cli_getatr(&cli1, fname, NULL, &fsize, NULL)) {
		printf("(3) getatr failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	
	if (fsize != 20) {
		printf("(3) file size != 20\n");
		return False;
	}

	/* Now test if we can truncate a file opened for readonly. */
	
	fnum1 = cli_open(&cli1, fname, O_RDONLY|O_TRUNC, DENY_NONE);
	if (fnum1 == -1) {
		printf("(3) open (2) of %s failed (%s)\n", fname, cli_errstr(&cli1));
		return False;
	}
	
	if (!cli_close(&cli1, fnum1)) {
		printf("close2 failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	/* Ensure size == 0. */
	if (!cli_getatr(&cli1, fname, NULL, &fsize, NULL)) {
		printf("(3) getatr failed (%s)\n", cli_errstr(&cli1));
		return False;
	}

	if (fsize != 0) {
		printf("(3) file size != 0\n");
		return False;
	}
	printf("finished open test 3\n");
	
	cli_unlink(&cli1, fname);


	printf("testing ctemp\n");
	fnum1 = cli_ctemp(&cli1, "\\", &tmp_path);
	if (fnum1 == -1) {
		printf("ctemp failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	printf("ctemp gave path %s\n", tmp_path);
	if (!cli_close(&cli1, fnum1)) {
		printf("close of temp failed (%s)\n", cli_errstr(&cli1));
	}
	if (!cli_unlink(&cli1, tmp_path)) {
		printf("unlink of temp failed (%s)\n", cli_errstr(&cli1));
	}
	
	if (!torture_close_connection(&cli1)) {
		correct = False;
	}
	
	return correct;
}

static void list_fn(file_info *finfo, const char *name, void *state)
{
	
}

/*
  test directory listing speed
 */
static BOOL run_dirtest(int dummy)
{
	int i;
	static struct cli_state cli;
	int fnum;
	double t1;
	BOOL correct = True;

	printf("starting directory test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	cli_sockopt(&cli, sockops);

	srandom(0);
	for (i=0;i<numops;i++) {
		fstring fname;
		slprintf(fname, sizeof(fname), "%x", (int)random());
		fnum = cli_open(&cli, fname, O_RDWR|O_CREAT, DENY_NONE);
		if (fnum == -1) {
			fprintf(stderr,"Failed to open %s\n", fname);
			return False;
		}
		cli_close(&cli, fnum);
	}

	t1 = end_timer();

	printf("Matched %d\n", cli_list(&cli, "a*.*", 0, list_fn, NULL));
	printf("Matched %d\n", cli_list(&cli, "b*.*", 0, list_fn, NULL));
	printf("Matched %d\n", cli_list(&cli, "xyzabc", 0, list_fn, NULL));

	printf("dirtest core %g seconds\n", end_timer() - t1);

	srandom(0);
	for (i=0;i<numops;i++) {
		fstring fname;
		slprintf(fname, sizeof(fname), "%x", (int)random());
		cli_unlink(&cli, fname);
	}

	if (!torture_close_connection(&cli)) {
		correct = False;
	}

	printf("finished dirtest\n");

	return correct;
}

static BOOL run_error_map_extract(int dummy) {
	
	static struct cli_state c_dos;
	static struct cli_state c_nt;

	uint32 error;

	uint32 flgs2, errnum;
        uint8 errclass;

	NTSTATUS nt_status;

	fstring user;

	/* NT-Error connection */

	if (!open_nbt_connection(&c_nt)) {
		return False;
	}

	c_nt.use_spnego = False;

	if (!cli_negprot(&c_nt)) {
		printf("%s rejected the NT-error negprot (%s)\n",host, cli_errstr(&c_nt));
		cli_shutdown(&c_nt);
		return False;
	}

	if (!cli_session_setup(&c_nt, "", "", 0, "", 0,
			       workgroup)) {
		printf("%s rejected the NT-error initial session setup (%s)\n",host, cli_errstr(&c_nt));
		return False;
	}

	/* DOS-Error connection */

	if (!open_nbt_connection(&c_dos)) {
		return False;
	}

	c_dos.use_spnego = False;
	c_dos.force_dos_errors = True;

	if (!cli_negprot(&c_dos)) {
		printf("%s rejected the DOS-error negprot (%s)\n",host, cli_errstr(&c_dos));
		cli_shutdown(&c_dos);
		return False;
	}

	if (!cli_session_setup(&c_dos, "", "", 0, "", 0,
			       workgroup)) {
		printf("%s rejected the DOS-error initial session setup (%s)\n",host, cli_errstr(&c_dos));
		return False;
	}

	for (error=(0xc0000000 | 0x1); error < (0xc0000000| 0xFFF); error++) {
		snprintf(user, sizeof(user), "%X", error);

		if (!cli_session_setup(&c_nt, user, 
				       password, strlen(password),
				       password, strlen(password),
				       workgroup)) {
			flgs2 = SVAL(c_nt.inbuf,smb_flg2);
			
			/* Case #1: 32-bit NT errors */
			if (flgs2 & FLAGS2_32_BIT_ERROR_CODES) {
				nt_status = NT_STATUS(IVAL(c_nt.inbuf,smb_rcls));
			} else {
				printf("** Dos error on NT connection! (%s)\n", cli_errstr(&c_nt));
				nt_status = NT_STATUS(0xc0000000);
			}
		} else {
			printf("** Session setup succeeded.  This shouldn't happen...\n");
		}

		if (!cli_session_setup(&c_dos, user, 
				       password, strlen(password),
				       password, strlen(password),
				       workgroup)) {
			flgs2 = SVAL(c_dos.inbuf,smb_flg2), errnum;
			
			/* Case #1: 32-bit NT errors */
			if (flgs2 & FLAGS2_32_BIT_ERROR_CODES) {
				printf("** NT error on DOS connection! (%s)\n", cli_errstr(&c_nt));
				errnum = errclass = 0;
			} else {
				cli_dos_error(&c_dos, &errclass, &errnum);
			}
		} else {
			printf("** Session setup succeeded.  This shouldn't happen...\n");
		}
		if (NT_STATUS_V(nt_status) == error) { 
			printf("\t{%s,\t%s,\t%s},\n", smb_dos_err_class(errclass), smb_dos_err_name(errclass, errnum), get_nt_error_c_code(nt_status));
		} else {
			printf("/*\t{ This NT error code was 'sqashed'\n\t from %s to %s \n\t during the session setup }\n*/\n", get_nt_error_c_code(NT_STATUS(error)), get_nt_error_c_code(nt_status));
		}
	}
	return True;
}

static double create_procs(BOOL (*fn)(int), BOOL *result)
{
	int i, status;
	volatile pid_t *child_status;
	volatile BOOL *child_status_out;
	int synccount;
	int tries = 8;

	synccount = 0;

	child_status = (volatile pid_t *)shm_setup(sizeof(pid_t)*nprocs);
	if (!child_status) {
		printf("Failed to setup shared memory\n");
		return -1;
	}

	child_status_out = (volatile BOOL *)shm_setup(sizeof(BOOL)*nprocs);
	if (!child_status_out) {
		printf("Failed to setup result status shared memory\n");
		return -1;
	}

	memset((void *)child_status, 0, sizeof(pid_t)*nprocs);
	memset((void *)child_status_out, True, sizeof(BOOL)*nprocs);

	start_timer();

	for (i=0;i<nprocs;i++) {
		procnum = i;
		if (fork() == 0) {
			pid_t mypid = getpid();
			sys_srandom(((int)mypid) ^ ((int)time(NULL)));

			slprintf(myname,sizeof(myname),"CLIENT%d", i);

			while (1) {
				memset(&current_cli, 0, sizeof(current_cli));
				if (torture_open_connection(&current_cli)) break;
				if (tries-- == 0) {
					printf("pid %d failed to start\n", (int)getpid());
					_exit(1);
				}
				msleep(10);	
			}

			child_status[i] = getpid();

			while (child_status[i]) msleep(2);

			child_status_out[i] = fn(i);
			_exit(0);
		}
	}

	do {
		synccount = 0;
		for (i=0;i<nprocs;i++) {
			if (child_status[i]) synccount++;
		}
		if (synccount == nprocs) break;
		msleep(10);
	} while (end_timer() < 30);

	if (synccount != nprocs) {
		printf("FAILED TO START %d CLIENTS (started %d)\n", nprocs, synccount);
		*result = False;
		return end_timer();
	}

	/* start the client load */
	start_timer();

	for (i=0;i<nprocs;i++) {
		child_status[i] = 0;
	}

	printf("%d clients started\n", nprocs);

	for (i=0;i<nprocs;i++) {
		waitpid(0, &status, 0);
		printf("*");
	}

	printf("\n");
	
	for (i=0;i<nprocs;i++) {
		if (!child_status_out[i]) {
			*result = False;
		}
	}
	return end_timer();
}


#define FLAG_MULTIPROC 1

static struct {
	char *name;
	BOOL (*fn)(int);
	unsigned flags;
} torture_ops[] = {
	{"FDPASS", run_fdpasstest, 0},
	{"LOCK1",  run_locktest1,  0},
	{"LOCK2",  run_locktest2,  0},
	{"LOCK3",  run_locktest3,  0},
	{"LOCK4",  run_locktest4,  0},
	{"LOCK5",  run_locktest5,  0},
	{"UNLINK", run_unlinktest, 0},
	{"BROWSE", run_browsetest, 0},
	{"ATTR",   run_attrtest,   0},
	{"TRANS2", run_trans2test, 0},
	{"MAXFID", run_maxfidtest, FLAG_MULTIPROC},
	{"TORTURE",run_torture,    FLAG_MULTIPROC},
	{"RANDOMIPC", run_randomipc, 0},
	{"NEGNOWAIT", run_negprot_nowait, 0},
	{"NBW95",  run_nbw95, 0},
	{"NBWNT",  run_nbwnt, 0},
	{"OPLOCK1",  run_oplock1, 0},
	{"OPLOCK2",  run_oplock2, 0},
	{"OPLOCK3",  run_oplock3, 0},
	{"DIR",  run_dirtest, 0},
	{"DENY1",  torture_denytest1, 0},
	{"DENY2",  torture_denytest2, 0},
	{"TCON",  run_tcon_test, 0},
	{"RW1",  run_readwritetest, 0},
	{"RW2",  run_readwritemulti, FLAG_MULTIPROC},
	{"RW3",  run_readwritelarge, 0},
	{"OPEN", run_opentest, 0},
	{"DELETE", run_deletetest, 0},
	{"W2K", run_w2ktest, 0},
	{"TRANS2SCAN", torture_trans2_scan, 0},
	{"NTTRANSSCAN", torture_nttrans_scan, 0},
	{"UTABLE", torture_utable, 0},
	{"CASETABLE", torture_casetable, 0},
	{"ERRMAPEXTRACT", run_error_map_extract, 0},
	{NULL, NULL, 0}};



/****************************************************************************
run a specified test or "ALL"
****************************************************************************/
static BOOL run_test(char *name)
{
	BOOL ret = True;
	BOOL result = True;
	int i;
	double t;
	if (strequal(name,"ALL")) {
		for (i=0;torture_ops[i].name;i++) {
			run_test(torture_ops[i].name);
		}
	}
	
	for (i=0;torture_ops[i].name;i++) {
		snprintf(randomfname, sizeof(randomfname), "\\XX%x", 
			 (unsigned)random());

		if (strequal(name, torture_ops[i].name)) {
			printf("Running %s\n", name);
			if (torture_ops[i].flags & FLAG_MULTIPROC) {
				t = create_procs(torture_ops[i].fn, &result);
				if (!result) { 
					ret = False;
					printf("TEST %s FAILED!\n", name);
				}
					 
			} else {
				start_timer();
				if (!torture_ops[i].fn(0)) {
					ret = False;
					printf("TEST %s FAILED!\n", name);
				}
				t = end_timer();
			}
			printf("%s took %g secs\n\n", name, t);
		}
	}
	return ret;
}


static void usage(void)
{
	int i;

	printf("Usage: smbtorture //server/share <options> TEST1 TEST2 ...\n");

	printf("\t-d debuglevel\n");
	printf("\t-U user%%pass\n");
	printf("\t-N numprocs\n");
	printf("\t-n my_netbios_name\n");
	printf("\t-W workgroup\n");
	printf("\t-o num_operations\n");
	printf("\t-O socket_options\n");
	printf("\t-m maximum protocol\n");
	printf("\t-L use oplocks\n");
	printf("\t-A showall\n");
	printf("\n\n");

	printf("tests are:");
	for (i=0;torture_ops[i].name;i++) {
		printf(" %s", torture_ops[i].name);
	}
	printf("\n");

	printf("default test is ALL\n");
	
	exit(1);
}





/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	int opt, i;
	char *p;
	int gotpass = 0;
	extern char *optarg;
	extern int optind;
	BOOL correct = True;

	dbf = x_stdout;

#ifdef HAVE_SETBUFFER
	setbuffer(stdout, NULL, 0);
#endif

	lp_load(dyn_CONFIGFILE,True,False,False);
	load_interfaces();

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
	p = strchr_m(&host[2],'/');
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


	fstrcpy(workgroup, lp_workgroup());

	while ((opt = getopt(argc, argv, "hW:U:n:N:O:o:m:Ld:A")) != EOF) {
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
		case 'd':
			DEBUGLEVEL = atoi(optarg);
			break;
		case 'O':
			sockops = optarg;
			break;
		case 'L':
			use_oplocks = True;
			break;
		case 'A':
			torture_showall = True;
			break;
		case 'n':
			fstrcpy(myname, optarg);
			break;
		case 'U':
			pstrcpy(username,optarg);
			p = strchr_m(username,'%');
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

	if (argc == 1) {
		correct = run_test("ALL");
	} else {
		for (i=1;i<argc;i++) {
			if (!run_test(argv[i])) {
				correct = False;
			}
		}
	}

	if (correct) {
		return(0);
	} else {
		return(1);
	}
}
