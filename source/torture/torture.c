/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   
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

#include "includes.h"

int torture_nprocs=4;
int torture_numops=100;
int torture_entries=1000;
int torture_failures=1;
static int procnum; /* records process count number when forking */
static struct smbcli_state *current_cli;
static BOOL use_oplocks;
static BOOL use_level_II_oplocks;
static BOOL use_kerberos;

BOOL torture_showall = False;

#define CHECK_MAX_FAILURES(label) do { if (++failures >= torture_failures) goto label; } while (0)

static struct smbcli_state *open_nbt_connection(void)
{
	struct nmb_name called, calling;
	struct smbcli_state *cli;
	const char *host = lp_parm_string(-1, "torture", "host");

	make_nmb_name(&calling, lp_netbios_name(), 0x0);
	choose_called_name(&called, host, 0x20);

	cli = smbcli_state_init(NULL);
	if (!cli) {
		printf("Failed initialize smbcli_struct to connect with %s\n", host);
		return NULL;
	}

	if (!smbcli_socket_connect(cli, host)) {
		printf("Failed to connect with %s\n", host);
		return cli;
	}

	cli->transport->socket->timeout = 120000; /* set a really long timeout (2 minutes) */

	if (!smbcli_transport_establish(cli, &calling, &called)) {
		/*
		 * Well, that failed, try *SMBSERVER ... 
		 * However, we must reconnect as well ...
		 */
		if (!smbcli_socket_connect(cli, host)) {
			printf("Failed to connect with %s\n", host);
			return False;
		}

		make_nmb_name(&called, "*SMBSERVER", 0x20);
		if (!smbcli_transport_establish(cli, &calling, &called)) {
			printf("%s rejected the session\n",host);
			printf("We tried with a called name of %s & %s\n",
				host, "*SMBSERVER");
			smbcli_shutdown(cli);
			return NULL;
		}
	}

	return cli;
}

BOOL torture_open_connection_share(struct smbcli_state **c, 
				   const char *hostname, 
				   const char *sharename)
{
	BOOL retry;
	int flags = 0;
	NTSTATUS status;
	const char *username = lp_parm_string(-1, "torture", "username");
	const char *userdomain = lp_parm_string(-1, "torture", "userdomain");
	const char *password = lp_parm_string(-1, "torture", "password");

	if (use_kerberos)
		flags |= SMBCLI_FULL_CONNECTION_USE_KERBEROS;

	status = smbcli_full_connection(NULL,
					c, lp_netbios_name(),
					hostname, NULL, 
					sharename, "?????", 
					username, username[0]?userdomain:"",
					password, flags, &retry);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open connection - %s\n", nt_errstr(status));
		return False;
	}

	(*c)->transport->options.use_oplocks = use_oplocks;
	(*c)->transport->options.use_level2_oplocks = use_level_II_oplocks;
	(*c)->transport->socket->timeout = 120000;

	return True;
}

BOOL torture_open_connection(struct smbcli_state **c)
{
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");

	return torture_open_connection_share(c, host, share);
}



BOOL torture_close_connection(struct smbcli_state *c)
{
	BOOL ret = True;
	if (!c) return True;
	if (NT_STATUS_IS_ERR(smbcli_tdis(c))) {
		printf("tdis failed (%s)\n", smbcli_errstr(c->tree));
		ret = False;
	}
	smbcli_shutdown(c);
	return ret;
}


/* open a rpc connection to the chosen binding string */
NTSTATUS torture_rpc_connection(struct dcerpc_pipe **p, 
				const char *pipe_name,
				const char *pipe_uuid, 
				uint32_t pipe_version)
{
        NTSTATUS status;
	const char *binding = lp_parm_string(-1, "torture", "binding");

	if (!binding) {
		printf("You must specify a ncacn binding string\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dcerpc_pipe_connect(p, binding, pipe_uuid, pipe_version,
				     lp_parm_string(-1, "torture", "userdomain"), 
				     lp_parm_string(-1, "torture", "username"),
				     lp_parm_string(-1, "torture", "password"));
 
        return status;
}

/* open a rpc connection to a specific transport */
NTSTATUS torture_rpc_connection_transport(struct dcerpc_pipe **p, 
					  const char *pipe_name,
					  const char *pipe_uuid, 
					  uint32_t pipe_version,
					  enum dcerpc_transport_t transport)
{
        NTSTATUS status;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	struct dcerpc_binding b;
	TALLOC_CTX *mem_ctx = talloc_init("torture_rpc_connection_smb");

	if (!binding) {
		printf("You must specify a ncacn binding string\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to parse dcerpc binding '%s'\n", binding));
		talloc_destroy(mem_ctx);
		return status;
	}

	b.transport = transport;

	status = dcerpc_pipe_connect_b(p, &b, pipe_uuid, pipe_version,
				       lp_parm_string(-1, "torture", "userdomain"), 
				       lp_parm_string(-1, "torture", "username"),
				       lp_parm_string(-1, "torture", "password"));
 
        return status;
}

/* close a rpc connection to a named pipe */
NTSTATUS torture_rpc_close(struct dcerpc_pipe *p)
{
	dcerpc_pipe_close(p);
	return NT_STATUS_OK;
}


/* check if the server produced the expected error code */
static BOOL check_error(int line, struct smbcli_state *c, 
			uint8_t eclass, uint32_t ecode, NTSTATUS nterr)
{
        if (smbcli_is_dos_error(c->tree)) {
                uint8_t class;
                uint32_t num;

                /* Check DOS error */

                smbcli_dos_error(c, &class, &num);

                if (eclass != class || ecode != num) {
                        printf("unexpected error code class=%d code=%d\n", 
                               (int)class, (int)num);
                        printf(" expected %d/%d %s (line=%d)\n", 
                               (int)eclass, (int)ecode, nt_errstr(nterr), line);
                        return False;
                }

        } else {
                NTSTATUS status;

                /* Check NT error */

                status = smbcli_nt_error(c->tree);

                if (NT_STATUS_V(nterr) != NT_STATUS_V(status)) {
                        printf("unexpected error code %s\n", nt_errstr(status));
                        printf(" expected %s (line=%d)\n", nt_errstr(nterr), line);
                        return False;
                }
        }

	return True;
}


static BOOL wait_lock(struct smbcli_state *c, int fnum, uint32_t offset, uint32_t len)
{
	while (NT_STATUS_IS_ERR(smbcli_lock(c->tree, fnum, offset, len, -1, WRITE_LOCK))) {
		if (!check_error(__LINE__, c, ERRDOS, ERRlock, NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}
	return True;
}


static BOOL rw_torture(struct smbcli_state *c)
{
	const char *lockfname = "\\torture.lck";
	char *fname;
	int fnum;
	int fnum2;
	pid_t pid2, pid = getpid();
	int i, j;
	char buf[1024];
	BOOL correct = True;

	fnum2 = smbcli_open(c->tree, lockfname, O_RDWR | O_CREAT | O_EXCL, 
			 DENY_NONE);
	if (fnum2 == -1)
		fnum2 = smbcli_open(c->tree, lockfname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open of %s failed (%s)\n", lockfname, smbcli_errstr(c->tree));
		return False;
	}


	for (i=0;i<torture_numops;i++) {
		uint_t n = (uint_t)sys_random()%10;
		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}
		asprintf(&fname, "\\torture.%u", n);

		if (!wait_lock(c, fnum2, n*sizeof(int), sizeof(int))) {
			return False;
		}

		fnum = smbcli_open(c->tree, fname, O_RDWR | O_CREAT | O_TRUNC, DENY_ALL);
		if (fnum == -1) {
			printf("open failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
			break;
		}

		if (smbcli_write(c->tree, fnum, 0, (char *)&pid, 0, sizeof(pid)) != sizeof(pid)) {
			printf("write failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}

		for (j=0;j<50;j++) {
			if (smbcli_write(c->tree, fnum, 0, (char *)buf, 
				      sizeof(pid)+(j*sizeof(buf)), 
				      sizeof(buf)) != sizeof(buf)) {
				printf("write failed (%s)\n", smbcli_errstr(c->tree));
				correct = False;
			}
		}

		pid2 = 0;

		if (smbcli_read(c->tree, fnum, (char *)&pid2, 0, sizeof(pid)) != sizeof(pid)) {
			printf("read failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}

		if (pid2 != pid) {
			printf("data corruption!\n");
			correct = False;
		}

		if (NT_STATUS_IS_ERR(smbcli_close(c->tree, fnum))) {
			printf("close failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}

		if (NT_STATUS_IS_ERR(smbcli_unlink(c->tree, fname))) {
			printf("unlink failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}

		if (NT_STATUS_IS_ERR(smbcli_unlock(c->tree, fnum2, n*sizeof(int), sizeof(int)))) {
			printf("unlock failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}
		free(fname);
	}

	smbcli_close(c->tree, fnum2);
	smbcli_unlink(c->tree, lockfname);

	printf("%d\n", i);

	return correct;
}

static BOOL run_torture(struct smbcli_state *cli, int dummy)
{
        BOOL ret;

	ret = rw_torture(cli);
	
	if (!torture_close_connection(cli)) {
		ret = False;
	}

	return ret;
}

static BOOL rw_torture3(struct smbcli_state *c, const char *lockfname)
{
	int fnum = -1;
	uint_t i = 0;
	char buf[131072];
	char buf_rd[131072];
	uint_t count;
	uint_t countprev = 0;
	ssize_t sent = 0;
	BOOL correct = True;

	srandom(1);
	for (i = 0; i < sizeof(buf); i += sizeof(uint32_t))
	{
		SIVAL(buf, i, sys_random());
	}

	if (procnum == 0)
	{
		fnum = smbcli_open(c->tree, lockfname, O_RDWR | O_CREAT | O_EXCL, 
				DENY_NONE);
		if (fnum == -1) {
			printf("first open read/write of %s failed (%s)\n",
					lockfname, smbcli_errstr(c->tree));
			return False;
		}
	}
	else
	{
		for (i = 0; i < 500 && fnum == -1; i++)
		{
			fnum = smbcli_open(c->tree, lockfname, O_RDONLY, 
					DENY_NONE);
			msleep(10);
		}
		if (fnum == -1) {
			printf("second open read-only of %s failed (%s)\n",
					lockfname, smbcli_errstr(c->tree));
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
			sent = ((uint_t)sys_random()%(20))+ 1;
			if (sent > sizeof(buf) - count)
			{
				sent = sizeof(buf) - count;
			}

			if (smbcli_write(c->tree, fnum, 0, buf+count, count, (size_t)sent) != sent) {
				printf("write failed (%s)\n", smbcli_errstr(c->tree));
				correct = False;
			}
		}
		else
		{
			sent = smbcli_read(c->tree, fnum, buf_rd+count, count,
					sizeof(buf)-count);
			if (sent < 0)
			{
				printf("read failed offset:%d size:%d (%s)\n",
						count, sizeof(buf)-count,
						smbcli_errstr(c->tree));
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

	if (NT_STATUS_IS_ERR(smbcli_close(c->tree, fnum))) {
		printf("close failed (%s)\n", smbcli_errstr(c->tree));
		correct = False;
	}

	return correct;
}

static BOOL rw_torture2(struct smbcli_state *c1, struct smbcli_state *c2)
{
	const char *lockfname = "\\torture2.lck";
	int fnum1;
	int fnum2;
	int i;
	uint8_t buf[131072];
	uint8_t buf_rd[131072];
	BOOL correct = True;
	ssize_t bytes_read, bytes_written;

	if (smbcli_deltree(c1->tree, lockfname) == -1) {
		printf("unlink failed (%s)\n", smbcli_errstr(c1->tree));
	}

	fnum1 = smbcli_open(c1->tree, lockfname, O_RDWR | O_CREAT | O_EXCL, 
			 DENY_NONE);
	if (fnum1 == -1) {
		printf("first open read/write of %s failed (%s)\n",
				lockfname, smbcli_errstr(c1->tree));
		return False;
	}
	fnum2 = smbcli_open(c2->tree, lockfname, O_RDONLY, 
			 DENY_NONE);
	if (fnum2 == -1) {
		printf("second open read-only of %s failed (%s)\n",
				lockfname, smbcli_errstr(c2->tree));
		smbcli_close(c1->tree, fnum1);
		return False;
	}

	printf("Checking data integrity over %d ops\n", torture_numops);

	for (i=0;i<torture_numops;i++)
	{
		size_t buf_size = ((uint_t)sys_random()%(sizeof(buf)-1))+ 1;
		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}

		generate_random_buffer(buf, buf_size);

		if ((bytes_written = smbcli_write(c1->tree, fnum1, 0, buf, 0, buf_size)) != buf_size) {
			printf("write failed (%s)\n", smbcli_errstr(c1->tree));
			printf("wrote %d, expected %d\n", bytes_written, buf_size); 
			correct = False;
			break;
		}

		if ((bytes_read = smbcli_read(c2->tree, fnum2, buf_rd, 0, buf_size)) != buf_size) {
			printf("read failed (%s)\n", smbcli_errstr(c2->tree));
			printf("read %d, expected %d\n", bytes_read, buf_size); 
			correct = False;
			break;
		}

		if (memcmp(buf_rd, buf, buf_size) != 0)
		{
			printf("read/write compare failed\n");
			correct = False;
			break;
		}
	}

	if (NT_STATUS_IS_ERR(smbcli_close(c2->tree, fnum2))) {
		printf("close failed (%s)\n", smbcli_errstr(c2->tree));
		correct = False;
	}
	if (NT_STATUS_IS_ERR(smbcli_close(c1->tree, fnum1))) {
		printf("close failed (%s)\n", smbcli_errstr(c1->tree));
		correct = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_unlink(c1->tree, lockfname))) {
		printf("unlink failed (%s)\n", smbcli_errstr(c1->tree));
		correct = False;
	}

	return correct;
}

static BOOL run_readwritetest(int dummy)
{
	struct smbcli_state *cli1, *cli2;
	BOOL test1, test2 = True;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}

	printf("starting readwritetest\n");

	test1 = rw_torture2(cli1, cli2);
	printf("Passed readwritetest v1: %s\n", BOOLSTR(test1));

	if (test1) {
		test2 = rw_torture2(cli1, cli1);
		printf("Passed readwritetest v2: %s\n", BOOLSTR(test2));
	}

	if (!torture_close_connection(cli1)) {
		test1 = False;
	}

	if (!torture_close_connection(cli2)) {
		test2 = False;
	}

	return (test1 && test2);
}

static BOOL run_readwritemulti(struct smbcli_state *cli, int dummy)
{
	BOOL test;

	test = rw_torture3(cli, "\\multitest.txt");

	if (!torture_close_connection(cli)) {
		test = False;
	}
	
	return test;
}


/*
  This test checks for two things:

  1) correct support for retaining locks over a close (ie. the server
     must not use posix semantics)
  2) support for lock timeouts
 */
static BOOL run_locktest1(int dummy)
{
	struct smbcli_state *cli1, *cli2;
	const char *fname = "\\lockt1.lck";
	int fnum1, fnum2, fnum3;
	time_t t1, t2;
	uint_t lock_timeout;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}

	printf("starting locktest1\n");

	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}
	fnum2 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open2 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}
	fnum3 = smbcli_open(cli2->tree, fname, O_RDWR, DENY_NONE);
	if (fnum3 == -1) {
		printf("open3 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_lock(cli1->tree, fnum1, 0, 4, 0, WRITE_LOCK))) {
		printf("lock1 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}


	if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum3, 0, 4, 0, WRITE_LOCK))) {
		printf("lock2 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__LINE__, cli2, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}


	lock_timeout = (6 + (random() % 20));
	printf("Testing lock timeout with timeout=%u\n", lock_timeout);
	t1 = time(NULL);
	if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum3, 0, 4, lock_timeout * 1000, WRITE_LOCK))) {
		printf("lock3 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__LINE__, cli2, ERRDOS, ERRlock, 
				 NT_STATUS_FILE_LOCK_CONFLICT)) return False;
	}
	t2 = time(NULL);

	if (t2 - t1 < 5) {
		printf("error: This server appears not to support timed lock requests\n");
	}
	printf("server slept for %u seconds for a %u second timeout\n",
	       (uint_t)(t2-t1), lock_timeout);

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum2))) {
		printf("close1 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum3, 0, 4, 0, WRITE_LOCK))) {
		printf("lock4 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__LINE__, cli2, ERRDOS, ERRlock, 
				 NT_STATUS_FILE_LOCK_CONFLICT)) return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("close2 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli2->tree, fnum3))) {
		printf("close3 failed (%s)\n", smbcli_errstr(cli2->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_unlink(cli1->tree, fname))) {
		printf("unlink failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}


	if (!torture_close_connection(cli1)) {
		return False;
	}

	if (!torture_close_connection(cli2)) {
		return False;
	}

	printf("Passed locktest1\n");
	return True;
}

/*
  this checks to see if a secondary tconx can use open files from an
  earlier tconx
 */
static BOOL run_tcon_test(int dummy)
{
	struct smbcli_state *cli;
	const char *fname = "\\tcontest.tmp";
	int fnum1;
	uint16_t cnum1, cnum2, cnum3;
	uint16_t vuid1, vuid2;
	char buf[4];
	BOOL ret = True;
	struct smbcli_tree *tree1;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");
	const char *password = lp_parm_string(-1, "torture", "password");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	printf("starting tcontest\n");

	if (smbcli_deltree(cli->tree, fname) == -1) {
		printf("unlink of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
	}

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		return False;
	}

	cnum1 = cli->tree->tid;
	vuid1 = cli->session->vuid;

	memset(&buf, 0, 4); /* init buf so valgrind won't complain */
	if (smbcli_write(cli->tree, fnum1, 0, buf, 130, 4) != 4) {
		printf("initial write failed (%s)\n", smbcli_errstr(cli->tree));
		return False;
	}

	tree1 = cli->tree;	/* save old tree connection */
	if (NT_STATUS_IS_ERR(smbcli_send_tconX(cli, share, "?????", password))) {
		printf("%s refused 2nd tree connect (%s)\n", host,
		           smbcli_errstr(cli->tree));
		smbcli_shutdown(cli);
		return False;
	}

	cnum2 = cli->tree->tid;
	cnum3 = MAX(cnum1, cnum2) + 1; /* any invalid number */
	vuid2 = cli->session->vuid + 1;

	/* try a write with the wrong tid */
	cli->tree->tid = cnum2;

	if (smbcli_write(cli->tree, fnum1, 0, buf, 130, 4) == 4) {
		printf("* server allows write with wrong TID\n");
		ret = False;
	} else {
		printf("server fails write with wrong TID : %s\n", smbcli_errstr(cli->tree));
	}


	/* try a write with an invalid tid */
	cli->tree->tid = cnum3;

	if (smbcli_write(cli->tree, fnum1, 0, buf, 130, 4) == 4) {
		printf("* server allows write with invalid TID\n");
		ret = False;
	} else {
		printf("server fails write with invalid TID : %s\n", smbcli_errstr(cli->tree));
	}

	/* try a write with an invalid vuid */
	cli->session->vuid = vuid2;
	cli->tree->tid = cnum1;

	if (smbcli_write(cli->tree, fnum1, 0, buf, 130, 4) == 4) {
		printf("* server allows write with invalid VUID\n");
		ret = False;
	} else {
		printf("server fails write with invalid VUID : %s\n", smbcli_errstr(cli->tree));
	}

	cli->session->vuid = vuid1;
	cli->tree->tid = cnum1;

	if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnum1))) {
		printf("close failed (%s)\n", smbcli_errstr(cli->tree));
		return False;
	}

	cli->tree->tid = cnum2;

	if (NT_STATUS_IS_ERR(smbcli_tdis(cli))) {
		printf("secondary tdis failed (%s)\n", smbcli_errstr(cli->tree));
		return False;
	}

	cli->tree = tree1;  /* restore initial tree */
	cli->tree->tid = cnum1;

	if (!torture_close_connection(cli)) {
		return False;
	}

	return ret;
}



static BOOL tcon_devtest(struct smbcli_state *cli,
			 const char *myshare, const char *devtype,
			 NTSTATUS expected_error)
{
	BOOL status;
	BOOL ret;
	const char *password = lp_parm_string(-1, "torture", "password");

	status = NT_STATUS_IS_OK(smbcli_send_tconX(cli, myshare, devtype, 
						password));

	printf("Trying share %s with devtype %s\n", myshare, devtype);

	if (NT_STATUS_IS_OK(expected_error)) {
		if (status) {
			ret = True;
		} else {
			printf("tconX to share %s with type %s "
			       "should have succeeded but failed\n",
			       myshare, devtype);
			ret = False;
		}
		smbcli_tdis(cli);
	} else {
		if (status) {
			printf("tconx to share %s with type %s "
			       "should have failed but succeeded\n",
			       myshare, devtype);
			ret = False;
		} else {
			if (NT_STATUS_EQUAL(smbcli_nt_error(cli->tree),
					    expected_error)) {
				ret = True;
			} else {
				printf("Returned unexpected error\n");
				ret = False;
			}
		}
	}
	return ret;
}

/*
 checks for correct tconX support
 */
static BOOL run_tcon_devtype_test(int dummy)
{
	struct smbcli_state *cli1 = NULL;
	BOOL retry;
	int flags = 0;
	NTSTATUS status;
	BOOL ret = True;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");
	const char *username = lp_parm_string(-1, "torture", "username");
	const char *userdomain = lp_parm_string(-1, "torture", "userdomain");
	const char *password = lp_parm_string(-1, "torture", "password");
	
	status = smbcli_full_connection(NULL,
					&cli1, lp_netbios_name(),
					host, NULL, 
					share, "?????",
					username, userdomain,
					password, flags, &retry);

	if (!NT_STATUS_IS_OK(status)) {
		printf("could not open connection\n");
		return False;
	}

	if (!tcon_devtest(cli1, "IPC$", "A:", NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	if (!tcon_devtest(cli1, "IPC$", "?????", NT_STATUS_OK))
		ret = False;

	if (!tcon_devtest(cli1, "IPC$", "LPT:", NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	if (!tcon_devtest(cli1, "IPC$", "IPC", NT_STATUS_OK))
		ret = False;
			
	if (!tcon_devtest(cli1, "IPC$", "FOOBA", NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	if (!tcon_devtest(cli1, share, "A:", NT_STATUS_OK))
		ret = False;

	if (!tcon_devtest(cli1, share, "?????", NT_STATUS_OK))
		ret = False;

	if (!tcon_devtest(cli1, share, "LPT:", NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	if (!tcon_devtest(cli1, share, "IPC", NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;
			
	if (!tcon_devtest(cli1, share, "FOOBA", NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	smbcli_shutdown(cli1);

	if (ret)
		printf("Passed tcondevtest\n");

	return ret;
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
	struct smbcli_state *cli;
	const char *fname = "\\lockt2.lck";
	int fnum1, fnum2, fnum3;
	BOOL correct = True;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	printf("starting locktest2\n");

	smbcli_unlink(cli->tree, fname);

	printf("Testing pid context\n");
	
	cli->session->pid = 1;

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		return False;
	}

	fnum2 = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open2 of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		return False;
	}

	cli->session->pid = 2;

	fnum3 = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	if (fnum3 == -1) {
		printf("open3 of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		return False;
	}

	cli->session->pid = 1;

	if (NT_STATUS_IS_ERR(smbcli_lock(cli->tree, fnum1, 0, 4, 0, WRITE_LOCK))) {
		printf("lock1 failed (%s)\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli->tree, fnum1, 0, 4, 0, WRITE_LOCK))) {
		printf("WRITE lock1 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, cli, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli->tree, fnum2, 0, 4, 0, WRITE_LOCK))) {
		printf("WRITE lock2 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, cli, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli->tree, fnum2, 0, 4, 0, READ_LOCK))) {
		printf("READ lock2 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, cli, ERRDOS, ERRlock, 
				 NT_STATUS_FILE_LOCK_CONFLICT)) return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_lock(cli->tree, fnum1, 100, 4, 0, WRITE_LOCK))) {
		printf("lock at 100 failed (%s)\n", smbcli_errstr(cli->tree));
	}

	cli->session->pid = 2;

	if (NT_STATUS_IS_OK(smbcli_unlock(cli->tree, fnum1, 100, 4))) {
		printf("unlock at 100 succeeded! This is a locking bug\n");
		correct = False;
	}

	if (NT_STATUS_IS_OK(smbcli_unlock(cli->tree, fnum1, 0, 4))) {
		printf("unlock1 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, cli, 
				 ERRDOS, ERRlock, 
				 NT_STATUS_RANGE_NOT_LOCKED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_unlock(cli->tree, fnum1, 0, 8))) {
		printf("unlock2 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, cli, 
				 ERRDOS, ERRlock, 
				 NT_STATUS_RANGE_NOT_LOCKED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli->tree, fnum3, 0, 4, 0, WRITE_LOCK))) {
		printf("lock3 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__LINE__, cli, ERRDOS, ERRlock, NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	cli->session->pid = 1;

	if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnum1))) {
		printf("close1 failed (%s)\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnum2))) {
		printf("close2 failed (%s)\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnum3))) {
		printf("close3 failed (%s)\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (!torture_close_connection(cli)) {
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
	struct smbcli_state *cli1, *cli2;
	const char *fname = "\\lockt3.lck";
	int fnum1, fnum2, i;
	uint32_t offset;
	BOOL correct = True;

#define NEXT_OFFSET offset += (~(uint32_t)0) / torture_numops

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}

	printf("starting locktest3\n");

	printf("Testing 32 bit offset ranges\n");

	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}
	fnum2 = smbcli_open(cli2->tree, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		return False;
	}

	printf("Establishing %d locks\n", torture_numops);

	for (offset=i=0;i<torture_numops;i++) {
		NEXT_OFFSET;
		if (NT_STATUS_IS_ERR(smbcli_lock(cli1->tree, fnum1, offset-1, 1, 0, WRITE_LOCK))) {
			printf("lock1 %d failed (%s)\n", 
			       i,
			       smbcli_errstr(cli1->tree));
			return False;
		}

		if (NT_STATUS_IS_ERR(smbcli_lock(cli2->tree, fnum2, offset-2, 1, 0, WRITE_LOCK))) {
			printf("lock2 %d failed (%s)\n", 
			       i,
			       smbcli_errstr(cli1->tree));
			return False;
		}
	}

	printf("Testing %d locks\n", torture_numops);

	for (offset=i=0;i<torture_numops;i++) {
		NEXT_OFFSET;

		if (NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, offset-2, 1, 0, WRITE_LOCK))) {
			printf("error: lock1 %d succeeded!\n", i);
			return False;
		}

		if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum2, offset-1, 1, 0, WRITE_LOCK))) {
			printf("error: lock2 %d succeeded!\n", i);
			return False;
		}

		if (NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, offset-1, 1, 0, WRITE_LOCK))) {
			printf("error: lock3 %d succeeded!\n", i);
			return False;
		}

		if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum2, offset-2, 1, 0, WRITE_LOCK))) {
			printf("error: lock4 %d succeeded!\n", i);
			return False;
		}
	}

	printf("Removing %d locks\n", torture_numops);

	for (offset=i=0;i<torture_numops;i++) {
		NEXT_OFFSET;

		if (NT_STATUS_IS_ERR(smbcli_unlock(cli1->tree, fnum1, offset-1, 1))) {
			printf("unlock1 %d failed (%s)\n", 
			       i,
			       smbcli_errstr(cli1->tree));
			return False;
		}

		if (NT_STATUS_IS_ERR(smbcli_unlock(cli2->tree, fnum2, offset-2, 1))) {
			printf("unlock2 %d failed (%s)\n", 
			       i,
			       smbcli_errstr(cli1->tree));
			return False;
		}
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("close1 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli2->tree, fnum2))) {
		printf("close2 failed (%s)\n", smbcli_errstr(cli2->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_unlink(cli1->tree, fname))) {
		printf("unlink failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	
	if (!torture_close_connection(cli2)) {
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
	struct smbcli_state *cli1, *cli2;
	const char *fname = "\\lockt4.lck";
	int fnum1, fnum2, f;
	BOOL ret;
	char buf[1000];
	BOOL correct = True;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}

	printf("starting locktest4\n");

	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	fnum2 = smbcli_open(cli2->tree, fname, O_RDWR, DENY_NONE);

	memset(buf, 0, sizeof(buf));

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 0, sizeof(buf)) != sizeof(buf)) {
		printf("Failed to create file\n");
		correct = False;
		goto fail;
	}

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 0, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 2, 4, 0, WRITE_LOCK));
	EXPECTED(ret, False);
	printf("the same process %s set overlapping write locks\n", ret?"can":"cannot");
	    
	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 10, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 12, 4, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("the same process %s set overlapping read locks\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 20, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum2, 22, 4, 0, WRITE_LOCK));
	EXPECTED(ret, False);
	printf("a different connection %s set overlapping write locks\n", ret?"can":"cannot");
	    
	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 30, 4, 0, READ_LOCK)) &&
		NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum2, 32, 4, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("a different connection %s set overlapping read locks\n", ret?"can":"cannot");
	
	ret = NT_STATUS_IS_OK((cli1->session->pid = 1, smbcli_lock(cli1->tree, fnum1, 40, 4, 0, WRITE_LOCK))) &&
	      NT_STATUS_IS_OK((cli1->session->pid = 2, smbcli_lock(cli1->tree, fnum1, 42, 4, 0, WRITE_LOCK)));
	EXPECTED(ret, False);
	printf("a different pid %s set overlapping write locks\n", ret?"can":"cannot");
	    
	ret = NT_STATUS_IS_OK((cli1->session->pid = 1, smbcli_lock(cli1->tree, fnum1, 50, 4, 0, READ_LOCK))) &&
	      NT_STATUS_IS_OK((cli1->session->pid = 2, smbcli_lock(cli1->tree, fnum1, 52, 4, 0, READ_LOCK)));
	EXPECTED(ret, True);
	printf("a different pid %s set overlapping read locks\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 60, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 60, 4, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("the same process %s set the same read lock twice\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 70, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 70, 4, 0, WRITE_LOCK));
	EXPECTED(ret, False);
	printf("the same process %s set the same write lock twice\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 80, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 80, 4, 0, WRITE_LOCK));
	EXPECTED(ret, False);
	printf("the same process %s overlay a read lock with a write lock\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 90, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 90, 4, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("the same process %s overlay a write lock with a read lock\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK((cli1->session->pid = 1, smbcli_lock(cli1->tree, fnum1, 100, 4, 0, WRITE_LOCK))) &&
	      NT_STATUS_IS_OK((cli1->session->pid = 2, smbcli_lock(cli1->tree, fnum1, 100, 4, 0, READ_LOCK)));
	EXPECTED(ret, False);
	printf("a different pid %s overlay a write lock with a read lock\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 110, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 112, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 110, 6));
	EXPECTED(ret, False);
	printf("the same process %s coalesce read locks\n", ret?"can":"cannot");


	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 120, 4, 0, WRITE_LOCK)) &&
	      (smbcli_read(cli2->tree, fnum2, buf, 120, 4) == 4);
	EXPECTED(ret, False);
	printf("this server %s strict write locking\n", ret?"doesn't do":"does");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 130, 4, 0, READ_LOCK)) &&
	      (smbcli_write(cli2->tree, fnum2, 0, buf, 130, 4) == 4);
	EXPECTED(ret, False);
	printf("this server %s strict read locking\n", ret?"doesn't do":"does");


	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 140, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 140, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 140, 4)) &&
	      NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 140, 4));
	EXPECTED(ret, True);
	printf("this server %s do recursive read locking\n", ret?"does":"doesn't");


	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 150, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 150, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 150, 4)) &&
	      (smbcli_read(cli2->tree, fnum2, buf, 150, 4) == 4) &&
	      !(smbcli_write(cli2->tree, fnum2, 0, buf, 150, 4) == 4) &&
	      NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 150, 4));
	EXPECTED(ret, True);
	printf("this server %s do recursive lock overlays\n", ret?"does":"doesn't");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 160, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 160, 4)) &&
	      (smbcli_write(cli2->tree, fnum2, 0, buf, 160, 4) == 4) &&		
	      (smbcli_read(cli2->tree, fnum2, buf, 160, 4) == 4);		
	EXPECTED(ret, True);
	printf("the same process %s remove a read lock using write locking\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 170, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 170, 4)) &&
	      (smbcli_write(cli2->tree, fnum2, 0, buf, 170, 4) == 4) &&		
	      (smbcli_read(cli2->tree, fnum2, buf, 170, 4) == 4);		
	EXPECTED(ret, True);
	printf("the same process %s remove a write lock using read locking\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 190, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 190, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 190, 4)) &&
	      !(smbcli_write(cli2->tree, fnum2, 0, buf, 190, 4) == 4) &&		
	      (smbcli_read(cli2->tree, fnum2, buf, 190, 4) == 4);		
	EXPECTED(ret, True);
	printf("the same process %s remove the first lock first\n", ret?"does":"doesn't");

	smbcli_close(cli1->tree, fnum1);
	smbcli_close(cli2->tree, fnum2);
	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_NONE);
	f = smbcli_open(cli1->tree, fname, O_RDWR, DENY_NONE);
	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 0, 8, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, f, 0, 1, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_close(cli1->tree, fnum1)) &&
	      ((fnum1 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_NONE)) != -1) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 7, 1, 0, WRITE_LOCK));
        smbcli_close(cli1->tree, f);
	smbcli_close(cli1->tree, fnum1);
	EXPECTED(ret, True);
	printf("the server %s have the NT byte range lock bug\n", !ret?"does":"doesn't");

 fail:
	smbcli_close(cli1->tree, fnum1);
	smbcli_close(cli2->tree, fnum2);
	smbcli_unlink(cli1->tree, fname);
	torture_close_connection(cli1);
	torture_close_connection(cli2);

	printf("finished locktest4\n");
	return correct;
}

/*
  looks at lock upgrade/downgrade.
*/
static BOOL run_locktest5(int dummy)
{
	struct smbcli_state *cli1, *cli2;
	const char *fname = "\\lockt5.lck";
	int fnum1, fnum2, fnum3;
	BOOL ret;
	char buf[1000];
	BOOL correct = True;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}

	printf("starting locktest5\n");

	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	fnum2 = smbcli_open(cli2->tree, fname, O_RDWR, DENY_NONE);
	fnum3 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_NONE);

	memset(buf, 0, sizeof(buf));

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 0, sizeof(buf)) != sizeof(buf)) {
		printf("Failed to create file\n");
		correct = False;
		goto fail;
	}

	/* Check for NT bug... */
	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 0, 8, 0, READ_LOCK)) &&
		  NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum3, 0, 1, 0, READ_LOCK));
	smbcli_close(cli1->tree, fnum1);
	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_NONE);
	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 7, 1, 0, WRITE_LOCK));
	EXPECTED(ret, True);
	printf("this server %s the NT locking bug\n", ret ? "doesn't have" : "has");
	smbcli_close(cli1->tree, fnum1);
	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_NONE);
	smbcli_unlock(cli1->tree, fnum3, 0, 1);

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 0, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 1, 1, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("the same process %s overlay a write with a read lock\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum2, 0, 4, 0, READ_LOCK));
	EXPECTED(ret, False);

	printf("a different processs %s get a read lock on the first process lock stack\n", ret?"can":"cannot");

	/* Unlock the process 2 lock. */
	smbcli_unlock(cli2->tree, fnum2, 0, 4);

	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum3, 0, 4, 0, READ_LOCK));
	EXPECTED(ret, False);

	printf("the same processs on a different fnum %s get a read lock\n", ret?"can":"cannot");

	/* Unlock the process 1 fnum3 lock. */
	smbcli_unlock(cli1->tree, fnum3, 0, 4);

	/* Stack 2 more locks here. */
	ret = NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 0, 4, 0, READ_LOCK)) &&
		  NT_STATUS_IS_OK(smbcli_lock(cli1->tree, fnum1, 0, 4, 0, READ_LOCK));

	EXPECTED(ret, True);
	printf("the same process %s stack read locks\n", ret?"can":"cannot");

	/* Unlock the first process lock, then check this was the WRITE lock that was
		removed. */

ret = NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 0, 4)) &&
	NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum2, 0, 4, 0, READ_LOCK));

	EXPECTED(ret, True);
	printf("the first unlock removes the %s lock\n", ret?"WRITE":"READ");

	/* Unlock the process 2 lock. */
	smbcli_unlock(cli2->tree, fnum2, 0, 4);

	/* We should have 3 stacked locks here. Ensure we need to do 3 unlocks. */

	ret = NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 1, 1)) &&
		  NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 0, 4)) &&
		  NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 0, 4));

	EXPECTED(ret, True);
	printf("the same process %s unlock the stack of 4 locks\n", ret?"can":"cannot"); 

	/* Ensure the next unlock fails. */
	ret = NT_STATUS_IS_OK(smbcli_unlock(cli1->tree, fnum1, 0, 4));
	EXPECTED(ret, False);
	printf("the same process %s count the lock stack\n", !ret?"can":"cannot"); 

	/* Ensure connection 2 can get a write lock. */
	ret = NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum2, 0, 4, 0, WRITE_LOCK));
	EXPECTED(ret, True);

	printf("a different processs %s get a write lock on the unlocked stack\n", ret?"can":"cannot");


 fail:
	smbcli_close(cli1->tree, fnum1);
	smbcli_close(cli2->tree, fnum2);
	smbcli_unlink(cli1->tree, fname);
	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	if (!torture_close_connection(cli2)) {
		correct = False;
	}

	printf("finished locktest5\n");
       
	return correct;
}

/*
  tries the unusual lockingX locktype bits
*/
static BOOL run_locktest6(int dummy)
{
	struct smbcli_state *cli;
	const char *fname[1] = { "\\lock6.txt" };
	int i;
	int fnum;
	NTSTATUS status;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	printf("starting locktest6\n");

	for (i=0;i<1;i++) {
		printf("Testing %s\n", fname[i]);

		smbcli_unlink(cli->tree, fname[i]);

		fnum = smbcli_open(cli->tree, fname[i], O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
		status = smbcli_locktype(cli->tree, fnum, 0, 8, 0, LOCKING_ANDX_CHANGE_LOCKTYPE);
		smbcli_close(cli->tree, fnum);
		printf("CHANGE_LOCKTYPE gave %s\n", nt_errstr(status));

		fnum = smbcli_open(cli->tree, fname[i], O_RDWR, DENY_NONE);
		status = smbcli_locktype(cli->tree, fnum, 0, 8, 0, LOCKING_ANDX_CANCEL_LOCK);
		smbcli_close(cli->tree, fnum);
		printf("CANCEL_LOCK gave %s\n", nt_errstr(status));

		smbcli_unlink(cli->tree, fname[i]);
	}

	torture_close_connection(cli);

	printf("finished locktest6\n");
	return True;
}

static BOOL run_locktest7(int dummy)
{
	struct smbcli_state *cli1;
	const char *fname = "\\lockt7.lck";
	int fnum1;
	int fnum2;
	size_t size;
	char buf[200];
	BOOL correct = False;

	if (!torture_open_connection(&cli1)) {
		return False;
	}

	printf("starting locktest7\n");

	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);

	memset(buf, 0, sizeof(buf));

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 0, sizeof(buf)) != sizeof(buf)) {
		printf("Failed to create file\n");
		goto fail;
	}

	cli1->session->pid = 1;

	if (NT_STATUS_IS_ERR(smbcli_lock(cli1->tree, fnum1, 130, 4, 0, READ_LOCK))) {
		printf("Unable to apply read lock on range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		goto fail;
	} else {
		printf("pid1 successfully locked range 130:4 for READ\n");
	}

	if (smbcli_read(cli1->tree, fnum1, buf, 130, 4) != 4) {
		printf("pid1 unable to read the range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		goto fail;
	} else {
		printf("pid1 successfully read the range 130:4\n");
	}

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 130, 4) != 4) {
		printf("pid1 unable to write to the range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		if (NT_STATUS_V(smbcli_nt_error(cli1->tree)) != NT_STATUS_V(NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT)\n");
			goto fail;
		}
	} else {
		printf("pid1 successfully wrote to the range 130:4 (should be denied)\n");
		goto fail;
	}

	cli1->session->pid = 2;

	if (smbcli_read(cli1->tree, fnum1, buf, 130, 4) != 4) {
		printf("pid2 unable to read the range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
	} else {
		printf("pid2 successfully read the range 130:4\n");
	}

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 130, 4) != 4) {
		printf("pid2 unable to write to the range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		if (NT_STATUS_V(smbcli_nt_error(cli1->tree)) != NT_STATUS_V(NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT)\n");
			goto fail;
		}
	} else {
		printf("pid2 successfully wrote to the range 130:4 (should be denied)\n");
		goto fail;
	}

	cli1->session->pid = 1;
	smbcli_unlock(cli1->tree, fnum1, 130, 4);

	if (NT_STATUS_IS_ERR(smbcli_lock(cli1->tree, fnum1, 130, 4, 0, WRITE_LOCK))) {
		printf("Unable to apply write lock on range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		goto fail;
	} else {
		printf("pid1 successfully locked range 130:4 for WRITE\n");
	}

	if (smbcli_read(cli1->tree, fnum1, buf, 130, 4) != 4) {
		printf("pid1 unable to read the range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		goto fail;
	} else {
		printf("pid1 successfully read the range 130:4\n");
	}

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 130, 4) != 4) {
		printf("pid1 unable to write to the range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		goto fail;
	} else {
		printf("pid1 successfully wrote to the range 130:4\n");
	}

	cli1->session->pid = 2;

	if (smbcli_read(cli1->tree, fnum1, buf, 130, 4) != 4) {
		printf("pid2 unable to read the range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		if (NT_STATUS_V(smbcli_nt_error(cli1->tree)) != NT_STATUS_V(NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT)\n");
			goto fail;
		}
	} else {
		printf("pid2 successfully read the range 130:4 (should be denied)\n");
		goto fail;
	}

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 130, 4) != 4) {
		printf("pid2 unable to write to the range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		if (NT_STATUS_V(smbcli_nt_error(cli1->tree)) != NT_STATUS_V(NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT)\n");
			goto fail;
		}
	} else {
		printf("pid2 successfully wrote to the range 130:4 (should be denied)\n");
		goto fail;
	}

	printf("Testing truncate of locked file.\n");

	fnum2 = smbcli_open(cli1->tree, fname, O_RDWR|O_TRUNC, DENY_NONE);

	if (fnum2 == -1) {
		printf("Unable to truncate locked file.\n");
		correct = False;
		goto fail;
	} else {
		printf("Truncated locked file.\n");
	}

	if (NT_STATUS_IS_ERR(smbcli_getatr(cli1->tree, fname, NULL, &size, NULL))) {
		printf("getatr failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (size != 0) {
		printf("Unable to truncate locked file. Size was %u\n", size);
		correct = False;
		goto fail;
	}

	cli1->session->pid = 1;

	smbcli_unlock(cli1->tree, fnum1, 130, 4);
	correct = True;

fail:
	smbcli_close(cli1->tree, fnum1);
	smbcli_close(cli1->tree, fnum2);
	smbcli_unlink(cli1->tree, fname);
	torture_close_connection(cli1);

	printf("finished locktest7\n");
	return correct;
}

/*
test whether fnums and tids open on one VC are available on another (a major
security hole)
*/
static BOOL run_fdpasstest(int dummy)
{
	struct smbcli_state *cli1, *cli2;
	const char *fname = "\\fdpass.tst";
	int fnum1, oldtid;
	pstring buf;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}

	printf("starting fdpasstest\n");

	smbcli_unlink(cli1->tree, fname);

	printf("Opening a file on connection 1\n");

	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}

	printf("writing to file on connection 1\n");

	if (smbcli_write(cli1->tree, fnum1, 0, "hello world\n", 0, 13) != 13) {
		printf("write failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	oldtid = cli2->tree->tid;
	cli2->session->vuid = cli1->session->vuid;
	cli2->tree->tid = cli1->tree->tid;
	cli2->session->pid = cli1->session->pid;

	printf("reading from file on connection 2\n");

	if (smbcli_read(cli2->tree, fnum1, buf, 0, 13) == 13) {
		printf("read succeeded! nasty security hole [%s]\n",
		       buf);
		return False;
	}

	smbcli_close(cli1->tree, fnum1);
	smbcli_unlink(cli1->tree, fname);

	cli2->tree->tid = oldtid;

	torture_close_connection(cli1);
	torture_close_connection(cli2);

	printf("finished fdpasstest\n");
	return True;
}


/*
  This test checks that 

  1) the server does not allow an unlink on a file that is open
*/
static BOOL run_unlinktest(int dummy)
{
	struct smbcli_state *cli;
	const char *fname = "\\unlink.tst";
	int fnum;
	BOOL correct = True;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	printf("starting unlink test\n");

	smbcli_unlink(cli->tree, fname);

	cli->session->pid = 1;

	printf("Opening a file\n");

	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		return False;
	}

	printf("Unlinking a open file\n");

	if (NT_STATUS_IS_OK(smbcli_unlink(cli->tree, fname))) {
		printf("error: server allowed unlink on an open file\n");
		correct = False;
	} else {
		correct = check_error(__LINE__, cli, ERRDOS, ERRbadshare, 
				      NT_STATUS_SHARING_VIOLATION);
	}

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("unlink test finished\n");
	
	return correct;
}


/*
test the timing of deferred open requests
*/
static BOOL run_deferopen(struct smbcli_state *cli, int dummy)
{
	const char *fname = "\\defer_open_test.dat";
	int retries=4;
	int i = 0;
	BOOL correct = True;

	if (retries <= 0) {
		printf("failed to connect\n");
		return False;
	}

	printf("Testing deferred open requests.\n");

	while (i < 4) {
		int fnum = -1;

		do {
			struct timeval tv_start, tv_end;
			GetTimeOfDay(&tv_start);
			fnum = smbcli_nt_create_full(cli->tree, fname, 0, GENERIC_RIGHTS_FILE_ALL_ACCESS,
				FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_NONE,
				NTCREATEX_DISP_OPEN_IF, 0, 0);
			if (fnum != -1) {
				break;
			}
			GetTimeOfDay(&tv_end);
			if (NT_STATUS_EQUAL(smbcli_nt_error(cli->tree),NT_STATUS_SHARING_VIOLATION)) {
				/* Sharing violation errors need to be 1 second apart. */
				int64_t tdif = usec_time_diff(&tv_end, &tv_start);
				if (tdif < 500000 || tdif > 1500000) {
					fprintf(stderr,"Timing incorrect %lld.%lld for share violation\n",
						tdif / (int64_t)1000000, 
						tdif % (int64_t)1000000);
				}
			}
		} while (NT_STATUS_EQUAL(smbcli_nt_error(cli->tree),NT_STATUS_SHARING_VIOLATION));

		if (fnum == -1) {
			fprintf(stderr,"Failed to open %s, error=%s\n", fname, smbcli_errstr(cli->tree));
			return False;
		}

		printf("pid %u open %d\n", getpid(), i);

		sleep(10);
		i++;
		if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnum))) {
			fprintf(stderr,"Failed to close %s, error=%s\n", fname, smbcli_errstr(cli->tree));
			return False;
		}
		sleep(2);
	}

	if (NT_STATUS_IS_ERR(smbcli_unlink(cli->tree, fname))) {
		/* All until the last unlink will fail with sharing violation. */
		if (!NT_STATUS_EQUAL(smbcli_nt_error(cli->tree),NT_STATUS_SHARING_VIOLATION)) {
			printf("unlink of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
			correct = False;
		}
	}

	printf("deferred test finished\n");
	if (!torture_close_connection(cli)) {
		correct = False;
	}
	return correct;
}

/*
test how many open files this server supports on the one socket
*/
static BOOL run_maxfidtest(struct smbcli_state *cli, int dummy)
{
#define MAXFID_TEMPLATE "\\maxfid.%d.%d"
	char *fname;
	int fnums[0x11000], i;
	int retries=4;
	BOOL correct = True;

	if (retries <= 0) {
		printf("failed to connect\n");
		return False;
	}

	printf("Testing maximum number of open files\n");

	for (i=0; i<0x11000; i++) {
		asprintf(&fname, MAXFID_TEMPLATE, i,(int)getpid());
		if ((fnums[i] = smbcli_open(cli->tree, fname, 
					O_RDWR|O_CREAT|O_TRUNC, DENY_NONE)) ==
		    -1) {
			printf("open of %s failed (%s)\n", 
			       fname, smbcli_errstr(cli->tree));
			printf("maximum fnum is %d\n", i);
			break;
		}
		free(fname);
		printf("%6d\r", i);
	}
	printf("%6d\n", i);
	i--;

	printf("cleaning up\n");
	for (;i>=0;i--) {
		asprintf(&fname, MAXFID_TEMPLATE, i,(int)getpid());
		if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnums[i]))) {
			printf("Close of fnum %d failed - %s\n", fnums[i], smbcli_errstr(cli->tree));
		}
		if (NT_STATUS_IS_ERR(smbcli_unlink(cli->tree, fname))) {
			printf("unlink of %s failed (%s)\n", 
			       fname, smbcli_errstr(cli->tree));
			correct = False;
		}
		free(fname);
		printf("%6d\r", i);
	}
	printf("%6d\n", 0);

	printf("maxfid test finished\n");
	if (!torture_close_connection(cli)) {
		correct = False;
	}
	return correct;
#undef MAXFID_TEMPLATE
}

/* send smb negprot commands, not reading the response */
static BOOL run_negprot_nowait(int dummy)
{
	int i;
	struct smbcli_state *cli, *cli2;
	BOOL correct = True;

	printf("starting negprot nowait test\n");

	cli = open_nbt_connection();
	if (!cli) {
		return False;
	}

	printf("Filling send buffer\n");

	for (i=0;i<10000;i++) {
		struct smbcli_request *req;
		time_t t1 = time(NULL);
		req = smb_negprot_send(cli->transport, PROTOCOL_NT1);
		while (req->state == SMBCLI_REQUEST_SEND && time(NULL) < t1+5) {
			smbcli_transport_process(cli->transport);
		}
		if (req->state == SMBCLI_REQUEST_ERROR) {
			printf("Failed to fill pipe - %s\n", nt_errstr(req->status));
			torture_close_connection(cli);
			return correct;
		}
		if (req->state == SMBCLI_REQUEST_SEND) {
			break;
		}
	}

	if (i == 10000) {
		printf("send buffer failed to fill\n");
		if (!torture_close_connection(cli)) {
			correct = False;
		}
		return correct;
	}

	printf("send buffer filled after %d requests\n", i);

	printf("Opening secondary connection\n");
	if (!torture_open_connection(&cli2)) {
		return False;
	}

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	if (!torture_close_connection(cli2)) {
		correct = False;
	}

	printf("finished negprot nowait test\n");

	return correct;
}


/*
  This checks how the getatr calls works
*/
static BOOL run_attrtest(int dummy)
{
	struct smbcli_state *cli;
	int fnum;
	time_t t, t2;
	const char *fname = "\\attrib123456789.tst";
	BOOL correct = True;

	printf("starting attrib test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	smbcli_unlink(cli->tree, fname);
	fnum = smbcli_open(cli->tree, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	smbcli_close(cli->tree, fnum);

	if (NT_STATUS_IS_ERR(smbcli_getatr(cli->tree, fname, NULL, NULL, &t))) {
		printf("getatr failed (%s)\n", smbcli_errstr(cli->tree));
		correct = False;
	}

	printf("New file time is %s", ctime(&t));

	if (abs(t - time(NULL)) > 60*60*24*10) {
		printf("ERROR: SMBgetatr bug. time is %s",
		       ctime(&t));
		t = time(NULL);
		correct = False;
	}

	t2 = t-60*60*24; /* 1 day ago */

	printf("Setting file time to %s", ctime(&t2));

	if (NT_STATUS_IS_ERR(smbcli_setatr(cli->tree, fname, 0, t2))) {
		printf("setatr failed (%s)\n", smbcli_errstr(cli->tree));
		correct = True;
	}

	if (NT_STATUS_IS_ERR(smbcli_getatr(cli->tree, fname, NULL, NULL, &t))) {
		printf("getatr failed (%s)\n", smbcli_errstr(cli->tree));
		correct = True;
	}

	printf("Retrieved file time as %s", ctime(&t));

	if (t != t2) {
		printf("ERROR: getatr/setatr bug. times are\n%s",
		       ctime(&t));
		printf("%s", ctime(&t2));
		correct = True;
	}

	smbcli_unlink(cli->tree, fname);

	if (!torture_close_connection(cli)) {
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
	struct smbcli_state *cli;
	int fnum;
	size_t size;
	time_t c_time, a_time, m_time, w_time, m_time2;
	const char *fname = "\\trans2.tst";
	const char *dname = "\\trans2";
	const char *fname2 = "\\trans2\\trans2.tst";
	const char *pname;
	BOOL correct = True;

	printf("starting trans2 test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	smbcli_unlink(cli->tree, fname);

	printf("Testing qfileinfo\n");
	
	fnum = smbcli_open(cli->tree, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	if (NT_STATUS_IS_ERR(smbcli_qfileinfo(cli->tree, fnum, NULL, &size, &c_time, &a_time, &m_time,
			   NULL, NULL))) {
		printf("ERROR: qfileinfo failed (%s)\n", smbcli_errstr(cli->tree));
		correct = False;
	}

	printf("Testing NAME_INFO\n");

	if (NT_STATUS_IS_ERR(smbcli_qfilename(cli->tree, fnum, &pname))) {
		printf("ERROR: qfilename failed (%s)\n", smbcli_errstr(cli->tree));
		correct = False;
	}

	if (!pname || strcmp(pname, fname)) {
		printf("qfilename gave different name? [%s] [%s]\n",
		       fname, pname);
		correct = False;
	}

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);

	fnum = smbcli_open(cli->tree, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		return False;
	}
	smbcli_close(cli->tree, fnum);

	printf("Checking for sticky create times\n");

	if (NT_STATUS_IS_ERR(smbcli_qpathinfo(cli->tree, fname, &c_time, &a_time, &m_time, &size, NULL))) {
		printf("ERROR: qpathinfo failed (%s)\n", smbcli_errstr(cli->tree));
		correct = False;
	} else {
		if (c_time != m_time) {
			printf("create time=%s", ctime(&c_time));
			printf("modify time=%s", ctime(&m_time));
			printf("This system appears to have sticky create times\n");
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


	smbcli_unlink(cli->tree, fname);
	fnum = smbcli_open(cli->tree, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	smbcli_close(cli->tree, fnum);
	if (NT_STATUS_IS_ERR(smbcli_qpathinfo2(cli->tree, fname, &c_time, &a_time, &m_time, &w_time, &size, NULL, NULL))) {
		printf("ERROR: qpathinfo2 failed (%s)\n", smbcli_errstr(cli->tree));
		correct = False;
	} else {
		if (w_time < 60*60*24*2) {
			printf("write time=%s", ctime(&w_time));
			printf("This system appears to set a initial 0 write time\n");
			correct = False;
		}
	}

	smbcli_unlink(cli->tree, fname);


	/* check if the server updates the directory modification time
           when creating a new file */
	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, dname))) {
		printf("ERROR: mkdir failed (%s)\n", smbcli_errstr(cli->tree));
		correct = False;
	}
	sleep(3);
	if (NT_STATUS_IS_ERR(smbcli_qpathinfo2(cli->tree, "\\trans2\\", &c_time, &a_time, &m_time, &w_time, &size, NULL, NULL))) {
		printf("ERROR: qpathinfo2 failed (%s)\n", smbcli_errstr(cli->tree));
		correct = False;
	}

	fnum = smbcli_open(cli->tree, fname2, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);
	smbcli_write(cli->tree, fnum,  0, (char *)&fnum, 0, sizeof(fnum));
	smbcli_close(cli->tree, fnum);
	if (NT_STATUS_IS_ERR(smbcli_qpathinfo2(cli->tree, "\\trans2\\", &c_time, &a_time, &m_time2, &w_time, &size, NULL, NULL))) {
		printf("ERROR: qpathinfo2 failed (%s)\n", smbcli_errstr(cli->tree));
		correct = False;
	} else {
		if (m_time2 == m_time) {
			printf("This system does not update directory modification times\n");
			correct = False;
		}
	}
	smbcli_unlink(cli->tree, fname2);
	smbcli_rmdir(cli->tree, dname);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("trans2 test finished\n");

	return correct;
}

/*
  Test delete on close semantics.
 */
static BOOL run_deletetest(int dummy)
{
	struct smbcli_state *cli1;
	struct smbcli_state *cli2 = NULL;
	const char *fname = "\\delete.file";
	int fnum1 = -1;
	int fnum2 = -1;
	BOOL correct = True;
	
	printf("starting delete test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	
	/* Test 1 - this should delete the file on close. */
	
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OVERWRITE_IF, 
				   NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 0);
	
	if (fnum1 == -1) {
		printf("[1] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[1] close failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_NONE);
	if (fnum1 != -1) {
		printf("[1] open of %s succeeded (should fail)\n", fname);
		correct = False;
		goto fail;
	}
	
	printf("first delete on close test succeeded.\n");
	
	/* Test 2 - this should delete the file on close. */
	
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_ALL_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_NONE, 
				   NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
	
	if (fnum1 == -1) {
		printf("[2] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("[2] setting delete_on_close failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[2] close failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("[2] open of %s succeeded should have been deleted on close !\n", fname);
		if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
			printf("[2] close failed (%s)\n", smbcli_errstr(cli1->tree));
			correct = False;
			goto fail;
		}
		smbcli_unlink(cli1->tree, fname);
	} else
		printf("second delete on close test succeeded.\n");
	
	/* Test 3 - ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("[3] open - 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should fail with a sharing violation - open for delete is only compatible
	   with SHARE_DELETE. */

	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_READ, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, 
				   NTCREATEX_DISP_OPEN, 0, 0);

	if (fnum2 != -1) {
		printf("[3] open  - 2 of %s succeeded - should have failed.\n", fname);
		correct = False;
		goto fail;
	}

	/* This should succeed. */

	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_READ, FILE_ATTRIBUTE_NORMAL,
			NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OPEN, 0, 0);

	if (fnum2 == -1) {
		printf("[3] open  - 2 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("[3] setting delete_on_close failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[3] close 1 failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum2))) {
		printf("[3] close 2 failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* This should fail - file should no longer be there. */

	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("[3] open of %s succeeded should have been deleted on close !\n", fname);
		if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
			printf("[3] close failed (%s)\n", smbcli_errstr(cli1->tree));
		}
		smbcli_unlink(cli1->tree, fname);
		correct = False;
		goto fail;
	} else
		printf("third delete on close test succeeded.\n");

	/* Test 4 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				   SA_RIGHT_FILE_READ_DATA  | 
				   SA_RIGHT_FILE_WRITE_DATA |
				   STD_RIGHT_DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, 
				   NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, 
				   NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
								
	if (fnum1 == -1) {
		printf("[4] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should succeed. */
	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_READ,
				   FILE_ATTRIBUTE_NORMAL, 
				   NTCREATEX_SHARE_ACCESS_READ  | 
				   NTCREATEX_SHARE_ACCESS_WRITE |
				   NTCREATEX_SHARE_ACCESS_DELETE, 
				   NTCREATEX_DISP_OPEN, 0, 0);
	if (fnum2 == -1) {
		printf("[4] open  - 2 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum2))) {
		printf("[4] close - 1 failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("[4] setting delete_on_close failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* This should fail - no more opens once delete on close set. */
	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_READ,
				   FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
				   NTCREATEX_DISP_OPEN, 0, 0);
	if (fnum2 != -1) {
		printf("[4] open  - 3 of %s succeeded ! Should have failed.\n", fname );
		correct = False;
		goto fail;
	} else
		printf("fourth delete on close test succeeded.\n");
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[4] close - 2 failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* Test 5 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		printf("[5] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should fail - only allowed on NT opens with DELETE access. */

	if (NT_STATUS_IS_OK(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("[5] setting delete_on_close on OpenX file succeeded - should fail !\n");
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[5] close - 2 failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	printf("fifth delete on close test succeeded.\n");
	
	/* Test 6 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				   SA_RIGHT_FILE_READ_DATA | SA_RIGHT_FILE_WRITE_DATA,
				   FILE_ATTRIBUTE_NORMAL, 
				   NTCREATEX_SHARE_ACCESS_READ  |
				   NTCREATEX_SHARE_ACCESS_WRITE |
				   NTCREATEX_SHARE_ACCESS_DELETE,
				   NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
	
	if (fnum1 == -1) {
		printf("[6] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* This should fail - only allowed on NT opens with DELETE access. */
	
	if (NT_STATUS_IS_OK(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("[6] setting delete_on_close on file with no delete access succeeded - should fail !\n");
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[6] close - 2 failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	printf("sixth delete on close test succeeded.\n");
	
	/* Test 7 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				   SA_RIGHT_FILE_READ_DATA  | 
				   SA_RIGHT_FILE_WRITE_DATA |
				   STD_RIGHT_DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, 0, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
								
	if (fnum1 == -1) {
		printf("[7] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("[7] setting delete_on_close on file failed !\n");
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, False))) {
		printf("[7] unsetting delete_on_close on file failed !\n");
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[7] close - 2 failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* This next open should succeed - we reset the flag. */
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 == -1) {
		printf("[5] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[7] close - 2 failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	printf("seventh delete on close test succeeded.\n");
	
	/* Test 7 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	if (!torture_open_connection(&cli2)) {
		printf("[8] failed to open second connection.\n");
		correct = False;
		goto fail;
	}

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA|STD_RIGHT_DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
				   NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
	
	if (fnum1 == -1) {
		printf("[8] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA|STD_RIGHT_DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
				   NTCREATEX_DISP_OPEN, 0, 0);
	
	if (fnum2 == -1) {
		printf("[8] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("[8] setting delete_on_close on file failed !\n");
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[8] close - 1 failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli2->tree, fnum2))) {
		printf("[8] close - 2 failed (%s)\n", smbcli_errstr(cli2->tree));
		correct = False;
		goto fail;
	}

	/* This should fail.. */
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("[8] open of %s succeeded should have been deleted on close !\n", fname);
		goto fail;
		correct = False;
	} else
		printf("eighth delete on close test succeeded.\n");

	/* This should fail - we need to set DELETE_ACCESS. */
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0,SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA,
				   FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 0);
	
	if (fnum1 != -1) {
		printf("[9] open of %s succeeded should have failed!\n", fname);
		correct = False;
		goto fail;
	}

	printf("ninth delete on close test succeeded.\n");

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA|STD_RIGHT_DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 0);
	if (fnum1 == -1) {
		printf("[10] open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should delete the file. */
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("[10] close failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should fail.. */
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("[10] open of %s succeeded should have been deleted on close !\n", fname);
		goto fail;
		correct = False;
	} else
		printf("tenth delete on close test succeeded.\n");
	printf("finished delete test\n");

  fail:
	/* FIXME: This will crash if we aborted before cli2 got
	 * intialized, because these functions don't handle
	 * uninitialized connections. */
		
	smbcli_close(cli1->tree, fnum1);
	smbcli_close(cli1->tree, fnum2);
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	if (!torture_close_connection(cli2)) {
		correct = False;
	}
	return correct;
}


/*
  print out server properties
 */
static BOOL run_properties(int dummy)
{
	struct smbcli_state *cli;
	BOOL correct = True;
	
	printf("starting properties test\n");
	
	ZERO_STRUCT(cli);

	if (!torture_open_connection(&cli)) {
		return False;
	}
	
	d_printf("Capabilities 0x%08x\n", cli->transport->negotiate.capabilities);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	return correct;
}



/* FIRST_DESIRED_ACCESS   0xf019f */
#define FIRST_DESIRED_ACCESS   SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA|SA_RIGHT_FILE_APPEND_DATA|\
                               SA_RIGHT_FILE_READ_EA|                           /* 0xf */ \
                               SA_RIGHT_FILE_WRITE_EA|SA_RIGHT_FILE_READ_ATTRIBUTES|     /* 0x90 */ \
                               SA_RIGHT_FILE_WRITE_ATTRIBUTES|                  /* 0x100 */ \
                               STD_RIGHT_DELETE_ACCESS|STD_RIGHT_READ_CONTROL_ACCESS|\
                               STD_RIGHT_WRITE_DAC_ACCESS|STD_RIGHT_WRITE_OWNER_ACCESS     /* 0xf0000 */
/* SECOND_DESIRED_ACCESS  0xe0080 */
#define SECOND_DESIRED_ACCESS  SA_RIGHT_FILE_READ_ATTRIBUTES|                   /* 0x80 */ \
                               STD_RIGHT_READ_CONTROL_ACCESS|STD_RIGHT_WRITE_DAC_ACCESS|\
                               STD_RIGHT_WRITE_OWNER_ACCESS                      /* 0xe0000 */

#if 0
#define THIRD_DESIRED_ACCESS   FILE_READ_ATTRIBUTES|                   /* 0x80 */ \
                               READ_CONTROL_ACCESS|WRITE_DAC_ACCESS|\
                               SA_RIGHT_FILE_READ_DATA|\
                               WRITE_OWNER_ACCESS                      /* */
#endif

/*
  Test ntcreate calls made by xcopy
 */
static BOOL run_xcopy(int dummy)
{
	struct smbcli_state *cli1;
	const char *fname = "\\test.txt";
	BOOL correct = True;
	int fnum1, fnum2;

	printf("starting xcopy test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0,
				   FIRST_DESIRED_ACCESS, FILE_ATTRIBUTE_ARCHIVE,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 
				   0x4044, 0);

	if (fnum1 == -1) {
		printf("First open failed - %s\n", smbcli_errstr(cli1->tree));
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0,
				   SECOND_DESIRED_ACCESS, 0,
				   NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OPEN, 
				   0x200000, 0);
	if (fnum2 == -1) {
		printf("second open failed - %s\n", smbcli_errstr(cli1->tree));
		return False;
	}
	
	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	
	return correct;
}

/*
  Test rename on files open with share delete and no share delete.
 */
static BOOL run_rename(int dummy)
{
	struct smbcli_state *cli1;
	const char *fname = "\\test.txt";
	const char *fname1 = "\\test1.txt";
	BOOL correct = True;
	int fnum1;

	printf("starting rename test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	
	smbcli_unlink(cli1->tree, fname);
	smbcli_unlink(cli1->tree, fname1);
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_READ, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_READ, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("First open failed - %s\n", smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_rename(cli1->tree, fname, fname1))) {
		printf("First rename failed (this is correct) - %s\n", smbcli_errstr(cli1->tree));
	} else {
		printf("First rename succeeded - this should have failed !\n");
		correct = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("close - 1 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	smbcli_unlink(cli1->tree, fname);
	smbcli_unlink(cli1->tree, fname1);
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_READ, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_DELETE|NTCREATEX_SHARE_ACCESS_READ, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("Second open failed - %s\n", smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_rename(cli1->tree, fname, fname1))) {
		printf("Second rename failed - this should have succeeded - %s\n", smbcli_errstr(cli1->tree));
		correct = False;
	} else {
		printf("Second rename succeeded\n");
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("close - 2 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	smbcli_unlink(cli1->tree, fname);
	smbcli_unlink(cli1->tree, fname1);

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, STD_RIGHT_READ_CONTROL_ACCESS, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("Third open failed - %s\n", smbcli_errstr(cli1->tree));
		return False;
	}


	if (NT_STATUS_IS_ERR(smbcli_rename(cli1->tree, fname, fname1))) {
		printf("Third rename failed - this should have succeeded - %s\n", smbcli_errstr(cli1->tree));
		correct = False;
	} else {
		printf("Third rename succeeded\n");
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("close - 3 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	smbcli_unlink(cli1->tree, fname);
	smbcli_unlink(cli1->tree, fname1);

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	
	return correct;
}


/*
  see how many RPC pipes we can open at once
*/
static BOOL run_pipe_number(int dummy)
{
	struct smbcli_state *cli1;
	const char *pipe_name = "\\WKSSVC";
	int fnum;
	int num_pipes = 0;

	printf("starting pipenumber test\n");
	if (!torture_open_connection(&cli1)) {
		return False;
	}

	while(1) {
		fnum = smbcli_nt_create_full(cli1->tree, pipe_name, 0, SA_RIGHT_FILE_READ_DATA, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, NTCREATEX_DISP_OPEN_IF, 0, 0);

		if (fnum == -1) {
			printf("Open of pipe %s failed with error (%s)\n", pipe_name, smbcli_errstr(cli1->tree));
			break;
		}
		num_pipes++;
		printf("%d\r", num_pipes);
		fflush(stdout);
	}

	printf("pipe_number test - we can open %d %s pipes.\n", num_pipes, pipe_name );
	torture_close_connection(cli1);
	return True;
}




/*
  open N connections to the server and just hold them open
  used for testing performance when there are N idle users
  already connected
 */
 static BOOL torture_holdcon(int dummy)
{
	int i;
	struct smbcli_state **cli;
	int num_dead = 0;

	printf("Opening %d connections\n", torture_numops);
	
	cli = malloc(sizeof(struct smbcli_state *) * torture_numops);

	for (i=0;i<torture_numops;i++) {
		if (!torture_open_connection(&cli[i])) {
			return False;
		}
		printf("opened %d connections\r", i);
		fflush(stdout);
	}

	printf("\nStarting pings\n");

	while (1) {
		for (i=0;i<torture_numops;i++) {
			NTSTATUS status;
			if (cli[i]) {
				status = smbcli_chkpath(cli[i]->tree, "\\");
				if (!NT_STATUS_IS_OK(status)) {
					printf("Connection %d is dead\n", i);
					cli[i] = NULL;
					num_dead++;
				}
				usleep(100);
			}
		}

		if (num_dead == torture_numops) {
			printf("All connections dead - finishing\n");
			break;
		}

		printf(".");
		fflush(stdout);
	}

	return True;
}

/*
  Try with a wrong vuid and check error message.
 */

static BOOL run_vuidtest(int dummy)
{
	struct smbcli_state *cli;
	const char *fname = "\\vuid.tst";
	int fnum;
	size_t size;
	time_t c_time, a_time, m_time;
	BOOL correct = True;

	uint16_t orig_vuid;
	NTSTATUS result;

	printf("starting vuid test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	smbcli_unlink(cli->tree, fname);

	fnum = smbcli_open(cli->tree, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE);

	orig_vuid = cli->session->vuid;

	cli->session->vuid += 1234;

	printf("Testing qfileinfo with wrong vuid\n");
	
	if (NT_STATUS_IS_OK(result = smbcli_qfileinfo(cli->tree, fnum, NULL,
						   &size, &c_time, &a_time,
						   &m_time, NULL, NULL))) {
		printf("ERROR: qfileinfo passed with wrong vuid\n");
		correct = False;
	}

	if ( (cli->transport->error.etype != ETYPE_DOS) ||
	     (cli->transport->error.e.dos.eclass != ERRSRV) ||
	     (cli->transport->error.e.dos.ecode != ERRbaduid) ) {
		printf("ERROR: qfileinfo should have returned DOS error "
		       "ERRSRV:ERRbaduid\n  but returned %s\n",
		       smbcli_errstr(cli->tree));
		correct = False;
	}

	cli->session->vuid -= 1234;

	if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnum))) {
		printf("close failed (%s)\n", smbcli_errstr(cli->tree));
		correct = False;
	}

	smbcli_unlink(cli->tree, fname);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("vuid test finished\n");

	return correct;
}

/*
  Test open mode returns on read-only files.
 */
 static BOOL run_opentest(int dummy)
{
	static struct smbcli_state *cli1;
	static struct smbcli_state *cli2;
	const char *fname = "\\readonly.file";
	int fnum1, fnum2;
	char buf[20];
	size_t fsize;
	BOOL correct = True;
	char *tmp_path;
	int failures = 0;

	printf("starting open test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("close2 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_setatr(cli1->tree, fname, FILE_ATTRIBUTE_READONLY, 0))) {
		printf("smbcli_setatr failed (%s)\n", smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test1);
		return False;
	}
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_WRITE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test1);
		return False;
	}
	
	/* This will fail - but the error should be ERRnoaccess, not ERRbadshare. */
	fnum2 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_ALL);
	
        if (check_error(__LINE__, cli1, ERRDOS, ERRnoaccess, 
			NT_STATUS_ACCESS_DENIED)) {
		printf("correct error code ERRDOS/ERRnoaccess returned\n");
	}
	
	printf("finished open test 1\n");
error_test1:
	smbcli_close(cli1->tree, fnum1);
	
	/* Now try not readonly and ensure ERRbadshare is returned. */
	
	smbcli_setatr(cli1->tree, fname, 0, 0);
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_WRITE);
	if (fnum1 == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}
	
	/* This will fail - but the error should be ERRshare. */
	fnum2 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_ALL);
	
	if (check_error(__LINE__, cli1, ERRDOS, ERRbadshare, 
			NT_STATUS_SHARING_VIOLATION)) {
		printf("correct error code ERRDOS/ERRbadshare returned\n");
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("close2 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}
	
	smbcli_unlink(cli1->tree, fname);
	
	printf("finished open test 2\n");
	
	/* Test truncate open disposition on file opened for read. */
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum1 == -1) {
		printf("(3) open (1) of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}
	
	/* write 20 bytes. */
	
	memset(buf, '\0', 20);

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 0, 20) != 20) {
		printf("write failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(3) close1 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}
	
	/* Ensure size == 20. */
	if (NT_STATUS_IS_ERR(smbcli_getatr(cli1->tree, fname, NULL, &fsize, NULL))) {
		printf("(3) getatr failed (%s)\n", smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test3);
		return False;
	}
	
	if (fsize != 20) {
		printf("(3) file size != 20\n");
		CHECK_MAX_FAILURES(error_test3);
		return False;
	}

	/* Now test if we can truncate a file opened for readonly. */
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY|O_TRUNC, DENY_NONE);
	if (fnum1 == -1) {
		printf("(3) open (2) of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test3);
		return False;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("close2 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	/* Ensure size == 0. */
	if (NT_STATUS_IS_ERR(smbcli_getatr(cli1->tree, fname, NULL, &fsize, NULL))) {
		printf("(3) getatr failed (%s)\n", smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test3);
		return False;
	}

	if (fsize != 0) {
		printf("(3) file size != 0\n");
		CHECK_MAX_FAILURES(error_test3);
		return False;
	}
	printf("finished open test 3\n");
error_test3:	
	smbcli_unlink(cli1->tree, fname);


	printf("testing ctemp\n");
	fnum1 = smbcli_ctemp(cli1->tree, "\\", &tmp_path);
	if (fnum1 == -1) {
		printf("ctemp failed (%s)\n", smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test4);
		return False;
	}
	printf("ctemp gave path %s\n", tmp_path);
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("close of temp failed (%s)\n", smbcli_errstr(cli1->tree));
	}
	if (NT_STATUS_IS_ERR(smbcli_unlink(cli1->tree, tmp_path))) {
		printf("unlink of temp failed (%s)\n", smbcli_errstr(cli1->tree));
	}
error_test4:	
	/* Test the non-io opens... */

	if (!torture_open_connection(&cli2)) {
		return False;
	}
	
	smbcli_setatr(cli2->tree, fname, 0, 0);
	smbcli_unlink(cli2->tree, fname);
	
	printf("TEST #1 testing 2 non-io opens (no delete)\n");
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 1 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test10);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OPEN_IF, 0, 0);
	if (fnum2 == -1) {
		printf("test 1 open 2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		CHECK_MAX_FAILURES(error_test10);
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("test 1 close 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}
	if (NT_STATUS_IS_ERR(smbcli_close(cli2->tree, fnum2))) {
		printf("test 1 close 2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		return False;
	}

	printf("non-io open test #1 passed.\n");
error_test10:
	smbcli_unlink(cli1->tree, fname);

	printf("TEST #2 testing 2 non-io opens (first with delete)\n");
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, STD_RIGHT_DELETE_ACCESS|SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 2 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test20);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OPEN_IF, 0, 0);

	if (fnum2 == -1) {
		printf("test 2 open 2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		CHECK_MAX_FAILURES(error_test20);
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("test 1 close 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}
	if (NT_STATUS_IS_ERR(smbcli_close(cli2->tree, fnum2))) {
		printf("test 1 close 2 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}

	printf("non-io open test #2 passed.\n");
error_test20:
	smbcli_unlink(cli1->tree, fname);

	printf("TEST #3 testing 2 non-io opens (second with delete)\n");
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 3 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test30);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, STD_RIGHT_DELETE_ACCESS|SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OPEN_IF, 0, 0);

	if (fnum2 == -1) {
		printf("test 3 open 2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		CHECK_MAX_FAILURES(error_test30);
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("test 3 close 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}
	if (NT_STATUS_IS_ERR(smbcli_close(cli2->tree, fnum2))) {
		printf("test 3 close 2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		return False;
	}

	printf("non-io open test #3 passed.\n");
error_test30:
	smbcli_unlink(cli1->tree, fname);

	printf("TEST #4 testing 2 non-io opens (both with delete)\n");
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, STD_RIGHT_DELETE_ACCESS|SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 4 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test40);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, STD_RIGHT_DELETE_ACCESS|SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OPEN_IF, 0, 0);

	if (fnum2 != -1) {
		printf("test 4 open 2 of %s SUCCEEDED - should have failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		CHECK_MAX_FAILURES(error_test40);
		return False;
	}

	printf("test 4 open 2 of %s gave %s (correct error should be %s)\n", fname, smbcli_errstr(cli2->tree), "sharing violation");

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("test 4 close 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}

	printf("non-io open test #4 passed.\n");
error_test40:
	smbcli_unlink(cli1->tree, fname);

	printf("TEST #5 testing 2 non-io opens (both with delete - both with file share delete)\n");
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, STD_RIGHT_DELETE_ACCESS|SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 5 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test50);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, STD_RIGHT_DELETE_ACCESS|SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OPEN_IF, 0, 0);

	if (fnum2 == -1) {
		printf("test 5 open 2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		CHECK_MAX_FAILURES(error_test50);
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("test 5 close 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli2->tree, fnum2))) {
		printf("test 5 close 2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		return False;
	}

	printf("non-io open test #5 passed.\n");
error_test50:
	printf("TEST #6 testing 1 non-io open, one io open\n");
	
	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SA_RIGHT_FILE_READ_DATA, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 6 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test60);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_READ, NTCREATEX_DISP_OPEN_IF, 0, 0);

	if (fnum2 == -1) {
		printf("test 6 open 2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		CHECK_MAX_FAILURES(error_test60);
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("test 6 close 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli2->tree, fnum2))) {
		printf("test 6 close 2 of %s failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		return False;
	}

	printf("non-io open test #6 passed.\n");
error_test60:
	printf("TEST #7 testing 1 non-io open, one io open with delete\n");

	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SA_RIGHT_FILE_READ_DATA, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 7 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test70);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, STD_RIGHT_DELETE_ACCESS|SA_RIGHT_FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OPEN_IF, 0, 0);

	if (fnum2 != -1) {
		printf("test 7 open 2 of %s SUCCEEDED - should have failed (%s)\n", fname, smbcli_errstr(cli2->tree));
		CHECK_MAX_FAILURES(error_test70);
		return False;
	}

	printf("test 7 open 2 of %s gave %s (correct error should be %s)\n", fname, smbcli_errstr(cli2->tree), "sharing violation");

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("test 7 close 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}

	printf("non-io open test #7 passed.\n");

error_test70:

	printf("TEST #8 testing one normal open, followed by lock, followed by open with truncate\n");

	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		printf("(8) open (1) of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}
	
	/* write 20 bytes. */
	
	memset(buf, '\0', 20);

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 0, 20) != 20) {
		printf("(8) write failed (%s)\n", smbcli_errstr(cli1->tree));
		correct = False;
	}

	/* Ensure size == 20. */
	if (NT_STATUS_IS_ERR(smbcli_getatr(cli1->tree, fname, NULL, &fsize, NULL))) {
		printf("(8) getatr (1) failed (%s)\n", smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test80);
		return False;
	}
	
	if (fsize != 20) {
		printf("(8) file size != 20\n");
		CHECK_MAX_FAILURES(error_test80);
		return False;
	}

	/* Get an exclusive lock on the open file. */
	if (NT_STATUS_IS_ERR(smbcli_lock(cli1->tree, fnum1, 0, 4, 0, WRITE_LOCK))) {
		printf("(8) lock1 failed (%s)\n", smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test80);
		return False;
	}

	fnum2 = smbcli_open(cli1->tree, fname, O_RDWR|O_TRUNC, DENY_NONE);
	if (fnum1 == -1) {
		printf("(8) open (2) of %s with truncate failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		return False;
	}

	/* Ensure size == 0. */
	if (NT_STATUS_IS_ERR(smbcli_getatr(cli1->tree, fname, NULL, &fsize, NULL))) {
		printf("(8) getatr (2) failed (%s)\n", smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test80);
		return False;
	}
	
	if (fsize != 0) {
		printf("(8) file size != 0\n");
		CHECK_MAX_FAILURES(error_test80);
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(8) close1 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum2))) {
		printf("(8) close1 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}
	
error_test80:

	printf("open test #8 passed.\n");

	smbcli_unlink(cli1->tree, fname);

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	if (!torture_close_connection(cli2)) {
		correct = False;
	}
	
	return correct;
}


static uint32_t open_attrs_table[] = {
		FILE_ATTRIBUTE_NORMAL,
		FILE_ATTRIBUTE_ARCHIVE,
		FILE_ATTRIBUTE_READONLY,
		FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_SYSTEM,

		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,

		FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_HIDDEN,FILE_ATTRIBUTE_SYSTEM,
};

struct trunc_open_results {
	uint_t num;
	uint32_t init_attr;
	uint32_t trunc_attr;
	uint32_t result_attr;
};

static struct trunc_open_results attr_results[] = {
	{ 0, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE },
	{ 1, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE },
	{ 2, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY },
	{ 16, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE },
	{ 17, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE },
	{ 18, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY },
	{ 51, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 54, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 56, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN },
	{ 68, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 71, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 73, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM },
	{ 99, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN,FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 102, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 104, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN },
	{ 116, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 119,  FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM,  FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 121, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM },
	{ 170, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN },
	{ 173, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM },
	{ 227, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 230, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 232, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN },
	{ 244, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 247, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 249, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM }
};

static BOOL run_openattrtest(int dummy)
{
	struct smbcli_state *cli1;
	const char *fname = "\\openattr.file";
	int fnum1;
	BOOL correct = True;
	uint16_t attr;
	uint_t i, j, k, l;
	int failures = 0;

	printf("starting open attr test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	
	for (k = 0, i = 0; i < sizeof(open_attrs_table)/sizeof(uint32_t); i++) {
		smbcli_setatr(cli1->tree, fname, 0, 0);
		smbcli_unlink(cli1->tree, fname);
		fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SA_RIGHT_FILE_WRITE_DATA, open_attrs_table[i],
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

		if (fnum1 == -1) {
			printf("open %d (1) of %s failed (%s)\n", i, fname, smbcli_errstr(cli1->tree));
			return False;
		}

		if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
			printf("close %d (1) of %s failed (%s)\n", i, fname, smbcli_errstr(cli1->tree));
			return False;
		}

		for (j = 0; j < ARRAY_SIZE(open_attrs_table); j++) {
			fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
						   SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA, 
						   open_attrs_table[j],
						   NTCREATEX_SHARE_ACCESS_NONE, 
						   NTCREATEX_DISP_OVERWRITE, 0, 0);

			if (fnum1 == -1) {
				for (l = 0; l < ARRAY_SIZE(attr_results); l++) {
					if (attr_results[l].num == k) {
						printf("[%d] trunc open 0x%x -> 0x%x of %s failed - should have succeeded !(0x%x:%s)\n",
								k, open_attrs_table[i],
								open_attrs_table[j],
								fname, NT_STATUS_V(smbcli_nt_error(cli1->tree)), smbcli_errstr(cli1->tree));
						correct = False;
						CHECK_MAX_FAILURES(error_exit);
					}
				}
				if (NT_STATUS_V(smbcli_nt_error(cli1->tree)) != NT_STATUS_V(NT_STATUS_ACCESS_DENIED)) {
					printf("[%d] trunc open 0x%x -> 0x%x failed with wrong error code %s\n",
							k, open_attrs_table[i], open_attrs_table[j],
							smbcli_errstr(cli1->tree));
					correct = False;
					CHECK_MAX_FAILURES(error_exit);
				}
#if 0
				printf("[%d] trunc open 0x%x -> 0x%x failed\n", k, open_attrs_table[i], open_attrs_table[j]);
#endif
				k++;
				continue;
			}

			if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
				printf("close %d (2) of %s failed (%s)\n", j, fname, smbcli_errstr(cli1->tree));
				return False;
			}

			if (NT_STATUS_IS_ERR(smbcli_getatr(cli1->tree, fname, &attr, NULL, NULL))) {
				printf("getatr(2) failed (%s)\n", smbcli_errstr(cli1->tree));
				return False;
			}

#if 0
			printf("[%d] getatr check [0x%x] trunc [0x%x] got attr 0x%x\n",
					k,  open_attrs_table[i],  open_attrs_table[j], attr );
#endif

			for (l = 0; l < ARRAY_SIZE(attr_results); l++) {
				if (attr_results[l].num == k) {
					if (attr != attr_results[l].result_attr ||
							open_attrs_table[i] != attr_results[l].init_attr ||
							open_attrs_table[j] != attr_results[l].trunc_attr) {
						printf("[%d] getatr check failed. [0x%x] trunc [0x%x] got attr 0x%x, should be 0x%x\n",
							k, open_attrs_table[i],
							open_attrs_table[j],
							(uint_t)attr,
							attr_results[l].result_attr);
						correct = False;
						CHECK_MAX_FAILURES(error_exit);
					}
					break;
				}
			}
			k++;
		}
	}
error_exit:
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);

	printf("open attr test %s.\n", correct ? "passed" : "failed");

	if (!torture_close_connection(cli1)) {
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
	struct smbcli_state *cli;
	int fnum;
	double t1;
	BOOL correct = True;

	printf("starting directory test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	printf("Creating %d random filenames\n", torture_numops);

	srandom(0);
	for (i=0;i<torture_numops;i++) {
		char *fname;
		asprintf(&fname, "\\%x", (int)random());
		fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
		if (fnum == -1) {
			fprintf(stderr,"Failed to open %s\n", fname);
			return False;
		}
		smbcli_close(cli->tree, fnum);
		free(fname);
	}

	t1 = end_timer();

	printf("Matched %d\n", smbcli_list(cli->tree, "a*.*", 0, list_fn, NULL));
	printf("Matched %d\n", smbcli_list(cli->tree, "b*.*", 0, list_fn, NULL));
	printf("Matched %d\n", smbcli_list(cli->tree, "xyzabc", 0, list_fn, NULL));

	printf("dirtest core %g seconds\n", end_timer() - t1);

	srandom(0);
	for (i=0;i<torture_numops;i++) {
		char *fname;
		asprintf(&fname, "\\%x", (int)random());
		smbcli_unlink(cli->tree, fname);
		free(fname);
	}

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("finished dirtest\n");

	return correct;
}

/*
  sees what IOCTLs are supported
 */
BOOL torture_ioctl_test(int dummy)
{
	struct smbcli_state *cli;
	uint16_t device, function;
	int fnum;
	const char *fname = "\\ioctl.dat";
	NTSTATUS status;
	union smb_ioctl parms;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("ioctl_test");

	printf("starting ioctl test\n");

	smbcli_unlink(cli->tree, fname);

	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		return False;
	}

	parms.ioctl.level = RAW_IOCTL_IOCTL;
	parms.ioctl.in.fnum = fnum;
	parms.ioctl.in.request = IOCTL_QUERY_JOB_INFO;
	status = smb_raw_ioctl(cli->tree, mem_ctx, &parms);
	printf("ioctl job info: %s\n", smbcli_errstr(cli->tree));

	for (device=0;device<0x100;device++) {
		printf("testing device=0x%x\n", device);
		for (function=0;function<0x100;function++) {
			parms.ioctl.in.request = (device << 16) | function;
			status = smb_raw_ioctl(cli->tree, mem_ctx, &parms);

			if (NT_STATUS_IS_OK(status)) {
				printf("ioctl device=0x%x function=0x%x OK : %d bytes\n", 
					device, function, parms.ioctl.out.blob.length);
			}
		}
	}

	if (!torture_close_connection(cli)) {
		return False;
	}

	return True;
}


/*
  tries variants of chkpath
 */
BOOL torture_chkpath_test(int dummy)
{
	struct smbcli_state *cli;
	int fnum;
	BOOL ret;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	printf("starting chkpath test\n");

	printf("Testing valid and invalid paths\n");

	/* cleanup from an old run */
	smbcli_rmdir(cli->tree, "\\chkpath.dir\\dir2");
	smbcli_unlink(cli->tree, "\\chkpath.dir\\*");
	smbcli_rmdir(cli->tree, "\\chkpath.dir");

	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, "\\chkpath.dir"))) {
		printf("mkdir1 failed : %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, "\\chkpath.dir\\dir2"))) {
		printf("mkdir2 failed : %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	fnum = smbcli_open(cli->tree, "\\chkpath.dir\\foo.txt", O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open1 failed (%s)\n", smbcli_errstr(cli->tree));
		return False;
	}
	smbcli_close(cli->tree, fnum);

	if (NT_STATUS_IS_ERR(smbcli_chkpath(cli->tree, "\\chkpath.dir"))) {
		printf("chkpath1 failed: %s\n", smbcli_errstr(cli->tree));
		ret = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_chkpath(cli->tree, "\\chkpath.dir\\dir2"))) {
		printf("chkpath2 failed: %s\n", smbcli_errstr(cli->tree));
		ret = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_chkpath(cli->tree, "\\chkpath.dir\\foo.txt"))) {
		ret = check_error(__LINE__, cli, ERRDOS, ERRbadpath, 
				  NT_STATUS_NOT_A_DIRECTORY);
	} else {
		printf("* chkpath on a file should fail\n");
		ret = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_chkpath(cli->tree, "\\chkpath.dir\\bar.txt"))) {
		ret = check_error(__LINE__, cli, ERRDOS, ERRbadfile, 
				  NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		printf("* chkpath on a non existent file should fail\n");
		ret = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_chkpath(cli->tree, "\\chkpath.dir\\dirxx\\bar.txt"))) {
		ret = check_error(__LINE__, cli, ERRDOS, ERRbadpath, 
				  NT_STATUS_OBJECT_PATH_NOT_FOUND);
	} else {
		printf("* chkpath on a non existent component should fail\n");
		ret = False;
	}

	smbcli_rmdir(cli->tree, "\\chkpath.dir\\dir2");
	smbcli_unlink(cli->tree, "\\chkpath.dir\\*");
	smbcli_rmdir(cli->tree, "\\chkpath.dir");

	if (!torture_close_connection(cli)) {
		return False;
	}

	return ret;
}

static BOOL run_dirtest1(int dummy)
{
	int i;
	struct smbcli_state *cli;
	int fnum, num_seen;
	BOOL correct = True;

	printf("starting directory test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	if (smbcli_deltree(cli->tree, "\\LISTDIR") == -1) {
		fprintf(stderr,"Failed to deltree %s, error=%s\n", "\\LISTDIR", smbcli_errstr(cli->tree));
		return False;
	}
	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, "\\LISTDIR"))) {
		fprintf(stderr,"Failed to mkdir %s, error=%s\n", "\\LISTDIR", smbcli_errstr(cli->tree));
		return False;
	}

	printf("Creating %d files\n", torture_entries);

	/* Create torture_entries files and torture_entries directories. */
	for (i=0;i<torture_entries;i++) {
		char *fname;
		asprintf(&fname, "\\LISTDIR\\f%d", i);
		fnum = smbcli_nt_create_full(cli->tree, fname, 0, GENERIC_RIGHTS_FILE_ALL_ACCESS, FILE_ATTRIBUTE_ARCHIVE,
				   NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
		if (fnum == -1) {
			fprintf(stderr,"Failed to open %s, error=%s\n", fname, smbcli_errstr(cli->tree));
			return False;
		}
		free(fname);
		smbcli_close(cli->tree, fnum);
	}
	for (i=0;i<torture_entries;i++) {
		char *fname;
		asprintf(&fname, "\\LISTDIR\\d%d", i);
		if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, fname))) {
			fprintf(stderr,"Failed to open %s, error=%s\n", fname, smbcli_errstr(cli->tree));
			return False;
		}
		free(fname);
	}

	/* Now ensure that doing an old list sees both files and directories. */
	num_seen = smbcli_list_old(cli->tree, "\\LISTDIR\\*", FILE_ATTRIBUTE_DIRECTORY, list_fn, NULL);
	printf("num_seen = %d\n", num_seen );
	/* We should see (torture_entries) each of files & directories + . and .. */
	if (num_seen != (2*torture_entries)+2) {
		correct = False;
		fprintf(stderr,"entry count mismatch, should be %d, was %d\n",
			(2*torture_entries)+2, num_seen);
	}
		

	/* Ensure if we have the "must have" bits we only see the
	 * relevant entries.
	 */
	num_seen = smbcli_list_old(cli->tree, "\\LISTDIR\\*", (FILE_ATTRIBUTE_DIRECTORY<<8)|FILE_ATTRIBUTE_DIRECTORY, list_fn, NULL);
	printf("num_seen = %d\n", num_seen );
	if (num_seen != torture_entries+2) {
		correct = False;
		fprintf(stderr,"entry count mismatch, should be %d, was %d\n",
			torture_entries+2, num_seen);
	}

	num_seen = smbcli_list_old(cli->tree, "\\LISTDIR\\*", (FILE_ATTRIBUTE_ARCHIVE<<8)|FILE_ATTRIBUTE_DIRECTORY, list_fn, NULL);
	printf("num_seen = %d\n", num_seen );
	if (num_seen != torture_entries) {
		correct = False;
		fprintf(stderr,"entry count mismatch, should be %d, was %d\n",
			torture_entries, num_seen);
	}

	/* Delete everything. */
	if (smbcli_deltree(cli->tree, "\\LISTDIR") == -1) {
		fprintf(stderr,"Failed to deltree %s, error=%s\n", "\\LISTDIR", smbcli_errstr(cli->tree));
		return False;
	}

#if 0
	printf("Matched %d\n", smbcli_list(cli->tree, "a*.*", 0, list_fn, NULL));
	printf("Matched %d\n", smbcli_list(cli->tree, "b*.*", 0, list_fn, NULL));
	printf("Matched %d\n", smbcli_list(cli->tree, "xyzabc", 0, list_fn, NULL));
#endif

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("finished dirtest1\n");

	return correct;
}


/*
   simple test harness for playing with deny modes
 */
static BOOL run_deny3test(int dummy)
{
	struct smbcli_state *cli1, *cli2;
	int fnum1, fnum2;
	const char *fname;

	printf("starting deny3 test\n");

	printf("Testing simple deny modes\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	if (!torture_open_connection(&cli2)) {
		return False;
	}

	fname = "\\deny_dos1.dat";

	smbcli_unlink(cli1->tree, fname);
	fnum1 = smbcli_open(cli1->tree, fname, O_CREAT|O_TRUNC|O_WRONLY, DENY_DOS);
	fnum2 = smbcli_open(cli1->tree, fname, O_CREAT|O_TRUNC|O_WRONLY, DENY_DOS);
	if (fnum1 != -1) smbcli_close(cli1->tree, fnum1);
	if (fnum2 != -1) smbcli_close(cli1->tree, fnum2);
	smbcli_unlink(cli1->tree, fname);
	printf("fnum1=%d fnum2=%d\n", fnum1, fnum2);


	fname = "\\deny_dos2.dat";

	smbcli_unlink(cli1->tree, fname);
	fnum1 = smbcli_open(cli1->tree, fname, O_CREAT|O_TRUNC|O_WRONLY, DENY_DOS);
	fnum2 = smbcli_open(cli2->tree, fname, O_CREAT|O_TRUNC|O_WRONLY, DENY_DOS);
	if (fnum1 != -1) smbcli_close(cli1->tree, fnum1);
	if (fnum2 != -1) smbcli_close(cli2->tree, fnum2);
	smbcli_unlink(cli1->tree, fname);
	printf("fnum1=%d fnum2=%d\n", fnum1, fnum2);


	torture_close_connection(cli1);
	torture_close_connection(cli2);

	return True;
}

/*
  parse a //server/share type UNC name
*/
static BOOL parse_unc(const char *unc_name, char **hostname, char **sharename)
{
	char *p;

	if (strncmp(unc_name, "//", 2)) {
		return False;
	}

	*hostname = strdup(&unc_name[2]);
	p = strchr_m(&(*hostname)[2],'/');
	if (!p) {
		return False;
	}
	*p = 0;
	*sharename = strdup(p+1);

	return True;
}



static void sigcont(void)
{
}

double torture_create_procs(BOOL (*fn)(struct smbcli_state *, int), BOOL *result)
{
	int i, status;
	volatile pid_t *child_status;
	volatile BOOL *child_status_out;
	int synccount;
	int tries = 8;
	double start_time_limit = 10 + (torture_nprocs * 1.5);
	char **unc_list = NULL;
	const char *p;
	int num_unc_names = 0;

	synccount = 0;

	signal(SIGCONT, sigcont);

	child_status = (volatile pid_t *)shm_setup(sizeof(pid_t)*torture_nprocs);
	if (!child_status) {
		printf("Failed to setup shared memory\n");
		return -1;
	}

	child_status_out = (volatile BOOL *)shm_setup(sizeof(BOOL)*torture_nprocs);
	if (!child_status_out) {
		printf("Failed to setup result status shared memory\n");
		return -1;
	}

	p = lp_parm_string(-1, "torture", "unclist");
	if (p) {
		unc_list = file_lines_load(p, &num_unc_names);
		if (!unc_list || num_unc_names <= 0) {
			printf("Failed to load unc names list from '%s'\n", p);
			exit(1);
		}
	}

	for (i = 0; i < torture_nprocs; i++) {
		child_status[i] = 0;
		child_status_out[i] = True;
	}

	start_timer();

	for (i=0;i<torture_nprocs;i++) {
		procnum = i;
		if (fork() == 0) {
			char *myname;
			char *hostname=NULL, *sharename;

			pid_t mypid = getpid();
			sys_srandom(((int)mypid) ^ ((int)time(NULL)));

			asprintf(&myname, "CLIENT%d", i);
			lp_set_cmdline("netbios name", myname);
			free(myname);


			if (unc_list) {
				if (!parse_unc(unc_list[i % num_unc_names],
					       &hostname, &sharename)) {
					printf("Failed to parse UNC name %s\n",
					       unc_list[i % num_unc_names]);
					exit(1);
				}
			}

			while (1) {
				if (hostname) {
					if (torture_open_connection_share(&current_cli,
									  hostname, 
									  sharename)) {
						break;
					}
				} else if (torture_open_connection(&current_cli)) {
						break;
				}
				if (tries-- == 0) {
					printf("pid %d failed to start\n", (int)getpid());
					_exit(1);
				}
				msleep(100);	
			}

			child_status[i] = getpid();

			pause();

			if (child_status[i]) {
				printf("Child %d failed to start!\n", i);
				child_status_out[i] = 1;
				_exit(1);
			}

			child_status_out[i] = fn(current_cli, i);
			_exit(0);
		}
	}

	do {
		synccount = 0;
		for (i=0;i<torture_nprocs;i++) {
			if (child_status[i]) synccount++;
		}
		if (synccount == torture_nprocs) break;
		msleep(100);
	} while (end_timer() < start_time_limit);

	if (synccount != torture_nprocs) {
		printf("FAILED TO START %d CLIENTS (started %d)\n", torture_nprocs, synccount);
		*result = False;
		return end_timer();
	}

	printf("Starting %d clients\n", torture_nprocs);

	/* start the client load */
	start_timer();
	for (i=0;i<torture_nprocs;i++) {
		child_status[i] = 0;
	}
	kill(0, SIGCONT);

	printf("%d clients started\n", torture_nprocs);

	for (i=0;i<torture_nprocs;i++) {
		int ret;
		while ((ret=waitpid(0, &status, 0)) == -1 && errno == EINTR) /* noop */ ;
		if (ret == -1 || WEXITSTATUS(status) != 0) {
			*result = False;
		}
	}

	printf("\n");
	
	for (i=0;i<torture_nprocs;i++) {
		if (!child_status_out[i]) {
			*result = False;
		}
	}
	return end_timer();
}

#define FLAG_MULTIPROC 1

static struct {
	const char *name;
	BOOL (*fn)(int);
	uint_t flags;
} torture_ops[] = {
	/* base tests */
	{"BASE-FDPASS", run_fdpasstest, 0},
	{"BASE-LOCK1",  run_locktest1,  0},
	{"BASE-LOCK2",  run_locktest2,  0},
	{"BASE-LOCK3",  run_locktest3,  0},
	{"BASE-LOCK4",  run_locktest4,  0},
	{"BASE-LOCK5",  run_locktest5,  0},
	{"BASE-LOCK6",  run_locktest6,  0},
	{"BASE-LOCK7",  run_locktest7,  0},
	{"BASE-UNLINK", run_unlinktest, 0},
	{"BASE-ATTR",   run_attrtest,   0},
	{"BASE-TRANS2", run_trans2test, 0},
	{"BASE-NEGNOWAIT", run_negprot_nowait, 0},
	{"BASE-DIR",  run_dirtest, 0},
	{"BASE-DIR1",  run_dirtest1, 0},
	{"BASE-DENY1",  torture_denytest1, 0},
	{"BASE-DENY2",  torture_denytest2, 0},
	{"BASE-TCON",  run_tcon_test, 0},
	{"BASE-TCONDEV",  run_tcon_devtype_test, 0},
	{"BASE-VUID", run_vuidtest, 0},
	{"BASE-RW1",  run_readwritetest, 0},
	{"BASE-RW2",  run_readwritemulti, FLAG_MULTIPROC},
	{"BASE-OPEN", run_opentest, 0},
	{"BASE-DENY3", run_deny3test, 0},
	{"BASE-DEFER_OPEN", run_deferopen, FLAG_MULTIPROC},
	{"BASE-XCOPY", run_xcopy, 0},
	{"BASE-RENAME", run_rename, 0},
	{"BASE-DELETE", run_deletetest, 0},
	{"BASE-PROPERTIES", run_properties, 0},
	{"BASE-MANGLE", torture_mangle, 0},
	{"BASE-OPENATTR", run_openattrtest, 0},
	{"BASE-CHARSET", torture_charset, 0},
	{"BASE-CHKPATH",  torture_chkpath_test, 0},
	{"BASE-SECLEAK",  torture_sec_leak, 0},

	/* benchmarking tests */
	{"BENCH-HOLDCON",  torture_holdcon, 0},
	{"BENCH-NBENCH",  torture_nbench, 0},
	{"BENCH-TORTURE",run_torture,    FLAG_MULTIPROC},

	/* RAW smb tests */
	{"RAW-QFSINFO", torture_raw_qfsinfo, 0},
	{"RAW-QFILEINFO", torture_raw_qfileinfo, 0},
	{"RAW-SFILEINFO", torture_raw_sfileinfo, 0},
	{"RAW-SFILEINFO-BUG", torture_raw_sfileinfo_bug, 0},
	{"RAW-SEARCH", torture_raw_search, 0},
	{"RAW-CLOSE", torture_raw_close, 0},
	{"RAW-OPEN", torture_raw_open, 0},
	{"RAW-MKDIR", torture_raw_mkdir, 0},
	{"RAW-OPLOCK", torture_raw_oplock, 0},
	{"RAW-NOTIFY", torture_raw_notify, 0},
	{"RAW-MUX", torture_raw_mux, 0},
	{"RAW-IOCTL", torture_raw_ioctl, 0},
	{"RAW-CHKPATH", torture_raw_chkpath, 0},
	{"RAW-UNLINK", torture_raw_unlink, 0},
	{"RAW-READ", torture_raw_read, 0},
	{"RAW-WRITE", torture_raw_write, 0},
	{"RAW-LOCK", torture_raw_lock, 0},
	{"RAW-CONTEXT", torture_raw_context, 0},
	{"RAW-RENAME", torture_raw_rename, 0},
	{"RAW-SEEK", torture_raw_seek, 0},
	{"RAW-RAP", torture_raw_rap, 0},

	/* protocol scanners */
	{"SCAN-TRANS2", torture_trans2_scan, 0},
	{"SCAN-NTTRANS", torture_nttrans_scan, 0},
	{"SCAN-ALIASES", torture_trans2_aliases, 0},
	{"SCAN-SMB", torture_smb_scan, 0},
	{"SCAN-MAXFID", run_maxfidtest, FLAG_MULTIPROC},
	{"SCAN-UTABLE", torture_utable, 0},
	{"SCAN-CASETABLE", torture_casetable, 0},
	{"SCAN-PIPE_NUMBER", run_pipe_number, 0},
	{"SCAN-IOCTL",  torture_ioctl_test, 0},

	/* rpc testers */
        {"RPC-LSA", torture_rpc_lsa, 0},
        {"RPC-ECHO", torture_rpc_echo, 0},
        {"RPC-DFS", torture_rpc_dfs, 0},
        {"RPC-SPOOLSS", torture_rpc_spoolss, 0},
        {"RPC-SAMR", torture_rpc_samr, 0},
        {"RPC-NETLOGON", torture_rpc_netlogon, 0},
        {"RPC-SCHANNEL", torture_rpc_schannel, 0},
        {"RPC-WKSSVC", torture_rpc_wkssvc, 0},
        {"RPC-SRVSVC", torture_rpc_srvsvc, 0},
        {"RPC-SVCCTL", torture_rpc_svcctl, 0},
        {"RPC-ATSVC", torture_rpc_atsvc, 0},
        {"RPC-EVENTLOG", torture_rpc_eventlog, 0},
        {"RPC-EPMAPPER", torture_rpc_epmapper, 0},
        {"RPC-WINREG", torture_rpc_winreg, 0},
        {"RPC-OXIDRESOLVE", torture_rpc_oxidresolve, 0},
        {"RPC-MGMT", torture_rpc_mgmt, 0},
        {"RPC-SCANNER", torture_rpc_scanner, 0},
        {"RPC-AUTOIDL", torture_rpc_autoidl, 0},
	{"RPC-MULTIBIND", torture_multi_bind, 0},
	{"RPC-DRSUAPI", torture_rpc_drsuapi, 0},

	/* local (no server) testers */
	{"LOCAL-NTLMSSP", torture_ntlmssp_self_check, 0},
	{"LOCAL-ICONV", torture_local_iconv, 0},
	{"LOCAL-TALLOC", torture_local_talloc, 0},

	/* ldap testers */
	{"LDAP-BASIC", torture_ldap_basic, 0},

	{NULL, NULL, 0}};



/****************************************************************************
run a specified test or "ALL"
****************************************************************************/
static BOOL run_test(const char *name)
{
	BOOL ret = True;
	int i;
	BOOL matched = False;

	if (strequal(name,"ALL")) {
		for (i=0;torture_ops[i].name;i++) {
			if (!run_test(torture_ops[i].name)) {
				ret = False;
			}
		}
		return ret;
	}

	for (i=0;torture_ops[i].name;i++) {
		if (gen_fnmatch(name, torture_ops[i].name) == 0) {
			double t;
			matched = True;
			printf("Running %s\n", torture_ops[i].name);
			if (torture_ops[i].flags & FLAG_MULTIPROC) {
				BOOL result;
				t = torture_create_procs(torture_ops[i].fn, &result);
				if (!result) { 
					ret = False;
					printf("TEST %s FAILED!\n", torture_ops[i].name);
				}
					 
			} else {
				start_timer();
				if (!torture_ops[i].fn(0)) {
					ret = False;
					printf("TEST %s FAILED!\n", torture_ops[i].name);
				}
				t = end_timer();
			}
			printf("%s took %g secs\n\n", torture_ops[i].name, t);
		}
	}

	if (!matched) {
		printf("Unknown torture operation '%s'\n", name);
	}

	return ret;
}


static void parse_dns(const char *dns)
{
	char *userdn, *basedn, *secret;
	char *p, *d;

	/* retrievieng the userdn */
	p = strchr_m(dns, '#');
	if (!p) {
		lp_set_cmdline("torture:ldap_userdn", "");
		lp_set_cmdline("torture:ldap_basedn", "");
		lp_set_cmdline("torture:ldap_secret", "");
		return;
	}
	userdn = strndup(dns, p - dns);
	lp_set_cmdline("torture:ldap_userdn", userdn);

	/* retrieve the basedn */
	d = p + 1;
	p = strchr_m(d, '#');
	if (!p) {
		lp_set_cmdline("torture:ldap_basedn", "");
		lp_set_cmdline("torture:ldap_secret", "");
		return;
	}
	basedn = strndup(d, p - d);
	lp_set_cmdline("torture:ldap_basedn", basedn);

	/* retrieve the secret */
	p = p + 1;
	if (!p) {
		lp_set_cmdline("torture:ldap_secret", "");
		return;
	}
	secret = strdup(p);
	lp_set_cmdline("torture:ldap_secret", secret);

	printf ("%s - %s - %s\n", userdn, basedn, secret);

}

static void usage(poptContext pc)
{
	int i;
	int perline = 5;

	poptPrintUsage(pc, stdout, 0);
	printf("\n");

	printf("tests are:");
	for (i=0;torture_ops[i].name;i++) {
		if ((i%perline)==0) {
			printf("\n");
		}
		printf("%s ", torture_ops[i].name);
	}
	printf("\n\n");

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
	BOOL correct = True;
	int argc_new;
	char **argv_new;
	poptContext pc;
	enum {OPT_LOADFILE=1000,OPT_UNCLIST,OPT_TIMELIMIT,OPT_DNS,OPT_DANGEROUS};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"smb-ports",	'p', POPT_ARG_STRING, NULL, 		0,	"SMB ports", 	NULL},
		{"seed",	  0, POPT_ARG_STRING, NULL, 		0,	"seed", 	NULL},
		{"num-progs",	  0, POPT_ARG_INT,  &torture_nprocs, 	0,	"num progs",	NULL},
		{"num-ops",	  0, POPT_ARG_INT,  &torture_numops, 	0, 	"num ops",	NULL},
		{"entries",	  0, POPT_ARG_INT,  &torture_entries, 	0,	"entries",	NULL},
		{"use-oplocks",	'L', POPT_ARG_NONE, &use_oplocks, 	0,	"use oplocks", 	NULL},
		{"show-all",	  0, POPT_ARG_NONE, &torture_showall, 	0,	"show all", 	NULL},
		{"loadfile",	  0, POPT_ARG_STRING,	NULL, 	OPT_LOADFILE,	"loadfile", 	NULL},
		{"unclist",	  0, POPT_ARG_STRING,	NULL, 	OPT_UNCLIST,	"unclist", 	NULL},
		{"timelimit",	't', POPT_ARG_STRING,	NULL, 	OPT_TIMELIMIT,	"timelimit", 	NULL},
		{"failures",	'f', POPT_ARG_INT,  &torture_failures, 	0,	"failures", 	NULL},
		{"parse-dns",	'D', POPT_ARG_STRING,	NULL, 	OPT_DNS,	"parse-dns", 	NULL},
		{"dangerous",	'X', POPT_ARG_NONE,	NULL,   OPT_DANGEROUS,	"dangerous", 	NULL},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	setup_logging("smbtorture", DEBUG_STDOUT);

#ifdef HAVE_SETBUFFER
	setbuffer(stdout, NULL, 0);
#endif

	pc = poptGetContext("smbtorture", argc, (const char **) argv, long_options, 
				POPT_CONTEXT_KEEP_FIRST);

	poptSetOtherOptionHelp(pc, "<binding>|<unc> TEST1 TEST2 ...");

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_LOADFILE:
			lp_set_cmdline("torture:loadfile", poptGetOptArg(pc));
			break;
		case OPT_UNCLIST:
			lp_set_cmdline("torture:unclist", poptGetOptArg(pc));
			break;
		case OPT_TIMELIMIT:
			lp_set_cmdline("torture:timelimit", poptGetOptArg(pc));
			break;
		case OPT_DNS:
			parse_dns(poptGetOptArg(pc));
			break;
		case OPT_DANGEROUS:
			lp_set_cmdline("torture:dangerous", "1");
			break;
		default:
			d_printf("Invalid option %s: %s\n", 
				 poptBadOption(pc, 0), poptStrerror(opt));
			usage(pc);
			exit(1);
		}
	}

	lp_load(dyn_CONFIGFILE,True,False,False);
	load_interfaces();
	srandom(time(NULL));

	argv_new = (const char **)poptGetArgs(pc);

	argc_new = argc;
	for (i=0; i<argc; i++) {
		if (argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}

	if (argc_new < 3) {
		usage(pc);
		exit(1);
	}

        for(p = argv_new[1]; *p; p++) {
		if(*p == '\\')
			*p = '/';
	}

	/* see if its a RPC transport specifier */
	if (strncmp(argv_new[1], "ncacn_", 6) == 0) {
		lp_set_cmdline("torture:binding", argv_new[1]);
	} else {
		char *binding = NULL;
		char *host = NULL, *share = NULL;

		if (!parse_unc(argv_new[1], &host, &share)) {
			usage(pc);
		}

		lp_set_cmdline("torture:host", host);
		lp_set_cmdline("torture:share", share);
		asprintf(&binding, "ncacn_np:%s", host);
		lp_set_cmdline("torture:binding", binding);
	}

	if (!lp_parm_string(-1,"torture","username")) {
		lp_set_cmdline("torture:username", cmdline_get_username());
	}
	if (!lp_parm_string(-1,"torture","userdomain")) {
		/* 
		 * backward compatibility
		 * maybe we should remove this to make this consistent
		 * for all cmdline tools
		 * --metze
		 */
		if (strequal(lp_netbios_name(),cmdline_get_userdomain())) {
			cmdline_set_userdomain(lp_workgroup());
		}
		lp_set_cmdline("torture:userdomain", cmdline_get_userdomain());
	}
	if (!lp_parm_string(-1,"torture","password")) {
		lp_set_cmdline("torture:password", cmdline_get_userpassword());
	}

	if (argc_new == 0) {
		printf("You must specify a test to run, or 'ALL'\n");
	} else {
		for (i=2;i<argc_new;i++) {
			if (!run_test(argv_new[i])) {
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
