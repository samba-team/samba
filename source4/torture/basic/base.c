/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
   
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
#include "torture/torture.h"
#include "torture/basic/proto.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "system/filesys.h"
#include "system/time.h"
#include "libcli/resolve/resolve.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "lib/events/events.h"
#include "lib/cmdline/popt_common.h"


#define CHECK_MAX_FAILURES(label) do { if (++failures >= torture_failures) goto label; } while (0)


static struct smbcli_state *open_nbt_connection(void)
{
	struct nbt_name called, calling;
	struct smbcli_state *cli;
	const char *host = lp_parm_string(-1, "torture", "host");

	make_nbt_name_client(&calling, lp_netbios_name());

	nbt_choose_called_name(NULL, &called, host, NBT_NAME_SERVER);

	cli = smbcli_state_init(NULL);
	if (!cli) {
		printf("Failed initialize smbcli_struct to connect with %s\n", host);
		goto failed;
	}

	if (!smbcli_socket_connect(cli, host)) {
		printf("Failed to connect with %s\n", host);
		goto failed;
	}

	if (!smbcli_transport_establish(cli, &calling, &called)) {
		printf("%s rejected the session\n",host);
		goto failed;
	}

	return cli;

failed:
	talloc_free(cli);
	return NULL;
}

static BOOL tcon_devtest(struct smbcli_state *cli,
			 const char *myshare, const char *devtype,
			 NTSTATUS expected_error)
{
	BOOL status;
	BOOL ret;
	const char *password = lp_parm_string(-1, "torture", "password");

	status = NT_STATUS_IS_OK(smbcli_tconX(cli, myshare, devtype, 
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



/**
test whether fnums and tids open on one VC are available on another (a major
security hole)
*/
static BOOL run_fdpasstest(struct torture_context *torture)
{
	struct smbcli_state *cli1, *cli2;
	const char *fname = "\\fdpass.tst";
	int fnum1, oldtid;
	uint8_t buf[1024];

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

/**
  This checks how the getatr calls works
*/
static BOOL run_attrtest(struct torture_context *torture)
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

/**
  This checks a couple of trans2 calls
*/
static BOOL run_trans2test(struct torture_context *torture)
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
	smbcli_write(cli->tree, fnum,  0, &fnum, 0, sizeof(fnum));
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

/* send smb negprot commands, not reading the response */
static BOOL run_negprot_nowait(struct torture_context *torture)
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

	for (i=0;i<100;i++) {
		struct smbcli_request *req;
		req = smb_raw_negotiate_send(cli->transport, PROTOCOL_NT1);
		event_loop_once(cli->transport->socket->event.ctx);
		if (req->state == SMBCLI_REQUEST_ERROR) {
			if (i > 0) {
				printf("Failed to fill pipe packet[%d] - %s (ignored)\n", i+1, nt_errstr(req->status));
				break;
			} else {
				printf("Failed to fill pipe - %s \n", nt_errstr(req->status));
				torture_close_connection(cli);
				return False;
			}
		}
	}

	printf("Opening secondary connection\n");
	if (!torture_open_connection(&cli2)) {
		printf("Failed to open secondary connection\n");
		correct = False;
	}

	if (!torture_close_connection(cli2)) {
		printf("Failed to close secondary connection\n");
		correct = False;
	}

	torture_close_connection(cli);

	printf("finished negprot nowait test\n");

	return correct;
}

/**
  this checks to see if a secondary tconx can use open files from an
  earlier tconx
 */
static BOOL run_tcon_test(struct torture_context *torture)
{
	struct smbcli_state *cli;
	const char *fname = "\\tcontest.tmp";
	int fnum1;
	uint16_t cnum1, cnum2, cnum3;
	uint16_t vuid1, vuid2;
	uint8_t buf[4];
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
	if (NT_STATUS_IS_ERR(smbcli_tconX(cli, share, "?????", password))) {
		printf("%s refused 2nd tree connect (%s)\n", host,
		           smbcli_errstr(cli->tree));
		talloc_free(cli);
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

	smbcli_unlink(tree1, fname);

	if (!torture_close_connection(cli)) {
		return False;
	}

	return ret;
}

/**
 checks for correct tconX support
 */
static BOOL run_tcon_devtype_test(struct torture_context *torture)
{
	struct smbcli_state *cli1 = NULL;
	NTSTATUS status;
	BOOL ret = True;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");
	
	status = smbcli_full_connection(NULL,
					&cli1, host, 
					share, NULL,
					cmdline_credentials, NULL);

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

	talloc_free(cli1);

	if (ret)
		printf("Passed tcondevtest\n");

	return ret;
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
		size_t buf_size = ((uint_t)random()%(sizeof(buf)-1))+ 1;
		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}

		generate_random_buffer(buf, buf_size);

		if ((bytes_written = smbcli_write(c1->tree, fnum1, 0, buf, 0, buf_size)) != buf_size) {
			printf("write failed (%s)\n", smbcli_errstr(c1->tree));
			printf("wrote %d, expected %d\n", (int)bytes_written, (int)buf_size); 
			correct = False;
			break;
		}

		if ((bytes_read = smbcli_read(c2->tree, fnum2, buf_rd, 0, buf_size)) != buf_size) {
			printf("read failed (%s)\n", smbcli_errstr(c2->tree));
			printf("read %d, expected %d\n", (int)bytes_read, (int)buf_size); 
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



#define BOOLSTR(b) ((b) ? "Yes" : "No")

static BOOL run_readwritetest(struct torture_context *torture)
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
			struct timeval tv;
			tv = timeval_current();
			fnum = smbcli_nt_create_full(cli->tree, fname, 0, 
						     SEC_RIGHTS_FILE_ALL,
						     FILE_ATTRIBUTE_NORMAL, 
						     NTCREATEX_SHARE_ACCESS_NONE,
						     NTCREATEX_DISP_OPEN_IF, 0, 0);
			if (fnum != -1) {
				break;
			}
			if (NT_STATUS_EQUAL(smbcli_nt_error(cli->tree),NT_STATUS_SHARING_VIOLATION)) {
				double e = timeval_elapsed(&tv);
				if (e < 0.5 || e > 1.5) {
					fprintf(stderr,"Timing incorrect %.2f violation\n",
						e);
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

/**
  Try with a wrong vuid and check error message.
 */

static BOOL run_vuidtest(struct torture_context *torture)
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

	if (!NT_STATUS_EQUAL(cli->transport->error.e.nt_status, 
			     NT_STATUS_DOS(ERRSRV, ERRbaduid)) &&
	    !NT_STATUS_EQUAL(cli->transport->error.e.nt_status, 
			     NT_STATUS_INVALID_HANDLE)) {
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
 static BOOL run_opentest(struct torture_context *torture)
{
	static struct smbcli_state *cli1;
	static struct smbcli_state *cli2;
	const char *fname = "\\readonly.file";
	char *control_char_fname;
	int fnum1, fnum2;
	uint8_t buf[20];
	size_t fsize;
	BOOL correct = True;
	char *tmp_path;
	int failures = 0;
	int i;

	printf("starting open test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	
	asprintf(&control_char_fname, "\\readonly.afile");
	for (i = 1; i <= 0x1f; i++) {
		control_char_fname[10] = i;
		fnum1 = smbcli_nt_create_full(cli1->tree, control_char_fname, 0, SEC_FILE_WRITE_DATA, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
		
        	if (!check_error(__location__, cli1, ERRDOS, ERRinvalidname, 
				NT_STATUS_OBJECT_NAME_INVALID)) {
			printf("Error code should be NT_STATUS_OBJECT_NAME_INVALID, was %s for file with %d char\n",
					smbcli_errstr(cli1->tree), i);
			failures++;
		}

		if (fnum1 != -1) {
			smbcli_close(cli1->tree, fnum1);
		}
		smbcli_setatr(cli1->tree, control_char_fname, 0, 0);
		smbcli_unlink(cli1->tree, control_char_fname);
	}
	free(control_char_fname);

	if (!failures)
		printf("Create file with control char names passed.\n");

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
	
        if (check_error(__location__, cli1, ERRDOS, ERRnoaccess, 
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
	
	if (check_error(__location__, cli1, ERRDOS, ERRbadshare, 
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
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 1 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test10);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
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
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SEC_STD_DELETE|SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 2 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test20);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
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
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 3 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test30);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SEC_STD_DELETE|SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
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
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SEC_STD_DELETE|SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 4 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test40);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SEC_STD_DELETE|SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
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
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SEC_STD_DELETE|SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 5 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test50);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SEC_STD_DELETE|SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
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

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SEC_FILE_READ_DATA, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 6 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test60);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
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

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SEC_FILE_READ_DATA, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_NONE, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("test 7 open 1 of %s failed (%s)\n", fname, smbcli_errstr(cli1->tree));
		CHECK_MAX_FAILURES(error_test70);
		return False;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SEC_STD_DELETE|SEC_FILE_READ_ATTRIBUTE, FILE_ATTRIBUTE_NORMAL,
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

/* FIRST_DESIRED_ACCESS   0xf019f */
#define FIRST_DESIRED_ACCESS   SEC_FILE_READ_DATA|SEC_FILE_WRITE_DATA|SEC_FILE_APPEND_DATA|\
                               SEC_FILE_READ_EA|                           /* 0xf */ \
                               SEC_FILE_WRITE_EA|SEC_FILE_READ_ATTRIBUTE|     /* 0x90 */ \
                               SEC_FILE_WRITE_ATTRIBUTE|                  /* 0x100 */ \
                               SEC_STD_DELETE|SEC_STD_READ_CONTROL|\
                               SEC_STD_WRITE_DAC|SEC_STD_WRITE_OWNER     /* 0xf0000 */
/* SECOND_DESIRED_ACCESS  0xe0080 */
#define SECOND_DESIRED_ACCESS  SEC_FILE_READ_ATTRIBUTE|                   /* 0x80 */ \
                               SEC_STD_READ_CONTROL|SEC_STD_WRITE_DAC|\
                               SEC_STD_WRITE_OWNER                      /* 0xe0000 */

#if 0
#define THIRD_DESIRED_ACCESS   FILE_READ_ATTRIBUTE|                   /* 0x80 */ \
                               READ_CONTROL|WRITE_DAC|\
                               SEC_FILE_READ_DATA|\
                               WRITE_OWNER                      /* */
#endif



/**
  Test ntcreate calls made by xcopy
 */
static BOOL run_xcopy(struct torture_context *torture)
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
				      FIRST_DESIRED_ACCESS, 
				      FILE_ATTRIBUTE_ARCHIVE,
				      NTCREATEX_SHARE_ACCESS_NONE, 
				      NTCREATEX_DISP_OVERWRITE_IF, 
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

static BOOL run_iometer(struct torture_context *torture)
{
	struct smbcli_state *cli;
	const char *fname = "\\iobw.tst";
	int fnum;
	size_t filesize;
	NTSTATUS status;
	char buf[2048];
	int ops;
	BOOL result = False;

	printf("Starting iometer test\n");

	memset(buf, 0, sizeof(buf));

	if (!torture_open_connection(&cli)) {
		return False;
	}

	status = smbcli_getatr(cli->tree, fname, NULL, &filesize, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbcli_getatr failed: %s\n", nt_errstr(status));
		goto done;
	}

	printf("size: %d\n", filesize);

	filesize -= (sizeof(buf) - 1);

	fnum = smbcli_nt_create_full(cli->tree, fname, 0x16,
				     0x2019f, 0, 0x3, 3, 0x42, 0x3);
	if (fnum == -1) {
		printf("open failed: %s\n", smbcli_errstr(cli->tree));
		goto done;
	}

	ops = 0;

	while (True) {
		int i, num_reads, num_writes;

		num_reads = random() % 10;
		num_writes = random() % 3;

		for (i=0; i<num_reads; i++) {
			ssize_t res;
			if (ops++ > torture_numops) {
				result = True;
				goto done;
			}
			res = smbcli_read(cli->tree, fnum, buf,
					  random() % filesize, sizeof(buf));
			if (res != sizeof(buf)) {
				printf("read failed: %s\n",
				       smbcli_errstr(cli->tree));
				goto done;
			}
		}
		for (i=0; i<num_writes; i++) {
			ssize_t res;
			if (ops++ > torture_numops) {
				result = True;
				goto done;
			}
			res = smbcli_write(cli->tree, fnum, 0, buf,
					  random() % filesize, sizeof(buf));
			if (res != sizeof(buf)) {
				printf("read failed: %s\n",
				       smbcli_errstr(cli->tree));
				goto done;
			}
		}
	}

	result = True;
 done:

	if (!torture_close_connection(cli)) {
		printf("close_connection failed: %s\n",
		       smbcli_errstr(cli->tree));
		return False;
	}

	return result;
}

/**
  tries variants of chkpath
 */
static BOOL torture_chkpath_test(struct torture_context *torture)
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
		ret = check_error(__location__, cli, ERRDOS, ERRbadpath, 
				  NT_STATUS_NOT_A_DIRECTORY);
	} else {
		printf("* chkpath on a file should fail\n");
		ret = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_chkpath(cli->tree, "\\chkpath.dir\\bar.txt"))) {
		ret = check_error(__location__, cli, ERRDOS, ERRbadpath, 
				  NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		printf("* chkpath on a non existent file should fail\n");
		ret = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_chkpath(cli->tree, "\\chkpath.dir\\dirxx\\bar.txt"))) {
		ret = check_error(__location__, cli, ERRDOS, ERRbadpath, 
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




NTSTATUS torture_base_init(void)
{
	register_torture_op("BASE-FDPASS", run_fdpasstest, 0);
	register_torture_op("BASE-LOCK1",  torture_locktest1,  0);
	register_torture_op("BASE-LOCK2",  torture_locktest2,  0);
	register_torture_op("BASE-LOCK3",  torture_locktest3,  0);
	register_torture_op("BASE-LOCK4",  torture_locktest4,  0);
	register_torture_op("BASE-LOCK5",  torture_locktest5,  0);
	register_torture_op("BASE-LOCK6",  torture_locktest6,  0);
	register_torture_op("BASE-LOCK7",  torture_locktest7,  0);
	register_torture_op("BASE-UNLINK", torture_unlinktest, 0);
	register_torture_op("BASE-ATTR",   run_attrtest,   0);
	register_torture_op("BASE-TRANS2", run_trans2test, 0);
	register_torture_op("BASE-NEGNOWAIT", run_negprot_nowait, 0);
	register_torture_op("BASE-DIR1",  torture_dirtest1, 0);
	register_torture_op("BASE-DIR2",  torture_dirtest2, 0);
	register_torture_op("BASE-DENY1",  torture_denytest1, 0);
	register_torture_op("BASE-DENY2",  torture_denytest2, 0);
	register_torture_op("BASE-DENY3",  torture_denytest3, 0);
	register_torture_op("BASE-DENYDOS",  torture_denydos_sharing, 0);
	register_torture_op("BASE-NTDENY1",  NULL, torture_ntdenytest1);
	register_torture_op("BASE-NTDENY2",  torture_ntdenytest2, 0);
	register_torture_op("BASE-TCON",  run_tcon_test, 0);
	register_torture_op("BASE-TCONDEV",  run_tcon_devtype_test, 0);
	register_torture_op("BASE-VUID", run_vuidtest, 0);
	register_torture_op("BASE-RW1",  run_readwritetest, 0);
	register_torture_op("BASE-OPEN", run_opentest, 0);
	register_torture_op("BASE-DEFER_OPEN", NULL, run_deferopen);
	register_torture_op("BASE-XCOPY", run_xcopy, 0);
	register_torture_op("BASE-IOMETER", run_iometer, 0);
	register_torture_op("BASE-RENAME", torture_test_rename, 0);
	register_torture_op("BASE-DELETE", torture_test_delete, 0);
	register_torture_op("BASE-PROPERTIES", torture_test_properties, 0);
	register_torture_op("BASE-MANGLE", torture_mangle, 0);
	register_torture_op("BASE-OPENATTR", torture_openattrtest, 0);
	register_torture_op("BASE-CHARSET", torture_charset, 0);
	register_torture_op("BASE-CHKPATH",  torture_chkpath_test, 0);
	register_torture_op("BASE-SECLEAK",  torture_sec_leak, 0);
	register_torture_op("BASE-DISCONNECT",  torture_disconnect, 0);
	register_torture_op("BASE-DELAYWRITE", torture_delay_write, 0);

	register_torture_op("SCAN-CASETABLE", torture_casetable, 0);
	register_torture_op("SCAN-UTABLE", torture_utable, 0);
	register_torture_op("SCAN-SMB", torture_smb_scan, 0);
	register_torture_op("SCAN-ALIASES", torture_trans2_aliases, 0);
	register_torture_op("SCAN-TRANS2", torture_trans2_scan, 0);
	register_torture_op("SCAN-NTTRANS", torture_nttrans_scan, 0);

	return NT_STATUS_OK;
}
