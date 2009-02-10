/* 
   Unix SMB/CIFS implementation.
   test suite for various lock operations
   Copyright (C) Andrew Tridgell 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "system/time.h"
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define BASEDIR "\\testlock"


/*
  test SMBlock and SMBunlock ops
*/
static bool test_lock(struct torture_context *tctx, struct smbcli_state *cli)
{
	union smb_lock io;
	NTSTATUS status;
	bool ret = true;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	printf("Testing RAW_LOCK_LOCK\n");
	io.generic.level = RAW_LOCK_LOCK;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}

	printf("Trying 0/0 lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.file.fnum = fnum;
	io.lock.in.count = 0;
	io.lock.in.offset = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying 0/1 lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.file.fnum = fnum;
	io.lock.in.count = 1;
	io.lock.in.offset = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying 0xEEFFFFFF lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.file.fnum = fnum;
	io.lock.in.count = 4000;
	io.lock.in.offset = 0xEEFFFFFF;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying 0xEF000000 lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.file.fnum = fnum;
	io.lock.in.count = 4000;
	io.lock.in.offset = 0xEEFFFFFF;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying max lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.file.fnum = fnum;
	io.lock.in.count = 4000;
	io.lock.in.offset = 0xEF000000;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying wrong pid unlock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.file.fnum = fnum;
	io.lock.in.count = 4002;
	io.lock.in.offset = 10001;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);
	cli->session->pid--;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test locking&X ops
*/
static bool test_lockx(struct torture_context *tctx, struct smbcli_state *cli)
{
	union smb_lock io;
	struct smb_lock_entry lock[1];
	NTSTATUS status;
	bool ret = true;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	printf("Testing RAW_LOCK_LOCKX\n");
	io.generic.level = RAW_LOCK_LOCKX;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}

	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 10;
	lock[0].count = 1;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);


	printf("Trying 0xEEFFFFFF lock\n");
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].count = 4000;
	lock[0].offset = 0xEEFFFFFF;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);
	lock[0].pid--;
	io.lockx.in.ulock_cnt = 1;
	io.lockx.in.lock_cnt = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying 0xEF000000 lock\n");
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].count = 4000;
	lock[0].offset = 0xEF000000;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	lock[0].pid--;
	io.lockx.in.ulock_cnt = 1;
	io.lockx.in.lock_cnt = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying zero lock\n");
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].count = 0;
	lock[0].offset = ~0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid--;
	io.lockx.in.ulock_cnt = 1;
	io.lockx.in.lock_cnt = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying max lock\n");
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].count = 0;
	lock[0].offset = ~0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid--;
	io.lockx.in.ulock_cnt = 1;
	io.lockx.in.lock_cnt = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying 2^63\n");
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].count = 1;
	lock[0].offset = 1;
	lock[0].offset <<= 63;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);
	lock[0].pid--;
	io.lockx.in.ulock_cnt = 1;
	io.lockx.in.lock_cnt = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying 2^63 - 1\n");
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].count = 1;
	lock[0].offset = 1;
	lock[0].offset <<= 63;
	lock[0].offset--;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	lock[0].pid--;
	io.lockx.in.ulock_cnt = 1;
	io.lockx.in.lock_cnt = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying max lock 2\n");
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].count = 1;
	lock[0].offset = ~0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid++;
	lock[0].count = 2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	lock[0].pid--;
	io.lockx.in.ulock_cnt = 1;
	io.lockx.in.lock_cnt = 0;
	lock[0].count = 1;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test high pid
*/
static bool test_pidhigh(struct torture_context *tctx, 
						 struct smbcli_state *cli)
{
	union smb_lock io;
	struct smb_lock_entry lock[1];
	NTSTATUS status;
	bool ret = true;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	uint8_t c = 1;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	printf("Testing high pid\n");
	io.generic.level = RAW_LOCK_LOCKX;

	cli->session->pid = 1;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}

	if (smbcli_write(cli->tree, fnum, 0, &c, 0, 1) != 1) {
		printf("Failed to write 1 byte - %s\n", smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}

	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 0;
	lock[0].count = 0xFFFFFFFF;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (smbcli_read(cli->tree, fnum, &c, 0, 1) != 1) {
		printf("Failed to read 1 byte - %s\n", smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}

	cli->session->pid = 2;

	if (smbcli_read(cli->tree, fnum, &c, 0, 1) == 1) {
		printf("pid is incorrect handled for read with lock!\n");
		ret = false;
		goto done;
	}

	cli->session->pid = 0x10001;

	if (smbcli_read(cli->tree, fnum, &c, 0, 1) != 1) {
		printf("High pid is used on this server!\n");
		ret = false;
	} else {
		printf("High pid is not used on this server (correct)\n");
	}

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test locking&X async operation
*/
static bool test_async(struct torture_context *tctx, 
					   struct smbcli_state *cli)
{
	struct smbcli_session *session;
	struct smb_composite_sesssetup setup;
	struct smbcli_tree *tree;
	union smb_tcon tcon;
	const char *host, *share;
	union smb_lock io;
	struct smb_lock_entry lock[2];
	NTSTATUS status;
	bool ret = true;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	time_t t;
	struct smbcli_request *req;
	struct smbcli_session_options options;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	lp_smbcli_session_options(tctx->lp_ctx, &options);

	printf("Testing LOCKING_ANDX_CANCEL_LOCK\n");
	io.generic.level = RAW_LOCK_LOCKX;

	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}

	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	t = time(NULL);

	printf("testing cancel by CANCEL_LOCK\n");

	/* setup a timed lock */
	io.lockx.in.timeout = 10000;
	req = smb_raw_lock_send(cli->tree, &io);
	if (req == NULL) {
		printf("Failed to setup timed lock (%s)\n", __location__);
		ret = false;
		goto done;
	}

	/* cancel the wrong range */
	lock[0].offset = 0;
	io.lockx.in.timeout = 0;
	io.lockx.in.mode = LOCKING_ANDX_CANCEL_LOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRcancelviolation));

	/* cancel with the wrong bits set */
	lock[0].offset = 100;
	io.lockx.in.timeout = 0;
	io.lockx.in.mode = LOCKING_ANDX_CANCEL_LOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRcancelviolation));

	/* cancel the right range */
	lock[0].offset = 100;
	io.lockx.in.timeout = 0;
	io.lockx.in.mode = LOCKING_ANDX_CANCEL_LOCK | LOCKING_ANDX_LARGE_FILES;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* receive the failed lock request */
	status = smbcli_request_simple_recv(req);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	if (time(NULL) > t+2) {
		printf("lock cancel was not immediate (%s)\n", __location__);
		ret = false;
		goto done;
	}

	printf("testing cancel by unlock\n");
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.timeout = 5000;
	req = smb_raw_lock_send(cli->tree, &io);
	if (req == NULL) {
		printf("Failed to setup timed lock (%s)\n", __location__);
		ret = false;
		goto done;
	}

	io.lockx.in.ulock_cnt = 1;
	io.lockx.in.lock_cnt = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	t = time(NULL);
	status = smbcli_request_simple_recv(req);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (time(NULL) > t+2) {
		printf("lock cancel by unlock was not immediate (%s) - took %d secs\n", 
		       __location__, (int)(time(NULL)-t));
		ret = false;
		goto done;
	}

	printf("testing cancel by close\n");
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	t = time(NULL);
	io.lockx.in.timeout = 10000;
	req = smb_raw_lock_send(cli->tree, &io);
	if (req == NULL) {
		printf("Failed to setup timed lock (%s)\n", __location__);
		ret = false;
		goto done;
	}

	status = smbcli_close(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smbcli_request_simple_recv(req);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	if (time(NULL) > t+2) {
		printf("lock cancel by close was not immediate (%s)\n", __location__);
		ret = false;
		goto done;
	}

	printf("create a new sessions\n");
	session = smbcli_session_init(cli->transport, tctx, false, options);
	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities;
	setup.in.workgroup = lp_workgroup(tctx->lp_ctx);
	setup.in.credentials = cmdline_credentials;
	setup.in.gensec_settings = lp_gensec_settings(tctx, tctx->lp_ctx);
	status = smb_composite_sesssetup(session, &setup);
	CHECK_STATUS(status, NT_STATUS_OK);
	session->vuid = setup.out.vuid;

	printf("create new tree context\n");
	share = torture_setting_string(tctx, "share", NULL);
	host  = torture_setting_string(tctx, "host", NULL);
	tree = smbcli_tree_init(session, tctx, false);
	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = 0;
	tcon.tconx.in.password = data_blob(NULL, 0);
	tcon.tconx.in.path = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	tcon.tconx.in.device = "A:";
	status = smb_raw_tcon(tree, tctx, &tcon);
	CHECK_STATUS(status, NT_STATUS_OK);
	tree->tid = tcon.tconx.out.tid;

	printf("testing cancel by exit\n");
	fname = BASEDIR "\\test_exit.txt";
	fnum = smbcli_open(tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to reopen %s - %s\n", fname, smbcli_errstr(tree));
		ret = false;
		goto done;
	}
	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = session->pid;
	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	status = smb_raw_lock(tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	io.lockx.in.timeout = 10000;
	t = time(NULL);
	req = smb_raw_lock_send(tree, &io);
	if (req == NULL) {
		printf("Failed to setup timed lock (%s)\n", __location__);
		ret = false;
		goto done;
	}

	status = smb_raw_exit(session);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smbcli_request_simple_recv(req);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	if (time(NULL) > t+2) {
		printf("lock cancel by exit was not immediate (%s)\n", __location__);
		ret = false;
		goto done;
	}

	printf("testing cancel by ulogoff\n");
	fname = BASEDIR "\\test_ulogoff.txt";
	fnum = smbcli_open(tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to reopen %s - %s\n", fname, smbcli_errstr(tree));
		ret = false;
		goto done;
	}
	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = session->pid;
	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	status = smb_raw_lock(tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	io.lockx.in.timeout = 10000;
	t = time(NULL);
	req = smb_raw_lock_send(tree, &io);
	if (req == NULL) {
		printf("Failed to setup timed lock (%s)\n", __location__);
		ret = false;
		goto done;
	}

	status = smb_raw_ulogoff(session);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smbcli_request_simple_recv(req);
	if (NT_STATUS_EQUAL(NT_STATUS_FILE_LOCK_CONFLICT, status)) {
		printf("lock not canceled by ulogoff - %s (ignored because of vfs_vifs fails it)\n",
			nt_errstr(status));
		smb_tree_disconnect(tree);
		smb_raw_exit(session);
		goto done;
	}
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	if (time(NULL) > t+2) {
		printf("lock cancel by ulogoff was not immediate (%s)\n", __location__);
		ret = false;
		goto done;
	}

	printf("testing cancel by tdis\n");
	tree->session = cli->session;

	fname = BASEDIR "\\test_tdis.txt";
	fnum = smbcli_open(tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to reopen %s - %s\n", fname, smbcli_errstr(tree));
		ret = false;
		goto done;
	}
	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_lock(tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	io.lockx.in.timeout = 10000;
	t = time(NULL);
	req = smb_raw_lock_send(tree, &io);
	if (req == NULL) {
		printf("Failed to setup timed lock (%s)\n", __location__);
		ret = false;
		goto done;
	}

	status = smb_tree_disconnect(tree);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smbcli_request_simple_recv(req);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	if (time(NULL) > t+2) {
		printf("lock cancel by tdis was not immediate (%s)\n", __location__);
		ret = false;
		goto done;
	}

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}

/*
  test NT_STATUS_LOCK_NOT_GRANTED vs. NT_STATUS_FILE_LOCK_CONFLICT
*/
static bool test_errorcode(struct torture_context *tctx, 
						   struct smbcli_state *cli)
{
	union smb_lock io;
	union smb_open op;
	struct smb_lock_entry lock[2];
	NTSTATUS status;
	bool ret = true;
	int fnum, fnum2;
	const char *fname;
	struct smbcli_request *req;
	time_t start;
	int t;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	printf("Testing LOCK_NOT_GRANTED vs. FILE_LOCK_CONFLICT\n");

	printf("testing with timeout = 0\n");
	fname = BASEDIR "\\test0.txt";
	t = 0;

	/*
	 * the first run is with t = 0,
	 * the second with t > 0 (=1)
	 */
next_run:
	/* 
	 * use the DENY_DOS mode, that creates two fnum's of one low-level file handle,
	 * this demonstrates that the cache is per fnum
	 */
	op.openx.level = RAW_OPEN_OPENX;
	op.openx.in.fname = fname;
	op.openx.in.flags = OPENX_FLAGS_ADDITIONAL_INFO;
	op.openx.in.open_mode = OPENX_MODE_ACCESS_RDWR | OPENX_MODE_DENY_DOS;
	op.openx.in.open_func = OPENX_OPEN_FUNC_OPEN | OPENX_OPEN_FUNC_CREATE;
	op.openx.in.search_attrs = 0;
	op.openx.in.file_attrs = 0;
	op.openx.in.write_time = 0;
	op.openx.in.size = 0;
	op.openx.in.timeout = 0;

	status = smb_raw_open(cli->tree, tctx, &op);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = op.openx.out.file.fnum;

	status = smb_raw_open(cli->tree, tctx, &op);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = op.openx.out.file.fnum;

	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = t;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * demonstrate that the first conflicting lock on each handle give LOCK_NOT_GRANTED
	 * this also demonstrates that the error code cache is per file handle
	 * (LOCK_NOT_GRANTED is only be used when timeout is 0!)
	 */
	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));

	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));

	/* demonstrate that each following conflict gives FILE_LOCK_CONFLICT */
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	/* demonstrate that the smbpid doesn't matter */
	lock[0].pid++;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	lock[0].pid--;

	/* 
	 * demonstrate the a successful lock with count = 0 and the same offset,
	 * doesn't reset the error cache
	 */
	lock[0].offset = 100;
	lock[0].count = 0;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	/* 
	 * demonstrate the a successful lock with count = 0 and outside the locked range,
	 * doesn't reset the error cache
	 */
	lock[0].offset = 110;
	lock[0].count = 0;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	lock[0].offset = 99;
	lock[0].count = 0;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	/* demonstrate that a changing count doesn't reset the error cache */
	lock[0].offset = 100;
	lock[0].count = 5;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	lock[0].offset = 100;
	lock[0].count = 15;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	/* 
	 * demonstrate the a lock with count = 0 and inside the locked range,
	 * fails and resets the error cache
	 */
	lock[0].offset = 101;
	lock[0].count = 0;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	/* demonstrate the a changing offset, resets the error cache */
	lock[0].offset = 105;
	lock[0].count = 10;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	lock[0].offset = 95;
	lock[0].count = 9;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	/* 
	 * demonstrate the a successful lock in a different range, 
	 * doesn't reset the cache, the failing lock on the 2nd handle
	 * resets the resets the cache
	 */
	lock[0].offset = 120;
	lock[0].count = 15;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));

	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.file.fnum = fnum;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	io.lockx.in.file.fnum = fnum2;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, (t?NT_STATUS_FILE_LOCK_CONFLICT:NT_STATUS_LOCK_NOT_GRANTED));
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	/* end of the loop */
	if (t == 0) {
		smb_raw_exit(cli->session);
		printf("testing with timeout > 0 (=1)\n");
		fname = BASEDIR "\\test1.txt";
		t = 1;
		goto next_run;
	}

	/*
	 * the following 3 test sections demonstrate that
	 * the cache is only set when the error is reported
	 * to the client (after the timeout went by)
	 */
	smb_raw_exit(cli->session);
	printf("testing a conflict while a lock is pending\n");
	fname = BASEDIR "\\test2.txt";
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to reopen %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}
	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	start = time(NULL);
	io.lockx.in.timeout = 1000;
	req = smb_raw_lock_send(cli->tree, &io);
	if (req == NULL) {
		printf("Failed to setup timed lock (%s)\n", __location__);
		ret = false;
		goto done;
	}

	io.lockx.in.timeout = 0;
	lock[0].offset = 105;
	lock[0].count = 10;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	status = smbcli_request_simple_recv(req);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	if (time(NULL) < start+1) {
		printf("lock comes back to early (%s)\n", __location__);
		ret = false;
		goto done;
	}

	smbcli_close(cli->tree, fnum);
	fname = BASEDIR "\\test3.txt";
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to reopen %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}
	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	start = time(NULL);
	io.lockx.in.timeout = 1000;
	req = smb_raw_lock_send(cli->tree, &io);
	if (req == NULL) {
		printf("Failed to setup timed lock (%s)\n", __location__);
		ret = false;
		goto done;
	}

	io.lockx.in.timeout = 0;
	lock[0].offset = 105;
	lock[0].count = 10;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	status = smbcli_request_simple_recv(req);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	lock[0].offset = 100;
	lock[0].count = 10;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	if (time(NULL) < start+1) {
		printf("lock comes back to early (%s)\n", __location__);
		ret = false;
		goto done;
	}

	smbcli_close(cli->tree, fnum);
	fname = BASEDIR "\\test4.txt";
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to reopen %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}
	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	start = time(NULL);
	io.lockx.in.timeout = 1000;
	req = smb_raw_lock_send(cli->tree, &io);
	if (req == NULL) {
		printf("Failed to setup timed lock (%s)\n", __location__);
		ret = false;
		goto done;
	}

	io.lockx.in.timeout = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	status = smbcli_request_simple_recv(req);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	if (time(NULL) < start+1) {
		printf("lock comes back to early (%s)\n", __location__);
		ret = false;
		goto done;
	}

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test LOCKING_ANDX_CHANGE_LOCKTYPE
*/
static bool test_changetype(struct torture_context *tctx, 
							struct smbcli_state *cli)
{
	union smb_lock io;
	struct smb_lock_entry lock[2];
	NTSTATUS status;
	bool ret = true;
	int fnum;
	uint8_t c = 0;
	const char *fname = BASEDIR "\\test.txt";

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	printf("Testing LOCKING_ANDX_CHANGE_LOCKTYPE\n");
	io.generic.level = RAW_LOCK_LOCKX;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = false;
		goto done;
	}

	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.file.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_SHARED_LOCK;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 100;
	lock[0].count = 10;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (smbcli_write(cli->tree, fnum, 0, &c, 100, 1) == 1) {
		printf("allowed write on read locked region (%s)\n", __location__);
		ret = false;
		goto done;
	}

	/* windows server don't seem to support this */
	io.lockx.in.mode = LOCKING_ANDX_CHANGE_LOCKTYPE;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRnoatomiclocks));

	if (smbcli_write(cli->tree, fnum, 0, &c, 100, 1) == 1) {
		printf("allowed write after lock change (%s)\n", __location__);
		ret = false;
		goto done;
	}

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/* 
   basic testing of lock calls
*/
struct torture_suite *torture_raw_lock(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "LOCK");

	torture_suite_add_1smb_test(suite, "lockx", test_lockx);
	torture_suite_add_1smb_test(suite, "lock", test_lock);
	torture_suite_add_1smb_test(suite, "pidhigh", test_pidhigh);
	torture_suite_add_1smb_test(suite, "async", test_async);
	torture_suite_add_1smb_test(suite, "errorcode", test_errorcode);
	torture_suite_add_1smb_test(suite, "changetype", test_changetype);

	return suite;
}
