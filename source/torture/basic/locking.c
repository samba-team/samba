/* 
   Unix SMB/CIFS implementation.

   basic locking tests

   Copyright (C) Andrew Tridgell 2000-2004
   Copyright (C) Jeremy Allison 2000-2004
   
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
#include "libcli/raw/libcliraw.h"

/*
  This test checks for two things:

  1) correct support for retaining locks over a close (ie. the server
     must not use posix semantics)
  2) support for lock timeouts
 */
BOOL torture_locktest1(void)
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
		if (!check_error(__location__, cli2, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum3, 0, 4, 0, WRITE_LOCK))) {
		printf("lock2 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__location__, cli2, ERRDOS, ERRlock, 
				 NT_STATUS_FILE_LOCK_CONFLICT)) return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_lock(cli1->tree, fnum1, 5, 9, 0, WRITE_LOCK))) {
		printf("lock1 failed (%s)\n", smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum3, 5, 9, 0, WRITE_LOCK))) {
		printf("lock2 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__location__, cli2, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum3, 0, 4, 0, WRITE_LOCK))) {
		printf("lock2 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__location__, cli2, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum3, 0, 4, 0, WRITE_LOCK))) {
		printf("lock2 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__location__, cli2, ERRDOS, ERRlock, 
				 NT_STATUS_FILE_LOCK_CONFLICT)) return False;
	}

	lock_timeout = (6 + (random() % 20));
	printf("Testing lock timeout with timeout=%u\n", lock_timeout);
	t1 = time(NULL);
	if (NT_STATUS_IS_OK(smbcli_lock(cli2->tree, fnum3, 0, 4, lock_timeout * 1000, WRITE_LOCK))) {
		printf("lock3 succeeded! This is a locking bug\n");
		return False;
	} else {
		if (!check_error(__location__, cli2, ERRDOS, ERRlock, 
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
		if (!check_error(__location__, cli2, ERRDOS, ERRlock, 
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
  This test checks that 

  1) the server supports multiple locking contexts on the one SMB
  connection, distinguished by PID.  

  2) the server correctly fails overlapping locks made by the same PID (this
     goes against POSIX behaviour, which is why it is tricky to implement)

  3) the server denies unlock requests by an incorrect client PID
*/
BOOL torture_locktest2(void)
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
		if (!check_error(__location__, cli, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli->tree, fnum2, 0, 4, 0, WRITE_LOCK))) {
		printf("WRITE lock2 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__location__, cli, ERRDOS, ERRlock, 
				 NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli->tree, fnum2, 0, 4, 0, READ_LOCK))) {
		printf("READ lock2 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__location__, cli, ERRDOS, ERRlock, 
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
		if (!check_error(__location__, cli, 
				 ERRDOS, ERRlock, 
				 NT_STATUS_RANGE_NOT_LOCKED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_unlock(cli->tree, fnum1, 0, 8))) {
		printf("unlock2 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__location__, cli, 
				 ERRDOS, ERRlock, 
				 NT_STATUS_RANGE_NOT_LOCKED)) return False;
	}

	if (NT_STATUS_IS_OK(smbcli_lock(cli->tree, fnum3, 0, 4, 0, WRITE_LOCK))) {
		printf("lock3 succeeded! This is a locking bug\n");
		correct = False;
	} else {
		if (!check_error(__location__, cli, ERRDOS, ERRlock, NT_STATUS_LOCK_NOT_GRANTED)) return False;
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
BOOL torture_locktest3(void)
{
	struct smbcli_state *cli1, *cli2;
	const char *fname = "\\lockt3.lck";
	int fnum1, fnum2, i;
	uint32_t offset;
	BOOL correct = True;
	extern int torture_numops;

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
BOOL torture_locktest4(void)
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
BOOL torture_locktest5(void)
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
BOOL torture_locktest6(void)
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

BOOL torture_locktest7(void)
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
		printf("Failed to create file (%s)\n", __location__);
		goto fail;
	}

	cli1->session->pid = 1;

	if (NT_STATUS_IS_ERR(smbcli_lock(cli1->tree, fnum1, 130, 4, 0, READ_LOCK))) {
		printf("Unable to apply read lock on range 130:4, error was %s (%s)\n", 
		       smbcli_errstr(cli1->tree), __location__);
		goto fail;
	} else {
		printf("pid1 successfully locked range 130:4 for READ\n");
	}

	if (smbcli_read(cli1->tree, fnum1, buf, 130, 4) != 4) {
		printf("pid1 unable to read the range 130:4, error was %s (%s)\n", 
		       smbcli_errstr(cli1->tree), __location__);
		goto fail;
	} else {
		printf("pid1 successfully read the range 130:4\n");
	}

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 130, 4) != 4) {
		printf("pid1 unable to write to the range 130:4, error was %s\n", smbcli_errstr(cli1->tree));
		if (NT_STATUS_V(smbcli_nt_error(cli1->tree)) != NT_STATUS_V(NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT) (%s)\n", 
			       __location__);
			goto fail;
		}
	} else {
		printf("pid1 successfully wrote to the range 130:4 (should be denied) (%s)\n", 
		       __location__);
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
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT) (%s)\n",
			       __location__);
			goto fail;
		}
	} else {
		printf("pid2 successfully wrote to the range 130:4 (should be denied) (%s)\n", 
		       __location__);
		goto fail;
	}

	cli1->session->pid = 1;
	smbcli_unlock(cli1->tree, fnum1, 130, 4);

	if (NT_STATUS_IS_ERR(smbcli_lock(cli1->tree, fnum1, 130, 4, 0, WRITE_LOCK))) {
		printf("Unable to apply write lock on range 130:4, error was %s (%s)\n", 
		       smbcli_errstr(cli1->tree), __location__);
		goto fail;
	} else {
		printf("pid1 successfully locked range 130:4 for WRITE\n");
	}

	if (smbcli_read(cli1->tree, fnum1, buf, 130, 4) != 4) {
		printf("pid1 unable to read the range 130:4, error was %s (%s)\n", 
		       smbcli_errstr(cli1->tree), __location__);
		goto fail;
	} else {
		printf("pid1 successfully read the range 130:4\n");
	}

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 130, 4) != 4) {
		printf("pid1 unable to write to the range 130:4, error was %s (%s)\n", 
		       smbcli_errstr(cli1->tree), __location__);
		goto fail;
	} else {
		printf("pid1 successfully wrote to the range 130:4\n");
	}

	cli1->session->pid = 2;

	if (smbcli_read(cli1->tree, fnum1, buf, 130, 4) != 4) {
		printf("pid2 unable to read the range 130:4, error was %s\n", 
		       smbcli_errstr(cli1->tree));
		if (NT_STATUS_V(smbcli_nt_error(cli1->tree)) != NT_STATUS_V(NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT) (%s)\n",
			       __location__);
			goto fail;
		}
	} else {
		printf("pid2 successfully read the range 130:4 (should be denied) (%s)\n", 
		       __location__);
		goto fail;
	}

	if (smbcli_write(cli1->tree, fnum1, 0, buf, 130, 4) != 4) {
		printf("pid2 unable to write to the range 130:4, error was %s\n", 
		       smbcli_errstr(cli1->tree));
		if (NT_STATUS_V(smbcli_nt_error(cli1->tree)) != NT_STATUS_V(NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT) (%s)\n",
			       __location__);
			goto fail;
		}
	} else {
		printf("pid2 successfully wrote to the range 130:4 (should be denied) (%s)\n", 
		       __location__);
		goto fail;
	}

	printf("Testing truncate of locked file.\n");

	fnum2 = smbcli_open(cli1->tree, fname, O_RDWR|O_TRUNC, DENY_NONE);

	if (fnum2 == -1) {
		printf("Unable to truncate locked file (%s)\n", __location__);
		correct = False;
		goto fail;
	} else {
		printf("Truncated locked file.\n");
	}

	if (NT_STATUS_IS_ERR(smbcli_getatr(cli1->tree, fname, NULL, &size, NULL))) {
		printf("getatr failed (%s) (%s)\n", smbcli_errstr(cli1->tree), __location__);
		correct = False;
		goto fail;
	}

	if (size != 0) {
		printf("Unable to truncate locked file. Size was %u (%s)\n", size, __location__);
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

