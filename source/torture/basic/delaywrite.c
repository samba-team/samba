/* 
   Unix SMB/CIFS implementation.

   test suite for delayed write update 

   Copyright (C) Volker Lendecke 2004
   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Jeremy Allison 2004
   
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

#define BASEDIR "\\delaywrite"

static bool test_delayed_write_update(struct torture_context *tctx, struct smbcli_state *cli)
{
	union smb_fileinfo finfo1, finfo2;
	const char *fname = BASEDIR "\\torture_file.txt";
	NTSTATUS status;
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	int used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		torture_comment(tctx, "Failed to open %s\n", fname);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	
	torture_comment(tctx, "Initial write time %s\n", 
	       nt_time_string(tctx, finfo1.basic_info.out.write_time));

	/* 3 second delay to ensure we get past any 2 second time
	   granularity (older systems may have that) */
	msleep(3 * msec);

	written =  smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);

	if (written != 1) {
		torture_comment(tctx, "write failed - wrote %d bytes (%s)\n", 
		       (int)written, __location__);
		return false;
	}

	start = timeval_current();
	end = timeval_add(&start, (120*sec), 0);
	while (!timeval_expired(&end)) {
		status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
			ret = false;
			break;
		}
		torture_comment(tctx, "write time %s\n", 
		       nt_time_string(tctx, finfo2.basic_info.out.write_time));
		if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			if (diff < (2 * sec * 0.75)) { /* 0.75 to cope with vmware timing */
				torture_comment(tctx, "Server updated write_time after %.2f seconds"
						"(1 sec == %.2f)(wrong!)\n",
						diff, sec);
				ret = false;
				break;
			}

			torture_comment(tctx, "Server updated write_time after %.2f seconds"
					"(1 sec == %.2f)(correct)\n",
					diff, sec);
			break;
		}
		fflush(stdout);
		msleep(1 * msec);
	}
	
	if (finfo1.basic_info.out.write_time == finfo2.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write time (wrong!)\n");
		ret = false;
	}


	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/* 
 * Do as above, but using 2 connections.
 */

static bool test_delayed_write_update2(struct torture_context *tctx, struct smbcli_state *cli, 
									   struct smbcli_state *cli2)
{
	union smb_fileinfo finfo1, finfo2;
	const char *fname = BASEDIR "\\torture_file.txt";
	NTSTATUS status;
	int fnum1 = -1;
	int fnum2 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	int used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;
	union smb_flush flsh;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		torture_comment(tctx, "Failed to open %s\n", fname);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	
	torture_comment(tctx, "Initial write time %s\n", 
	       nt_time_string(tctx, finfo1.basic_info.out.write_time));

	/* 3 second delay to ensure we get past any 2 second time
	   granularity (older systems may have that) */
	msleep(3 * msec);

	{
		/* Try using setfileinfo instead of write to update write time. */
		union smb_setfileinfo sfinfo;
		time_t t_set = time(NULL);
		sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFO;
		sfinfo.basic_info.in.file.fnum = fnum1;
		sfinfo.basic_info.in.create_time = finfo1.basic_info.out.create_time;
		sfinfo.basic_info.in.access_time = finfo1.basic_info.out.access_time;

		/* I tried this with both + and - ve to see if it makes a different.
		   It doesn't - once the filetime is set via setfileinfo it stays that way. */
#if 1
		unix_to_nt_time(&sfinfo.basic_info.in.write_time, t_set - 30000);
#else
		unix_to_nt_time(&sfinfo.basic_info.in.write_time, t_set + 30000);
#endif
		sfinfo.basic_info.in.change_time = finfo1.basic_info.out.change_time;
		sfinfo.basic_info.in.attrib = finfo1.basic_info.out.attrib;

		status = smb_raw_setfileinfo(cli->tree, &sfinfo);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("sfileinfo failed: %s\n", nt_errstr(status)));
			return false;
		}
	}

	finfo2.basic_info.in.file.path = fname;
	
	status = smb_raw_pathinfo(cli2->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	torture_comment(tctx, "write time %s\n",
	       nt_time_string(tctx, finfo2.basic_info.out.write_time));

	if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
		torture_comment(tctx, "Server updated write_time (correct)\n");
	} else {
		torture_comment(tctx, "Server did not update write time (wrong!)\n");
		ret = false;
	}

	/* Now try a write to see if the write time gets reset. */

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	
	torture_comment(tctx, "Modified write time %s\n", 
	       nt_time_string(tctx, finfo1.basic_info.out.write_time));


	torture_comment(tctx, "Doing a 10 byte write to extend the file and see if this changes the last write time.\n");

	written =  smbcli_write(cli->tree, fnum1, 0, "0123456789", 1, 10);

	if (written != 10) {
		torture_comment(tctx, "write failed - wrote %d bytes (%s)\n", 
		       (int)written, __location__);
		return false;
	}

	/* Just to prove to tridge that the an smbflush has no effect on
	   the write time :-). The setfileinfo IS STICKY. JRA. */

	torture_comment(tctx, "Doing flush after write\n");

	flsh.flush.level	= RAW_FLUSH_FLUSH;
	flsh.flush.in.file.fnum = fnum1;
	status = smb_raw_flush(cli->tree, &flsh);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smbflush failed: %s\n", nt_errstr(status)));
		return false;
	}

	/* Once the time was set using setfileinfo then it stays set - writes
	   don't have any effect. But make sure. */
	start = timeval_current();
	end = timeval_add(&start, (15*sec), 0);
	while (!timeval_expired(&end)) {
		status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
			ret = false;
			break;
		}
		torture_comment(tctx, "write time %s\n", 
		       nt_time_string(tctx, finfo2.basic_info.out.write_time));
		if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_comment(tctx, "Server updated write_time after %.2f seconds"
					"(1sec == %.2f) (wrong!)\n",
					diff, sec);
			ret = false;
			break;
		}
		fflush(stdout);
		msleep(1 * msec);
	}
	
	if (finfo1.basic_info.out.write_time == finfo2.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write time (correct)\n");
	}

	fnum2 = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		torture_comment(tctx, "Failed to open %s\n", fname);
		return false;
	}
	
	torture_comment(tctx, "Doing a 10 byte write to extend the file via second fd and see if this changes the last write time.\n");

	written =  smbcli_write(cli->tree, fnum2, 0, "0123456789", 11, 10);

	if (written != 10) {
		torture_comment(tctx, "write failed - wrote %d bytes (%s)\n", 
		       (int)written, __location__);
		return false;
	}

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	torture_comment(tctx, "write time %s\n", 
	       nt_time_string(tctx, finfo2.basic_info.out.write_time));
	if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
		torture_comment(tctx, "Server updated write_time (wrong!)\n");
		ret = false;
	}

	torture_comment(tctx, "Closing the first fd to see if write time updated.\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	torture_comment(tctx, "Doing a 10 byte write to extend the file via second fd and see if this changes the last write time.\n");

	written =  smbcli_write(cli->tree, fnum2, 0, "0123456789", 21, 10);

	if (written != 10) {
		torture_comment(tctx, "write failed - wrote %d bytes (%s)\n", 
		       (int)written, __location__);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum2;
	finfo2 = finfo1;
	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	torture_comment(tctx, "write time %s\n", 
	       nt_time_string(tctx, finfo2.basic_info.out.write_time));
	if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
		torture_comment(tctx, "Server updated write_time (wrong!)\n");
		ret = false;
	}

	/* Once the time was set using setfileinfo then it stays set - writes
	   don't have any effect. But make sure. */
	start = timeval_current();
	end = timeval_add(&start, (15*sec), 0);
	while (!timeval_expired(&end)) {
		status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
			ret = false;
			break;
		}
		torture_comment(tctx, "write time %s\n", 
		       nt_time_string(tctx, finfo2.basic_info.out.write_time));
		if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_comment(tctx, "Server updated write_time after %.2f seconds "
					"(1sec == %.2f) (wrong!)\n",
					diff, sec);
			ret = false;
			break;
		}
		fflush(stdout);
		msleep(1 * msec);
	}
	
	if (finfo1.basic_info.out.write_time == finfo2.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write time (correct)\n");
	}

	torture_comment(tctx, "Closing second fd to see if write time updated.\n");

	smbcli_close(cli->tree, fnum2);
	fnum2 = -1;

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	if (fnum1 == -1) {
		torture_comment(tctx, "Failed to open %s\n", fname);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	
	torture_comment(tctx, "Second open initial write time %s\n", 
	       nt_time_string(tctx, finfo1.basic_info.out.write_time));

	msleep(10 * msec);
	torture_comment(tctx, "Doing a 10 byte write to extend the file to see if this changes the last write time.\n");

	written =  smbcli_write(cli->tree, fnum1, 0, "0123456789", 31, 10);

	if (written != 10) {
		torture_comment(tctx, "write failed - wrote %d bytes (%s)\n", 
		       (int)written, __location__);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;
	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	torture_comment(tctx, "write time %s\n", 
	       nt_time_string(tctx, finfo2.basic_info.out.write_time));
	if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
		torture_comment(tctx, "Server updated write_time (wrong!)\n");
		ret = false;
	}

	/* Now the write time should be updated again */
	start = timeval_current();
	end = timeval_add(&start, (15*sec), 0);
	while (!timeval_expired(&end)) {
		status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
			ret = false;
			break;
		}
		torture_comment(tctx, "write time %s\n", 
		       nt_time_string(tctx, finfo2.basic_info.out.write_time));
		if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			if (diff < (2 * sec * 0.75)) { /* 0.75 to cope with vmware timing */
				torture_comment(tctx, "Server updated write_time after %.2f seconds"
						"(1sec == %.2f) (wrong!)\n",
						diff, sec);
				ret = false;
				break;
			}

			torture_comment(tctx, "Server updated write_time after %.2f seconds"
					"(1sec == %.2f) (correct)\n",
					diff, sec);
			break;
		}
		fflush(stdout);
		msleep(1*msec);
	}
	
	if (finfo1.basic_info.out.write_time == finfo2.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write time (wrong!)\n");
		ret = false;
	}


	/* One more test to do. We should read the filetime via findfirst on the
	   second connection to ensure it's the same. This is very easy for a Windows
	   server but a bastard to get right on a POSIX server. JRA. */

	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}


/* Windows does obviously not update the stat info during a write call. I
 * *think* this is the problem causing a spurious Excel 2003 on XP error
 * message when saving a file. Excel does a setfileinfo, writes, and then does
 * a getpath(!)info. Or so... For Samba sometimes it displays an error message
 * that the file might have been changed in between. What i've been able to
 * trace down is that this happens if the getpathinfo after the write shows a
 * different last write time than the setfileinfo showed. This is really
 * nasty....
 */

static bool test_finfo_after_write(struct torture_context *tctx, struct smbcli_state *cli, 
								   struct smbcli_state *cli2)
{
	union smb_fileinfo finfo1, finfo2;
	const char *fname = BASEDIR "\\torture_file.txt";
	NTSTATUS status;
	int fnum1 = -1;
	int fnum2;
	bool ret = true;
	ssize_t written;
	int used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": fileinfo failed: %s", nt_errstr(status));
		goto done;
	}

	msleep(1 * msec);

	written =  smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);

	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	fnum2 = smbcli_open(cli2->tree, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		torture_result(tctx, TORTURE_FAIL, __location__": failed to open 2nd time - %s", 
		       smbcli_errstr(cli2->tree));
		ret = false;
		goto done;
	}
	
	written =  smbcli_write(cli2->tree, fnum2, 0, "x", 0, 1);
	
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", 
		       (int)written);
		ret = false;
		goto done;
	}
	
	finfo2.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo2.basic_info.in.file.path = fname;
	
	status = smb_raw_pathinfo(cli2->tree, tctx, &finfo2);
	
	if (!NT_STATUS_IS_OK(status)) {
		torture_result(tctx, TORTURE_FAIL, __location__": fileinfo failed: %s", 
			  nt_errstr(status));
		ret = false;
		goto done;
	}
	
	if (finfo1.basic_info.out.create_time !=
	    finfo2.basic_info.out.create_time) {
		torture_result(tctx, TORTURE_FAIL, __location__": create_time changed");
		ret = false;
		goto done;
	}
	
	if (finfo1.basic_info.out.access_time !=
	    finfo2.basic_info.out.access_time) {
		torture_result(tctx, TORTURE_FAIL, __location__": access_time changed");
		ret = false;
		goto done;
	}
	
	if (finfo1.basic_info.out.write_time !=
	    finfo2.basic_info.out.write_time) {
		torture_result(tctx, TORTURE_FAIL, __location__": write_time changed:\n"
					   "write time conn 1 = %s, conn 2 = %s", 
		       nt_time_string(tctx, finfo1.basic_info.out.write_time),
		       nt_time_string(tctx, finfo2.basic_info.out.write_time));
		ret = false;
		goto done;
	}
	
	if (finfo1.basic_info.out.change_time !=
	    finfo2.basic_info.out.change_time) {
		torture_result(tctx, TORTURE_FAIL, __location__": change_time changed");
		ret = false;
		goto done;
	}
	
	/* One of the two following calls updates the qpathinfo. */
	
	/* If you had skipped the smbcli_write on fnum2, it would
	 * *not* have updated the stat on disk */
	
	smbcli_close(cli2->tree, fnum2);
	cli2 = NULL;

	/* This call is only for the people looking at ethereal :-) */
	finfo2.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo2.basic_info.in.file.path = fname;

	status = smb_raw_pathinfo(cli->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		torture_result(tctx, TORTURE_FAIL, __location__": fileinfo failed: %s", nt_errstr(status));
		ret = false;
		goto done;
	}

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

#define COMPARE_WRITE_TIME_CMP(given, correct, cmp) do { \
	NTTIME g = (given).basic_info.out.write_time; \
	NTTIME c = (correct).basic_info.out.write_time; \
	if (g cmp c) { \
		torture_result(tctx, TORTURE_FAIL, __location__": wrong write_time (%s)%s(%llu) %s (%s)%s(%llu)", \
				#given, nt_time_string(tctx, g), (unsigned long long)g, \
				#cmp, #correct, nt_time_string(tctx, c), (unsigned long long)c); \
		ret = false; \
		goto done; \
	} \
} while (0)
#define COMPARE_WRITE_TIME_EQUAL(given,correct) \
	COMPARE_WRITE_TIME_CMP(given,correct,!=)
#define COMPARE_WRITE_TIME_GREATER(given,correct) \
	COMPARE_WRITE_TIME_CMP(given,correct,<=)
#define COMPARE_WRITE_TIME_LESS(given,correct) \
	COMPARE_WRITE_TIME_CMP(given,correct,>=)

#define COMPARE_ACCESS_TIME_CMP(given, correct, cmp) do { \
	NTTIME g = (given).basic_info.out.access_time; \
	NTTIME c = (correct).basic_info.out.access_time; \
	if (g cmp c) { \
		torture_result(tctx, TORTURE_FAIL, __location__": wrong access_time (%s)%s %s (%s)%s", \
				#given, nt_time_string(tctx, g), \
				#cmp, #correct, nt_time_string(tctx, c)); \
		ret = false; \
		goto done; \
	} \
} while (0)
#define COMPARE_ACCESS_TIME_EQUAL(given,correct) \
	COMPARE_ACCESS_TIME_CMP(given,correct,!=)
#define COMPARE_ACCESS_TIME_GREATER(given,correct) \
	COMPARE_ACCESS_TIME_CMP(given,correct,<=)
#define COMPARE_ACCESS_TIME_LESS(given,correct) \
	COMPARE_ACCESS_TIME_CMP(given,correct,>=)

#define COMPARE_BOTH_TIMES_EQUAL(given,correct) do { \
	COMPARE_ACCESS_TIME_EQUAL(given,correct); \
	COMPARE_WRITE_TIME_EQUAL(given,correct); \
} while (0)
#define COMPARE_BOTH_TIMES_GEATER(given,correct) do { \
	COMPARE_ACCESS_TIME_GREATER(given,correct); \
	COMPARE_WRITE_TIME_GREATER(given,correct); \
} while (0)
#define COMPARE_BOTH_TIMES_LESS(given,correct) do { \
	COMPARE_ACCESS_TIME_LESS(given,correct); \
	COMPARE_WRITE_TIME_LESS(given,correct); \
} while (0)

#define GET_INFO_FILE(finfo) do { \
	NTSTATUS _status; \
	_status = smb_raw_fileinfo(cli->tree, tctx, &finfo); \
	if (!NT_STATUS_IS_OK(_status)) { \
		ret = false; \
		torture_result(tctx, TORTURE_FAIL, __location__": fileinfo failed: %s", \
			       nt_errstr(_status)); \
		goto done; \
	} \
	torture_comment(tctx, "fileinfo: Access(%s) Write(%s)\n", \
			nt_time_string(tctx, finfo.basic_info.out.access_time), \
			nt_time_string(tctx, finfo.basic_info.out.write_time)); \
} while (0)
#define GET_INFO_PATH(pinfo) do { \
	NTSTATUS _status; \
	_status = smb_raw_pathinfo(cli2->tree, tctx, &pinfo); \
	if (!NT_STATUS_IS_OK(_status)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": pathinfo failed: %s", \
			       nt_errstr(_status)); \
		ret = false; \
		goto done; \
	} \
	torture_comment(tctx, "pathinfo: Access(%s) Write(%s)\n", \
			nt_time_string(tctx, pinfo.basic_info.out.access_time), \
			nt_time_string(tctx, pinfo.basic_info.out.write_time)); \
} while (0)
#define GET_INFO_BOTH(finfo,pinfo) do { \
	GET_INFO_FILE(finfo); \
	GET_INFO_PATH(pinfo); \
	COMPARE_BOTH_TIMES_EQUAL(finfo,pinfo); \
} while (0)

#define SET_INFO_FILE_EX(finfo, wrtime, tree, tfnum) do { \
	NTSTATUS _status; \
	union smb_setfileinfo sfinfo; \
	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFO; \
	sfinfo.basic_info.in.file.fnum = tfnum; \
	sfinfo.basic_info.in.create_time = 0; \
	sfinfo.basic_info.in.access_time = 0; \
	unix_to_nt_time(&sfinfo.basic_info.in.write_time, (wrtime)); \
	sfinfo.basic_info.in.change_time = 0; \
	sfinfo.basic_info.in.attrib = finfo1.basic_info.out.attrib; \
	_status = smb_raw_setfileinfo(tree, &sfinfo); \
	if (!NT_STATUS_IS_OK(_status)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": setfileinfo failed: %s", \
			       nt_errstr(_status)); \
		ret = false; \
		goto done; \
	} \
} while (0)
#define SET_INFO_FILE(finfo, wrtime) \
	SET_INFO_FILE_EX(finfo, wrtime, cli->tree, fnum1)

static bool test_delayed_write_update3(struct torture_context *tctx,
				       struct smbcli_state *cli,
				       struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3, finfo4;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4, pinfo5;
	const char *fname = BASEDIR "\\torture_file.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	int used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	finfo4 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;
	pinfo5 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/*
	 * make sure the write time is updated 2 seconds later
	 * calcuated from the first write
	 * (but expect upto 5 seconds extra time for a busy server)
	 */
	start = timeval_current();
	end = timeval_add(&start, 7 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_FILE(finfo1);

		if (finfo1.basic_info.out.write_time > finfo0.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			if (diff < (2 * sec * 0.75)) { /* 0.75 to cope with vmware timing */
				torture_comment(tctx, "Server updated write_time after %.2f seconds "
						"(1sec == %.2f) (wrong!)\n",
						diff, sec);
				ret = false;
				break;
			}

			torture_comment(tctx, "Server updated write_time after %.2f seconds "
					"(1sec == %.2f) (correct)\n",
					diff, sec);
			break;
		}
		msleep(0.5 * msec);
	}

	GET_INFO_BOTH(finfo1,pinfo1);

	/* sure any further write doesn't update the write time */
	start = timeval_current();
	end = timeval_add(&start, 15 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);

		if (finfo2.basic_info.out.write_time > finfo1.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_comment(tctx, "Server updated write_time after %.2f seconds "
					"(1sec == %.2f) (wrong!)\n",
					diff, sec);
			ret = false;
			break;
		}
		msleep(2 * msec);
	}

	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_EQUAL(finfo2, finfo1);
	if (finfo2.basic_info.out.write_time == finfo1.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write_time (correct)\n");
	}

	/* sleep */
	msleep(5 * msec);

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);

	/*
	 * the close updates the write time to the time of the close
	 * and not to the time of the last write!
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo4);
	COMPARE_WRITE_TIME_GREATER(pinfo4, pinfo3);

	if (pinfo4.basic_info.out.write_time > pinfo3.basic_info.out.write_time) {
		torture_comment(tctx, "Server updated the write_time on close (correct)\n");
	}

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

static bool test_delayed_write_update4(struct torture_context *tctx,
				       struct smbcli_state *cli,
				       struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3, finfo4;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4, pinfo5;
	const char *fname = BASEDIR "\\torture_file.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	int used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	finfo4 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;
	pinfo5 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/* sleep a bit */
	msleep(5 * msec);

	/* do a write */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_EQUAL(finfo1,finfo0);

	/*
	 * make sure the write time is updated 2 seconds later
	 * calcuated from the first write
	 * (but expect upto 3 seconds extra time for a busy server)
	 */
	start = timeval_current();
	end = timeval_add(&start, 5 * sec, 0);
	while (!timeval_expired(&end)) {
		/* get the times after the first write */
		GET_INFO_FILE(finfo1);

		if (finfo1.basic_info.out.write_time > finfo0.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			if (diff < (2 * sec * 0.75)) { /* 0.75 to cope with vmware timing */
				torture_comment(tctx, "Server updated write_time after %.2f seconds "
						"(1sec == %.2f) (wrong!)\n",
						diff, sec);
				ret = false;
				break;
			}

			torture_comment(tctx, "Server updated write_time after %.2f seconds "
					"(1sec == %.2f) (correct)\n",
					diff, sec);
			break;
		}
		msleep(0.5 * msec);
	}

	GET_INFO_BOTH(finfo1,pinfo1);

	/* sure any further write doesn't update the write time */
	start = timeval_current();
	end = timeval_add(&start, 15 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);

		if (finfo2.basic_info.out.write_time > finfo1.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_comment(tctx, "Server updated write_time after %.2f seconds "
					"(1sec == %.2f) (wrong!)\n",
					diff, sec);
			ret = false;
			break;
		}
		msleep(2 * msec);
	}

	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_EQUAL(finfo2, finfo1);
	if (finfo2.basic_info.out.write_time == finfo1.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not updatewrite_time (correct)\n");
	}

	/* sleep */
	msleep(5 * msec);

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);

	/*
	 * the close updates the write time to the time of the close
	 * and not to the time of the last write!
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo4);
	COMPARE_WRITE_TIME_GREATER(pinfo4, pinfo3);

	if (pinfo4.basic_info.out.write_time > pinfo3.basic_info.out.write_time) {
		torture_comment(tctx, "Server updated the write_time on close (correct)\n");
	}

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

static bool test_delayed_write_update5(struct torture_context *tctx,
				       struct smbcli_state *cli,
				       struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3, finfo4, finfo5;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4, pinfo5, pinfo6;
	const char *fname = BASEDIR "\\torture_file.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	int used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	finfo4 = finfo0;
	finfo5 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;
	pinfo5 = pinfo0;
	pinfo6 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/* do a write */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_EQUAL(finfo1, finfo0);

	torture_comment(tctx, "Set write time in the future on the file handle\n");
	SET_INFO_FILE(finfo0, time(NULL) + 86400);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_GREATER(finfo2, finfo1);

	torture_comment(tctx, "Set write time in the past on the file handle\n");
	SET_INFO_FILE(finfo0, time(NULL) - 86400);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_LESS(finfo2, finfo1);

	/* make sure the 2 second delay from the first write are canceled */
	start = timeval_current();
	end = timeval_add(&start, 15 * sec, 0);
	while (!timeval_expired(&end)) {

		/* get the times after the first write */
		GET_INFO_BOTH(finfo3,pinfo3);

		if (finfo3.basic_info.out.write_time > finfo2.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_comment(tctx, "Server updated write_time after %.2f seconds "
					"(1sec == %.2f) (wrong!)\n",
					diff, sec);
			ret = false;
			break;
		}
		msleep(2 * msec);
	}

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);
	if (finfo3.basic_info.out.write_time == finfo3.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write_time (correct)\n");
	}

	/* sure any further write doesn't update the write time */
	start = timeval_current();
	end = timeval_add(&start, 15 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo4,pinfo4);

		if (finfo4.basic_info.out.write_time > finfo3.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_comment(tctx, "Server updated write_time after %.2f seconds "
					"(1sec == %.2f) (wrong!)\n",
					diff, sec);
			ret = false;
			break;
		}
		msleep(2 * msec);
	}

	GET_INFO_BOTH(finfo4,pinfo4);
	COMPARE_WRITE_TIME_EQUAL(finfo4, finfo3);
	if (finfo4.basic_info.out.write_time == finfo3.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write_time (correct)\n");
	}

	/* sleep */
	msleep(5 * msec);

	GET_INFO_BOTH(finfo5,pinfo5);
	COMPARE_WRITE_TIME_EQUAL(finfo5, finfo4);

	/*
	 * the close doesn't update the write time
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo6);
	COMPARE_WRITE_TIME_EQUAL(pinfo6, pinfo5);

	if (pinfo6.basic_info.out.write_time == pinfo5.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update the write_time on close (correct)\n");
	}

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

static bool test_delayed_write_update6(struct torture_context *tctx,
				       struct smbcli_state *cli,
				       struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3, finfo4, finfo5;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4, pinfo5, pinfo6, pinfo7;
	const char *fname = BASEDIR "\\torture_file.txt";
	int fnum1 = -1;
	int fnum2 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	int used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;
	bool first = true;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return false;
	}
again:
	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	if (fnum2 == -1) {
		torture_comment(tctx, "Open the 2nd file handle on 2nd connection\n");
		fnum2 = smbcli_open(cli2->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
		if (fnum2 == -1) {
			ret = false;
			torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
			goto done;
		}
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	finfo4 = finfo0;
	finfo5 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;
	pinfo5 = pinfo0;
	pinfo6 = pinfo0;
	pinfo7 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/* do a write */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_EQUAL(finfo1, finfo0);

	torture_comment(tctx, "Set write time in the future on the 2nd file handle\n");
	SET_INFO_FILE_EX(finfo0, time(NULL) + 86400, cli2->tree, fnum2);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_GREATER(finfo2, finfo1);

	torture_comment(tctx, "Set write time in the past on the 2nd file handle\n");
	SET_INFO_FILE_EX(finfo0, time(NULL) - 86400, cli2->tree, fnum2);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_LESS(finfo2, finfo1);

	/* make sure the 2 second delay from the first write are canceled */
	start = timeval_current();
	end = timeval_add(&start, 15 * sec, 0);
	while (!timeval_expired(&end)) {

		/* get the times after the first write */
		GET_INFO_BOTH(finfo3,pinfo3);

		if (finfo3.basic_info.out.write_time > finfo2.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_comment(tctx, "Server updated write_time after %.2f seconds "
					"(1sec == %.2f) (wrong!)\n",
					diff, sec);
			ret = false;
			break;
		}
		msleep(2 * msec);
	}

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);
	if (finfo3.basic_info.out.write_time == finfo3.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write_time (correct)\n");
	}

	/* sure any further write doesn't update the write time */
	start = timeval_current();
	end = timeval_add(&start, 15 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo4,pinfo4);

		if (finfo4.basic_info.out.write_time > finfo3.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_comment(tctx, "Server updated write_time after %.2f seconds "
					"(1sec == %.2f) (wrong!)\n",
					diff, sec);
			ret = false;
			break;
		}
		msleep(2 * msec);
	}

	GET_INFO_BOTH(finfo4,pinfo4);
	COMPARE_WRITE_TIME_EQUAL(finfo4, finfo3);
	if (finfo4.basic_info.out.write_time == finfo3.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write_time (correct)\n");
	}

	/* sleep */
	msleep(5 * msec);

	GET_INFO_BOTH(finfo5,pinfo5);
	COMPARE_WRITE_TIME_EQUAL(finfo5, finfo4);

	/*
	 * the close updates the write time to the time of the close
	 * as the write time was set on the 2nd handle
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo6);
	COMPARE_WRITE_TIME_GREATER(pinfo6, pinfo5);

	if (pinfo6.basic_info.out.write_time > pinfo5.basic_info.out.write_time) {
		torture_comment(tctx, "Server updated the write_time on close (correct)\n");
	}

	/* keep the 2nd handle open and rerun tests */
	if (first) {
		first = false;
		goto again;
	}

	/*
	 * closing the 2nd handle will cause no write time update
	 * as the write time was explicit set on this handle
	 */
	torture_comment(tctx, "Close the 2nd file handle\n");
	smbcli_close(cli2->tree, fnum2);
	fnum2 = -1;

	GET_INFO_PATH(pinfo7);
	COMPARE_WRITE_TIME_EQUAL(pinfo7, pinfo6);

	if (pinfo7.basic_info.out.write_time == pinfo6.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update the write_time on close (correct)\n");
	}

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	if (fnum2 != -1)
		smbcli_close(cli2->tree, fnum2);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}


/* 
   testing of delayed update of write_time
*/
struct torture_suite *torture_delay_write(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "DELAYWRITE");

	torture_suite_add_2smb_test(suite, "finfo update on close", test_finfo_after_write);
	torture_suite_add_1smb_test(suite, "delayed update of write time", test_delayed_write_update);
	torture_suite_add_2smb_test(suite, "delayed update of write time using 2 connections", test_delayed_write_update2);
	torture_suite_add_2smb_test(suite, "delayed update of write time 3", test_delayed_write_update3);
	torture_suite_add_2smb_test(suite, "delayed update of write time 4", test_delayed_write_update4);
	torture_suite_add_2smb_test(suite, "delayed update of write time 5", test_delayed_write_update5);
	torture_suite_add_2smb_test(suite, "delayed update of write time 6", test_delayed_write_update6);

	return suite;
}
