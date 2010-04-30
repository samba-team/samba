/*
   Unix SMB/CIFS implementation.
   test suite for SMB printing operations

   Copyright (C) Guenther Deschner 2010

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
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "system/filesys.h"

#include "torture/smbtorture.h"
#include "torture/util.h"
#include "../librpc/gen_ndr/rap.h"
#include "torture/rap/proto.h"
#include "param/param.h"


#define TORTURE_PRINT_FILE "torture_print_file"

static bool test_raw_print(struct torture_context *tctx,
			   struct smbcli_state *cli)
{
	int fnum;
	DATA_BLOB data;
	ssize_t size_written;
	const char *str;

	fnum = smbcli_open(cli->tree, TORTURE_PRINT_FILE, O_RDWR|O_CREAT|O_TRUNC, DENY_NONE);
	if (fnum == -1) {
		torture_fail(tctx, "failed to open file");
	}

	str = talloc_asprintf(tctx, "TortureTestPage: %d\nData\n",0);

	data = data_blob_string_const(str);

	size_written = smbcli_write(cli->tree, fnum, 0, data.data, 0, data.length);
	if (size_written != data.length) {
		torture_fail(tctx, "failed to write file");
	}

	torture_assert_ntstatus_ok(tctx,
		smbcli_close(cli->tree, fnum),
		"failed to close file");

	return true;
}

static bool test_netprintqenum(struct torture_context *tctx,
			       struct smbcli_state *cli)
{
	struct rap_NetPrintQEnum r;
	int i, q;
	uint16_t levels[] = { 0, 1, 2, 3, 4, 5 };
	NTSTATUS status;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		r.in.level = levels[i];
		r.in.bufsize = 8192;

		torture_comment(tctx,
			"Testing rap_NetPrintQEnum level %d\n", r.in.level);

		status = smbcli_rap_netprintqenum(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			torture_warning(tctx, "smbcli_rap_netprintqenum failed with %s\n", nt_errstr(status));
			continue;
		}

		for (q=0; q<r.out.count; q++) {
			switch (r.in.level) {
			case 0:
				printf("%s\n", r.out.info[q].info0.PrintQName);
				break;
			}
		}
	}

	return true;
}

static bool test_netprintqgetinfo(struct torture_context *tctx,
				  struct smbcli_state *cli)
{
	struct rap_NetPrintQGetInfo r;
	struct rap_NetPrintQEnum r_enum;
	int i, p;
	uint16_t levels[] = { 0, 1, 2, 3, 4, 5 };
	NTSTATUS status;

	r_enum.in.level = 5;
	r_enum.in.bufsize = 8192;

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netprintqenum(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r_enum),
		"failed to enum printq");

	for (p=0; p < r_enum.out.count; p++) {

		for (i=0; i < ARRAY_SIZE(levels); i++) {

			r.in.level = levels[i];
			r.in.bufsize = 8192;
			r.in.PrintQueueName = r_enum.out.info[p].info5.PrintQueueName;

			torture_comment(tctx, "Testing rap_NetPrintQGetInfo(%s) level %d\n",
				r.in.PrintQueueName, r.in.level);

			status = smbcli_rap_netprintqgetinfo(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r);
			if (!NT_STATUS_IS_OK(status)) {
				torture_warning(tctx, "smbcli_rap_netprintqgetinfo failed with %s\n", nt_errstr(status));
				continue;
			}

			switch (r.in.level) {
			case 0:
				printf("%s\n", r.out.info.info0.PrintQName);
				break;
			}
		}
	}

	return true;
}

static bool test_netprintjob_pause(struct torture_context *tctx,
				   struct smbcli_state *cli,
				   uint16_t job_id)
{
	struct rap_NetPrintJobPause r;

	r.in.JobID = job_id;

	torture_comment(tctx, "Testing rap_NetPrintJobPause(%d)\n", r.in.JobID);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netprintjobpause(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netprintjobpause failed");

	return true;
}

static bool test_netprintjob_continue(struct torture_context *tctx,
				      struct smbcli_state *cli,
				      uint16_t job_id)
{
	struct rap_NetPrintJobContinue r;

	r.in.JobID = job_id;

	torture_comment(tctx, "Testing rap_NetPrintJobContinue(%d)\n", r.in.JobID);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netprintjobcontinue(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netprintjobcontinue failed");

	return true;
}

static bool test_netprintjob_delete(struct torture_context *tctx,
				    struct smbcli_state *cli,
				    uint16_t job_id)
{
	struct rap_NetPrintJobDelete r;

	r.in.JobID = job_id;

	torture_comment(tctx, "Testing rap_NetPrintJobDelete(%d)\n", r.in.JobID);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netprintjobdelete(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netprintjobdelete failed");

	return true;
}

static bool test_netprintjob(struct torture_context *tctx,
			     struct smbcli_state *cli)
{
	uint16_t job_id = 400;

	torture_assert(tctx,
		test_netprintjob_pause(tctx, cli, job_id),
		"failed to pause job");
	torture_assert(tctx,
		test_netprintjob_continue(tctx, cli, job_id),
		"failed to continue job");
	torture_assert(tctx,
		test_netprintjob_delete(tctx, cli, job_id),
		"failed to delete job");

	return true;
}

static bool test_netprintq_pause(struct torture_context *tctx,
				 struct smbcli_state *cli,
				 const char *PrintQueueName)
{
	struct rap_NetPrintQueuePause r;

	r.in.PrintQueueName = PrintQueueName;

	torture_comment(tctx, "Testing rap_NetPrintQueuePause(%s)\n", r.in.PrintQueueName);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netprintqueuepause(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netprintqueuepause failed");

	return true;
}

static bool test_netprintq_resume(struct torture_context *tctx,
				  struct smbcli_state *cli,
				  const char *PrintQueueName)
{
	struct rap_NetPrintQueueResume r;

	r.in.PrintQueueName = PrintQueueName;

	torture_comment(tctx, "Testing rap_NetPrintQueueResume(%s)\n", r.in.PrintQueueName);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netprintqueueresume(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netprintqueueresume failed");

	return true;
}

static bool test_netprintq(struct torture_context *tctx,
			   struct smbcli_state *cli)
{
	struct rap_NetPrintQEnum r;
	int i;

	r.in.level = 5;
	r.in.bufsize = 8192;

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netprintqenum(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"failed to enum printq");

	for (i=0; i < r.out.count; i++) {

		const char *printqname = r.out.info[i].info5.PrintQueueName;

		torture_assert(tctx,
			test_netprintq_pause(tctx, cli, printqname),
			"failed to pause print queue");

		torture_assert(tctx,
			test_netprintq_resume(tctx, cli, printqname),
			"failed to resume print queue");
	}

	return true;
}

static bool test_rap_print(struct torture_context *tctx,
			   struct smbcli_state *cli)
{
	/*
	pause printer
	print printfile
	enumjobs printer
	delete job
	start printer
	*/

	return true;
}

struct torture_suite *torture_rap_printing(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "PRINTING");

	torture_suite_add_1smb_test(suite, "raw_print", test_raw_print);
	torture_suite_add_1smb_test(suite, "rap_print", test_rap_print);
	torture_suite_add_1smb_test(suite, "rap_printq_enum", test_netprintqenum);
	torture_suite_add_1smb_test(suite, "rap_printq_getinfo", test_netprintqgetinfo);
	torture_suite_add_1smb_test(suite, "rap_printjob", test_netprintjob);
	torture_suite_add_1smb_test(suite, "rap_printq", test_netprintq);

	return suite;
}
