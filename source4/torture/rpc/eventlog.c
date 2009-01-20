/*
   Unix SMB/CIFS implementation.
   test suite for eventlog rpc operations

   Copyright (C) Tim Potter 2003,2005
   Copyright (C) Jelmer Vernooij 2004

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
#include "librpc/gen_ndr/ndr_eventlog.h"
#include "librpc/gen_ndr/ndr_eventlog_c.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "torture/rpc/rpc.h"
#include "param/param.h"

static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
	name->length = 2*strlen_m(s);
	name->size = name->length;
}

static bool get_policy_handle(struct torture_context *tctx,
			      struct dcerpc_pipe *p,
			      struct policy_handle *handle)
{
	struct eventlog_OpenEventLogW r;
	struct eventlog_OpenUnknown0 unknown0;
	struct lsa_String logname, servername;

	unknown0.unknown0 = 0x005c;
	unknown0.unknown1 = 0x0001;

	r.in.unknown0 = &unknown0;
	init_lsa_String(&logname, "dns server");
	init_lsa_String(&servername, NULL);
	r.in.logname = &logname;
	r.in.servername = &servername;
	r.in.major_version = 0x00000001;
	r.in.minor_version = 0x00000001;
	r.out.handle = handle;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_eventlog_OpenEventLogW(p, tctx, &r),
			"OpenEventLog failed");

	torture_assert_ntstatus_ok(tctx, r.out.result, "OpenEventLog failed");

	return true;
}



static bool test_GetNumRecords(struct torture_context *tctx, struct dcerpc_pipe *p)
{
	struct eventlog_GetNumRecords r;
	struct eventlog_CloseEventLog cr;
	struct policy_handle handle;
	uint32_t number = 0;

	if (!get_policy_handle(tctx, p, &handle))
		return false;

	ZERO_STRUCT(r);
	r.in.handle = &handle;
	r.out.number = &number;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_eventlog_GetNumRecords(p, tctx, &r),
			"GetNumRecords failed");

	torture_comment(tctx, "%d records\n", *r.out.number);

	cr.in.handle = cr.out.handle = &handle;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_eventlog_CloseEventLog(p, tctx, &cr),
			"CloseEventLog failed");
	return true;
}

static bool test_ReadEventLog(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct eventlog_ReadEventLogW r;
	struct eventlog_CloseEventLog cr;
	struct policy_handle handle;

	uint32_t sent_size = 0;
	uint32_t real_size = 0;

	if (!get_policy_handle(tctx, p, &handle))
		return false;

	ZERO_STRUCT(r);
	r.in.offset = 0;
	r.in.handle = &handle;
	r.in.flags = 0;
	r.out.data = NULL;
	r.out.sent_size = &sent_size;
	r.out.real_size = &real_size;

	status = dcerpc_eventlog_ReadEventLogW(p, tctx, &r);

	torture_assert_ntstatus_equal(tctx, r.out.result, NT_STATUS_INVALID_PARAMETER,
			"ReadEventLog failed");

	while (1) {
		DATA_BLOB blob;
		struct eventlog_Record rec;
		struct ndr_pull *ndr;
		enum ndr_err_code ndr_err;

		/* Read first for number of bytes in record */

		r.in.number_of_bytes = 0;
		r.in.flags = EVENTLOG_BACKWARDS_READ|EVENTLOG_SEQUENTIAL_READ;
		r.out.data = NULL;
		r.out.sent_size = &sent_size;
		r.out.real_size = &real_size;

		status = dcerpc_eventlog_ReadEventLogW(p, tctx, &r);

		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_END_OF_FILE)) {
			break;
		}

		torture_assert_ntstatus_equal(tctx, r.out.result, NT_STATUS_BUFFER_TOO_SMALL,
			"ReadEventLog failed");

		/* Now read the actual record */

		r.in.number_of_bytes = *r.out.real_size;
		r.out.data = talloc_array(tctx, uint8_t, r.in.number_of_bytes);

		status = dcerpc_eventlog_ReadEventLogW(p, tctx, &r);

		torture_assert_ntstatus_ok(tctx, status, "ReadEventLog failed");

		/* Decode a user-marshalled record */

		blob.length = *r.out.sent_size;
		blob.data = talloc_steal(tctx, r.out.data);

		ndr = ndr_pull_init_blob(&blob, tctx, lp_iconv_convenience(tctx->lp_ctx));

		ndr_err = ndr_pull_eventlog_Record(
			ndr, NDR_SCALARS|NDR_BUFFERS, &rec);
		status = ndr_map_error2ntstatus(ndr_err);

		NDR_PRINT_DEBUG(eventlog_Record, &rec);

		torture_assert_ntstatus_ok(tctx, status,
				"ReadEventLog failed parsing event log record");

		r.in.offset++;
	}

	cr.in.handle = cr.out.handle = &handle;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_eventlog_CloseEventLog(p, tctx, &cr),
			"CloseEventLog failed");

	return true;
}

static bool test_ReportEventLog(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct eventlog_ReportEventW r;
	struct eventlog_CloseEventLog cr;
	struct policy_handle handle;

	uint32_t record_number = 0;
	time_t time_written = 0;
	struct lsa_String servername, *strings;

	if (!get_policy_handle(tctx, p, &handle))
		return false;

	init_lsa_String(&servername, NULL);

	strings = talloc_array(tctx, struct lsa_String, 1);
	init_lsa_String(&strings[0], "Currently tortured by samba 4");

	ZERO_STRUCT(r);

	r.in.handle = &handle;
	r.in.timestamp = time(NULL);
	r.in.event_type = EVENTLOG_INFORMATION_TYPE;
	r.in.event_category = 0;
	r.in.event_id = 0;
	r.in.num_of_strings = 1;
	r.in.data_size = 0;
	r.in.servername = &servername;
	r.in.user_sid = NULL;
	r.in.strings = &strings;
	r.in.data = NULL;
	r.in.flags = 0;
	r.out.record_number = &record_number;
	r.out.time_written = &time_written;

	status = dcerpc_eventlog_ReportEventW(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, r.out.result, "ReportEventW failed");

	cr.in.handle = cr.out.handle = &handle;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_eventlog_CloseEventLog(p, tctx, &cr),
			"CloseEventLog failed");
	return true;
}

static bool test_FlushEventLog(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct eventlog_FlushEventLog r;
	struct eventlog_CloseEventLog cr;
	struct policy_handle handle;

	if (!get_policy_handle(tctx, p, &handle))
		return false;

	r.in.handle = &handle;

	/* Huh?  Does this RPC always return access denied? */
	torture_assert_ntstatus_equal(tctx,
			dcerpc_eventlog_FlushEventLog(p, tctx, &r),
			NT_STATUS_ACCESS_DENIED,
			"FlushEventLog failed");

	cr.in.handle = cr.out.handle = &handle;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_eventlog_CloseEventLog(p, tctx, &cr),
			"CloseEventLog failed");

	return true;
}

static bool test_ClearEventLog(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct eventlog_ClearEventLogW r;
	struct eventlog_CloseEventLog cr;
	struct policy_handle handle;

	if (!get_policy_handle(tctx, p, &handle))
		return false;

	r.in.handle = &handle;
	r.in.backupfile = NULL;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_eventlog_ClearEventLogW(p, tctx, &r),
			"ClearEventLog failed");

	cr.in.handle = cr.out.handle = &handle;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_eventlog_CloseEventLog(p, tctx, &cr),
			"CloseEventLog failed");

	return true;
}

static bool test_OpenEventLog(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct policy_handle handle;
	struct eventlog_CloseEventLog cr;

	if (!get_policy_handle(tctx, p, &handle))
		return false;

	cr.in.handle = cr.out.handle = &handle;

	torture_assert_ntstatus_ok(tctx,
			dcerpc_eventlog_CloseEventLog(p, tctx, &cr),
			"CloseEventLog failed");

	return true;
}

struct torture_suite *torture_rpc_eventlog(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite;
	struct torture_rpc_tcase *tcase;
	struct torture_test *test;

	suite = torture_suite_create(mem_ctx, "EVENTLOG");
	tcase = torture_suite_add_rpc_iface_tcase(suite, "eventlog",
						  &ndr_table_eventlog);

	torture_rpc_tcase_add_test(tcase, "OpenEventLog", test_OpenEventLog);
	test = torture_rpc_tcase_add_test(tcase, "ClearEventLog",
					  test_ClearEventLog);
	test->dangerous = true;
	torture_rpc_tcase_add_test(tcase, "GetNumRecords", test_GetNumRecords);
	torture_rpc_tcase_add_test(tcase, "ReadEventLog", test_ReadEventLog);
	torture_rpc_tcase_add_test(tcase, "ReportEventLog", test_ReportEventLog);
	torture_rpc_tcase_add_test(tcase, "FlushEventLog", test_FlushEventLog);

	return suite;
}
