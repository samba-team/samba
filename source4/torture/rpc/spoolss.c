/* 
   Unix SMB/CIFS implementation.
   test suite for spoolss rpc operations

   Copyright (C) Tim Potter 2003
   Copyright (C) Stefan Metzmacher 2005
   Copyright (C) Jelmer Vernooij 2007
   
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
#include "torture/rpc/rpc.h"
#include "librpc/gen_ndr/ndr_spoolss_c.h"

struct test_spoolss_context {
	/* print server handle */
	struct policy_handle server_handle;

	/* for EnumPorts */
	uint32_t port_count[3];
	union spoolss_PortInfo *ports[3];

	/* for EnumPrinterDrivers */
	uint32_t driver_count[7];
	union spoolss_DriverInfo *drivers[7];

	/* for EnumMonitors */
	uint32_t monitor_count[3];
	union spoolss_MonitorInfo *monitors[3];

	/* for EnumPrintProcessors */
	uint32_t print_processor_count[2];
	union spoolss_PrintProcessorInfo *print_processors[2];

	/* for EnumPrinters */
	uint32_t printer_count[6];
	union spoolss_PrinterInfo *printers[6];
};

#define COMPARE_STRING(tctx, c,r,e) \
	torture_assert_str_equal(tctx, c.e, r.e, "invalid value")

/* not every compiler supports __typeof__() */
#if (__GNUC__ >= 3)
#define _CHECK_FIELD_SIZE(c,r,e,type) do {\
	if (sizeof(__typeof__(c.e)) != sizeof(type)) { \
		torture_fail(tctx, #c "." #e "field is not " #type "\n"); \
	}\
	if (sizeof(__typeof__(r.e)) != sizeof(type)) { \
		torture_fail(tctx, #r "." #e "field is not " #type "\n"); \
	}\
} while(0)
#else
#define _CHECK_FIELD_SIZE(c,r,e,type) do {} while(0)
#endif

#define COMPARE_UINT32(tctx, c, r, e) do {\
	_CHECK_FIELD_SIZE(c, r, e, uint32_t); \
	torture_assert_int_equal(tctx, c.e, r.e, "invalid value"); \
} while(0)

#define COMPARE_STRING_ARRAY(tctx, c,r,e)

static bool test_OpenPrinter_server(struct torture_context *tctx, struct dcerpc_pipe *p, struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_OpenPrinter op;

	op.in.printername	= talloc_asprintf(ctx, "\\\\%s", dcerpc_server_name(p));
	op.in.datatype		= NULL;
	op.in.devmode_ctr.devmode= NULL;
	op.in.access_mask	= 0;
	op.out.handle		= &ctx->server_handle;

	torture_comment(tctx, "Testing OpenPrinter(%s)\n", op.in.printername);

	status = dcerpc_spoolss_OpenPrinter(p, ctx, &op);
	torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_OpenPrinter failed");
	torture_assert_werr_ok(tctx, op.out.result, "dcerpc_spoolss_OpenPrinter failed"); 

	return true;
}

static bool test_EnumPorts(struct torture_context *tctx, 
			   struct dcerpc_pipe *p, 
			   struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_EnumPorts r;
	uint16_t levels[] = { 1, 2 };
	int i, j;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;
		uint32_t needed;
		uint32_t count;
		union spoolss_PortInfo *info;

		r.in.servername = "";
		r.in.level = level;
		r.in.buffer = NULL;
		r.in.offered = 0;
		r.out.needed = &needed;
		r.out.count = &count;
		r.out.info = &info;

		torture_comment(tctx, "Testing EnumPorts level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPorts(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumPorts failed");
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		torture_assert_werr_equal(tctx, r.out.result, WERR_INSUFFICIENT_BUFFER, 
			"EnumPorts unexpected return code");

		blob = data_blob_talloc(ctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;

		status = dcerpc_spoolss_EnumPorts(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumPorts failed");

		torture_assert_werr_ok(tctx, r.out.result, "EnumPorts failed");

		torture_assert(tctx, info, "EnumPorts returned no info");

		ctx->port_count[level]	= count;
		ctx->ports[level]	= info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		torture_assert_int_equal(tctx, ctx->port_count[level], ctx->port_count[old_level], 
			"EnumPorts invalid value");
	}
	/* if the array sizes are not the same we would maybe segfault in the following code */

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		for (j=0;j<ctx->port_count[level];j++) {
			union spoolss_PortInfo *cur = &ctx->ports[level][j];
			union spoolss_PortInfo *ref = &ctx->ports[2][j];
			switch (level) {
			case 1:
				COMPARE_STRING(tctx, cur->info1, ref->info2, port_name);
				break;
			case 2:
				/* level 2 is our reference, and it makes no sense to compare it to itself */
				break;
			}
		}
	}

	return true;
}

static bool test_GetPrintProcessorDirectory(struct torture_context *tctx,
					    struct dcerpc_pipe *p,
					    struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_GetPrintProcessorDirectory r;
	struct {
		uint16_t level;
		const char *server;
	} levels[] = {{
			.level	= 1,
			.server	= NULL
		},{
			.level	= 1,
			.server	= ""
		},{
			.level	= 78,
			.server	= ""
		},{
			.level	= 1,
			.server	= talloc_asprintf(ctx, "\\\\%s", dcerpc_server_name(p))
		},{
			.level	= 1024,
			.server	= talloc_asprintf(ctx, "\\\\%s", dcerpc_server_name(p))
		}
	};
	int i;
	uint32_t needed;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i].level;
		DATA_BLOB blob;

		r.in.server		= levels[i].server;
		r.in.environment	= SPOOLSS_ARCHITECTURE_NT_X86;
		r.in.level		= level;
		r.in.buffer		= NULL;
		r.in.offered		= 0;
		r.out.needed		= &needed;

		torture_comment(tctx, "Testing GetPrintProcessorDirectory level %u\n", r.in.level);

		status = dcerpc_spoolss_GetPrintProcessorDirectory(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status,
			"dcerpc_spoolss_GetPrintProcessorDirectory failed");
		torture_assert_werr_equal(tctx, r.out.result, WERR_INSUFFICIENT_BUFFER,
			"GetPrintProcessorDirectory unexpected return code");

		blob = data_blob_talloc(ctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;

		status = dcerpc_spoolss_GetPrintProcessorDirectory(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_GetPrintProcessorDirectory failed");

		torture_assert_werr_ok(tctx, r.out.result, "GetPrintProcessorDirectory failed");
	}

	return true;
}


static bool test_GetPrinterDriverDirectory(struct torture_context *tctx, 
					   struct dcerpc_pipe *p, 
					   struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_GetPrinterDriverDirectory r;
	struct {
		uint16_t level;
		const char *server;
	} levels[] = {{
			.level	= 1,
			.server	= NULL
		},{
			.level	= 1,
			.server	= ""
		},{
			.level	= 78,
			.server	= ""
		},{
			.level	= 1,
			.server	= talloc_asprintf(ctx, "\\\\%s", dcerpc_server_name(p))
		},{
			.level	= 1024,
			.server	= talloc_asprintf(ctx, "\\\\%s", dcerpc_server_name(p))
		}
	};
	int i;
	uint32_t needed;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i].level;
		DATA_BLOB blob;

		r.in.server		= levels[i].server;
		r.in.environment	= SPOOLSS_ARCHITECTURE_NT_X86;
		r.in.level		= level;
		r.in.buffer		= NULL;
		r.in.offered		= 0;
		r.out.needed		= &needed;

		torture_comment(tctx, "Testing GetPrinterDriverDirectory level %u\n", r.in.level);

		status = dcerpc_spoolss_GetPrinterDriverDirectory(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, 
			"dcerpc_spoolss_GetPrinterDriverDirectory failed");
		torture_assert_werr_equal(tctx, r.out.result, WERR_INSUFFICIENT_BUFFER, 
			"GetPrinterDriverDirectory unexpected return code");

		blob = data_blob_talloc(ctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;

		status = dcerpc_spoolss_GetPrinterDriverDirectory(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_GetPrinterDriverDirectory failed");

		torture_assert_werr_ok(tctx, r.out.result, "GetPrinterDriverDirectory failed");
	}

	return true;
}

static bool test_EnumPrinterDrivers(struct torture_context *tctx, 
				    struct dcerpc_pipe *p,
				    struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_EnumPrinterDrivers r;
	uint16_t levels[] = { 1, 2, 3, 4, 5, 6 };
	int i, j;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;
		uint32_t needed;
		uint32_t count;
		union spoolss_DriverInfo *info;

		/* FIXME: gd, come back and fix "" as server, and handle
		 * priority of returned error codes in torture test and samba 3
		 * server */

		r.in.server		= talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
		r.in.environment	= SPOOLSS_ARCHITECTURE_NT_X86;
		r.in.level		= level;
		r.in.buffer		= NULL;
		r.in.offered		= 0;
		r.out.needed		= &needed;
		r.out.count		= &count;
		r.out.info		= &info;

		torture_comment(tctx, "Testing EnumPrinterDrivers level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinterDrivers(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, 
					   "dcerpc_spoolss_EnumPrinterDrivers failed");
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			blob = data_blob_talloc(ctx, NULL, needed);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			r.in.offered = needed;

			status = dcerpc_spoolss_EnumPrinterDrivers(p, ctx, &r);
			torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumPrinterDrivers failed");
		}

		torture_assert_werr_ok(tctx, r.out.result, "EnumPrinterDrivers failed");

		ctx->driver_count[level]	= count;
		ctx->drivers[level]		= info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		torture_assert_int_equal(tctx, ctx->driver_count[level], ctx->driver_count[old_level],
			"EnumPrinterDrivers invalid value");
	}

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		for (j=0;j<ctx->driver_count[level];j++) {
			union spoolss_DriverInfo *cur = &ctx->drivers[level][j];
			union spoolss_DriverInfo *ref = &ctx->drivers[6][j];
			switch (level) {
			case 1:
				COMPARE_STRING(tctx, cur->info1, ref->info6, driver_name);
				break;
			case 2:
				COMPARE_UINT32(tctx, cur->info2, ref->info6, version);
				COMPARE_STRING(tctx, cur->info2, ref->info6, driver_name);
				COMPARE_STRING(tctx, cur->info2, ref->info6, architecture);
				COMPARE_STRING(tctx, cur->info2, ref->info6, driver_path);
				COMPARE_STRING(tctx, cur->info2, ref->info6, data_file);
				COMPARE_STRING(tctx, cur->info2, ref->info6, config_file);
				break;
			case 3:
				COMPARE_UINT32(tctx, cur->info3, ref->info6, version);
				COMPARE_STRING(tctx, cur->info3, ref->info6, driver_name);
				COMPARE_STRING(tctx, cur->info3, ref->info6, architecture);
				COMPARE_STRING(tctx, cur->info3, ref->info6, driver_path);
				COMPARE_STRING(tctx, cur->info3, ref->info6, data_file);
				COMPARE_STRING(tctx, cur->info3, ref->info6, config_file);
				COMPARE_STRING(tctx, cur->info3, ref->info6, help_file);
				COMPARE_STRING_ARRAY(tctx, cur->info3, ref->info6, dependent_files);
				COMPARE_STRING(tctx, cur->info3, ref->info6, monitor_name);
				COMPARE_STRING(tctx, cur->info3, ref->info6, default_datatype);
				break;
			case 4:
				COMPARE_UINT32(tctx, cur->info4, ref->info6, version);
				COMPARE_STRING(tctx, cur->info4, ref->info6, driver_name);
				COMPARE_STRING(tctx, cur->info4, ref->info6, architecture);
				COMPARE_STRING(tctx, cur->info4, ref->info6, driver_path);
				COMPARE_STRING(tctx, cur->info4, ref->info6, data_file);
				COMPARE_STRING(tctx, cur->info4, ref->info6, config_file);
				COMPARE_STRING(tctx, cur->info4, ref->info6, help_file);
				COMPARE_STRING_ARRAY(tctx, cur->info4, ref->info6, dependent_files);
				COMPARE_STRING(tctx, cur->info4, ref->info6, monitor_name);
				COMPARE_STRING(tctx, cur->info4, ref->info6, default_datatype);
				COMPARE_STRING_ARRAY(tctx, cur->info4, ref->info6, previous_names);
				break;
			case 5:
				COMPARE_UINT32(tctx, cur->info5, ref->info6, version);
				COMPARE_STRING(tctx, cur->info5, ref->info6, driver_name);
				COMPARE_STRING(tctx, cur->info5, ref->info6, architecture);
				COMPARE_STRING(tctx, cur->info5, ref->info6, driver_path);
				COMPARE_STRING(tctx, cur->info5, ref->info6, data_file);
				COMPARE_STRING(tctx, cur->info5, ref->info6, config_file);
				/*COMPARE_UINT32(tctx, cur->info5, ref->info6, driver_attributes);*/
				/*COMPARE_UINT32(tctx, cur->info5, ref->info6, config_version);*/
				/*TODO: ! COMPARE_UINT32(tctx, cur->info5, ref->info6, driver_version); */
				break;
			case 6:
				/* level 6 is our reference, and it makes no sense to compare it to itself */
				break;
			}
		}
	}

	return true;
}

static bool test_EnumMonitors(struct torture_context *tctx, 
			      struct dcerpc_pipe *p, 
			      struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_EnumMonitors r;
	uint16_t levels[] = { 1, 2 };
	int i, j;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;
		uint32_t needed;
		uint32_t count;
		union spoolss_MonitorInfo *info;

		r.in.servername = "";
		r.in.level = level;
		r.in.buffer = NULL;
		r.in.offered = 0;
		r.out.needed = &needed;
		r.out.count = &count;
		r.out.info = &info;

		torture_comment(tctx, "Testing EnumMonitors level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumMonitors(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumMonitors failed");
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		torture_assert_werr_equal(tctx, r.out.result, WERR_INSUFFICIENT_BUFFER, 
			"EnumMonitors failed");

		blob = data_blob_talloc(ctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;

		status = dcerpc_spoolss_EnumMonitors(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumMonitors failed");

		torture_assert_werr_ok(tctx, r.out.result, "EnumMonitors failed");

		ctx->monitor_count[level]	= count;
		ctx->monitors[level]		= info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		torture_assert_int_equal(tctx, ctx->monitor_count[level], ctx->monitor_count[old_level], 
					 "EnumMonitors invalid value");
	}

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		for (j=0;j<ctx->monitor_count[level];j++) {
			union spoolss_MonitorInfo *cur = &ctx->monitors[level][j];
			union spoolss_MonitorInfo *ref = &ctx->monitors[2][j];
			switch (level) {
			case 1:
				COMPARE_STRING(tctx, cur->info1, ref->info2, monitor_name);
				break;
			case 2:
				/* level 2 is our reference, and it makes no sense to compare it to itself */
				break;
			}
		}
	}

	return true;
}

static bool test_EnumPrintProcessors(struct torture_context *tctx, 
				     struct dcerpc_pipe *p,
				     struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_EnumPrintProcessors r;
	uint16_t levels[] = { 1 };
	int i, j;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;
		uint32_t needed;
		uint32_t count;
		union spoolss_PrintProcessorInfo *info;

		r.in.servername = "";
		r.in.environment = "Windows NT x86";
		r.in.level = level;
		r.in.buffer = NULL;
		r.in.offered = 0;
		r.out.needed = &needed;
		r.out.count = &count;
		r.out.info = &info;

		torture_comment(tctx, "Testing EnumPrintProcessors level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrintProcessors(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumPrintProcessors failed");
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		torture_assert_werr_equal(tctx, r.out.result, WERR_INSUFFICIENT_BUFFER, 
			"EnumPrintProcessors unexpected return code");

		blob = data_blob_talloc(ctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;

		status = dcerpc_spoolss_EnumPrintProcessors(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumPrintProcessors failed");

		torture_assert_werr_ok(tctx, r.out.result, "EnumPrintProcessors failed");

		ctx->print_processor_count[level]	= count;
		ctx->print_processors[level]		= info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		torture_assert_int_equal(tctx, ctx->print_processor_count[level], ctx->print_processor_count[old_level],
			"EnumPrintProcessors failed");
	}

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		for (j=0;j<ctx->print_processor_count[level];j++) {
#if 0
			union spoolss_PrintProcessorInfo *cur = &ctx->print_processors[level][j];
			union spoolss_PrintProcessorInfo *ref = &ctx->print_processors[1][j];
#endif
			switch (level) {
			case 1:
				/* level 1 is our reference, and it makes no sense to compare it to itself */
				break;
			}
		}
	}

	return true;
}

static bool test_EnumPrintProcDataTypes(struct torture_context *tctx,
					struct dcerpc_pipe *p,
					struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_EnumPrintProcDataTypes r;
	uint16_t levels[] = { 1 };
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;
		uint32_t needed;
		uint32_t count;
		union spoolss_PrintProcDataTypesInfo *info;

		r.in.servername = "";
		r.in.print_processor_name = "winprint";
		r.in.level = level;
		r.in.buffer = NULL;
		r.in.offered = 0;
		r.out.needed = &needed;
		r.out.count = &count;
		r.out.info = &info;

		torture_comment(tctx, "Testing EnumPrintProcDataTypes level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrintProcDataTypes(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumPrintProcDataType failed");
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		torture_assert_werr_equal(tctx, r.out.result, WERR_INSUFFICIENT_BUFFER,
			"EnumPrintProcDataTypes unexpected return code");

		blob = data_blob_talloc(ctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;

		status = dcerpc_spoolss_EnumPrintProcDataTypes(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumPrintProcDataTypes failed");

		torture_assert_werr_ok(tctx, r.out.result, "EnumPrintProcDataTypes failed");
	}

	return true;
}


static bool test_EnumPrinters(struct torture_context *tctx, 
			      struct dcerpc_pipe *p,
			      struct test_spoolss_context *ctx)
{
	struct spoolss_EnumPrinters r;
	NTSTATUS status;
	uint16_t levels[] = { 0, 1, 2, 4, 5 };
	int i, j;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;
		uint32_t needed;
		uint32_t count;
		union spoolss_PrinterInfo *info;

		r.in.flags	= PRINTER_ENUM_LOCAL;
		r.in.server	= "";
		r.in.level	= level;
		r.in.buffer	= NULL;
		r.in.offered	= 0;
		r.out.needed	= &needed;
		r.out.count	= &count;
		r.out.info	= &info;

		torture_comment(tctx, "Testing EnumPrinters level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinters(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumPrinters failed");
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		torture_assert_werr_equal(tctx, r.out.result, WERR_INSUFFICIENT_BUFFER, 
			"EnumPrinters unexpected return code");

		blob = data_blob_talloc(ctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;

		status = dcerpc_spoolss_EnumPrinters(p, ctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EnumPrinters failed");

		torture_assert_werr_ok(tctx, r.out.result, "EnumPrinters failed");

		ctx->printer_count[level]	= count;
		ctx->printers[level]		= info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		torture_assert_int_equal(tctx, ctx->printer_count[level], ctx->printer_count[old_level],
					 "EnumPrinters invalid value");
	}

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		for (j=0;j<ctx->printer_count[level];j++) {
			union spoolss_PrinterInfo *cur = &ctx->printers[level][j];
			union spoolss_PrinterInfo *ref = &ctx->printers[2][j];
			switch (level) {
			case 0:
				COMPARE_STRING(tctx, cur->info0, ref->info2, printername);
				COMPARE_STRING(tctx, cur->info0, ref->info2, servername);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, cjobs);
				/*COMPARE_UINT32(tctx, cur->info0, ref->info2, total_jobs);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, total_bytes);
				COMPARE_SPOOLSS_TIME(cur->info0, ref->info2, spoolss_Time time);		
				COMPARE_UINT32(tctx, cur->info0, ref->info2, global_counter);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, total_pages);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, version);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown10);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown11);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown12);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, session_counter);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown14);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, printer_errors);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown16);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown17);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown18);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown19);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, change_id);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown21);*/
				COMPARE_UINT32(tctx, cur->info0, ref->info2, status);
				/*COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown23);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, c_setprinter);
				COMPARE_UINT16(cur->info0, ref->info2, unknown25);
				COMPARE_UINT16(cur->info0, ref->info2, unknown26);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown27);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown28);
				COMPARE_UINT32(tctx, cur->info0, ref->info2, unknown29);*/
				break;
			case 1:
				/*COMPARE_UINT32(tctx, cur->info1, ref->info2, flags);*/
				/*COMPARE_STRING(tctx, cur->info1, ref->info2, name);*/
				/*COMPARE_STRING(tctx, cur->info1, ref->info2, description);*/
				COMPARE_STRING(tctx, cur->info1, ref->info2, comment);
				break;
			case 2:
				/* level 2 is our reference, and it makes no sense to compare it to itself */
				break;
			case 4:
				COMPARE_STRING(tctx, cur->info4, ref->info2, printername);
				COMPARE_STRING(tctx, cur->info4, ref->info2, servername);
				COMPARE_UINT32(tctx, cur->info4, ref->info2, attributes);
				break;
			case 5:
				COMPARE_STRING(tctx, cur->info5, ref->info2, printername);
				COMPARE_STRING(tctx, cur->info5, ref->info2, portname);
				COMPARE_UINT32(tctx, cur->info5, ref->info2, attributes);
				/*COMPARE_UINT32(tctx, cur->info5, ref->info2, device_not_selected_timeout);
				COMPARE_UINT32(tctx, cur->info5, ref->info2, transmission_retry_timeout);*/
				break;
			}
		}
	}

	/* TODO:
	 * 	- verify that the port of a printer was in the list returned by EnumPorts
	 */

	return true;
}

static bool test_GetPrinter(struct torture_context *tctx, 
			    struct dcerpc_pipe *p, 
		     struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_GetPrinter r;
	uint16_t levels[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
	int i;
	uint32_t needed;
	
	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.handle = handle;
		r.in.level = levels[i];
		r.in.buffer = NULL;
		r.in.offered = 0;
		r.out.needed = &needed;

		torture_comment(tctx, "Testing GetPrinter level %u\n", r.in.level);

		status = dcerpc_spoolss_GetPrinter(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "GetPrinter failed");
		
		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(tctx, NULL, needed);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			r.in.offered = needed;
			status = dcerpc_spoolss_GetPrinter(p, tctx, &r);
		}
		
		torture_assert_ntstatus_ok(tctx, status, "GetPrinter failed");

		torture_assert_werr_ok(tctx, r.out.result, "GetPrinter failed");
	}

	return true;
}


static bool test_ClosePrinter(struct torture_context *tctx, 
			      struct dcerpc_pipe *p, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_ClosePrinter r;

	r.in.handle = handle;
	r.out.handle = handle;

	torture_comment(tctx, "Testing ClosePrinter\n");

	status = dcerpc_spoolss_ClosePrinter(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "ClosePrinter failed");

	return true;
}

static bool test_GetForm(struct torture_context *tctx, 
			 struct dcerpc_pipe *p, 
			 struct policy_handle *handle, 
			 const char *form_name,
			 uint32_t level)
{
	NTSTATUS status;
	struct spoolss_GetForm r;
	uint32_t needed;

	r.in.handle = handle;
	r.in.form_name = form_name;
	r.in.level = level;
	r.in.buffer = NULL;
	r.in.offered = 0;
	r.out.needed = &needed;

	torture_comment(tctx, "Testing GetForm level %d\n", r.in.level);

	status = dcerpc_spoolss_GetForm(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "GetForm failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(tctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;
		status = dcerpc_spoolss_GetForm(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "GetForm failed");

		torture_assert_werr_ok(tctx, r.out.result, "GetForm failed");

		torture_assert(tctx, r.out.info, "No form info returned");
	}

	torture_assert_werr_ok(tctx, r.out.result, "GetForm failed");

	return true;
}

static bool test_EnumForms(struct torture_context *tctx, 
			   struct dcerpc_pipe *p, 
			   struct policy_handle *handle, bool print_server)
{
	NTSTATUS status;
	struct spoolss_EnumForms r;
	bool ret = true;
	uint32_t needed;
	uint32_t count;
	uint32_t levels[] = { 1, 2 };
	int i;

	for (i=0; i<ARRAY_SIZE(levels); i++) {

		union spoolss_FormInfo *info;

		r.in.handle = handle;
		r.in.level = levels[i];
		r.in.buffer = NULL;
		r.in.offered = 0;
		r.out.needed = &needed;
		r.out.count = &count;
		r.out.info = &info;

		torture_comment(tctx, "Testing EnumForms level %d\n", levels[i]);

		status = dcerpc_spoolss_EnumForms(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "EnumForms failed");

		if ((r.in.level == 2) && (W_ERROR_EQUAL(r.out.result, WERR_UNKNOWN_LEVEL))) {
			break;
		}

		if (print_server && W_ERROR_EQUAL(r.out.result, WERR_BADFID))
			torture_fail(tctx, "EnumForms on the PrintServer isn't supported by test server (NT4)");

		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			int j;
			DATA_BLOB blob = data_blob_talloc(tctx, NULL, needed);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			r.in.offered = needed;

			status = dcerpc_spoolss_EnumForms(p, tctx, &r);

			torture_assert(tctx, info, "No forms returned");

			for (j = 0; j < count; j++) {
				if (!print_server)
					ret &= test_GetForm(tctx, p, handle, info[j].info1.form_name, levels[i]);
			}
		}

		torture_assert_ntstatus_ok(tctx, status, "EnumForms failed");

		torture_assert_werr_ok(tctx, r.out.result, "EnumForms failed");
	}

	return true;
}

static bool test_DeleteForm(struct torture_context *tctx, 
			    struct dcerpc_pipe *p, 
			    struct policy_handle *handle, 
			    const char *form_name)
{
	NTSTATUS status;
	struct spoolss_DeleteForm r;

	r.in.handle = handle;
	r.in.form_name = form_name;

	status = dcerpc_spoolss_DeleteForm(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "DeleteForm failed");

	torture_assert_werr_ok(tctx, r.out.result, "DeleteForm failed");

	return true;
}

static bool test_AddForm(struct torture_context *tctx, 
			 struct dcerpc_pipe *p, 
			 struct policy_handle *handle, bool print_server)
{
	struct spoolss_AddForm r;
	struct spoolss_AddFormInfo1 addform;
	const char *form_name = "testform3";
	NTSTATUS status;
	bool ret = true;

	r.in.handle	= handle;
	r.in.level	= 1;
	r.in.info.info1 = &addform;
	addform.flags		= SPOOLSS_FORM_USER;
	addform.form_name	= form_name;
	addform.size.width	= 50;
	addform.size.height	= 25;
	addform.area.left	= 5;
	addform.area.top	= 10;
	addform.area.right	= 45;
	addform.area.bottom	= 15;

	status = dcerpc_spoolss_AddForm(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "AddForm failed");

	torture_assert_werr_ok(tctx, r.out.result, "AddForm failed");

	if (!print_server) ret &= test_GetForm(tctx, p, handle, form_name, 1);

	{
		struct spoolss_SetForm sf;
		struct spoolss_AddFormInfo1 setform;

		sf.in.handle	= handle;
		sf.in.form_name = form_name;
		sf.in.level	= 1;
		sf.in.info.info1= &setform;
		setform.flags		= addform.flags;
		setform.form_name	= addform.form_name;
		setform.size		= addform.size;
		setform.area		= addform.area;

		setform.size.width	= 1234;

		status = dcerpc_spoolss_SetForm(p, tctx, &sf);

		torture_assert_ntstatus_ok(tctx, status, "SetForm failed");

		torture_assert_werr_ok(tctx, r.out.result, "SetForm failed");
	}

	if (!print_server) ret &= test_GetForm(tctx, p, handle, form_name, 1);

	if (!test_DeleteForm(tctx, p, handle, form_name)) {
		ret = false;
	}

	return ret;
}

static bool test_EnumPorts_old(struct torture_context *tctx, 
			       struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct spoolss_EnumPorts r;
	uint32_t needed;
	uint32_t count;
	union spoolss_PortInfo *info;

	r.in.servername = talloc_asprintf(tctx, "\\\\%s", 
					  dcerpc_server_name(p));
	r.in.level = 2;
	r.in.buffer = NULL;
	r.in.offered = 0;
	r.out.needed = &needed;
	r.out.count = &count;
	r.out.info = &info;

	torture_comment(tctx, "Testing EnumPorts\n");

	status = dcerpc_spoolss_EnumPorts(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "EnumPorts failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(tctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;

		status = dcerpc_spoolss_EnumPorts(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "EnumPorts failed");

		torture_assert(tctx, info, "No ports returned");
	}

	return true;
}

static bool test_AddPort(struct torture_context *tctx, 
			 struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct spoolss_AddPort r;

	r.in.server_name = talloc_asprintf(tctx, "\\\\%s", 
					   dcerpc_server_name(p));
	r.in.unknown = 0;
	r.in.monitor_name = "foo";

	torture_comment(tctx, "Testing AddPort\n");

	status = dcerpc_spoolss_AddPort(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "AddPort failed");

	/* win2k3 returns WERR_NOT_SUPPORTED */

#if 0

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("AddPort failed - %s\n", win_errstr(r.out.result));
		return false;
	}

#endif

	return true;
}

static bool test_GetJob(struct torture_context *tctx, 
			struct dcerpc_pipe *p, 
			struct policy_handle *handle, uint32_t job_id)
{
	NTSTATUS status;
	struct spoolss_GetJob r;
	uint32_t needed;
	uint32_t levels[] = {1, 2 /* 3, 4 */};
	uint32_t i;

	r.in.handle = handle;
	r.in.job_id = job_id;
	r.in.level = 0;
	r.in.buffer = NULL;
	r.in.offered = 0;
	r.out.needed = &needed;

	torture_comment(tctx, "Testing GetJob level %d\n", r.in.level);

	status = dcerpc_spoolss_GetJob(p, tctx, &r);
	torture_assert_werr_equal(tctx, r.out.result, WERR_UNKNOWN_LEVEL, "Unexpected return code");

	for (i = 0; i < ARRAY_SIZE(levels); i++) {

		torture_comment(tctx, "Testing GetJob level %d\n", r.in.level);

		r.in.level = levels[i];
		r.in.offered = 0;

		status = dcerpc_spoolss_GetJob(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "GetJob failed");

		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(tctx, NULL, needed);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			r.in.offered = needed;

			status = dcerpc_spoolss_GetJob(p, tctx, &r);
			torture_assert_ntstatus_ok(tctx, status, "GetJob failed");

		}
		torture_assert(tctx, r.out.info, "No job info returned");
		torture_assert_werr_ok(tctx, r.out.result, "GetJob failed");
	}

	return true;
}

static bool test_SetJob(struct torture_context *tctx, 
			struct dcerpc_pipe *p, 
			struct policy_handle *handle, uint32_t job_id, 
			enum spoolss_JobControl command)
{
	NTSTATUS status;
	struct spoolss_SetJob r;

	r.in.handle	= handle;
	r.in.job_id	= job_id;
	r.in.ctr	= NULL;
	r.in.command	= command;

	switch (command) {
	case SPOOLSS_JOB_CONTROL_PAUSE:
		torture_comment(tctx, "Testing SetJob: SPOOLSS_JOB_CONTROL_PAUSE\n");
		break;
	case SPOOLSS_JOB_CONTROL_RESUME:
		torture_comment(tctx, "Testing SetJob: SPOOLSS_JOB_CONTROL_RESUME\n");
		break;
	case SPOOLSS_JOB_CONTROL_CANCEL:
		torture_comment(tctx, "Testing SetJob: SPOOLSS_JOB_CONTROL_CANCEL\n");
		break;
	case SPOOLSS_JOB_CONTROL_RESTART:
		torture_comment(tctx, "Testing SetJob: SPOOLSS_JOB_CONTROL_RESTART\n");
		break;
	case SPOOLSS_JOB_CONTROL_DELETE:
		torture_comment(tctx, "Testing SetJob: SPOOLSS_JOB_CONTROL_DELETE\n");
		break;
	case SPOOLSS_JOB_CONTROL_SEND_TO_PRINTER:
		torture_comment(tctx, "Testing SetJob: SPOOLSS_JOB_CONTROL_SEND_TO_PRINTER\n");
		break;
	case SPOOLSS_JOB_CONTROL_LAST_PAGE_EJECTED:
		torture_comment(tctx, "Testing SetJob: SPOOLSS_JOB_CONTROL_LAST_PAGE_EJECTED\n");
		break;
	case SPOOLSS_JOB_CONTROL_RETAIN:
		torture_comment(tctx, "Testing SetJob: SPOOLSS_JOB_CONTROL_RETAIN\n");
		break;
	case SPOOLSS_JOB_CONTROL_RELEASE:
		torture_comment(tctx, "Testing SetJob: SPOOLSS_JOB_CONTROL_RELEASE\n");
		break;
	default:
		torture_comment(tctx, "Testing SetJob\n");
		break;
	}

	status = dcerpc_spoolss_SetJob(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "SetJob failed");
	torture_assert_werr_ok(tctx, r.out.result, "SetJob failed");

	return true;
}

static bool test_AddJob(struct torture_context *tctx,
			struct dcerpc_pipe *p,
			struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_AddJob r;
	uint32_t needed;

	r.in.level = 0;
	r.in.handle = handle;
	r.in.offered = 0;
	r.out.needed = &needed;
	r.in.buffer = r.out.buffer = NULL;

	torture_comment(tctx, "Testing AddJob\n");

	status = dcerpc_spoolss_AddJob(p, tctx, &r);
	torture_assert_werr_equal(tctx, r.out.result, WERR_UNKNOWN_LEVEL, "AddJob failed");

	r.in.level = 1;

	status = dcerpc_spoolss_AddJob(p, tctx, &r);
	torture_assert_werr_equal(tctx, r.out.result, WERR_INVALID_PARAM, "AddJob failed");

	return true;
}


static bool test_EnumJobs(struct torture_context *tctx, 
			  struct dcerpc_pipe *p, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumJobs r;
	uint32_t needed;
	uint32_t count;
	union spoolss_JobInfo *info;

	r.in.handle = handle;
	r.in.firstjob = 0;
	r.in.numjobs = 0xffffffff;
	r.in.level = 1;
	r.in.buffer = NULL;
	r.in.offered = 0;
	r.out.needed = &needed;
	r.out.count = &count;
	r.out.info = &info;

	torture_comment(tctx, "Testing EnumJobs\n");

	status = dcerpc_spoolss_EnumJobs(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "EnumJobs failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		int j;
		DATA_BLOB blob = data_blob_talloc(tctx, NULL, needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = needed;

		status = dcerpc_spoolss_EnumJobs(p, tctx, &r);

		torture_assert(tctx, info, "No jobs returned");

		for (j = 0; j < count; j++) {

			test_GetJob(tctx, p, handle, info[j].info1.job_id);

			/* FIXME - gd */
			if (!torture_setting_bool(tctx, "samba3", false)) {
				test_SetJob(tctx, p, handle, info[j].info1.job_id, SPOOLSS_JOB_CONTROL_PAUSE);
				test_SetJob(tctx, p, handle, info[j].info1.job_id, SPOOLSS_JOB_CONTROL_RESUME);
			}
		}

	} else {
		torture_assert_werr_ok(tctx, r.out.result, "EnumJobs failed");
	}

	return true;
}

static bool test_DoPrintTest(struct torture_context *tctx, 
			     struct dcerpc_pipe *p, 
			     struct policy_handle *handle)
{
	bool ret = true;
	NTSTATUS status;
	struct spoolss_StartDocPrinter s;
	struct spoolss_DocumentInfo1 info1;
	struct spoolss_StartPagePrinter sp;
	struct spoolss_WritePrinter w;
	struct spoolss_EndPagePrinter ep;
	struct spoolss_EndDocPrinter e;
	int i;
	uint32_t job_id;
	uint32_t num_written;

	torture_comment(tctx, "Testing StartDocPrinter\n");

	s.in.handle		= handle;
	s.in.level		= 1;
	s.in.info.info1		= &info1;
	s.out.job_id		= &job_id;
	info1.document_name	= "TorturePrintJob";
	info1.output_file	= NULL;
	info1.datatype		= "RAW";

	status = dcerpc_spoolss_StartDocPrinter(p, tctx, &s);
	torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_StartDocPrinter failed");
	torture_assert_werr_ok(tctx, s.out.result, "StartDocPrinter failed");

	for (i=1; i < 4; i++) {
		torture_comment(tctx, "Testing StartPagePrinter: Page[%d]\n", i);

		sp.in.handle		= handle;

		status = dcerpc_spoolss_StartPagePrinter(p, tctx, &sp);
		torture_assert_ntstatus_ok(tctx, status, 
					   "dcerpc_spoolss_StartPagePrinter failed");
		torture_assert_werr_ok(tctx, sp.out.result, "StartPagePrinter failed");

		torture_comment(tctx, "Testing WritePrinter: Page[%d]\n", i);

		w.in.handle		= handle;
		w.in.data		= data_blob_string_const(talloc_asprintf(tctx,"TortureTestPage: %d\nData\n",i));
		w.out.num_written	= &num_written;

		status = dcerpc_spoolss_WritePrinter(p, tctx, &w);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_WritePrinter failed");
		torture_assert_werr_ok(tctx, w.out.result, "WritePrinter failed");

		torture_comment(tctx, "Testing EndPagePrinter: Page[%d]\n", i);

		ep.in.handle		= handle;

		status = dcerpc_spoolss_EndPagePrinter(p, tctx, &ep);
		torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EndPagePrinter failed");
		torture_assert_werr_ok(tctx, ep.out.result, "EndPagePrinter failed");
	}

	torture_comment(tctx, "Testing EndDocPrinter\n");

	e.in.handle = handle;

	status = dcerpc_spoolss_EndDocPrinter(p, tctx, &e);
	torture_assert_ntstatus_ok(tctx, status, "dcerpc_spoolss_EndDocPrinter failed");
	torture_assert_werr_ok(tctx, e.out.result, "EndDocPrinter failed");

	ret &= test_AddJob(tctx, p, handle);
	ret &= test_EnumJobs(tctx, p, handle);

	ret &= test_SetJob(tctx, p, handle, job_id, SPOOLSS_JOB_CONTROL_DELETE);

	return ret;
}

static bool test_PausePrinter(struct torture_context *tctx, 
			      struct dcerpc_pipe *p, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_SetPrinter r;
	struct spoolss_SetPrinterInfoCtr info_ctr;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct sec_desc_buf secdesc_ctr;

	info_ctr.level = 0;
	info_ctr.info.info0 = NULL;

	ZERO_STRUCT(devmode_ctr);
	ZERO_STRUCT(secdesc_ctr);

	r.in.handle		= handle;
	r.in.info_ctr		= &info_ctr;
	r.in.devmode_ctr	= &devmode_ctr;
	r.in.secdesc_ctr	= &secdesc_ctr;
	r.in.command		= SPOOLSS_PRINTER_CONTROL_PAUSE;

	torture_comment(tctx, "Testing SetPrinter: SPOOLSS_PRINTER_CONTROL_PAUSE\n");

	status = dcerpc_spoolss_SetPrinter(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "SetPrinter failed");

	torture_assert_werr_ok(tctx, r.out.result, "SetPrinter failed");

	return true;
}

static bool test_ResumePrinter(struct torture_context *tctx, 
			       struct dcerpc_pipe *p, 
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_SetPrinter r;
	struct spoolss_SetPrinterInfoCtr info_ctr;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct sec_desc_buf secdesc_ctr;

	info_ctr.level = 0;
	info_ctr.info.info0 = NULL;

	ZERO_STRUCT(devmode_ctr);
	ZERO_STRUCT(secdesc_ctr);

	r.in.handle		= handle;
	r.in.info_ctr		= &info_ctr;
	r.in.devmode_ctr	= &devmode_ctr;
	r.in.secdesc_ctr	= &secdesc_ctr;
	r.in.command		= SPOOLSS_PRINTER_CONTROL_RESUME;

	torture_comment(tctx, "Testing SetPrinter: SPOOLSS_PRINTER_CONTROL_RESUME\n");

	status = dcerpc_spoolss_SetPrinter(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "SetPrinter failed");

	torture_assert_werr_ok(tctx, r.out.result, "SetPrinter failed");

	return true;
}

static bool test_GetPrinterData(struct torture_context *tctx, 
				struct dcerpc_pipe *p, 
				struct policy_handle *handle, 
				const char *value_name)
{
	NTSTATUS status;
	struct spoolss_GetPrinterData r;
	uint32_t needed;
	enum winreg_Type type;
	union spoolss_PrinterData data;

	r.in.handle = handle;
	r.in.value_name = value_name;
	r.in.offered = 0;
	r.out.needed = &needed;
	r.out.type = &type;
	r.out.data = &data;

	torture_comment(tctx, "Testing GetPrinterData\n");

	status = dcerpc_spoolss_GetPrinterData(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "GetPrinterData failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.in.offered = needed;

		status = dcerpc_spoolss_GetPrinterData(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "GetPrinterData failed");

		torture_assert_werr_ok(tctx, r.out.result, "GetPrinterData failed");
	}

	return true;
}

static bool test_GetPrinterDataEx(struct torture_context *tctx, 
				  struct dcerpc_pipe *p, 
				  struct policy_handle *handle, 
				  const char *key_name,
				  const char *value_name)
{
	NTSTATUS status;
	struct spoolss_GetPrinterDataEx r;
	enum winreg_Type type;
	uint32_t needed;

	r.in.handle = handle;
	r.in.key_name = key_name;
	r.in.value_name = value_name;
	r.in.offered = 0;
	r.out.type = &type;
	r.out.needed = &needed;
	r.out.buffer = NULL;

	torture_comment(tctx, "Testing GetPrinterDataEx\n");

	status = dcerpc_spoolss_GetPrinterDataEx(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_NET_WRITE_FAULT) &&
		    p->last_fault_code == DCERPC_FAULT_OP_RNG_ERROR) {
			torture_skip(tctx, "GetPrinterDataEx not supported by server\n");
		}
		torture_assert_ntstatus_ok(tctx, status, "GetPrinterDataEx failed");
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.in.offered = needed;
		r.out.buffer = talloc_array(tctx, uint8_t, needed);

		status = dcerpc_spoolss_GetPrinterDataEx(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "GetPrinterDataEx failed");

		torture_assert_werr_ok(tctx, r.out.result,  "GetPrinterDataEx failed");
	}

	return true;
}

static bool test_EnumPrinterData(struct torture_context *tctx, struct dcerpc_pipe *p, 
				 struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumPrinterData r;

	ZERO_STRUCT(r);
	r.in.handle = handle;
	r.in.enum_index = 0;

	do {
		uint32_t value_size = 0;
		uint32_t data_size = 0;
		enum winreg_Type type = 0;

		r.in.value_offered = value_size;
		r.out.value_needed = &value_size;
		r.in.data_offered = data_size;
		r.out.data_needed = &data_size;

		r.out.type = &type;
		r.out.data = talloc_zero_array(tctx, uint8_t, 0);

		torture_comment(tctx, "Testing EnumPrinterData\n");

		status = dcerpc_spoolss_EnumPrinterData(p, tctx, &r);

		torture_assert_ntstatus_ok(tctx, status, "EnumPrinterData failed");

		r.in.value_offered = value_size;
		r.out.value_name = talloc_zero_array(tctx, const char, value_size);
		r.in.data_offered = data_size;
		r.out.data = talloc_zero_array(tctx, uint8_t, data_size);

		status = dcerpc_spoolss_EnumPrinterData(p, tctx, &r);

		torture_assert_ntstatus_ok(tctx, status, "EnumPrinterData failed");
		
		test_GetPrinterData(tctx, p, handle, r.out.value_name);

		test_GetPrinterDataEx(tctx, 
			p, handle, "PrinterDriverData", 
			r.out.value_name);

		r.in.enum_index++;

	} while (W_ERROR_IS_OK(r.out.result));

	return true;
}

static bool test_EnumPrinterDataEx(struct torture_context *tctx, 
				   struct dcerpc_pipe *p, 
				   struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumPrinterDataEx r;
	struct spoolss_PrinterEnumValues *info;
	uint32_t needed;
	uint32_t count;

	r.in.handle = handle;
	r.in.key_name = "PrinterDriverData";
	r.in.offered = 0;
	r.out.needed = &needed;
	r.out.count = &count;
	r.out.info = &info;

	torture_comment(tctx, "Testing EnumPrinterDataEx\n");

	status = dcerpc_spoolss_EnumPrinterDataEx(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "EnumPrinterDataEx failed");

	r.in.offered = needed;

	status = dcerpc_spoolss_EnumPrinterDataEx(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "EnumPrinterDataEx failed");

	return true;
}


static bool test_DeletePrinterData(struct torture_context *tctx, 
				   struct dcerpc_pipe *p, 
				   struct policy_handle *handle, 
				   const char *value_name)
{
	NTSTATUS status;
	struct spoolss_DeletePrinterData r;

	r.in.handle = handle;
	r.in.value_name = value_name;

	torture_comment(tctx, "Testing DeletePrinterData\n");

	status = dcerpc_spoolss_DeletePrinterData(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "DeletePrinterData failed");

	return true;
}

static bool test_SetPrinterData(struct torture_context *tctx, 
				struct dcerpc_pipe *p, 
				struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_SetPrinterData r;
	const char *value_name = "spottyfoot";
	
	r.in.handle = handle;
	r.in.value_name = value_name;
	r.in.type = REG_SZ;
	r.in.data.string = "dog";

	torture_comment(tctx, "Testing SetPrinterData\n");

	status = dcerpc_spoolss_SetPrinterData(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "SetPrinterData failed");

	if (!test_GetPrinterData(tctx, p, handle, value_name)) {
		return false;
	}

	if (!test_DeletePrinterData(tctx, p, handle, value_name)) {
		return false;
	}

	return true;
}

static bool test_SecondaryClosePrinter(struct torture_context *tctx, 
				       struct dcerpc_pipe *p, 
				       struct policy_handle *handle)
{
	NTSTATUS status;
	struct dcerpc_binding *b;
	struct dcerpc_pipe *p2;
	struct spoolss_ClosePrinter cp;

	/* only makes sense on SMB */
	if (p->conn->transport.transport != NCACN_NP) {
		return true;
	}

	torture_comment(tctx, "testing close on secondary pipe\n");

	status = dcerpc_parse_binding(tctx, p->conn->binding_string, &b);
	torture_assert_ntstatus_ok(tctx, status, "Failed to parse dcerpc binding");

	status = dcerpc_secondary_connection(p, &p2, b);
	torture_assert_ntstatus_ok(tctx, status, "Failed to create secondary connection");

	status = dcerpc_bind_auth_none(p2, &ndr_table_spoolss);
	torture_assert_ntstatus_ok(tctx, status, "Failed to create bind on secondary connection");

	cp.in.handle = handle;
	cp.out.handle = handle;

	status = dcerpc_spoolss_ClosePrinter(p2, tctx, &cp);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_NET_WRITE_FAULT,
			"ERROR: Allowed close on secondary connection");

	torture_assert_int_equal(tctx, p2->last_fault_code, DCERPC_FAULT_CONTEXT_MISMATCH, 
				 "Unexpected fault code");

	talloc_free(p2);

	return true;
}

static bool test_OpenPrinter_badname(struct torture_context *tctx, 
				     struct dcerpc_pipe *p, const char *name)
{
	NTSTATUS status;
	struct spoolss_OpenPrinter op;
	struct spoolss_OpenPrinterEx opEx;
	struct policy_handle handle;
	bool ret = true;

	op.in.printername	= name;
	op.in.datatype		= NULL;
	op.in.devmode_ctr.devmode= NULL;
	op.in.access_mask	= 0;
	op.out.handle		= &handle;

	torture_comment(tctx, "\nTesting OpenPrinter(%s) with bad name\n", op.in.printername);

	status = dcerpc_spoolss_OpenPrinter(p, tctx, &op);
	torture_assert_ntstatus_ok(tctx, status, "OpenPrinter failed");
	if (!W_ERROR_EQUAL(WERR_INVALID_PRINTER_NAME,op.out.result)) {
		torture_comment(tctx, "OpenPrinter(%s) unexpected result[%s] should be WERR_INVALID_PRINTER_NAME\n",
			name, win_errstr(op.out.result));
	}

	if (W_ERROR_IS_OK(op.out.result)) {
		ret &=test_ClosePrinter(tctx, p, &handle);
	}

	opEx.in.printername		= name;
	opEx.in.datatype		= NULL;
	opEx.in.devmode_ctr.devmode	= NULL;
	opEx.in.access_mask		= 0;
	opEx.in.level			= 1;
	opEx.in.userlevel.level1	= NULL;
	opEx.out.handle			= &handle;

	torture_comment(tctx, "Testing OpenPrinterEx(%s) with bad name\n", opEx.in.printername);

	status = dcerpc_spoolss_OpenPrinterEx(p, tctx, &opEx);
	torture_assert_ntstatus_ok(tctx, status, "OpenPrinterEx failed");
	if (!W_ERROR_EQUAL(WERR_INVALID_PARAM,opEx.out.result)) {
		torture_comment(tctx, "OpenPrinterEx(%s) unexpected result[%s] should be WERR_INVALID_PARAM\n",
			name, win_errstr(opEx.out.result));
	}

	if (W_ERROR_IS_OK(opEx.out.result)) {
		ret &=test_ClosePrinter(tctx, p, &handle);
	}

	return ret;
}

static bool test_OpenPrinter(struct torture_context *tctx, 
			     struct dcerpc_pipe *p, 
			     const char *name)
{
	NTSTATUS status;
	struct spoolss_OpenPrinter r;
	struct policy_handle handle;
	bool ret = true;

	r.in.printername	= talloc_asprintf(tctx, "\\\\%s\\%s", dcerpc_server_name(p), name);
	r.in.datatype		= NULL;
	r.in.devmode_ctr.devmode= NULL;
	r.in.access_mask	= SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle		= &handle;

	torture_comment(tctx, "Testing OpenPrinter(%s)\n", r.in.printername);

	status = dcerpc_spoolss_OpenPrinter(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "OpenPrinter failed");

	torture_assert_werr_ok(tctx, r.out.result, "OpenPrinter failed");

	if (!test_GetPrinter(tctx, p, &handle)) {
		ret = false;
	}

	if (!torture_setting_bool(tctx, "samba3", false)) {
		if (!test_SecondaryClosePrinter(tctx, p, &handle)) {
			ret = false;
		}
	}

	if (!test_ClosePrinter(tctx, p, &handle)) {
		ret = false;
	}

	return ret;
}

static bool call_OpenPrinterEx(struct torture_context *tctx, 
			       struct dcerpc_pipe *p, 
			       const char *name, struct policy_handle *handle)
{
	struct spoolss_OpenPrinterEx r;
	struct spoolss_UserLevel1 userlevel1;
	NTSTATUS status;

	if (name && name[0]) {
		r.in.printername = talloc_asprintf(tctx, "\\\\%s\\%s", 
						   dcerpc_server_name(p), name);
	} else {
		r.in.printername = talloc_asprintf(tctx, "\\\\%s", 
						   dcerpc_server_name(p));
	}

	r.in.datatype		= NULL;
	r.in.devmode_ctr.devmode= NULL;
	r.in.access_mask	= SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.level		= 1;
	r.in.userlevel.level1	= &userlevel1;
	r.out.handle = handle;

	userlevel1.size = 1234;
	userlevel1.client = "hello";
	userlevel1.user = "spottyfoot!";
	userlevel1.build = 1;
	userlevel1.major = 2;
	userlevel1.minor = 3;
	userlevel1.processor = 4;

	torture_comment(tctx, "Testing OpenPrinterEx(%s)\n", r.in.printername);

	status = dcerpc_spoolss_OpenPrinterEx(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "OpenPrinterEx failed");
	
	torture_assert_werr_ok(tctx, r.out.result, "OpenPrinterEx failed");

	return true;
}

static bool test_OpenPrinterEx(struct torture_context *tctx, 
			       struct dcerpc_pipe *p, 
			       const char *name)
{
	struct policy_handle handle;
	bool ret = true;

	if (!call_OpenPrinterEx(tctx, p, name, &handle)) {
		return false;
	}

	if (!test_GetPrinter(tctx, p, &handle)) {
		ret = false;
	}

	if (!test_EnumForms(tctx, p, &handle, false)) {
		ret = false;
	}

	if (!test_AddForm(tctx, p, &handle, false)) {
		ret = false;
	}

	if (!test_EnumPrinterData(tctx, p, &handle)) {
		ret = false;
	}

	if (!test_EnumPrinterDataEx(tctx, p, &handle)) {
		ret = false;
	}

	if (!test_PausePrinter(tctx, p, &handle)) {
		ret = false;
	}

	if (!test_DoPrintTest(tctx, p, &handle)) {
		ret = false;
	}

	if (!test_ResumePrinter(tctx, p, &handle)) {
		ret = false;
	}

	if (!test_SetPrinterData(tctx, p, &handle)) {
		ret = false;
	}

	if (!torture_setting_bool(tctx, "samba3", false)) {
		if (!test_SecondaryClosePrinter(tctx, p, &handle)) {
			ret = false;
		}
	}

	if (!test_ClosePrinter(tctx, p, &handle)) {
		ret = false;
	}
	
	return ret;
}

static bool test_EnumPrinters_old(struct torture_context *tctx, struct dcerpc_pipe *p)
{
	struct spoolss_EnumPrinters r;
	NTSTATUS status;
	uint16_t levels[] = {1, 2, 4, 5};
	int i;
	bool ret = true;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		union spoolss_PrinterInfo *info;
		int j;
		uint32_t needed;
		uint32_t count;

		r.in.flags	= PRINTER_ENUM_LOCAL;
		r.in.server	= "";
		r.in.level	= levels[i];
		r.in.buffer	= NULL;
		r.in.offered	= 0;
		r.out.needed	= &needed;
		r.out.count	= &count;
		r.out.info	= &info;

		torture_comment(tctx, "Testing EnumPrinters level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinters(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "EnumPrinters failed");

		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(tctx, NULL, needed);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			r.in.offered = needed;
			status = dcerpc_spoolss_EnumPrinters(p, tctx, &r);
		}

		torture_assert_ntstatus_ok(tctx, status, "EnumPrinters failed");

		torture_assert_werr_ok(tctx, r.out.result, "EnumPrinters failed");

		if (!info) {
			torture_comment(tctx, "No printers returned\n");
			return true;
		}

		for (j=0;j<count;j++) {
			if (r.in.level == 1) {
				char *unc = talloc_strdup(tctx, info[j].info1.name);
				char *slash, *name;
				name = unc;
				if (unc[0] == '\\' && unc[1] == '\\') {
					unc +=2;
				}
				slash = strchr(unc, '\\');
				if (slash) {
					slash++;
					name = slash;
				}
				if (!test_OpenPrinter(tctx, p, name)) {
					ret = false;
				}
				if (!test_OpenPrinterEx(tctx, p, name)) {
					ret = false;
				}
			}
		}
	}

	return ret;
}

#if 0
static bool test_GetPrinterDriver2(struct dcerpc_pipe *p, 
				   struct policy_handle *handle, 
				   const char *driver_name)
{
	NTSTATUS status;
	struct spoolss_GetPrinterDriver2 r;
	uint32_t needed;
	uint32_t server_major_version;
	uint32_t server_minor_version;

	r.in.handle = handle;
	r.in.architecture = "W32X86";
	r.in.level = 1;
	r.in.buffer = NULL;
	r.in.offered = 0;
	r.in.client_major_version = 0;
	r.in.client_minor_version = 0;
	r.out.needed = &needed;
	r.out.server_major_version = &server_major_version;
	r.out.server_minor_version = &server_minor_version;

	printf("Testing GetPrinterDriver2\n");

	status = dcerpc_spoolss_GetPrinterDriver2(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetPrinterDriver2 failed - %s\n", nt_errstr(status));
		return false;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		r.in.offered = needed;
		status = dcerpc_spoolss_GetPrinterDriver2(p, tctx, &r);
	}
		
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetPrinterDriver2 failed - %s\n", 
		       nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("GetPrinterDriver2 failed - %s\n", 
		       win_errstr(r.out.result));
		return false;
	}

	return true;
}
#endif

static bool test_EnumPrinterDrivers_old(struct torture_context *tctx, 
					struct dcerpc_pipe *p)
{
	struct spoolss_EnumPrinterDrivers r;
	NTSTATUS status;
	uint16_t levels[] = {1, 2, 3, 4, 5, 6};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {

		uint32_t needed;
		uint32_t count;
		union spoolss_DriverInfo *info;

		r.in.server = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
		r.in.environment = "Windows NT x86";
		r.in.level = levels[i];
		r.in.buffer = NULL;
		r.in.offered = 0;
		r.out.needed = &needed;
		r.out.count = &count;
		r.out.info = &info;

		torture_comment(tctx, "Testing EnumPrinterDrivers level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinterDrivers(p, tctx, &r);

		torture_assert_ntstatus_ok(tctx, status, "EnumPrinterDrivers failed");

		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(tctx, NULL, needed);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			r.in.offered = needed;
			status = dcerpc_spoolss_EnumPrinterDrivers(p, tctx, &r);
		}

		torture_assert_ntstatus_ok(tctx, status, "EnumPrinterDrivers failed");

		torture_assert_werr_ok(tctx, r.out.result, "EnumPrinterDrivers failed");

		if (!info) {
			torture_comment(tctx, "No printer drivers returned\n");
			break;
		}
	}

	return true;
}

bool torture_rpc_spoolss(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	bool ret = true;
	struct test_spoolss_context *ctx;

	status = torture_rpc_connection(torture, &p, &ndr_table_spoolss);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	ctx = talloc_zero(torture, struct test_spoolss_context);

	ret &= test_OpenPrinter_server(torture, p, ctx);

	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "W3SvcInstalled");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "BeepEnabled");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "EventLog");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "NetPopup");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "NetPopupToComputer");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "MajorVersion");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "MinorVersion");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "DefaultSpoolDirectory");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "Architecture");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "DsPresent");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "OSVersion");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "OSVersionEx");
	ret &= test_GetPrinterData(torture, p, &ctx->server_handle, "DNSMachineName");
	ret &= test_EnumForms(torture, p, &ctx->server_handle, true);
	ret &= test_AddForm(torture, p, &ctx->server_handle, true);
	ret &= test_EnumPorts(torture, p, ctx);
	ret &= test_GetPrinterDriverDirectory(torture, p, ctx);
	ret &= test_GetPrintProcessorDirectory(torture, p, ctx);
	ret &= test_EnumPrinterDrivers(torture, p, ctx);
	ret &= test_EnumMonitors(torture, p, ctx);
	ret &= test_EnumPrintProcessors(torture, p, ctx);
	ret &= test_EnumPrintProcDataTypes(torture, p, ctx);
	ret &= test_EnumPrinters(torture, p, ctx);
	ret &= test_OpenPrinter_badname(torture, p, "__INVALID_PRINTER__");
	ret &= test_OpenPrinter_badname(torture, p, "\\\\__INVALID_HOST__");
	ret &= test_OpenPrinter_badname(torture, p, "");
	ret &= test_OpenPrinter_badname(torture, p, "\\\\\\");
	ret &= test_OpenPrinter_badname(torture, p, "\\\\\\__INVALID_PRINTER__");
	ret &= test_OpenPrinter_badname(torture, p, talloc_asprintf(torture, "\\\\%s\\", dcerpc_server_name(p)));
	ret &= test_OpenPrinter_badname(torture, p, 
					talloc_asprintf(torture, "\\\\%s\\__INVALID_PRINTER__", dcerpc_server_name(p)));


	ret &= test_AddPort(torture, p);
	ret &= test_EnumPorts_old(torture, p);
	ret &= test_EnumPrinters_old(torture, p);
	ret &= test_EnumPrinterDrivers_old(torture, p);

	return ret;
}
