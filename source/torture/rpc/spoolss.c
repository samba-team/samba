/* 
   Unix SMB/CIFS implementation.
   test suite for spoolss rpc operations

   Copyright (C) Tim Potter 2003
   Copyright (C) Stefan Metzmacher 2005
   
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
	struct dcerpc_pipe *p;

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

#define COMPARE_STRING(c,r,e) do {\
	BOOL _ok = True;\
	if (c.e && !r.e) _ok = False;\
	if (!c.e && r.e) _ok = False;\
	if (c.e && r.e && strcmp_safe(c.e, r.e) != 0) _ok = False;\
	if (!_ok){\
		printf("%s: " #c "." #e " [%s] doesn't match " #r "." #e " [%s]\n",\
			__location__, c.e, r.e);\
		ret = False;\
	}\
} while(0)

/* not every compiler supports __typeof__() */
#if (__GNUC__ >= 3)
#define _CHECK_FIELD_SIZE(c,r,e,type) do {\
	if (sizeof(__typeof__(c.e)) != sizeof(type)) { \
		printf(__location__ ":" #c "." #e "field is not " #type "\n"); \
		smb_panic(__location__ ":" #c "." #e "field is not " #type ); \
		ret = False; \
	}\
	if (sizeof(__typeof__(r.e)) != sizeof(type)) { \
		printf(__location__ ":" #r "." #e "field is not " #type "\n"); \
		smb_panic(__location__ ":" #r "." #e "field is not " #type ); \
		ret = False; \
	}\
} while(0)
#else
#define _CHECK_FIELD_SIZE(c,r,e,type) do {} while(0)
#endif

#if 0 /* unused */
#define COMPARE_UINT16(c,r,e) do {\
	_CHECK_FIELD_SIZE(c,r,e,uint16_t); \
	if (c.e != r.e){\
		printf("%s: " #c "." #e "  0x%04X (%u) doesn't match " #r "." #e " 0x%04X (%u)\n",\
			__location__, c.e, c.e, r.e, r.e);\
		ret = False;\
	}\
} while(0)
#endif

#define COMPARE_UINT32(c,r,e) do {\
	_CHECK_FIELD_SIZE(c,r,e,uint32_t); \
	if (c.e != r.e){\
		printf("%s: " #c "." #e "  0x%08X (%u) doesn't match " #r "." #e " 0x%08X (%u)\n",\
			__location__, c.e, c.e, r.e, r.e);\
		ret = False;\
	}\
} while(0)

#if 0 /* unused */
#define COMPARE_UINT64(c,r,e) do {\
	_CHECK_FIELD_SIZE(c,r,e,uint64_t); \
	if (c.e != r.e){\
		printf("%s: " #c "." #e "  0x%016llX (%llu) doesn't match " #r "." #e " 0x%016llX (%llu)\n",\
			__location__, c.e, c.e, r.e, r.e);\
		ret = False;\
	}\
} while(0)
#endif

/* TODO: ! */
#if 0 /* unused */
#define COMPARE_SEC_DESC(c,r,e)
#define COMPARE_SPOOLSS_TIME(c,r,e)
#endif
#define COMPARE_STRING_ARRAY(c,r,e)

static BOOL test_OpenPrinter_server(struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_OpenPrinter op;
	BOOL ret = True;

	op.in.printername	= talloc_asprintf(ctx, "\\\\%s", dcerpc_server_name(ctx->p));
	op.in.datatype		= NULL;
	op.in.devmode_ctr.devmode= NULL;
	op.in.access_mask	= 0;
	op.out.handle		= &ctx->server_handle;

	printf("\nTesting OpenPrinter(%s)\n", op.in.printername);

	status = dcerpc_spoolss_OpenPrinter(ctx->p, ctx, &op);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_spoolss_OpenPrinter failed - %s\n", nt_errstr(status));
		ret = False;
	}
	if (!W_ERROR_IS_OK(op.out.result)) {
		printf("OpenPrinter(%s) failed - %s\n",
			op.in.printername, win_errstr(op.out.result));
		ret = False;
	}

	return ret;
}

static BOOL test_EnumPorts(struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_EnumPorts r;
	uint16_t levels[] = { 1, 2 };
	int i, j;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;

		r.in.servername = "";
		r.in.level = level;
		r.in.buffer = NULL;
		r.in.offered = 0;

		printf("Testing EnumPorts level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPorts(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumPorts failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		if (!W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			printf("EnumPorts unexspected return code %s, should be WERR_INSUFFICIENT_BUFFER\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		blob = data_blob_talloc(ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_EnumPorts(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumPorts failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("EnumPorts failed - %s\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		ctx->port_count[level]	= r.out.count;
		ctx->ports[level]	= r.out.info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		if (ctx->port_count[level] != ctx->port_count[old_level]) {
			printf("EnumPorts level[%d] returns [%u] ports, but level[%d] returns [%u]\n",
				level, ctx->port_count[level], old_level, ctx->port_count[old_level]);
			ret = False;
		}
	}
	/* if the array sizes are not the same we would maybe segfault in the following code */
	if (!ret) return ret;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		for (j=0;j<ctx->port_count[level];j++) {
			union spoolss_PortInfo *cur = &ctx->ports[level][j];
			union spoolss_PortInfo *ref = &ctx->ports[2][j];
			switch (level) {
			case 1:
				COMPARE_STRING(cur->info1, ref->info2, port_name);
				break;
			case 2:
				/* level 2 is our reference, and it makes no sense to compare it to itself */
				break;
			}
		}
	}

	return True;
}

static BOOL test_GetPrinterDriverDirectory(struct test_spoolss_context *ctx)
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
			.server	= talloc_asprintf(ctx, "\\\\%s", dcerpc_server_name(ctx->p))
		},{
			.level	= 1024,
			.server	= talloc_asprintf(ctx, "\\\\%s", dcerpc_server_name(ctx->p))
		}
	};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i].level;
		DATA_BLOB blob;

		r.in.server		= levels[i].server;
		r.in.environment	= SPOOLSS_ARCHITECTURE_NT_X86;
		r.in.level		= level;
		r.in.buffer		= NULL;
		r.in.offered		= 0;

		printf("Testing GetPrinterDriverDirectory level %u\n", r.in.level);

		status = dcerpc_spoolss_GetPrinterDriverDirectory(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_GetPrinterDriverDirectory failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			printf("GetPrinterDriverDirectory unexspected return code %s, should be WERR_INSUFFICIENT_BUFFER\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		blob = data_blob_talloc(ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_GetPrinterDriverDirectory(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_GetPrinterDriverDirectory failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("GetPrinterDriverDirectory failed - %s\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}
	}

	return True;
}

static BOOL test_EnumPrinterDrivers(struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_EnumPrinterDrivers r;
	uint16_t levels[] = { 1, 2, 3, 4, 5, 6 };
	int i, j;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;

		r.in.server		= "";
		r.in.environment	= SPOOLSS_ARCHITECTURE_NT_X86;
		r.in.level		= level;
		r.in.buffer		= NULL;
		r.in.offered		= 0;

		printf("Testing EnumPrinterDrivers level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinterDrivers(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumPrinterDrivers failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		if (!W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			printf("EnumPrinterDrivers unexspected return code %s, should be WERR_INSUFFICIENT_BUFFER\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		blob = data_blob_talloc(ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_EnumPrinterDrivers(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumPrinterDrivers failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("EnumPrinterDrivers failed - %s\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		ctx->driver_count[level]	= r.out.count;
		ctx->drivers[level]		= r.out.info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		if (ctx->driver_count[level] != ctx->driver_count[old_level]) {
			printf("EnumPrinterDrivers level[%d] returns [%u] drivers, but level[%d] returns [%u]\n",
				level, ctx->driver_count[level], old_level, ctx->driver_count[old_level]);
			ret = False;
		}
	}
	/* if the array sizes are not the same we would maybe segfault in the following code */
	if (!ret) return ret;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		for (j=0;j<ctx->driver_count[level];j++) {
			union spoolss_DriverInfo *cur = &ctx->drivers[level][j];
			union spoolss_DriverInfo *ref = &ctx->drivers[6][j];
			switch (level) {
			case 1:
				COMPARE_STRING(cur->info1, ref->info6, driver_name);
				break;
			case 2:
				COMPARE_UINT32(cur->info2, ref->info6, version);
				COMPARE_STRING(cur->info2, ref->info6, driver_name);
				COMPARE_STRING(cur->info2, ref->info6, architecture);
				COMPARE_STRING(cur->info2, ref->info6, driver_path);
				COMPARE_STRING(cur->info2, ref->info6, data_file);
				COMPARE_STRING(cur->info2, ref->info6, config_file);
				break;
			case 3:
				COMPARE_UINT32(cur->info3, ref->info6, version);
				COMPARE_STRING(cur->info3, ref->info6, driver_name);
				COMPARE_STRING(cur->info3, ref->info6, architecture);
				COMPARE_STRING(cur->info3, ref->info6, driver_path);
				COMPARE_STRING(cur->info3, ref->info6, data_file);
				COMPARE_STRING(cur->info3, ref->info6, config_file);
				COMPARE_STRING(cur->info3, ref->info6, help_file);
				COMPARE_STRING_ARRAY(cur->info3, ref->info6, dependent_files);
				COMPARE_STRING(cur->info3, ref->info6, monitor_name);
				COMPARE_STRING(cur->info3, ref->info6, default_datatype);
				break;
			case 4:
				COMPARE_UINT32(cur->info4, ref->info6, version);
				COMPARE_STRING(cur->info4, ref->info6, driver_name);
				COMPARE_STRING(cur->info4, ref->info6, architecture);
				COMPARE_STRING(cur->info4, ref->info6, driver_path);
				COMPARE_STRING(cur->info4, ref->info6, data_file);
				COMPARE_STRING(cur->info4, ref->info6, config_file);
				COMPARE_STRING(cur->info4, ref->info6, help_file);
				COMPARE_STRING_ARRAY(cur->info4, ref->info6, dependent_files);
				COMPARE_STRING(cur->info4, ref->info6, monitor_name);
				COMPARE_STRING(cur->info4, ref->info6, default_datatype);
				COMPARE_STRING_ARRAY(cur->info4, ref->info6, previous_names);
				break;
			case 5:
				COMPARE_UINT32(cur->info5, ref->info6, version);
				COMPARE_STRING(cur->info5, ref->info6, driver_name);
				COMPARE_STRING(cur->info5, ref->info6, architecture);
				COMPARE_STRING(cur->info5, ref->info6, driver_path);
				COMPARE_STRING(cur->info5, ref->info6, data_file);
				COMPARE_STRING(cur->info5, ref->info6, config_file);
				/*COMPARE_UINT32(cur->info5, ref->info6, driver_attributes);*/
				/*COMPARE_UINT32(cur->info5, ref->info6, config_version);*/
				/*TODO: ! COMPARE_UINT32(cur->info5, ref->info6, driver_version); */
				break;
			case 6:
				/* level 6 is our reference, and it makes no sense to compare it to itself */
				break;
			}
		}
	}

	return ret;
}

static BOOL test_EnumMonitors(struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_EnumMonitors r;
	uint16_t levels[] = { 1, 2 };
	int i, j;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;

		r.in.servername = "";
		r.in.level = level;
		r.in.buffer = NULL;
		r.in.offered = 0;

		printf("Testing EnumMonitors level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumMonitors(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumMonitors failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		if (!W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			printf("EnumMonitors unexspected return code %s, should be WERR_INSUFFICIENT_BUFFER\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		blob = data_blob_talloc(ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_EnumMonitors(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumMonitors failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("EnumMonitors failed - %s\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		ctx->monitor_count[level]	= r.out.count;
		ctx->monitors[level]		= r.out.info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		if (ctx->monitor_count[level] != ctx->monitor_count[old_level]) {
			printf("EnumMonitors level[%d] returns [%u] monitors, but level[%d] returns [%u]\n",
				level, ctx->monitor_count[level], old_level, ctx->monitor_count[old_level]);
			ret = False;
		}
	}
	/* if the array sizes are not the same we would maybe segfault in the following code */
	if (!ret) return ret;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		for (j=0;j<ctx->monitor_count[level];j++) {
			union spoolss_MonitorInfo *cur = &ctx->monitors[level][j];
			union spoolss_MonitorInfo *ref = &ctx->monitors[2][j];
			switch (level) {
			case 1:
				COMPARE_STRING(cur->info1, ref->info2, monitor_name);
				break;
			case 2:
				/* level 2 is our reference, and it makes no sense to compare it to itself */
				break;
			}
		}
	}

	return ret;
}

static BOOL test_EnumPrintProcessors(struct test_spoolss_context *ctx)
{
	NTSTATUS status;
	struct spoolss_EnumPrintProcessors r;
	uint16_t levels[] = { 1 };
	int i, j;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;

		r.in.servername = "";
		r.in.environment = "Windows NT x86";
		r.in.level = level;
		r.in.buffer = NULL;
		r.in.offered = 0;

		printf("Testing EnumPrintProcessors level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrintProcessors(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumPrintProcessors failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		if (!W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			printf("EnumPrintProcessors unexspected return code %s, should be WERR_INSUFFICIENT_BUFFER\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		blob = data_blob_talloc(ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_EnumPrintProcessors(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumPrintProcessors failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("EnumPrintProcessors failed - %s\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		ctx->print_processor_count[level]	= r.out.count;
		ctx->print_processors[level]		= r.out.info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		if (ctx->print_processor_count[level] != ctx->print_processor_count[old_level]) {
			printf("EnumPrintProcessors level[%d] returns [%u] print_processors, but level[%d] returns [%u]\n",
				level, ctx->print_processor_count[level], old_level, ctx->print_processor_count[old_level]);
			ret = False;
		}
	}
	/* if the array sizes are not the same we would maybe segfault in the following code */
	if (!ret) return ret;

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

	return ret;
}

static BOOL test_EnumPrinters(struct test_spoolss_context *ctx)
{
	struct spoolss_EnumPrinters r;
	NTSTATUS status;
	uint16_t levels[] = { 0, 1, 2, 4, 5 };
	int i, j;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		DATA_BLOB blob;

		r.in.flags	= PRINTER_ENUM_LOCAL;
		r.in.server	= "";
		r.in.level	= level;
		r.in.buffer	= NULL;
		r.in.offered	= 0;

		printf("\nTesting EnumPrinters level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinters(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumPrinters failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
		if (W_ERROR_IS_OK(r.out.result)) {
			/* TODO: do some more checks here */
			continue;
		}
		if (!W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			printf("EnumPrinters unexspected return code %s, should be WERR_INSUFFICIENT_BUFFER\n",
				win_errstr(r.out.result));
			ret = False;
			continue;
		}

		blob = data_blob_talloc(ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_EnumPrinters(ctx->p, ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EnumPrinters failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("EnumPrinters failed - %s\n", 
			       win_errstr(r.out.result));
			continue;
		}

		ctx->printer_count[level]	= r.out.count;
		ctx->printers[level]		= r.out.info;
	}

	for (i=1;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		int old_level = levels[i-1];
		if (ctx->printer_count[level] != ctx->printer_count[old_level]) {
			printf("EnumPrinters level[%d] returns [%u] printers, but level[%d] returns [%u]\n",
				level, ctx->printer_count[level], old_level, ctx->printer_count[old_level]);
			ret = False;
		}
	}
	/* if the array sizes are not the same we would maybe segfault in the following code */
	if (!ret) return ret;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int level = levels[i];
		for (j=0;j<ctx->printer_count[level];j++) {
			union spoolss_PrinterInfo *cur = &ctx->printers[level][j];
			union spoolss_PrinterInfo *ref = &ctx->printers[2][j];
			switch (level) {
			case 0:
				COMPARE_STRING(cur->info0, ref->info2, printername);
				COMPARE_STRING(cur->info0, ref->info2, servername);
				COMPARE_UINT32(cur->info0, ref->info2, cjobs);
				/*COMPARE_UINT32(cur->info0, ref->info2, total_jobs);
				COMPARE_UINT32(cur->info0, ref->info2, total_bytes);
				COMPARE_SPOOLSS_TIME(cur->info0, ref->info2, spoolss_Time time);		
				COMPARE_UINT32(cur->info0, ref->info2, global_counter);
				COMPARE_UINT32(cur->info0, ref->info2, total_pages);
				COMPARE_UINT32(cur->info0, ref->info2, version);
				COMPARE_UINT32(cur->info0, ref->info2, unknown10);
				COMPARE_UINT32(cur->info0, ref->info2, unknown11);
				COMPARE_UINT32(cur->info0, ref->info2, unknown12);
				COMPARE_UINT32(cur->info0, ref->info2, session_counter);
				COMPARE_UINT32(cur->info0, ref->info2, unknown14);
				COMPARE_UINT32(cur->info0, ref->info2, printer_errors);
				COMPARE_UINT32(cur->info0, ref->info2, unknown16);
				COMPARE_UINT32(cur->info0, ref->info2, unknown17);
				COMPARE_UINT32(cur->info0, ref->info2, unknown18);
				COMPARE_UINT32(cur->info0, ref->info2, unknown19);
				COMPARE_UINT32(cur->info0, ref->info2, change_id);
				COMPARE_UINT32(cur->info0, ref->info2, unknown21);*/
				COMPARE_UINT32(cur->info0, ref->info2, status);
				/*COMPARE_UINT32(cur->info0, ref->info2, unknown23);
				COMPARE_UINT32(cur->info0, ref->info2, c_setprinter);
				COMPARE_UINT16(cur->info0, ref->info2, unknown25);
				COMPARE_UINT16(cur->info0, ref->info2, unknown26);
				COMPARE_UINT32(cur->info0, ref->info2, unknown27);
				COMPARE_UINT32(cur->info0, ref->info2, unknown28);
				COMPARE_UINT32(cur->info0, ref->info2, unknown29);*/
				break;
			case 1:
				/*COMPARE_UINT32(cur->info1, ref->info2, flags);*/
				/*COMPARE_STRING(cur->info1, ref->info2, name);*/
				/*COMPARE_STRING(cur->info1, ref->info2, description);*/
				COMPARE_STRING(cur->info1, ref->info2, comment);
				break;
			case 2:
				/* level 2 is our reference, and it makes no sense to compare it to itself */
				break;
			case 4:
				COMPARE_STRING(cur->info4, ref->info2, printername);
				COMPARE_STRING(cur->info4, ref->info2, servername);
				COMPARE_UINT32(cur->info4, ref->info2, attributes);
				break;
			case 5:
				COMPARE_STRING(cur->info5, ref->info2, printername);
				COMPARE_STRING(cur->info5, ref->info2, portname);
				COMPARE_UINT32(cur->info5, ref->info2, attributes);
				/*COMPARE_UINT32(cur->info5, ref->info2, device_not_selected_timeout);
				COMPARE_UINT32(cur->info5, ref->info2, transmission_retry_timeout);*/
				break;
			}
		}
	}

	/* TODO:
	 * 	- verify that the port of a printer was in the list returned by EnumPorts
	 */

	return ret;
}

static BOOL test_GetPrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		     struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_GetPrinter r;
	uint16_t levels[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
	int i;
	BOOL ret = True;
	
	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.handle = handle;
		r.in.level = levels[i];
		r.in.buffer = NULL;
		r.in.offered = 0;

		printf("Testing GetPrinter level %u\n", r.in.level);

		status = dcerpc_spoolss_GetPrinter(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("GetPrinter failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
		
		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, r.out.needed);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			r.in.offered = r.out.needed;
			status = dcerpc_spoolss_GetPrinter(p, mem_ctx, &r);
		}
		
		if (!NT_STATUS_IS_OK(status)) {
			printf("GetPrinter failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("GetPrinter failed - %s\n", 
			       win_errstr(r.out.result));
			ret = False;
			continue;
		}
	}

	return ret;
}


static BOOL test_ClosePrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		       struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_ClosePrinter r;

	r.in.handle = handle;
	r.out.handle = handle;

	printf("Testing ClosePrinter\n");

	status = dcerpc_spoolss_ClosePrinter(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ClosePrinter failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_GetForm(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle, 
			 const char *form_name)
{
	NTSTATUS status;
	struct spoolss_GetForm r;

	r.in.handle = handle;
	r.in.form_name = form_name;
	r.in.level = 1;
	r.in.buffer = NULL;
	r.in.offered = 0;

	printf("Testing GetForm\n");

	status = dcerpc_spoolss_GetForm(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetForm failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;
		status = dcerpc_spoolss_GetForm(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("GetForm failed - %s\n",
				nt_errstr(status));
			return False;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("GetForm failed - %s\n",
				win_errstr(r.out.result));
			return False;
		}

		if (!r.out.info) {
			printf("No form info returned\n");
			return False;
		}
	}


	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("GetForm failed - %s\n",
			win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_EnumForms(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		    struct policy_handle *handle, BOOL print_server)
{
	NTSTATUS status;
	struct spoolss_EnumForms r;
	BOOL ret = True;

	r.in.handle = handle;
	r.in.level = 1;
	r.in.buffer = NULL;
	r.in.offered = 0;

	printf("Testing EnumForms\n");

	status = dcerpc_spoolss_EnumForms(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumForms failed - %s\n", nt_errstr(status));
		return False;
	}

	if (print_server && W_ERROR_EQUAL(r.out.result,WERR_BADFID)) {
		printf("EnumForms on the PrintServer isn't supported by test server (NT4)\n");
		return True;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		union spoolss_FormInfo *info;
		int j;
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_EnumForms(p, mem_ctx, &r);

		if (!r.out.info) {
			printf("No forms returned\n");
			return False;
		}

		info = r.out.info;

		for (j = 0; j < r.out.count; j++) {
			if (!print_server) ret &= test_GetForm(p, mem_ctx, handle, info[j].info1.form_name);
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumForms failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("EnumForms failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_DeleteForm(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *handle, 
			    const char *form_name)
{
	NTSTATUS status;
	struct spoolss_DeleteForm r;

	r.in.handle = handle;
	r.in.form_name = form_name;

	status = dcerpc_spoolss_DeleteForm(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteForm failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DeleteForm failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_AddForm(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		  struct policy_handle *handle, BOOL print_server)
{
	struct spoolss_AddForm r;
	struct spoolss_AddFormInfo1 addform;
	const char *form_name = "testform3";
	NTSTATUS status;
	BOOL ret = True;

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

	status = dcerpc_spoolss_AddForm(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("AddForm failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("AddForm failed - %s\n", win_errstr(r.out.result));
		goto done;
	}

	if (!print_server) ret &= test_GetForm(p, mem_ctx, handle, form_name);

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

		status = dcerpc_spoolss_SetForm(p, mem_ctx, &sf);

		if (!NT_STATUS_IS_OK(status)) {
			printf("SetForm failed - %s\n", nt_errstr(status));
			ret = False;
			goto done;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("SetForm failed - %s\n", 
			       win_errstr(r.out.result));
			ret = False;
			goto done;
		}
	}

	if (!print_server) ret &= test_GetForm(p, mem_ctx, handle, form_name);

 done:
	if (!test_DeleteForm(p, mem_ctx, handle, form_name)) {
		printf("DeleteForm failed\n");
		ret = False;
	}

	return ret;
}

static BOOL test_EnumPorts_old(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct spoolss_EnumPorts r;

	r.in.servername = talloc_asprintf(mem_ctx, "\\\\%s", 
					  dcerpc_server_name(p));
	r.in.level = 2;
	r.in.buffer = NULL;
	r.in.offered = 0;

	printf("Testing EnumPorts\n");

	status = dcerpc_spoolss_EnumPorts(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPorts failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_EnumPorts(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPorts failed - %s\n", nt_errstr(status));
			return False;
		}

		if (!r.out.info) {
			printf("No ports returned\n");
			return False;
		}
	}

	return True;
}

static BOOL test_AddPort(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct spoolss_AddPort r;

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", 
					   dcerpc_server_name(p));
	r.in.unknown = 0;
	r.in.monitor_name = "foo";

	printf ("Testing AddPort\n");

	status = dcerpc_spoolss_AddPort(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("AddPort failed - %s\n", nt_errstr(status));
		return False;
	}

	/* win2k3 returns WERR_NOT_SUPPORTED */

#if 0

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("AddPort failed - %s\n", win_errstr(r.out.result));
		return False;
	}

#endif

	return True;
}

static BOOL test_GetJob(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		  struct policy_handle *handle, uint32_t job_id)
{
	NTSTATUS status;
	struct spoolss_GetJob r;

	r.in.handle = handle;
	r.in.job_id = job_id;
	r.in.level = 1;
	r.in.buffer = NULL;
	r.in.offered = 0;

	printf("Testing GetJob\n");

	status = dcerpc_spoolss_GetJob(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetJob failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_GetJob(p, mem_ctx, &r);

		if (!r.out.info) {
			printf("No job info returned\n");
			return False;
		}
	}

	return True;
}

static BOOL test_SetJob(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		 struct policy_handle *handle, uint32_t job_id, enum spoolss_JobControl command)
{
	NTSTATUS status;
	struct spoolss_SetJob r;

	r.in.handle	= handle;
	r.in.job_id	= job_id;
	r.in.ctr	= NULL;
	r.in.command	= command;

	printf("Testing SetJob\n");

	status = dcerpc_spoolss_SetJob(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetJob failed - %s\n", nt_errstr(status));
		return False;
	}
	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("SetJob failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_EnumJobs(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		   struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumJobs r;

	r.in.handle = handle;
	r.in.firstjob = 0;
	r.in.numjobs = 0xffffffff;
	r.in.level = 1;
	r.in.buffer = NULL;
	r.in.offered = 0;

	printf("Testing EnumJobs\n");

	status = dcerpc_spoolss_EnumJobs(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumJobs failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		union spoolss_JobInfo *info;
		int j;
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, r.out.needed);
		data_blob_clear(&blob);
		r.in.buffer = &blob;
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_EnumJobs(p, mem_ctx, &r);

		if (!r.out.info) {
			printf("No jobs returned\n");
			return True;
		}

		info = r.out.info;

		for (j = 0; j < r.out.count; j++) {
			test_GetJob(p, mem_ctx, handle, info[j].info1.job_id);
			test_SetJob(p, mem_ctx, handle, info[j].info1.job_id, SPOOLSS_JOB_CONTROL_PAUSE);
			test_SetJob(p, mem_ctx, handle, info[j].info1.job_id, SPOOLSS_JOB_CONTROL_RESUME);
		}

	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("EnumJobs failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_DoPrintTest(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		   struct policy_handle *handle)
{
	BOOL ret = True;
	NTSTATUS status;
	struct spoolss_StartDocPrinter s;
	struct spoolss_DocumentInfo1 info1;
	struct spoolss_StartPagePrinter sp;
	struct spoolss_WritePrinter w;
	struct spoolss_EndPagePrinter ep;
	struct spoolss_EndDocPrinter e;
	int i;
	uint32_t job_id;

	printf("Testing StartDocPrinter\n");

	s.in.handle		= handle;
	s.in.level		= 1;
	s.in.info.info1		= &info1;
	info1.document_name	= "TorturePrintJob";
	info1.output_file	= NULL;
	info1.datatype		= "RAW";

	status = dcerpc_spoolss_StartDocPrinter(p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_spoolss_StartDocPrinter failed - %s\n", nt_errstr(status));
		return False;
	}
	if (!W_ERROR_IS_OK(s.out.result)) {
		printf("StartDocPrinter failed - %s\n", win_errstr(s.out.result));
		return False;
	}

	job_id = s.out.job_id;

	for (i=1; i < 4; i++) {
		printf("Testing StartPagePrinter: Page[%d]\n", i);

		sp.in.handle		= handle;

		status = dcerpc_spoolss_StartPagePrinter(p, mem_ctx, &sp);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_StartPagePrinter failed - %s\n", nt_errstr(status));
			return False;
		}
		if (!W_ERROR_IS_OK(sp.out.result)) {
			printf("StartPagePrinter failed - %s\n", win_errstr(sp.out.result));
			return False;
		}

		printf("Testing WritePrinter: Page[%d]\n", i);

		w.in.handle		= handle;
		w.in.data		= data_blob_string_const(talloc_asprintf(mem_ctx,"TortureTestPage: %d\nData\n",i));

		status = dcerpc_spoolss_WritePrinter(p, mem_ctx, &w);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_WritePrinter failed - %s\n", nt_errstr(status));
			return False;
		}
		if (!W_ERROR_IS_OK(w.out.result)) {
			printf("WritePrinter failed - %s\n", win_errstr(w.out.result));
			return False;
		}

		printf("Testing EndPagePrinter: Page[%d]\n", i);

		ep.in.handle		= handle;

		status = dcerpc_spoolss_EndPagePrinter(p, mem_ctx, &ep);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_spoolss_EndPagePrinter failed - %s\n", nt_errstr(status));
			return False;
		}
		if (!W_ERROR_IS_OK(ep.out.result)) {
			printf("EndPagePrinter failed - %s\n", win_errstr(ep.out.result));
			return False;
		}
	}

	printf("Testing EndDocPrinter\n");

	e.in.handle = handle;

	status = dcerpc_spoolss_EndDocPrinter(p, mem_ctx, &e);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_spoolss_EndDocPrinter failed - %s\n", nt_errstr(status));
		return False;
	}
	if (!W_ERROR_IS_OK(e.out.result)) {
		printf("EndDocPrinter failed - %s\n", win_errstr(e.out.result));
		return False;
	}

	ret &= test_EnumJobs(p, mem_ctx, handle);

	ret &= test_SetJob(p, mem_ctx, handle, job_id, SPOOLSS_JOB_CONTROL_DELETE);

	return ret;
}

static BOOL test_PausePrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		   struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_SetPrinter r;

	r.in.handle		= handle;
	r.in.level		= 0;
	r.in.info.info1		= NULL;
	r.in.devmode_ctr.devmode= NULL;
	r.in.secdesc_ctr.sd	= NULL;
	r.in.command		= SPOOLSS_PRINTER_CONTROL_PAUSE;

	printf("Testing SetPrinter: SPOOLSS_PRINTER_CONTROL_PAUSE\n");

	status = dcerpc_spoolss_SetPrinter(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("SetPrinter failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("SetPrinter failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_ResumePrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		   struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_SetPrinter r;

	r.in.handle		= handle;
	r.in.level		= 0;
	r.in.info.info1		= NULL;
	r.in.devmode_ctr.devmode= NULL;
	r.in.secdesc_ctr.sd	= NULL;
	r.in.command		= SPOOLSS_PRINTER_CONTROL_RESUME;

	printf("Testing SetPrinter: SPOOLSS_PRINTER_CONTROL_RESUME\n");

	status = dcerpc_spoolss_SetPrinter(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("SetPrinter failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("SetPrinter failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_GetPrinterData(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				struct policy_handle *handle, 
				const char *value_name)
{
	NTSTATUS status;
	struct spoolss_GetPrinterData r;

	r.in.handle = handle;
	r.in.value_name = value_name;
	r.in.offered = 0;

	printf("Testing GetPrinterData\n");

	status = dcerpc_spoolss_GetPrinterData(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetPrinterData failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_GetPrinterData(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("GetPrinterData failed - %s\n", 
			       nt_errstr(status));
			return False;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("GetPrinterData failed - %s\n", 
			       win_errstr(r.out.result));
			return False;
		}
	}

	return True;
}

static BOOL test_GetPrinterDataEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				  struct policy_handle *handle, 
				  const char *key_name,
				  const char *value_name)
{
	NTSTATUS status;
	struct spoolss_GetPrinterDataEx r;

	r.in.handle = handle;
	r.in.key_name = key_name;
	r.in.value_name = value_name;
	r.in.offered = 0;

	printf("Testing GetPrinterDataEx\n");

	status = dcerpc_spoolss_GetPrinterDataEx(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_NET_WRITE_FAULT) &&
		    p->last_fault_code == DCERPC_FAULT_OP_RNG_ERROR) {
			printf("GetPrinterDataEx not supported by server\n");
			return True;
		}
		printf("GetPrinterDataEx failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.in.offered = r.out.needed;

		status = dcerpc_spoolss_GetPrinterDataEx(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("GetPrinterDataEx failed - %s\n", 
			       nt_errstr(status));
			return False;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("GetPrinterDataEx failed - %s\n", 
			       win_errstr(r.out.result));
			return False;
		}
	}

	return True;
}

static BOOL test_EnumPrinterData(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				 struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumPrinterData r;

	r.in.handle = handle;
	r.in.enum_index = 0;

	do {
		uint32_t data_size;
		
		r.in.value_offered = 0;
		data_size = 0;
		r.in.data_size = &data_size;
		r.out.data_size = &data_size;

		printf("Testing EnumPrinterData\n");

		status = dcerpc_spoolss_EnumPrinterData(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrinterData failed - %s\n", nt_errstr(status));
			return False;
		}

		r.in.value_offered = r.out.value_needed;

		status = dcerpc_spoolss_EnumPrinterData(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrinterData failed - %s\n", nt_errstr(status));
			return False;
		}
		
		test_GetPrinterData(p, mem_ctx, handle, r.out.value_name);

		test_GetPrinterDataEx(
			p, mem_ctx, handle, "PrinterDriverData", 
			r.out.value_name);

		r.in.enum_index++;

	} while (W_ERROR_IS_OK(r.out.result));

	return True;
}

static BOOL test_EnumPrinterDataEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				   struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumPrinterDataEx r;

	r.in.handle = handle;
	r.in.key_name = "PrinterDriverData";
	r.in.offered = 0;

	printf("Testing EnumPrinterDataEx\n");

	status = dcerpc_spoolss_EnumPrinterDataEx(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrinterDataEx failed - %s\n", nt_errstr(status));
		return False;
	}

	r.in.offered = r.out.needed;

	status = dcerpc_spoolss_EnumPrinterDataEx(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrinterDataEx failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_DeletePrinterData(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				   struct policy_handle *handle, 
				   const char *value_name)
{
	NTSTATUS status;
	struct spoolss_DeletePrinterData r;

	r.in.handle = handle;
	r.in.value_name = value_name;

	printf("Testing DeletePrinterData\n");

	status = dcerpc_spoolss_DeletePrinterData(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("DeletePrinterData failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_SetPrinterData(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_SetPrinterData r;
	const char *value_name = "spottyfoot";
	
	r.in.handle = handle;
	r.in.value_name = value_name;
	r.in.type = SPOOLSS_PRINTER_DATA_TYPE_STRING;
	r.in.data.string = "dog";

	printf("Testing SetPrinterData\n");

	status = dcerpc_spoolss_SetPrinterData(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("SetPrinterData failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_GetPrinterData(p, mem_ctx, handle, value_name)) {
		return False;
	}

	if (!test_DeletePrinterData(p, mem_ctx, handle, value_name)) {
		return False;
	}

	return True;
}

static BOOL test_SecondaryClosePrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				       struct policy_handle *handle)
{
	NTSTATUS status;
	struct dcerpc_binding *b;
	struct dcerpc_pipe *p2;
	BOOL ret = True;

	/* only makes sense on SMB */
	if (p->conn->transport.transport != NCACN_NP) {
		return True;
	}

	printf("testing close on secondary pipe\n");

	status = dcerpc_parse_binding(mem_ctx, p->conn->binding_string, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to parse dcerpc binding '%s'\n", p->conn->binding_string);
		return False;
	}

	status = dcerpc_secondary_connection(p, &p2, b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create secondary connection\n");
		return False;
	}

	status = dcerpc_bind_auth_none(p2, &ndr_table_spoolss);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create bind on secondary connection\n");
		talloc_free(p2);

                return False;
        }

	if (test_ClosePrinter(p2, mem_ctx, handle)) {
		printf("ERROR: Allowed close on secondary connection!\n");
		ret = False;
	}

	if (p2->last_fault_code != DCERPC_FAULT_CONTEXT_MISMATCH) {
		printf("Unexpected fault code 0x%x - expected 0x%x\n",
		       p2->last_fault_code, DCERPC_FAULT_CONTEXT_MISMATCH);
		ret = False;
	}

	talloc_free(p2);

	return ret;
}

static BOOL test_OpenPrinter_badname(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, const char *name)
{
	NTSTATUS status;
	struct spoolss_OpenPrinter op;
	struct spoolss_OpenPrinterEx opEx;
	struct policy_handle handle;
	BOOL ret = True;

	op.in.printername	= name;
	op.in.datatype		= NULL;
	op.in.devmode_ctr.devmode= NULL;
	op.in.access_mask	= 0;
	op.out.handle		= &handle;

	printf("\nTesting OpenPrinter(%s) with bad name\n", op.in.printername);

	status = dcerpc_spoolss_OpenPrinter(p, mem_ctx, &op);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPrinter failed - %s\n", nt_errstr(status));
		ret = False;
	}
	if (!W_ERROR_EQUAL(WERR_INVALID_PRINTER_NAME,op.out.result)) {
		printf("OpenPrinter(%s) unexpected result[%s] should be WERR_INVALID_PRINTER_NAME\n",
			name, win_errstr(op.out.result));
	}

	if (W_ERROR_IS_OK(op.out.result)) {
		ret &=test_ClosePrinter(p, mem_ctx, &handle);
	}

	opEx.in.printername		= name;
	opEx.in.datatype		= NULL;
	opEx.in.devmode_ctr.devmode	= NULL;
	opEx.in.access_mask		= 0;
	opEx.in.level			= 1;
	opEx.in.userlevel.level1	= NULL;
	opEx.out.handle			= &handle;

	printf("\nTesting OpenPrinterEx(%s) with bad name\n", opEx.in.printername);

	status = dcerpc_spoolss_OpenPrinterEx(p, mem_ctx, &opEx);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPrinter failed - %s\n", nt_errstr(status));
		ret = False;
	}
	if (!W_ERROR_EQUAL(WERR_INVALID_PRINTER_NAME,opEx.out.result)) {
		printf("OpenPrinterEx(%s) unexpected result[%s] should be WERR_INVALID_PRINTER_NAME\n",
			name, win_errstr(opEx.out.result));
	}

	if (W_ERROR_IS_OK(opEx.out.result)) {
		ret &=test_ClosePrinter(p, mem_ctx, &handle);
	}

	return ret;
}

static BOOL test_OpenPrinter_badnames(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	char *name;

	ret &= test_OpenPrinter_badname(p, mem_ctx, "__INVALID_PRINTER__");
	ret &= test_OpenPrinter_badname(p, mem_ctx, "\\\\__INVALID_HOST__");
	ret &= test_OpenPrinter_badname(p, mem_ctx, "");
	ret &= test_OpenPrinter_badname(p, mem_ctx, "\\\\\\");
	ret &= test_OpenPrinter_badname(p, mem_ctx, "\\\\\\__INVALID_PRINTER__");

	name = talloc_asprintf(mem_ctx, "\\\\%s\\", dcerpc_server_name(p));
	ret &= test_OpenPrinter_badname(p, mem_ctx, name);
	talloc_free(name);

	name = talloc_asprintf(mem_ctx, "\\\\%s\\__INVALID_PRINTER__", dcerpc_server_name(p));
	ret &= test_OpenPrinter_badname(p, mem_ctx, name);
	talloc_free(name);

	return ret;
}

static BOOL test_OpenPrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			     const char *name)
{
	NTSTATUS status;
	struct spoolss_OpenPrinter r;
	struct policy_handle handle;
	BOOL ret = True;

	r.in.printername	= talloc_asprintf(mem_ctx, "\\\\%s\\%s", dcerpc_server_name(p), name);
	r.in.datatype		= NULL;
	r.in.devmode_ctr.devmode= NULL;
	r.in.access_mask	= SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle		= &handle;

	printf("\nTesting OpenPrinter(%s)\n", r.in.printername);

	status = dcerpc_spoolss_OpenPrinter(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPrinter failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("OpenPrinter failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	if (!test_GetPrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_SecondaryClosePrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_ClosePrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	return ret;
}

static BOOL call_OpenPrinterEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       const char *name, struct policy_handle *handle)
{
	struct spoolss_OpenPrinterEx r;
	struct spoolss_UserLevel1 userlevel1;
	NTSTATUS status;

	if (name && name[0]) {
		r.in.printername = talloc_asprintf(mem_ctx, "\\\\%s\\%s", 
						   dcerpc_server_name(p), name);
	} else {
		r.in.printername = talloc_asprintf(mem_ctx, "\\\\%s", 
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

	printf("Testing OpenPrinterEx(%s)\n", r.in.printername);

	status = dcerpc_spoolss_OpenPrinterEx(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPrinterEx failed - %s\n", nt_errstr(status));
		return False;
	}
	
	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("OpenPrinterEx failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_OpenPrinterEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       const char *name)
{
	struct policy_handle handle;
	BOOL ret = True;

	if (!call_OpenPrinterEx(p, mem_ctx, name, &handle)) {
		return False;
	}

	if (!test_GetPrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumForms(p, mem_ctx, &handle, False)) {
		ret = False;
	}

	if (!test_AddForm(p, mem_ctx, &handle, False)) {
		ret = False;
	}

	if (!test_EnumPrinterData(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumPrinterDataEx(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_PausePrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_DoPrintTest(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_ResumePrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_SetPrinterData(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_SecondaryClosePrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_ClosePrinter(p, mem_ctx, &handle)) {
		ret = False;
	}
	
	return ret;
}

static BOOL test_EnumPrinters_old(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct spoolss_EnumPrinters r;
	NTSTATUS status;
	uint16_t levels[] = {1, 2, 4, 5};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		union spoolss_PrinterInfo *info;
		int j;

		r.in.flags	= PRINTER_ENUM_LOCAL;
		r.in.server	= "";
		r.in.level	= levels[i];
		r.in.buffer	= NULL;
		r.in.offered	= 0;

		printf("\nTesting EnumPrinters level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinters(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrinters failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}

		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, r.out.needed);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			r.in.offered = r.out.needed;
			status = dcerpc_spoolss_EnumPrinters(p, mem_ctx, &r);
		}

		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrinters failed - %s\n", 
			       nt_errstr(status));
			continue;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("EnumPrinters failed - %s\n", 
			       win_errstr(r.out.result));
			continue;
		}

		if (!r.out.info) {
			printf("No printers returned\n");
			continue;
		}

		info = r.out.info;

		for (j=0;j<r.out.count;j++) {
			if (r.in.level == 1) {
				/* the names appear to be comma-separated name lists? */
				char *name = talloc_strdup(mem_ctx, info[j].info1.name);
				char *comma = strchr(name, ',');
				if (comma) *comma = 0;
				if (!test_OpenPrinter(p, mem_ctx, name)) {
					ret = False;
				}
				if (!test_OpenPrinterEx(p, mem_ctx, name)) {
					ret = False;
				}
			}
		}
	}

	return ret;
}

#if 0
static BOOL test_GetPrinterDriver2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				   struct policy_handle *handle, 
				   const char *driver_name)
{
	NTSTATUS status;
	struct spoolss_GetPrinterDriver2 r;

	r.in.handle = handle;
	r.in.architecture = "W32X86";
	r.in.level = 1;
	r.in.buffer = NULL;
	r.in.offered = 0;
	r.in.client_major_version = 0;
	r.in.client_minor_version = 0;

	printf("Testing GetPrinterDriver2\n");

	status = dcerpc_spoolss_GetPrinterDriver2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetPrinterDriver2 failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		r.in.offered = r.out.needed;
		status = dcerpc_spoolss_GetPrinterDriver2(p, mem_ctx, &r);
	}
		
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetPrinterDriver2 failed - %s\n", 
		       nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("GetPrinterDriver2 failed - %s\n", 
		       win_errstr(r.out.result));
		return False;
	}

	return True;
}
#endif

static BOOL test_EnumPrinterDrivers_old(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct spoolss_EnumPrinterDrivers r;
	NTSTATUS status;
	uint16_t levels[] = {1, 2, 3, 4, 5, 6};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {

		r.in.server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
		r.in.environment = "Windows NT x86";
		r.in.level = levels[i];
		r.in.buffer = NULL;
		r.in.offered = 0;

		printf("\nTesting EnumPrinterDrivers level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinterDrivers(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrinterDrivers failed - %s\n", 
			       nt_errstr(status));
			ret = False;
			continue;
		}

		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, r.out.needed);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			r.in.offered = r.out.needed;
			status = dcerpc_spoolss_EnumPrinterDrivers(p, mem_ctx, &r);
		}

		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrinterDrivers failed - %s\n", 
			       nt_errstr(status));
			ret = False;
			break;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("EnumPrinterDrivers failed - %s\n", 
			       win_errstr(r.out.result));
			ret = False;
			break;
		}

		if (!r.out.info) {
			printf("No printer drivers returned\n");
			break;
		}
	}

	return ret;
}

BOOL torture_rpc_spoolss(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct test_spoolss_context *ctx;

	mem_ctx = talloc_init("torture_rpc_spoolss");

	status = torture_rpc_connection(mem_ctx, &p, &ndr_table_spoolss);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	ctx = talloc_zero(mem_ctx, struct test_spoolss_context);
	ctx->p	= p;

	ret &= test_OpenPrinter_server(ctx);

	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "W3SvcInstalled");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "BeepEnabled");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "EventLog");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "NetPopup");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "NetPopupToComputer");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "MajorVersion");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "MinorVersion");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "DefaultSpoolDirectory");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "Architecture");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "DsPresent");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "OSVersion");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "OSVersionEx");
	ret &= test_GetPrinterData(ctx->p, ctx, &ctx->server_handle, "DNSMachineName");

	ret &= test_EnumForms(ctx->p, ctx, &ctx->server_handle, True);

	ret &= test_AddForm(ctx->p, ctx, &ctx->server_handle, True);

	ret &= test_EnumPorts(ctx);

	ret &= test_GetPrinterDriverDirectory(ctx);

	ret &= test_EnumPrinterDrivers(ctx);

	ret &= test_EnumMonitors(ctx);

	ret &= test_EnumPrintProcessors(ctx);

	ret &= test_EnumPrinters(ctx);

	ret &= test_OpenPrinter_badnames(p, mem_ctx);

	ret &= test_AddPort(p, mem_ctx);

	ret &= test_EnumPorts_old(p, mem_ctx);

	ret &= test_EnumPrinters_old(p, mem_ctx);

	ret &= test_EnumPrinterDrivers_old(p, mem_ctx);

	talloc_free(mem_ctx);

	return ret;
}
