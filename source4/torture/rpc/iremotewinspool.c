/*
   Unix SMB/CIFS implementation.
   test suite for iremotewinspool rpc operations

   Copyright (C) Guenther Deschner 2013

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
#include "librpc/gen_ndr/ndr_winspool.h"
#include "librpc/gen_ndr/ndr_winspool_c.h"
#include "torture/rpc/torture_rpc.h"
#include "libcli/registry/util_reg.h"

struct test_iremotewinspool_context {
	struct GUID object_uuid;
	struct dcerpc_pipe *iremotewinspool_pipe;
	struct policy_handle server_handle;
	const char *environment;
};

static bool test_AsyncOpenPrinter_byprinter(struct torture_context *tctx,
					    struct test_iremotewinspool_context *ctx,
					    struct dcerpc_pipe *p,
					    const char *printer_name,
					    struct policy_handle *handle)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct spoolss_UserLevelCtr client_info_ctr;
	struct spoolss_UserLevel1 level1;
	uint32_t access_mask = SERVER_ALL_ACCESS;
	struct winspool_AsyncOpenPrinter r;

	ZERO_STRUCT(devmode_ctr);

	level1.size	= 28;
	level1.client	= talloc_asprintf(tctx, "\\\\%s", "mthelena");
	level1.user	= "GD";
	level1.build	= 1381;
	level1.major	= 3;
	level1.minor	= 0;
	level1.processor = PROCESSOR_ARCHITECTURE_AMD64;

	client_info_ctr.level = 1;
	client_info_ctr.user_info.level1 = &level1;

	r.in.pPrinterName	= printer_name;
	r.in.pDatatype		= NULL;
	r.in.pDevModeContainer	= &devmode_ctr;
	r.in.AccessRequired	= access_mask;
	r.in.pClientInfo	= &client_info_ctr;
	r.out.pHandle		= handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncOpenPrinter_r(b, tctx, &r),
		"AsyncOpenPrinter failed");
	torture_assert_werr_ok(tctx, r.out.result,
		"AsyncOpenPrinter failed");

	return true;
}

static bool test_AsyncClosePrinter_byhandle(struct torture_context *tctx,
					    struct test_iremotewinspool_context *ctx,
					    struct dcerpc_pipe *p,
					    struct policy_handle *handle)
{
	struct dcerpc_binding_handle *b = p->binding_handle;

	struct winspool_AsyncClosePrinter r;

	r.in.phPrinter = handle;
	r.out.phPrinter = handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncClosePrinter_r(b, tctx, &r),
		"AsyncClosePrinter failed");
	torture_assert_werr_ok(tctx, r.out.result,
		"AsyncClosePrinter failed");

	return true;
}

static bool test_AsyncGetPrinterData_checktype(struct torture_context *tctx,
					       struct dcerpc_binding_handle *b,
					       struct policy_handle *handle,
					       const char *value_name,
					       enum winreg_Type *expected_type,
					       enum winreg_Type *type_p,
					       uint8_t **data_p,
					       uint32_t *needed_p)
{
	struct winspool_AsyncGetPrinterData r;
	enum winreg_Type type;
	uint32_t needed;

	r.in.hPrinter = *handle;
	r.in.pValueName = value_name;
	r.in.nSize = 0;
	r.out.pType = &type;
	r.out.pData = talloc_zero_array(tctx, uint8_t, r.in.nSize);
	r.out.pcbNeeded = &needed;

	torture_comment(tctx, "Testing AsyncGetPrinterData(%s)\n",
		r.in.pValueName);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncGetPrinterData_r(b, tctx, &r),
		"AsyncGetPrinterData failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		if (expected_type) {
			torture_assert_int_equal(tctx, type, *expected_type, "unexpected type");
		}
		r.in.nSize = needed;
		r.out.pData = talloc_zero_array(tctx, uint8_t, r.in.nSize);

		torture_assert_ntstatus_ok(tctx,
			dcerpc_winspool_AsyncGetPrinterData_r(b, tctx, &r),
			"AsyncGetPrinterData failed");
	}

	torture_assert_werr_ok(tctx, r.out.result,
		"AsyncGetPrinterData failed");

	if (type_p) {
		*type_p = type;
	}

	if (data_p) {
		*data_p = r.out.pData;
	}

	if (needed_p) {
		*needed_p = needed;
	}

	return true;
}

static bool test_AsyncGetPrinterData(struct torture_context *tctx,
				     struct dcerpc_binding_handle *b,
				     struct policy_handle *handle,
				     const char *value_name,
				     enum winreg_Type *type_p,
				     uint8_t **data_p,
				     uint32_t *needed_p)
{
	return test_AsyncGetPrinterData_checktype(tctx, b, handle,
						  value_name,
						  NULL,
						  type_p, data_p, needed_p);
}

static bool test_get_environment(struct torture_context *tctx,
				 struct dcerpc_binding_handle *b,
				 struct policy_handle *handle,
				 const char **architecture)
{
	DATA_BLOB blob;
	enum winreg_Type type;
	uint8_t *data;
	uint32_t needed;

	torture_assert(tctx,
		test_AsyncGetPrinterData(tctx, b, handle, "Architecture", &type, &data, &needed),
		"failed to get Architecture");

	torture_assert_int_equal(tctx, type, REG_SZ, "unexpected type");

	blob = data_blob_const(data, needed);

	torture_assert(tctx,
		pull_reg_sz(tctx, &blob, architecture),
		"failed to pull environment");

	return true;
}

static bool torture_rpc_iremotewinspool_setup_common(struct torture_context *tctx,
						     struct test_iremotewinspool_context *t)
{
	const char *printer_name;
	struct dcerpc_binding *binding;

	torture_assert_ntstatus_ok(tctx,
		GUID_from_string(IREMOTEWINSPOOL_OBJECT_GUID, &t->object_uuid),
		"failed to parse GUID");

	torture_assert_ntstatus_ok(tctx,
		torture_rpc_binding(tctx, &binding),
		"failed to retrieve torture binding");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_binding_set_object(binding, t->object_uuid),
		"failed to set object_uuid");

	torture_assert_ntstatus_ok(tctx,
		torture_rpc_connection_with_binding(tctx, binding, &t->iremotewinspool_pipe, &ndr_table_iremotewinspool),
		"Error connecting to server");

	printer_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(t->iremotewinspool_pipe));

	torture_assert(tctx,
		test_AsyncOpenPrinter_byprinter(tctx, t,
						t->iremotewinspool_pipe, printer_name,
						&t->server_handle),
						"failed to open printserver");
	torture_assert(tctx,
		test_get_environment(tctx,
				     t->iremotewinspool_pipe->binding_handle,
				     &t->server_handle, &t->environment),
				     "failed to get environment");

	return true;
}

static bool torture_rpc_iremotewinspool_setup(struct torture_context *tctx,
					      void **data)
{
	struct test_iremotewinspool_context *t;

	*data = t = talloc_zero(tctx, struct test_iremotewinspool_context);

	return torture_rpc_iremotewinspool_setup_common(tctx, t);
}

static bool torture_rpc_iremotewinspool_teardown_common(struct torture_context *tctx,
							struct test_iremotewinspool_context *t)
{

	test_AsyncClosePrinter_byhandle(tctx, t, t->iremotewinspool_pipe, &t->server_handle);

	return true;
}

static bool torture_rpc_iremotewinspool_teardown(struct torture_context *tctx,
						 void *data)
{
	struct test_iremotewinspool_context *t = talloc_get_type(data, struct test_iremotewinspool_context);
	bool ret;

	ret = torture_rpc_iremotewinspool_teardown_common(tctx, t);
	talloc_free(t);

	return ret;
}

static bool test_AsyncClosePrinter(struct torture_context *tctx,
				   void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	const char *printer_name;
	struct policy_handle handle;

	printer_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));

	torture_assert(tctx,
		test_AsyncOpenPrinter_byprinter(tctx, ctx, p, printer_name, &handle),
		"failed to test AsyncOpenPrinter");

	torture_assert(tctx,
		test_AsyncClosePrinter_byhandle(tctx, ctx, p, &handle),
		"failed to test AsyncClosePrinter");

	return true;
}

static bool test_AsyncOpenPrinter(struct torture_context *tctx,
				  void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	const char *printer_name;
	struct policy_handle handle;

	printer_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));

	torture_assert(tctx,
		test_AsyncOpenPrinter_byprinter(tctx, ctx, p, printer_name, &handle),
		"failed to test AsyncOpenPrinter");

	test_AsyncClosePrinter_byhandle(tctx, ctx, p, &handle);

	return true;
}

struct torture_suite *torture_rpc_iremotewinspool(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "iremotewinspool");
	struct torture_tcase *tcase = torture_suite_add_tcase(suite, "printserver");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_iremotewinspool_setup,
				  torture_rpc_iremotewinspool_teardown);

	torture_tcase_add_simple_test(tcase, "AsyncOpenPrinter", test_AsyncOpenPrinter);
	torture_tcase_add_simple_test(tcase, "AsyncClosePrinter", test_AsyncClosePrinter);

	return suite;
}
