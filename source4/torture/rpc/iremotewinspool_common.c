#include "includes.h"
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_winspool.h"
#include "librpc/gen_ndr/ndr_winspool_c.h"
#include "librpc/gen_ndr/ndr_spoolss_c.h"
#include "torture/rpc/torture_rpc.h"
#include "libcli/registry/util_reg.h"
#include "torture/rpc/iremotewinspool_common.h"

struct spoolss_UserLevel1 test_get_client_info(struct torture_context *tctx,
						      enum client_os_version os,
						      enum spoolss_MajorVersion major_number,
						      enum spoolss_MinorVersion minor_number)
{
	struct spoolss_UserLevel1 level1;

	level1.size	= 28;
	level1.client	= talloc_asprintf(tctx, "\\\\%s", "mthelena");
	level1.user	= "GD";
	level1.processor = PROCESSOR_ARCHITECTURE_AMD64;
	level1.major	= major_number;
	level1.minor	= minor_number;

	if (os == WIN_SERVER_2016 || os == WIN_10) {
		level1.build = 10586;
	} else if (os == WIN_SERVER_2012 || os == WIN_8) {
		level1.build = 9200;
	} else if (os == WIN_SERVER_2008R2 || os == WIN_7) {
		level1.build = 7007;
	} else if (os == WIN_SERVER_2008 || os == WIN_VISTA) {
		level1.build = 6000;
	} else if (os == WIN_2000) {
		level1.build = 1382;
	}

	return level1;
}

bool test_AsyncOpenPrinter_byprinter(struct torture_context *tctx,
					    struct test_iremotewinspool_context *ctx,
					    struct dcerpc_pipe *p,
					    const char *printer_name,
					    struct spoolss_UserLevel1 cinfo,
					    struct policy_handle *handle)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct spoolss_UserLevelCtr client_info_ctr;
	uint32_t access_mask = SERVER_ALL_ACCESS;
	struct winspool_AsyncOpenPrinter r;

	ZERO_STRUCT(devmode_ctr);

	client_info_ctr.level = 1;
	client_info_ctr.user_info.level1 = &cinfo;

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

bool test_get_environment(struct torture_context *tctx,
				 struct dcerpc_binding_handle *b,
				 struct policy_handle *handle,
				 const char **architecture)
{
	DATA_BLOB blob;
	enum winreg_Type type;
	uint8_t *data;
	uint32_t needed;

	torture_assert(tctx,
		test_AsyncGetPrinterData_args(tctx, b, handle, "Architecture", &type, &data, &needed),
		"failed to get Architecture");

	torture_assert_int_equal(tctx, type, REG_SZ, "unexpected type");

	blob = data_blob_const(data, needed);

	torture_assert(tctx,
		pull_reg_sz(tctx, &blob, architecture),
		"failed to pull environment");

	return true;
}

bool test_AsyncClosePrinter_byhandle(struct torture_context *tctx,
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

bool test_AsyncGetPrinterData_args(struct torture_context *tctx,
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
