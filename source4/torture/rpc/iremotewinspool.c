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
#include "librpc/gen_ndr/ndr_spoolss_c.h"
#include "torture/rpc/torture_rpc.h"
#include "libcli/registry/util_reg.h"
#include "torture/rpc/iremotewinspool_common.h"

static bool torture_rpc_iremotewinspool_setup_common(struct torture_context *tctx,
						     struct test_iremotewinspool_context *t)
{
	const char *printer_name;
	struct spoolss_UserLevel1 client_info;
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

	client_info = test_get_client_info(tctx, WIN_7, 6, 1, "testclient_machine", "testclient_user");

	torture_assert(tctx,
		test_AsyncOpenPrinter_byprinter(tctx, t,
						t->iremotewinspool_pipe, printer_name,
						client_info, &t->server_handle),
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
	struct spoolss_UserLevel1 client_info;
	struct policy_handle handle;

	printer_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));

	client_info = test_get_client_info(tctx, WIN_7, 6, 1, "testclient_machine", "testclient_user");

	torture_assert(tctx,
		test_AsyncOpenPrinter_byprinter(tctx, ctx, p, printer_name, client_info, &handle),
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
	struct spoolss_UserLevel1 client_info;
	struct policy_handle handle;

	printer_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));

	client_info = test_get_client_info(tctx, WIN_7, 6, 1, "testclient_machine", "testclient_user");

	torture_assert(tctx,
		test_AsyncOpenPrinter_byprinter(tctx, ctx, p, printer_name, client_info, &handle),
		"failed to test AsyncOpenPrinter");

	test_AsyncClosePrinter_byhandle(tctx, ctx, p, &handle);

	return true;
}

/*
 * Validate the result of AsyncOpenPrinter calls based on client info
 * build number. Windows Server 2016 rejects an advertised build
 * number less than 6000(Windows Vista and Windows Server 2008, or older)
 */
static bool test_AsyncOpenPrinterValidateBuildNumber(struct torture_context *tctx,
						     void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	const char *printer_name;
	struct spoolss_UserLevel1 client_info;
	struct policy_handle handle;
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct spoolss_UserLevelCtr client_info_ctr = {
		.level = 1,
	};
	uint32_t access_mask = SERVER_ALL_ACCESS;
	struct winspool_AsyncOpenPrinter r;
	NTSTATUS status;
	bool ok = false;

	printer_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	torture_assert_not_null(tctx, printer_name, "Cannot allocate memory");

	/* fail with Windows 2000 build number */
	client_info = test_get_client_info(tctx, WIN_2000, 3, SPOOLSS_MINOR_VERSION_0,
					   "testclient_machine", "testclient_user");

	ZERO_STRUCT(devmode_ctr);

	client_info_ctr.user_info.level1 = &client_info;

	r.in.pPrinterName	= printer_name;
	r.in.pDatatype		= NULL;
	r.in.pDevModeContainer	= &devmode_ctr;
	r.in.AccessRequired	= access_mask;
	r.in.pClientInfo	= &client_info_ctr;
	r.out.pHandle		= &handle;

	status = dcerpc_winspool_AsyncOpenPrinter_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "AsyncOpenPrinter failed");
	torture_assert_werr_equal(tctx, r.out.result, WERR_ACCESS_DENIED,
		"AsyncOpenPrinter should have failed");

	/* succeed with Windows 7 build number */
	client_info = test_get_client_info(tctx, WIN_7, 6, 1,
					   "testclient_machine", "testclient_user");
	client_info_ctr.user_info.level1 = &client_info;
	r.in.pClientInfo	= &client_info_ctr;

	status = dcerpc_winspool_AsyncOpenPrinter_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "AsyncOpenPrinter failed");
	torture_assert_werr_ok(tctx, r.out.result,
		"AsyncOpenPrinter failed");

	ok = test_AsyncClosePrinter_byhandle(tctx, ctx, p, &handle);
	torture_assert(tctx, ok, "failed to AsyncClosePrinter handle");

	return true;

}

static struct spoolss_NotifyOption *setup_printserver_NotifyOption(struct torture_context *tctx)
{
	struct spoolss_NotifyOption *o;

	o = talloc_zero(tctx, struct spoolss_NotifyOption);
	if (o == NULL) {
		return NULL;
	}

	o->version = 2;
	o->flags = PRINTER_NOTIFY_OPTIONS_REFRESH;

	o->count = 2;
	o->types = talloc_zero_array(o, struct spoolss_NotifyOptionType, o->count);
	if (o->types == NULL) {
		talloc_free(o);
		return NULL;
	}

	o->types[0].type = PRINTER_NOTIFY_TYPE;
	o->types[0].count = 1;
	o->types[0].fields = talloc_array(o->types, union spoolss_Field, o->types[0].count);
	if (o->types[0].fields == NULL) {
		talloc_free(o);
		return NULL;
	}
	o->types[0].fields[0].field = PRINTER_NOTIFY_FIELD_SERVER_NAME;

	o->types[1].type = JOB_NOTIFY_TYPE;
	o->types[1].count = 1;
	o->types[1].fields = talloc_array(o->types, union spoolss_Field, o->types[1].count);
	if (o->types[1].fields == NULL) {
		talloc_free(o);
		return NULL;
	}
	o->types[1].fields[0].field = JOB_NOTIFY_FIELD_MACHINE_NAME;

	return o;
}

static bool test_SyncUnRegisterForRemoteNotifications_args(struct torture_context *tctx,
							   struct dcerpc_pipe *p,
							   struct policy_handle *notify_handle)
{
	struct winspool_SyncUnRegisterForRemoteNotifications r;
	struct dcerpc_binding_handle *b = p->binding_handle;

	r.in.phRpcHandle = notify_handle;
	r.out.phRpcHandle = notify_handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_SyncUnRegisterForRemoteNotifications_r(b, tctx, &r),
		"SyncUnRegisterForRemoteNotifications failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"SyncUnRegisterForRemoteNotifications failed");

	return true;
}

static bool test_SyncRegisterForRemoteNotifications_args(struct torture_context *tctx,
							 struct dcerpc_pipe *p,
							 struct policy_handle *server_handle,
							 struct policy_handle *notify_handle);

static bool test_SyncUnRegisterForRemoteNotifications(struct torture_context *tctx,
						      void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);
	struct policy_handle notify_handle;

	torture_assert(tctx,
		test_SyncRegisterForRemoteNotifications_args(tctx,
							     ctx->iremotewinspool_pipe,
							     &ctx->server_handle,
							     &notify_handle),
		"failed to test SyncRegisterForRemoteNotifications");

	torture_assert(tctx,
		test_SyncUnRegisterForRemoteNotifications_args(tctx,
							       ctx->iremotewinspool_pipe,
							       &notify_handle),
		"failed to test UnSyncRegisterForRemoteNotifications");

	return true;
}

static bool test_SyncRegisterForRemoteNotifications_args(struct torture_context *tctx,
							 struct dcerpc_pipe *p,
							 struct policy_handle *server_handle,
							 struct policy_handle *notify_handle)
{
	struct dcerpc_binding_handle *b = p->binding_handle;

	struct winspool_SyncRegisterForRemoteNotifications r;
	struct winspool_PrintPropertiesCollection NotifyFilter;
	struct winspool_PrintNamedProperty *c;
	struct spoolss_NotifyOption *options;

	ZERO_STRUCT(NotifyFilter);

	options = setup_printserver_NotifyOption(tctx);
	torture_assert(tctx, options, "out of memory");

	c = talloc_zero_array(tctx, struct winspool_PrintNamedProperty, 4);
	torture_assert(tctx, c, "out of memory");

	c[0].propertyName = "RemoteNotifyFilter Flags";
	c[0].propertyValue.PropertyType = winspool_PropertyTypeInt32;
	c[0].propertyValue.value.propertyInt32 = 0xff;

	c[1].propertyName = "RemoteNotifyFilter Options";
	c[1].propertyValue.PropertyType = winspool_PropertyTypeInt32;
	c[1].propertyValue.value.propertyInt32 = 0;

	c[2].propertyName = "RemoteNotifyFilter Color";
	c[2].propertyValue.PropertyType = winspool_PropertyTypeInt32;
	c[2].propertyValue.value.propertyInt32 = 0;

	c[3].propertyName = "RemoteNotifyFilter NotifyOptions";
	c[3].propertyValue.PropertyType = winspool_PropertyTypeNotificationOptions;
	c[3].propertyValue.value.propertyOptionsContainer.pOptions = options;

	NotifyFilter.numberOfProperties = 4;
	NotifyFilter.propertiesCollection = c;

	r.in.hPrinter = *server_handle;
	r.in.pNotifyFilter = &NotifyFilter;
	r.out.phRpcHandle = notify_handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_SyncRegisterForRemoteNotifications_r(b, tctx, &r),
		"SyncRegisterForRemoteNotifications failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"SyncRegisterForRemoteNotifications failed");

	return true;
}

static bool test_SyncRegisterForRemoteNotifications(struct torture_context *tctx,
						    void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);
	struct policy_handle notify_handle;

	torture_assert(tctx,
		test_SyncRegisterForRemoteNotifications_args(tctx,
							     ctx->iremotewinspool_pipe,
							     &ctx->server_handle,
							     &notify_handle),
		"failed to test SyncRegisterForRemoteNotifications");

	test_SyncUnRegisterForRemoteNotifications_args(tctx, ctx->iremotewinspool_pipe, &notify_handle);

	return true;
}

static bool test_AsyncUploadPrinterDriverPackage(struct torture_context *tctx,
						 void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;

	struct winspool_AsyncUploadPrinterDriverPackage r;
	uint32_t pcchDestInfPath = 0;

	r.in.pszServer = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.pszInfPath = "";
	r.in.pszEnvironment = "";
	r.in.dwFlags = 0;
	r.in.pszDestInfPath = NULL;
	r.in.pcchDestInfPath = &pcchDestInfPath;
	r.out.pszDestInfPath = NULL;
	r.out.pcchDestInfPath = &pcchDestInfPath;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncUploadPrinterDriverPackage_r(b, tctx, &r),
		"AsyncUploadPrinterDriverPackage failed");
	torture_assert_hresult_equal(tctx, r.out.result, HRES_E_INVALIDARG,
		"AsyncUploadPrinterDriverPackage failed");

	pcchDestInfPath = 260;
	r.in.pszDestInfPath = talloc_zero(tctx, const char);
	r.out.pszDestInfPath = talloc_zero(tctx, const char);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncUploadPrinterDriverPackage_r(b, tctx, &r),
		"AsyncUploadPrinterDriverPackage failed");
	torture_assert_werr_equal(tctx,
		W_ERROR(WIN32_FROM_HRESULT(r.out.result)), WERR_INVALID_ENVIRONMENT,
		"AsyncUploadPrinterDriverPackage failed");

	r.in.pszEnvironment = SPOOLSS_ARCHITECTURE_x64;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncUploadPrinterDriverPackage_r(b, tctx, &r),
		"AsyncUploadPrinterDriverPackage failed");
	torture_assert_werr_equal(tctx,
		W_ERROR(WIN32_FROM_HRESULT(r.out.result)), WERR_FILE_NOT_FOUND,
		"AsyncUploadPrinterDriverPackage failed");

	r.in.pszInfPath = "\\\\mthelena\\print$\\x64\\{BD443844-ED00-4D96-8CAE-95E49492312A}\\prnbrcl1.inf";

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncUploadPrinterDriverPackage_r(b, tctx, &r),
		"AsyncUploadPrinterDriverPackage failed");
	torture_assert_werr_equal(tctx,
		W_ERROR(WIN32_FROM_HRESULT(r.out.result)), WERR_FILE_NOT_FOUND,
		"AsyncUploadPrinterDriverPackage failed");

	return true;
}

static bool test_AsyncEnumPrinters(struct torture_context *tctx,
				   void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;

	struct winspool_AsyncEnumPrinters r;
	uint32_t levels[] = { 1, 2, /*3,*/ 4, 5 };
	int i;

	uint32_t needed;
	uint32_t returned;

	for (i = 0; i < ARRAY_SIZE(levels); i++) {

		r.in.Flags = PRINTER_ENUM_LOCAL;
		r.in.pName = NULL;
		r.in.Level = levels[i];
		r.in.cbBuf = 0;
		r.in.pPrinterEnum = NULL;
		r.out.pcbNeeded = &needed;
		r.out.pcReturned = &returned;
		r.out.pPrinterEnum = NULL;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_winspool_AsyncEnumPrinters_r(b, tctx, &r),
			"AsyncEnumPrinters failed");
		torture_assert_werr_equal(tctx, r.out.result, WERR_INSUFFICIENT_BUFFER,
			"AsyncEnumPrinters failed");

		r.in.cbBuf = needed;
		r.in.pPrinterEnum = talloc_zero_array(tctx, uint8_t, r.in.cbBuf);
		r.out.pPrinterEnum = r.in.pPrinterEnum;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_winspool_AsyncEnumPrinters_r(b, tctx, &r),
			"AsyncEnumPrinters failed");
		torture_assert_werr_ok(tctx, r.out.result,
			"AsyncEnumPrinters failed");
	}

	return true;
}

static bool test_AsyncGetPrinterData(struct torture_context *tctx,
				     void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB blob;
	const char *s;
	bool ok;

	uint32_t pType;
	uint32_t pcbNeeded;
	uint8_t *pData;

	torture_assert(tctx,
		test_AsyncGetPrinterData_args(tctx, b, &ctx->server_handle,
					      "MajorVersion",
					      &pType, &pData, &pcbNeeded),
		"failed to check for MajorVersion");

	torture_assert_int_equal(tctx, pcbNeeded, 4, "pcbNeeded");
	torture_assert_int_equal(tctx, pType, REG_DWORD, "pType");
	torture_assert_int_equal(tctx, IVAL(pData, 0), 3, "pData");

	torture_assert(tctx,
		test_AsyncGetPrinterData_args(tctx, b, &ctx->server_handle,
					      "Architecture",
					      &pType, &pData, &pcbNeeded),
		"failed to check for Architecture");

	blob = data_blob_const(pData, pcbNeeded);

	torture_assert_int_equal(tctx, pType, REG_SZ, "pType");
	torture_assert(tctx, pull_reg_sz(tctx, &blob, &s), "");
	ok = strequal(s, SPOOLSS_ARCHITECTURE_x64) || strequal(s, SPOOLSS_ARCHITECTURE_NT_X86);
	torture_assert(tctx, ok, "unexpected architecture returned");

	return true;
}

static bool test_AsyncCorePrinterDriverInstalled(struct torture_context *tctx,
						 void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;

	struct winspool_AsyncCorePrinterDriverInstalled r;
	int32_t pbDriverInstalled;
	struct GUID guid;

	r.in.pszServer = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.pszEnvironment = "";
	r.in.CoreDriverGUID = GUID_zero();
	r.in.ftDriverDate = 0;
	r.in.dwlDriverVersion = 0;
	r.out.pbDriverInstalled = &pbDriverInstalled;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncCorePrinterDriverInstalled_r(b, tctx, &r),
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_werr_equal(tctx,
		W_ERROR(WIN32_FROM_HRESULT(r.out.result)), WERR_INVALID_ENVIRONMENT,
		"AsyncCorePrinterDriverInstalled failed");

	r.in.pszEnvironment = SPOOLSS_ARCHITECTURE_x64;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncCorePrinterDriverInstalled_r(b, tctx, &r),
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_int_equal(tctx, *r.out.pbDriverInstalled, false,
				"unexpected driver installed");

	r.in.CoreDriverGUID = GUID_random();

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncCorePrinterDriverInstalled_r(b, tctx, &r),
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_int_equal(tctx, *r.out.pbDriverInstalled, false,
				"unexpected driver installed");

	torture_assert_ntstatus_ok(tctx,
		GUID_from_string(SPOOLSS_CORE_PRINT_PACKAGE_FILES_XPSDRV, &guid), "");

	r.in.CoreDriverGUID = guid;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncCorePrinterDriverInstalled_r(b, tctx, &r),
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_int_equal(tctx, *r.out.pbDriverInstalled, true,
				"xps core driver not installed?");

	r.in.dwlDriverVersion = 0xffffffff;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncCorePrinterDriverInstalled_r(b, tctx, &r),
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_int_equal(tctx, *r.out.pbDriverInstalled, true,
				"xps core driver not installed?");

	r.in.dwlDriverVersion = 1234;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncCorePrinterDriverInstalled_r(b, tctx, &r),
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_int_equal(tctx, *r.out.pbDriverInstalled, true,
				"xps core driver not installed?");

	r.in.ftDriverDate = unix_timespec_to_nt_time(timespec_current());

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncCorePrinterDriverInstalled_r(b, tctx, &r),
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_int_equal(tctx, *r.out.pbDriverInstalled, false,
				"driver too old ?");

	r.in.dwlDriverVersion = 0;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncCorePrinterDriverInstalled_r(b, tctx, &r),
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"AsyncCorePrinterDriverInstalled failed");
	torture_assert_int_equal(tctx, *r.out.pbDriverInstalled, false,
				"unexpected driver installed");

	return true;
}

static bool test_get_core_printer_drivers_arch_guid(struct torture_context *tctx,
						    struct dcerpc_pipe *p,
						    const char *architecture,
						    const char *guid_str,
						    const char **package_id)
{
	struct winspool_AsyncGetCorePrinterDrivers r;
	DATA_BLOB blob;
	const char **s;
	struct dcerpc_binding_handle *b = p->binding_handle;

	s = talloc_zero_array(tctx, const char *, 2);
	s[0] = guid_str;

	torture_assert(tctx,
		push_reg_multi_sz(tctx, &blob, s),
		"push_reg_multi_sz failed");

	r.in.pszServer = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.pszEnvironment = architecture;
	r.in.cchCoreDrivers = blob.length/2;
	r.in.pszzCoreDriverDependencies = (uint16_t *)blob.data;
	r.in.cCorePrinterDrivers = 1;
	r.out.pCorePrinterDrivers = talloc_zero_array(tctx, struct spoolss_CorePrinterDriver, r.in.cCorePrinterDrivers);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncGetCorePrinterDrivers_r(b, tctx, &r),
		"winspool_AsyncCorePrinterDrivers failed");
	torture_assert_hresult_ok(tctx, r.out.result,
		"winspool_AsyncCorePrinterDrivers failed");

	if (package_id) {
		*package_id = r.out.pCorePrinterDrivers[0].szPackageID;
	}

	return true;
}

static bool test_AsyncDeletePrintDriverPackage(struct torture_context *tctx,
					       void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct winspool_AsyncDeletePrinterDriverPackage r;

	const char *architectures[] = {
/*		SPOOLSS_ARCHITECTURE_NT_X86, */
		SPOOLSS_ARCHITECTURE_x64
	};
	int i;

	for (i=0; i < ARRAY_SIZE(architectures); i++) {

		const char *package_id;

		torture_assert(tctx,
			test_get_core_printer_drivers_arch_guid(tctx, p,
								architectures[i],
								SPOOLSS_CORE_PRINT_PACKAGE_FILES_XPSDRV,
								&package_id),
			"failed to get core printer driver");

		r.in.pszServer = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
		r.in.pszEnvironment = "";
		r.in.pszInfPath = "";

		torture_comment(tctx, "Testing AsyncDeletePrinterDriverPackage(%s, %s, %s)\n",
			r.in.pszServer, architectures[i], package_id);

		torture_assert_ntstatus_ok(tctx,
			dcerpc_winspool_AsyncDeletePrinterDriverPackage_r(b, tctx, &r),
			"AsyncDeletePrinterDriverPackage failed");
		torture_assert_werr_equal(tctx,
			W_ERROR(WIN32_FROM_HRESULT(r.out.result)), WERR_NOT_FOUND,
			"AsyncDeletePrinterDriverPackage failed");

		r.in.pszInfPath = package_id;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_winspool_AsyncDeletePrinterDriverPackage_r(b, tctx, &r),
			"AsyncDeletePrinterDriverPackage failed");
		torture_assert_werr_equal(tctx,
			W_ERROR(WIN32_FROM_HRESULT(r.out.result)), WERR_INVALID_ENVIRONMENT,
			"AsyncDeletePrinterDriverPackage failed");

		r.in.pszEnvironment = architectures[i];

		torture_assert_ntstatus_ok(tctx,
			dcerpc_winspool_AsyncDeletePrinterDriverPackage_r(b, tctx, &r),
			"AsyncDeletePrinterDriverPackage failed");
		torture_assert_hresult_equal(tctx, r.out.result, HRES_E_ACCESSDENIED,
			"AsyncDeletePrinterDriverPackage failed");
	}

	return true;
}

static bool test_AsyncGetPrinterDriverDirectory(struct torture_context *tctx,
						void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct winspool_AsyncGetPrinterDriverDirectory r;
	uint32_t pcbNeeded;
	DATA_BLOB blob;
	const char *s;

	r.in.pName = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.pEnvironment = ctx->environment;
	r.in.Level = 1;
	r.in.cbBuf = 0x200;
	r.in.pDriverDirectory = talloc_zero_array(tctx, uint8_t, r.in.cbBuf);
	r.out.pcbNeeded = &pcbNeeded;
	r.out.pDriverDirectory = r.in.pDriverDirectory;

	torture_comment(tctx, "Testing AsyncGetPrinterDriverDirectory(%s, %s)\n",
		r.in.pName, r.in.pEnvironment);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_winspool_AsyncGetPrinterDriverDirectory_r(b, tctx, &r),
		"AsyncGetPrinterDriverDirectory failed");
	torture_assert_werr_ok(tctx, r.out.result,
		"AsyncGetPrinterDriverDirectory failed");

	blob = data_blob_const(r.out.pDriverDirectory, pcbNeeded);

	torture_assert(tctx,
		pull_reg_sz(tctx, &blob, &s),
		"failed to pull reg_sz");

	torture_comment(tctx, "got: %s\n", s);

	return true;
}

/*
 * Test if one can close a printserver handle that has been acquired via
 * winspool_AsyncOpenPrinter with a spoolss_ClosePrinter operation.
 */

static bool test_OpenPrinter(struct torture_context *tctx,
			     void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	const char *printer_name;
	struct policy_handle handle;
	struct dcerpc_pipe *s;
	struct dcerpc_binding *binding;
	struct spoolss_UserLevel1 client_info;
	struct spoolss_ClosePrinter r;

	torture_assert_ntstatus_ok(tctx,
		torture_rpc_binding(tctx, &binding),
		"failed to get binding");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_binding_set_transport(binding, NCACN_NP),
		"failed to set ncacn_np transport");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_binding_set_object(binding, GUID_zero()),
		"failed to set object uuid to zero");

	torture_assert_ntstatus_ok(tctx,
		torture_rpc_connection_with_binding(tctx, binding, &s, &ndr_table_spoolss),
		"failed to connect to spoolss");

	printer_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));

	client_info = test_get_client_info(tctx, WIN_7, 6, 1, "testclient_machine", "testclient_user");

	torture_assert(tctx,
		test_AsyncOpenPrinter_byprinter(tctx, ctx, p, printer_name, client_info, &handle),
		"failed to open printserver via winspool");


	r.in.handle = &handle;
	r.out.handle = &handle;

	torture_assert_ntstatus_equal(tctx,
		dcerpc_spoolss_ClosePrinter_r(s->binding_handle, tctx, &r),
		NT_STATUS_RPC_SS_CONTEXT_MISMATCH,
		"ClosePrinter failed");

	talloc_free(s);

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
	torture_tcase_add_simple_test(tcase, "SyncRegisterForRemoteNotifications", test_SyncRegisterForRemoteNotifications);
	torture_tcase_add_simple_test(tcase, "SyncUnRegisterForRemoteNotifications", test_SyncUnRegisterForRemoteNotifications);
	torture_tcase_add_simple_test(tcase, "AsyncClosePrinter", test_AsyncClosePrinter);
	torture_tcase_add_simple_test(tcase, "AsyncUploadPrinterDriverPackage", test_AsyncUploadPrinterDriverPackage);
	torture_tcase_add_simple_test(tcase, "AsyncEnumPrinters", test_AsyncEnumPrinters);
	torture_tcase_add_simple_test(tcase, "AsyncGetPrinterData", test_AsyncGetPrinterData);
	torture_tcase_add_simple_test(tcase, "AsyncCorePrinterDriverInstalled", test_AsyncCorePrinterDriverInstalled);
	torture_tcase_add_simple_test(tcase, "AsyncDeletePrintDriverPackage", test_AsyncDeletePrintDriverPackage);
	torture_tcase_add_simple_test(tcase, "AsyncGetPrinterDriverDirectory", test_AsyncGetPrinterDriverDirectory);
	torture_tcase_add_simple_test(tcase, "AsyncOpenPrinterValidateBuildNumber", test_AsyncOpenPrinterValidateBuildNumber);

	tcase = torture_suite_add_tcase(suite, "handles");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_iremotewinspool_setup,
				  torture_rpc_iremotewinspool_teardown);

	torture_tcase_add_simple_test(tcase, "OpenPrinter", test_OpenPrinter);

	return suite;
}
