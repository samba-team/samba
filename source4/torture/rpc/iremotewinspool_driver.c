/*
   Unix SMB/CIFS implementation.
   test suite for iremotewinspool driver rpc operations

   Copyright (C) Justin Stephenson 2018

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

static bool test_init_iremotewinspool_conn(struct torture_context *tctx,
					   struct test_iremotewinspool_context *t)
{
	struct dcerpc_binding *binding = {0};
	bool ok = true;
	NTSTATUS status;

	status = GUID_from_string(IREMOTEWINSPOOL_OBJECT_GUID, &t->object_uuid);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "failed to parse GUID");

	status = torture_rpc_binding(tctx, &binding);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "failed to retrieve torture binding");

	status = dcerpc_binding_set_object(binding, t->object_uuid);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "failed to set object_uuid");

	status = torture_rpc_connection_with_binding(tctx, binding, &t->iremotewinspool_pipe,
						     &ndr_table_iremotewinspool);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "Error connecting to server");

done:

	return ok;

}

static bool test_init_iremotewinspool_openprinter(struct torture_context *tctx,
						  struct test_iremotewinspool_context *t)
{
	struct spoolss_UserLevel1 client_info = {0};
	char *printer_name = NULL;
	bool ok = true;

	printer_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(t->iremotewinspool_pipe));
	torture_assert_not_null_goto(tctx, printer_name, ok, done, "Cannot allocate memory");

	client_info = test_get_client_info(tctx, WIN_7, 3, SPOOLSS_MINOR_VERSION_0);

	ok = test_AsyncOpenPrinter_byprinter(tctx, t, t->iremotewinspool_pipe, printer_name,
					     client_info, &t->server_handle);
	torture_assert_goto(tctx, ok, ok, done, "failed to open printserver");

	ok = test_get_environment(tctx, t->iremotewinspool_pipe->binding_handle,
				  &t->server_handle, &t->environment);
	torture_assert_goto(tctx, ok, ok, done, "failed to get environment");

done:
	TALLOC_FREE(printer_name);

	return ok;
}

static bool torture_rpc_iremotewinspool_drv_setup_common(struct torture_context *tctx,
						     struct test_iremotewinspool_context *t)
{
	bool ok = true;

	ok = test_init_iremotewinspool_conn(tctx, t);
	torture_assert_goto(tctx, ok, ok, done, "failed to init iremotewinspool conn");

	ok = test_init_iremotewinspool_openprinter(tctx, t);
	torture_assert_goto(tctx, ok, ok, done, "failed to init iremotewinspool openprinter");
done:

	return ok;
}

static bool torture_rpc_iremotewinspool_drv_setup(struct torture_context *tctx,
					      void **data)
{
	struct test_iremotewinspool_context *t;

	*data = t = talloc_zero(tctx, struct test_iremotewinspool_context);

	return torture_rpc_iremotewinspool_drv_setup_common(tctx, t);
}

static bool torture_rpc_iremotewinspool_drv_teardown_common(struct torture_context *tctx,
							struct test_iremotewinspool_context *t)
{

	test_AsyncClosePrinter_byhandle(tctx, t, t->iremotewinspool_pipe, &t->server_handle);

	return true;
}

static bool torture_rpc_iremotewinspool_drv_teardown(struct torture_context *tctx,
						 void *data)
{
	struct test_iremotewinspool_context *t = talloc_get_type(data, struct test_iremotewinspool_context);
	bool ret;

	ret = torture_rpc_iremotewinspool_drv_teardown_common(tctx, t);
	talloc_free(t);

	return ret;
}

struct torture_suite *torture_rpc_iremotewinspool_drv(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "iremotewinspool_driver");
	struct torture_tcase *tcase = torture_suite_add_tcase(suite, "drivers");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_iremotewinspool_drv_setup,
				  torture_rpc_iremotewinspool_drv_teardown);

	return suite;
}
