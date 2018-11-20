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

#include <dirent.h>
#include <talloc.h>
#include <libgen.h>
#include "includes.h"
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_winspool.h"
#include "librpc/gen_ndr/ndr_winspool_c.h"
#include "librpc/gen_ndr/ndr_spoolss_c.h"
#include "librpc/gen_ndr/ndr_winreg_c.h"
#include "torture/rpc/torture_rpc.h"
#include "libcli/registry/util_reg.h"
#include "torture/rpc/iremotewinspool_common.h"
#include "libcli/libcli.h"
#include "param/param.h"
#include "lib/registry/registry.h"
#include "libcli/libcli.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/resolve/resolve.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "lib/cmdline/popt_common.h"
#include "system/filesys.h"
#include "lib/util/tftw.h"

/* Connect to print driver share //server_name/share */
static bool smb_connect_print_share(struct torture_context *tctx,
				    const char *server_name,
				    const char *share_name,
				    struct smbcli_state **cli)
{
	NTSTATUS status;
	bool ok = true;

	struct smbcli_options smb_options;
	struct smbcli_session_options smb_session_options;

	torture_comment(tctx, "Connecting to printer driver share '//%s/%s'\n",
			server_name, share_name);

	lpcfg_smbcli_options(tctx->lp_ctx, &smb_options);
	lpcfg_smbcli_session_options(tctx->lp_ctx, &smb_session_options);

	/* On Windows, SMB1 must be enabled! */
	status = smbcli_full_connection(tctx, cli, server_name,
					lpcfg_smb_ports(tctx->lp_ctx),
					share_name, NULL,
					lpcfg_socket_options(tctx->lp_ctx),
					popt_get_cmdline_credentials(),
					lpcfg_resolve_context(tctx->lp_ctx),
					tctx->ev,
					&smb_options,
					&smb_session_options,
					lpcfg_gensec_settings(tctx, tctx->lp_ctx));

	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "Failed to connect to print$ share");

done:

	return ok;
}

/* Copy file to destination where dst_fpath is a smb share path,
 * files are either created or overwritten */
static bool smb_copy_files(TALLOC_CTX *tctx,
				const char *fpath,
				const char *dst_fpath,
				struct test_driver_info *dinfo)
{
	FILE *fp;
	int smbfp = 0;
	char *buffer = NULL;
	int maxwrite = 64512;
	size_t nread;
	ssize_t nwrote;
	bool ok = true;
	size_t total_read;

	fp = fopen(fpath, "r");
	torture_assert_goto(tctx, fp, ok, done, "Failed to open local file\n");

	smbfp = smbcli_open(dinfo->cli->tree, dst_fpath, O_RDWR|O_CREAT|O_TRUNC, DENY_NONE);
	torture_assert_int_not_equal_goto(tctx, smbfp, -1, ok, done, "Failed to open dst file\n");

	buffer = talloc_array(tctx, char, maxwrite);
	torture_assert_not_null_goto(tctx, buffer, ok, done, "Failed to allocate buffer\n");

	total_read = 0;

	while (!feof(fp)) {
		nread = fread(buffer, 1, maxwrite, fp);
		if (ferror(fp)) {
			torture_warning(tctx, "Error reading file [%s]\n", fpath);
			continue;
		}

		nwrote = smbcli_write(dinfo->cli->tree, smbfp, 0, buffer, total_read, nread);
		if (nwrote != nread) {
			torture_warning(tctx, "Not all data in stream written!\n");
		}

		total_read += nread;
	}

	fclose(fp);
	smbcli_close(dinfo->cli->tree, smbfp);
done:

	TALLOC_FREE(buffer);
	return ok;
}

/* Callback function provided to tftw() to
 * copy driver files to smb share */
static int copy_driver_files(TALLOC_CTX *tctx,
			     const char *fpath,
			     const struct stat *sb,
			     enum tftw_flags_e flag,
			     void *userdata)
{
	char *dst_fpath = NULL;
	struct test_driver_info *dinfo = userdata;
	char *path = NULL;
	NTSTATUS status;
	bool ok = true;

	path = talloc_strdup(tctx, fpath + dinfo->driver_path_len);
	torture_assert_not_null_goto(tctx, path, ok, done, "Cannot allocate memory");

	string_replace(path, '/', '\\');

	dst_fpath = talloc_asprintf(tctx, "%s%s", dinfo->print_upload_guid_dir, path);
	torture_assert_not_null_goto(tctx, dst_fpath, ok, done, "Cannot allocate memory");

	switch (flag) {
		case TFTW_FLAG_FILE:
			ok = smb_copy_files(tctx, fpath, dst_fpath, dinfo);
			torture_assert_goto(tctx, ok, ok, done, "Failed to copy files over smb");
			break;
		case TFTW_FLAG_DIR:
			status = smbcli_mkdir(dinfo->cli->tree, dst_fpath);
			torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "Failed to create directories");
			break;
		case TFTW_FLAG_SLINK:
		case TFTW_FLAG_DNR:
		case TFTW_FLAG_NSTAT:
		case TFTW_FLAG_SPEC:
		case TFTW_FLAG_DP:
		case TFTW_FLAG_SLN:
			torture_warning(tctx, "WARN: Unhandled typeflag [%s]\n", fpath);
			break;
	}

done:
	TALLOC_FREE(path);
	TALLOC_FREE(dst_fpath);

	if (ok == true) {
		return 0;
	} else {
		return 1;
	}
}

static bool test_get_driver_torture_options(struct torture_context *tctx,
					    const char **_local_driver_path,
					    const char **_inf_file,
					    const char **_driver_name,
					    const char **_driver_arch,
					    const char **_core_driver_inf)
{
	const char *local_driver_path = NULL;
	const char *inf_file = NULL;
	const char *driver_name = NULL;
	const char *driver_arch = NULL;
	const char *core_driver_inf = NULL;
	const char *arches_list[] = {
		SPOOLSS_ARCHITECTURE_x64,
		SPOOLSS_ARCHITECTURE_NT_X86,
		SPOOLSS_ARCHITECTURE_IA_64,
		SPOOLSS_ARCHITECTURE_ARM,
		SPOOLSS_ARCHITECTURE_4_0,
		NULL,
	};
	const char **p;
	bool valid = false;
	bool ok = true;

	local_driver_path = torture_setting_string(tctx, "driver_path", NULL);
	if (local_driver_path == NULL) {
		torture_fail(tctx,
			     "option --option=torture:driver_path="
			     "/full/path/to/local/driver/dir\n");
	}

	inf_file = torture_setting_string(tctx, "inf_file", NULL);
	if (inf_file == NULL) {
		torture_fail(tctx,
			     "option --option=torture:inf_file="
			     "filename.inf\n");
	}

	driver_name = torture_setting_string(tctx, "driver_name", NULL);
	if (driver_name == NULL) {
		torture_fail(tctx,
			     "option --option=torture:driver_name="
			     "driver name\n");
	}

	driver_arch = torture_setting_string(tctx, "driver_arch", NULL);
	if (driver_arch == NULL) {
		torture_fail(tctx,
			     "option --option=torture:driver_arch="
			     "driver arch\n");
	}

	core_driver_inf = torture_setting_string(tctx, "core_driver_inf", NULL);

	for (p = arches_list; *p != NULL; p++) {
		if (strequal(*p, driver_arch) == 0) {
			valid = true;
			break;
		}
	}
	torture_assert_goto(tctx, valid, ok, done, "Invalid driver arch provided");

	*_local_driver_path = local_driver_path;
	*_inf_file = inf_file;
	*_driver_name = driver_name;
	*_driver_arch = driver_arch;
	*_core_driver_inf = core_driver_inf;
done:
	return ok;
}


static bool test_get_misc_driver_info(struct torture_context *tctx,
				      struct test_driver_info *dinfo,
				      const char **_abs_inf_path,
				      size_t *_driver_path_len)
{
	const char *abs_inf_path;
	size_t driver_path_len;
	bool ok = true;

	driver_path_len = strlen(dinfo->local_driver_path);
	torture_assert_int_not_equal_goto(tctx, driver_path_len, 0, ok, done, "driver path length is 0");

	abs_inf_path = talloc_asprintf(tctx, "%s/%s", dinfo->local_driver_path, dinfo->inf_file);
	torture_assert_not_null_goto(tctx, abs_inf_path, ok, done, "Cannot allocate memory");

	*_abs_inf_path = abs_inf_path;
	*_driver_path_len = driver_path_len;
done:

	return ok;
}

/* Uninstall the previously installed print driver */
static bool test_uninstall_printer_driver(struct torture_context *tctx,
					  struct test_iremotewinspool_context *ctx)
{
	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct winspool_AsyncDeletePrinterDriverEx r;
	bool ok = true;
	NTSTATUS status;

	r.in.pName = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));

	r.in.pDriverName = talloc_strdup(tctx, ctx->dinfo->driver_name);
	torture_assert_not_null_goto(tctx, r.in.pDriverName, ok, done, "Cannot allocate memory");

	r.in.pEnvironment = SPOOLSS_ARCHITECTURE_x64;

	r.in.dwDeleteFlag = 0;
	r.in.dwVersionNum = 0;

	status = dcerpc_winspool_AsyncDeletePrinterDriverEx_r(b, tctx, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "AsyncDeletePrinterDriverEx failed");

	torture_assert_werr_ok(tctx, r.out.result, "AsyncDeletePrinterDriverEx failed");
done:

	return ok;
}

/* Remove the leftover print driver package files from the driver store */
static bool test_remove_driver_package(struct torture_context *tctx,
				       struct test_iremotewinspool_context *ctx)
{
	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct winspool_AsyncDeletePrinterDriverPackage r;
	bool ok = true;
	NTSTATUS status;

	r.in.pszServer = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	torture_assert_not_null_goto(tctx, r.in.pszServer, ok, done, "Cannot allocate memory");

	r.in.pszInfPath = ctx->dinfo->uploaded_inf_path;

	r.in.pszEnvironment = SPOOLSS_ARCHITECTURE_x64;

	status = dcerpc_winspool_AsyncDeletePrinterDriverPackage_r(b, tctx, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "AsyncDeletePrinterPackage failed");

	torture_assert_hresult_ok(tctx, r.out.result, "AsyncDeletePrinterDriverPackage failed");
done:

	return ok;
}

static bool test_winreg_iremotewinspool_openhklm(struct torture_context *tctx,
						 struct dcerpc_binding_handle *winreg_bh,
						 struct policy_handle *_hklm_handle)
{
	struct winreg_OpenHKLM r;
	NTSTATUS status;
	bool ok = true;

	r.in.system_name = NULL;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = _hklm_handle;

	status = dcerpc_winreg_OpenHKLM_r(winreg_bh, tctx, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "Failed to Open HKLM");

	torture_assert_werr_ok(tctx, r.out.result, "Failed to Open HKLM");
done:

	return ok;
}

static bool test_winreg_iremotewinspool_openkey(struct torture_context *tctx,
						struct dcerpc_binding_handle *winreg_bh,
						struct policy_handle *hklm_handle,
						const char *keyname,
						struct policy_handle *_key_handle)
{
	struct winreg_OpenKey r;
	NTSTATUS status;
	bool ok = true;

	r.in.parent_handle = hklm_handle;
	init_winreg_String(&r.in.keyname, keyname);
	r.in.options = REG_OPTION_NON_VOLATILE;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = _key_handle;

	status = dcerpc_winreg_OpenKey_r(winreg_bh, tctx, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "OpenKey failed");

	torture_assert_werr_ok(tctx, r.out.result, "OpenKey failed");
done:

	return ok;
}

static bool test_winreg_iremotewinspool_queryvalue(struct torture_context *tctx,
						   struct dcerpc_binding_handle *b,
						   struct policy_handle *key_handle,
						   const char *value_name,
						   const char **_valuestr)
{
	struct winreg_QueryValue r;
	enum winreg_Type type = REG_NONE;
	struct winreg_String valuename;
	DATA_BLOB blob;
	const char *str;
	uint32_t data_size = 0;
	uint32_t data_length = 0;
	uint8_t *data = NULL;
	NTSTATUS status;
	bool ok = true;

	init_winreg_String(&valuename, value_name);

	data = talloc_zero_array(tctx, uint8_t, 0);

	r.in.handle = key_handle;
	r.in.value_name = &valuename;
	r.in.type = &type;
	r.in.data_size = &data_size;
	r.in.data_length = &data_length;
	r.in.data = data;

	r.out.type = &type;
	r.out.data = data;
	r.out.data_size = &data_size;
	r.out.data_length = &data_length;

	status = dcerpc_winreg_QueryValue_r(b, tctx, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "winreg_QueryValue failure");

	torture_assert_ntstatus_ok(tctx, dcerpc_winreg_QueryValue_r(b, tctx, &r), "QueryValue failed");
	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		*r.in.data_size = *r.out.data_size;
		data = talloc_zero_array(tctx, uint8_t, *r.in.data_size);
		r.in.data = data;
		r.out.data = data;
		status = dcerpc_winreg_QueryValue_r(b, tctx, &r);
		torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "QueryValue failed");
	}
	torture_assert_werr_ok(tctx, r.out.result, "QueryValue failed");

	torture_assert_int_equal_goto(tctx, *r.out.type, REG_SZ, ok, done, "unexpected type");
	blob = data_blob(r.out.data, *r.out.data_size);
	str = reg_val_data_string(tctx, REG_SZ, blob);

	*_valuestr = str;
done:

	return ok;
}

/* Validate the installed driver subkey exists, and the InfPath
 * value matches the pszDestInfPath from test_UploadPrinterDriverPackage */
static bool test_winreg_validate_driver(struct torture_context *tctx,
					struct dcerpc_pipe *winreg_pipe,
					struct test_driver_info *dinfo)
{
	struct policy_handle hklm_handle;
	struct policy_handle key_handle;
	char *driver_key = NULL;
	const char *val_name = NULL;
	const char *val_str = NULL;
	bool ok = true;

	struct dcerpc_binding_handle *winreg_bh;
	struct spoolss_AddDriverInfo8 *parsed_dinfo;

	winreg_bh = winreg_pipe->binding_handle;
	parsed_dinfo = dinfo->info;

	/* OpenHKLM */
	ok = test_winreg_iremotewinspool_openhklm(tctx, winreg_bh, &hklm_handle);
	torture_assert_goto(tctx, ok, ok, done, "Failed to perform winreg OpenHKLM");

	/* Open registry subkey for the installed print driver */
	driver_key = talloc_asprintf(tctx, "%s\\Environments\\%s\\Drivers\\Version-%d\\%s",
				     REG_DRIVER_CONTROL_KEY,
				     parsed_dinfo->architecture,
				     parsed_dinfo->version,
				     parsed_dinfo->driver_name);
	torture_assert_not_null_goto(tctx, driver_key, ok, done, "Cannot allocate driver_key string");
	ok = test_winreg_iremotewinspool_openkey(tctx, winreg_bh, &hklm_handle,
						 driver_key,
						 &key_handle);
	torture_assert_goto(tctx, ok, ok, done, "Failed to perform winreg OpenKey");

	/* Read infpath value and validate this matches what was uploaded */
	val_name = "InfPath";
	ok = test_winreg_iremotewinspool_queryvalue(tctx, winreg_bh, &key_handle, val_name,
						    &val_str);
	torture_assert_goto(tctx, ok, ok, done, "QueryValue failed");

	torture_assert_casestr_equal(tctx, val_str,
				 dinfo->uploaded_inf_path,
				 "InfPath does not match uploaded inf");
done:

	return ok;
}

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

	client_info = test_get_client_info(tctx, WIN_7, 3, SPOOLSS_MINOR_VERSION_0,
					   "testclient_machine", "testclient_user");

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

static bool test_init_driver_info(struct torture_context *tctx,
				  struct test_iremotewinspool_context *t)
{
	bool ok = true;
	const char *abs_inf_path;
	struct test_driver_info *drv_info = {0};

	drv_info = talloc_zero(tctx, struct test_driver_info);
	torture_assert_not_null_goto(tctx, drv_info, ok, done, "Cannot allocate memory");

	t->dinfo = drv_info;

	ok = test_get_driver_torture_options(tctx,
					     &drv_info->local_driver_path,
					     &drv_info->inf_file,
					     &drv_info->driver_name,
					     &drv_info->driver_arch,
					     &drv_info->core_driver_inf);
	torture_assert_goto(tctx, ok, ok, done, "Failed to get driver torture options");

	ok = test_get_misc_driver_info(tctx, drv_info,
				       &abs_inf_path,
				       &drv_info->driver_path_len);
	torture_assert_goto(tctx, ok, ok, done, "Failed to get misc driver info");

	ok = parse_inf_driver(tctx, drv_info->driver_name, abs_inf_path, drv_info->driver_arch,
			      drv_info->core_driver_inf, &drv_info->info);
	torture_assert_goto(tctx, ok, ok, done, "Failed to parse inf driver");

	/* Ensure that we are trying to install the correct device class:
	 * https://docs.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors
	 */
	if (!(drv_info->info->printer_driver_attributes & PRINTER_DRIVER_CLASS)) {
				ok = false;
				torture_fail_goto(tctx, done, "Inf file Class value must be Printer");
	}
done:
	return ok;

}

static bool test_init_server_and_share_info(struct torture_context *tctx,
					    struct test_iremotewinspool_context *t)
{
	struct GUID guid;
	bool ok = true;

	t->dinfo->server_name = talloc_asprintf(tctx, "%s", dcerpc_server_name(t->iremotewinspool_pipe));
	torture_assert_not_null_goto(tctx, t->dinfo->server_name, ok, done, "Cannot allocate memory");

	t->dinfo->share_name = talloc_strdup(tctx, "print$");
	torture_assert_not_null_goto(tctx, t->dinfo->share_name, ok, done, "Cannot allocate memory");

	guid = GUID_random();
	t->dinfo->print_upload_guid_dir = GUID_string2(tctx, &guid);
done:
	return ok;
}


static bool torture_rpc_iremotewinspool_drv_setup_common(struct torture_context *tctx,
						     struct test_iremotewinspool_context *t)
{
	bool ok = true;
	int ret = 0;

	ok = test_init_driver_info(tctx, t);
	torture_assert_goto(tctx, ok, ok, done, "failed to init driver info");

	ok = test_init_iremotewinspool_conn(tctx, t);
	torture_assert_goto(tctx, ok, ok, done, "failed to init iremotewinspool conn");

	ok = test_init_iremotewinspool_openprinter(tctx, t);
	torture_assert_goto(tctx, ok, ok, done, "failed to init iremotewinspool openprinter");

	ok = test_init_server_and_share_info(tctx, t);
	torture_assert_goto(tctx, ok, ok, done, "failed to init server and share info");

	ret = smb_connect_print_share(tctx, t->dinfo->server_name, t->dinfo->share_name, &t->dinfo->cli);
	torture_assert_goto(tctx, ret, ok, done, "Failed to connect to print share");

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
	smbcli_deltree(t->dinfo->cli->tree, t->dinfo->print_upload_guid_dir);
	smb_raw_exit(t->dinfo->cli->session);

	test_uninstall_printer_driver(tctx, t);
	test_remove_driver_package(tctx, t);

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

/* Creates {GUID} directory inside //server/print$ then copies driver files
 * and directories from torture option driver_path to this directory over smb */
static bool test_CopyDriverFiles(struct torture_context *tctx,
				   void *private_data)
{
	struct test_iremotewinspool_context *ctx =
	talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	bool ret = false;
	bool ok = true;
	NTSTATUS status;

	status = smbcli_mkdir(ctx->dinfo->cli->tree, ctx->dinfo->print_upload_guid_dir);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "Failed to create upload directory");

	/* Walk the provided torture option driver_path file tree, creating the directory heirarchy and
	 * copying all files to print$/{GUID}/ share */
	ret = tftw(tctx, ctx->dinfo->local_driver_path, copy_driver_files, TFTW_MAX_DEPTH, ctx->dinfo);
	torture_assert_int_equal_goto(tctx, ret, 0, ok, done, "Failed to copy driver files to print$/{GUID}/ dir");

done:

	return ok;
}

/*
 * Upload print driver package files and inf file, preparing the print server
 * for driver installation
 */
static bool test_UploadPrinterDriverPackage(struct torture_context *tctx,
					    void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;

	struct spoolss_AddDriverInfo8 *parsed_dinfo;
	struct winspool_AsyncUploadPrinterDriverPackage r;
	uint32_t pcchDestInfPath = 0;
	NTSTATUS status;
	bool ok = true;

	parsed_dinfo = ctx->dinfo->info;

	r.in.pszServer = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	torture_assert_not_null_goto(tctx, r.in.pszServer, ok, done, "Cannot allocate memory");

	r.in.pszInfPath = talloc_asprintf(tctx, "\\\\%s\\%s\\%s\\%s", ctx->dinfo->server_name,
								      ctx->dinfo->share_name,
							              ctx->dinfo->print_upload_guid_dir,
							              ctx->dinfo->inf_file);
	torture_assert_not_null_goto(tctx, r.in.pszInfPath, ok, done, "Cannot allocate memory");

	r.in.pszEnvironment = parsed_dinfo->architecture;
	/* Upload driver package files even if the driver package is already present
	 * on the print server */
	r.in.dwFlags = UPDP_UPLOAD_ALWAYS;
	pcchDestInfPath = 260;
	r.in.pszDestInfPath = NULL;
	r.in.pcchDestInfPath = &pcchDestInfPath;
	r.out.pszDestInfPath = NULL;
	r.out.pcchDestInfPath = &pcchDestInfPath;

	r.in.pszDestInfPath = talloc_zero(tctx, const char);
	torture_assert_not_null_goto(tctx, r.in.pszDestInfPath, ok, done, "Cannot allocate memory");
	r.out.pszDestInfPath = talloc_zero(tctx, const char);
	torture_assert_not_null_goto(tctx, r.out.pszDestInfPath, ok, done, "Cannot allocate memory");

	status = dcerpc_winspool_AsyncUploadPrinterDriverPackage_r(b, tctx, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "AsyncUploadPrinterDriverPackage failed");

	torture_assert_hresult_ok(tctx, r.out.result, "AsyncUploadPrinterDriverPackage failed");

	ctx->dinfo->uploaded_inf_path = talloc_strdup(tctx, r.out.pszDestInfPath);
	torture_assert_not_null_goto(tctx, ctx->dinfo->uploaded_inf_path, ok, done, "Cannot allocate memory");

done:

	return ok;
}

/* Install the driver that was successfully uploaded to the printer driver
 * store, note that Windows validates the pszDriverName as mentioned below */
static bool test_InstallPrinterDriverFromPackage(struct torture_context *tctx,
					     void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *p = ctx->iremotewinspool_pipe;
	struct dcerpc_binding_handle *b = p->binding_handle;

	char *abs_inf_path = NULL;
	struct spoolss_AddDriverInfo8 *parsed_dinfo;
	struct winspool_AsyncInstallPrinterDriverFromPackage r;
	bool ok = true;
	NTSTATUS status;

	parsed_dinfo = ctx->dinfo->info;

	r.in.pszServer = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	torture_assert_not_null_goto(tctx, r.in.pszServer, ok, done, "Cannot allocate memory");

	/* output string(pszDestInfPath) from test_UploadPrinterDriverPackage() */
	r.in.pszInfPath = talloc_strdup(tctx, ctx->dinfo->uploaded_inf_path);
	torture_assert_not_null_goto(tctx, r.in.pszInfPath, ok, done, "Cannot allocate memory");

	abs_inf_path = talloc_asprintf(tctx, "%s/%s", ctx->dinfo->local_driver_path, ctx->dinfo->inf_file);
	torture_assert_not_null_goto(tctx, abs_inf_path, ok, done, "Cannot allocate memory");

	r.in.pszEnvironment = parsed_dinfo->architecture;
	torture_assert_not_null_goto(tctx, r.in.pszEnvironment, ok, done, "Cannot allocate memory");

	/* Windows validates the print driver name by checking the pszDriverName input against the inf file:
	 * 1) "DriverName" value
	 * 2) "CompatName" value
	 * 3) left-hand-side value under the [Model] section
	 * otherwise ERROR_UNKNOWN_PRINTER_DRIVER is returned */
	r.in.pszDriverName = parsed_dinfo->driver_name;
	torture_assert_not_null_goto(tctx, r.in.pszDriverName, ok, done, "Cannot allocate memory");

	/* All files should be installed, even if doing so would overwrite some newer
	 * versions */
	r.in.dwFlags = IPDFP_COPY_ALL_FILES;

	status = dcerpc_winspool_AsyncInstallPrinterDriverFromPackage_r(b, tctx, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "AsyncInstallPrinterDriverFromPackage failed");

	torture_assert_hresult_ok(tctx, r.out.result, "AsyncInstallPrinterDriverFromPackage failed");
done:
	TALLOC_FREE(abs_inf_path);

	return ok;
}

/* Check the registry to validate the print driver installed successfully */
static bool test_ValidatePrinterDriverInstalled(struct torture_context *tctx,
						 void *private_data)
{
	struct test_iremotewinspool_context *ctx =
		talloc_get_type_abort(private_data, struct test_iremotewinspool_context);

	struct dcerpc_pipe *winreg_pipe = NULL;
	NTSTATUS status;
	bool ok = true;

	/* winreg is not available over ncacn_ip_tcp */
	status = torture_rpc_connection_transport(tctx, &winreg_pipe, &ndr_table_winreg, NCACN_NP, 0, 0);
	if (NT_STATUS_EQUAL(status, NT_STATUS_PIPE_NOT_AVAILABLE)) {
		/* retry */
		status = torture_rpc_connection_transport(tctx, &winreg_pipe, &ndr_table_winreg, NCACN_NP, 0, 0);
	}
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "Failed to connect to winreg");

	ok = test_winreg_validate_driver(tctx, winreg_pipe, ctx->dinfo);
	torture_assert_goto(tctx, ok, ok, done, "Failed to validate driver with winreg");

done:
	TALLOC_FREE(winreg_pipe);

	return ok;
}

struct torture_suite *torture_rpc_iremotewinspool_drv(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "iremotewinspool_driver");
	struct torture_tcase *tcase = torture_suite_add_tcase(suite, "drivers");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_iremotewinspool_drv_setup,
				  torture_rpc_iremotewinspool_drv_teardown);

	torture_tcase_add_simple_test(tcase, "CopyDriverFiles", test_CopyDriverFiles);
	torture_tcase_add_simple_test(tcase, "UploadPrinterDriverPackage", test_UploadPrinterDriverPackage);
	torture_tcase_add_simple_test(tcase, "InstallPrinterDriverFromPackage", test_InstallPrinterDriverFromPackage);
	torture_tcase_add_simple_test(tcase, "ValidatePrinterDriverInstalled", test_ValidatePrinterDriverInstalled);

	return suite;
}
