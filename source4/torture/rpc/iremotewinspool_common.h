/*
   Unix SMB/CIFS implementation.

   iremotewinspool rpc test operations

   Copyright (C) 2018 Justin Stephenson

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

#include "torture/rpc/torture_rpc.h"

#define REG_DRIVER_CONTROL_KEY "SYSTEM\\CurrentControlSet\\Control\\Print"

struct test_driver_info {
	struct smbcli_state *cli;
	struct spoolss_AddDriverInfo8 *info;
	const char *local_driver_path;
	size_t driver_path_len;
	char *server_name;
	char *share_name;
	char *print_upload_guid_dir;
	const char *inf_file;
	const char *uploaded_inf_path;
	const char *driver_name;
	const char *driver_arch;
	const char *core_driver_inf;
};

struct test_iremotewinspool_context {
	struct GUID object_uuid;
	struct dcerpc_pipe *iremotewinspool_pipe;
	struct policy_handle server_handle;
	struct test_driver_info *dinfo;
	const char *environment;
};

enum client_os_version
{
	WIN_2000,
	WIN_VISTA,
	WIN_SERVER_2008,
	WIN_7,
	WIN_SERVER_2008R2,
	WIN_8,
	WIN_SERVER_2012,
	WIN_10,
	WIN_SERVER_2016
};

void init_winreg_String(struct winreg_String *name, const char *s);

struct spoolss_UserLevel1 test_get_client_info(struct torture_context *tctx,
						      enum client_os_version os,
						      enum spoolss_MajorVersion major_number,
						      enum spoolss_MinorVersion minor_number,
						      const char *machine,
						      const char *user);

bool test_AsyncOpenPrinter_byprinter(struct torture_context *tctx,
					    struct test_iremotewinspool_context *ctx,
					    struct dcerpc_pipe *p,
					    const char *printer_name,
					    struct spoolss_UserLevel1 cinfo,
					    struct policy_handle *handle);

bool test_get_environment(struct torture_context *tctx,
				 struct dcerpc_binding_handle *b,
				 struct policy_handle *handle,
				 const char **architecture);

bool test_AsyncClosePrinter_byhandle(struct torture_context *tctx,
					    struct test_iremotewinspool_context *ctx,
					    struct dcerpc_pipe *p,
					    struct policy_handle *handle);

bool test_AsyncGetPrinterData_args(struct torture_context *tctx,
					  struct dcerpc_binding_handle *b,
					  struct policy_handle *handle,
					  const char *value_name,
					  enum winreg_Type *type_p,
					  uint8_t **data_p,
					  uint32_t *needed_p);

bool parse_inf_driver(struct torture_context *tctx,
		      const char *driver_name,
		      const char *abs_inf_path,
		      const char *driver_arch,
		      const char *core_driver_inf,
		      struct spoolss_AddDriverInfo8 **_parsed_dinfo);
