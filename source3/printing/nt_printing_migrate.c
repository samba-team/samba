/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *
 *  Copyright (c) Andreas Schneider            2010.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "printing/nt_printing_migrate.h"

#include "librpc/gen_ndr/ndr_ntprinting.h"
#include "librpc/gen_ndr/cli_spoolss.h"
#include "rpc_client/cli_spoolss.h"
#include "librpc/gen_ndr/ndr_security.h"

#define FORMS_PREFIX "FORMS/"
#define DRIVERS_PREFIX "DRIVERS/"
#define PRINTERS_PREFIX "PRINTERS/"
#define SECDESC_PREFIX "SECDESC/"

static NTSTATUS migrate_form(TALLOC_CTX *mem_ctx,
			 struct rpc_pipe_client *pipe_hnd,
			 const char *key_name,
			 unsigned char *data,
			 size_t length)
{
	struct spoolss_DevmodeContainer devmode_ctr;
	struct policy_handle hnd;
	enum ndr_err_code ndr_err;
	struct ntprinting_form r;
	union spoolss_AddFormInfo f;
	struct spoolss_AddFormInfo1 f1;
	const char *srv_name_slash;
	DATA_BLOB blob;
	NTSTATUS status;
	WERROR result;


	blob = data_blob_const(data, length);

	ZERO_STRUCT(r);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &r,
		   (ndr_pull_flags_fn_t)ndr_pull_ntprinting_form);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(2, ("Form pull failed: %s\n",
			  ndr_errstr(ndr_err)));
		return NT_STATUS_NO_MEMORY;
	}

	/* Don't migrate builtin forms */
	if (r.flag == SPOOLSS_FORM_BUILTIN) {
		return NT_STATUS_OK;
	}

	DEBUG(2, ("Migrating Form: %s\n", key_name));

	srv_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", global_myname());
	if (srv_name_slash == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(devmode_ctr);

	status = rpccli_spoolss_OpenPrinter(pipe_hnd,
					    mem_ctx,
					    srv_name_slash,
					    NULL,
					    devmode_ctr,
					    SEC_FLAG_MAXIMUM_ALLOWED,
					    &hnd,
					    &result);
	if (!NT_STATUS_IS_OK(status)) {
		if (!W_ERROR_IS_OK(result)) {
			status = werror_to_ntstatus(result);
		}
		DEBUG(2, ("OpenPrinter(%s) failed: %s\n",
			  srv_name_slash, nt_errstr(status)));
		return status;
	}

	f1.form_name = key_name;
	f1.flags = r.flag;

	f1.size.width = r.width;
	f1.size.height = r.length;

	f1.area.top = r.top;
	f1.area.right = r.right;
	f1.area.bottom = r.bottom;
	f1.area.left = r.left;

	f.info1 = &f1;

	status = rpccli_spoolss_AddForm(pipe_hnd,
					mem_ctx,
					&hnd,
					1,
					f,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("AddForm(%s) refused -- %s.\n",
			  f.info1->form_name, nt_errstr(status)));
	}

	rpccli_spoolss_ClosePrinter(pipe_hnd, mem_ctx, &hnd, NULL);

	return status;
}

static NTSTATUS migrate_driver(TALLOC_CTX *mem_ctx,
			       struct rpc_pipe_client *pipe_hnd,
			       const char *key_name,
			       unsigned char *data,
			       size_t length)
{
	const char *srv_name_slash;
	enum ndr_err_code ndr_err;
	struct ntprinting_driver r;
	struct spoolss_AddDriverInfoCtr d;
	struct spoolss_AddDriverInfo3 d3;
	struct spoolss_StringArray a;
	DATA_BLOB blob;
	NTSTATUS status;
	WERROR result;

	blob = data_blob_const(data, length);

	ZERO_STRUCT(r);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &r,
		   (ndr_pull_flags_fn_t)ndr_pull_ntprinting_driver);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(2, ("Driver pull failed: %s\n",
			  ndr_errstr(ndr_err)));
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(2, ("Migrating Printer Driver: %s\n", key_name));

	srv_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", global_myname());
	if (srv_name_slash == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(d3);
	ZERO_STRUCT(a);

	a.string = r.dependent_files;

	d3.architecture = r.environment;
	d3.config_file = r.configfile;
	d3.data_file = r.datafile;
	d3.default_datatype = r.defaultdatatype;
	d3.dependent_files = &a;
	d3.driver_path = r.driverpath;
	d3.help_file = r.helpfile;
	d3.monitor_name = r.monitorname;
	d3.driver_name = r.name;
	d3.version = r.version;

	d.level = 3;
	d.info.info3 = &d3;

	status = rpccli_spoolss_AddPrinterDriver(pipe_hnd,
						 mem_ctx,
						 srv_name_slash,
						 &d,
						 &result);
	if (!NT_STATUS_IS_OK(status)) {
		if (!W_ERROR_IS_OK(result)) {
			status = werror_to_ntstatus(result);
		}
		DEBUG(2, ("AddPrinterDriver(%s) refused -- %s.\n",
			  d3.driver_name, nt_errstr(status)));
	}

	return status;
}

static NTSTATUS migrate_printer(TALLOC_CTX *mem_ctx,
				struct rpc_pipe_client *pipe_hnd,
				const char *key_name,
				unsigned char *data,
				size_t length)
{
	struct policy_handle hnd;
	enum ndr_err_code ndr_err;
	struct ntprinting_printer r;
	struct spoolss_SetPrinterInfo2 info2;
	struct spoolss_DeviceMode dm;
	struct spoolss_SetPrinterInfoCtr info_ctr;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct sec_desc_buf secdesc_ctr;
	DATA_BLOB blob;
	NTSTATUS status;
	WERROR result;
	int j;

	if (strequal(key_name, "printers")) {
		return NT_STATUS_OK;
	}

	blob = data_blob_const(data, length);

	ZERO_STRUCT(r);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &r,
		   (ndr_pull_flags_fn_t) ndr_pull_ntprinting_printer);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(2, ("printer pull failed: %s\n",
			  ndr_errstr(ndr_err)));
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(2, ("Migrating Printer: %s\n", key_name));

	ZERO_STRUCT(devmode_ctr);

	status = rpccli_spoolss_OpenPrinter(pipe_hnd,
					    mem_ctx,
					    key_name,
					    NULL,
					    devmode_ctr,
					    SEC_FLAG_MAXIMUM_ALLOWED,
					    &hnd,
					    &result);
	if (!NT_STATUS_IS_OK(status)) {
		if (!W_ERROR_IS_OK(result)) {
			status = werror_to_ntstatus(result);
		}
		DEBUG(2, ("OpenPrinter(%s) failed: %s\n",
			  key_name, nt_errstr(status)));
		return status;
	}

	/* Create printer info level 2 */
	ZERO_STRUCT(info2);
	ZERO_STRUCT(secdesc_ctr);

	info2.attributes = r.info.attributes;
	info2.averageppm = r.info.averageppm;
	info2.cjobs = r.info.cjobs;
	info2.comment = r.info.comment;
	info2.datatype = r.info.datatype;
	info2.defaultpriority = r.info.default_priority;
	info2.drivername = r.info.drivername;
	info2.location = r.info.location;
	info2.parameters = r.info.parameters;
	info2.portname = r.info.portname;
	info2.printername = r.info.printername;
	info2.printprocessor = r.info.printprocessor;
	info2.priority = r.info.priority;
	info2.sepfile = r.info.sepfile;
	info2.sharename = r.info.sharename;
	info2.starttime = r.info.starttime;
	info2.status = r.info.status;
	info2.untiltime = r.info.untiltime;

	/* Create Device Mode */
	if (r.devmode != NULL) {
		ZERO_STRUCT(dm);

		dm.bitsperpel              = r.devmode->bitsperpel;
		dm.collate                 = r.devmode->collate;
		dm.color                   = r.devmode->color;
		dm.copies                  = r.devmode->copies;
		dm.defaultsource           = r.devmode->defaultsource;
		dm.devicename              = r.devmode->devicename;
		dm.displayflags            = r.devmode->displayflags;
		dm.displayfrequency        = r.devmode->displayfrequency;
		dm.dithertype              = r.devmode->dithertype;
		dm.driverversion           = r.devmode->driverversion;
		dm.duplex                  = r.devmode->duplex;
		dm.fields                  = r.devmode->fields;
		dm.formname                = r.devmode->formname;
		dm.icmintent               = r.devmode->icmintent;
		dm.icmmethod               = r.devmode->icmmethod;
		dm.logpixels               = r.devmode->logpixels;
		dm.mediatype               = r.devmode->mediatype;
		dm.orientation             = r.devmode->orientation;
		dm.panningheight           = r.devmode->pelsheight;
		dm.panningwidth            = r.devmode->panningwidth;
		dm.paperlength             = r.devmode->paperlength;
		dm.papersize               = r.devmode->papersize;
		dm.paperwidth              = r.devmode->paperwidth;
		dm.pelsheight              = r.devmode->pelsheight;
		dm.pelswidth               = r.devmode->pelswidth;
		dm.printquality            = r.devmode->printquality;
		dm.scale                   = r.devmode->scale;
		dm.specversion             = r.devmode->specversion;
		dm.ttoption                = r.devmode->ttoption;
		dm.yresolution             = r.devmode->yresolution;

		if (r.devmode->nt_dev_private != NULL) {
			dm.driverextra_data.data   = r.devmode->nt_dev_private->data;
			dm.driverextra_data.length = r.devmode->nt_dev_private->length;
			dm.__driverextra_length    = r.devmode->nt_dev_private->length;
		}

		devmode_ctr.devmode = &dm;

		info2.devmode_ptr = 1;
	}

	info_ctr.info.info2 = &info2;
	info_ctr.level = 2;

	status = rpccli_spoolss_SetPrinter(pipe_hnd,
					   mem_ctx,
					   &hnd,
					   &info_ctr,
					   &devmode_ctr,
					   &secdesc_ctr,
					   0, /* command */
					   &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("SetPrinter(%s) level 2 refused -- %s.\n",
			  key_name, nt_errstr(status)));
		goto done;
	}

	/* migrate printerdata */
	for (j = 0; j < r.count; j++) {
		char *valuename;
		char *keyname;

		if (r.printer_data[j].type == REG_NONE) {
			continue;
		}

		keyname = CONST_DISCARD(char *, r.printer_data[j].name);
		valuename = strchr(keyname, '\\');
		if (valuename == NULL) {
			continue;
		} else {
			valuename[0] = '\0';
			valuename++;
		}

		status = rpccli_spoolss_SetPrinterDataEx(pipe_hnd,
							 mem_ctx,
							 &hnd,
							 keyname,
							 valuename,
							 r.printer_data[j].type,
							 r.printer_data[j].data.data,
							 r.printer_data[j].data.length,
							 &result);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("SetPrinterDataEx: printer [%s], keyname [%s], "
				  "valuename [%s] refused -- %s.\n",
				  key_name, keyname, valuename,
				  nt_errstr(status)));
			break;
		}
	}

 done:
	rpccli_spoolss_ClosePrinter(pipe_hnd, mem_ctx, &hnd, NULL);

	return status;
}

static NTSTATUS migrate_secdesc(TALLOC_CTX *mem_ctx,
				struct rpc_pipe_client *pipe_hnd,
				const char *key_name,
				unsigned char *data,
				size_t length)
{
	struct policy_handle hnd;
	enum ndr_err_code ndr_err;
	struct sec_desc_buf secdesc_ctr;
	struct spoolss_SetPrinterInfo3 info3;
	struct spoolss_SetPrinterInfoCtr info_ctr;
	struct spoolss_DevmodeContainer devmode_ctr;
	DATA_BLOB blob;
	NTSTATUS status;
	WERROR result;

	if (strequal(key_name, "printers")) {
		return NT_STATUS_OK;
	}

	blob = data_blob_const(data, length);

	ZERO_STRUCT(secdesc_ctr);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &secdesc_ctr,
		   (ndr_pull_flags_fn_t)ndr_pull_sec_desc_buf);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(2, ("security descriptor pull failed: %s\n",
			  ndr_errstr(ndr_err)));
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(2, ("Migrating Security Descriptor: %s\n", key_name));

	ZERO_STRUCT(devmode_ctr);

	status = rpccli_spoolss_OpenPrinter(pipe_hnd,
					    mem_ctx,
					    key_name,
					    NULL,
					    devmode_ctr,
					    SEC_FLAG_MAXIMUM_ALLOWED,
					    &hnd,
					    &result);
	if (!NT_STATUS_IS_OK(status)) {
		if (!W_ERROR_IS_OK(result)) {
			status = werror_to_ntstatus(result);
		}
		DEBUG(2, ("OpenPrinter(%s) failed: %s\n",
			  key_name, nt_errstr(status)));
		return status;
	}

	ZERO_STRUCT(devmode_ctr);

	info3.sec_desc_ptr = 1;

	info_ctr.info.info3 = &info3;
	info_ctr.level = 3;

	status = rpccli_spoolss_SetPrinter(pipe_hnd,
					   mem_ctx,
					   &hnd,
					   &info_ctr,
					   &devmode_ctr,
					   &secdesc_ctr,
					   0, /* command */
					   &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("SetPrinter(%s) level 3 refused -- %s.\n",
			  key_name, nt_errstr(status)));
	}

	rpccli_spoolss_ClosePrinter(pipe_hnd, mem_ctx, &hnd, NULL);

	return status;
}

static int rename_file_with_suffix(TALLOC_CTX *mem_ctx,
				   const char *path,
				   const char *suffix)
{
	int rc = -1;
	char *dst_path;

	dst_path = talloc_asprintf(mem_ctx, "%s%s", path, suffix);
	if (dst_path == NULL) {
		DEBUG(3, ("error out of memory\n"));
		return rc;
	}

	rc = (rename(path, dst_path) != 0);

	if (rc == 0) {
		DEBUG(5, ("moved '%s' to '%s'\n", path, dst_path));
	} else if (errno == ENOENT) {
		DEBUG(3, ("file '%s' does not exist - so not moved\n", path));
		rc = 0;
	} else {
		DEBUG(3, ("error renaming %s to %s: %s\n", path, dst_path,
			  strerror(errno)));
	}

	TALLOC_FREE(dst_path);
	return rc;
}

static NTSTATUS migrate_internal(TALLOC_CTX *mem_ctx,
				 const char *tdb_path,
				 struct rpc_pipe_client *pipe_hnd)
{
	const char *backup_suffix = ".bak";
	TDB_DATA kbuf, newkey, dbuf;
	TDB_CONTEXT *tdb;
	NTSTATUS status;
	int rc;

	tdb = tdb_open_log(tdb_path, 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (tdb == NULL) {
		DEBUG(2, ("Failed to open tdb file: %s\n", tdb_path));
		return NT_STATUS_NO_SUCH_FILE;
	}

	for (kbuf = tdb_firstkey(tdb);
	     kbuf.dptr;
	     newkey = tdb_nextkey(tdb, kbuf), free(kbuf.dptr), kbuf = newkey)
	{
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr) {
			continue;
		}

		if (strncmp((const char *) kbuf.dptr, FORMS_PREFIX, strlen(FORMS_PREFIX)) == 0) {
			status = migrate_form(mem_ctx,
					      pipe_hnd,
					      (const char *) kbuf.dptr + strlen(FORMS_PREFIX),
					      dbuf.dptr,
					      dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			if (!NT_STATUS_IS_OK(status)) {
				tdb_close(tdb);
				return status;
			}
			continue;
		}

		if (strncmp((const char *) kbuf.dptr, DRIVERS_PREFIX, strlen(DRIVERS_PREFIX)) == 0) {
			status = migrate_driver(mem_ctx,
						pipe_hnd,
						(const char *) kbuf.dptr + strlen(DRIVERS_PREFIX),
						dbuf.dptr,
						dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			if (!NT_STATUS_IS_OK(status)) {
				tdb_close(tdb);
				return status;
			}
			continue;
		}

		if (strncmp((const char *) kbuf.dptr, PRINTERS_PREFIX, strlen(PRINTERS_PREFIX)) == 0) {
			migrate_printer(mem_ctx,
					pipe_hnd,
					(const char *) kbuf.dptr + strlen(PRINTERS_PREFIX),
					dbuf.dptr,
					dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			if (!NT_STATUS_IS_OK(status)) {
				tdb_close(tdb);
				return status;
			}
			continue;
		}

		if (strncmp((const char *) kbuf.dptr, SECDESC_PREFIX, strlen(SECDESC_PREFIX)) == 0) {
			status = migrate_secdesc(mem_ctx,
						 pipe_hnd,
						 (const char *) kbuf.dptr + strlen(SECDESC_PREFIX),
						 dbuf.dptr,
						 dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			if (!NT_STATUS_IS_OK(status)) {
				tdb_close(tdb);
				return status;
			}
			continue;
		}
	}

	tdb_close(tdb);

	rc = rename_file_with_suffix(mem_ctx, tdb_path, backup_suffix);
	if (rc != 0) {
		DEBUG(0, ("Error moving tdb to '%s%s'\n",
			  tdb_path, backup_suffix));
	}

	return NT_STATUS_OK;
}

bool nt_printing_tdb_migrate(void)
{
	const char *drivers_path = state_path("ntdrivers.tdb");
	const char *printers_path = state_path("ntprinters.tdb");
	const char *forms_path = state_path("ntforms.tdb");
	bool drivers_exists = file_exist(drivers_path);
	bool printers_exists = file_exist(printers_path);
	bool forms_exists = file_exist(forms_path);
	struct auth_serversupplied_info *server_info;
	struct rpc_pipe_client *spoolss_pipe = NULL;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	NTSTATUS status;

	if (!drivers_exists && !printers_exists && !forms_exists) {
		return true;
	}

	status = make_server_info_system(tmp_ctx, &server_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Couldn't create server_info: %s\n",
			  nt_errstr(status)));
		talloc_free(tmp_ctx);
		return false;
	}

	status = rpc_pipe_open_internal(tmp_ctx,
					&ndr_table_spoolss.syntax_id,
					server_info,
					&spoolss_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Couldn't open internal spoolss pipe: %s\n",
			  nt_errstr(status)));
		talloc_free(tmp_ctx);
		return false;
	}

	if (drivers_exists) {
		status = migrate_internal(tmp_ctx, drivers_path, spoolss_pipe);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Couldn't migrate drivers tdb file: %s\n",
			  nt_errstr(status)));
			talloc_free(tmp_ctx);
			return false;
		}
	}

	if (printers_exists) {
		status = migrate_internal(tmp_ctx, printers_path, spoolss_pipe);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Couldn't migrate printers tdb file: %s\n",
				  nt_errstr(status)));
			talloc_free(tmp_ctx);
			return false;
		}
	}

	if (forms_exists) {
		status = migrate_internal(tmp_ctx, forms_path, spoolss_pipe);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Couldn't migrate forms tdb file: %s\n",
				  nt_errstr(status)));
			talloc_free(tmp_ctx);
			return false;
		}
	}

	talloc_free(tmp_ctx);
	return true;
}
