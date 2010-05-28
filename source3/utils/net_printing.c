/*
   Samba Unix/Linux SMB client library
   Distributed SMB/CIFS Server Management Utility
   Local printing tdb migration interface

   Copyright (C) Guenther Deschner 2010

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
#include "utils/net.h"
#include "librpc/gen_ndr/ndr_ntprinting.h"
#include "librpc/gen_ndr/cli_spoolss.h"
#include "rpc_client/cli_spoolss.h"
#include "../librpc/gen_ndr/ndr_security.h"

#define FORMS_PREFIX "FORMS/"
#define DRIVERS_PREFIX "DRIVERS/"
#define PRINTERS_PREFIX "PRINTERS/"
#define SECDESC_PREFIX "SECDESC/"

static void dump_form(TALLOC_CTX *mem_ctx,
		      const char *key_name,
		      unsigned char *data,
		      size_t length)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	char *s;
	struct ntprinting_form r;

	printf("found form: %s\n", key_name);

	blob = data_blob_const(data, length);

	ZERO_STRUCT(r);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &r,
		   (ndr_pull_flags_fn_t)ndr_pull_ntprinting_form);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		d_fprintf(stderr, _("form pull failed: %s\n"),
			  ndr_errstr(ndr_err));
		return;
	}

	s = NDR_PRINT_STRUCT_STRING(mem_ctx, ntprinting_form, &r);
	if (s) {
		printf("%s\n", s);
	}
}

static void dump_driver(TALLOC_CTX *mem_ctx,
			const char *key_name,
			unsigned char *data,
			size_t length)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	char *s;
	struct ntprinting_driver r;

	printf("found driver: %s\n", key_name);

	blob = data_blob_const(data, length);

	ZERO_STRUCT(r);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &r,
		   (ndr_pull_flags_fn_t)ndr_pull_ntprinting_driver);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		d_fprintf(stderr, _("driver pull failed: %s\n"),
			  ndr_errstr(ndr_err));
		return;
	}

	s = NDR_PRINT_STRUCT_STRING(mem_ctx, ntprinting_driver, &r);
	if (s) {
		printf("%s\n", s);
	}
}

static void dump_printer(TALLOC_CTX *mem_ctx,
			 const char *key_name,
			 unsigned char *data,
			 size_t length)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	char *s;
	struct ntprinting_printer r;

	printf("found printer: %s\n", key_name);

	blob = data_blob_const(data, length);

	ZERO_STRUCT(r);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &r,
		   (ndr_pull_flags_fn_t)ndr_pull_ntprinting_printer);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		d_fprintf(stderr, _("printer pull failed: %s\n"),
			  ndr_errstr(ndr_err));
		return;
	}

	s = NDR_PRINT_STRUCT_STRING(mem_ctx, ntprinting_printer, &r);
	if (s) {
		printf("%s\n", s);
	}
}

static void dump_sd(TALLOC_CTX *mem_ctx,
		    const char *key_name,
		    unsigned char *data,
		    size_t length)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	char *s;
	struct sec_desc_buf r;

	printf("found security descriptor: %s\n", key_name);

	blob = data_blob_const(data, length);

	ZERO_STRUCT(r);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &r,
		   (ndr_pull_flags_fn_t)ndr_pull_sec_desc_buf);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		d_fprintf(stderr, _("security descriptor pull failed: %s\n"),
			  ndr_errstr(ndr_err));
		return;
	}

	s = NDR_PRINT_STRUCT_STRING(mem_ctx, sec_desc_buf, &r);
	if (s) {
		printf("%s\n", s);
	}
}


static int net_printing_dump(struct net_context *c, int argc,
			     const char **argv)
{
	int ret = -1;
	TALLOC_CTX *ctx = talloc_stackframe();
	TDB_CONTEXT *tdb;
	TDB_DATA kbuf, newkey, dbuf;

	if (argc < 1 || c->display_usage) {
		d_fprintf(stderr, "%s\nnet printing dump <file.tdb>\n",
			  _("Usage:"));
		goto done;
	}

	tdb = tdb_open_log(argv[0], 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (!tdb) {
		d_fprintf(stderr, _("failed to open tdb file: %s\n"), argv[0]);
		goto done;
	}

	for (kbuf = tdb_firstkey(tdb);
	     kbuf.dptr;
	     newkey = tdb_nextkey(tdb, kbuf), free(kbuf.dptr), kbuf=newkey)
	{
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr) {
			continue;
		}

		if (strncmp((const char *)kbuf.dptr, FORMS_PREFIX, strlen(FORMS_PREFIX)) == 0) {
			dump_form(ctx, (const char *)kbuf.dptr+strlen(FORMS_PREFIX), dbuf.dptr, dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			continue;
		}

		if (strncmp((const char *)kbuf.dptr, DRIVERS_PREFIX, strlen(DRIVERS_PREFIX)) == 0) {
			dump_driver(ctx, (const char *)kbuf.dptr+strlen(DRIVERS_PREFIX), dbuf.dptr, dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			continue;
		}

		if (strncmp((const char *)kbuf.dptr, PRINTERS_PREFIX, strlen(PRINTERS_PREFIX)) == 0) {
			dump_printer(ctx, (const char *)kbuf.dptr+strlen(PRINTERS_PREFIX), dbuf.dptr, dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			continue;
		}

		if (strncmp((const char *)kbuf.dptr, SECDESC_PREFIX, strlen(SECDESC_PREFIX)) == 0) {
			dump_sd(ctx, (const char *)kbuf.dptr+strlen(SECDESC_PREFIX), dbuf.dptr, dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			continue;
		}

	}

	ret = 0;

 done:
	talloc_free(ctx);
	return ret;
}

static NTSTATUS migrate_form(TALLOC_CTX *mem_ctx,
			 struct rpc_pipe_client *pipe_hnd,
			 const char *key_name,
			 unsigned char *data,
			 size_t length)
{
	struct policy_handle hnd;
	enum ndr_err_code ndr_err;
	struct ntprinting_form r;
	union spoolss_AddFormInfo f;
	struct spoolss_AddFormInfo1 f1;
	DATA_BLOB blob;
	NTSTATUS status;
	WERROR result;

	blob = data_blob_const(data, length);

	ZERO_STRUCT(r);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &r,
		   (ndr_pull_flags_fn_t)ndr_pull_ntprinting_form);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		d_fprintf(stderr, _("form pull failed: %s\n"),
			  ndr_errstr(ndr_err));
		return NT_STATUS_NO_MEMORY;
	}

	/* Don't migrate builtin forms */
	if (r.flag == SPOOLSS_FORM_BUILTIN) {
		return NT_STATUS_OK;
	}

	d_printf(_("Migrating Form: %s\n"), key_name);

	result = rpccli_spoolss_openprinter_ex(pipe_hnd,
					       mem_ctx,
					       pipe_hnd->srv_name_slash,
					       MAXIMUM_ALLOWED_ACCESS,
					       &hnd);
	if (!W_ERROR_IS_OK(result)) {
		d_fprintf(stderr, _("OpenPrinter(%s) failed: %s\n"),
				  pipe_hnd->srv_name_slash, win_errstr(result));
		return werror_to_ntstatus(result);
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
		d_printf(_("\tAddForm(%s) refused -- %s.\n"),
			f.info1->form_name, nt_errstr(status));
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
		d_fprintf(stderr, _("driver pull failed: %s\n"),
			  ndr_errstr(ndr_err));
		return NT_STATUS_NO_MEMORY;
	}

	d_printf(_("Migrating Printer Driver: %s\n"), key_name);

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

	d.info.info3 = &d3;
	d.level = 3;

	status = rpccli_spoolss_AddPrinterDriver(pipe_hnd,
						 mem_ctx,
						 NULL,
						 &d,
						 &result);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf(_("\tAddDriver driver: [%s] refused -- %s.\n"),
			d3.driver_name, nt_errstr(status));
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
		d_fprintf(stderr, _("printer pull failed: %s\n"),
			  ndr_errstr(ndr_err));
		return NT_STATUS_NO_MEMORY;
	}

	d_printf(_("Migrating Printer: %s\n"), key_name);

	result = rpccli_spoolss_openprinter_ex(pipe_hnd,
					       mem_ctx,
					       key_name,
					       MAXIMUM_ALLOWED_ACCESS,
					       &hnd);
	if (!W_ERROR_IS_OK(result)) {
		d_fprintf(stderr, _("OpenPrinter(%s) failed: %s\n"),
				  key_name, win_errstr(result));
		return werror_to_ntstatus(result);
	}

	/* Create printer info level 2 */
	ZERO_STRUCT(info2);
	ZERO_STRUCT(devmode_ctr);
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
		d_printf(_("\tSetPrinter(%s) level 2 refused -- %s.\n"),
			key_name, nt_errstr(status));
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

		printf("          data: %s\\%s\n", keyname, valuename);

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
			d_printf(_("\tSetPrinterDataEx: printer [%s], keyname [%s], valuename [%s] refused -- %s.\n"),
				key_name, keyname, valuename, nt_errstr(status));
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
		d_fprintf(stderr, _("security descriptor pull failed: %s\n"),
			  ndr_errstr(ndr_err));
		return NT_STATUS_NO_MEMORY;
	}

	d_printf(_("Migrating Security Descriptor: %s\n"), key_name);

	result = rpccli_spoolss_openprinter_ex(pipe_hnd,
					       mem_ctx,
					       key_name,
					       MAXIMUM_ALLOWED_ACCESS,
					       &hnd);
	if (!W_ERROR_IS_OK(result)) {
		d_fprintf(stderr, _("\tOpenPrinter(%s) failed: %s\n"),
				  key_name, win_errstr(result));
		return werror_to_ntstatus(result);
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
		d_printf(_("\tSetPrinter(%s) level 3 refused -- %s.\n"),
			key_name, nt_errstr(status));
	}

	rpccli_spoolss_ClosePrinter(pipe_hnd, mem_ctx, &hnd, NULL);

	return status;
}

static NTSTATUS printing_migrate_internal(struct net_context *c,
					  const struct dom_sid *domain_sid,
					  const char *domain_name,
					  struct cli_state *cli,
					  struct rpc_pipe_client *pipe_hnd,
					  TALLOC_CTX *mem_ctx,
					  int argc,
					  const char **argv)
{
	TALLOC_CTX *tmp_ctx;
	TDB_CONTEXT *tdb;
	TDB_DATA kbuf, newkey, dbuf;
	NTSTATUS status;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	tdb = tdb_open_log(argv[0], 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (tdb == NULL) {
		d_fprintf(stderr, _("failed to open tdb file: %s\n"), argv[0]);
		status = NT_STATUS_NO_SUCH_FILE;
		goto done;
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
			migrate_form(tmp_ctx,
				     pipe_hnd,
				     (const char *) kbuf.dptr + strlen(FORMS_PREFIX),
				     dbuf.dptr,
				     dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			continue;
		}

		if (strncmp((const char *) kbuf.dptr, DRIVERS_PREFIX, strlen(DRIVERS_PREFIX)) == 0) {
			migrate_driver(tmp_ctx,
				       pipe_hnd,
				       (const char *) kbuf.dptr + strlen(DRIVERS_PREFIX),
				       dbuf.dptr,
				       dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			continue;
		}

		if (strncmp((const char *) kbuf.dptr, PRINTERS_PREFIX, strlen(PRINTERS_PREFIX)) == 0) {
			migrate_printer(tmp_ctx,
					pipe_hnd,
					(const char *) kbuf.dptr + strlen(PRINTERS_PREFIX),
					dbuf.dptr,
					dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			continue;
		}

		if (strncmp((const char *) kbuf.dptr, SECDESC_PREFIX, strlen(SECDESC_PREFIX)) == 0) {
			migrate_secdesc(tmp_ctx,
					pipe_hnd,
					(const char *) kbuf.dptr + strlen(SECDESC_PREFIX),
					dbuf.dptr,
					dbuf.dsize);
			SAFE_FREE(dbuf.dptr);
			continue;
		}

	}

	status = NT_STATUS_OK;

 done:
	talloc_free(tmp_ctx);
	return status;
}

static int net_printing_migrate(struct net_context *c,
				int argc,
				const char **argv)
{
	if (argc < 1 || c->display_usage) {
		d_printf(  "%s\n"
			   "net printing migrate <file.tdb>\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Migrate tdb printing files to new storage"));
		return 0;
	}

	return run_rpc_command(c,
			       NULL,
			       &ndr_table_spoolss.syntax_id,
			       0,
			       printing_migrate_internal,
			       argc,
			       argv);
}
/**
 * 'net printing' entrypoint.
 * @param argc  Standard main() style argc.
 * @param argv  Standard main() style argv. Initial components are already
 *              stripped.
 **/

int net_printing(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;

	struct functable func[] = {
		{
			"dump",
			net_printing_dump,
			NET_TRANSPORT_LOCAL,
			N_("Dump eventlog"),
			N_("net printing dump\n"
			   "    Dump tdb printing file")
		},

		{
			"migrate",
			net_printing_migrate,
			NET_TRANSPORT_LOCAL | NET_TRANSPORT_RPC,
			N_("Migrate printer databases"),
			N_("net printing migrate\n"
			   "    Migrate tdb printing files to new storage")
		},

	{ NULL, NULL, 0, NULL, NULL }
	};

	ret = net_run_function(c, argc, argv, "net printing", func);

	return ret;
}
