/* 
   Unix SMB/CIFS implementation.
   test suite for spoolss rpc operations

   Copyright (C) Tim Potter 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

BOOL test_GetPrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		     struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_GetPrinter r;
	uint16 levels[] = {1, 2, 3, 4, 5, 6, 7};
	int i;
	BOOL ret = True;
	
	for (i=0;i<ARRAY_SIZE(levels);i++) {
		uint32 buf_size = 0;
		r.in.handle = handle;
		r.in.level = levels[i];
		r.in.buffer = NULL;
		r.in.buf_size = &buf_size;
		r.out.buf_size = &buf_size;

		printf("Testing GetPrinter level %u\n", r.in.level);

		status = dcerpc_spoolss_GetPrinter(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("GetPrinter failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
		
		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, buf_size);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			status = dcerpc_spoolss_GetPrinter(p, mem_ctx, &r);
		}
		
		if (!NT_STATUS_IS_OK(status) ||
		    !W_ERROR_IS_OK(r.out.result)) {
			printf("GetPrinter failed - %s/%s\n", 
			       nt_errstr(status), win_errstr(r.out.result));
			ret = False;
			continue;
		}
	}

	return ret;
}


BOOL test_ClosePrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
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

BOOL test_GetForm(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		  struct policy_handle *handle, char *formname)
{
	NTSTATUS status;
	struct spoolss_GetForm r;
	uint32 buf_size;

	r.in.handle = handle;
	r.in.formname = formname;
	r.in.level = 1;
	r.in.buffer = NULL;
	buf_size = 0;
	r.in.buf_size = r.out.buf_size = &buf_size;

	printf("Testing GetForm\n");

	status = dcerpc_spoolss_GetForm(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetForm failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, buf_size);

		data_blob_clear(&blob);
		r.in.buffer = &blob;

		status = dcerpc_spoolss_GetForm(p, mem_ctx, &r);

		if (!r.out.info) {
			printf("No form info returned");
			return False;
		}

		{
			struct spoolss_AddForm af;
			struct spoolss_AddFormInfo1 form;

			af.in.handle = handle;
			af.in.level = 1;
			form.flags = 2;
			form.name = "testform3";
			form.width = r.out.info->info1.width;
			form.length = r.out.info->info1.length;
			form.left = r.out.info->info1.left;
			form.top = r.out.info->info1.top;
			form.right = r.out.info->info1.right;
			form.bottom = r.out.info->info1.bottom;
			af.in.info.info1 = &form;

			status = dcerpc_spoolss_AddForm(
				p, mem_ctx, &af);
		}
	}

	return True;
}

BOOL test_EnumForms(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		    struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumForms r;
	uint32 buf_size;

	r.in.handle = handle;
	r.in.level = 1;
	r.in.buffer = NULL;
	buf_size = 0;
	r.in.buf_size = &buf_size;
	r.out.buf_size = &buf_size;

	printf("Testing EnumForms\n");

	status = dcerpc_spoolss_EnumForms(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumForms failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, buf_size);
		union spoolss_FormInfo *info;
		int j;

		data_blob_clear(&blob);
		r.in.buffer = &blob;

		status = dcerpc_spoolss_EnumForms(p, mem_ctx, &r);

		if (!r.out.buffer) {
			printf("No forms returned");
			return False;
		}

		status = pull_spoolss_FormInfoArray(r.out.buffer, mem_ctx, r.in.level, r.out.count, &info);
		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumFormsArray parse failed - %s\n", nt_errstr(status));
			return False;
		}

		for (j=0;j<r.out.count;j++) {
			printf("Form %d\n", j);
			NDR_PRINT_UNION_DEBUG(spoolss_FormInfo, r.in.level, &info[j]);
		}

		for (j = 0; j < r.out.count; j++)
			test_GetForm(p, mem_ctx, handle, info[j].info1.name);
	}

	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("EnumForms failed - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		return False;
	}

	return True;
}

BOOL test_EnumPrinterData(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumPrinterData r;

	r.in.handle = handle;
	r.in.enum_index = 0;

	do {
		uint32 data_size;
		
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
		
		r.in.enum_index++;
	} while (!W_ERROR_IS_OK(r.out.result));

	return True;
}

static BOOL test_OpenPrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			     const char *name)
{
	NTSTATUS status;
	struct spoolss_OpenPrinter r;
	struct policy_handle handle;
	DATA_BLOB blob;
	BOOL ret = True;

	blob = data_blob(NULL, 0);

	r.in.server = talloc_asprintf(mem_ctx, "\\\\%s\\%s", dcerpc_server_name(p), name);
	r.in.printer = NULL;
	r.in.buffer = &blob;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;	
	r.out.handle = &handle;

	printf("\nTesting OpenPrinter(\\\\%s)\n", r.in.server);

	status = dcerpc_spoolss_OpenPrinter(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("OpenPrinter failed - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		/* don't consider failing this an error until we understand it */
		return True;
	}


	if (!test_GetPrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_ClosePrinter(p, mem_ctx, &handle)) {
		ret = False;
	}
	
	return ret;
}

static BOOL test_OpenPrinterEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       const char *name)
{
	struct policy_handle handle;
	struct spoolss_OpenPrinterEx r;
	struct spoolss_UserLevel1 userlevel1;
	NTSTATUS status;
	BOOL ret = True;

	r.in.printername = talloc_asprintf(mem_ctx, "\\\\%s\\%s", 
					   dcerpc_server_name(p), name);
	r.in.datatype = NULL;
	r.in.devmode_ctr.size = 0;
	r.in.devmode_ctr.devmode = NULL;
	r.in.access_required = 0x02000000;
	r.in.level = 1;
	r.out.handle = &handle;

	userlevel1.size = 1234;
	userlevel1.client = "hello";
	userlevel1.user = "spottyfoot!";
	userlevel1.build = 1;
	userlevel1.major = 2;
	userlevel1.minor = 3;
	userlevel1.processor = 4;
	r.in.userlevel.level1 = &userlevel1;

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

	if (!test_GetPrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumForms(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumPrinterData(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_ClosePrinter(p, mem_ctx, &handle)) {
		ret = False;
	}

	return ret;
}


static BOOL test_EnumPrinters(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct spoolss_EnumPrinters r;
	NTSTATUS status;
	uint16 levels[] = {1, 2, 4, 5};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		uint32 buf_size = 0;
		union spoolss_PrinterInfo *info;
		int j;

		r.in.flags = 0x02;
		r.in.server = "";
		r.in.level = levels[i];
		r.in.buffer = NULL;
		r.in.buf_size = &buf_size;
		r.out.buf_size = &buf_size;

		printf("\nTesting EnumPrinters level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinters(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrinters failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
		
		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, buf_size);
			data_blob_clear(&blob);
			r.in.buffer = &blob;
			status = dcerpc_spoolss_EnumPrinters(p, mem_ctx, &r);
		}
		
		if (!NT_STATUS_IS_OK(status) ||
		    !W_ERROR_IS_OK(r.out.result)) {
			printf("EnumPrinters failed - %s/%s\n", 
			       nt_errstr(status), win_errstr(r.out.result));
			continue;
		}

		if (!r.out.buffer) {
			printf("No printers returned");
			continue;
		}

		status = pull_spoolss_PrinterInfoArray(r.out.buffer, mem_ctx, r.in.level, r.out.count, &info);
		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrintersArray parse failed - %s\n", nt_errstr(status));
			continue;
		}

		for (j=0;j<r.out.count;j++) {
			printf("Printer %d\n", j);
			NDR_PRINT_UNION_DEBUG(spoolss_PrinterInfo, r.in.level, &info[j]);
		}

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

BOOL torture_rpc_spoolss(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_spoolss");

	status = torture_rpc_connection(&p, 
					DCERPC_SPOOLSS_NAME,
					DCERPC_SPOOLSS_UUID,
					DCERPC_SPOOLSS_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	p->flags |= DCERPC_DEBUG_PRINT_BOTH;
	
	if (!test_EnumPrinters(p, mem_ctx)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
