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
#include "librpc/gen_ndr/ndr_spoolss.h"

static BOOL test_GetPrinter(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		     struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_GetPrinter r;
	uint16_t levels[] = {1, 2, 3, 4, 5, 6, 7};
	int i;
	BOOL ret = True;
	
	for (i=0;i<ARRAY_SIZE(levels);i++) {
		uint32_t buf_size = 0;
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
			 const char *formname)
{
	NTSTATUS status;
	struct spoolss_GetForm r;
	uint32_t buf_size;

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
	}

	return True;
}

static BOOL test_EnumForms(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		    struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumForms r;
	uint32_t buf_size;

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
			test_GetForm(p, mem_ctx, handle, info[j].info1.formname);
	}

	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("EnumForms failed - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_DeleteForm(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *handle, 
			    const char *formname)
{
	NTSTATUS status;
	struct spoolss_DeleteForm r;

	r.in.handle = handle;
	r.in.formname = formname;

	status = dcerpc_spoolss_DeleteForm(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("DeleteForm failed - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_AddForm(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		  struct policy_handle *handle)
{
	struct spoolss_AddForm r;
	struct spoolss_AddFormInfo1 form;
	NTSTATUS status;
	const char *formname = "testform3";
	BOOL ret = True;

	r.in.handle = handle;
	r.in.level = 1;
	form.flags = 2;		/* User form */
	form.formname = formname;
	form.width = 1;
	form.length = 2;
	form.left = 3;
	form.top = 4;
	form.right = 5;
	form.bottom = 6;
	r.in.info.info1 = &form;
	
	status = dcerpc_spoolss_AddForm(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("AddForm failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("AddForm failed - %s\n", nt_errstr(status));
		goto done;
	}

	{
		struct spoolss_SetForm sf;

		sf.in.handle = handle;
		sf.in.formname = formname;
		sf.in.level = 1;
		sf.in.info.info1 = &form;
		form.width = 1234;

		status = dcerpc_spoolss_SetForm(p, mem_ctx, &sf);

		if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
			printf("SetForm failed - %s/%s\n", 
			       nt_errstr(status), win_errstr(r.out.result));
			ret = False;
			/* Fall through to delete */
		}
	}

 done:
	if (!test_DeleteForm(p, mem_ctx, handle, formname)) {
		printf("DeleteForm failed\n");
		ret = False;
	}

	return ret;
}

static BOOL test_EnumPorts(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct spoolss_EnumPorts r;
	uint32_t buf_size;

	r.in.servername = talloc_asprintf(mem_ctx, "\\\\%s", 
					  dcerpc_server_name(p));
	r.in.level = 2;
	r.in.buffer = NULL;
	buf_size = 0;
	r.in.buf_size = &buf_size;
	r.out.buf_size = &buf_size;

	printf("Testing EnumPorts\n");

	status = dcerpc_spoolss_EnumPorts(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPorts failed -- %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, buf_size);
		union spoolss_PortInfo *info;
		int j;

		data_blob_clear(&blob);
		r.in.buffer = &blob;

		status = dcerpc_spoolss_EnumPorts(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPorts failed -- %s\n", nt_errstr(status));
			return False;
		}

		if (!r.out.buffer) {
			printf("No ports returned");
			return False;
		}

		status = pull_spoolss_PortInfoArray(r.out.buffer, mem_ctx,
						    r.in.level, r.out.count,
						    &info);
		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPortArray parse failed - %s\n",
			       nt_errstr(status));
			return False;
		}

		for (j=0;j<r.out.count;j++) {
			printf("Port %d\n", j);
			NDR_PRINT_UNION_DEBUG(spoolss_PortInfo, r.in.level,
					      &info[j]);
		}
	}

	return True;
}

static BOOL test_GetJob(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		  struct policy_handle *handle, uint32_t job_id)
{
	NTSTATUS status;
	struct spoolss_GetJob r;
	uint32_t buf_size;

	r.in.handle = handle;
	r.in.job_id = job_id;
	r.in.level = 1;
	r.in.buffer = NULL;
	buf_size = 0;
	r.in.buf_size = r.out.buf_size = &buf_size;

	printf("Testing GetJob\n");

	status = dcerpc_spoolss_GetJob(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetJob failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, buf_size);

		data_blob_clear(&blob);
		r.in.buffer = &blob;

		status = dcerpc_spoolss_GetJob(p, mem_ctx, &r);

		if (!r.out.info) {
			printf("No job info returned");
			return False;
		}
	}

	return True;
}

static BOOL test_SetJob(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		 struct policy_handle *handle, uint32_t job_id, uint32_t command)
{
	NTSTATUS status;
	struct spoolss_SetJob r;

	r.in.handle = handle;
	r.in.job_id = job_id;
	r.in.level = 0;
	r.in.command = command;

	printf("Testing SetJob\n");

	status = dcerpc_spoolss_SetJob(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("SetJob failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_EnumJobs(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		   struct policy_handle *handle)
{
	NTSTATUS status;
	struct spoolss_EnumJobs r;
	uint32_t buf_size;

	r.in.handle = handle;
	r.in.firstjob = 0;
	r.in.numjobs = 0xffffffff;
	r.in.level = 1;
	r.in.buffer = NULL;
	buf_size = 0;
	r.in.buf_size = &buf_size;
	r.out.buf_size = &buf_size;

	printf("Testing EnumJobs\n");

	status = dcerpc_spoolss_EnumJobs(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumJobs failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, buf_size);
		union spoolss_JobInfo *info;
		int j;

		data_blob_clear(&blob);
		r.in.buffer = &blob;

		status = dcerpc_spoolss_EnumJobs(p, mem_ctx, &r);

		if (!r.out.buffer) {
			printf("No jobs returned");
			return True;
		}

		status = pull_spoolss_JobInfoArray(
			r.out.buffer, mem_ctx, r.in.level, r.out.count,
			&info);

		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumJobsArray parse failed - %s\n",
			       nt_errstr(status));
			return False;
		}

		for (j = 0; j < r.out.count; j++) {
			printf("Job %d\n", j);
			NDR_PRINT_UNION_DEBUG(
				spoolss_JobInfo, r.in.level, &info[j]);
		}

		for (j = 0; j < r.out.count; j++) {
			test_GetJob(p, mem_ctx, handle, info[j].info1.job_id);
			test_SetJob(
				p, mem_ctx, handle, info[j].info1.job_id, 1);
		}

	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("EnumJobs failed - %s\n", win_errstr(r.out.result));
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
	uint32_t buf_size;

	r.in.handle = handle;
	r.in.value_name = value_name;
	buf_size = 0;
	r.in.buf_size = r.out.buf_size = &buf_size;

	printf("Testing GetPrinterData\n");

	status = dcerpc_spoolss_GetPrinterData(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetPrinterData failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {

		status = dcerpc_spoolss_GetPrinterData(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
			printf("GetPrinterData failed - %s/%s\n", 
			       nt_errstr(status), win_errstr(r.out.result));
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
	uint32_t buf_size;

	r.in.handle = handle;
	r.in.key_name = key_name;
	r.in.value_name = value_name;
	buf_size = 0;
	r.in.buf_size = r.out.buf_size = &buf_size;

	printf("Testing GetPrinterDataEx\n");

	status = dcerpc_spoolss_GetPrinterDataEx(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetPrinterDataEx failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {

		status = dcerpc_spoolss_GetPrinterDataEx(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
			printf("GetPrinterDataEx failed - %s/%s\n", 
			       nt_errstr(status), win_errstr(r.out.result));
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
	r.in.type = 0;
	r.in.buffer = data_blob_talloc(mem_ctx, "dog", 4);
	r.in.real_len = 4;

	printf("Testing SetPrinterData\n");

	status = dcerpc_spoolss_SetPrinterData(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("SetPrinterData failed - %s\n", nt_errstr(status));
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
	struct dcerpc_pipe *p2;
	BOOL ret = True;

	/* only makes sense on SMB */
	if (p->transport.transport != NCACN_NP) {
		return True;
	}

	printf("testing close on secondary pipe\n");

	status = dcerpc_secondary_connection(p, &p2, 
					     DCERPC_SPOOLSS_NAME, 
					     DCERPC_SPOOLSS_UUID, 
					     DCERPC_SPOOLSS_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create secondary connection\n");
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

	dcerpc_pipe_close(p2);

	return ret;
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
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;	
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

	if (name && name[0])
		r.in.printername = talloc_asprintf(mem_ctx, "\\\\%s\\%s", 
						   dcerpc_server_name(p), name);
	else
		r.in.printername = talloc_asprintf(mem_ctx, "\\\\%s", 
						   dcerpc_server_name(p));

	r.in.datatype = NULL;
	r.in.devmode_ctr.size = 0;
	r.in.devmode_ctr.devmode = NULL;
	r.in.access_mask = 0x02000000;
	r.in.level = 1;
	r.out.handle = handle;

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

	if (!test_EnumForms(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_AddForm(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumPrinterData(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumJobs(p, mem_ctx, &handle)) {
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

static BOOL test_EnumPrinters(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct spoolss_EnumPrinters r;
	NTSTATUS status;
	uint16_t levels[] = {1, 2, 4, 5};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		uint32_t buf_size = 0;
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

static BOOL test_GetPrinterDriver2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				   struct policy_handle *handle, 
				   const char *driver_name)
{
	NTSTATUS status;
	struct spoolss_GetPrinterDriver2 r;
	uint32_t buf_size;

	r.in.handle = handle;
	r.in.architecture = "W32X86";
	r.in.level = 1;
	buf_size = 0;
	r.in.buffer = NULL;
	r.in.buf_size = r.out.buf_size = &buf_size;
	r.in.client_major_version = 0;
	r.in.client_minor_version = 0;

	printf("Testing GetPrinterDriver2\n");

	status = dcerpc_spoolss_GetPrinterDriver2(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetPrinterDriver2 failed - %s\n", nt_errstr(status));
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		status = dcerpc_spoolss_GetPrinterDriver2(p, mem_ctx, &r);
	}
		
	if (!NT_STATUS_IS_OK(status) ||
	    !W_ERROR_IS_OK(r.out.result)) {
		printf("GetPrinterDriver2 failed - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		return False;
	}

	return True;
}
	
static BOOL test_EnumPrinterDrivers(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct spoolss_EnumPrinterDrivers r;
	NTSTATUS status;
	uint16_t levels[] = {1, 2, 3};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		uint32_t buf_size;
		char *server;
		union spoolss_DriverInfo *info;
		uint32_t j;

		asprintf(&server, "\\\\%s", dcerpc_server_name(p));
		r.in.server = server;
		r.in.environment = "Windows NT x86";
		r.in.level = levels[i];
		r.in.buffer = NULL;
		buf_size = 0;
		r.in.buf_size = &buf_size;
		r.out.buf_size = &buf_size;

		printf("\nTesting EnumPrinterDrivers level %u\n", r.in.level);

		status = dcerpc_spoolss_EnumPrinterDrivers(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrinterDrivers failed - %s\n", 
			       nt_errstr(status));
			ret = False;
			continue;
		}
		
		if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
			DATA_BLOB blob = data_blob_talloc(
				mem_ctx, NULL, buf_size);

			data_blob_clear(&blob);
			r.in.buffer = &blob;
			status = dcerpc_spoolss_EnumPrinterDrivers(
				p, mem_ctx, &r);
		}
		
		if (!NT_STATUS_IS_OK(status) ||
		    !W_ERROR_IS_OK(r.out.result)) {
			printf("EnumPrinterDrivers failed - %s/%s\n", 
			       nt_errstr(status), win_errstr(r.out.result));
			goto done;
		}

		if (!r.out.buffer) {
			printf("No printer drivers returned");
			goto done;
		}

		status = pull_spoolss_DriverInfoArray(
			r.out.buffer, mem_ctx, r.in.level, r.out.count, &info);

		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumPrinterDriverArray parse failed - %s\n", 
			       nt_errstr(status));
			continue;
		}

		for (j=0;j<r.out.count;j++) {
			printf("Printer driver %d\n", j);
			NDR_PRINT_UNION_DEBUG(
				spoolss_DriverInfo, r.in.level, 
				&info[j]);

			if (r.in.level == 1) {
				struct policy_handle handle;

				if (!call_OpenPrinterEx(
					    p, mem_ctx, "",
					    &handle))
					continue;

				test_GetPrinterDriver2(
					p, mem_ctx, &handle, 
					info[j].info1.driver_name);
			}
		}

	done:
		free(server);
	}
	
	return ret;
}

BOOL torture_rpc_spoolss(void)
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

	if (!test_EnumPorts(p, mem_ctx)) {
		ret = False;
	}

	if (!test_EnumPrinters(p, mem_ctx)) {
		ret = False;
	}

	if (!test_EnumPrinterDrivers(p, mem_ctx)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
