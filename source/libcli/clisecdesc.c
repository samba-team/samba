/* 
   Unix SMB/CIFS implementation.
   client security descriptor functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   
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

/****************************************************************************
  query the security descriptor for a open file
 ****************************************************************************/
SEC_DESC *smbcli_query_secdesc(struct smbcli_tree *tree, int fnum, 
			    TALLOC_CTX *mem_ctx)
{
	struct smb_nttrans parms;
	char param[8];
	DATA_BLOB param_blob;
	prs_struct pd;
	SEC_DESC *psd = NULL;
	NTSTATUS status;

	param_blob.length = 8;
	param_blob.data = &param[0];

	SIVAL(param, 0, fnum);
	SSVAL(param, 4, 0x7);

	parms.in.max_param = 1024;
	parms.in.max_data = 1024;
	parms.in.max_setup = 0;
	parms.in.setup_count = 18;
	parms.in.function = NT_TRANSACT_QUERY_SECURITY_DESC;
	parms.in.params = param_blob;
	parms.in.data = data_blob(NULL, 0);
	
	status = smb_raw_nttrans(tree, mem_ctx, &parms);
	
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("Failed to send NT_TRANSACT_QUERY_SECURITY_DESC\n"));
		goto cleanup;
	}

	prs_init(&pd, parms.out.data.length, mem_ctx, UNMARSHALL);
	prs_copy_data_in(&pd, parms.out.data.data, parms.out.data.length);
	prs_set_offset(&pd,0);

	if (!sec_io_desc("sd data", &psd, &pd, 1)) {
		DEBUG(1,("Failed to parse secdesc\n"));
		goto cleanup;
	}

 cleanup:
	prs_mem_free(&pd);
	return psd;
}

/****************************************************************************
  set the security descriptor for a open file
 ****************************************************************************/
BOOL smbcli_set_secdesc(struct smbcli_tree *tree, int fnum, SEC_DESC *sd)
{
	struct smb_nttrans parms;
	char param[8];
	DATA_BLOB param_blob;
	prs_struct pd;
	BOOL ret = False;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;

	mem_ctx = talloc_init("smbcli_set_secdesc");

	prs_init(&pd, 0, mem_ctx, MARSHALL);
	prs_give_memory(&pd, NULL, 0, True);

	if (!sec_io_desc("sd data", &sd, &pd, 1)) {
		DEBUG(1,("Failed to marshall secdesc\n"));
		goto cleanup;
	}
	
	param_blob.length = 8;
	param_blob.data = &param[0];

	SIVAL(param, 0, fnum);
	SSVAL(param, 4, 0x7);

	parms.in.max_param = 1000;
	parms.in.max_data = 1000;
	parms.in.max_setup = 0;
	parms.in.setup_count = 18;
	parms.in.function = NT_TRANSACT_SET_SECURITY_DESC;
	parms.in.params = param_blob;
	parms.in.data = data_blob(NULL, 0);
	
	status = smb_raw_nttrans(tree, mem_ctx, &parms);
	
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(1,("Failed to send NT_TRANSACT_SET_SECURITY_DESC\n"));
		goto cleanup;
	}
	ret = True;

 cleanup:
	prs_mem_free(&pd);
	talloc_destroy(mem_ctx);
	return ret;
}
