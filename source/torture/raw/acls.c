/* 
   Unix SMB/CIFS implementation.

   test security descriptor operations

   Copyright (C) Andrew Tridgell 2004
   
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
#include "libcli/raw/libcliraw.h"
#include "librpc/gen_ndr/ndr_security.h"

#define BASEDIR "\\testsd"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


static BOOL test_sd(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\sd.txt";
	BOOL ret = True;
	int fnum;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_ace ace;
	struct security_descriptor *sd;
	struct dom_sid *test_sid;

	printf("TESTING SETFILEINFO EA_SET\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHT_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;
	
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = 
		OWNER_SECURITY_INFORMATION | 
		GROUP_SECURITY_INFORMATION | 
		DACL_SECURITY_INFORMATION;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd = q.query_secdesc.out.sd;

	printf("add a new ACE to the DACL\n");

	test_sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1234-5432");

	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;
	ace.access_mask = STD_RIGHT_ALL_ACCESS;
	ace.trustee = *test_sid;

	status = security_descriptor_dacl_add(sd, &ace);
	CHECK_STATUS(status, NT_STATUS_OK);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = q.query_secdesc.in.secinfo_flags;
	set.set_secdesc.in.sd = sd;

	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (!security_descriptor_equal(q.query_secdesc.out.sd, sd)) {
		printf("security descriptors don't match!\n");
		printf("got:\n");
		NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
		printf("expected:\n");
		NDR_PRINT_DEBUG(security_descriptor, sd);
	}

	printf("remove it again\n");

	status = security_descriptor_dacl_del(sd, test_sid);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (!security_descriptor_equal(q.query_secdesc.out.sd, sd)) {
		printf("security descriptors don't match!\n");
		printf("got:\n");
		NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
		printf("expected:\n");
		NDR_PRINT_DEBUG(security_descriptor, sd);
	}

done:
	smbcli_close(cli->tree, fnum);
	return ret;
}


/* 
   basic testing of security descriptor calls
*/
BOOL torture_raw_acls(void)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_acls");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	ret &= test_sd(cli, mem_ctx);

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
