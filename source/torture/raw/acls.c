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
	int fnum = -1;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_ace ace;
	struct security_descriptor *sd;
	struct dom_sid *test_sid;

	printf("TESTING SETFILEINFO EA_SET\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
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
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd = q.query_secdesc.out.sd;

	printf("add a new ACE to the DACL\n");

	test_sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1234-5432");

	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;
	ace.access_mask = SEC_STD_ALL;
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
  test using NTTRANS CREATE to create a file with an initial ACL set
*/
static BOOL test_nttrans_create(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\acl2.txt";
	BOOL ret = True;
	int fnum = -1;
	union smb_fileinfo q;
	struct security_ace ace;
	struct security_descriptor *sd;
	struct dom_sid *test_sid;

	printf("TESTING NTTRANS CREATE WITH SEC_DESC\n");

	io.generic.level = RAW_OPEN_NTTRANS_CREATE;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
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
	io.ntcreatex.in.sec_desc = NULL;
	io.ntcreatex.in.ea_list = NULL;

	printf("creating normal file\n");

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;

	printf("querying ACL\n");

	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = 
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd = q.query_secdesc.out.sd;

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);

	printf("adding a new ACE\n");
	test_sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1234-54321");

	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;
	ace.access_mask = SEC_STD_ALL;
	ace.trustee = *test_sid;

	status = security_descriptor_dacl_add(sd, &ace);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	printf("creating a file with an initial ACL\n");

	io.ntcreatex.in.sec_desc = sd;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;
	
	q.query_secdesc.in.fnum = fnum;
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

#define CHECK_ACCESS_FLAGS(_fnum, flags) do { \
	union smb_fileinfo _q; \
	_q.access_information.level = RAW_FILEINFO_ACCESS_INFORMATION; \
	_q.access_information.in.fnum = (_fnum); \
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &_q); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	if (_q.access_information.out.access_flags != (flags)) { \
		printf("(%s) Incorrect access_flags 0x%08x - should be 0x%08x\n", \
		       __location__, _q.access_information.out.access_flags, (flags)); \
		ret = False; \
		goto done; \
	} \
} while (0)


/*
  test the behaviour of the well known SID_CREATOR_OWNER sid, and some generic
  mapping bits
*/
static BOOL test_creator_sid(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\creator.txt";
	BOOL ret = True;
	int fnum = -1;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig, *sd2;
	const char *owner_sid;

	printf("TESTING SID_CREATOR_OWNER\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;

	printf("get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(mem_ctx, sd_orig->owner_sid);

	printf("set a sec desc allowing no write by CREATOR_OWNER\n");
	sd = security_descriptor_create(mem_ctx,
					NULL, NULL,
					SID_CREATOR_OWNER,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.file.fnum = fnum;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("try open for write\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	printf("try open for read\n");
	io.ntcreatex.in.access_mask = SEC_FILE_READ_DATA;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	printf("try open for generic write\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_WRITE;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	printf("try open for generic read\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_READ;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	printf("set a sec desc allowing no write by owner\n");
	sd = security_descriptor_create(mem_ctx,
					owner_sid, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					NULL);

	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("try open for write\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	printf("try open for read\n");
	io.ntcreatex.in.access_mask = SEC_FILE_READ_DATA;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.fnum, 
			   SEC_FILE_READ_DATA|
			   SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.fnum);

	printf("try open for generic write\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_WRITE;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	printf("try open for generic read\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_READ;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.fnum, 
			   SEC_RIGHTS_FILE_READ);
	smbcli_close(cli->tree, io.ntcreatex.out.fnum);

	printf("set a sec desc allowing generic read by owner\n");
	sd = security_descriptor_create(mem_ctx,
					NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_GENERIC_READ | SEC_STD_ALL,
					NULL);

	set.set_secdesc.in.sd = sd;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("check that generic read has been mapped correctly\n");
	sd2 = security_descriptor_create(mem_ctx,
					 owner_sid, NULL,
					 owner_sid,
					 SEC_ACE_TYPE_ACCESS_ALLOWED,
					 SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					 NULL);

	status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	if (!security_descriptor_equal(q.query_secdesc.out.sd, sd2)) {
		printf("security descriptors don't match!\n");
		printf("got:\n");
		NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
		printf("expected:\n");
		NDR_PRINT_DEBUG(security_descriptor, sd2);
	}
	

	printf("try open for write\n");
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	printf("try open for read\n");
	io.ntcreatex.in.access_mask = SEC_FILE_READ_DATA;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.fnum, 
			   SEC_FILE_READ_DATA | 
			   SEC_FILE_READ_ATTRIBUTE);
	smbcli_close(cli->tree, io.ntcreatex.out.fnum);

	printf("try open for generic write\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_WRITE;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	printf("try open for generic read\n");
	io.ntcreatex.in.access_mask = SEC_GENERIC_READ;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.ntcreatex.out.fnum, SEC_RIGHTS_FILE_READ);
	smbcli_close(cli->tree, io.ntcreatex.out.fnum);


	printf("put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);


done:
	smbcli_close(cli->tree, fnum);
	return ret;
}


/*
  test the mapping of the SEC_GENERIC_xx bits to SEC_STD_xx and
  SEC_FILE_xx bits
*/
static BOOL test_generic_bits(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\generic.txt";
	BOOL ret = True;
	int fnum = -1, i;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig, *sd2;
	const char *owner_sid;
	const struct {
		uint32_t gen_bits;
		uint32_t specific_bits;
	} file_mappings[] = {
		{ 0,                   0 },
		{ SEC_GENERIC_READ,    SEC_RIGHTS_FILE_READ },
		{ SEC_GENERIC_WRITE,   SEC_RIGHTS_FILE_WRITE },
		{ SEC_GENERIC_EXECUTE, SEC_RIGHTS_FILE_EXECUTE },
		{ SEC_GENERIC_ALL,     SEC_RIGHTS_FILE_ALL }
	};
	const struct {
		uint32_t gen_bits;
		uint32_t specific_bits;
	} dir_mappings[] = {
		{ 0,                   0 },
		{ SEC_GENERIC_READ,    SEC_RIGHTS_DIR_READ },
		{ SEC_GENERIC_WRITE,   SEC_RIGHTS_DIR_WRITE },
		{ SEC_GENERIC_EXECUTE, SEC_RIGHTS_DIR_EXECUTE },
		{ SEC_GENERIC_ALL,     SEC_RIGHTS_DIR_ALL }
	};

	printf("TESTING FILE GENERIC BITS\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;

	printf("get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(mem_ctx, sd_orig->owner_sid);


	for (i=0;i<ARRAY_SIZE(file_mappings);i++) {

		printf("testing generic bits 0x%08x\n", 
		       file_mappings[i].gen_bits);
		sd = security_descriptor_create(mem_ctx,
						NULL, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						file_mappings[i].gen_bits,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd;

		status = smb_raw_setfileinfo(cli->tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_create(mem_ctx,
						 owner_sid, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 file_mappings[i].specific_bits,
						 NULL);

		status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		if (!security_descriptor_equal(q.query_secdesc.out.sd, sd2)) {
			printf("security descriptors don't match!\n");
			printf("got:\n");
			NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
			printf("expected:\n");
			NDR_PRINT_DEBUG(security_descriptor, sd2);
		}

		io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb_raw_open(cli->tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.ntcreatex.out.fnum, 
				   SEC_STD_WRITE_DAC | 
				   SEC_STD_READ_CONTROL | 
				   SEC_STD_DELETE | 
				   SEC_FILE_READ_ATTRIBUTE |
				   file_mappings[i].specific_bits);
		smbcli_close(cli->tree, io.ntcreatex.out.fnum);

	}

	printf("put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);


	printf("TESTING DIR GENERIC BITS\n");

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_DIRECTORY;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;

	printf("get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.fnum = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(mem_ctx, sd_orig->owner_sid);


	for (i=0;i<ARRAY_SIZE(file_mappings);i++) {

		printf("testing generic bits 0x%08x\n", 
		       file_mappings[i].gen_bits);
		sd = security_descriptor_create(mem_ctx,
						NULL, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						dir_mappings[i].gen_bits,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.file.fnum = fnum;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd;

		status = smb_raw_setfileinfo(cli->tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_create(mem_ctx,
						 owner_sid, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 dir_mappings[i].specific_bits,
						 NULL);

		status = smb_raw_fileinfo(cli->tree, mem_ctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		if (!security_descriptor_equal(q.query_secdesc.out.sd, sd2)) {
			printf("security descriptors don't match!\n");
			printf("got:\n");
			NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
			printf("expected:\n");
			NDR_PRINT_DEBUG(security_descriptor, sd2);
		}

		io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb_raw_open(cli->tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.ntcreatex.out.fnum, 
				   SEC_STD_WRITE_DAC | 
				   SEC_STD_READ_CONTROL | 
				   SEC_STD_DELETE | 
				   SEC_FILE_READ_ATTRIBUTE |
				   dir_mappings[i].specific_bits);
		smbcli_close(cli->tree, io.ntcreatex.out.fnum);

	}
	printf("put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb_raw_setfileinfo(cli->tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);

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
	ret &= test_nttrans_create(cli, mem_ctx);
	ret &= test_creator_sid(cli, mem_ctx);
	ret &= test_generic_bits(cli, mem_ctx);

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
