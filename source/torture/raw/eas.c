/* 
   Unix SMB/CIFS implementation.

   test DOS extended attributes

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

#define BASEDIR "\\testeas"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

/*
  check that an EA has the right value 
*/
static BOOL check_ea(struct smbcli_state *cli, TALLOC_CTX *mem_ctx,
		     const char *fname, const char *eaname, const char *value)
{
	union smb_fileinfo info;
	NTSTATUS status;
	BOOL ret = True;
	int i;

	info.all_eas.level = RAW_FILEINFO_ALL_EAS;
	info.all_eas.in.fname = fname;

	status = smb_raw_pathinfo(cli->tree, mem_ctx, &info);
	CHECK_STATUS(status, NT_STATUS_OK);

	for (i=0;i<info.all_eas.out.num_eas;i++) {
		if (StrCaseCmp(eaname, info.all_eas.out.eas[i].name.s) == 0) {
			if (value == NULL) {
				printf("attr '%s' should not be present\n", eaname);
				return False;
			}
			if (strlen(value) == info.all_eas.out.eas[i].value.length &&
			    memcmp(value, 
				   info.all_eas.out.eas[i].value.data,
				   info.all_eas.out.eas[i].value.length) == 0) {
				return True;
			} else {
				printf("attr '%s' has wrong value '%*.*s'\n", 
				       eaname, 
				       info.all_eas.out.eas[i].value.length,
				       info.all_eas.out.eas[i].value.length,
				       info.all_eas.out.eas[i].value.data);
				ret = False;
				goto done;
			}
		}
	}

	if (value != NULL) {
		printf("attr '%s' not found\n", eaname);
		ret = False;
	}

done:
	return ret;
}

static DATA_BLOB data_blob_string_const(const char *str)
{
	DATA_BLOB blob;
	blob.data = discard_const(str);
	blob.length = strlen(str);
	return blob;
}


static BOOL test_eas(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	union smb_setfileinfo setfile;
	union smb_open io;
	const char *fname = BASEDIR "\\ea.txt";
	BOOL ret = True;
	int fnum;

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
	
	ret &= check_ea(cli, mem_ctx, fname, "EAONE", NULL);

	printf("Adding first EA\n");
	setfile.generic.level = RAW_SFILEINFO_EA_SET;
	setfile.generic.file.fnum = fnum;
	setfile.ea_set.in.ea.flags = 0;
	setfile.ea_set.in.ea.name.s = "EAONE";
	setfile.ea_set.in.ea.value = data_blob_string_const("VALUE1");

	status = smb_raw_setfileinfo(cli->tree, &setfile);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret &= check_ea(cli, mem_ctx, fname, "EAONE", "VALUE1");

	setfile.ea_set.in.ea.name.s = "SECONDEA";
	setfile.ea_set.in.ea.value = data_blob_string_const("ValueTwo");

	printf("Adding second EA\n");
	status = smb_raw_setfileinfo(cli->tree, &setfile);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret &= check_ea(cli, mem_ctx, fname, "EAONE", "VALUE1");
	ret &= check_ea(cli, mem_ctx, fname, "SECONDEA", "ValueTwo");

	printf("Modifying 2nd EA\n");
	setfile.ea_set.in.ea.value = data_blob_string_const(" Changed Value");
	status = smb_raw_setfileinfo(cli->tree, &setfile);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret &= check_ea(cli, mem_ctx, fname, "EAONE", "VALUE1");
	ret &= check_ea(cli, mem_ctx, fname, "SECONDEA", " Changed Value");

	printf("Setting a NULL EA\n");
	setfile.ea_set.in.ea.value = data_blob(NULL, 0);
	setfile.ea_set.in.ea.name.s = "NULLEA";
	status = smb_raw_setfileinfo(cli->tree, &setfile);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret &= check_ea(cli, mem_ctx, fname, "EAONE", "VALUE1");
	ret &= check_ea(cli, mem_ctx, fname, "SECONDEA", " Changed Value");
	ret &= check_ea(cli, mem_ctx, fname, "NULLEA", NULL);

	printf("Deleting first EA\n");
	setfile.ea_set.in.ea.flags = 0;
	setfile.ea_set.in.ea.name.s = "EAONE";
	setfile.ea_set.in.ea.value = data_blob(NULL, 0);
	status = smb_raw_setfileinfo(cli->tree, &setfile);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret &= check_ea(cli, mem_ctx, fname, "EAONE", NULL);
	ret &= check_ea(cli, mem_ctx, fname, "SECONDEA", " Changed Value");

	printf("Deleting second EA\n");
	setfile.ea_set.in.ea.flags = 0;
	setfile.ea_set.in.ea.name.s = "SECONDEA";
	setfile.ea_set.in.ea.value = data_blob(NULL, 0);
	status = smb_raw_setfileinfo(cli->tree, &setfile);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret &= check_ea(cli, mem_ctx, fname, "EAONE", NULL);
	ret &= check_ea(cli, mem_ctx, fname, "SECONDEA", NULL);

done:
	smbcli_close(cli->tree, fnum);
	return True;
}

/* 
   basic testing of EA calls
*/
BOOL torture_raw_eas(void)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_eas");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	ret &= test_eas(cli, mem_ctx);

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
