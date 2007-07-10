/* 
   Unix SMB/CIFS implementation.

   SMB torture tester - charset test routines

   Copyright (C) Andrew Tridgell 2001
   
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
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "torture/util.h"

#define BASEDIR "\\chartest\\"

/* 
   open a file using a set of unicode code points for the name

   the prefix BASEDIR is added before the name
*/
static NTSTATUS unicode_open(struct torture_context *tctx,
							 struct smbcli_tree *tree,
			     TALLOC_CTX *mem_ctx,
			     uint32_t open_disposition, 
			     const uint32_t *u_name, 
			     size_t u_name_len)
{
	union smb_open io;
	char *fname, *fname2=NULL, *ucs_name;
	int i;
	NTSTATUS status;

	ucs_name = talloc_size(mem_ctx, (1+u_name_len)*2);
	if (!ucs_name) {
		printf("Failed to create UCS2 Name - talloc() failure\n");
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<u_name_len;i++) {
		SSVAL(ucs_name, i*2, u_name[i]);
	}
	SSVAL(ucs_name, i*2, 0);

	i = convert_string_talloc(ucs_name, CH_UTF16, CH_UNIX, ucs_name, (1+u_name_len)*2, (void **)&fname);
	if (i == -1) {
		torture_comment(tctx, "Failed to convert UCS2 Name into unix - convert_string_talloc() failure\n");
		talloc_free(ucs_name);
		return NT_STATUS_NO_MEMORY;
	}

	fname2 = talloc_asprintf(ucs_name, "%s%s", BASEDIR, fname);
	if (!fname2) {
		talloc_free(ucs_name);
		return NT_STATUS_NO_MEMORY;
	}

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname2;
	io.ntcreatex.in.open_disposition = open_disposition;

	status = smb_raw_open(tree, mem_ctx, &io);

	talloc_free(ucs_name);

	return status;
}


/*
  see if the server recognises composed characters
*/
static BOOL test_composed(struct torture_context *tctx, 
						  struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	const uint32_t name1[] = {0x61, 0x308};
	const uint32_t name2[] = {0xe4};
	NTSTATUS status1, status2;

	printf("Testing composite character (a umlaut)\n");
	
	status1 = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name1, 2);
	if (!NT_STATUS_IS_OK(status1)) {
		printf("Failed to create composed name - %s\n",
		       nt_errstr(status1));
		return False;
	}

	status2 = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name2, 1);

	if (!NT_STATUS_IS_OK(status2)) {
		printf("Failed to create accented character - %s\n",
		       nt_errstr(status2));
		return False;
	}

	return True;
}

/*
  see if the server recognises a naked diacritical
*/
static BOOL test_diacritical(struct torture_context *tctx, 
							 struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	const uint32_t name1[] = {0x308};
	const uint32_t name2[] = {0x308, 0x308};
	NTSTATUS status1, status2;

	printf("Testing naked diacritical (umlaut)\n");
	
	status1 = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name1, 1);

	if (!NT_STATUS_IS_OK(status1)) {
		printf("Failed to create naked diacritical - %s\n",
		       nt_errstr(status1));
		return False;
	}

	/* try a double diacritical */
	status2 = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name2, 2);

	if (!NT_STATUS_IS_OK(status2)) {
		printf("Failed to create double naked diacritical - %s\n",
		       nt_errstr(status2));
		return False;
	}

	return True;
}

/*
  see if the server recognises a partial surrogate pair
*/
static BOOL test_surrogate(struct torture_context *tctx, 
						   struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	const uint32_t name1[] = {0xd800};
	const uint32_t name2[] = {0xdc00};
	const uint32_t name3[] = {0xd800, 0xdc00};
	NTSTATUS status;

	printf("Testing partial surrogate\n");

	status = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name1, 1);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create partial surrogate 1 - %s\n",
		       nt_errstr(status));
		return False;
	}

	status = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name2, 1);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create partial surrogate 2 - %s\n",
		       nt_errstr(status));
		return False;
	}

	status = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name3, 2);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create full surrogate - %s\n",
		       nt_errstr(status));
		return False;
	}

	return True;
}

/*
  see if the server recognises wide-a characters
*/
static BOOL test_widea(struct torture_context *tctx, 
					   struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	const uint32_t name1[] = {'a'};
	const uint32_t name2[] = {0xff41};
	const uint32_t name3[] = {0xff21};
	NTSTATUS status;

	printf("Testing wide-a\n");
	
	status = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name1, 1);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create 'a' - %s\n",
		       nt_errstr(status));
		return False;
	}

	status = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name2, 1);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create wide-a - %s\n",
		       nt_errstr(status));
		return False;
	}

	status = unicode_open(tctx, cli->tree, mem_ctx, NTCREATEX_DISP_CREATE, name3, 1);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
		printf("Expected %s creating wide-A - %s\n",
		       nt_errstr(NT_STATUS_OBJECT_NAME_COLLISION),
		       nt_errstr(status));
		return False;
	}

	return True;
}

BOOL torture_charset(struct torture_context *tctx, struct smbcli_state *cli)
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("torture_charset");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	if (!test_composed(tctx, cli, mem_ctx)) {
		ret = False;
	}

	if (!test_diacritical(tctx, cli, mem_ctx)) {
		ret = False;
	}

	if (!test_surrogate(tctx, cli, mem_ctx)) {
		ret = False;
	}

	if (!test_widea(tctx, cli, mem_ctx)) {
		ret = False;
	}

	return ret;
}
