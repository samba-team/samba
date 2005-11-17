/* 
   Unix SMB/CIFS implementation.

   SMB2 getinfo test suite

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

static struct {
	const char *name;
	uint16_t level;
	NTSTATUS fstatus;
	NTSTATUS dstatus;
	union smb2_fileinfo finfo;
	union smb2_fileinfo dinfo;
} levels[] = {
#define LEVEL(x) #x, x
	{ LEVEL(SMB2_GETINFO_FS_VOLUME_INFO) },
	{ LEVEL(SMB2_GETINFO_FS_SIZE_INFO) },
	{ LEVEL(SMB2_GETINFO_FS_DEVICE_INFO) },
	{ LEVEL(SMB2_GETINFO_FS_ATTRIBUTE_INFO) },
	{ LEVEL(SMB2_GETINFO_FS_QUOTA_INFO) },
	{ LEVEL(SMB2_GETINFO_FS_FULL_SIZE_INFO) },
	{ LEVEL(SMB2_GETINFO_FS_OBJECTID_INFO) },
	{ LEVEL(SMB2_GETINFO_SECURITY) },
	{ LEVEL(SMB2_GETINFO_FILE_BASIC_INFO) },
	{ LEVEL(SMB2_GETINFO_FILE_SIZE_INFO) },
	{ LEVEL(SMB2_GETINFO_FILE_ID) },
	{ LEVEL(SMB2_GETINFO_FILE_EA_SIZE) },
	{ LEVEL(SMB2_GETINFO_FILE_ACCESS_INFO) },
	{ LEVEL(SMB2_GETINFO_FILE_0E) },
	{ LEVEL(SMB2_GETINFO_FILE_ALL_EAS) },
	{ LEVEL(SMB2_GETINFO_FILE_10) },
	{ LEVEL(SMB2_GETINFO_FILE_11) },
	{ LEVEL(SMB2_GETINFO_FILE_ALL_INFO) },
	{ LEVEL(SMB2_GETINFO_FILE_SHORT_INFO) },
	{ LEVEL(SMB2_GETINFO_FILE_STREAM_INFO) },
	{ LEVEL(SMB2_GETINFO_FILE_EOF_INFO) },
	{ LEVEL(SMB2_GETINFO_FILE_STANDARD_INFO) },
	{ LEVEL(SMB2_GETINFO_FILE_ATTRIB_INFO) }
};

#define FNAME "testsmb2_file.dat"
#define DNAME "testsmb2_dir"

/* basic testing of all SMB2 getinfo levels
*/
BOOL torture_smb2_getinfo(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_handle hfile, hdir;
	struct smb2_tree *tree;
	NTSTATUS status;
	int i;

	if (!torture_smb2_connection(mem_ctx, &tree)) {
		goto failed;
	}

	torture_setup_complex_file(FNAME);
	torture_setup_complex_file(FNAME ":streamtwo");
	torture_setup_complex_dir(DNAME);
	torture_setup_complex_file(DNAME ":streamtwo");

	status = torture_smb2_testfile(tree, FNAME, &hfile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Unable to create test file '%s' - %s\n", FNAME, nt_errstr(status));
		goto failed;
	}

	status = torture_smb2_testdir(tree, DNAME, &hdir);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Unable to create test directory '%s' - %s\n", DNAME, nt_errstr(status));
		goto failed;
	}

	torture_smb2_all_info(tree, hfile);
	torture_smb2_all_info(tree, hdir);

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		levels[i].fstatus = smb2_getinfo_level(tree, mem_ctx, hfile, 
						       levels[i].level, &levels[i].finfo);
		if (!NT_STATUS_IS_OK(levels[i].fstatus)) {
			printf("%s failed on file - %s\n", levels[i].name, nt_errstr(levels[i].fstatus));
		}
		levels[i].dstatus = smb2_getinfo_level(tree, mem_ctx, hdir, 
						       levels[i].level, &levels[i].dinfo);
		if (!NT_STATUS_IS_OK(levels[i].dstatus)) {
			printf("%s failed on dir - %s\n", levels[i].name, nt_errstr(levels[i].dstatus));
		}
	}

	return True;

failed:
	talloc_free(mem_ctx);
	return False;
}
