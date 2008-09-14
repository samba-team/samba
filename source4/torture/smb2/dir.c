/* 
   Unix SMB/CIFS implementation.

   SMB2 dir list test suite

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

#include "torture/torture.h"
#include "torture/smb2/proto.h"

/*
  test find continue
*/
static bool torture_smb2_find_dir(struct smb2_tree *tree)
{
	struct smb2_handle handle;
	NTSTATUS status;
	int i;
	struct smb2_find f;
	bool ret = true;
	union smb_search_data *d;
	uint_t count;

	status = smb2_util_roothandle(tree, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	ZERO_STRUCT(f);
	f.in.file.handle	= handle;
	f.in.pattern		= "*";
	f.in.continue_flags	= SMB2_CONTINUE_FLAG_SINGLE;
	f.in.max_response_size	= 0x100;
	f.in.level              = SMB2_FIND_BOTH_DIRECTORY_INFO;

	do {
		status = smb2_find_level(tree, tree, &f, &count, &d);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SMB2_FIND_ID_BOTH_DIRECTORY_INFO failed - %s\n", nt_errstr(status));
			break;
		}

		printf("Got %d files\n", count);
		for (i=0;i<count;i++) {
			printf("\t'%s'\n", 
			       d[i].both_directory_info.name.s);
		}
		f.in.continue_flags = 0;
		f.in.max_response_size	= 4096;
	} while (count != 0);


	return ret;
}


/* 
   basic testing of directory listing with continue
*/
bool torture_smb2_dir(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	bool ret = true;

	if (!torture_smb2_connection(torture, &tree)) {
		return false;
	}

	ret &= torture_smb2_find_dir(tree);

	talloc_free(mem_ctx);

	return ret;
}
