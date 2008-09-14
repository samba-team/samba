/* 
   Unix SMB/CIFS implementation.

   SMB2 find test suite

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

static struct {
	const char *name;
	uint16_t level;
	NTSTATUS status;
	union smb_search_data data;
} levels[] = {
#define LEVEL(x) #x, x
 { LEVEL(SMB2_FIND_ID_BOTH_DIRECTORY_INFO) },
 { LEVEL(SMB2_FIND_DIRECTORY_INFO) },
 { LEVEL(SMB2_FIND_FULL_DIRECTORY_INFO) },
 { LEVEL(SMB2_FIND_NAME_INFO) },
 { LEVEL(SMB2_FIND_BOTH_DIRECTORY_INFO) },
 { LEVEL(SMB2_FIND_ID_FULL_DIRECTORY_INFO) },
};

#define FNAME "smb2-find.dat"

#define CHECK_VALUE(call_name, stype, field) do { \
	union smb_search_data *d = find_level("SMB2_FIND_" #call_name); \
	if (io.all_info2.out.field != d->stype.field) { \
		printf("(%s) %s/%s should be 0x%llx - 0x%llx\n", __location__, \
		       #call_name, #field, \
		       (long long)io.all_info2.out.field, (long long)d->stype.field); \
		ret = false; \
	}} while (0)

#define CHECK_CONST_STRING(call_name, stype, field, str) do { \
	union smb_search_data *d = find_level("SMB2_FIND_" #call_name); \
	if (strcmp(str, d->stype.field.s) != 0) { \
		printf("(%s) %s/%s should be '%s' - '%s'\n", __location__, \
		       #call_name, #field, \
		       str, d->stype.field.s); \
		ret = false; \
	}} while (0)

static union smb_search_data *find_level(const char *name)
{
	int i;
	for (i=0;i<ARRAY_SIZE(levels);i++) {
		if (strcmp(name, levels[i].name) == 0) {
			return &levels[i].data;
		}
	}
	return NULL;
}

/*
  test find levels
*/
static bool torture_smb2_find_levels(struct smb2_tree *tree)
{
	struct smb2_handle handle;
	NTSTATUS status;
	int i;
	struct smb2_find f;
	bool ret = true;
	union smb_fileinfo io;
	const char *alt_name;

	status = smb2_create_complex_file(tree, FNAME, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	io.generic.level = RAW_FILEINFO_ALT_NAME_INFORMATION;
	io.generic.in.file.handle = handle;
	status = smb2_getinfo_file(tree, tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	alt_name = talloc_strdup(tree, io.alt_name_info.out.fname.s);	

	io.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	io.generic.in.file.handle = handle;
	status = smb2_getinfo_file(tree, tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	status = smb2_util_roothandle(tree, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	ZERO_STRUCT(f);
	f.in.file.handle	= handle;
	f.in.pattern		= FNAME;
	f.in.continue_flags	= SMB2_CONTINUE_FLAG_RESTART;
	f.in.max_response_size	= 0x10000;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		union smb_search_data *d;
		uint_t count;

		f.in.level = levels[i].level - 0x100;

		levels[i].status = smb2_find_level(tree, tree, &f, &count, &d);
		if (!NT_STATUS_IS_OK(levels[i].status)) {
			printf("%s failed - %s\n", levels[i].name, 
			       nt_errstr(levels[i].status));
		}

		if (count != 1) {
			printf("Expected count 1 - got %d in %s\n", count, levels[i].name);
			ret = false;
		}

		levels[i].data = d[0];
	}

	CHECK_VALUE(DIRECTORY_INFO, directory_info, create_time);
	CHECK_VALUE(DIRECTORY_INFO, directory_info, access_time);
	CHECK_VALUE(DIRECTORY_INFO, directory_info, write_time);
	CHECK_VALUE(DIRECTORY_INFO, directory_info, change_time);
	CHECK_VALUE(DIRECTORY_INFO, directory_info, size);
	CHECK_VALUE(DIRECTORY_INFO, directory_info, alloc_size);
	CHECK_VALUE(DIRECTORY_INFO, directory_info, attrib);
	CHECK_CONST_STRING(DIRECTORY_INFO, directory_info, name, FNAME);

	CHECK_VALUE(FULL_DIRECTORY_INFO, full_directory_info, create_time);
	CHECK_VALUE(FULL_DIRECTORY_INFO, full_directory_info, access_time);
	CHECK_VALUE(FULL_DIRECTORY_INFO, full_directory_info, write_time);
	CHECK_VALUE(FULL_DIRECTORY_INFO, full_directory_info, change_time);
	CHECK_VALUE(FULL_DIRECTORY_INFO, full_directory_info, size);
	CHECK_VALUE(FULL_DIRECTORY_INFO, full_directory_info, alloc_size);
	CHECK_VALUE(FULL_DIRECTORY_INFO, full_directory_info, attrib);
	CHECK_VALUE(FULL_DIRECTORY_INFO, full_directory_info, ea_size);
	CHECK_CONST_STRING(FULL_DIRECTORY_INFO, full_directory_info, name, FNAME);

	CHECK_VALUE(BOTH_DIRECTORY_INFO, both_directory_info, create_time);
	CHECK_VALUE(BOTH_DIRECTORY_INFO, both_directory_info, access_time);
	CHECK_VALUE(BOTH_DIRECTORY_INFO, both_directory_info, write_time);
	CHECK_VALUE(BOTH_DIRECTORY_INFO, both_directory_info, change_time);
	CHECK_VALUE(BOTH_DIRECTORY_INFO, both_directory_info, size);
	CHECK_VALUE(BOTH_DIRECTORY_INFO, both_directory_info, alloc_size);
	CHECK_VALUE(BOTH_DIRECTORY_INFO, both_directory_info, attrib);
	CHECK_VALUE(BOTH_DIRECTORY_INFO, both_directory_info, ea_size);
	CHECK_CONST_STRING(BOTH_DIRECTORY_INFO, both_directory_info, short_name, alt_name);
	CHECK_CONST_STRING(BOTH_DIRECTORY_INFO, both_directory_info, name, FNAME);

	CHECK_VALUE(ID_FULL_DIRECTORY_INFO, id_full_directory_info, create_time);
	CHECK_VALUE(ID_FULL_DIRECTORY_INFO, id_full_directory_info, access_time);
	CHECK_VALUE(ID_FULL_DIRECTORY_INFO, id_full_directory_info, write_time);
	CHECK_VALUE(ID_FULL_DIRECTORY_INFO, id_full_directory_info, change_time);
	CHECK_VALUE(ID_FULL_DIRECTORY_INFO, id_full_directory_info, size);
	CHECK_VALUE(ID_FULL_DIRECTORY_INFO, id_full_directory_info, alloc_size);
	CHECK_VALUE(ID_FULL_DIRECTORY_INFO, id_full_directory_info, attrib);
	CHECK_VALUE(ID_FULL_DIRECTORY_INFO, id_full_directory_info, ea_size);
	CHECK_VALUE(ID_FULL_DIRECTORY_INFO, id_full_directory_info, file_id);
	CHECK_CONST_STRING(ID_FULL_DIRECTORY_INFO, id_full_directory_info, name, FNAME);

	CHECK_VALUE(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, create_time);
	CHECK_VALUE(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, access_time);
	CHECK_VALUE(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, write_time);
	CHECK_VALUE(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, change_time);
	CHECK_VALUE(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, size);
	CHECK_VALUE(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, alloc_size);
	CHECK_VALUE(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, attrib);
	CHECK_VALUE(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, ea_size);
	CHECK_VALUE(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, file_id);
	CHECK_CONST_STRING(ID_BOTH_DIRECTORY_INFO, id_both_directory_info, name, FNAME);


	return ret;
}


/* basic testing of all SMB2 find levels
*/
bool torture_smb2_find(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	bool ret = true;
	NTSTATUS status;

	if (!torture_smb2_connection(torture, &tree)) {
		return false;
	}

	status = torture_setup_complex_file(tree, FNAME);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	torture_setup_complex_file(tree, FNAME ":streamtwo");

	ret &= torture_smb2_find_levels(tree);

	talloc_free(mem_ctx);

	return ret;
}
