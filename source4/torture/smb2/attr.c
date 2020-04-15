/*
   Unix SMB/CIFS implementation.

   openattr tester

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) David Mulder 2019

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
#include "libcli/security/security_descriptor.h"
#include "torture/smb2/proto.h"

static const uint32_t open_attrs_table[] = {
		FILE_ATTRIBUTE_NORMAL,
		FILE_ATTRIBUTE_ARCHIVE,
		FILE_ATTRIBUTE_READONLY,
		FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_SYSTEM,

		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,

		FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_HIDDEN,FILE_ATTRIBUTE_SYSTEM,
};

struct trunc_open_results {
	unsigned int num;
	uint32_t init_attr;
	uint32_t trunc_attr;
	uint32_t result_attr;
};

static const struct trunc_open_results attr_results[] = {
	{ 0, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE },
	{ 1, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE },
	{ 2, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY },
	{ 16, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE },
	{ 17, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE },
	{ 18, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY },
	{ 51, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 54, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 56, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN },
	{ 68, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 71, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 73, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM },
	{ 99, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN,FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 102, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 104, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN },
	{ 116, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 119,  FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM,  FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 121, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM },
	{ 170, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN },
	{ 173, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM },
	{ 227, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 230, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 232, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN },
	{ 244, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 247, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 249, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM }
};

static NTSTATUS smb2_setatr(struct smb2_tree *tree, const char *name,
			    uint32_t attrib)
{
	NTSTATUS status;
	struct smb2_create create_io = {0};
	union smb_setfileinfo io;

	create_io.in.desired_access = SEC_FILE_READ_DATA |
				      SEC_FILE_WRITE_ATTRIBUTE;
	create_io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create_io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	create_io.in.create_disposition = NTCREATEX_DISP_OPEN;
	create_io.in.fname = name;
	status = smb2_create(tree, tree, &create_io);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ZERO_STRUCT(io);
	io.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION;
	io.basic_info.in.file.handle = create_io.out.file.handle;
	io.basic_info.in.attrib = attrib;
	status = smb2_setinfo_file(tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smb2_util_close(tree, create_io.out.file.handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return status;
}

bool torture_smb2_openattrtest(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	NTSTATUS status;
	const char *fname = "openattr.file";
	uint16_t attr;
	unsigned int i, j, k, l;
	int ret = true;

	for (k = 0, i = 0; i < sizeof(open_attrs_table)/sizeof(uint32_t); i++) {
		struct smb2_create create_io = {0};
		smb2_setatr(tree, fname, FILE_ATTRIBUTE_NORMAL);
		smb2_util_unlink(tree, fname);
		create_io.in.create_flags = 0;
		create_io.in.desired_access = SEC_FILE_WRITE_DATA;
		create_io.in.file_attributes = open_attrs_table[i];
		create_io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
		create_io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
		create_io.in.create_options = 0;
		create_io.in.security_flags = 0;
		create_io.in.fname = fname;
		status = smb2_create(tree, tctx, &create_io);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
			talloc_asprintf(tctx, "open %d (1) of %s failed (%s)",
			i, fname, nt_errstr(status)));

		status = smb2_util_close(tree, create_io.out.file.handle);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
			talloc_asprintf(tctx, "close %d (1) of %s failed (%s)",
			i, fname, nt_errstr(status)));

		for (j = 0; j < ARRAY_SIZE(open_attrs_table); j++) {
			create_io = (struct smb2_create){0};
			create_io.in.create_flags = 0;
			create_io.in.desired_access = SEC_FILE_READ_DATA|
						      SEC_FILE_WRITE_DATA;
			create_io.in.file_attributes = open_attrs_table[j];
			create_io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
			create_io.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
			create_io.in.create_options = 0;
			create_io.in.security_flags = 0;
			create_io.in.fname = fname;
			status = smb2_create(tree, tctx, &create_io);

			if (!NT_STATUS_IS_OK(status)) {
				for (l = 0; l < ARRAY_SIZE(attr_results); l++) {
					torture_assert_goto(tctx,
						attr_results[l].num != k,
						ret, error_exit,
						talloc_asprintf(tctx,
							"[%d] trunc open 0x%x "
							"-> 0x%x of %s failed "
							"- should have "
							"succeeded !(%s)",
							k, open_attrs_table[i],
							open_attrs_table[j],
							fname,
							nt_errstr(status)));
				}
				torture_assert_ntstatus_equal_goto(tctx,
					status, NT_STATUS_ACCESS_DENIED,
					ret, error_exit,
					talloc_asprintf(tctx,
							"[%d] trunc open 0x%x "
							"-> 0x%x failed with "
							"wrong error code %s",
							k, open_attrs_table[i],
							open_attrs_table[j],
							nt_errstr(status)));
				k++;
				continue;
			}

			status = smb2_util_close(tree, create_io.out.file.handle);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
				error_exit, talloc_asprintf(tctx,
					"close %d (2) of %s failed (%s)", j,
					fname, nt_errstr(status)));

			status = smb2_util_getatr(tree, fname, &attr, NULL, NULL);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
				error_exit, talloc_asprintf(tctx,
					"getatr(2) failed (%s)",
					nt_errstr(status)));

			for (l = 0; l < ARRAY_SIZE(attr_results); l++) {
				if (attr_results[l].num == k) {
					if (attr != attr_results[l].result_attr ||
					    open_attrs_table[i] != attr_results[l].init_attr ||
					    open_attrs_table[j] != attr_results[l].trunc_attr) {
						ret = false;
						torture_fail_goto(tctx, error_exit,
							talloc_asprintf(tctx,
							"[%d] getatr check "
							"failed. [0x%x] trunc "
							"[0x%x] got attr 0x%x,"
							" should be 0x%x",
							k, open_attrs_table[i],
							open_attrs_table[j],
							(unsigned int)attr,
							attr_results[l].result_attr));
					}
					break;
				}
			}
			k++;
		}
	}
error_exit:
	smb2_setatr(tree, fname, FILE_ATTRIBUTE_NORMAL);
	smb2_util_unlink(tree, fname);


	return ret;
}

bool torture_smb2_winattrtest(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	const char *fname = "winattr1.file";
	const char *dname = "winattr1.dir";
	uint16_t attr;
	uint16_t j;
	uint32_t aceno;
	bool ret = true;
	union smb_fileinfo query, query_org;
	NTSTATUS status;
	struct security_descriptor *sd1 = NULL, *sd2 = NULL;
	struct smb2_create create_io = {0};
	ZERO_STRUCT(query);
	ZERO_STRUCT(query_org);

	/* Test winattrs for file */
	smb2_util_unlink(tree, fname);

	/* Open a file*/
	create_io.in.create_flags = 0;
	create_io.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA |
				SEC_STD_READ_CONTROL;
	create_io.in.file_attributes = 0;
	create_io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	create_io.in.create_disposition = FILE_SUPERSEDE;
	create_io.in.create_options = 0;
	create_io.in.security_flags = 0;
	create_io.in.fname = fname;
	status = smb2_create(tree, tctx, &create_io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
		talloc_asprintf(tctx, "open(1) of %s failed (%s)\n",
		fname, nt_errstr(status)));

	/* Get security descriptor and store it*/
	query_org.generic.level = RAW_FILEINFO_SEC_DESC;
	query_org.generic.in.file.handle = create_io.out.file.handle;
	query_org.query_secdesc.in.secinfo_flags = SECINFO_OWNER|
						SECINFO_GROUP|
						SECINFO_DACL;
	status = smb2_getinfo_file(tree, tctx, &query_org);
	if(!NT_STATUS_IS_OK(status)){
		NTSTATUS s = smb2_util_close(tree, create_io.out.file.handle);
		torture_assert_ntstatus_ok_goto(tctx, s, ret, error_exit,
				talloc_asprintf(tctx,
					"close(1) of %s failed (%s)\n",
					fname, nt_errstr(s)));
		ret = false;
		torture_fail_goto(tctx, error_exit, talloc_asprintf(tctx,
			"smb2_getinfo_file(1) of %s failed (%s)\n",
			fname, nt_errstr(status)));
	}
	sd1 = query_org.query_secdesc.out.sd;

	status = smb2_util_close(tree, create_io.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
		       talloc_asprintf(tctx, "close(1) of %s failed (%s)\n",
				       fname, nt_errstr(status)));

	/*Set and get attributes*/
	for (j = 0; j < ARRAY_SIZE(open_attrs_table); j++) {
		status = smb2_setatr(tree, fname, open_attrs_table[j]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret,
			error_exit,
			talloc_asprintf(tctx, "setatr(2) failed (%s)",
				nt_errstr(status)));

		status = smb2_util_getatr(tree, fname, &attr, NULL, NULL);
		torture_assert_ntstatus_ok_goto(tctx, status, ret,
			error_exit,
			talloc_asprintf(tctx, "getatr(2) failed (%s)",
			nt_errstr(status)));

		/* Check the result */
		torture_assert_goto(tctx, attr == open_attrs_table[j], ret,
			error_exit, talloc_asprintf(tctx,
				"getatr check failed. \
				Attr applied [0x%x],got attr 0x%x, \
				should be 0x%x ", open_attrs_table[j],
				(uint16_t)attr, open_attrs_table[j]));

		create_io = (struct smb2_create){0};
		create_io.in.create_flags = 0;
		create_io.in.desired_access = SEC_FILE_READ_ATTRIBUTE|
						SEC_STD_READ_CONTROL;
		create_io.in.file_attributes = 0;
		create_io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
		create_io.in.create_disposition = FILE_OPEN_IF;
		create_io.in.create_options = 0;
		create_io.in.security_flags = 0;
		create_io.in.fname = fname;
		status = smb2_create(tree, tctx, &create_io);
		torture_assert_ntstatus_ok_goto(tctx, status, ret,
			error_exit,
			talloc_asprintf(tctx, "open(2) of %s failed (%s)\n",
			fname, nt_errstr(status)));
		/*Get security descriptor */
		query.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
		query.query_secdesc.in.file.handle = create_io.out.file.handle;
		query.query_secdesc.in.secinfo_flags = SECINFO_OWNER|
						SECINFO_GROUP|
						SECINFO_DACL;
		status = smb2_getinfo_file(tree, tctx, &query);
		if(!NT_STATUS_IS_OK(status)){
			NTSTATUS s = smb2_util_close(tree, create_io.out.file.handle);
			torture_assert_ntstatus_ok_goto(tctx, s, ret,
				error_exit,
				talloc_asprintf(tctx,
					"close(2) of %s failed (%s)\n",
					fname, nt_errstr(s)));
			ret = false;
			torture_fail_goto(tctx, error_exit,
				talloc_asprintf(tctx,
				"smb2_getinfo_file(2) of %s failed (%s)\n",
				fname, nt_errstr(status)));
		}
		sd2 = query.query_secdesc.out.sd;

		status = smb2_util_close(tree, create_io.out.file.handle);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
		       talloc_asprintf(tctx, "close(2) of %s failed (%s)\n",
				       fname, nt_errstr(status)));

		/*Compare security descriptors -- Must be same*/
		for (aceno=0;(sd1->dacl&&aceno < sd1->dacl->num_aces);aceno++){
			struct security_ace *ace1 = &sd1->dacl->aces[aceno];
			struct security_ace *ace2 = &sd2->dacl->aces[aceno];

			torture_assert_goto(tctx, security_ace_equal(ace1, ace2),
				ret, error_exit,
				"ACLs changed! Not expected!\n");
		}

		torture_comment(tctx, "[%d] setattr = [0x%x] got attr 0x%x\n",
			j,  open_attrs_table[j], attr );

	}


/* Check for Directory. */

	smb2_deltree(tree, dname);
	smb2_util_rmdir(tree, dname);

	/* Open a directory */
	create_io = (struct smb2_create){0};
	create_io.in.create_flags = 0;
	create_io.in.desired_access = SEC_RIGHTS_DIR_ALL;
	create_io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	create_io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	create_io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create_io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	create_io.in.security_flags = 0;
	create_io.in.fname = dname;
	status = smb2_create(tree, tctx, &create_io);

	torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
			talloc_asprintf(tctx,
			"open (1) of %s failed (%s)",
			dname, nt_errstr(status)));


	/* Get Security Descriptor */
	query_org.generic.level = RAW_FILEINFO_SEC_DESC;
	query_org.generic.in.file.handle = create_io.out.file.handle;
	status = smb2_getinfo_file(tree, tctx, &query_org);
	if(!NT_STATUS_IS_OK(status)){
		NTSTATUS s = smb2_util_close(tree, create_io.out.file.handle);
		torture_assert_ntstatus_ok_goto(tctx, s, ret, error_exit,
				talloc_asprintf(tctx,
					"close(1) of %s failed (%s)\n",
					dname, nt_errstr(s)));
		ret = false;
		torture_fail_goto(tctx, error_exit, talloc_asprintf(tctx,
			"smb2_getinfo_file(1) of %s failed (%s)\n", dname,
			nt_errstr(status)));
	}
	sd1 = query_org.query_secdesc.out.sd;

	status = smb2_util_close(tree, create_io.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
				talloc_asprintf(tctx,
				"close (1) of %s failed (%s)", dname,
				nt_errstr(status)));

	/* Set and get win attributes*/
	for (j = 1; j < ARRAY_SIZE(open_attrs_table); j++) {

		status = smb2_setatr(tree, dname, open_attrs_table[j]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
			talloc_asprintf(tctx, "setatr(2) failed (%s)",
				nt_errstr(status)));

		status = smb2_util_getatr(tree, dname, &attr, NULL, NULL);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
			talloc_asprintf(tctx, "getatr(2) failed (%s)",
				nt_errstr(status)));

		torture_comment(tctx, "[%d] setatt = [0x%x] got attr 0x%x\n",
			j,  open_attrs_table[j], attr );

		/* Check the result */
		torture_assert_goto(tctx,
			attr == (open_attrs_table[j]|FILE_ATTRIBUTE_DIRECTORY),
			ret, error_exit, talloc_asprintf(tctx,
			"getatr check failed. set attr "
			"[0x%x], got attr 0x%x, should be 0x%x\n",
			open_attrs_table[j], (uint16_t)attr,
			(unsigned int)(open_attrs_table[j]|FILE_ATTRIBUTE_DIRECTORY)));

		create_io = (struct smb2_create){0};
		create_io.in.create_flags = 0;
		create_io.in.desired_access = SEC_RIGHTS_DIR_READ;
		create_io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
		create_io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
		create_io.in.create_disposition = NTCREATEX_DISP_OPEN;
		create_io.in.create_options = 0;
		create_io.in.security_flags = 0;
		create_io.in.fname = dname;
		status = smb2_create(tree, tctx, &create_io);

		torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
			talloc_asprintf(tctx,
			"open (2) of %s failed (%s)",
			dname, nt_errstr(status)));
		/* Get security descriptor */
		query.generic.level = RAW_FILEINFO_SEC_DESC;
		query.generic.in.file.handle = create_io.out.file.handle;
		status = smb2_getinfo_file(tree, tctx, &query);
		if(!NT_STATUS_IS_OK(status)){
			NTSTATUS s = smb2_util_close(tree, create_io.out.file.handle);
			torture_assert_ntstatus_ok_goto(tctx, s, ret, error_exit,
					talloc_asprintf(tctx,
					"close (2) of %s failed (%s)", dname,
					nt_errstr(s)));
			ret = false;
			torture_fail_goto(tctx, error_exit,
				talloc_asprintf(tctx,
				"smb2_getinfo_file(2) of %s failed(%s)\n",
				dname, nt_errstr(status)));
		}
		sd2 = query.query_secdesc.out.sd;
		status = smb2_util_close(tree, create_io.out.file.handle);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
				talloc_asprintf(tctx,
				"close (2) of %s failed (%s)", dname,
				nt_errstr(status)));

		/* Security descriptor must be same*/
		for (aceno=0;(sd1->dacl&&aceno < sd1->dacl->num_aces);aceno++){
			struct security_ace *ace1 = &sd1->dacl->aces[aceno];
			struct security_ace *ace2 = &sd2->dacl->aces[aceno];

			torture_assert_goto(tctx, security_ace_equal(ace1, ace2),
				ret, error_exit,
				"ACLs changed! Not expected!\n");
		}

	}

error_exit:
	smb2_setatr(tree, fname, FILE_ATTRIBUTE_NORMAL);
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, dname);
	smb2_util_rmdir(tree, dname);

	return ret;
}

bool torture_smb2_sdreadtest(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	const char *fname = "sdread.file";
	bool ret = true;
	union smb_fileinfo query;
	NTSTATUS status;
	struct security_descriptor *sd = NULL;
	struct smb2_create create_io = {0};
	uint32_t sd_bits[] = { SECINFO_OWNER,
				SECINFO_GROUP,
				SECINFO_DACL };
	size_t i;

	ZERO_STRUCT(query);

	smb2_util_unlink(tree, fname);

	/* Create then close a file*/
	create_io.in.create_flags = 0;
	create_io.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA;
	create_io.in.file_attributes = 0;
	create_io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	create_io.in.create_disposition = FILE_SUPERSEDE;
	create_io.in.create_options = 0;
	create_io.in.security_flags = 0;
	create_io.in.fname = fname;
	status = smb2_create(tree, tctx, &create_io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
		talloc_asprintf(tctx, "open(1) of %s failed (%s)\n",
		fname, nt_errstr(status)));
	status = smb2_util_close(tree, create_io.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, error_exit,
		       talloc_asprintf(tctx, "close(1) of %s failed (%s)\n",
				       fname, nt_errstr(status)));

	/*
	 * Open the file with READ_ATTRIBUTES *only*,
	 * no READ_CONTROL.
	 *
	 * This should deny access for any attempt to
	 * get a security descriptor if we ask for
	 * any of OWNER|GROUP|DACL, but if
	 * we ask for *NO* info but still ask for
	 * the security descriptor, then Windows
	 * returns an ACL but with zero entries
	 * for OWNER|GROUP|DACL.
	 */

	create_io = (struct smb2_create){0};
	create_io.in.create_flags = 0;
	create_io.in.desired_access = SEC_FILE_READ_ATTRIBUTE;
	create_io.in.file_attributes = 0;
	create_io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	create_io.in.create_disposition = FILE_OPEN;
	create_io.in.create_options = 0;
	create_io.in.security_flags = 0;
	create_io.in.fname = fname;
	status = smb2_create(tree, tctx, &create_io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret,
			error_exit,
			talloc_asprintf(tctx, "open(2) of %s failed (%s)\n",
			fname, nt_errstr(status)));

	/* Check asking for SD fails ACCESS_DENIED with actual bits set. */
	for (i = 0; i < ARRAY_SIZE(sd_bits); i++) {
		query.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
		query.query_secdesc.in.file.handle = create_io.out.file.handle;
		query.query_secdesc.in.secinfo_flags = sd_bits[i];

		status = smb2_getinfo_file(tree, tctx, &query);

		/* Must return ACESS_DENIED. */
		if(!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)){
			NTSTATUS s = smb2_util_close(tree,
					create_io.out.file.handle);
			torture_assert_ntstatus_ok_goto(tctx, s, ret,
				error_exit,
				talloc_asprintf(tctx,
					"close(2) of %s failed (%s)\n",
					fname, nt_errstr(s)));
			ret = false;
			torture_fail_goto(tctx, error_exit,
				talloc_asprintf(tctx,
				"smb2_getinfo_file(2) of %s failed (%s)\n",
				fname, nt_errstr(status)));
		}
	}

	/*
	 * Get security descriptor whilst asking for *NO* bits.
	 * This succeeds even though we don't have READ_CONTROL
	 * access but returns an SD with zero data.
	 */
	query.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	query.query_secdesc.in.file.handle = create_io.out.file.handle;
	query.query_secdesc.in.secinfo_flags = 0;

	status = smb2_getinfo_file(tree, tctx, &query);
	if(!NT_STATUS_IS_OK(status)){
		NTSTATUS s = smb2_util_close(tree, create_io.out.file.handle);
		torture_assert_ntstatus_ok_goto(tctx, s, ret, error_exit,
				talloc_asprintf(tctx,
					"close(3) of %s failed (%s)\n",
					fname, nt_errstr(s)));
		ret = false;
		torture_fail_goto(tctx, error_exit, talloc_asprintf(tctx,
			"smb2_getinfo_file(3) of %s failed (%s)\n",
			fname, nt_errstr(status)));
	}

	sd = query.query_secdesc.out.sd;

	/* Check it's empty. */
	torture_assert_goto(tctx,
			(sd->owner_sid == NULL),
			ret,
			error_exit,
			"sd->owner_sid != NULL\n");

	torture_assert_goto(tctx,
			(sd->group_sid == NULL),
			ret,
			error_exit,
			"sd->group_sid != NULL\n");

	torture_assert_goto(tctx,
			(sd->dacl == NULL),
			ret,
			error_exit,
			"sd->dacl != NULL\n");

	status = smb2_util_close(tree, create_io.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx,
			status,
			ret,
			error_exit,
			talloc_asprintf(tctx, "close(4) of %s failed (%s)\n",
				fname,
			nt_errstr(status)));

error_exit:

	smb2_setatr(tree, fname, FILE_ATTRIBUTE_NORMAL);
	smb2_util_unlink(tree, fname);

	return ret;
}
