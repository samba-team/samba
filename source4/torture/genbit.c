/* 
   Unix SMB/CIFS implementation.
   Gentest test definitions

   Copyright (C) James Myers 2003

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

get_field_function test_field_get_file_attr;	
get_field_function test_field_get_fid;	
get_field_function test_field_get_filename;	
get_field_function test_field_get_mtime;	
get_field_function test_field_get_trans2;	
get_field_function test_field_get_fsinfo_level;		

static struct unlink_test_parms_t gen_unlink_test_parms;
static struct close_test_parms_t gen_close_test_parms;
static struct qfsi_test_parms_t gen_qfsi_test_parms;

static struct trans2_parms trans2_qfsi_parms = {
	testFieldTypeTrans2, 1, 2, 0, 0, TRANSACT2_QFSINFO
};

static struct field_test_spec gen_unlink_test_spec[] = {
	{"FATTR", testFieldTypeFileAttr, NULL,
		 1, test_field_get_file_attr},
	{"FNAME", testFieldTypeFilename, NULL,
		 -1, test_field_get_filename},
	{"", -1, NULL, -1, NULL}
};

static struct field_test_spec gen_close_test_spec[] = {
	{"FID", testFieldTypeFid, NULL, 1,
		test_field_get_fid},
	{"MTIME", testFieldTypeMtime, NULL, 2,
		test_field_get_mtime},
	{"", -1, NULL, -1, NULL}
};

static struct field_test_spec gen_qfsi_test_spec[] = {
	{"TRANS2", testFieldTypeTrans2,
		(void*)&trans2_qfsi_parms, 15,
		test_field_get_trans2},
	{"INFO_LEVEL", 0, NULL, 1, test_field_get_fsinfo_level},	
	{"", -1, NULL, -1, NULL}
};						

static struct enum_test gen_enum_tests[] = {
	{SMBunlink, "UNLINK", TEST_COND_TCON,
		testTypeFilename,
		TEST_OPTION_FILE_EXISTS | 
			TEST_OPTION_FILE_SYSTEM |
			TEST_OPTION_FILE_HIDDEN |
			TEST_OPTION_FILE_INVISIBLE |
			TEST_OPTION_FILE_WILDCARD |
			TEST_OPTION_FILE_NOT_EXIST,
		1, gen_unlink_test_spec, (void*)&gen_unlink_test_parms,
		gen_execute_unlink, gen_verify_unlink},
	{SMBclose, "CLOSE", TEST_COND_TCON,
		testTypeFid,
		TEST_OPTION_FID_VALID | TEST_OPTION_FID_INVALID,
		3, gen_close_test_spec, (void*)&gen_close_test_parms, 
		gen_execute_close, gen_verify_close},
	{SMBtrans2, "QUERY_FS_INFO", TEST_COND_TCON,
		testTypeConnected,
		1,
		16, gen_qfsi_test_spec, (void*)&gen_qfsi_test_parms,
		gen_execute_qfsi, gen_verify_qfsi},
	{-1, NULL, 0, 0, 0, -1, NULL, NULL, NULL}
};
