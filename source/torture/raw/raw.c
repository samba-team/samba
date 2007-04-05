/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Jelmer Vernooij 2006
   
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
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "torture/raw/proto.h"

NTSTATUS torture_raw_init(void)
{
	struct torture_suite *suite = torture_suite_create(
		talloc_autofree_context(),
		"RAW");
	/* RAW smb tests */
	torture_suite_add_simple_test(suite, "BENCH-OPLOCK", torture_bench_oplock);
	torture_suite_add_simple_test(suite, "BENCH-LOCK", torture_bench_lock);
	torture_suite_add_simple_test(suite, "BENCH-OPEN", torture_bench_open);
	torture_suite_add_simple_test(suite, "QFSINFO", torture_raw_qfsinfo);
	torture_suite_add_simple_test(suite, "QFILEINFO", torture_raw_qfileinfo);
	torture_suite_add_simple_test(suite, "SFILEINFO", torture_raw_sfileinfo);
	torture_suite_add_simple_test(suite, "SFILEINFO-BUG", torture_raw_sfileinfo_bug);
	torture_suite_add_simple_test(suite, "SEARCH", torture_raw_search);
	torture_suite_add_simple_test(suite, "CLOSE", torture_raw_close);
	torture_suite_add_simple_test(suite, "OPEN", torture_raw_open);
	torture_suite_add_simple_test(suite, "MKDIR", torture_raw_mkdir);
	torture_suite_add_simple_test(suite, "OPLOCK", torture_raw_oplock);
	torture_suite_add_simple_test(suite, "NOTIFY", torture_raw_notify);
	torture_suite_add_simple_test(suite, "MUX", torture_raw_mux);
	torture_suite_add_simple_test(suite, "IOCTL", torture_raw_ioctl);
	torture_suite_add_simple_test(suite, "CHKPATH", torture_raw_chkpath);
	torture_suite_add_simple_test(suite, "UNLINK", torture_raw_unlink);
	torture_suite_add_simple_test(suite, "READ", torture_raw_read);
	torture_suite_add_simple_test(suite, "WRITE", torture_raw_write);
	torture_suite_add_simple_test(suite, "LOCK", torture_raw_lock);
	torture_suite_add_simple_test(suite, "CONTEXT", torture_raw_context);
	torture_suite_add_simple_test(suite, "RENAME", torture_raw_rename);
	torture_suite_add_simple_test(suite, "SEEK", torture_raw_seek);
	torture_suite_add_simple_test(suite, "EAS", torture_raw_eas);
	torture_suite_add_simple_test(suite, "STREAMS", torture_raw_streams);
	torture_suite_add_simple_test(suite, "ACLS", torture_raw_acls);
	torture_suite_add_simple_test(suite, "COMPOSITE", torture_raw_composite);
	torture_suite_add_simple_test(suite, "SAMBA3HIDE", torture_samba3_hide);
	torture_suite_add_simple_test(suite, "SAMBA3CLOSEERR", torture_samba3_closeerr);
	torture_suite_add_simple_test(suite, "SAMBA3CHECKFSP", torture_samba3_checkfsp);
	torture_suite_add_simple_test(suite, "SAMBA3BADPATH", torture_samba3_badpath);
	torture_suite_add_simple_test(suite, "SCAN-EAMAX", torture_max_eas);

	suite->description = talloc_strdup(suite, 
							"Tests for the raw SMB interface");

	torture_register_suite(suite);

	return NT_STATUS_OK;
}
