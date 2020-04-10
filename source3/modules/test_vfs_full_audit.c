/*
 *  Unix SMB/CIFS implementation.
 *
 *  Unit test for entries in vfs_full_audit arrays.
 *
 *  Copyright (C) Jeremy Allison 2020
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Needed for static build to complete... */
#include "includes.h"
#include "smbd/smbd.h"
NTSTATUS vfs_full_audit_init(TALLOC_CTX *ctx);

#include "vfs_full_audit.c"
#include <cmocka.h>

static void test_full_audit_array(void **state)
{
	unsigned i;

	for (i=0; i<SMB_VFS_OP_LAST; i++) {
		assert_non_null(vfs_op_names[i].name);
		assert_int_equal(vfs_op_names[i].type, i);
	}
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_full_audit_array),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
