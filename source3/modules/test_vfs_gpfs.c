/*
 *  Unix SMB/CIFS implementation.
 *
 *  Unit test for vfs_gpfs module.
 *
 *  Copyright (C) Christof Schmitt 2020
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

#include "vfs_gpfs.c"
#include <cmocka.h>

static void test_share_deny_mapping(void **state)
{
	assert_int_equal(vfs_gpfs_share_access_to_deny(FILE_SHARE_NONE),
			 GPFS_DENY_READ|GPFS_DENY_WRITE|GPFS_DENY_DELETE);
	assert_int_equal(vfs_gpfs_share_access_to_deny(FILE_SHARE_READ),
			 GPFS_DENY_WRITE|GPFS_DENY_DELETE);
	assert_int_equal(vfs_gpfs_share_access_to_deny(FILE_SHARE_WRITE),
			 GPFS_DENY_READ|GPFS_DENY_DELETE);
	assert_int_equal(vfs_gpfs_share_access_to_deny(FILE_SHARE_DELETE),
			 GPFS_DENY_READ|GPFS_DENY_WRITE);
	assert_int_equal(vfs_gpfs_share_access_to_deny(
				 FILE_SHARE_READ|FILE_SHARE_DELETE),
			 GPFS_DENY_WRITE);
	assert_int_equal(vfs_gpfs_share_access_to_deny(
				 FILE_SHARE_WRITE|FILE_SHARE_DELETE),
			 GPFS_DENY_READ);
	assert_int_equal(vfs_gpfs_share_access_to_deny(
				 FILE_SHARE_READ|FILE_SHARE_WRITE),
			 0); /* GPFS limitation, cannot deny only delete. */
}

static void test_gpfs_lease_mapping(void **state)
{
	assert_int_equal(lease_type_to_gpfs(F_RDLCK), GPFS_LEASE_READ);
	assert_int_equal(lease_type_to_gpfs(F_WRLCK), GPFS_LEASE_WRITE);
	assert_int_equal(lease_type_to_gpfs(F_UNLCK), GPFS_LEASE_NONE);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_share_deny_mapping),
		cmocka_unit_test(test_gpfs_lease_mapping),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
