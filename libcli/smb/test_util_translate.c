/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2020      Andreas Schneider <asn@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "lib/replace/replace.h"
#include <talloc.h>

#include "libcli/smb/util.c"

static void test_smb_signing_setting_translate(void **state)
{
	enum smb_signing_setting signing_state;

	signing_state = smb_signing_setting_translate("wurst");
	assert_int_equal(signing_state, SMB_SIGNING_REQUIRED);

	signing_state = smb_signing_setting_translate("off");
	assert_int_equal(signing_state, SMB_SIGNING_OFF);

	signing_state = smb_signing_setting_translate("if_required");
	assert_int_equal(signing_state, SMB_SIGNING_IF_REQUIRED);

	signing_state = smb_signing_setting_translate("mandatory");
	assert_int_equal(signing_state, SMB_SIGNING_REQUIRED);

}

static void test_smb_encryption_setting_translate(void **state)
{
	enum smb_encryption_setting encryption_state;

	encryption_state = smb_encryption_setting_translate("wurst");
	assert_int_equal(encryption_state, SMB_ENCRYPTION_REQUIRED);

	encryption_state = smb_encryption_setting_translate("off");
	assert_int_equal(encryption_state, SMB_ENCRYPTION_OFF);

	encryption_state = smb_encryption_setting_translate("if_required");
	assert_int_equal(encryption_state, SMB_ENCRYPTION_IF_REQUIRED);

	encryption_state = smb_encryption_setting_translate("mandatory");
	assert_int_equal(encryption_state, SMB_ENCRYPTION_REQUIRED);

}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_smb_signing_setting_translate),
		cmocka_unit_test(test_smb_encryption_setting_translate),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests, NULL, NULL);

	return rc;
}
