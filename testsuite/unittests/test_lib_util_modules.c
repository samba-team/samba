#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <talloc.h>

#include "include/config.h"
#include "libcli/util/ntstatus.h"
#include "lib/util/samba_modules.h"

static int teardown(void **state)
{
	unsetenv("UNITTEST_DUMMY_MODULE_LOADED");

	return 0;
}

static void test_samba_module_probe(void **state)
{
	NTSTATUS status;

	status = smb_probe_module("auth", "skel");
	assert_true(NT_STATUS_IS_OK(status));
}

static void test_samba_module_probe_dummy(void **state)
{
	const char *module_env;
	NTSTATUS status;

	status = smb_probe_module("rpc", "test_dummy_module");
	assert_true(NT_STATUS_IS_OK(status));

	module_env = getenv("UNITTEST_DUMMY_MODULE_LOADED");
	assert_non_null(module_env);
	assert_string_equal(module_env, "TRUE");
}

static void test_samba_module_probe_slash(void **state)
{
	char dummy_module_path[4096] = {0};
	const char *module_env;
	NTSTATUS status;

	snprintf(dummy_module_path,
		 sizeof(dummy_module_path),
		 "%s/bin/modules/rpc/test_dummy_module.so",
		 SRCDIR);

	status = smb_probe_module("rpc", dummy_module_path);
	assert_true(NT_STATUS_IS_ERR(status));

	module_env = getenv("UNITTEST_DUMMY_MODULE_LOADED");
	assert_null(module_env);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_teardown(test_samba_module_probe,
					  teardown),
		cmocka_unit_test_teardown(test_samba_module_probe_dummy,
					  teardown),
		cmocka_unit_test_teardown(test_samba_module_probe_slash,
					  teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
