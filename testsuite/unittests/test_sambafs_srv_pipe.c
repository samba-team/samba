#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cmocka.h>

#include "include/config.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "source3/rpc_server/srv_pipe.h"
#include "librpc/gen_ndr/srv_samr.h"

static int setup_samr(void **state)
{
	rpc_samr_init(NULL);

	return 0;
}

static int teardown(void **state)
{
	unsetenv("UNITTEST_DUMMY_MODULE_LOADED");

	return 0;
}

static int teardown_samr(void **state)
{
	rpc_samr_shutdown();

	teardown(state);

	return 0;
}

static void test_is_known_pipename(void **state)
{
	struct ndr_syntax_id syntax_id = ndr_table_samr.syntax_id;
	NTSTATUS status;

	status = is_known_pipename("samr", &syntax_id);
	assert_true(NT_STATUS_IS_OK(status));
}

static void test_is_known_pipename_slash(void **state)
{
	struct ndr_syntax_id syntax_id = ndr_table_samr.syntax_id;
	char dummy_module_path[4096] = {0};
	const char *module_env;
	NTSTATUS status;

	snprintf(dummy_module_path,
		 sizeof(dummy_module_path),
		 "%s/bin/modules/rpc/test_dummy_module.so",
		 SRCDIR);

	status = is_known_pipename(dummy_module_path, &syntax_id);
	assert_true(NT_STATUS_IS_ERR(status));

	module_env = getenv("UNITTEST_DUMMY_MODULE_LOADED");
	assert_null(module_env);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_is_known_pipename,
						setup_samr,
						teardown_samr),
		cmocka_unit_test_teardown(test_is_known_pipename_slash,
					  teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
