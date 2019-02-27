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
#include "librpc/gen_ndr/ndr_samr_scompat.h"
#include "source3/rpc_server/srv_pipe.h"
#include "librpc/rpc/rpc_common.h"
#include "librpc/rpc/dcesrv_core.h"
#include "talloc.h"

struct test_state {
	TALLOC_CTX *mem_ctx;
	struct loadparm_context *lp_ctx;
	struct dcesrv_context *dce_ctx;
};

static int setup_samr(void **state)
{
	TALLOC_CTX *mem_ctx;
	struct test_state *s;
	const struct dcesrv_endpoint_server *ep_server;
	NTSTATUS status;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	s = talloc_zero(mem_ctx, struct test_state);
	assert_non_null(s);

	s->mem_ctx = mem_ctx;

	ep_server = samr_get_ep_server();
	assert_non_null(ep_server);

	status = dcerpc_register_ep_server(ep_server);
	assert_true(NT_STATUS_IS_OK(status));

	status = dcesrv_init_context(s, NULL, NULL, &s->dce_ctx);
	assert_true(NT_STATUS_IS_OK(status));

	status = dcesrv_init_ep_server(s->dce_ctx, "samr");
	assert_true(NT_STATUS_IS_OK(status));

	*state = s;

	return 0;
}

static int teardown_samr(void **state)
{
	struct test_state *s = talloc_get_type_abort(*state,
			struct test_state);

	unsetenv("UNITTEST_DUMMY_MODULE_LOADED");

	dcesrv_shutdown_ep_server(s->dce_ctx, "samr");

	talloc_free(s->mem_ctx);

	return 0;
}

static void test_is_known_pipename(void **state)
{
	struct test_state *s = talloc_get_type_abort(*state,
			struct test_state);
	struct dcesrv_endpoint *ep;
	char dummy_module_path[4096] = {0};
	const char *module_env;
	NTSTATUS status;

	status = is_known_pipename(s->dce_ctx, "samr", &ep);
	assert_true(NT_STATUS_IS_OK(status));

	status = is_known_pipename(s->dce_ctx, "SAMR", &ep);
	assert_true(NT_STATUS_IS_OK(status));

	snprintf(dummy_module_path,
		 sizeof(dummy_module_path),
		 "%s/bin/modules/rpc/test_dummy_module.so",
		 SRCDIR);

	status = is_known_pipename(s->dce_ctx, dummy_module_path, &ep);
	assert_false(NT_STATUS_IS_OK(status));

	module_env = getenv("UNITTEST_DUMMY_MODULE_LOADED");
	assert_null(module_env);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_is_known_pipename,
						setup_samr,
						teardown_samr),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
