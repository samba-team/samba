/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <unistd.h>
#include <talloc.h>

#include <ldb.h>
#include <ldb_private.h>
#include <string.h>
#include <ctype.h>

int ldb_ldap_init(const char *version);

#include "ldb_ldap/ldb_ldap.c"

struct test_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;
	struct ldb_message *msg;
};

static int lldb_msg_setup(void **state)
{
	struct test_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	test_ctx->msg = ldb_msg_new(test_ctx);
	assert_non_null(test_ctx->msg);

	*state = test_ctx;
	return 0;
}

static int lldb_msg_teardown(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);

	talloc_free(test_ctx);
	return 0;
}

static void test_lldb_add_msg_attr(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_message *msg = test_ctx->msg;
	int ret;
	unsigned int num_elements = 0;
	struct berval **v = NULL;

	v = talloc_zero_array(test_ctx, struct berval *, 2);
	assert_non_null(v);

	v[0] = talloc_zero(v, struct berval);
	assert_non_null(v[0]);

	v[0]->bv_val = talloc_strdup(msg, "dc=example,dc=test");
	assert_non_null(v[0]->bv_val);

	v[0]->bv_len = strlen(v[0]->bv_val);

	num_elements = msg->num_elements;

	ret = lldb_add_msg_attr(test_ctx->ldb, msg, "defaultNamingContext", v);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_int_equal(msg->num_elements, num_elements + 1);
}


int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_lldb_add_msg_attr,
						lldb_msg_setup,
						lldb_msg_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
