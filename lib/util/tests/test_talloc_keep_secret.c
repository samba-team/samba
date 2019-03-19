#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <talloc.h>
#include "lib/util/talloc_keep_secret.h"

int rep_memset_s(void *dest, size_t destsz, int ch, size_t count);

int rep_memset_s(void *dest, size_t destsz, int ch, size_t count)
{
	check_expected_ptr(dest);
	check_expected(destsz);
	check_expected(ch);
	check_expected(count);

	return 0;
}

static void test_talloc_keep_secret(void ** state)
{
	TALLOC_CTX *pool = NULL;
	char *ptr1 = NULL;
	char *ptr2 = NULL;
	const char *ptr1_talloc_name = NULL;
	size_t ptr1_size;
	size_t i;

	pool = talloc_pool(NULL, 256);
	assert_non_null(pool);

	ptr1 = talloc_strdup(pool, "secret");
	assert_non_null(ptr1);
	assert_string_equal(ptr1, "secret");

	talloc_keep_secret(ptr1);

	ptr1_talloc_name = talloc_get_name(ptr1);
	assert_string_equal(ptr1_talloc_name, "ptr1");

	ptr1_size = talloc_get_size(ptr1);
	assert_int_equal(ptr1_size, strlen(ptr1) + 1);

	expect_string(rep_memset_s, dest, "secret");
	expect_value(rep_memset_s, destsz, strlen(ptr1) + 1);
	expect_value(rep_memset_s, ch, (int)'\0');
	expect_value(rep_memset_s, count, strlen(ptr1) + 1);

	talloc_free(ptr1);

	ptr2 = talloc_size(pool, ptr1_size);
	assert_ptr_equal(ptr1, ptr2);

	for (i = 1; i < ptr1_size; i++) {
		assert_int_not_equal(ptr2[0], ptr2[i]);
	}

	talloc_free(pool);
}

static void test_talloc_keep_secret_validate_memset(void **state)
{
	TALLOC_CTX *mem_ctx = NULL;
	char *password = NULL;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	password = talloc_strdup(mem_ctx, "secret");
	assert_non_null(password);
	talloc_keep_secret(password);

	expect_string(rep_memset_s, dest, "secret");
	expect_value(rep_memset_s, destsz, strlen(password) + 1);
	expect_value(rep_memset_s, ch, (int)'\0');
	expect_value(rep_memset_s, count, strlen(password) + 1);

	talloc_free(mem_ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_talloc_keep_secret),
        cmocka_unit_test(test_talloc_keep_secret_validate_memset),
    };

    cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
