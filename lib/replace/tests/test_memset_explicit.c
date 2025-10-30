#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "lib/replace/replace.h"


/*
 * To check that a memset_explicit string is being memset when it
 * appears unused, we meed to be sneaky in our check -- otherwise the
 * check counts as a use.
 *
 * We are sneaky by using a function that seens to take an int
 * argument which is really a pointer, and we hide that it is a
 * pointer by masking it.
 *
 * For these tests we don't use talloc because the talloc magic gets
 * in the way a little bit.
 */

#define MASK 0x12345678

__attribute__((noinline))
static void check_memset_explicit(intmax_t p, const char *expected, size_t len)
{
	size_t i;
	char *secret = (char *) (p ^ MASK);
	for (i = 0; i < len; i++) {
		assert_int_equal(secret[i], expected[i]);
	}
}


__attribute__((noinline))
static char *get_secret(off_t offset)
{
	char * secret = malloc(7 + offset);
	memset(secret, 0, 7 + offset);
	memcpy(secret + offset, "secret", 7);
	/* avoiding *this* being elided */
	print_message("secret is '%s'\n", secret);
	asm("");
	return secret;
}


static void test_memset_explicit(void ** state)
{
	uintptr_t p;
	char zeros[7] = {0};
	char *secret = get_secret(0);
	p = ((uintptr_t)secret) ^ MASK;
	memset_explicit(secret, 'o', 3);
	check_memset_explicit(p, "oooret", 7);
	memset_explicit(secret, 0, 7);
	check_memset_explicit(p, zeros, 7);
	free(secret);
}

static void test_memset_explicit_double_alloc(void ** state)
{
	size_t i, found;
	uintptr_t p, q;
	char *secret = get_secret(20);
	p = (uintptr_t)secret ^ MASK;
	memset_explicit(secret, 'x', 23);
	free(secret);
	/*
	 * Now we malloc the same size again, and hope we got the
	 * block we just freed.
	 */
	found = 0;
	for (i = 0; i < 1000; i++) {
		secret = malloc(27);
		q = (uintptr_t)secret ^ MASK;
		if (q == p) {
			q = (uintptr_t)(secret + 20) ^ MASK;
			check_memset_explicit(q, "xxxret", 7);
			found ++;
		}
		free(secret);
	}
	print_message("found freed pointer %zu/1000 times \n",
		found);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_memset_explicit),
		cmocka_unit_test(test_memset_explicit_double_alloc),
	};
	if (! isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}
