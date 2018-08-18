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

struct test_ctx {
	struct ldb_message *msg;
};

static int ldb_msg_setup(void **state)
{
	struct test_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(test_ctx);

	test_ctx->msg = ldb_msg_new(test_ctx);

	*state = test_ctx;
	return 0;
}

static int ldb_msg_teardown(void **state)
{
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);

	talloc_free(test_ctx);
	return 0;
}


static void add_uint_value(struct test_ctx *test_ctx,
			   struct ldb_message *msg,
			   const char *attr,
			   unsigned int x)
{
	int ret;
	struct ldb_val v, v_dup;
	char s[5];
	snprintf(s, sizeof(s), "%04x", x);
	v.data = (uint8_t *)s;
	v.length = 4;
	v_dup = ldb_val_dup(test_ctx, &v);
	assert_non_null(v_dup.data);
	assert_ptr_not_equal(v_dup.data, v.data);
	assert_int_equal(v_dup.length, 4);

	ret = ldb_msg_add_value(msg, attr, &v_dup, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
}


static void test_ldb_msg_find_duplicate_val(void **state)
{
	int ret;
	unsigned int i;
	struct test_ctx *test_ctx = talloc_get_type_abort(*state,
							  struct test_ctx);
	struct ldb_message *msg = test_ctx->msg;
	struct ldb_message_element *el;
	struct ldb_val dummy;
	struct ldb_val *dupe = &dummy;  /* so we can tell it was modified to NULL, not left as NULL */

	ret = ldb_msg_add_empty(msg, "el1", 0, &el);
	assert_int_equal(ret, LDB_SUCCESS);

	/* An empty message contains no duplicates */
	ret = ldb_msg_find_duplicate_val(NULL, test_ctx, el, &dupe, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_null(dupe);

	for (i = 0; i < 5; i++) {
		add_uint_value(test_ctx, msg, "el1", i);
	}
	/* at this point there are no duplicates, and the check uses the naive
	   quadratic path */
	ret = ldb_msg_find_duplicate_val(NULL, test_ctx, el, &dupe, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_null(dupe);

	/* add a duplicate, still using quadratric path */
	add_uint_value(test_ctx, msg, "el1", 3);
	ret = ldb_msg_find_duplicate_val(NULL, test_ctx, el, &dupe, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(dupe);
	assert_int_equal(dupe->length, 4);
	assert_memory_equal(dupe->data, "0003", 4);

	/* add some more, triggering algorithmic jump */
	for (i = 2; i < 11; i++) {
		add_uint_value(test_ctx, msg, "el1", i);
	}
	ret = ldb_msg_find_duplicate_val(NULL, test_ctx, el, &dupe, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(dupe);
	assert_int_equal(dupe->length, 4);
	/*XXX not really guaranteed by the API */
	assert_memory_equal(dupe->data, "0002", 4);

	/* start a new element without duplicates, for the clever algorithm */
	ldb_msg_add_empty(msg, "el2", 0, &el);
	for (i = 0; i < 12; i++) {
		add_uint_value(test_ctx, msg, "el2", i);
	}
	ret = ldb_msg_find_duplicate_val(NULL, test_ctx, el, &dupe, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_null(dupe);
}


static struct ldb_message_element *new_msg_element(TALLOC_CTX *mem_ctx,
						   const char *name,
						   unsigned int value_offset,
						   unsigned int num_values)
{
	unsigned int i, x;
	struct ldb_message_element *el = talloc_zero(mem_ctx,
						     struct ldb_message_element);

	el->values = talloc_array(el, struct ldb_val, num_values);
	for (i = 0; i < num_values; i++) {
		struct ldb_val v;
		char s[50];
		v.data = (uint8_t *)s;
		/* % 3 is to ensure the values list is unsorted */
		x = i + value_offset;
		v.length = snprintf(s, sizeof(s), "%u %u", x % 3, x);
		el->values[i] = ldb_val_dup(mem_ctx, &v);
	}
	el->name = name;
	el->num_values = num_values;
	return el;
}

static void _assert_element_equal(struct ldb_message_element *a,
				  struct ldb_message_element *b,
				  const char * const file,
				  const int line)
{
	unsigned int i;
	_assert_int_equal(a->num_values, b->num_values, file, line);
	_assert_int_equal(a->flags, b->flags, file, line);
	_assert_string_equal(a->name, b->name, file, line);
	for (i = 0; i < a->num_values; i++) {
		struct ldb_val *v1 = &a->values[i];
		struct ldb_val *v2 = &b->values[i];
		_assert_int_equal(v1->length, v2->length, file, line);
		_assert_memory_equal(v1->data, v2->data, v1->length,
				     file, line);
	}
}

#define assert_element_equal(a, b)				\
	_assert_element_equal((a), (b),				\
			      __FILE__, __LINE__)


static void test_ldb_msg_find_common_values(void **state)
{
	/* we only use the state as a talloc context */
	struct ldb_message_element *el, *el2, *el3, *el4, *el2b, *empty;
	struct ldb_message_element *orig, *orig2, *orig3, *orig4;
	int ret;
	const uint32_t remove_dupes = LDB_MSG_FIND_COMMON_REMOVE_DUPLICATES;
	el = new_msg_element(*state, "test", 0, 4);
	el2 = new_msg_element(*state, "test", 4, 4);
	el3 = new_msg_element(*state, "test", 6, 4);
	empty = new_msg_element(*state, "test", 0, 0);
	orig = new_msg_element(*state, "test", 0, 4);
	orig2 = new_msg_element(*state, "test", 4, 4);
	orig3 = new_msg_element(*state, "test", 6, 4);

	/* first round is with short value arrays, using quadratic method */
	/* we expect no collisions here */
	ret = ldb_msg_find_common_values(NULL, *state, el, el2, 0);
	assert_int_equal(ret, LDB_SUCCESS);

	/*or here */
	ret = ldb_msg_find_common_values(NULL, *state, el, el3, 0);
	assert_int_equal(ret, LDB_SUCCESS);

	/* the same elements in reverse order */
	ret = ldb_msg_find_common_values(NULL, *state, el2, el, 0);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_msg_find_common_values(NULL, *state, el3, el, 0);
	assert_int_equal(ret, LDB_SUCCESS);

	/* 6, 7 collide */
	ret = ldb_msg_find_common_values(NULL, *state, el2, el3, 0);
	assert_int_equal(ret, LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS);

	/* and again */
	ret = ldb_msg_find_common_values(NULL, *state, el3, el2, 0);
	assert_int_equal(ret, LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS);

	/* make sure the arrays haven't changed */
	assert_element_equal(el, orig);
	assert_element_equal(el2, orig2);
	assert_element_equal(el3, orig3);

	/* now with the control permisive flag, the first element should be
	   modified to remove the overlap.*/

	/* 6, 7 collide, so el2 will only have 4 and 5 */
	ret = ldb_msg_find_common_values(NULL, *state, el2, el3, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);

	assert_element_equal(el3, orig3);
	assert_int_not_equal(el2->num_values, orig2->num_values);
	assert_int_equal(el2->num_values, 2);
	el2b = new_msg_element(*state, "test", 4, 2);
	assert_element_equal(el2, el2b);

	/* now try the same things with a long and a short value list.
	   this should still trigger the quadratic path.
	 */
	el2 = new_msg_element(*state, "test", 4, 10);
	orig2 = new_msg_element(*state, "test", 4, 10);

	/* no collisions */
	ret = ldb_msg_find_common_values(NULL, *state, el, el2, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, el2, el, 0);
	assert_int_equal(ret, LDB_SUCCESS);

	/*collisions */
	ret = ldb_msg_find_common_values(NULL, *state, el3, el2, 0);
	assert_int_equal(ret, LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS);

	assert_element_equal(el, orig);
	assert_element_equal(el2, orig2);
	assert_element_equal(el3, orig3);

	/*collisions with permissive flag*/
	ret = ldb_msg_find_common_values(NULL, *state, el3, el2, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_element_equal(el2, orig2);
	assert_int_equal(el3->num_values, 0);

	/* permutations involving empty elements.
	   everything should succeed. */
	ret = ldb_msg_find_common_values(NULL, *state, el3, el2, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, el3, el, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, el2, el3, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_int_equal(el2->num_values, orig2->num_values);
	ret = ldb_msg_find_common_values(NULL, *state, el3, el2, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_int_equal(el2->num_values, orig2->num_values);
	assert_int_equal(el3->num_values, 0); /* el3 is now empty */
	ret = ldb_msg_find_common_values(NULL, *state, el2, el3, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, el3, empty, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, empty, empty, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, empty, el3, 0);
	assert_int_equal(ret, LDB_SUCCESS);

	assert_element_equal(el2, orig2);
	assert_element_equal(el, orig);
	assert_int_equal(el3->num_values, 0);

	/* now with two large value lists */
	el = new_msg_element(*state, "test", 0, 12);
	orig = new_msg_element(*state, "test", 0, 12);
	el4 = new_msg_element(*state, "test", 12, 12);
	orig4 = new_msg_element(*state, "test", 12, 12);

	/* no collisions */
	ret = ldb_msg_find_common_values(NULL, *state, el, el4, 0);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_msg_find_common_values(NULL, *state, el4, el, 0);
	assert_int_equal(ret, LDB_SUCCESS);

	/* collisions */
	ret = ldb_msg_find_common_values(NULL, *state, el4, el2, 0);
	assert_int_equal(ret, LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS);
	ret = ldb_msg_find_common_values(NULL, *state, el2, el4, 0);
	assert_int_equal(ret, LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS);
	ret = ldb_msg_find_common_values(NULL, *state, el2, el, 0);
	assert_int_equal(ret, LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS);

	assert_element_equal(el, orig);
	assert_element_equal(el2, orig2);
	assert_element_equal(el4, orig4);

	/* with permissive control, but no collisions */
	ret = ldb_msg_find_common_values(NULL, *state, el, el4, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, el4, el, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);

	assert_element_equal(el, orig);
	assert_element_equal(el4, orig4);

	/* now with collisions, thus modifications.
	   At this stage:
	   el is 0-11 (inclusive)
	   e2 is 4-13
	   el3 is empty
	   el4 is 12-23
	 */
	ret = ldb_msg_find_common_values(NULL, *state, el4, el2, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_element_equal(el2, orig2);
	assert_int_not_equal(el4->num_values, orig4->num_values);
	/* 4 should start at 14 */
	orig4 = new_msg_element(*state, "test", 14, 10);
	assert_element_equal(el4, orig4);

	ret = ldb_msg_find_common_values(NULL, *state, el2, el, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_element_equal(el, orig);
	assert_int_not_equal(el2->num_values, orig2->num_values);
	orig2 = new_msg_element(*state, "test", 12, 2);
	assert_element_equal(el2, orig2);

	/* test the empty el against the full elements */
	ret = ldb_msg_find_common_values(NULL, *state, el, empty, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, empty, el, 0);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, el, empty, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);
	ret = ldb_msg_find_common_values(NULL, *state, empty, el, remove_dupes);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_element_equal(el, orig);
	assert_element_equal(empty, el3);

	/* make sure an identical element with a different name is rejected */
	el2 = new_msg_element(*state, "fish", 12, 2);
	ret = ldb_msg_find_common_values(NULL, *state, el2, el, remove_dupes);
	assert_int_equal(ret, LDB_ERR_INAPPROPRIATE_MATCHING);
}



int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_ldb_msg_find_duplicate_val,
						ldb_msg_setup,
						ldb_msg_teardown),
		cmocka_unit_test_setup_teardown(
			test_ldb_msg_find_common_values,
			ldb_msg_setup,
			ldb_msg_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
