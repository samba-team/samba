/*
 * Unit tests for conditional ACE SDDL.
 *
 *  Copyright (C) Catalyst.NET Ltd 2023
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
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmocka.h"

#include "lib/util/attr.h"
#include "includes.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "libcli/security/conditional_ace.h"
#include "librpc/gen_ndr/conditional_ace.h"
#include "libcli/security/claims-conversions.h"

#define debug_message(...) print_message(__VA_ARGS__)

#define debug_fail(x, ...) print_message("\033[1;31m" x "\033[0m", __VA_ARGS__)
#define debug_ok(x, ...) print_message("\033[1;32m" x "\033[0m", __VA_ARGS__)

#define assert_ntstatus_equal(got, expected, comment)	  \
	do { NTSTATUS __got = got, __expected = expected;		\
		if (!NT_STATUS_EQUAL(__got, __expected)) {		\
			print_message(": "#got" was %s, expected %s: %s", \
				      nt_errstr(__got),			\
				      nt_errstr(__expected), comment);	\
			fail();						\
		}							\
	} while(0)




/*
static void print_error_message(const char *sddl,
				const char *message,
				size_t message_offset)
{
	print_message("%s\n\033[1;33m %*c\033[0m\n", sddl,
		      (int)message_offset, '^');
	print_message("%s\n", message);
}
*/
static bool fill_token_claims(TALLOC_CTX *mem_ctx,
			      struct security_token *token,
			   const char *claim_type,
			   const char *name,
			   ...)
{
	va_list args;
	va_start(args, name);
	while (true) {
		struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim = NULL;
		const char *str = va_arg(args, const char *);
		if (str == NULL) {
			break;
		}
		claim = parse_sddl_literal_as_claim(mem_ctx,
						    name,
						    str);
		if (claim == NULL) {
			va_end(args);
			debug_fail("bad claim: %s\n", str);
			return false;
		}
		add_claim_to_token(mem_ctx, token, claim, claim_type);
	}
	va_end(args);
	return true;
}


static bool fill_token_sids(TALLOC_CTX *mem_ctx,
			    struct security_token *token,
			    const char *owner,
			 ...)
{
	uint32_t *n = &token->num_sids;
	struct dom_sid **list = NULL;
	va_list args;
	if (strcmp(owner, "device") == 0) {
		n = &token->num_device_sids;
		list = &token->device_sids;
	} else if (strcmp(owner, "user") == 0) {
		n = &token->num_sids;
		list = &token->sids;
	} else {
		return false;
	}

	*n = 0;
	va_start(args, owner);
	while (true) {
		struct dom_sid *sid = NULL;
		const char *str = va_arg(args, const char *);
		if (str == NULL) {
			break;
		}

		sid = sddl_decode_sid(mem_ctx, &str, NULL);
		if (sid == NULL) {
			debug_fail("bad SID: %s\n", str);
			va_end(args);
			return false;
		}
		add_sid_to_array(mem_ctx, sid, list, n);
	}
	va_end(args);
	return true;
}


static void test_device_claims_composite(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct security_token token = {
		.evaluate_claims = CLAIMS_EVALUATION_ALWAYS
	};
	bool ok;
	NTSTATUS status;
	uint32_t access_granted = 0;
	struct security_descriptor *sd = NULL;
	const char *sddl = \
		"D:(XA;;0x1f;;;AA;(@Device.colour == {\"orange\", \"blue\"}))";
	ok = fill_token_sids(mem_ctx, &token,
			     "user",
			     "WD", "AA", NULL);
	assert_true(ok);
	ok = fill_token_claims(mem_ctx, &token,
			       "device", "colour",
			       "{\"orange\", \"blue\"}",
			       NULL);
	assert_true(ok);
	sd = sddl_decode(mem_ctx, sddl, NULL);
	assert_non_null(sd);
	status = se_access_check(sd, &token, 0x10, &access_granted);
	assert_ntstatus_equal(status, NT_STATUS_OK, "access check failed\n");
	TALLOC_FREE(mem_ctx);
}


static bool fill_sd(TALLOC_CTX *mem_ctx,
		    struct security_descriptor **sd,
		    const char *sddl)
{
	*sd = sddl_decode(mem_ctx, sddl, NULL);
	return *sd != NULL;
}

#define USER_SIDS(...) \
	assert_true(fill_token_sids(mem_ctx, &token, "user", __VA_ARGS__, NULL))

#define DEVICE_SIDS(...) \
	assert_true(     \
		fill_token_sids(mem_ctx, &token, "device", __VA_ARGS__, NULL))

#define USER_CLAIMS(...) \
	assert_true(     \
		fill_token_claims(mem_ctx, &token, "user", __VA_ARGS__, NULL))

#define LOCAL_CLAIMS(...)                          \
	assert_true(fill_token_claims(mem_ctx,     \
				      &token,      \
				      "local",     \
				      __VA_ARGS__, \
				      NULL))

#define DEVICE_CLAIMS(...)                         \
	assert_true(fill_token_claims(mem_ctx,     \
				      &token,      \
				      "device",    \
				      __VA_ARGS__, \
				      NULL))


#define SD(sddl) assert_true(fill_sd(mem_ctx, &sd, sddl))
#define SD_FAIL(sddl) assert_false(fill_sd(mem_ctx, &sd, sddl))

#define ALLOW_CHECK(requested)                                 \
	do {                                                   \
		NTSTATUS status;                               \
		uint32_t access_granted = 0;                   \
		status = se_access_check(sd,                   \
					 &token,               \
					 requested,            \
					 &access_granted);     \
		assert_ntstatus_equal(status,                  \
				      NT_STATUS_OK,            \
				      "access not granted\n"); \
	} while (0)


#define DENY_CHECK(requested)                                  \
	do {                                                   \
		NTSTATUS status;                               \
		uint32_t access_granted = 0;                   \
		status = se_access_check(sd,                   \
					 &token,               \
					 requested,            \
					 &access_granted);     \
		assert_ntstatus_equal(status,                  \
				      NT_STATUS_ACCESS_DENIED, \
				      "not denied\n");         \
	} while (0)


#define INIT()							\
	TALLOC_CTX *mem_ctx = talloc_new(NULL);			\
	struct security_token token = {				\
		.evaluate_claims = CLAIMS_EVALUATION_ALWAYS	\
	};							\
	struct security_descriptor *sd = NULL;

#define DEINIT()						\
	TALLOC_FREE(mem_ctx);

static void test_composite_different_order(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {\"orange\", \"blue\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"blue\", \"orange\"}");
	/*
	 * Claim arrays are sets, so we assume conditional ACE ones are too.
	 */
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_composite_different_order_with_dupes(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {\"orange\", \"blue\", \"orange\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\", \"orange\"}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_composite_different_order_with_dupes_in_composite(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {\"orange\", \"blue\", \"orange\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_composite_different_order_with_SID_dupes(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {SID(WD), SID(AA), SID(WD)}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{SID(AA), SID(AA), SID(WD)}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_composite_different_order_with_SID_dupes_in_composite(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {SID(WD), SID(AA), SID(WD)}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{SID(AA), SID(WD)}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_composite_mixed_types(void **state)
{
	/*
	 * If the conditional ACE composite has mixed types, it can
	 * never equal a claim, which only has one type.
	 */
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {2, SID(WD), SID(AA), SID(WD)}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{SID(AA), SID(WD)}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_composite_mixed_types_different_last(void **state)
{
	/*
	 * If the conditional ACE composite has mixed types, it can
	 * never equal a claim, which only has one type.
	 */
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {SID(WD), SID(AA), 2}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{SID(AA), SID(WD)}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_composite_mixed_types_deny(void **state)
{
	/*
	 * If the conditional ACE composite has mixed types, it can
	 * never equal a claim, which only has one type.
	 */
	INIT()
	SD("D:(XD;;0x1f;;;AA;(@Device.colour == {2, SID(WD), SID(AA), SID(WD)}))"
		"(D;;;;;WD)");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{SID(AA), SID(WD)}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_different_case(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {\"OraNgE\", \"BLuE\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_different_case_with_case_sensitive_flag(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {\"OraNgE\", \"BLuE\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	/* set the flag bit */
	token.device_claims[0].flags = CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
	DENY_CHECK(0x10);
	DEINIT()
}


static void test_claim_name_different_case(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.Colour == {\"orange\", \"blue\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_claim_name_different_case_case_flag(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.Colour == {\"orange\", \"blue\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	/*
	 * The CASE_SENSITIVE flag is for the values, not the names.
	 */
	token.device_claims[0].flags = CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_more_values_not_equal(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour != {\"orange\", \"blue\", \"green\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_contains(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Contains {\"orange\", \"blue\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_contains_incomplete(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Contains {\"orange\", \"blue\", \"red\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_any_of(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Any_of {\"orange\", \"blue\", \"red\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_any_of_match_last(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Any_of {\"a\", \"b\", \"blue\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_any_of_1(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Any_of\"blue\"))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_contains_1(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Contains \"blue\"))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_contains_1_fail(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Contains \"pink\"))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_any_of_1_fail(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Any_of \"pink\"))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	DENY_CHECK(0x10);
	DEINIT()
}


static void test_not_any_of_1_fail(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Not_Any_of\"blue\"))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_not_any_of_composite_1(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Not_Any_of{\"blue\"}))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_not_contains_1_fail(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Not_Contains \"blue\"))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_not_contains_1(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Not_Contains \"pink\"))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_not_any_of_1(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Not_Any_of \"pink\"))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_not_Not_Any_of_1(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(!(@Device.colour Not_Any_of \"pink\")))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_not_Not_Contains_1(void **state)
{
	INIT()
	SD("D:(XA;;0x1f;;;AA;(! (@Device.colour Not_Contains \"blue\")))");
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	ALLOW_CHECK(0x10);
	DEINIT()
}


static void test_not_not_Not_Member_of(void **state)
{
	INIT();
	SD("D:(XA;;0x1f;;;AA;(!(!(Not_Member_of{SID(BA)}))))");
	USER_SIDS("WD", "AA");
	DEVICE_SIDS("BA", "BG");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_not_not_Not_Member_of_fail(void **state)
{
	INIT();
	SD("D:(XA;;0x1f;;;AA;(!(!(Not_Member_of{SID(AA)}))))");
	USER_SIDS("WD", "AA");
	DEVICE_SIDS("BA", "BG");
	DENY_CHECK(0x10);
	DEINIT()
}

static void test_not_not_not_not_not_not_not_not_not_not_Not_Member_of(void **state)
{
	INIT();
	SD("D:(XA;;0x1f;;;AA;(!(!(!( !(!(!(  !(!(!( "
	   "Not_Member_of{SID(AA)})))))))))))");
	USER_SIDS("WD", "AA");
	DEVICE_SIDS("BA", "BG");
	ALLOW_CHECK(0x10);
	DEINIT()
}


static void test_Device_Member_of_and_Member_of(void **state)
{
	INIT();
	USER_SIDS("WD", "AA");
	DEVICE_SIDS("BA", "BG");
	SD("D:(XA;;0x1f;;;AA;"
	   "(Device_Member_of{SID(BA)} && Member_of{SID(WD)}))");
	ALLOW_CHECK(0x10);
	DEINIT()
}


static void test_Device_claim_contains_Resource_claim(void **state)
{
	INIT();
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "\"blue\"");
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Contains @Resource.colour))"
	   "S:(RA;;;;;WD;(\"colour\",TS,0,\"blue\"))");
	ALLOW_CHECK(0x10);
	DEINIT()
}


static void test_device_claim_contains_resource_claim(void **state)
{
	INIT();
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "\"blue\"");
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Contains @Resource.colour))"
	   "S:(RA;;;;;WD;(\"colour\",TS,0,\"blue\"))");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_device_claim_eq_resource_claim(void **state)
{
	INIT();
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "\"blue\"");
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == @Resource.colour))"
	   "S:(RA;;;;;WD;(\"colour\",TS,0,\"blue\"))");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_user_claim_eq_device_claim(void **state)
{
	INIT();
	USER_SIDS("WD", "AA");
	USER_CLAIMS("colour", "\"blue\"");
	DEVICE_CLAIMS("colour", "\"blue\"");
	SD("D:(XA;;0x1f;;;AA;(@User.colour == @Device.colour))");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_device_claim_eq_resource_claim_2(void **state)
{
	INIT();
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"orange\", \"blue\"}");
	SD("D:(XA;;0x1f;;;AA;(@Device.colour == {\"orange\", \"blue\"}))");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_resource_ace_multi(void **state)
{
	INIT();
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "{\"blue\", \"red\"}");
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Contains @Resource.colour))"
	   "S:(RA;;;;;WD;(\"colour\",TS,0,\"blue\", \"red\"))");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_resource_ace_multi_any_of(void **state)
{
	INIT();
	USER_SIDS("WD", "AA");
	DEVICE_CLAIMS("colour", "\"blue\"");
	SD("D:(XA;;0x1f;;;AA;(@Device.colour Any_of @Resource.colour))"
	   "S:(RA;;;;;WD;(\"colour\",TS,0,\"grue\", \"blue\", \"red\"))");
	ALLOW_CHECK(0x10);
	DEINIT()
}

static void test_horrible_fuzz_derived_test_3(void **state)
{
	INIT();
	USER_SIDS("WD", "AA", "IS");
	SD_FAIL("S:PPD:(XA;OI;0x1;;;IS;(q>))");
	DEINIT()
}

static void test_resource_ace_single(void **state)
{
        INIT();
        USER_SIDS("WD", "AA");
        DEVICE_CLAIMS("colour", "\"blue\"");
        SD("D:(XA;;0x1f;;;AA;(@Device.colour Contains @Resource.colour))"
	   "S:(RA;;;;;WD;(\"colour\",TS,0,\"blue\"))");
        ALLOW_CHECK(0x10);
	DEINIT()
}


static void test_user_attr_any_of_missing_resource_and_user_attr(void **state)
{
        INIT();
        USER_SIDS("WD", "AA");
        DEVICE_CLAIMS("colour", "\"blue\"");
        SD("D:(XD;;FX;;;S-1-1-0;(@User.Project Any_of @Resource.Project))");
        DENY_CHECK(0x10);
	DEINIT()
}

static void test_user_attr_any_of_missing_resource_attr(void **state)
{
        INIT();
        USER_SIDS("WD", "AA");
        USER_CLAIMS("Project", "3");
        SD("D:(XD;;FX;;;S-1-1-0;(@User.Project Any_of @Resource.Project))");
        DENY_CHECK(0x10);
	DEINIT()
}

static void test_user_attr_any_of_missing_user_attr(void **state)
{
        INIT();
        USER_SIDS("WD", "AA");
        SD("D:(XD;;FX;;;S-1-1-0;(@User.Project Any_of @Resource.Project))"
	   "S:(RA;;;;;WD;(\"Project\",TX,0,1234))");
        DENY_CHECK(0x10);
	DEINIT()
}


int main(_UNUSED_ int argc, _UNUSED_ const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_user_attr_any_of_missing_resource_and_user_attr),
		cmocka_unit_test(test_user_attr_any_of_missing_resource_attr),
		cmocka_unit_test(test_user_attr_any_of_missing_user_attr),
		cmocka_unit_test(test_composite_mixed_types),
		cmocka_unit_test(test_composite_mixed_types_different_last),
		cmocka_unit_test(test_composite_mixed_types_deny),
		cmocka_unit_test(test_composite_different_order_with_SID_dupes),
		cmocka_unit_test(test_composite_different_order_with_SID_dupes_in_composite),
		cmocka_unit_test(test_device_claim_eq_resource_claim_2),
		cmocka_unit_test(test_not_Not_Any_of_1),
		cmocka_unit_test(test_not_any_of_composite_1),
		cmocka_unit_test(test_resource_ace_single),
		cmocka_unit_test(test_horrible_fuzz_derived_test_3),
		cmocka_unit_test(test_Device_Member_of_and_Member_of),
		cmocka_unit_test(test_resource_ace_multi),
		cmocka_unit_test(test_resource_ace_multi_any_of),
		cmocka_unit_test(test_user_claim_eq_device_claim),
		cmocka_unit_test(test_device_claim_contains_resource_claim),
		cmocka_unit_test(test_device_claim_eq_resource_claim),
		cmocka_unit_test(test_Device_claim_contains_Resource_claim),
		cmocka_unit_test(test_not_Not_Contains_1),
		cmocka_unit_test(test_not_not_Not_Member_of_fail),
		cmocka_unit_test(test_not_not_Not_Member_of),
		cmocka_unit_test(test_not_not_not_not_not_not_not_not_not_not_Not_Member_of),
		cmocka_unit_test(test_not_any_of_1_fail),
		cmocka_unit_test(test_not_any_of_1),
		cmocka_unit_test(test_not_contains_1),
		cmocka_unit_test(test_not_contains_1_fail),
		cmocka_unit_test(test_any_of_1_fail),
		cmocka_unit_test(test_any_of_1),
		cmocka_unit_test(test_any_of),
		cmocka_unit_test(test_any_of_match_last),
		cmocka_unit_test(test_contains_incomplete),
		cmocka_unit_test(test_contains),
		cmocka_unit_test(test_contains_1),
		cmocka_unit_test(test_contains_1_fail),
		cmocka_unit_test(test_device_claims_composite),
		cmocka_unit_test(test_claim_name_different_case),
		cmocka_unit_test(test_claim_name_different_case_case_flag),
		cmocka_unit_test(test_different_case_with_case_sensitive_flag),
		cmocka_unit_test(test_composite_different_order),
		cmocka_unit_test(test_different_case),
		cmocka_unit_test(test_composite_different_order_with_dupes),
		cmocka_unit_test(test_composite_different_order_with_dupes_in_composite),
		cmocka_unit_test(test_more_values_not_equal),
	};
	if (isatty(1)) {
		/*
		 * interactive testers can set debug level
		 * -- just give it a number.
		 */
		int debug_level = DBGLVL_WARNING;
		if (argc > 1) {
			debug_level = atoi(argv[1]);
		}
		debuglevel_set(debug_level);

	} else {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}
