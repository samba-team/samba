
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <cmocka.h>
#include "includes.h"
#include "talloc.h"
#include "libcli/util/ntstatus.h"
#include "../librpc/gen_ndr/samr.h"
#include "rpc_server/samr/srv_samr_util.h"

/* set SAMR_DEBUG_VERBOSE to true to print more. */
#define SAMR_DEBUG_VERBOSE true

#if SAMR_DEBUG_VERBOSE
#define debug_message(...) print_message(__VA_ARGS__)
#else
#define debug_message(...) /* debug_message */
#endif

static int setup_talloc_context(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	*state = mem_ctx;
	return 0;
}

static int teardown_talloc_context(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	TALLOC_FREE(mem_ctx);
	return 0;
}

struct cmd_expansion {
	const char *lp_cmd;
	const char *username;
	const char *result_cmd;
	NTSTATUS result_code;
};

static struct cmd_expansion expansions[] = {
	{
		"/bin/echo '%u'",
		"bob",
		"/bin/echo 'bob'",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		"bob",
		"/bin/echo 'bob'",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		"bob'",
		"/bin/echo 'bob_'",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		"bob\'",
		"/bin/echo 'bob_'",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		"bob'''",
		"/bin/echo 'bob___'",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		"bob*",
		NULL,
		NT_STATUS_INVALID_USER_PRINCIPAL_NAME
	},
	{
		"/bin/echo %u",
		"bob\"",
		NULL,
		NT_STATUS_INVALID_USER_PRINCIPAL_NAME
	},
	{
		"/bin/echo '%u",
		"bob bob bob",
		"/bin/echo '__CVE-2026-4408_FallbackUsername__",
		NT_STATUS_OK
	},
	{
		"/bin/echo \"%u\"",
		" ",
		"/bin/echo ' '",
		NT_STATUS_OK
	},
	{
		"/bin/echo \"--uu=%u\"",
		"bob",
		"/bin/echo \"--uu=__CVE-2026-4408_FallbackUsername__\"",
		NT_STATUS_OK
	},
	{
		"/bin/echo \"--uu=%u\"",
		"bob !0",
		"/bin/echo \"--uu=__CVE-2026-4408_FallbackUsername__\"",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		"!0",
		"/bin/echo '!0'",
		NT_STATUS_OK
	},
	{
		"/bin/echo \"--uu=%u\"",
		"bob \\",
		NULL,
		NT_STATUS_INVALID_USER_PRINCIPAL_NAME
	},
	{
		"/bin/echo --uu='%u'",
		"bob >> x",
		NULL,
		NT_STATUS_INVALID_USER_PRINCIPAL_NAME
	},
	{
		"/bin/echo '--uu=%u\"",
		"bob",
		"/bin/echo '--uu=__CVE-2026-4408_FallbackUsername__\"",
		NT_STATUS_OK
	},
	{
		"/bin/echo --uu='%u'",
		"bob",
		"/bin/echo --uu='bob'",
		NT_STATUS_OK
	},
	{
		"/bin/echo --uu'=%u'",
		"bob",
		"/bin/echo --uu'=__CVE-2026-4408_FallbackUsername__'",
		NT_STATUS_OK
	},
	{
		"/bin/echo --uu'=%u'",
		"`ls`",
		"/bin/echo --uu'=__CVE-2026-4408_FallbackUsername__'",
		NT_STATUS_OK
	},
	{
		"/bin/echo --uu'=%u'",
		"$(ls)",
		"/bin/echo --uu'=__CVE-2026-4408_FallbackUsername__'",
		NT_STATUS_OK
	},
	{
		"/bin/echo --uu='%u'",
		"$(ls)",
		"/bin/echo --uu='_(ls)'",
		NT_STATUS_OK
	},
	{
		"/bin/echo --uu=\"'%u'\"",
		"bob",
		"/bin/echo --uu=\"'bob'\"",
		NT_STATUS_OK
	},
	{
		"/bin/echo --uu='%u' --yy='%u' '%u' %u",
		"bob",
		"/bin/echo --uu='bob' --yy='bob' 'bob' __CVE-2026-4408_FallbackUsername__",
		NT_STATUS_OK
	},
	{
		"/bin/echo --uu=%u%u'' %user 50%u",
		"bob",
		"/bin/echo --uu=__CVE-2026-4408_FallbackUsername____CVE-2026-4408_FallbackUsername__'' __CVE-2026-4408_FallbackUsername__ser 50__CVE-2026-4408_FallbackUsername__",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		"!!",
		"/bin/echo '!!'",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		">xxx",
		NULL,
		NT_STATUS_INVALID_USER_PRINCIPAL_NAME
	},
	{
		"/bin/echo %u",
		"\\",
		NULL,
		NT_STATUS_INVALID_USER_PRINCIPAL_NAME
	},
	{
		"/bin/echo %u",
		"3",
		"/bin/echo '3'",
		NT_STATUS_OK
	},
	{
		"/bin/echo '%u'",
		"3$",
		"/bin/echo '3_'",
		NT_STATUS_OK
	},
	{
		"/bin/echo '%u'",
		"comp$",
		"/bin/echo 'comp_'",
		NT_STATUS_OK
	},
	{
		"/bin/echo '%u'",
		"3$3",
		"/bin/echo '3_3'",
		NT_STATUS_OK
	},
	{
		"/bin/echo '%u'",
		"q $3",
		"/bin/echo 'q _3'",
		NT_STATUS_OK
	},
	{
		"/bin/echo -s '%u' %u",
		"āāā",
		"/bin/echo -s 'āāā' __CVE-2026-4408_FallbackUsername__",
		NT_STATUS_OK
	},
	{
		"/bin/echo -s '%u' %u",
		"-āāā",
		"/bin/echo -s '_āāā' __CVE-2026-4408_FallbackUsername__",
		NT_STATUS_OK
	},
	{
		"/bin/echo -s %u",
		"āāā",
		"/bin/echo -s 'āāā'",
		NT_STATUS_OK
	},
	{
		"/bin/echo -s %u",
		"a -a",
		"/bin/echo -s 'a -a'",
		NT_STATUS_OK
	},
	{
		"/bin/echo -s=%u %u",
		"ā -a",
		"/bin/echo -s='ā -a' 'ā -a'",
		NT_STATUS_OK
	},
	{
		"/bin/echo -s=\"%u %u\"",
		"ā -a",
		"/bin/echo -s=\"__CVE-2026-4408_FallbackUsername__ __CVE-2026-4408_FallbackUsername__\"",
		NT_STATUS_OK
	},
	{
		"/bin/echo -m='fridge' %u",
		"ā -x -ß",
		"/bin/echo -m='fridge' __CVE-2026-4408_FallbackUsername__",
		NT_STATUS_OK
	},
	{
		"/bin/echo -m='fridge' %u",
		"-ā -a",
		"/bin/echo -m='fridge' __CVE-2026-4408_FallbackUsername__",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		"-n",
		"/bin/echo '_n'",
		NT_STATUS_OK
	},
	{
		"/bin/echo %u",
		"o'clock",
		"/bin/echo 'o_clock'",
		NT_STATUS_OK
	},
};

static void test_expansions(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(expansions); i++) {
		struct cmd_expansion t = expansions[i];
		char *result_cmd = NULL;
		NTSTATUS status;

		status = check_password_complexity_internal(mem_ctx,
							    t.lp_cmd,
							    t.username,
							    &result_cmd);
		if (NT_STATUS_IS_OK(t.result_code) && NT_STATUS_IS_OK(status)) {
			int cmp;

			cmp = strcmp(t.result_cmd, result_cmd);
			if (cmp == 0) {
				debug_message("[%zu] «%s» «%s»   ->   «%s», nstatus %s; AS EXPECTED\n",
					      i, t.lp_cmd,
					      t.username,
					      result_cmd,
					      nt_errstr(status));
			} else {
				debug_message("[%zu] «%s» «%s», nstatus %s; "
					      "expected   «%s»   got  «%s»\033[1;31m BAD! \033[0m\n",
					      i, t.lp_cmd,
					      t.username,
					      nt_errstr(status),
					      t.result_cmd,
					      result_cmd);
			}
			assert_int_equal(cmp, 0);
		} else if (NT_STATUS_EQUAL(status, t.result_code)) {
			debug_message("[%zu] «%s» «%s», nstatus %s FAILED AS EXPECTED\n",
				      i, t.lp_cmd,
				      t.username,
				      nt_errstr(status));
		} else {
			debug_message("[%zu] «%s» «%s» -> «%s», nstatus %s; "
				      "EXPECTED result «%s»   ntstatus %s; \033[1;31m BAD! \033[0m\n",
				      i, t.lp_cmd,
				      t.username,
				      result_cmd,
				      nt_errstr(status),
				      t.result_cmd,
				      nt_errstr(t.result_code));
			assert_int_equal(true, false);
		}
	}
	debug_message("ALL correct\n");
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_expansions),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests,
				      setup_talloc_context,
				      teardown_talloc_context);
}
