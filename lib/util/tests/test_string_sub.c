
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/stat.h>
#include "replace.h"
#include <cmocka.h>
#include "talloc.h"

#include "../substitute.h"

/* set _DEBUG_VERBOSE to print more. */
#define _DEBUG_VERBOSE

#ifdef _DEBUG_VERBOSE
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
	bool modified;
	bool masked;
	bool mixed_fallback;
};

static void _test_talloc_string_sub_unsafe(void **state,
					   struct cmd_expansion expansions[],
					   size_t n_expansions,
					   const char *unsafe_characters)
{
	TALLOC_CTX *mem_ctx = *state;
	size_t i;

	for (i = 0; i < n_expansions; i++) {
		struct cmd_expansion t = expansions[i];
		char *result_cmd = NULL;
		bool masked;
		bool mixed_fallback;
		bool modified;
		bool flags_correct;
		bool mixed;
		int cmp;

		mixed = talloc_string_sub_mixed_quoting(t.lp_cmd, 'u');

		result_cmd = talloc_string_sub_unsafe(mem_ctx,
						      t.lp_cmd,
						      'u',
						      t.username,
						      unsafe_characters,
						      '_',
						      "FallbackUsername",
						      &modified,
						      &masked,
						      &mixed_fallback);
		assert_ptr_not_equal(result_cmd, NULL);
		assert_ptr_not_equal(t.result_cmd, NULL);

		cmp = strcmp(t.result_cmd, result_cmd);
		flags_correct = (modified == t.modified &&
				 masked == t.masked &&
				 mixed_fallback == t.mixed_fallback);

		if (cmp == 0) {
			debug_message("[%zu] «%s» «%s»   ->   «%s»; AS EXPECTED\n",
				      i, t.lp_cmd,
				      t.username,
				      result_cmd);
		} else {
			debug_message("[%zu] «%s» «%s»; "
				      "expected   [%zu] «%s»   got  [%zu] «%s»\033[1;31m BAD! \033[0m\n",
				      i, t.lp_cmd,
				      t.username,
				      strlen(t.result_cmd), t.result_cmd,
				      strlen(result_cmd), result_cmd);
		}
		assert_int_equal(cmp, 0);
		if (!flags_correct) {
			debug_message("[%zu] ", i);
#define _FLAG(x) debug_message((t. x  == x) ? "%s: %s √; ":		\
			       "%s \033[1;31m expected %s \033[0m; ",	\
			       #x, t.x ? "true": "false");
			_FLAG(modified);
			_FLAG(masked);
			_FLAG(mixed_fallback);
			debug_message("\n");
		}
		assert_int_equal(flags_correct, true);
		if (mixed_fallback != mixed) {
			debug_message("[%zu] %s mixed \033[1;31m expected %s \033[0m; ",
				      i, t.lp_cmd,
				      mixed_fallback ? "true": "false");
		}
		assert_int_equal(mixed_fallback, mixed);
#undef _FLAG
	}
	debug_message("ALL correct\n");
}

static void test_talloc_string_sub_unsafe(void **state)
{
	const char *unsafe_characters = STRING_SUB_UNSAFE_CHARACTERS;

	static struct cmd_expansion expansions[] = {
		{
			"/bin/echo \"bob'",
			"bob",
			"/bin/echo \"bob'",
			false,
			false,
			false,
		},
		{
			"/bin/echo '%u'",
			"bob",
			"/bin/echo 'bob'",
			true,
			false,
			false,
		},
		{
			"/bin/echo %u",
			"bob",
			"/bin/echo 'bob'",
			true,
			false,
			false,
		},
		{
			"/bin/echo %u",
			"bob'",
			"/bin/echo 'bob_'",
			true,
			true,
			false,
		},
		{
			"/bin/echo %u",
			"bob'''",
			"/bin/echo 'bob___'",
			true,
			true,
			false,
		},
		{
			"/bin/echo %u",
			"bob\'",
			"/bin/echo 'bob_'",
			true,
			true,
			false,
		},
		{
			"/bin/echo '%u",
			"bob bob bob",
			"/bin/echo 'FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo \"%u\"",
			" ",
			"/bin/echo ' '",
			true,
			false,
			false,
		},
		{
			"/bin/echo \"--uu=%u\"",
			"bob",
			"/bin/echo \"--uu=FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo \"--uu=%u\"",
			"bob !0",
			"/bin/echo \"--uu=FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo %u",
			"!0",
			"/bin/echo '!0'",
			true,
			false,
			false,
		},
		{
			"/bin/echo \"--uu=%u\"",
			"bob \\",
			"/bin/echo \"--uu=FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu='%u'",
			"bob >> x",
			"/bin/echo --uu='bob __ x'",
			true,
			true,
			false,
		},
		{
			"/bin/echo '--uu=%u\"",
			"bob",
			"/bin/echo '--uu=FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu='%u'",
			"bob",
			"/bin/echo --uu='bob'",
			true,
			false,
			false,
		},
		{
			"/bin/echo --uu'=%u'",
			"bob",
			"/bin/echo --uu'=FallbackUsername'",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu'=%u'",
			"`ls`",
			"/bin/echo --uu'=FallbackUsername'",
			true,
			true,
			true,
		},
		{
			"/bin/echo --uu='%u'",
			"u%u%u%u%u",
			"/bin/echo --uu='u_u_u_u_u'",
			true,
			true,
			false,
		},
		{
			"/bin/echo --uu='%u'",
			"$(ls)",
			"/bin/echo --uu='_(ls)'",
			true,
			true,
			false,
		},
		{
			"/bin/echo --uu='%u'",
			"`ls`",
			"/bin/echo --uu='_ls_'",
			true,
			true,
			false,
		},
		{
			"/bin/echo --uu='1' %u",
			"`ls`",
			"/bin/echo --uu='1' FallbackUsername",
			true,
			true,
			true,
		},
		{
			"/bin/echo --uu=\"'%u'\"",
			"bob",
			"/bin/echo --uu=\"'bob'\"",
			true,
			false,
			false,
		},
		{
			"/bin/echo --uu='%u' --yy='%u' '%u' %u",
			"bob",
			"/bin/echo --uu='bob' --yy='bob' 'bob' FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu=%u%u%u'' %user 50%u",
			"bob",
			"/bin/echo --uu=FallbackUsernameFallbackUsernameFallbackUsername'' FallbackUsernameser 50FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo %u",
			"!!",
			"/bin/echo '!!'",
			true,
			false,
			false,
		},
		{
			"/bin/echo %u",
			">xxx",
			"/bin/echo '_xxx'",
			true,
			true,
			false,
		},
		{
			"/bin/echo %u",
			"3",
			"/bin/echo '3'",
			true,
			false,
			false,
		},
		{
			"/bin/echo '%u'",
			"3$",
			"/bin/echo '3_'",
			true,
			true,
			false,
		},
		{
			"/bin/echo '%u'",
			"comp$",
			"/bin/echo 'comp_'",
			true,
			true,
			false,
		},
		{
			"/bin/echo '%u'",
			"3$3",
			"/bin/echo '3_3'",
			true,
			true,
			false,
		},
		{
			"/bin/echo '%u'",
			"q $3",
			"/bin/echo 'q _3'",
			true,
			true,
			false,
		},
		{
			"/bin/echo '%u",
			"q $3",
			"/bin/echo 'FallbackUsername",
			true,
			true,
			true,
		},
		{
			"/bin/echo -s '%u' %u",
			"āāā",
			"/bin/echo -s 'āāā' FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo -s '%u' %u",
			"-āāā",
			"/bin/echo -s '_āāā' FallbackUsername",
			true,
			true,
			true,
		},
		{
			"/bin/echo -s %u",
			"āāā",
			"/bin/echo -s 'āāā'",
			true,
			false,
			false,
		},
		{
			"/bin/echo -s %u",
			"a -a",
			"/bin/echo -s 'a -a'",
			true,
			false,
			false,
		},
		{
			"/bin/echo -s=%u %u",
			"ā -a",
			"/bin/echo -s='ā -a' 'ā -a'",
			true,
			false,
			false,
		},
		{
			"/bin/echo -s=\"%u %u\"",
			"ā -a",
			"/bin/echo -s=\"FallbackUsername FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo -m='fridge' %u",
			"ā  -ß",
			"/bin/echo -m='fridge' FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo -m='fridge' %u",
			"-ā -a",
			"/bin/echo -m='fridge' FallbackUsername",
			true,
			true,
			true,
		},
		{
			"/bin/echo %u",
			"-n",
			"/bin/echo '_n'",
			true,
			true,
			false,
		},
		{
			"/bin/echo %u",
			"o'clock",
			"/bin/echo 'o_clock'",
			true,
			true,
			false,
		},
		{
			"/bin/echo \"bob'",
			"bob",
			"/bin/echo \"bob'",
			false,
			false,
			false,
		},
		{
			"/bin/echo \"%u\"",
			"%u",
			"/bin/echo '_u'",
			true,
			true,
			false,
		},
		{
			"/bin/echo \"$(ls)\"",
			"%u",
			"/bin/echo \"$(ls)\"",
			false,
			false,
			false,
		},
		{
			"/bin/echo %u",
			"\\",
			"/bin/echo '\\'",
			true,
			false,
			false,
		},
		{
			"/bin/echo '%u'",
			"\\",
			"/bin/echo '\\'",
			true,
			false,
			false,
		},
		{
			"/bin/echo \"%u\"",
			"\\",
			"/bin/echo '\\'",
			true,
			false,
			false,
		},
		{
			"/bin/echo \"%u\" %u",
			"\\",
			"/bin/echo '\\' FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo '%u' \"%u\" %u",
			"\\",
			"/bin/echo '\\' \"FallbackUsername\" FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo '%u' \"%u\"",
			"bob",
			"/bin/echo 'bob' \"FallbackUsername\"",
			true,
			false,
			true,
		},
	};

	_test_talloc_string_sub_unsafe(state,
				       expansions,
				       ARRAY_SIZE(expansions),
				       unsafe_characters);
}

static void test_talloc_string_sub_unsafe_minimal_unsafe_chars(void **state)
{
	const char *unsafe_characters = "\"'%";

	static struct cmd_expansion expansions[] = {
		{
			"/bin/echo \"bob'",
			"bob",
			"/bin/echo \"bob'",
			false,
			false,
			false,
		},
		{
			"/bin/echo '%u'",
			"bob",
			"/bin/echo 'bob'",
			true,
			false,
			false,
		},
		{
			"/bin/echo %u",
			"bob",
			"/bin/echo 'bob'",
			true,
			false,
			false,
		},
		{
			"/bin/echo %u",
			"bob'",
			"/bin/echo 'bob_'",
			true,
			true,
			false,
		},
		{
			"/bin/echo %u",
			"bob'''",
			"/bin/echo 'bob___'",
			true,
			true,
			false,
		},
		{
			"/bin/echo %u",
			"bob\'",
			"/bin/echo 'bob_'",
			true,
			true,
			false,
		},
		{
			"/bin/echo '%u",
			"bob bob bob",
			"/bin/echo 'FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo \"%u\"",
			" ",
			"/bin/echo ' '",
			true,
			false,
			false,
		},
		{
			"/bin/echo \"--uu=%u\"",
			"bob",
			"/bin/echo \"--uu=FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo \"--uu=%u\"",
			"bob !0",
			"/bin/echo \"--uu=FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo %u",
			"!0",
			"/bin/echo '!0'",
			true,
			false,
			false,
		},
		{
			"/bin/echo \"--uu=%u\"",
			"bob \\",
			"/bin/echo \"--uu=FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu='%u'",
			"bob >> x",
			"/bin/echo --uu='bob >> x'",
			true,
			false,
			false,
		},
		{
			"/bin/echo '--uu=%u\"",
			"bob",
			"/bin/echo '--uu=FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu='%u'",
			"bob",
			"/bin/echo --uu='bob'",
			true,
			false,
			false,
		},
		{
			"/bin/echo --uu'=%u'",
			"bob",
			"/bin/echo --uu'=FallbackUsername'",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu'=%u'",
			"`ls`",
			"/bin/echo --uu'=FallbackUsername'",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu='%u'",
			"u%u%u%u%u",
			"/bin/echo --uu='u_u_u_u_u'",
			true,
			true,
			false,
		},
		{
			"/bin/echo --uu='%u'",
			"$(ls)",
			"/bin/echo --uu='$(ls)'",
			true,
			false,
			false,
		},
		{
			"/bin/echo --uu='%u'",
			"`ls`",
			"/bin/echo --uu='`ls`'",
			true,
			false,
			false,
		},
		{
			"/bin/echo --uu='1' %u",
			"`ls`",
			"/bin/echo --uu='1' FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu=\"'%u'\"",
			"bob",
			"/bin/echo --uu=\"'bob'\"",
			true,
			false,
			false,
		},
		{
			"/bin/echo --uu='%u' --yy='%u' '%u' %u",
			"bob",
			"/bin/echo --uu='bob' --yy='bob' 'bob' FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo --uu=%u%u%u'' %user 50%u",
			"bob",
			"/bin/echo --uu=FallbackUsernameFallbackUsernameFallbackUsername'' FallbackUsernameser 50FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo %u",
			"!!",
			"/bin/echo '!!'",
			true,
			false,
			false,
		},
		{
			"/bin/echo %u",
			">xxx",
			"/bin/echo '>xxx'",
			true,
			false,
			false,
		},
		{
			"/bin/echo %u",
			"3",
			"/bin/echo '3'",
			true,
			false,
			false,
		},
		{
			"/bin/echo '%u'",
			"3$",
			"/bin/echo '3$'",
			true,
			false,
			false,
		},
		{
			"/bin/echo '%u'",
			"comp$",
			"/bin/echo 'comp$'",
			true,
			false,
			false,
		},
		{
			"/bin/echo '%u'",
			"3$3",
			"/bin/echo '3$3'",
			true,
			false,
			false,
		},
		{
			"/bin/echo '%u'",
			"q $3",
			"/bin/echo 'q $3'",
			true,
			false,
			false,
		},
		{
			"/bin/echo '%u",
			"q $3",
			"/bin/echo 'FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo -s '%u' %u",
			"āāā",
			"/bin/echo -s 'āāā' FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo -s '%u' %u",
			"-āāā",
			"/bin/echo -s '_āāā' FallbackUsername",
			true,
			true,
			true,
		},
		{
			"/bin/echo -s %u",
			"āāā",
			"/bin/echo -s 'āāā'",
			true,
			false,
			false,
		},
		{
			"/bin/echo -s %u",
			"a -a",
			"/bin/echo -s 'a -a'",
			true,
			false,
			false,
		},
		{
			"/bin/echo -s=%u %u",
			"ā -a",
			"/bin/echo -s='ā -a' 'ā -a'",
			true,
			false,
			false,
		},
		{
			"/bin/echo -s=\"%u %u\"",
			"ā -a",
			"/bin/echo -s=\"FallbackUsername FallbackUsername\"",
			true,
			false,
			true,
		},
		{
			"/bin/echo -m='fridge' %u",
			"ā  -ß",
			"/bin/echo -m='fridge' FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo -m='fridge' %u",
			"-ā -a",
			"/bin/echo -m='fridge' FallbackUsername",
			true,
			true,
			true,
		},
		{
			"/bin/echo %u",
			"-n",
			"/bin/echo '_n'",
			true,
			true,
			false,
		},
		{
			"/bin/echo %u",
			"o'clock",
			"/bin/echo 'o_clock'",
			true,
			true,
			false,
		},
		{
			"/bin/echo \"bob'",
			"bob",
			"/bin/echo \"bob'",
			false,
			false,
			false,
		},
		{
			"/bin/echo \"%u\"",
			"%u",
			"/bin/echo '_u'",
			true,
			true,
			false,
		},
		{
			"/bin/echo \"$(ls)\"",
			"%u",
			"/bin/echo \"$(ls)\"",
			false,
			false,
			false,
		},
		{
			"/bin/echo %u",
			"\\",
			"/bin/echo '\\'",
			true,
			false,
			false,
		},
		{
			"/bin/echo '%u'",
			"\\",
			"/bin/echo '\\'",
			true,
			false,
			false,
		},
		{
			"/bin/echo \"%u\"",
			"\\",
			"/bin/echo '\\'",
			true,
			false,
			false,
		},
		{
			"/bin/echo \"%u\" %u",
			"\\",
			"/bin/echo '\\' FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo '%u' \"%u\" %u",
			"\\",
			"/bin/echo '\\' \"FallbackUsername\" FallbackUsername",
			true,
			false,
			true,
		},
		{
			"/bin/echo '%u' \"%u\"",
			"bob",
			"/bin/echo 'bob' \"FallbackUsername\"",
			true,
			false,
			true,
		},
	};

	_test_talloc_string_sub_unsafe(state,
				       expansions,
				       ARRAY_SIZE(expansions),
				       unsafe_characters);
}

static void test_talloc_string_sub_unsafe_all_mixes(void **state)
{
	const char *unsafe_characters = STRING_SUB_UNSAFE_CHARACTERS;
	size_t i;

	for (i = 0; i < 32; i++) {
		char in[100] = { 0, };
		char out[100] = { 0, };
		struct cmd_expansion expansions[] = {
			{
				in,
				"bob",
				out,
				true,
				false,
				false,
			},
		};
		bool vsq = i & 1;
		bool vdq = i & 2;
		bool v = i & 4;
		bool sq = i & 8;
		bool dq = i & 16;
		char *inp = in;
		char *outp = out;
		if (vsq) {
			inp = stpcpy(inp, "'%u' ");
			outp = stpcpy(outp, "'bob' ");
			debug_message("vsq ");
		}
		if (vdq) {
			inp = stpcpy(inp, "\"%u\" ");
			outp = stpcpy(outp, (vsq || sq) ? "\"FallbackUsername\" " : "'bob' ");
			debug_message("vdq ");
			if (vsq || sq) {
				expansions[0].mixed_fallback = true;
			}
		}
		if (v) {
			inp = stpcpy(inp, "%u ");
			outp = stpcpy(outp, (vsq || vdq || sq || dq) ? "FallbackUsername " : "'bob' ");
			debug_message("v ");
			if (vsq || vdq || sq || dq) {
				expansions[0].mixed_fallback = true;
			}
		}
		if (sq) {
			inp = stpcpy(inp, "' ");
			outp = stpcpy(outp, "' ");
			debug_message("sq ");
		}
		if (dq) {
			inp = stpcpy(inp, "\" ");
			outp = stpcpy(outp, "\" ");
			debug_message("dq ");
		}
		debug_message("(i: %zu)\n", i);
		*inp = '\0';
		*outp = '\0';
		expansions[0].modified = strcmp(in, out) != 0;

		_test_talloc_string_sub_unsafe(state,
					       expansions,
					       ARRAY_SIZE(expansions),
					       unsafe_characters);
	}
}


int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_talloc_string_sub_unsafe),
		cmocka_unit_test(test_talloc_string_sub_unsafe_minimal_unsafe_chars),
		cmocka_unit_test(test_talloc_string_sub_unsafe_all_mixes),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests,
				      setup_talloc_context,
				      teardown_talloc_context);
}
