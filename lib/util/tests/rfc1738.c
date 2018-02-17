#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include "lib/replace/replace.h"

#include <errno.h>
#include <unistd.h>
#include <talloc.h>
#include <ctype.h>
#include <string.h>
#include "lib/util/samba_util.h"

/* These flags say what can be asserted about a relationship between a string
   and its supposedly escaped equivalent.

   The first part of the flag name indicates the direction of transformation;
   tyhe second part is the expected result. For example, ESCAPE_EQ means the
   escape is expected to succeed and result is expected to be equal to the
   given answer. ESCAPE_EQ_CASECMP is only equal when compared
   case-insensitively. UNESCAPE_ERR means unescaping the escaped string should
   result in an error.
*/
#define UNESCAPE_ERR 1
#define ESCAPE_ERR 2
#define ESCAPE_EQ 4
#define UNESCAPE_EQ 8
#define ESCAPE_NE 16
#define UNESCAPE_NE 32
#define ESCAPE_EQ_CASECMP 64

struct rfc1738_test {
	const char *escaped;   /* original for unescape; result for escape  */
	const char *unescaped; /* result in unescape; original for escape */
	uint32_t flags;   /* see above */
	int unesc_len;    /* end - start will be this */
	int unesc_strlen; /* strlen() will say this */
	int esc_len;      /* escaped string length */
};

/* unreserved = ALPHA DIGIT - . _ ~       */

char spectrum[255 + 1];
char spectrum_escaped[255 * 3 + 1];

struct rfc1738_test examples[] = {

#define SIMPLE1 "this_is_a_simple-string._With_no_escapes~" /* maps to self */
	{
		SIMPLE1,
		SIMPLE1,
		ESCAPE_EQ | UNESCAPE_EQ, /* round trip should work */
		sizeof(SIMPLE1) - 1,
		sizeof(SIMPLE1) - 1,
		sizeof(SIMPLE1) - 1,
	},
#define SIMPLE2 "no escapes, but\n non-printables \xc5\x8d\x99"
#define SIMPLE2_ESC "no%20escapes%2C%20but%0A%20non-printables%20%C5%8D%99"
	{
		SIMPLE2_ESC,
		SIMPLE2,
		ESCAPE_EQ | UNESCAPE_EQ,
		sizeof(SIMPLE2) - 1,
		sizeof(SIMPLE2) - 1,
		sizeof(SIMPLE2_ESC) - 1,
	},
#define SIMPLE3 "this @#$^&*()_+{}:;"
#define SIMPLE3_ESC "this%20%40%23%24%5E%26%2A%28%29_%2B%7B%7D%3A%3B"
	{
		SIMPLE3_ESC,
		SIMPLE3,
		ESCAPE_EQ | UNESCAPE_EQ,
		sizeof(SIMPLE3) - 1,
		sizeof(SIMPLE3) - 1,
		sizeof(SIMPLE3_ESC) - 1,
	},

#define ESCAPE1 "%/\x06this string has expected escapes"
#define ESCAPE1_ESC "%25%2F%06this%20string%20has%20expected%20escapes"
#define ESCAPE1_ESC_ESC "%2525%252F%2506this%2520string%2520has%2520expected"\
	"%2520escapes"
	{
		ESCAPE1_ESC,
		ESCAPE1,
		ESCAPE_EQ | UNESCAPE_EQ,
		sizeof(ESCAPE1) - 1,
		sizeof(ESCAPE1) - 1,
		sizeof(ESCAPE1_ESC) - 1,
	},
	{
		ESCAPE1_ESC_ESC, /*re-escaping */
		ESCAPE1_ESC,
		ESCAPE_EQ | UNESCAPE_EQ,
		sizeof(ESCAPE1_ESC) - 1,
		sizeof(ESCAPE1_ESC) - 1,
		sizeof(ESCAPE1_ESC_ESC) - 1,
	},
#define ESCAPE2 "%25%2f%06-this-string-has-expected-lowercase-escapes-%ab"
#define ESCAPE2_UNESC "%/\x06-this-string-has-expected-lowercase-escapes-\xab"
	{
		ESCAPE2,
		ESCAPE2_UNESC,
		ESCAPE_EQ_CASECMP | UNESCAPE_EQ, /* escape won't match case */
		sizeof(ESCAPE2_UNESC) - 1,
		sizeof(ESCAPE2_UNESC) - 1,
		sizeof(ESCAPE2) - 1,
	},
#define ESCAPE3 "%25%2f%06 %32 %44 %6a%AA THIS string h%61s random escapes %ab"
#define ESCAPE3_UNESC "%/\x06 2 D j\xAA THIS string has random escapes \xab"
	{
		ESCAPE3,
		ESCAPE3_UNESC,
		ESCAPE_NE | UNESCAPE_EQ, /* escape will have escaped spaces */
		sizeof(ESCAPE3_UNESC) - 1,
		sizeof(ESCAPE3_UNESC) - 1,
		sizeof(ESCAPE3) - 1,
	},
#define ESCAPE4 "%25%25%25" /*  */
#define ESCAPE4_UNESC "%%%" /*  */
#define ESCAPE4_ESC "%2525%2525%2525"
	{
		ESCAPE4,
		ESCAPE4_UNESC,
		ESCAPE_EQ | UNESCAPE_EQ,
		sizeof(ESCAPE4_UNESC) - 1,
		sizeof(ESCAPE4_UNESC) - 1,
		sizeof(ESCAPE4) - 1,
	},
	{
		ESCAPE4_ESC,
		ESCAPE4,
		ESCAPE_EQ | UNESCAPE_EQ,
		sizeof(ESCAPE4) - 1,
		sizeof(ESCAPE4) - 1,
		sizeof(ESCAPE4_ESC) - 1,
	},
#define BAD1 "trailing percent is bad %"
#define BAD1_ESC "trailing%20percent%20is%20bad%20%25"
	{
		BAD1_ESC,
		BAD1,
		UNESCAPE_EQ |ESCAPE_EQ,
		sizeof(BAD1) - 1,
		sizeof(BAD1) - 1,
		sizeof(BAD1_ESC) - 1,
	},
	{
		BAD1,
		NULL,
		UNESCAPE_ERR,
		0,
		0,
		sizeof(BAD1) - 1,
	},
#define BAD2 "trailing percent is bad %1"
#define BAD3 "bad characters %1 "
	{
		BAD2,
		NULL,
		UNESCAPE_ERR,
		0,
		0,
		sizeof(BAD2) - 1,
	},
	{
		BAD3,
		NULL,
		UNESCAPE_ERR,
		0,
		0,
		sizeof(BAD3) - 1,
	},
#define BAD4 "bad characters %1 "
	{
		BAD4,
		NULL,
		UNESCAPE_ERR,
		0,
		0,
		sizeof(BAD4) - 1,
	},
#define BAD5 "bad characters %1- "
	{
		BAD5,
		NULL,
		UNESCAPE_ERR,
		0,
		0,
		sizeof(BAD5) - 1,
	},
#define BAD6 "bad characters %1G "
	{
		BAD6,
		NULL,
		UNESCAPE_ERR,
		0,
		0,
		sizeof(BAD6) - 1,
	},
#define BAD7 "bad characters %%1 "
	{
		BAD7,
		NULL,
		UNESCAPE_ERR,
		0,
		0,
		sizeof(BAD7) - 1,
	},
#define BAD8 "bad characters %sb "
	{
		BAD8,
		NULL,
		UNESCAPE_ERR,
		0,
		0,
		sizeof(BAD8) - 1,
	},
#define BAD_SSCANF "sscanf would be happy with this\n"
#define BAD_SSCANF_ESC "sscanf would be happy with this% a"
	{
		BAD_SSCANF_ESC,
		BAD_SSCANF,
		ESCAPE_NE | UNESCAPE_ERR,
		sizeof(BAD_SSCANF) - 1,
		sizeof(BAD_SSCANF) - 1,
		sizeof(BAD_SSCANF_ESC) - 1,
	},
	/* now try some with zeros in. escaping can't see past zeros, and the result is truncated */
#define ZERO "%00"
#define ZERO_UNESC "\0"
	{
		ESCAPE4 ZERO ESCAPE4,
		ESCAPE4_UNESC ZERO_UNESC ESCAPE4_UNESC,
		ESCAPE_NE | UNESCAPE_EQ,
		sizeof(ESCAPE4_UNESC ZERO_UNESC ESCAPE4_UNESC) - 1,
		sizeof(ESCAPE4_UNESC) - 1,
		sizeof(ESCAPE4 ZERO ESCAPE4) - 1,
	},
	{
		ZERO ESCAPE4,
		ZERO_UNESC ESCAPE4_UNESC,
		ESCAPE_NE | UNESCAPE_EQ,
		sizeof(ZERO_UNESC ESCAPE4_UNESC) - 1,
		0,
		sizeof(ZERO ESCAPE4) - 1,
	},
	{
		ZERO,
		ZERO_UNESC,
		ESCAPE_NE | UNESCAPE_EQ,
		sizeof(ZERO_UNESC) - 1,
		0,
		sizeof(ZERO) - 1,
	},
	{
		spectrum_escaped,
		spectrum,
		ESCAPE_EQ | UNESCAPE_EQ,
		255,
		255,
		255 * 3,
	},
};

static struct rfc1738_test * dup_test(struct rfc1738_test *src)
{
	struct rfc1738_test *dest = malloc(sizeof(*dest));
	char *esc = NULL, *unesc = NULL;
	if (dest == NULL) {
		return NULL;
	}
	*dest = *src;
	if (src->esc_len) {
		esc = malloc(src->esc_len + 1);
		if (esc == NULL) {
			free(dest);
			return NULL;
		}
		memcpy(esc, src->escaped, src->esc_len + 1);
		dest->escaped = esc;
	}

	if (src->unesc_len) {
		unesc = malloc(src->unesc_len + 1);
		if (unesc == NULL) {
			free(esc);
			free(dest);
			return NULL;
		}
		memcpy(unesc, src->unescaped, src->unesc_len + 1);
		dest->unescaped = unesc;
	}

	return dest;
}

static void free_test(struct rfc1738_test *t)
{
	free(discard_const_p(char, t->escaped));
	free(discard_const_p(char, t->unescaped));
	free(t);
}


static void test_unescape(void **state)
{
	uint i;
	char *s, *e;
	struct rfc1738_test *test, *orig;
	for (i = 0; i < ARRAY_SIZE(examples); i++) {
		orig = &examples[i];
		if ((orig->flags & (UNESCAPE_ERR |
				    UNESCAPE_EQ |
				    UNESCAPE_NE)) == 0) {
			continue;
		}
		test = dup_test(&examples[i]);
		s = discard_const_p(char, test->escaped);
		e = rfc1738_unescape(s);
		if (test->flags & UNESCAPE_ERR) {
			assert_null(e);
			free_test(test);
			continue;
		}
		assert_non_null(e);
		assert_int_equal(e - s, test->unesc_len);

		if (test->flags & UNESCAPE_EQ) {
			assert_memory_equal(s,
					    orig->unescaped,
					    orig->unesc_len);
			assert_int_equal(strlen(s),
					 orig->unesc_strlen);
		} else {
			assert_memory_not_equal(s,
						orig->unescaped,
						orig->unesc_len);
			assert_int_equal(strlen(s),
					 orig->unesc_strlen);
		}
		free_test(test);
	}
}

static void test_escape(void **state)
{
	uint i;
	char *s, *e;
	struct rfc1738_test *test, *orig;
	for (i = 0; i < ARRAY_SIZE(examples); i++) {
		orig = &examples[i];
		if ((orig->flags & (ESCAPE_EQ |
				    ESCAPE_EQ_CASECMP |
				    ESCAPE_NE)) == 0) {
			continue;
		}
		test = dup_test(&examples[i]);
		s = discard_const_p(char, test->unescaped);
		e = rfc1738_escape_part(NULL, s);
		if (test->flags & ESCAPE_EQ) {
			assert_memory_equal(e, test->escaped,
					    test->esc_len + 1);
		} else if (test->flags & ESCAPE_EQ_CASECMP) {
			int cmp = strcasecmp(e, test->escaped);
			assert_int_equal(cmp, 0);
			assert_string_not_equal(e, test->escaped);
		} else {
			assert_string_not_equal(e, test->escaped);
		}
		free_test(test);
	}
}


static void gen_spectrum(void)
{
	int i, j = 0;
	const char *lut = "0123456789ABCDEF";
	for (i = 1; i < 256; i++) {
		spectrum[i - 1] = i;
		if (isalnum(i) ||
		    i == '-'   ||
		    i == '.'   ||
		    i == '_'   ||
		    i == '-'   ||
		    i == '~') {
			spectrum_escaped[j] = i;
			j++;
		} else {
			spectrum_escaped[j] = '%';
			spectrum_escaped[j + 1] = lut[i >> 4];
			spectrum_escaped[j + 2] = lut[i & 15];
			j += 3;
		}
	}
	spectrum[i - 1] = '\0';
	spectrum_escaped[j] = '\0';
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_escape),
		cmocka_unit_test(test_unescape),
	};

	gen_spectrum();
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
