#include "includes.h"
#include "torture/ndr/ndr.h"
#include "torture/ndr/proto.h"
#include "../lib/util/dlinklist.h"
#include "param/param.h"

static const char *ascii = "ascii";
/* the following is equivalent to "kamelåså öäüÿéèóò" in latin1 */
static const char latin1[] = { 0x6b, 0x61, 0x6d, 0x65, 0x6c, 0xe5, 0x73,
			       0xe5, 0x20, 0xF6, 0xE4, 0xFC, 0xFF, 0xE9,
			       0xE8, 0xF3, 0xF2, 0x00 };
/* the following is equivalent to "kamelåså ☺☺☺ öäüÿéèóò" in utf8 */
static const char utf8[] = { 0x6b, 0x61, 0x6d, 0x65, 0x6c, 0xc3, 0xa5,
			     0x73, 0xc3, 0xa5, 0x20, 0xE2, 0x98, 0xBA,
			     0xE2, 0x98, 0xBA, 0xE2, 0x98, 0xBA, 0x20,
			     0xc3, 0xb6, 0xc3, 0xa4, 0xc3, 0xbc, 0xc3,
			     0xbf, 0xc3, 0xa9, 0xc3, 0xa8, 0xc3, 0xb3,
			     0xc3, 0xb2, 0x00 };

/* purely for convenience */
static int fl_ascii_null = LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_NULLTERM;
static int fl_utf8_null = LIBNDR_FLAG_STR_UTF8|LIBNDR_FLAG_STR_NULLTERM;
static int fl_raw8_null = LIBNDR_FLAG_STR_RAW8|LIBNDR_FLAG_STR_NULLTERM;

static bool
test_ndr_push_string (struct torture_context *tctx, const char *string,
                      int flags, enum ndr_err_code exp_ndr_err,
                      bool strcmp_pass)
{
	TALLOC_CTX *mem_ctx;
	struct ndr_push *ndr;
	enum ndr_err_code err;

	torture_comment(tctx,
                        "test_ndr_push_string %s flags 0x%x expecting "
	                "err 0x%x and strcmp %s\n", string, flags, exp_ndr_err,
	                strcmp_pass?"pass":"fail");
	if (exp_ndr_err != NDR_ERR_SUCCESS) {
		torture_comment(tctx, "(ignore any Conversion error) ");
	}

	mem_ctx = talloc_named (NULL, 0, "test_ndr_push_string");
	ndr = talloc_zero (mem_ctx, struct ndr_push);
	ndr_set_flags (&ndr->flags, flags);

	err = ndr_push_string (ndr, NDR_SCALARS, string);
	torture_assert(tctx, err == exp_ndr_err,
	               "ndr_push_string: unexpected return code");

	if (exp_ndr_err == NDR_ERR_SUCCESS) {
		torture_assert(tctx, ndr->data != NULL,
		               "ndr_push_string: succeeded but NULL data");

		torture_assert(tctx,
			       strcmp_pass == !strcmp(string, (char *)ndr->data),
		               "ndr_push_string: post-push strcmp");
	}

	talloc_free(mem_ctx);
	return true;
}

static bool
test_ndr_pull_string (struct torture_context *tctx, const char *string,
                      int flags, enum ndr_err_code exp_ndr_err,
                      bool strcmp_pass)
{
	TALLOC_CTX *mem_ctx;
	DATA_BLOB blob;
	struct ndr_pull *ndr;
	enum ndr_err_code err;
	const char *result = NULL;

	torture_comment(tctx,
                        "test_ndr_pull_string '%s' flags 0x%x expecting "
	                "err 0x%x and strcmp %s\n", string, flags, exp_ndr_err,
	                strcmp_pass?"pass":"fail");
	if (exp_ndr_err != NDR_ERR_SUCCESS) {
		torture_comment(tctx, "(ignore any Conversion error) ");
	}

	mem_ctx = talloc_named (NULL, 0, "test_ndr_pull_string");

	blob = data_blob_string_const(string);
	ndr = ndr_pull_init_blob(&blob, mem_ctx);
	ndr_set_flags (&ndr->flags, flags);

	err = ndr_pull_string (ndr, NDR_SCALARS, &result);
	torture_assert(tctx, err == exp_ndr_err,
	               "ndr_pull_string: unexpected return code");

	if (exp_ndr_err == NDR_ERR_SUCCESS) {
		torture_assert(tctx, result != NULL,
		               "ndr_pull_string: NULL data");
		torture_assert(tctx, strcmp_pass == !strcmp(string, result),
		               "ndr_pull_string: post-pull strcmp");
		torture_assert(tctx, result != NULL,
		               "ndr_pull_string succeeded but result NULL");
	}

	talloc_free(mem_ctx);
	return true;
}

static bool
torture_ndr_string(struct torture_context *torture)
{
	const char *saved_dos_cp = talloc_strdup(torture, lpcfg_dos_charset(torture->lp_ctx));

	torture_assert(torture,
	               test_ndr_push_string (torture, ascii, fl_ascii_null,
	                                     NDR_ERR_SUCCESS, true),
	               "test_ndr_push_string(ASCII, STR_ASCII|STR_NULL)");
	torture_assert(torture,
	               test_ndr_push_string (torture, utf8, fl_utf8_null,
	                                     NDR_ERR_SUCCESS, true),
	               "test_ndr_push_string(UTF8, STR_UTF8|STR_NULL)");
	torture_assert(torture,
	               test_ndr_push_string (torture, utf8, fl_raw8_null,
	                                     NDR_ERR_SUCCESS, true),
	               "test_ndr_push_string(UTF8, STR_RAW8|STR_NULL)");
	torture_assert(torture,
	               test_ndr_push_string (torture, latin1, fl_raw8_null,
	                                     NDR_ERR_SUCCESS, true),
	               "test_ndr_push_string(LATIN1, STR_RAW8|STR_NULL)");
	torture_assert(torture,
	               test_ndr_push_string (torture, utf8, fl_ascii_null,
	                                     NDR_ERR_CHARCNV, false),
	               "test_ndr_push_string(UTF8, STR_ASCII|STR_NULL)");
	torture_assert(torture,
	               test_ndr_push_string (torture, latin1, fl_ascii_null,
	                                     NDR_ERR_CHARCNV, false),
	               "test_ndr_push_string(LATIN1, STR_ASCII|STR_NULL)");


	torture_assert(torture,
	               test_ndr_pull_string (torture, ascii, fl_ascii_null,
	                                     NDR_ERR_SUCCESS, true),
	               "test_ndr_pull_string(ASCII, STR_ASCII|STR_NULL)");
	torture_assert(torture,
	               test_ndr_pull_string (torture, utf8, fl_utf8_null,
	                                     NDR_ERR_SUCCESS, true),
	               "test_ndr_pull_string(UTF8, STR_UTF8|STR_NULL)");
	torture_assert(torture,
	               test_ndr_pull_string (torture, utf8, fl_raw8_null,
	                                     NDR_ERR_SUCCESS, true),
	               "test_ndr_pull_string(UTF8, STR_RAW8|STR_NULL)");
	torture_assert(torture,
	               test_ndr_pull_string (torture, latin1, fl_raw8_null,
	                                     NDR_ERR_SUCCESS, true),
	               "test_ndr_pull_string(LATIN1, STR_RAW8|STR_NULL)");

	/* Depending on runtime config, the behavior of ndr_pull_string on
	 * incorrect combinations of strings and flags (latin1 with ASCII
	 * flags, for example) may differ; it may return NDR_ERR_CHARCNV, or
	 * it may return NDR_ERR_SUCCESS but with a string that has been
	 * mutilated, depending on the value of "dos charset".  We test for
	 * both cases here. */

	lpcfg_do_global_parameter(torture->lp_ctx, "dos charset", "ASCII");
	reload_charcnv(torture->lp_ctx);

	torture_assert(torture,
	               test_ndr_pull_string (torture, latin1, fl_ascii_null,
	                                     NDR_ERR_CHARCNV, false),
	               "test_ndr_pull_string(LATIN1, STR_ASCII|STR_NULL)");
	torture_assert(torture,
	               test_ndr_pull_string (torture, utf8, fl_ascii_null,
	                                     NDR_ERR_CHARCNV, false),
	               "test_ndr_pull_string(UTF8, STR_ASCII|STR_NULL)");

	lpcfg_do_global_parameter(torture->lp_ctx, "dos charset", "CP850");
	reload_charcnv(torture->lp_ctx);

	torture_assert(torture,
	               test_ndr_pull_string (torture, latin1, fl_ascii_null,
	                                     NDR_ERR_SUCCESS, false),
	               "test_ndr_pull_string(LATIN1, STR_ASCII|STR_NULL)");
	torture_assert(torture,
	               test_ndr_pull_string (torture, utf8, fl_ascii_null,
	                                     NDR_ERR_SUCCESS, false),
	               "test_ndr_pull_string(UTF8, STR_ASCII|STR_NULL)");

	lpcfg_do_global_parameter(torture->lp_ctx, "dos charset", saved_dos_cp);
	reload_charcnv(torture->lp_ctx);

	return true;
}

struct torture_suite *ndr_string_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "ndr_string");

	torture_suite_add_simple_test(suite, "ndr_string", torture_ndr_string);
	suite->description = talloc_strdup(suite, "NDR - string-conversion focused push/pull tests");

	return suite;
}
