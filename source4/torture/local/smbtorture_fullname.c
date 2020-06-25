#include "includes.h"
#include "torture/smbtorture.h"
#include "torture/local/proto.h"

static bool test_smbtorture_always_pass(struct torture_context *tctx)
{
	return true;
}

struct torture_suite *torture_local_smbtorture(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "smbtorture");
	struct torture_suite *suite_level1 = torture_suite_create(ctx,
								   "level1");
	struct torture_suite *suite_level2 = torture_suite_create(ctx,
								   "level2");
	struct torture_suite *suite_level3 = torture_suite_create(ctx,
								  "level3");

	torture_suite_add_suite(suite_level2, suite_level3);
	torture_suite_add_suite(suite_level1, suite_level2);
	torture_suite_add_suite(suite, suite_level1);

	torture_suite_add_simple_test(suite_level3, "always_pass",
				     test_smbtorture_always_pass);

	suite->description = talloc_strdup(suite,
				"smbtorture multilevel always pass test.");

	return suite;
}
