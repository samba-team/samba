coverity_assert_model.c:

This file is a Coverity Modeling file for which currently adds the needed models
for using the cmocka unit test framework. The assert functions could create
false positives, to avoid that you can load this modeling file in the Coverity
web interface. If needed add models for torture_ and talloc_ macros.
