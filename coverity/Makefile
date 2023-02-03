.PHONY: check-gcc

# Part of Coverity
COV_MAKE_LIBRARY ?= cov-make-library

CFLAGS ?= -Wall -Wno-uninitialized -Wno-unused-variable -Wno-unused-but-set-variable -Werror

check-gcc:
	gcc -o /dev/null -fPIC -shared -include ./coverity_builtins.h $(CFLAGS) coverity_assert_model.c

cov-user-model: check-gcc
	$(COV_MAKE_LIBRARY) -of user_models.xmldb --security coverity_assert_model.c
