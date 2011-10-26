/*
 * Copyright (C) 2005 by Volker Lendecke
 *
 * Test harness for sprintf_append
 */

#include "includes.h"
#include "torture/proto.h"

bool run_local_sprintf_append(int dummy)
{
	TALLOC_CTX *mem_ctx;
	char *string = NULL;
	ssize_t len = 0;
	size_t bufsize = 4;
	int i;

	mem_ctx = talloc_init("t_strappend");
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_init failed\n");
		return false;
	}

	sprintf_append(mem_ctx, &string, &len, &bufsize, "");
	assert(strlen(string) == len);
	sprintf_append(mem_ctx, &string, &len, &bufsize, "");
	assert(strlen(string) == len);
	sprintf_append(mem_ctx, &string, &len, &bufsize,
		       "01234567890123456789012345678901234567890123456789\n");
	assert(strlen(string) == len);


	for (i=0; i<(10000); i++) {
		if (i%1000 == 0) {
			printf("%d %lld\r", i, (long long int)bufsize);
			fflush(stdout);
		}
		sprintf_append(mem_ctx, &string, &len, &bufsize, "%d\n", i);
		if (strlen(string) != len) {
			fprintf(stderr, "sprintf_append failed: strlen(string) %lld != len %lld\n",
				(long long int)strlen(string), (long long int)len);
			return false;
		}
	}

	talloc_destroy(mem_ctx);

	return true;
}
