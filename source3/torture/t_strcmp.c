/*
 * Copyright (C) 2003 by Martin Pool
 *
 * Test harness for StrCaseCmp
 */

#include "includes.h"

int main(int argc, char *argv[])
{
	int i, ret;
	
	if (argc != 3) {
		fprintf(stderr, "usage: %s STRING1 STRING2\n"
			"Compares two strings, prints the results of StrCaseCmp\n",
			argv[0]);
		return 2;
	}

	for (i = 0; i < 10000; i++)
		ret = StrCaseCmp(argv[1], argv[2]);

	printf("%d\n", ret);
	
	return 0;
}
