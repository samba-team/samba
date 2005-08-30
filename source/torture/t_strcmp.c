/*
 * Copyright (C) 2003 by Martin Pool
 *
 * Test harness for strcasecmp_m
 */

#include "includes.h"

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s STRING1 STRING2\nCompares two strings\n",
			argv[0]);
		return 2;
	}
	
	printf("%d\n", strcasecmp_m(argv[1], argv[2]));
	
	return 0;
}
