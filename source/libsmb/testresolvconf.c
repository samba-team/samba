/*
 * test harness for parse_resolvconf
 */

#include "includes.h"

int main(void)
{
	char name_server_arr[3][16];

	if (parse_resolvconf(name_server_arr)) {
		printf("parse succeeded\n"
		       "first nameserver: %s\n",
		       name_server_arr[0]);
	} else {
		printf("parse failed\n");
	}

	return 0;
}
