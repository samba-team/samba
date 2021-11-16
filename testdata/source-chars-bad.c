/*
 * "Trojan Source"  CVE-2021-42574 test.
 *
 * Based on an example from https://lwn.net/Articles/874951/
 */
#include <stdio.h>

int main(int argc, char *argv[])
{
	int isAdmin = 0;

#if 0
	/* This is what is really there. */

	/*«RLO» } «LRI»if (isAdmin)«PDI» «LRI» begin admins only */
	puts("hello admin");
	/* end admin only «RLO» { «LRI»*/
#else
	/*‮ } ⁦if (isAdmin)⁩ ⁦ begin admins only */
	puts("hello admin");
	/* end admin only ‮ { ⁦*/
#endif
}
