/*
 * Test for single process memory leaks using getgrent()
 *
 */

#include <stdio.h>
#include <signal.h>
#include <grp.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	struct group *grp;

	/* Do this a couple of times */

	while(1) {
		int got_dom_group = 0;

		/* Enumerate domain groups */

		setgrent();

		while((grp = getgrent())) {
			if (strchr(grp->gr_name, '/')) 
				got_dom_group = 1;
		}

		endgrent();

		/* Check we actually got one or more domain groups */
		
		if (!got_dom_group) {
			printf("ERROR: did not find any domain groups\n");
			return 1;
		}

		/* Check for exit condition */

		if (open("/tmp/leaktest1.exit", O_RDONLY) != -1) {
			unlink("/tmp/leaktest1.exit");
			return 0;
		}
	}
}
