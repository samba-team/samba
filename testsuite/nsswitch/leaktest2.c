/*
 * Test for single process memory leaks using getpwent() and friends
 */

#include <stdio.h>
#include <signal.h>
#include <pwd.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	struct passwd *pwd;

	/* Do this a couple of times */

	while(1) {
		int got_dom_group = 0;

		/* Enumerate domain groups */

		setpwent();

		while((pwd = getpwent())) {
			if (strchr(pwd->pw_name, '/')) 
				got_dom_group = 1;
		}

		endpwent();

		/* Check we actually got one or more domain groups */
		
		if (!got_dom_group) {
			printf("ERROR: did not find any domain groups\n");
			return 1;
		}

		/* Check for exit condition */

		if (open("/tmp/leaktest2.exit", O_RDONLY) != -1) {
			unlink("/tmp/leaktest2.exit");
			return 0;
		}
	}
}
