/*
 * Test for single process memory leaks using getgrnam
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <grp.h>
#include <fcntl.h>

#include "../lib/default-nt-names.h"

struct name_type {
	char name[128];       /* A name */
	int ok;           /* Should this resolve? */
};

/* Return a random group name */

static void get_random_groupname(char *domain, struct name_type *name)
{
	switch (random() % 2) {

		/* Return a random domain group */

	case 0:
		snprintf(name->name, sizeof(name->name), "%s/%s", domain,
			 domain_groups[random() % NUM_DOMAIN_GROUPS]);
		name->ok = 1;

		return;

	case 1:
		if (random() % 2) {
			strcpy(name->name, "asmithee");
			name->ok = 0;
		} else {
			strcpy(name->name, "sys");
			name->ok = 1;
		}

		return;
	}

	/* Oops */

	strcpy(name->name, "foo");
	name->ok = 1;                     /* This should fail */
}

int main(int argc, char **argv)
{
	char *domain;
	struct group *grp;

	if (!(domain = getenv("TEST_WORKGROUP"))) {
		printf("ERROR: $TEST_WORKGROUP variable undefined\n");
		return 1;
	}

	/* Do this a couple of times */

	while(1) {
		struct name_type name;

		get_random_groupname(domain, &name);

		grp = getgrnam(name.name);

		if (name.ok != (grp != NULL)) {
			printf("ERROR: getpwnam(%s) %d:%d\n", name.name, 
			       name.ok, (grp != NULL));
			return 1;
		}

		/* Check for exit condition */

		if (open("/tmp/leaktest4.exit", O_RDONLY) != -1) {
			unlink("/tmp/leaktest4.exit");
			return 0;
		}
	}
}
