/*
 * Test for single process memory leaks using getpwnam
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pwd.h>
#include <fcntl.h>

#include "../lib/default-nt-names.h"

struct name_type {
	char name[128];       /* A name */
	int ok;           /* Should this resolve? */
};

static void get_random_username(char *domain, struct name_type *name)
{
	switch (random() % 2) {

		/* Return random domain user */

	case 0:
		snprintf(name->name, sizeof(name->name), "%s/%s", domain,
			 domain_users[random() % NUM_DOMAIN_USERS]);
		name->ok = 1;
		return;

		/* Local user name */

	case 1:
		if (random() % 2) {
			strcpy(name->name, "asmithee");
			name->ok = 0;
		} else {
			strcpy(name->name, "root");
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
	struct passwd *pwd;

	if (!(domain = getenv("TEST_WORKGROUP"))) {
		printf("ERROR: $TEST_WORKGROUP variable undefined\n");
		return 1;
	}

	/* Do this a couple of times */

	while(1) {
		struct name_type name;

		get_random_username(domain, &name);

		pwd = getpwnam(name.name);

		if (name.ok != (pwd != NULL)) {
			printf("ERROR: getpwnam(%s) %d:%d\n", name.name, 
			       name.ok, (pwd != NULL));
			return 1;
		}

		/* Check for exit condition */

		if (open("/tmp/leaktest3.exit", O_RDONLY) != -1) {
			unlink("/tmp/leaktest3.exit");
			return 0;
		}
	}
}
