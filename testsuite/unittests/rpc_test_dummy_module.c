#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

int samba_init_module(void);
int samba_init_module(void)
{
	int rc;

	fprintf(stderr, "Test dummy executed!\n");

	rc = setenv("UNITTEST_DUMMY_MODULE_LOADED", "TRUE", 1);
	if (rc < 0) {
		kill(getpid(), SIGILL);
		exit(-1);
	}

	return 0;
}
