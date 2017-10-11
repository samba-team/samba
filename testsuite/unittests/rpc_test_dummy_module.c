#include "replace.h"
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include "libcli/util/ntstatus.h"

NTSTATUS samba_init_module(void);
NTSTATUS samba_init_module(void)
{
	int rc;

	fprintf(stderr, "Test dummy executed!\n");

	rc = setenv("UNITTEST_DUMMY_MODULE_LOADED", "TRUE", 1);
	if (rc < 0) {
		kill(getpid(), SIGILL);
		exit(-1);
	}

	return NT_STATUS_OK;
}
