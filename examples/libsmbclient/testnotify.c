#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <libsmbclient.h>
#include <inttypes.h>
#include "get_auth_data_fn.h"

static int notify_cb(const struct smbc_notify_callback_action *actions,
		     size_t num_actions, void *private_data)
{
	int *count = private_data;
	size_t i;

	printf("%zu\n", num_actions);

	for (i=0; i<num_actions; i++) {
		const struct smbc_notify_callback_action *a = &actions[i];
		printf("%s: %"PRIu32"\n", a->filename, a->action);
	}

	*count -= 1;
	if (*count < 0) {
		return 1;
	}

	return 0;
}

int main(int argc, char * argv[])
{
	int             fd;
	int             ret;
	int             debug = 0;
	int             saved_errno;
	char            path[2048];
	char *          p;
	int count = 1000;

	smbc_init(get_auth_data_fn, debug);

	fprintf(stdout, "Path: ");
	*path = '\0';
	p = fgets(path, sizeof(path) - 1, stdin);
	if (p == NULL) {
		fprintf(stderr, "error reading from stdin\n");
		return 1;
	}
	if (strlen(path) == 0) {
		return 0;
	}

	p = path + strlen(path) - 1;
	if (*p == '\n')	{
		*p = '\0';
	}

	fd = smbc_opendir(path);
	if (fd < 0) {
		perror("smbc_open");
		return 1;
	}

	ret = smbc_notify(fd, 1,
			  SMBC_NOTIFY_CHANGE_SECURITY|
			  SMBC_NOTIFY_CHANGE_FILE_NAME,
			  1000, notify_cb, &count);
	if (ret < 0) {
		saved_errno = errno;
	}

	smbc_close(fd);

	if (ret < 0) {
		errno = saved_errno;
		perror("notify");
	}

	return 0;
}
