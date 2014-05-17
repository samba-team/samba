#include "replace.h"
#include "unix_msg.h"
#include "poll_funcs/poll_funcs_tevent.h"
#include "tevent.h"

int main(int argc, const char *argv[])
{
	struct poll_funcs *funcs;
	void *tevent_handle;
	struct unix_msg_ctx **ctxs;
	struct tevent_context *ev;
	struct iovec iov;
	int ret;
	unsigned i;
	unsigned num_ctxs = 1;
	struct sockaddr_un dst;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <sockname> [num_contexts]\n", argv[0]);
		return 1;
	}
	if (argc > 2) {
		num_ctxs = atoi(argv[2]);
	}

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		perror("tevent_context_init failed");
		return 1;
	}
	funcs = poll_funcs_init_tevent(NULL);
	if (funcs == NULL) {
		fprintf(stderr, "poll_funcs_init_tevent failed\n");
		return 1;
	}
	tevent_handle = poll_funcs_tevent_register(NULL, funcs, ev);
	if (tevent_handle == NULL) {
		fprintf(stderr, "poll_funcs_tevent_register failed\n");
		return 1;
	}

	ctxs = talloc_array(ev, struct unix_msg_ctx *, num_ctxs);
	if (ctxs == NULL) {
		fprintf(stderr, "talloc failed\n");
		return 1;
	}

	for (i=0; i<num_ctxs; i++) {
		ret = unix_msg_init(NULL, funcs, 256, 1, NULL, NULL,
				    &ctxs[i]);
		if (ret != 0) {
			fprintf(stderr, "unix_msg_init failed: %s\n",
				strerror(ret));
			return 1;
		}
	}

	iov.iov_base = &i;
	iov.iov_len = sizeof(i);

	dst = (struct sockaddr_un) { .sun_family = AF_UNIX };
	strlcpy(dst.sun_path, argv[1], sizeof(dst.sun_path));

	for (i=0; i<num_ctxs; i++) {
		unsigned j;

		for (j=0; j<100000; j++) {
			ret = unix_msg_send(ctxs[i], &dst, &iov, 1, NULL, 0);
			if (ret != 0) {
				fprintf(stderr, "unix_msg_send failed: %s\n",
					strerror(ret));
				return 1;
			}
		}
	}

	while (true) {
		ret = tevent_loop_once(ev);
		if (ret == -1) {
			fprintf(stderr, "tevent_loop_once failed: %s\n",
				strerror(errno));
			exit(1);
		}
	}

	for (i=0; i<num_ctxs; i++) {
		unix_msg_free(ctxs[i]);
	}

	talloc_free(ev);

	return 0;
}
