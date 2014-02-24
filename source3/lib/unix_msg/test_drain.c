#include "replace.h"
#include "unix_msg.h"
#include "poll_funcs/poll_funcs_tevent.h"
#include "tevent.h"
#include "system/select.h"

struct cb_state {
	unsigned num_received;
	uint8_t *buf;
	size_t buflen;
};

static void recv_cb(struct unix_msg_ctx *ctx,
		    uint8_t *msg, size_t msg_len,
		    void *private_data);

int main(int argc, const char *argv[])
{
	struct poll_funcs funcs;
	const char *sock;
	struct unix_msg_ctx *ctx;
	struct tevent_context *ev;
	int ret;

	struct cb_state state;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <sockname>\n", argv[0]);
		return 1;
	}

	sock = argv[1];
	unlink(sock);

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		perror("tevent_context_init failed");
		return 1;
	}
	poll_funcs_init_tevent(&funcs, ev);

	ret = unix_msg_init(sock, &funcs, 256, 1,
			    recv_cb, &state, &ctx);
	if (ret != 0) {
		fprintf(stderr, "unix_msg_init failed: %s\n",
			strerror(ret));
		return 1;
	}

	while (1) {
		ret = tevent_loop_once(ev);
		if (ret == -1) {
			fprintf(stderr, "tevent_loop_once failed: %s\n",
				strerror(errno));
			exit(1);
		}
	}
	return 0;
}

static void recv_cb(struct unix_msg_ctx *ctx,
		    uint8_t *msg, size_t msg_len,
		    void *private_data)
{
	unsigned num;
	if (msg_len == sizeof(num)) {
		memcpy(&num, msg, msg_len);
		printf("%u\n", num);
	}
}
