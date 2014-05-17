#include "replace.h"
#include "unix_msg.h"
#include "poll_funcs/poll_funcs_tevent.h"
#include "tevent.h"

struct cb_state {
	unsigned num_received;
	uint8_t *buf;
	size_t buflen;
};

static void recv_cb(struct unix_msg_ctx *ctx,
		    uint8_t *msg, size_t msg_len,
		    int *fds, size_t num_fds,
		    void *private_data);

static void expect_messages(struct tevent_context *ev, struct cb_state *state,
			    unsigned num_msgs)
{
	state->num_received = 0;

	while (state->num_received < num_msgs) {
		int ret;

		ret = tevent_loop_once(ev);
		if (ret == -1) {
			fprintf(stderr, "tevent_loop_once failed: %s\n",
				strerror(errno));
			exit(1);
		}
	}
}

int main(void)
{
	struct poll_funcs *funcs;
	void *tevent_handle;
	struct sockaddr_un addr1, addr2;
	struct unix_msg_ctx *ctx1, *ctx2;
	struct tevent_context *ev;
	struct iovec iov;
	uint8_t msg;
	int i, ret;
	static uint8_t buf[1755];

	struct cb_state state;

	addr1 = (struct sockaddr_un) { .sun_family = AF_UNIX };
	strlcpy(addr1.sun_path, "sock1", sizeof(addr1.sun_path));
	unlink(addr1.sun_path);

	addr2 = (struct sockaddr_un) { .sun_family = AF_UNIX };
	strlcpy(addr2.sun_path, "sock2", sizeof(addr2.sun_path));
	unlink(addr2.sun_path);

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		perror("tevent_context_init failed");
		return 1;
	}

	funcs = poll_funcs_init_tevent(ev);
	if (funcs == NULL) {
		fprintf(stderr, "poll_funcs_init_tevent failed\n");
		return 1;
	}
	tevent_handle = poll_funcs_tevent_register(ev, funcs, ev);
	if (tevent_handle == NULL) {
		fprintf(stderr, "poll_funcs_register_tevent failed\n");
		return 1;
	}

	ret = unix_msg_init(&addr1, funcs, 256, 1,
			    recv_cb, &state, &ctx1);
	if (ret != 0) {
		fprintf(stderr, "unix_msg_init failed: %s\n",
			strerror(ret));
		return 1;
	}

	ret = unix_msg_init(&addr1, funcs, 256, 1,
			    recv_cb, &state, &ctx1);
	if (ret == 0) {
		fprintf(stderr, "unix_msg_init succeeded unexpectedly\n");
		return 1;
	}
	if (ret != EADDRINUSE) {
		fprintf(stderr, "unix_msg_init returned %s, expected "
			"EADDRINUSE\n", strerror(ret));
		return 1;
	}

	ret = unix_msg_init(&addr2, funcs, 256, 1,
			    recv_cb, &state, &ctx2);
	if (ret != 0) {
		fprintf(stderr, "unix_msg_init failed: %s\n",
			strerror(ret));
		return 1;
	}

	printf("sending a 0-length message\n");

	state.buf = NULL;
	state.buflen = 0;

	ret = unix_msg_send(ctx1, &addr2, NULL, 0, NULL, 0);
	if (ret != 0) {
		fprintf(stderr, "unix_msg_send failed: %s\n",
			strerror(ret));
		return 1;
	}

	expect_messages(ev, &state, 1);

	printf("sending a small message\n");

	msg = random();
	iov.iov_base = &msg;
	iov.iov_len = sizeof(msg);
	state.buf = &msg;
	state.buflen = sizeof(msg);

	ret = unix_msg_send(ctx1, &addr2, &iov, 1, NULL, 0);
	if (ret != 0) {
		fprintf(stderr, "unix_msg_send failed: %s\n",
			strerror(ret));
		return 1;
	}

	expect_messages(ev, &state, 1);

	printf("sending six large, interleaved messages\n");

	for (i=0; i<sizeof(buf); i++) {
		buf[i] = random();
	}

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	state.buf = buf;
	state.buflen = sizeof(buf);

	for (i=0; i<3; i++) {
		ret = unix_msg_send(ctx1, &addr2, &iov, 1, NULL, 0);
		if (ret != 0) {
			fprintf(stderr, "unix_msg_send failed: %s\n",
				strerror(ret));
			return 1;
		}
		ret = unix_msg_send(ctx2, &addr2, &iov, 1, NULL, 0);
		if (ret != 0) {
			fprintf(stderr, "unix_msg_send failed: %s\n",
				strerror(ret));
			return 1;
		}
	}

	expect_messages(ev, &state, 6);

	printf("sending a few messages in small pieces\n");

	for (i = 0; i<5; i++) {
		struct iovec iovs[20];
		const size_t num_iovs = ARRAY_SIZE(iovs);
		uint8_t *p = buf;
		size_t j;

		for (j=0; j<num_iovs-1; j++) {
			size_t chunk = (random() % ((sizeof(buf) * 2) / num_iovs));
			size_t space = (sizeof(buf) - (p - buf));

			if (space == 0) {
				break;
			}

			chunk = MIN(chunk, space);

			iovs[j].iov_base = p;
			iovs[j].iov_len = chunk;
			p += chunk;
		}

		if (p < (buf + sizeof(buf))) {
			iovs[j].iov_base = p;
			iovs[j].iov_len = (sizeof(buf) - (p - buf));
			j++;
		}

		ret = unix_msg_send(ctx1, &addr1, iovs, j, NULL, 0);
		if (ret != 0) {
			fprintf(stderr, "unix_msg_send failed: %s\n",
				strerror(ret));
			return 1;
		}
	}

	expect_messages(ev, &state, 5);

	printf("Filling send queues before freeing\n");

	for (i=0; i<5; i++) {
		ret = unix_msg_send(ctx1, &addr2, &iov, 1, NULL, 0);
		if (ret != 0) {
			fprintf(stderr, "unix_msg_send failed: %s\n",
				strerror(ret));
			return 1;
		}
		ret = unix_msg_send(ctx1, &addr1, &iov, 1, NULL, 0);
		if (ret != 0) {
			fprintf(stderr, "unix_msg_send failed: %s\n",
				strerror(ret));
			return 1;
		}
	}

	expect_messages(ev, &state, 1); /* Read just one msg */

	unix_msg_free(ctx1);
	unix_msg_free(ctx2);
	talloc_free(tevent_handle);
	talloc_free(funcs);
	talloc_free(ev);

	return 0;
}

static void recv_cb(struct unix_msg_ctx *ctx,
		    uint8_t *msg, size_t msg_len,
		    int *fds, size_t num_fds,
		    void *private_data)
{
	struct cb_state *state = (struct cb_state *)private_data;

	if (msg_len != state->buflen) {
		fprintf(stderr, "expected %u bytes, got %u\n",
			(unsigned)state->buflen, (unsigned)msg_len);
		exit(1);
	}
	if ((msg_len != 0) && (memcmp(msg, state->buf, msg_len) != 0)) {
		fprintf(stderr, "message content differs\n");
		exit(1);
	}
	state->num_received += 1;
}
