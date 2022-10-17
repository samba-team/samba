/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2022      Andrew Bartlett <abartlet@samba.org>
 * Copyright (C) 2021      Andreas Schneider <asn@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include "includes.h"
#include "system/network.h"
#include "socketpair_tcp.h"
#include "tsocket.h"

enum socket_pair_selector {
	SOCKET_SERVER = 0,
	SOCKET_CLIENT = 1,
};

struct socket_pair {
	struct tevent_context *ev;
	int socket_server;
	int socket_client;

	/* for tstream tests */
	int rc;
	int sys_errno;
	int expected_errno;
	struct timeval endtime;
	size_t max_loops;
	size_t num_loops;
};

/* If this is too large, we get EPIPE rather than EAGAIN */
static const uint8_t TEST_STRING[128] = { 0 };

static int sigpipe_setup(void **state)
{
	BlockSignals(true, SIGPIPE);
	return 0;
}

static int setup_socketpair_tcp_context(void **state)
{
	int fd[2];
	struct socket_pair *sp = talloc_zero(NULL, struct socket_pair);
	assert_non_null(sp);

	/* Set up a socketpair over TCP to test with */
	assert_return_code(socketpair_tcp(fd), errno);

	sp->socket_server = fd[SOCKET_SERVER];
	sp->socket_client = fd[SOCKET_CLIENT];

	sp->ev = tevent_context_init(sp);
	assert_non_null(sp->ev);

	*state = sp;
	return 0;
}

static int setup_socketpair_context(void **state)
{
	int fd[2];
	struct socket_pair *sp = talloc_zero(NULL, struct socket_pair);
	assert_non_null(sp);

	/* Set up a socketpair over TCP to test with */
	assert_return_code(socketpair(AF_UNIX, SOCK_STREAM, 0, fd), errno);

	sp->socket_server = fd[SOCKET_SERVER];
	sp->socket_client = fd[SOCKET_CLIENT];

	sp->ev = tevent_context_init(sp);
	assert_non_null(sp->ev);

	*state = sp;
	return 0;
}

static int teardown_socketpair_context(void **state)
{
	struct socket_pair *sp = *state;
	struct socket_pair sp_save = *sp;

	TALLOC_FREE(sp);

	/*
	 * Close these after the TALLOC_FREE() to allow clean shutdown
	 * of epoll() in tstream
	 */
	if (sp_save.socket_client != -1) {
		close(sp_save.socket_client);
	}
	if (sp_save.socket_server != -1) {
		close(sp_save.socket_server);
	}
	return 0;
}


/* Test socket behaviour */
static void test_simple_socketpair(void **state) {

	struct socket_pair *sp = *state;

	char buf[sizeof(TEST_STRING)];

	assert_int_equal(write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING)),
			 sizeof(TEST_STRING));
	assert_int_equal(read(sp->socket_client, buf, sizeof(buf)),
			 sizeof(buf));


}

/* Test socket behaviour */
static void test_read_client_after_close_server_socket(void **state) {

	struct socket_pair *sp = *state;
	int rc;
	char buf[sizeof(TEST_STRING)];

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_return_code(rc, errno);
	assert_int_equal(rc, sizeof(TEST_STRING));

	assert_return_code(close(sp->socket_server), 0);

	rc = read(sp->socket_client, buf, sizeof(buf));

	assert_return_code(rc, errno);
	assert_int_equal(rc, sizeof(buf));
}

static void test_write_server_after_close_client_socket(void **state) {

	struct socket_pair *sp = *state;
	int rc;

	assert_return_code(close(sp->socket_client), 0);
	sp->socket_client = -1;

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_return_code(rc, errno);
	assert_int_equal(rc, sizeof(TEST_STRING));
}

static void test_fill_socket(int sock)
{
	size_t num_busy = 0;
	int rc;

	while (true) {
		rc = write(sock, TEST_STRING, sizeof(TEST_STRING));
		if (rc == -1 && errno == EAGAIN) {
			/*
			 * This makes sure we write until we get a whole second
			 * only with EAGAIN every 50 ms (20 times)
			 *
			 * Otherwise the tests are not reliable...
			 */
			num_busy++;
			if (num_busy > 20) {
				break;
			}
			smb_msleep(50);
			continue;
		}
		/* try again next time */
		num_busy = 0;
	}

	assert_int_equal(rc, -1);
	assert_int_equal(errno, EAGAIN);
}

static void test_big_write_server(void **state) {

	struct socket_pair *sp = *state;
	int rc;

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_return_code(rc, errno);
	assert_int_equal(rc, sizeof(TEST_STRING));

	rc = set_blocking(sp->socket_server, 0);
	assert_return_code(rc, errno);

	test_fill_socket(sp->socket_server);
}

static void test_big_write_server_close_write(void **state) {

	struct socket_pair *sp = *state;
	int rc;

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_return_code(rc, errno);
	assert_int_equal(rc, sizeof(TEST_STRING));

	rc = set_blocking(sp->socket_server, 0);
	assert_return_code(rc, errno);

	test_fill_socket(sp->socket_server);

	assert_return_code(close(sp->socket_client), 0);
	sp->socket_client = -1;

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_int_equal(errno, ECONNRESET);

}

static void test_big_write_server_shutdown_wr_write(void **state) {

	struct socket_pair *sp = *state;
	int rc;

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_return_code(rc, errno);
	assert_int_equal(rc, sizeof(TEST_STRING));

	rc = set_blocking(sp->socket_server, 0);
	assert_return_code(rc, errno);

	test_fill_socket(sp->socket_server);

	assert_return_code(shutdown(sp->socket_client, SHUT_WR), 0);
	sp->socket_client = -1;

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_int_equal(rc, -1);
	assert_int_equal(errno, EAGAIN);
}

static void test_big_write_server_shutdown_rd_write(void **state) {

	struct socket_pair *sp = *state;
	int rc;

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_return_code(rc, errno);
	assert_int_equal(rc, sizeof(TEST_STRING));

	rc = set_blocking(sp->socket_server, 0);
	assert_return_code(rc, errno);

	test_fill_socket(sp->socket_server);

	assert_return_code(shutdown(sp->socket_client, SHUT_RD), 0);
	sp->socket_client = -1;

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_int_equal(rc, -1);
	assert_int_equal(errno, EAGAIN);
}

static void test_call_writev_done(struct tevent_req *subreq)
{
	struct socket_pair *sp =
		tevent_req_callback_data(subreq,
		struct socket_pair);
	int rc;

	rc = tstream_writev_recv(subreq, &sp->sys_errno);
	TALLOC_FREE(subreq);

	sp->rc = rc;
}

static void test_tstream_server_spin_client_shutdown(struct socket_pair *sp)
{
	int rc;

	rc = shutdown(sp->socket_client, SHUT_WR);
	assert_return_code(rc, errno);
	/*
	 * It should only take a few additional loop to realise that this socket is
	 * in CLOSE_WAIT
	 */
	sp->max_loops = sp->num_loops + 2;
	sp->expected_errno = ECONNRESET;
}

static void test_tstream_server_spin_client_write(struct socket_pair *sp)
{
	int rc;
	int timeout = 5000;

	sp->endtime = timeval_current_ofs_msec(timeout);

	rc = write(sp->socket_client, TEST_STRING, sizeof(TEST_STRING));
	assert_return_code(rc, errno);
	sp->expected_errno = ETIMEDOUT;
}

static void test_tstream_server_spin_client_tcp_user_timeout(struct socket_pair *sp)
{
	int rc;
	int timeout = 5000;

	rc = setsockopt(sp->socket_server, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout, sizeof(timeout));
	assert_return_code(rc, errno);

	rc = write(sp->socket_client, TEST_STRING, sizeof(TEST_STRING));
	assert_return_code(rc, errno);
	sp->expected_errno = ETIMEDOUT;
	sp->max_loops = 15;
}

static void test_tstream_server_spin_client_both_timer(struct tevent_context *ev,
						       struct tevent_timer *te,
						       struct timeval current_time,
						       void *private_data)
{
	struct socket_pair *sp =
		talloc_get_type_abort(private_data,
		struct socket_pair);

	test_tstream_server_spin_client_shutdown(sp);
}

static void test_tstream_server_spin_client_both(struct socket_pair *sp)
{
	struct tevent_timer *te = NULL;
	struct timeval endtime;

	test_tstream_server_spin_client_write(sp);

	endtime = timeval_current_ofs_msec(2500);

	te = tevent_add_timer(sp->ev,
			      sp,
			      endtime,
			      test_tstream_server_spin_client_both_timer,
			      sp);
	assert_non_null(te);
	sp->expected_errno = ENXIO;
}

static void test_tstream_server_spin(struct socket_pair *sp,
				     void (*client_fn)(struct socket_pair *sp))
{
	struct tstream_context *stream = NULL;
	struct tevent_req *req = NULL;
	struct iovec iov;
	int rc;

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_return_code(rc, errno);
	assert_int_equal(rc, sizeof(TEST_STRING));

	rc = set_blocking(sp->socket_server, 0);
	assert_return_code(rc, errno);

	test_fill_socket(sp->socket_server);

	/*
	 * by default we don't expect more then 2 loop iterations
	 * for a timeout of 5 seconds.
	 */
	sp->max_loops = 10;

	client_fn(sp);

	rc = write(sp->socket_server, TEST_STRING, sizeof(TEST_STRING));
	assert_int_equal(rc, -1);
	assert_int_equal(errno, EAGAIN);

	/* OK, so we now know the socket is in CLOSE_WAIT */

	rc = tstream_bsd_existing_socket(sp->ev, sp->socket_server, &stream);
	assert_return_code(rc, errno);
	sp->socket_server = -1;

	iov.iov_base = discard_const_p(char, TEST_STRING);
	iov.iov_len = sizeof(TEST_STRING);

	req = tstream_writev_send(stream, sp->ev, stream, &iov, 1);
	assert_non_null(req);
	if (!timeval_is_zero(&sp->endtime)) {
		assert_true(tevent_req_set_endtime(req, sp->ev, sp->endtime));
	}
	tevent_req_set_callback(req, test_call_writev_done, sp);

	while (tevent_req_is_in_progress(req)) {
		if (sp->num_loops >= sp->max_loops) {
			assert_int_not_equal(sp->num_loops, sp->max_loops);
			assert_int_equal(sp->num_loops, sp->max_loops);
		}
		sp->num_loops += 1;

		rc = tevent_loop_once(sp->ev);
		assert_int_equal(rc, 0);
	}

	assert_int_equal(sp->rc, -1);
	assert_int_equal(sp->sys_errno, sp->expected_errno);
	return;
}

/*
 * We need two names to run this with the two different setup
 * routines
 */
static void test_tstream_disconnected_tcp_client_spin(void **state)
{
	struct socket_pair *sp = *state;
	test_tstream_server_spin(sp, test_tstream_server_spin_client_shutdown);
}

static void test_tstream_disconnected_unix_client_spin(void **state)
{
	struct socket_pair *sp = *state;
	test_tstream_server_spin(sp, test_tstream_server_spin_client_shutdown);
}

static void test_tstream_more_tcp_client_spin(void **state)
{
	struct socket_pair *sp = *state;
	test_tstream_server_spin(sp, test_tstream_server_spin_client_write);
}

static void test_tstream_more_unix_client_spin(void **state)
{
	struct socket_pair *sp = *state;
	test_tstream_server_spin(sp, test_tstream_server_spin_client_write);
}

static void test_tstream_more_disconnect_tcp_client_spin(void **state)
{
	struct socket_pair *sp = *state;
	test_tstream_server_spin(sp, test_tstream_server_spin_client_both);
}

static void test_tstream_more_disconnect_unix_client_spin(void **state)
{
	struct socket_pair *sp = *state;
	test_tstream_server_spin(sp, test_tstream_server_spin_client_both);
}

static void test_tstream_more_tcp_user_timeout_spin(void **state)
{
	struct socket_pair *sp = *state;
	if (socket_wrapper_enabled()) {
		skip();
	}
	test_tstream_server_spin(sp, test_tstream_server_spin_client_tcp_user_timeout);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_simple_socketpair,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_read_client_after_close_server_socket,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_write_server_after_close_client_socket,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_big_write_server,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_big_write_server_close_write,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_big_write_server_shutdown_wr_write,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_big_write_server_shutdown_rd_write,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_tstream_disconnected_tcp_client_spin,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_tstream_disconnected_unix_client_spin,
						setup_socketpair_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_tstream_more_tcp_client_spin,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_tstream_more_unix_client_spin,
						setup_socketpair_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_tstream_more_disconnect_tcp_client_spin,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_tstream_more_disconnect_unix_client_spin,
						setup_socketpair_context,
						teardown_socketpair_context),
		cmocka_unit_test_setup_teardown(test_tstream_more_tcp_user_timeout_spin,
						setup_socketpair_tcp_context,
						teardown_socketpair_context),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, sigpipe_setup, NULL);
}
