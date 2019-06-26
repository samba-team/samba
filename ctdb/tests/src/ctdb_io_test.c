/*
   ctdb_io tests

   Copyright (C) Christof Schmitt 2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"

#include <assert.h>

#include "common/ctdb_io.c"

void ctdb_set_error(struct ctdb_context *ctdb, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	assert(false);
}

static void test_setup(ctdb_queue_cb_fn_t cb,
		       int *pfd,
		       struct ctdb_context **pctdb,
		       struct ctdb_queue **pqueue)
{
	int pipefd[2], ret;
	struct ctdb_context *ctdb;
	struct ctdb_queue *queue;

	ret = pipe(pipefd);
	assert(ret == 0);

	ctdb = talloc_zero(NULL, struct ctdb_context);
	assert(ctdb != NULL);

	ctdb->ev = tevent_context_init(NULL);

	queue = ctdb_queue_setup(ctdb, ctdb, pipefd[0], 0, cb,
				 NULL, "test queue");
	assert(queue != NULL);

	*pctdb = ctdb;
	*pfd = pipefd[1];
	if (pqueue != NULL) {
		*pqueue = queue;
	}
}

static const size_t test1_req_len = 8;
static const char *test1_req = "abcdefgh";

static void test1_callback(uint8_t *data, size_t length, void *private_data)
{
	uint32_t len;

	len = *(uint32_t *)data;
	assert(len == sizeof(uint32_t) + test1_req_len);

	assert(length == sizeof(uint32_t) + test1_req_len);
	assert(memcmp(data  + sizeof(len), test1_req, test1_req_len) == 0);
}

static void test1(void)
{
	struct ctdb_context *ctdb;
	int fd;
	ssize_t ret;
	uint32_t pkt_size;

	test_setup(test1_callback, &fd, &ctdb, NULL);

	pkt_size = sizeof(uint32_t) + test1_req_len;
	ret = write(fd, &pkt_size, sizeof(pkt_size));
	assert(ret != -1 && (size_t)ret == sizeof(pkt_size));

	ret = write(fd, test1_req, test1_req_len);
	assert(ret != -1 && (size_t)ret == test1_req_len);

	tevent_loop_once(ctdb->ev);

	TALLOC_FREE(ctdb);
}

static const size_t test2_req_len[] = { 900, 24, 600 };

static int test2_cb_num = 0;

static void test2_callback(uint8_t *data, size_t length, void *private_data)
{
	uint32_t len;

	len = *(uint32_t *)data;
	assert(len == sizeof(uint32_t) + test2_req_len[test2_cb_num]);
	assert(length == sizeof(uint32_t) + test2_req_len[test2_cb_num]);

	test2_cb_num++;
}

static void test2(void)
{
	struct ctdb_context *ctdb;
	int fd;
	ssize_t ret;
	size_t i;
	uint32_t pkt_size;
	char req[1024] = { 0 };

	for (i = 0; i < sizeof(req); i++) {
		req[i] = i % CHAR_MAX;
	}

	test_setup(test2_callback, &fd, &ctdb, NULL);

	/*
	 * request 0
	 */

	pkt_size = sizeof(uint32_t) + test2_req_len[0];
	ret = write(fd, &pkt_size, sizeof(pkt_size));
	assert(ret != -1 && (size_t)ret == sizeof(pkt_size));

	ret = write(fd, req, test2_req_len[0]);
	assert(ret != -1 && (size_t)ret == test2_req_len[0]);

	/*
	 * request 1
	 */
	pkt_size = sizeof(uint32_t) + test2_req_len[1];
	ret = write(fd, &pkt_size, sizeof(pkt_size));
	assert(ret != -1 && (size_t)ret == sizeof(pkt_size));

	/*
	 * Omit the last byte to avoid buffer processing.
	 */
	ret = write(fd, req, test2_req_len[1] - 1);
	assert(ret != -1 && (size_t)ret == test2_req_len[1] - 1);

	tevent_loop_once(ctdb->ev);

	/*
	 * Write the missing byte now.
	 */
	ret = write(fd, &req[test2_req_len[1] - 1], 1);
	assert(ret != -1 && (size_t)ret == 1);

	/*
	 * request 2
	 */
	pkt_size = sizeof(uint32_t) + test2_req_len[2];
	ret = write(fd, &pkt_size, sizeof(pkt_size));
	assert(ret != -1 && (size_t)ret == sizeof(pkt_size));

	ret = write(fd, req, test2_req_len[2]);
	assert(ret != -1 && (size_t)ret == test2_req_len[2]);

	tevent_loop_once(ctdb->ev);
	tevent_loop_once(ctdb->ev);

	assert(test2_cb_num == 2);

	TALLOC_FREE(ctdb);
}

static void test_cb(uint8_t *data, size_t length, void *private_data)
{
	/* dummy handler, not verifying anything */
	TALLOC_FREE(data);
}

static void test3(void)
{
	struct ctdb_context *ctdb;
	struct ctdb_queue *queue;
	uint32_t pkt_size;
	char *request;
	size_t req_len;
	int fd;
	ssize_t ret;

	test_setup(test_cb, &fd, &ctdb, &queue);
	request = talloc_zero_size(queue, queue->buffer_size);

	/*
	 * calculate a request length which will fit into the buffer
	 * but not twice. Because we need to write the size integer
	 * as well (4-bytes) we're guaranteed that no 2 packets will fit.
	 */
	req_len = queue->buffer_size >> 1;

	/* writing first packet */
	pkt_size = sizeof(uint32_t) + req_len;

	ret = write(fd, &pkt_size, sizeof(pkt_size));
	assert(ret != -1 && (size_t)ret == sizeof(pkt_size));

	ret = write(fd, request, req_len);
	assert(ret != -1 && (size_t)ret == req_len);

	/* writing second, incomplete packet */
	pkt_size = sizeof(uint32_t) + req_len;

	ret = write(fd, &pkt_size, sizeof(pkt_size));
	assert(ret != -1 && (size_t)ret == sizeof(pkt_size));

	ret = write(fd, request, req_len >> 1);
	assert(ret != -1 && (size_t)ret == req_len >> 1);

	/* process...only 1st packet can be processed */
	tevent_loop_once(ctdb->ev);

	/* we should see a progressed offset of req_len + sizeof(pkt_size) */
	assert(queue->buffer.offset == req_len + sizeof(pkt_size));

	/* writing another few bytes of the still incomplete packet */
	ret = write(fd, request, (req_len >> 1) - 1);
	assert(ret != -1 && (size_t)ret == (req_len >> 1) - 1);

	/*
	 * the packet is still incomplete and connot be processed
	 * but the packet data had to be moved in the buffer in order
	 * to fetch the new 199 bytes -> offset must be 0 now.
	 */
	tevent_loop_once(ctdb->ev);
	/*
	 * needs to be called twice as an incomplete packet
	 * does not trigger a schedule_immediate
	 */
	tevent_loop_once(ctdb->ev);

	assert(queue->buffer.offset == 0);

	TALLOC_FREE(ctdb);
}

static void test4(void)
{
	struct ctdb_context *ctdb;
	struct ctdb_queue *queue;
	uint32_t pkt_size;
	char *request;
	size_t req_len, half_buf_size;
	int fd;
	ssize_t ret;

	test_setup(test_cb, &fd, &ctdb, &queue);

	req_len = queue->buffer_size << 1; /* double the buffer size */
	request = talloc_zero_size(queue, req_len);

	/* writing first part of packet exceeding standard buffer size */
	pkt_size = sizeof(uint32_t) + req_len;

	ret = write(fd, &pkt_size, sizeof(pkt_size));
	assert(ret != -1 && (size_t)ret == sizeof(pkt_size));

	half_buf_size = queue->buffer_size >> 1;

	ret = write(fd, request, req_len - half_buf_size);
	assert(ret != -1 && (size_t)ret == req_len - half_buf_size);

	/*
	 * process...
	 * this needs to be done to have things changed
	 */
	tevent_loop_once(ctdb->ev);
	/*
	 * needs to be called twice as an initial incomplete packet
	 * does not trigger a schedule_immediate
	 */
	tevent_loop_once(ctdb->ev);

	/* the buffer should be resized to packet size now */
	assert(queue->buffer.size == pkt_size);

	/* writing remaining data */
	ret = write(fd, request, half_buf_size);
	assert(ret != -1 && (size_t)ret == half_buf_size);

	/* process... */
	tevent_loop_once(ctdb->ev);

	/*
	 * the buffer was increased beyond its standard size.
	 * once packet got processed, the buffer has to be free'd
	 * and will be re-allocated with standard size on new request arrival.
	 */

	assert(queue->buffer.size == 0);

	/* writing new packet to verify standard buffer size */
	pkt_size = sizeof(uint32_t) + half_buf_size;

	ret = write(fd, &pkt_size, sizeof(pkt_size));
	assert(ret != -1 && (size_t)ret == sizeof(pkt_size));

	ret = write(fd, request, half_buf_size);
	assert(ret != -1 && (size_t)ret == half_buf_size);

	/* process... */
	tevent_loop_once(ctdb->ev);

	/* back to standard buffer size */
	assert(queue->buffer.size == queue->buffer_size);

	TALLOC_FREE(ctdb);
}

int main(int argc, const char **argv)
{
	int num;

	if (argc != 2) {
		fprintf(stderr, "%s <testnum>\n", argv[0]);
		exit(1);
	}


	num = atoi(argv[1]);
	switch (num) {
	case 1:
		test1();
		break;

	case 2:
		test2();
		break;

	case 3:
		test3();
		break;

	case 4:
		test4();
		break;

	default:
		fprintf(stderr, "Unknown test number %s\n", argv[1]);
	}

	return 0;
}
