/*
   protocol utilities tests

   Copyright (C) Martin Schwenke  2016

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
#include "system/network.h"

#include <assert.h>

#include "protocol/protocol_basic.c"
#include "protocol/protocol_types.c"
#include "protocol/protocol_util.c"

/*
 * Test parsing of IPs, conversion to string
 */

static void test_sock_addr_to_string(const char *ip, bool with_port)
{
	ctdb_sock_addr sa;
	const char *s;
	int ret;

	ret = ctdb_sock_addr_from_string(ip, &sa, with_port);
	assert(ret == 0);
	s = ctdb_sock_addr_to_string(NULL, &sa, with_port);
	assert(strcmp(ip, s) == 0);
	talloc_free(discard_const(s));
}

static void test_sock_addr_from_string_bad(const char *ip, bool with_port)
{
	ctdb_sock_addr sa;
	int ret;

	ret = ctdb_sock_addr_from_string(ip, &sa, with_port);
	assert(ret == EINVAL);
}

static void test_sock_addr_from_string_memcmp(const char *ip1,
					      const char* ip2)
{
	ctdb_sock_addr sa1, sa2;
	int ret;

	ret = ctdb_sock_addr_from_string(ip1, &sa1, false);
	assert(ret == 0);
	ret = ctdb_sock_addr_from_string(ip2, &sa2, false);
	assert(ret == 0);
	ret = memcmp(&sa1, &sa2, sizeof(ctdb_sock_addr));
	assert(ret == 0);
}

static void test_sock_addr_cmp(const char *ip1, const char *ip2,
			       bool with_port, int res)
{
	ctdb_sock_addr sa1, sa2;
	int ret;

	ret = ctdb_sock_addr_from_string(ip1, &sa1, with_port);
	assert(ret == 0);
	ret = ctdb_sock_addr_from_string(ip2, &sa2, with_port);
	assert(ret == 0);
	ret = ctdb_sock_addr_cmp(&sa1, &sa2);
	if (ret < 0) {
		ret = -1;
	} else if (ret > 0) {
		ret = 1;
	}

	assert(ret == res);
}

/*
 * Test parsing of IP/mask, conversion to string
 */

static void test_sock_addr_mask_from_string(const char *ip_mask)
{
	ctdb_sock_addr sa;
	unsigned mask;
	const char *s, *t;
	int ret;

	ret = ctdb_sock_addr_mask_from_string(ip_mask, &sa, &mask);
	assert(ret == 0);
	s = ctdb_sock_addr_to_string(NULL, &sa, false);
	assert(s != NULL);
	t = talloc_asprintf(s, "%s/%u", s, mask);
	assert(strcmp(ip_mask, t) == 0);
	talloc_free(discard_const(s));
}

static void test_sock_addr_mask_from_string_bad(const char *ip_mask)
{
	ctdb_sock_addr sa;
	unsigned mask;
	int ret;

	ret = ctdb_sock_addr_mask_from_string(ip_mask, &sa, &mask);
	assert(ret == EINVAL);
}

/*
 * Test parsing of connection, conversion to string
 */

static void test_connection_to_string(const char *conn_str)
{
	TALLOC_CTX *tmp_ctx;
	struct ctdb_connection conn;
	const char *s, *r;
	int ret;

	tmp_ctx = talloc_new(NULL);
	assert(tmp_ctx != NULL);

	/*
	 * Test non-reversed parse and render
	 */

	ret = ctdb_connection_from_string(conn_str, false, &conn);
	assert(ret == 0);

	s = ctdb_connection_to_string(tmp_ctx, &conn, false);
	assert(s != NULL);
	ret = strcmp(conn_str, s);
	assert(ret == 0);

	talloc_free(discard_const(s));

	/*
	 * Reversed render
	 */
	r = ctdb_connection_to_string(tmp_ctx, &conn, true);
	assert(r != NULL);
	ret = strcmp(conn_str, r);
	assert(ret != 0);

	/*
	 * Reversed parse with forward render
	 */
	ret = ctdb_connection_from_string(conn_str, true, &conn);
	assert(ret == 0);

	s = ctdb_connection_to_string(tmp_ctx, &conn, false);
	assert(s != NULL);
	ret = strcmp(r, s);
	assert(ret == 0);

	talloc_free(discard_const(s));

	/*
	 * Reversed parse and render
	 */
	ret = ctdb_connection_from_string(conn_str, true, &conn);
	assert(ret == 0);

	s = ctdb_connection_to_string(tmp_ctx, &conn, true);
	assert(s != NULL);
	ret = strcmp(conn_str, s);
	assert(ret == 0);

	talloc_free(tmp_ctx);
}

static void test_connection_from_string_bad(const char *conn_str)
{
	struct ctdb_connection conn;
	int ret;

	ret = ctdb_connection_from_string(conn_str, false, &conn);
	assert(ret == EINVAL);
}

/*
 * Test connection list utilities
 */

static void test_connection_list_read(const char *s1, const char *s2)
{
	TALLOC_CTX *tmp_ctx;
	int pipefd[2];
	pid_t pid;
	struct ctdb_connection_list *conn_list = NULL;
	const char *t;
	int ret;

	tmp_ctx = talloc_new(NULL);
	assert(tmp_ctx != NULL);

	ret = pipe(pipefd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		close(pipefd[0]);

		ret = dup2(pipefd[1], STDOUT_FILENO);
		assert(ret != -1);

		close(pipefd[1]);

		printf("%s", s1);
		fflush(stdout);

		exit(0);
	}

	close(pipefd[1]);

	ret = ctdb_connection_list_read(tmp_ctx, pipefd[0], false, &conn_list);
	assert(ret == 0);

	close(pipefd[0]);

	ret = ctdb_connection_list_sort(conn_list);
	assert(ret == 0);

	t = ctdb_connection_list_to_string(tmp_ctx, conn_list, false);
	assert(t != NULL);
	ret = strcmp(t, s2);
	assert(ret == 0);

	talloc_free(tmp_ctx);
}

static void test_connection_list_read_bad(const char *s1)
{
	TALLOC_CTX *tmp_ctx;
	int pipefd[2];
	pid_t pid;
	struct ctdb_connection_list *conn_list = NULL;
	int ret;

	tmp_ctx = talloc_new(NULL);
	assert(tmp_ctx != NULL);

	ret = pipe(pipefd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		close(pipefd[0]);

		ret = dup2(pipefd[1], STDOUT_FILENO);
		assert(ret != -1);

		close(pipefd[1]);

		printf("%s", s1);
		fflush(stdout);

		exit(0);
	}

	close(pipefd[1]);

	ret = ctdb_connection_list_read(tmp_ctx, pipefd[0], false, &conn_list);
	assert(ret == EINVAL);

	close(pipefd[0]);

	talloc_free(tmp_ctx);
}

/*
 * Use macros for these to make them easy to concatenate
 */

#define CONN4 \
"\
127.0.0.1:12345 127.0.0.2:54321\n\
127.0.0.2:12345 127.0.0.1:54322\n\
127.0.0.1:12346 127.0.0.2:54323\n\
127.0.0.2:12345 127.0.0.1:54324\n\
127.0.0.1:12345 127.0.0.2:54325\n\
"

#define CONN4_SORT \
"\
127.0.0.1:12345 127.0.0.2:54321\n\
127.0.0.1:12345 127.0.0.2:54325\n\
127.0.0.1:12346 127.0.0.2:54323\n\
127.0.0.2:12345 127.0.0.1:54322\n\
127.0.0.2:12345 127.0.0.1:54324\n\
"

#define CONN6 \
"\
fe80::6af7:28ff:fefa:d136:12345 fe80::6af7:28ff:fefa:d137:54321\n\
fe80::6af7:28ff:fefa:d138:12345 fe80::6af7:28ff:fefa:d137:54322\n\
fe80::6af7:28ff:fefa:d136:12346 fe80::6af7:28ff:fefa:d137:54323\n\
fe80::6af7:28ff:fefa:d132:12345 fe80::6af7:28ff:fefa:d137:54324\n\
fe80::6af7:28ff:fefa:d136:12345 fe80::6af7:28ff:fefa:d137:54325\n\
"

#define CONN6_SORT \
"\
fe80::6af7:28ff:fefa:d132:12345 fe80::6af7:28ff:fefa:d137:54324\n\
fe80::6af7:28ff:fefa:d136:12345 fe80::6af7:28ff:fefa:d137:54321\n\
fe80::6af7:28ff:fefa:d136:12345 fe80::6af7:28ff:fefa:d137:54325\n\
fe80::6af7:28ff:fefa:d136:12346 fe80::6af7:28ff:fefa:d137:54323\n\
fe80::6af7:28ff:fefa:d138:12345 fe80::6af7:28ff:fefa:d137:54322\n\
"

int main(int argc, char *argv[])
{
	test_sock_addr_to_string("0.0.0.0", false);
	test_sock_addr_to_string("127.0.0.1", false);
	test_sock_addr_to_string("::1", false);
	test_sock_addr_to_string("192.168.2.1", false);
	test_sock_addr_to_string("fe80::6af7:28ff:fefa:d136", false);

	test_sock_addr_to_string("0.0.0.0:0", true);
	test_sock_addr_to_string("127.0.0.1:123", true);
	test_sock_addr_to_string("::1:234", true);
	test_sock_addr_to_string("192.168.2.1:123", true);
	test_sock_addr_to_string("fe80::6af7:28ff:fefa:d136:234", true);

	test_sock_addr_from_string_bad("0.0.0", false);
	test_sock_addr_from_string_bad("0.0.0:0", true);
	test_sock_addr_from_string_bad("fe80::6af7:28ff:fefa:d136", true);
	test_sock_addr_from_string_bad("junk", false);
	test_sock_addr_from_string_bad("0.0.0.0:0 trailing junk", true);

	test_sock_addr_from_string_memcmp("127.0.0.1", "127.0.0.1");
	test_sock_addr_from_string_memcmp("fe80::6af7:28ff:fefa:d136",
					  "fe80::6af7:28ff:fefa:d136");
	test_sock_addr_from_string_memcmp("::ffff:192.0.2.128", "192.0.2.128");

	test_sock_addr_cmp("127.0.0.1", "127.0.0.1" , false, 0);
	test_sock_addr_cmp("127.0.0.1", "127.0.0.2" , false, -1);
	test_sock_addr_cmp("127.0.0.2", "127.0.0.1" , false, 1);
	test_sock_addr_cmp("127.0.1.2", "127.0.2.1" , false, -1);
	test_sock_addr_cmp("127.0.2.1", "127.0.1.2" , false, 1);
	test_sock_addr_cmp("fe80::6af7:28ff:fefa:d136", "127.0.1.2" , false, 1);
	test_sock_addr_cmp("fe80::6af7:28ff:fefa:d136",
			   "fe80::6af7:28ff:fefa:d136" , false, 0);
	test_sock_addr_cmp("fe80::6af7:28ff:fefa:d136",
			   "fe80::6af7:28ff:fefa:d137" , false, -1);
	test_sock_addr_cmp("fe80::6af7:28ff:fefa:d136",
			   "fe80:0000:0000:0000:6af7:28ff:fefa:d136" ,
			   false, 0);
	test_sock_addr_cmp("::ffff:192.0.2.128", "192.0.2.128", false, 0);

	test_sock_addr_cmp("127.0.0.1:123", "127.0.0.1:124" , true, -1);
	test_sock_addr_cmp("fe80::6af7:28ff:fefa:d136:123",
			   "fe80::6af7:28ff:fefa:d136:122" , true, 1);

	test_sock_addr_mask_from_string("127.0.0.1/8");
	test_sock_addr_mask_from_string("::1/128");
	test_sock_addr_mask_from_string("fe80::6af7:28ff:fefa:d136/64");
	test_sock_addr_mask_from_string_bad("127.0.0.1");

	test_connection_to_string("127.0.0.1:12345 127.0.0.2:54321");
	test_connection_to_string("fe80::6af7:28ff:fefa:d137:12345 "
				  "fe80::6af7:28ff:fefa:d138:54321");

	test_connection_from_string_bad("127.0.0.1:12345 127.0.0.2:");
	test_connection_from_string_bad("127.0.0.1:12345");
	test_connection_from_string_bad("127.0.0.1:12345 "
					"fe80::6af7:28ff:fefa:d136:122");
	test_connection_from_string_bad("Junk!");
	test_connection_from_string_bad("More junk");

	test_connection_list_read(CONN4, CONN4_SORT);
	test_connection_list_read(CONN6, CONN6_SORT);
	test_connection_list_read(CONN4 CONN6, CONN4_SORT CONN6_SORT);
	test_connection_list_read(CONN4 "# Comment\n\n# Comment\n" CONN6,
				  CONN4_SORT CONN6_SORT);

	test_connection_list_read_bad(CONN4 "# Comment\n\nJunk!!!\n" CONN6);
	test_connection_list_read_bad(CONN4
				      "# Comment\n\n127.0.0.1: 127.0.0.1:124\n"
				      CONN6);

	return 0;
}
