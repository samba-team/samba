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

#include "common/system_util.c"

/* Test parsing of IPs, conversion to string */
static void test_sock_addr_to_string(const char *ip, bool with_port)
{
	ctdb_sock_addr sa;
	const char *s;
	bool status;

	if (with_port) {
		status = parse_ip_port(ip, &sa);
	} else {
		status = parse_ip(ip, NULL, 0, &sa);
	}
	assert(status);
	s = ctdb_sock_addr_to_string(NULL, &sa, with_port);
	assert(strcmp(ip, s) == 0);
	talloc_free(discard_const(s));
}

static void test_sock_addr_cmp(const char *ip1, const char *ip2, int res)
{
	ctdb_sock_addr sa1, sa2;
	int ret;

	assert(parse_ip(ip1, NULL, 0, &sa1));
	assert(parse_ip(ip2, NULL, 0, &sa2));
	ret = ctdb_sock_addr_cmp(&sa1, &sa2);
	if (ret < 0) {
		ret = -1;
	} else if (ret > 0) {
		ret = 1;
	}

	assert(ret == res);
}

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


	test_sock_addr_cmp("127.0.0.1", "127.0.0.1" , 0);
	test_sock_addr_cmp("127.0.0.1", "127.0.0.2" , -1);
	test_sock_addr_cmp("127.0.0.2", "127.0.0.1" , 1);
	test_sock_addr_cmp("127.0.1.2", "127.0.2.1" , -1);
	test_sock_addr_cmp("127.0.2.1", "127.0.1.2" , 1);
	test_sock_addr_cmp("fe80::6af7:28ff:fefa:d136", "127.0.1.2" , 1);
	test_sock_addr_cmp("fe80::6af7:28ff:fefa:d136",
			   "fe80::6af7:28ff:fefa:d136" , 0);
	test_sock_addr_cmp("fe80::6af7:28ff:fefa:d136",
			   "fe80::6af7:28ff:fefa:d137" , -1);
	test_sock_addr_cmp("fe80::6af7:28ff:fefa:d136",
			   "fe80:0000:0000:0000:6af7:28ff:fefa:d136" , 0);
	test_sock_addr_cmp("::ffff:192.0.2.128", "192.0.2.128", 0);

	return 0;
}
