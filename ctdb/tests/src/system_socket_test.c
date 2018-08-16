/*
   Raw socket (un) marshalling tests

   Copyright (C) Martin Schwenke  2018

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

#include <assert.h>

/* For ether_aton() */
#ifdef _AIX
#include <arpa/inet.h>
#endif
#ifdef __FreeBSD__
#include <net/ethernet.h>
#endif
#ifdef linux
#include <netinet/ether.h>
#endif

#include "common/system_socket.c"

#include "protocol/protocol_util.h"

static void test_types(void)
{
	/*
	 * We use this struct in the code but don't pack it due to
	 * portability concerns.  It should have no padding.
	 */
	struct {
		struct ip ip;
		struct tcphdr tcp;
	} ip4pkt;

	assert(sizeof(ip4pkt) == sizeof(struct ip) + sizeof(struct tcphdr));
}

#ifdef HAVE_PACKETSOCKET

static void test_arp(const char *addr_str, const char *hwaddr_str, bool reply)
{
	ctdb_sock_addr addr;
	struct ether_addr *hw, *dhw;
	uint8_t buf[512];
	size_t buflen = sizeof(buf);
	size_t len;
	int ret;

	ret = ctdb_sock_addr_from_string(addr_str, &addr, false);
	assert(ret == 0);

	hw = ether_aton(hwaddr_str);
	assert(hw != NULL);

	switch (addr.ip.sin_family) {
	case AF_INET:
		ret = arp_build(buf, buflen, &addr.ip, hw, reply, &dhw, &len);
		break;
	case AF_INET6:
		ret = ip6_na_build(buf, buflen, &addr.ip6, hw, &dhw, &len);
		break;
	default:
		abort();
	}

	assert(ret == 0);

	write(STDOUT_FILENO, buf, len);
}

#else /* HAVE_PACKETSOCKET  */

static void test_arp(const char *addr_str, const char *hwaddr_str, bool reply)
{
	fprintf(stderr, "PACKETSOCKET not supported\n");
}

#endif /* HAVE_PACKETSOCKET */

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s <cmd> [<arg> ...]\n", prog);
	fprintf(stderr, "  commands:\n");
	fprintf(stderr, "    types\n");
	fprintf(stderr, "    arp <ipaddr> <hwaddr> [reply]\n");

	exit(1);
}

int main(int argc, char **argv)
{

	if (argc < 2) {
		usage(argv[0]);
	}

	if (strcmp(argv[1], "types") == 0) {
		test_types();
	} else if (strcmp(argv[1], "arp") == 0) {
		/*
		 * Extra arg indicates that a reply should be
		 * constructed for IPv4 - value is ignored
		 */
		if (argc != 4 && argc != 5) {
			usage(argv[0]);
		}
		test_arp(argv[2], argv[3], (argc == 5));
	} else {
		usage(argv[0]);
	}

	return 0;
}
