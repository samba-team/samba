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

static void hexdump(uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			if (i != 0) {
				printf("\n");
			}
			printf("%06zx", i);
		}
		printf(" %02x", buf[i]);
	}

	printf("\n%06zx\n", i);
}

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

	hexdump(buf, len);
}

#else /* HAVE_PACKETSOCKET  */

static void test_arp(const char *addr_str, const char *hwaddr_str, bool reply)
{
	fprintf(stderr, "PACKETSOCKET not supported\n");
}

#endif /* HAVE_PACKETSOCKET */

static void test_tcp(const char *src_str,
		     const char *dst_str,
		     const char *seq_str,
		     const char *ack_str,
		     const char *rst_str)
{
	ctdb_sock_addr src, dst;
	uint32_t seq, ack;
	int rst;
	uint8_t buf[512];
	struct ether_header *eth;
	size_t expected_len, len;
	char src_str_out[64], dst_str_out[64];
	uint32_t seq_out, ack_out;
	int rst_out = 0;
	uint16_t window;
	int ret;

	ret = ctdb_sock_addr_from_string(src_str, &src, true);
	assert(ret == 0);

	ret = ctdb_sock_addr_from_string(dst_str, &dst, true);
	assert(ret == 0);

	seq = atoi(seq_str);
	ack = atoi(ack_str);
	rst = atoi(rst_str);

	/* Need to fake this up */
	eth = (struct ether_header *) buf;
	memset(eth, 0, sizeof(*eth));

	switch (src.ip.sin_family) {
	case AF_INET:
		eth->ether_type = htons(ETHERTYPE_IP);
		expected_len = 40;
		ret = tcp4_build(buf + sizeof(struct ether_header),
				 sizeof(buf) - sizeof(struct ether_header),
				 &src.ip,
				 &dst.ip,
				 seq,
				 ack,
				 rst,
				 &len);
		break;
	case AF_INET6:
		eth->ether_type = htons(ETHERTYPE_IP6);
		expected_len = 60;
		ret = tcp6_build(buf + sizeof(struct ether_header),
				 sizeof(buf) - sizeof(struct ether_header),
				 &src.ip6,
				 &dst.ip6,
				 seq,
				 ack,
				 rst,
				 &len);
		break;
	default:
		abort();
	}

	assert(ret == 0);
	assert(len == expected_len);

	hexdump(buf + sizeof(struct ether_header), len);

	switch (ntohs(eth->ether_type)) {
	case ETHERTYPE_IP:
		ret = tcp4_extract(buf + sizeof(struct ether_header),
				   len,
				   &src.ip,
				   &dst.ip,
				   &ack_out,
				   &seq_out,
				   &rst_out,
				   &window);
		break;
	case ETHERTYPE_IP6:
		ret = tcp6_extract(buf + sizeof(struct ether_header),
				   len,
				   &src.ip6,
				   &dst.ip6,
				   &ack_out,
				   &seq_out,
				   &rst_out,
				   &window);
		break;
	default:
		abort();
	}

	assert(ret == 0);

	assert(seq == seq_out);
	assert(ack == ack_out);
	assert((rst != 0) == (rst_out != 0));
	assert(window == htons(1234));

	ret = ctdb_sock_addr_to_buf(src_str_out, sizeof(src_str_out),
				    &src, true);
	assert(ret == 0);
	ret = strcmp(src_str, src_str_out);
	assert(ret == 0);

	ret = ctdb_sock_addr_to_buf(dst_str_out, sizeof(dst_str_out),
				    &dst, true);
	assert(ret == 0);
	ret = strcmp(dst_str, dst_str_out);
	assert(ret == 0);
}

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s <cmd> [<arg> ...]\n", prog);
	fprintf(stderr, "  commands:\n");
	fprintf(stderr, "    types\n");
	fprintf(stderr, "    arp <ipaddr> <hwaddr> [reply]\n");
	fprintf(stderr, "    tcp <src> <dst> <seq> <ack> <rst>\n");

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
	} else if (strcmp(argv[1], "tcp") == 0) {
		if (argc != 7) {
			usage(argv[0]);
		}
		test_tcp(argv[2], argv[3], argv[4], argv[5], argv[6]);
	} else {
		usage(argv[0]);
	}

	return 0;
}
