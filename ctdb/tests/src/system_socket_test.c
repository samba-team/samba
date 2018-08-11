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

#include <assert.h>

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

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s <cmd> [<arg> ...]\n", prog);
	fprintf(stderr, "  commands:\n");
	fprintf(stderr, "    types\n");

	exit(1);
}

int main(int argc, char **argv)
{

	if (argc < 2) {
		usage(argv[0]);
	}

	if (strcmp(argv[1], "types") == 0) {
		test_types();
	} else {
		usage(argv[0]);
	}

	return 0;
}
