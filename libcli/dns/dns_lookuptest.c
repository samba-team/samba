/*
 *  Unix SMB/CIFS implementation.
 *  Internal DNS query structures
 *  Copyright (C) Volker Lendecke 2018
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <talloc.h>
#include <errno.h>
#include "libcli/dns/dns_lookup.h"
#include "lib/util/debug.h"

static int dns_lookuptest1(void)
{
	struct dns_name_packet *reply = NULL;
	int ret;

	ret = dns_lookup(NULL, "www.samba.org", DNS_QCLASS_IN, DNS_QTYPE_A,
			 NULL, &reply);
	if (ret != 0) {
		fprintf(stderr, "dns_lookup failed: %s\n", strerror(ret));
		return ret;
	}

	TALLOC_FREE(reply);
	return 0;
}

int main(int argc, const char *argv[]) {
	int ret;

	setup_logging(argv[0], DEBUG_DEFAULT_STDERR);
	debug_parse_levels("10");

	ret = dns_lookuptest1();
	if (ret != 0) {
		return 1;
	}

	return 0;
}
