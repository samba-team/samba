/*
   CTDB SM_NOTIFY helper for NFSv3 statd snippets

   Copyright 2023, DataDirect Networks, Inc. All rights reserved.
   Author: Martin Schwenke <mschwenke@ddn.com>

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

#include "lib/util/sys_rw.h"

static void print_monitor_line(const char *client_ip,
			       const char *server_ip)
{
	/*
	 * sm-notify doesn't read priv.  rpc.statd appears to use it
	 * for uniqueness of multi-line files.
	 */
	const char *priv = "00000000000000000000000000000000";
	/*
	 * sm_mon_1_svc() takes care to write in this format, so let's
	 * do that too, even though sm-notify ignores this field...
	 */
	uint32_t inaddr_loopback = htonl(INADDR_LOOPBACK);

	printf("%08x %08x %08x %08x %s %s %s\n",
	       inaddr_loopback,
	       100021, /* NLM_PROG */
	       4, /* SM_VERS */
	       16,
	       priv,
	       client_ip,
	       server_ip);
}

static void print_state(const char *state_str)
{
	int state = atoi(state_str);

	/*
	 * Uncomplicated binary output.  sm-notify just reads this as
	 * an int via nsm_get_state().  This file will always be
	 * created in a local temporary directory and is consumed by
	 * sm-notify locally, so no inter-node endianness issues.
	 */
	sys_write(STDOUT_FILENO, &state, sizeof(state));
}

static void usage(const char *prog)
{
	printf("usage: %s { monitor <client-ip> <source-ip> | state <state> }\n",
	       prog);
	exit(1);
}

int main(int argc, const char *argv[])
{
	if (argc == 4 && strcmp(argv[1], "monitor") == 0) {
		print_monitor_line(argv[2], argv[3]);
	} else if (argc == 3 && strcmp(argv[1], "state") == 0) {
		print_state(argv[2]);
	} else {
		usage(argv[0]);
	}

	return 0;
}
