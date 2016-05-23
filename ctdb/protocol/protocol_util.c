/*
   CTDB protocol marshalling

   Copyright (C) Amitay Isaacs  2015

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

#include <talloc.h>
#include <tdb.h>

#include "protocol.h"
#include "protocol_private.h"
#include "protocol_api.h"

static struct {
	enum ctdb_runstate runstate;
	const char * label;
} runstate_map[] = {
	{ CTDB_RUNSTATE_UNKNOWN, "UNKNOWN" },
	{ CTDB_RUNSTATE_INIT, "INIT" },
	{ CTDB_RUNSTATE_SETUP, "SETUP" },
	{ CTDB_RUNSTATE_FIRST_RECOVERY, "FIRST_RECOVERY" },
	{ CTDB_RUNSTATE_STARTUP, "STARTUP" },
	{ CTDB_RUNSTATE_RUNNING, "RUNNING" },
	{ CTDB_RUNSTATE_SHUTDOWN, "SHUTDOWN" },
	{ -1, NULL },
};

const char *ctdb_runstate_to_string(enum ctdb_runstate runstate)
{
	int i;

	for (i=0; runstate_map[i].label != NULL; i++) {
		if (runstate_map[i].runstate == runstate) {
			return runstate_map[i].label;
		}
	}

	return runstate_map[0].label;
}

enum ctdb_runstate ctdb_runstate_from_string(const char *runstate_str)
{
	int i;

	for (i=0; runstate_map[i].label != NULL; i++) {
		if (strcasecmp(runstate_map[i].label,
			       runstate_str) == 0) {
			return runstate_map[i].runstate;
		}
	}

	return CTDB_RUNSTATE_UNKNOWN;
}

static struct {
	enum ctdb_event event;
	const char *label;
} event_map[] = {
	{ CTDB_EVENT_INIT, "init" },
	{ CTDB_EVENT_SETUP, "setup" },
	{ CTDB_EVENT_STARTUP, "startup" },
	{ CTDB_EVENT_START_RECOVERY, "startrecovery" },
	{ CTDB_EVENT_RECOVERED, "recovered" },
	{ CTDB_EVENT_TAKE_IP, "takeip" },
	{ CTDB_EVENT_RELEASE_IP, "releaseip" },
	{ CTDB_EVENT_MONITOR, "monitor" },
	{ CTDB_EVENT_SHUTDOWN, "shutdown" },
	{ CTDB_EVENT_UPDATE_IP, "updateip" },
	{ CTDB_EVENT_IPREALLOCATED, "ipreallocated" },
	{ CTDB_EVENT_MAX, "all" },
	{ -1, NULL },
};

const char *ctdb_event_to_string(enum ctdb_event event)
{
	int i;

	for (i=0; event_map[i].label != NULL; i++) {
		if (event_map[i].event == event) {
			return event_map[i].label;
		}
	}

	return "unknown";
}

enum ctdb_event ctdb_event_from_string(const char *event_str)
{
	int i;

	for (i=0; event_map[i].label != NULL; i++) {
		if (strcmp(event_map[i].label, event_str) == 0) {
			return event_map[i].event;
		}
	}

	return CTDB_EVENT_MAX;
}

const char *ctdb_sock_addr_to_string(TALLOC_CTX *mem_ctx, ctdb_sock_addr *addr)
{
	char *cip;

	cip = talloc_size(mem_ctx, 128);
	if (cip == NULL) {
		return "Memory Error";
	}

	switch (addr->sa.sa_family) {
	case AF_INET:
		inet_ntop(addr->ip.sin_family, &addr->ip.sin_addr,
			  cip, 128);
		break;

	case AF_INET6:
		inet_ntop(addr->ip6.sin6_family, &addr->ip6.sin6_addr,
			  cip, 128);
		break;

	default:
		sprintf(cip, "Unknown family %u", addr->sa.sa_family);
		break;
	}

	return cip;
}

int ctdb_sock_addr_cmp_ip(const ctdb_sock_addr *addr1,
			  const ctdb_sock_addr *addr2)
{
	int ret = 0;

	/* This is somewhat arbitrary.  However, when used for sorting
	 * it just needs to be consistent.
	 */
	if (addr1->sa.sa_family < addr2->sa.sa_family) {
		return -1;
	}
	if (addr1->sa.sa_family > addr2->sa.sa_family) {
		return 1;
	}

	switch (addr1->sa.sa_family) {
	case AF_INET:
		ret = memcmp(&addr1->ip.sin_addr.s_addr,
			     &addr2->ip.sin_addr.s_addr, 4);
		break;

	case AF_INET6:
		ret = memcmp(addr1->ip6.sin6_addr.s6_addr,
			     addr2->ip6.sin6_addr.s6_addr, 16);
		break;

	default:
		ret = -1;
	}

	return ret;
}

int ctdb_sock_addr_cmp(const ctdb_sock_addr *addr1,
		       const ctdb_sock_addr *addr2)
{
	int ret = 0;

	ret = ctdb_sock_addr_cmp_ip(addr1, addr2);
	if (ret != 0) {
		return ret;
	}

	switch (addr1->sa.sa_family) {
	case AF_INET:
		if (addr1->ip.sin_port < addr2->ip.sin_port) {
			ret = -1;
		} else if (addr1->ip.sin_port > addr2->ip.sin_port) {
			ret = 1;
		}
		break;

	case AF_INET6:
		if (addr1->ip6.sin6_port < addr2->ip6.sin6_port) {
			ret = -1;
		} else if (addr1->ip6.sin6_port > addr2->ip6.sin6_port) {
			ret = 1;
		}
		break;

	default:
		ret = -1;
	}

	return ret;
}

bool ctdb_sock_addr_same_ip(const ctdb_sock_addr *addr1,
			    const ctdb_sock_addr *addr2)
{
	return (ctdb_sock_addr_cmp_ip(addr1, addr2) == 0);
}

bool ctdb_sock_addr_same(const ctdb_sock_addr *addr1,
			 const ctdb_sock_addr *addr2)
{
	return (ctdb_sock_addr_cmp(addr1, addr2) == 0);
}
