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

#include "common/line.h"

#include "protocol.h"
#include "protocol_util.h"
#include "lib/util/util.h"

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

int ctdb_sock_addr_to_buf(char *buf, socklen_t buflen,
			  ctdb_sock_addr *addr, bool with_port)
{
	const char *t;

	switch (addr->sa.sa_family) {
	case AF_INET:
		t = inet_ntop(addr->ip.sin_family, &addr->ip.sin_addr,
			      buf, buflen);
		if (t == NULL) {
			return errno;
		}
		break;

	case AF_INET6:
		t = inet_ntop(addr->ip6.sin6_family, &addr->ip6.sin6_addr,
			      buf, buflen);
		if (t == NULL) {
			return errno;
		}
		break;

	default:
		return EAFNOSUPPORT;
		break;
	}

	if (with_port) {
		size_t len = strlen(buf);
		int ret;

		ret = snprintf(buf+len, buflen-len,
			       ":%u", ctdb_sock_addr_port(addr));
		if (ret < 0 || (size_t)ret >= buflen-len) {
			return ENOSPC;
		}
	}

	return 0;
}

char *ctdb_sock_addr_to_string(TALLOC_CTX *mem_ctx,
			       ctdb_sock_addr *addr,
			       bool with_port)
{
	size_t len = 64;
	char *cip;
	int ret;

	cip = talloc_size(mem_ctx, len);

	if (cip == NULL) {
		return NULL;
	}

	ret = ctdb_sock_addr_to_buf(cip, len, addr, with_port);
	if (ret != 0) {
		talloc_free(cip);
		return NULL;
	}

	return cip;
}

static int ipv4_from_string(const char *str, struct sockaddr_in *ip)
{
	int ret;

	*ip = (struct sockaddr_in) {
		.sin_family = AF_INET,
	};

	ret = inet_pton(AF_INET, str, &ip->sin_addr);
	if (ret != 1) {
		return EINVAL;
	}

#ifdef HAVE_SOCK_SIN_LEN
	ip->sin_len = sizeof(*ip);
#endif
	return 0;
}

static int ipv6_from_string(const char *str, struct sockaddr_in6 *ip6)
{
	int ret;

	*ip6 = (struct sockaddr_in6) {
		.sin6_family   = AF_INET6,
	};

	ret = inet_pton(AF_INET6, str, &ip6->sin6_addr);
	if (ret != 1) {
		return EINVAL;
	}

#ifdef HAVE_SOCK_SIN6_LEN
	ip6->sin6_len = sizeof(*ip6);
#endif
	return 0;
}

static int ip_from_string(const char *str, ctdb_sock_addr *addr)
{
	char *p;
	int ret;

	if (addr == NULL) {
		return EINVAL;
	}

	ZERO_STRUCTP(addr); /* valgrind :-) */

	/* IPv4 or IPv6 address?
	 *
	 * Use rindex() because we need the right-most ':' below for
	 * IPv4-mapped IPv6 addresses anyway...
	 */
	p = rindex(str, ':');
	if (p == NULL) {
		ret = ipv4_from_string(str, &addr->ip);
	} else {
		uint8_t ipv4_mapped_prefix[12] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
		};

		ret = ipv6_from_string(str, &addr->ip6);
		if (ret != 0) {
			return ret;
		}

		/*
		 * Check for IPv4-mapped IPv6 address
		 * (e.g. ::ffff:192.0.2.128) - reparse as IPv4 if
		 * necessary
		 */
		if (memcmp(&addr->ip6.sin6_addr.s6_addr[0],
			   ipv4_mapped_prefix,
			   sizeof(ipv4_mapped_prefix)) == 0) {
                        /* Initialize addr struct to zero before reparsing as IPV4 */
                        ZERO_STRUCTP(addr);

			/* Reparse as IPv4 */
			ret = ipv4_from_string(p+1, &addr->ip);
		}
	}

	return ret;
}

int ctdb_sock_addr_from_string(const char *str,
			       ctdb_sock_addr *addr, bool with_port)
{
	char *p;
	char s[64]; /* Much longer than INET6_ADDRSTRLEN */
	unsigned port;
	size_t len;
	int ret;

	if (! with_port) {
		ret = ip_from_string(str, addr);
		return ret;
	}

	/* Parse out port number and then IP address */

	len = strlcpy(s, str, sizeof(s));
	if (len >= sizeof(s)) {
		return EINVAL;
	}

	p = rindex(s, ':');
	if (p == NULL) {
		return EINVAL;
	}

	port = smb_strtoul(p+1, NULL, 10, &ret, SMB_STR_FULL_STR_CONV);
	if (ret != 0) {
		/* Empty string or trailing garbage */
		return EINVAL;
	}

	*p = '\0';
	ret = ip_from_string(s, addr);

	ctdb_sock_addr_set_port(addr, port);

	return ret;
}

int ctdb_sock_addr_mask_from_string(const char *str,
				    ctdb_sock_addr *addr,
				    unsigned int *mask)
{
	char *p;
	char s[64]; /* Much longer than INET6_ADDRSTRLEN */
	unsigned int m;
	size_t len;
	int ret = 0;

	if (addr == NULL || mask == NULL) {
		return EINVAL;
	}

	len = strlcpy(s, str, sizeof(s));
	if (len >= sizeof(s)) {
		return EINVAL;
	}

	p = rindex(s, '/');
	if (p == NULL) {
		return EINVAL;
	}

	m = smb_strtoul(p+1, NULL, 10, &ret, SMB_STR_FULL_STR_CONV);
	if (ret != 0) {
		/* Empty string or trailing garbage */
		return EINVAL;
	}

	*p = '\0';
	ret = ip_from_string(s, addr);

	if (ret == 0) {
		*mask = m;
	}

	return ret;
}

unsigned int ctdb_sock_addr_port(ctdb_sock_addr *addr)
{
	switch (addr->sa.sa_family) {
	case AF_INET:
		return ntohs(addr->ip.sin_port);
		break;
	case AF_INET6:
		return ntohs(addr->ip6.sin6_port);
		break;
	default:
		return 0;
	}
}

void ctdb_sock_addr_set_port(ctdb_sock_addr *addr, unsigned int port)
{
	switch (addr->sa.sa_family) {
	case AF_INET:
		addr->ip.sin_port = htons(port);
		break;
	case AF_INET6:
		addr->ip6.sin6_port = htons(port);
		break;
	default:
		break;
	}
}

static int ctdb_sock_addr_cmp_family(const ctdb_sock_addr *addr1,
				     const ctdb_sock_addr *addr2)
{
	/* This is somewhat arbitrary.  However, when used for sorting
	 * it just needs to be consistent.
	 */
	if (addr1->sa.sa_family < addr2->sa.sa_family) {
		return -1;
	}
	if (addr1->sa.sa_family > addr2->sa.sa_family) {
		return 1;
	}

	return 0;
}

int ctdb_sock_addr_cmp_ip(const ctdb_sock_addr *addr1,
			  const ctdb_sock_addr *addr2)
{
	int ret;

	ret = ctdb_sock_addr_cmp_family(addr1, addr2);
	if (ret != 0) {
		return ret;
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

int ctdb_connection_to_buf(char *buf, size_t buflen,
			   struct ctdb_connection *conn, bool client_first)
{
	char server[64], client[64];
	int ret;

	ret = ctdb_sock_addr_to_buf(server, sizeof(server),
				    &conn->server, true);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_sock_addr_to_buf(client, sizeof(client),
				    &conn->client, true);
	if (ret != 0) {
		return ret;
	}

	if (! client_first) {
		ret = snprintf(buf, buflen, "%s %s", server, client);
	} else {
		ret = snprintf(buf, buflen, "%s %s", client, server);
	}
	if (ret < 0 || (size_t)ret >= buflen) {
		return ENOSPC;
	}

	return 0;
}

char *ctdb_connection_to_string(TALLOC_CTX *mem_ctx,
				struct ctdb_connection *conn,
				bool client_first)
{
	const size_t len = 128;
	char *out;
	int ret;

	out = talloc_size(mem_ctx, len);
	if (out == NULL) {
		return NULL;
	}

	ret = ctdb_connection_to_buf(out, len, conn, client_first);
	if (ret != 0) {
		talloc_free(out);
		return NULL;
	}

	return out;
}

int ctdb_connection_from_string(const char *str, bool client_first,
				struct ctdb_connection *conn)
{
	char s[128];
	char *t1 = NULL, *t2 = NULL;
	size_t len;
	ctdb_sock_addr *first = (client_first ? &conn->client : &conn->server);
	ctdb_sock_addr *second = (client_first ? &conn->server : &conn->client);
	int ret;

	len = strlcpy(s, str, sizeof(s));
	if (len >= sizeof(s)) {
		return EINVAL;
	}

	t1 = strtok(s, " \t\n");
	if (t1 == NULL) {
		return EINVAL;
	}

	t2 = strtok(NULL, " \t\n\0");
	if (t2 == NULL) {
		return EINVAL;
	}

	ret = ctdb_sock_addr_from_string(t1, first, true);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_sock_addr_from_string(t2, second, true);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_sock_addr_cmp_family(first, second);
	if (ret != 0) {
		return EINVAL;
	}

	return 0;
}

int ctdb_connection_list_add(struct ctdb_connection_list *conn_list,
			     struct ctdb_connection *conn)
{
	uint32_t len;

	if (conn_list == NULL) {
		return EINVAL;
	}

	/* Ensure array is big enough */
	len = talloc_array_length(conn_list->conn);
	if (conn_list->num == len) {
		conn_list->conn = talloc_realloc(conn_list, conn_list->conn,
						 struct ctdb_connection,
						 len+128);
		if (conn_list->conn == NULL) {
			return ENOMEM;
		}
	}

	conn_list->conn[conn_list->num] = *conn;
	conn_list->num++;

	return 0;
}

static int connection_cmp(const void *a, const void *b)
{
	const struct ctdb_connection *conn_a = a;
	const struct ctdb_connection *conn_b = b;
	int ret;

	ret = ctdb_sock_addr_cmp(&conn_a->server, &conn_b->server);
	if (ret == 0) {
		ret = ctdb_sock_addr_cmp(&conn_a->client, &conn_b->client);
	}

	return ret;
}

int ctdb_connection_list_sort(struct ctdb_connection_list *conn_list)
{
	if (conn_list == NULL) {
		return EINVAL;
	}

	if (conn_list->num > 0) {
		qsort(conn_list->conn, conn_list->num,
		      sizeof(struct ctdb_connection), connection_cmp);
	}

	return 0;
}

char *ctdb_connection_list_to_string(
	TALLOC_CTX *mem_ctx,
	struct ctdb_connection_list *conn_list, bool client_first)
{
	uint32_t i;
	char *out;

	out = talloc_strdup(mem_ctx, "");
	if (out == NULL) {
		return NULL;
	}

	if (conn_list == NULL || conn_list->num == 0) {
		return out;
	}

	for (i = 0; i < conn_list->num; i++) {
		char buf[128];
		int ret;

		ret = ctdb_connection_to_buf(buf, sizeof(buf),
					     &conn_list->conn[i], client_first);
		if (ret != 0) {
			talloc_free(out);
			return NULL;
		}

		out = talloc_asprintf_append(out, "%s\n", buf);
		if (out == NULL) {
			return NULL;
		}
	}

	return out;
}

struct ctdb_connection_list_read_state {
	struct ctdb_connection_list *list;
	bool client_first;
};

static int ctdb_connection_list_read_line(char *line, void *private_data)
{
	struct ctdb_connection_list_read_state *state =
		(struct ctdb_connection_list_read_state *)private_data;
	struct ctdb_connection conn;
	int ret;

	/* Skip empty lines */
	if (line[0] == '\0') {
		return 0;
	}

	/* Comment */
	if (line[0] == '#') {
		return 0;
	}

	ret = ctdb_connection_from_string(line, state->client_first, &conn);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_connection_list_add(state->list, &conn);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

int ctdb_connection_list_read(TALLOC_CTX *mem_ctx,
			      int fd,
			      bool client_first,
			      struct ctdb_connection_list **conn_list)
{
	struct ctdb_connection_list_read_state state;
	int ret;

	if (conn_list == NULL) {
		return EINVAL;
	}

	state.list = talloc_zero(mem_ctx, struct ctdb_connection_list);
	if (state.list == NULL) {
		return ENOMEM;
	}

	state.client_first = client_first;

	ret = line_read(fd,
			128,
			mem_ctx,
			ctdb_connection_list_read_line,
			&state,
			NULL);

	*conn_list = state.list;

	return ret;
}
