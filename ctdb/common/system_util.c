/*
   common system utilities

   Copyright (C) Amitay Isaacs  2014
   Copyright (C) Martin Schwenke  2014

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
#include "system/shmem.h"
#include "system/network.h"

#include <talloc.h>
#include <libgen.h>

#include "lib/util/debug.h"

#include "protocol/protocol.h"

#include "common/logging.h"
#include "common/system.h"

#if HAVE_SCHED_H
#include <sched.h>
#endif

#if HAVE_PROCINFO_H
#include <procinfo.h>
#endif

#include "lib/util/mkdir_p.h"

/*
  if possible, make this task real time
 */
bool set_scheduler(void)
{
#ifdef _AIX_
#if HAVE_THREAD_SETSCHED
	struct thrdentry64 te;
	tid64_t ti;

	ti = 0ULL;
	if (getthrds64(getpid(), &te, sizeof(te), &ti, 1) != 1) {
		DEBUG(DEBUG_ERR, ("Unable to get thread information\n"));
		return false;
	}

	if (thread_setsched(te.ti_tid, 0, SCHED_RR) == -1) {
		DEBUG(DEBUG_ERR, ("Unable to set scheduler to SCHED_RR (%s)\n",
				  strerror(errno)));
		return false;
	} else {
		return true;
	}
#endif
#else /* no AIX */
#if HAVE_SCHED_SETSCHEDULER
	struct sched_param p;

	p.sched_priority = 1;

	if (sched_setscheduler(0, SCHED_FIFO, &p) == -1) {
		DEBUG(DEBUG_CRIT,("Unable to set scheduler to SCHED_FIFO (%s)\n",
			 strerror(errno)));
		return false;
	} else {
		return true;
	}
#endif
#endif
	DEBUG(DEBUG_CRIT,("No way to set real-time priority.\n"));
	return false;
}

/*
  reset scheduler from real-time to normal scheduling
 */
void reset_scheduler(void)
{
#ifdef _AIX_
#if HAVE_THREAD_SETSCHED
	struct thrdentry64 te;
	tid64_t ti;

	ti = 0ULL;
	if (getthrds64(getpid(), &te, sizeof(te), &ti, 1) != 1) {
		DEBUG(DEBUG_ERR, ("Unable to get thread information\n"));
	}
	if (thread_setsched(te.ti_tid, 0, SCHED_OTHER) == -1) {
		DEBUG(DEBUG_ERR, ("Unable to set scheduler to SCHED_OTHER\n"));
	}
#endif
#else /* no AIX */
#if HAVE_SCHED_SETSCHEDULER
	struct sched_param p;

	p.sched_priority = 0;
	if (sched_setscheduler(0, SCHED_OTHER, &p) == -1) {
		DEBUG(DEBUG_ERR, ("Unable to set scheduler to SCHED_OTHER\n"));
	}
#endif
#endif
}

static bool parse_ipv4(const char *s, unsigned port, struct sockaddr_in *sin)
{
	sin->sin_family = AF_INET;
	sin->sin_port   = htons(port);

	if (inet_pton(AF_INET, s, &sin->sin_addr) != 1) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to translate %s into sin_addr\n", s));
		return false;
	}

#ifdef HAVE_SOCK_SIN_LEN
	sin->sin_len = sizeof(*sin);
#endif
	return true;
}

static bool parse_ipv6(const char *s, const char *ifaces, unsigned port, ctdb_sock_addr *saddr)
{
	saddr->ip6.sin6_family   = AF_INET6;
	saddr->ip6.sin6_port     = htons(port);
	saddr->ip6.sin6_flowinfo = 0;
	saddr->ip6.sin6_scope_id = 0;

	if (inet_pton(AF_INET6, s, &saddr->ip6.sin6_addr) != 1) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to translate %s into sin6_addr\n", s));
		return false;
	}

	if (ifaces && IN6_IS_ADDR_LINKLOCAL(&saddr->ip6.sin6_addr)) {
		if (strchr(ifaces, ',')) {
			DEBUG(DEBUG_ERR, (__location__ " Link local address %s "
					  "is specified for multiple ifaces %s\n",
					  s, ifaces));
			return false;
		}
		saddr->ip6.sin6_scope_id = if_nametoindex(ifaces);
	}

#ifdef HAVE_SOCK_SIN_LEN
	saddr->ip6.sin6_len = sizeof(*saddr);
#endif
	return true;
}

/*
  parse an ip
 */
static bool parse_ip(const char *addr, const char *ifaces, unsigned port,
		     ctdb_sock_addr *saddr)
{
	char *p;
	bool ret;

	ZERO_STRUCTP(saddr); /* valgrind :-) */

	/* IPv4 or IPv6 address?
	 *
	 * Use rindex() because we need the right-most ':' below for
	 * IPv4-mapped IPv6 addresses anyway...
	 */
	p = rindex(addr, ':');
	if (p == NULL) {
		ret = parse_ipv4(addr, port, &saddr->ip);
	} else {
		uint8_t ipv4_mapped_prefix[12] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
		};

		ret = parse_ipv6(addr, ifaces, port, saddr);
		if (! ret) {
			return ret;
		}

		/*
		 * Check for IPv4-mapped IPv6 address
		 * (e.g. ::ffff:192.0.2.128) - reparse as IPv4 if
		 * necessary
		 */
		if (memcmp(&saddr->ip6.sin6_addr.s6_addr[0],
			   ipv4_mapped_prefix,
			   sizeof(ipv4_mapped_prefix)) == 0) {
			/* Reparse as IPv4 */
			ret = parse_ipv4(p+1, port, &saddr->ip);
		}
	}

	return ret;
}

/*
  parse a ip/mask pair
 */
bool parse_ip_mask(const char *str, const char *ifaces, ctdb_sock_addr *addr, unsigned *mask)
{
	char *p;
	char s[64]; /* Much longer than INET6_ADDRSTRLEN */
	char *endp = NULL;
	ssize_t len;
	bool ret;

	ZERO_STRUCT(*addr);

	len = strlen(str);
	if (len >= sizeof(s)) {
		DEBUG(DEBUG_ERR, ("Address %s is unreasonably long\n", str));
		return false;
	}

	strncpy(s, str, len+1);

	p = rindex(s, '/');
	if (p == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " This addr: %s does not contain a mask\n", s));
		return false;
	}

	*mask = strtoul(p+1, &endp, 10);
	if (endp == NULL || *endp != 0) {
		/* trailing garbage */
		DEBUG(DEBUG_ERR, (__location__ " Trailing garbage after the mask in %s\n", s));
		return false;
	}
	*p = 0;


	/* now is this a ipv4 or ipv6 address ?*/
	ret = parse_ip(s, ifaces, 0, addr);

	return ret;
}

/* we don't lock future pages here; it would increase the chance that
 * we'd fail to mmap later on. */
void lockdown_memory(bool valgrinding)
{
#if defined(HAVE_MLOCKALL) && !defined(_AIX_)
	/* Extra stack, please! */
	char dummy[10000];
	memset(dummy, 0, sizeof(dummy));

	if (valgrinding) {
		return;
	}

	/* Ignore when running in local daemons mode */
	if (getuid() != 0) {
		return;
	}

	/* Avoid compiler optimizing out dummy. */
	mlock(dummy, sizeof(dummy));
	if (mlockall(MCL_CURRENT) != 0) {
		DEBUG(DEBUG_WARNING,("Failed to lockdown memory: %s'\n",
				     strerror(errno)));
	}
#endif
}

void mkdir_p_or_die(const char *dir, int mode)
{
	int ret;

	ret = mkdir_p(dir, mode);
	if (ret != 0) {
		DEBUG(DEBUG_ALERT,
		      ("ctdb exiting with error: "
		       "failed to create directory \"%s\" (%s)\n",
		       dir, strerror(errno)));
		exit(1);
	}
}

void ctdb_wait_for_process_to_exit(pid_t pid)
{
	while (kill(pid, 0) == 0 || errno != ESRCH) {
		sleep(5);
	}
}
