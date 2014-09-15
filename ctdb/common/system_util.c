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

#include "includes.h"
#include "system/filesys.h"
#include "system/shmem.h"

#include <libgen.h>

#include "ctdb_private.h"

#if HAVE_SCHED_H
#include <sched.h>
#endif

#if HAVE_PROCINFO_H
#include <procinfo.h>
#endif

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
	int policy = SCHED_FIFO;

	p.sched_priority = 1;

#ifdef SCHED_RESET_ON_FORK
	policy |= SCHED_RESET_ON_FORK;
#endif
	if (sched_setscheduler(0, policy, &p) == -1) {
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
#ifndef SCHED_RESET_ON_FORK
	struct sched_param p;

	p.sched_priority = 0;
	if (sched_setscheduler(0, SCHED_OTHER, &p) == -1) {
		DEBUG(DEBUG_ERR, ("Unable to set scheduler to SCHED_OTHER\n"));
	}
#endif
#endif
#endif
}

void set_nonblocking(int fd)
{
	int v;

	v = fcntl(fd, F_GETFL, 0);
	if (v == -1) {
		DEBUG(DEBUG_WARNING, ("Failed to get file status flags - %s\n",
				      strerror(errno)));
		return;
	}
        if (fcntl(fd, F_SETFL, v | O_NONBLOCK) == -1) {
		DEBUG(DEBUG_WARNING, ("Failed to set non_blocking on fd - %s\n",
				      strerror(errno)));
	}
}

void set_close_on_exec(int fd)
{
	int v;

	v = fcntl(fd, F_GETFD, 0);
	if (v == -1) {
		DEBUG(DEBUG_WARNING, ("Failed to get file descriptor flags - %s\n",
				      strerror(errno)));
		return;
	}
	if (fcntl(fd, F_SETFD, v | FD_CLOEXEC) != 0) {
		DEBUG(DEBUG_WARNING, ("Failed to set close_on_exec on fd - %s\n",
				      strerror(errno)));
	}
}


bool parse_ipv4(const char *s, unsigned port, struct sockaddr_in *sin)
{
	sin->sin_family = AF_INET;
	sin->sin_port   = htons(port);

	if (inet_pton(AF_INET, s, &sin->sin_addr) != 1) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to translate %s into sin_addr\n", s));
		return false;
	}

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

	return true;
}

/*
  parse an ip
 */
bool parse_ip(const char *addr, const char *ifaces, unsigned port, ctdb_sock_addr *saddr)
{
	char *p;
	bool ret;

	ZERO_STRUCTP(saddr); /* valgrind :-) */

	/* now is this a ipv4 or ipv6 address ?*/
	p = index(addr, ':');
	if (p == NULL) {
		ret = parse_ipv4(addr, port, &saddr->ip);
	} else {
		ret = parse_ipv6(addr, ifaces, port, saddr);
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

/*
  parse a ip:port pair
 */
bool parse_ip_port(const char *addr, ctdb_sock_addr *saddr)
{
	char *p;
	char s[64]; /* Much longer than INET6_ADDRSTRLEN */
	unsigned port;
	char *endp = NULL;
	ssize_t len;
	bool ret;

	len = strlen(addr);
	if (len >= sizeof(s)) {
		DEBUG(DEBUG_ERR, ("Address %s is unreasonably long\n", addr));
		return false;
	}

	strncpy(s, addr, len+1);

	p = rindex(s, ':');
	if (p == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " This addr: %s does not contain a port number\n", s));
		return false;
	}

	port = strtoul(p+1, &endp, 10);
	if (endp == NULL || *endp != 0) {
		/* trailing garbage */
		DEBUG(DEBUG_ERR, (__location__ " Trailing garbage after the port in %s\n", s));
		return false;
	}
	*p = 0;

	/* now is this a ipv4 or ipv6 address ?*/
	ret = parse_ip(s, NULL, port, saddr);

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

int mkdir_p(const char *dir, int mode)
{
	char t[PATH_MAX];
	ssize_t len;
	int ret;

	if (strcmp(dir, "/") == 0) {
		return 0;
	}

	if (strcmp(dir, ".") == 0) {
		return 0;
	}

	/* Try to create directory */
	ret = mkdir(dir, mode);
	/* Succeed if that worked or if it already existed */
	if (ret == 0 || errno == EEXIST) {
		return 0;
	}
	/* Fail on anything else except ENOENT */
	if (errno != ENOENT) {
		return ret;
	}

	/* Create ancestors */
	len = strlen(dir);
	if (len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}
	strncpy(t, dir, len+1);

	ret = mkdir_p(dirname(t), mode);
	if (ret != 0) {
		return ret;
	}

	/* Create directory */
	ret = mkdir(dir, mode);
	if ((ret == -1) && (errno == EEXIST)) {
		ret = 0;
	}

	return ret;
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

/* A read wrapper that will deal with EINTR.  For now, copied from
 * source3/lib/system.c
 */
ssize_t sys_read(int fd, void *buf, size_t count)
{
        ssize_t ret;

        do {
                ret = read(fd, buf, count);
#if defined(EWOULDBLOCK)
        } while (ret == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
#else
        } while (ret == -1 && (errno == EINTR || errno == EAGAIN));
#endif
        return ret;
}

/* A write wrapper that will deal with EINTR.  For now, copied from
 * source3/lib/system.c
 */
ssize_t sys_write(int fd, const void *buf, size_t count)
{
        ssize_t ret;

        do {
                ret = write(fd, buf, count);
#if defined(EWOULDBLOCK)
        } while (ret == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
#else
        } while (ret == -1 && (errno == EINTR || errno == EAGAIN));
#endif
        return ret;
}
