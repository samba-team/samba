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

#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

#ifdef HAVE_PROCINFO_H
#include <procinfo.h>
#endif

/*
  if possible, make this task real time
 */
bool set_scheduler(void)
{
#ifdef _AIX_
#ifdef HAVE_THREAD_SETSCHED
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
#ifdef HAVE_SCHED_SETSCHEDULER
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
#ifdef HAVE_THREAD_SETSCHED
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
#ifdef HAVE_SCHED_SETSCHEDULER
	struct sched_param p;

	p.sched_priority = 0;
	if (sched_setscheduler(0, SCHED_OTHER, &p) == -1) {
		DEBUG(DEBUG_ERR, ("Unable to set scheduler to SCHED_OTHER\n"));
	}
#endif
#endif
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

void ctdb_wait_for_process_to_exit(pid_t pid)
{
	while (kill(pid, 0) == 0 || errno != ESRCH) {
		sleep(5);
	}
}

#ifdef HAVE_IF_NAMETOINDEX

bool ctdb_sys_check_iface_exists(const char *iface)
{
	unsigned int index = 0;

	index = if_nametoindex(iface);

	return index != 0;
}

#else /* HAVE_IF_NAMETOINDEX */

bool ctdb_sys_check_iface_exists(const char *iface)
{
	/* Not implemented: Interface always considered present */
	return true;
}

#endif /* HAVE_IF_NAMETOINDEX */

#ifdef HAVE_PEERCRED

int ctdb_get_peer_pid(const int fd, pid_t *peer_pid)
{
	struct ucred cr;
	socklen_t crl = sizeof(struct ucred);
	int ret;

	ret = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &crl);
	if (ret == 0) {
		*peer_pid = cr.pid;
	} else {
		*peer_pid = -1;
	}
	return ret;
}

#else /* HAVE_PEERCRED */

#ifdef _AIX_

int ctdb_get_peer_pid(const int fd, pid_t *peer_pid)
{
	struct peercred_struct cr;
	socklen_t crl = sizeof(struct peercred_struct);
	int ret;

	ret = getsockopt(fd, SOL_SOCKET, SO_PEERID, &cr, &crl);
	if (ret == 0) {
		*peer_pid = cr.pid;
	} else {
		*peer_pid = -1;
	}
	return ret;
}

#else /* _AIX_ */

int ctdb_get_peer_pid(const int fd, pid_t *peer_pid)
{
	/* Not implemented */
	*peer_pid = -1;
	return ENOSYS;
}

#endif /* _AIX_ */

#endif /* HAVE_PEERCRED */
