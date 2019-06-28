/*
 * Unix SMB/CIFS implementation.
 * Samba utility functions
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Jeremy Allison 2001-2007
 * Copyright (C) Simo Sorce 2001
 * Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
 * Copyright (C) James Peach 2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "util_procid.h"
#include "lib/util/debug.h"
#include "lib/messaging/messages_dgm.h"

pid_t procid_to_pid(const struct server_id *proc)
{
	return proc->pid;
}

static uint32_t my_vnn = NONCLUSTER_VNN;

void set_my_vnn(uint32_t vnn)
{
	DEBUG(10, ("vnn pid %d = %u\n", (int)getpid(), (unsigned int)vnn));
	my_vnn = vnn;
}

uint32_t get_my_vnn(void)
{
	return my_vnn;
}

struct server_id pid_to_procid(pid_t pid)
{
	uint64_t unique = 0;
	int ret;

	ret = messaging_dgm_get_unique(pid, &unique);
	if (ret != 0) {
		DBG_NOTICE("messaging_dgm_get_unique failed: %s\n",
			   strerror(ret));
	}

	return (struct server_id) {
		.pid = pid, .unique_id = unique, .vnn = my_vnn };
}

bool procid_valid(const struct server_id *pid)
{
	return (pid->pid != (uint64_t)-1);
}

bool procid_is_local(const struct server_id *pid)
{
	return pid->vnn == my_vnn;
}
