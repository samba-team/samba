/*
   System specific code

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

#ifndef __CTDB_SYSTEM_H__
#define __CTDB_SYSTEM_H__

#include <talloc.h>

/* From system_util.c */

bool set_scheduler(void);
void reset_scheduler(void);

void lockdown_memory(bool valgrinding);

void ctdb_wait_for_process_to_exit(pid_t pid);

bool ctdb_sys_check_iface_exists(const char *iface);
int ctdb_get_peer_pid(const int fd, pid_t *peer_pid);

#endif /* __CTDB_SYSTEM_H__ */
