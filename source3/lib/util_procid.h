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

#ifndef __LIB_UTIL_PROCID_H__
#define __LIB_UTIL_PROCID_H__

#include "replace.h"
#include "librpc/gen_ndr/server_id.h"

pid_t procid_to_pid(const struct server_id *proc);
void set_my_vnn(uint32_t vnn);
uint32_t get_my_vnn(void);
struct server_id pid_to_procid(pid_t pid);
bool procid_valid(const struct server_id *pid);
bool procid_is_local(const struct server_id *pid);

#endif
