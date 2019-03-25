/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Volker Lendecke 2019
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

#ifndef __LIBCLI_SMB_SMB2_LOCK_H__
#define __LIBCLI_SMB_SMB2_LOCK_H__

#include "replace.h"

struct smb2_lock_element {
	uint64_t offset;
	uint64_t length;
	uint32_t flags;
	uint32_t reserved;
};

#endif
