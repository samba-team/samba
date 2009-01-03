/*
   Unix SMB/CIFS implementation.

   common events code for fd events

   Copyright (C) Stefan Metzmacher	2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

uint16_t tevent_common_fd_get_flags(struct tevent_fd *fde)
{
	return fde->flags;
}

void tevent_common_fd_set_flags(struct tevent_fd *fde, uint16_t flags)
{
	if (fde->flags == flags) return;
	fde->flags = flags;
}
