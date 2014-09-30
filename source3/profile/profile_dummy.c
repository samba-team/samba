/*
 * Unix SMB/CIFS implementation.
 * profile.c implementation if profiles are not enabled
 * Copyright (C) Volker Lendecke 2014
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

#include "includes.h"
#include "smbprofile.h"

bool profile_setup(struct messaging_context *msg_ctx, bool rdonly)
{
	return true;
}

void set_profile_level(int level, struct server_id src)
{
	DEBUG(1,("INFO: Profiling support unavailable in this build.\n"));
}
