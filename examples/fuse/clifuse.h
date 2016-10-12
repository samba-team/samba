/*
 * Unix SMB/CIFS implementation.
 * fusermount smb2 client
 * Copyright (C) Volker Lendecke 2016
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

#ifndef __EXAMPLES_FUSE_CLIFUSE_H__
#define __EXAMPLES_FUSE_CLIFUSE_H__

struct cli_state;

int do_mount(struct cli_state *cli, const char *mountpoint);

#endif
