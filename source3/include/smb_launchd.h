/*
   Unix SMB/CIFS implementation.
   Launchd integration wrapper API

   Copyright (C) James Peach 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

struct smb_launch_info
{
	int idle_timeout_secs;
	int num_sockets;
	int *socket_list;
};

/* Retrieve launchd configuration. Returns True if we are running under
 * launchd, False otherwise. NOTE this does not guarantee to provide a list of
 * sockets since this is a user configuration option.
 */
BOOL smb_launchd_checkin(struct smb_launch_info *linfo);

/* Retrieve launchd configuration. The variadic arguments are a list of
 * constant null-terminated strings. The strings are the names of the socket
 * dictionaries to retrieve sockets from. The list of names is terminated by a
 * NULL.
 */
BOOL smb_launchd_checkin_names(struct smb_launch_info *linfo, ...);

/* Free any data or state associated with a successful launchd checkin. */
void smb_launchd_checkout(struct smb_launch_info *linfo);
