/*
   Unix SMB/CIFS implementation.
   Samba3 ctdb srvid assignments
   Copyright (C) Volker Lendecke 2012

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

/*
 * ctdb has reserved all srvids starting with 0xFE for Samba. Here we list our
 * static assignments that are supposed to be globally unique.
 */

/*
 * ctdb_protocol.h already has the following definition, used in the g_lock
 * implementation. Waiters for a g_lock register this to receive notifications
 * when g_lock holders die.
 */

#if 0
#define CTDB_SRVID_SAMBA_NOTIFY  0xFE00000000000000LL
#endif

/*
 * SRVID for notify_internal.c: On every node, one process registers this
 * SRVID. It receives filechangenotify notifications and multicasts them
 * locally according to the non-clustered local notify.tdb
 */
#define CTDB_SRVID_SAMBA_NOTIFY_PROXY  0xFE00000000000001LL
