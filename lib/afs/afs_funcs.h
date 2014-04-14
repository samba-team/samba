/*
 *  Unix SMB/CIFS implementation.
 *  Generate AFS tickets
 *  Copyright (C) Volker Lendecke 2003
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIB_AFS_AFS_FUNCS_H
#define LIB_AFS_AFS_FUNCS_H 1

char *afs_createtoken_str(const char *username, const char *cell);

/*
  This routine takes a radical approach completely bypassing the
  Kerberos idea of security and using AFS simply as an intelligent
  file backend. Samba has persuaded itself somehow that the user is
  actually correctly identified and then we create a ticket that the
  AFS server hopefully accepts using its KeyFile that the admin has
  kindly stored to our secrets.tdb.

  Thanks to the book "Network Security -- PRIVATE Communication in a
  PUBLIC World" by Charlie Kaufman, Radia Perlman and Mike Speciner
  Kerberos 4 tickets are not really hard to construct.

  For the comments "Alice" is the User to be auth'ed, and "Bob" is the
  AFS server.  */

bool afs_login(connection_struct *conn);

#endif
