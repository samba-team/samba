/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Tim Potter      2000-2001

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

/*******************************************************************
this is like socketpair but uses tcp. It is used by the Samba
regression test code
The function guarantees that nobody else can attach to the socket,
or if they do that this function fails and the socket gets closed
returns 0 on success, -1 on failure
the resulting file descriptors are symmetrical
 ******************************************************************/
int socketpair_tcp(int fd[2]);
