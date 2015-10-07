/*
Unix SMB/CIFS implementation.

Common socket definitions and default values.

Copyright (C) Andrew Tridgell 1992-1998
Copyright (C) Luke Kenneth Casson Leighton 1996-1998
Copyright (C) Jeremy Allison 1998

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

#ifndef _SOCKET_COMMON_H
#define _SOCKET_COMMON_H


/* default socket connection timeouts */
#define LONG_CONNECT_TIMEOUT_MS (30 * 1000)
#define SHORT_CONNECT_TIMEOUT_MS (5 * 1000)


#endif /* _SOCKET_COMMON_H */
