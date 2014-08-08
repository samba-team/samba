/*
   Unix SMB/CIFS implementation.
   ctdb debug functions
   Copyright (C) Volker Lendecke 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef UTIL_DEBUG_H
#define UTIL_DEBUG_H

extern void (*do_debug_v)(const char *, va_list ap);
extern void (*do_debug_add_v)(const char *, va_list ap);
void do_debug(const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
void do_debug_add(const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
void dump_data(int level, const uint8_t *buf1, size_t len);

#endif /* UTIL_DEBUG_H */
