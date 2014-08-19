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

bool dbgtext( const char *, ... ) PRINTF_ATTRIBUTE(1,2);
bool dbghdr( int level, const char *location, const char *func);
void dump_data(int level, const uint8_t *buf1, size_t len);

extern int DEBUGLEVEL;

#define DEBUGLVL(lvl) ((lvl) <= DEBUGLEVEL)
#define DEBUG( lvl, body ) \
  (void)( ((lvl) <= DEBUGLEVEL) \
       && (dbghdr( lvl, __location__, __FUNCTION__ )) \
       && (dbgtext body) )
#define DEBUGADD(lvl, body) DEBUG(lvl, body)

typedef void (*debug_callback_fn)(void *private_ptr, int level, const char *msg);
void debug_set_callback(void *private_ptr, debug_callback_fn fn);

#endif /* UTIL_DEBUG_H */
