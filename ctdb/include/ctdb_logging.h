/*
   ctdb logging code

   Copyright (C) Andrew Tridgell  2008

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

#ifndef _CTDB_LOGGING_H_
#define _CTDB_LOGGING_H_

extern const char *debug_extra;

enum debug_level {
	DEBUG_EMERG   = -3,
	DEBUG_ALERT   = -2,
	DEBUG_CRIT    = -1,
	DEBUG_ERR     =  0,
	DEBUG_WARNING =  1,
	DEBUG_NOTICE  =  2,
	DEBUG_INFO    =  3,
	DEBUG_DEBUG   =  4,
};

#endif /* _CTDB_LOGGING_H_ */
