/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Marcin Krzysztof Porwit    2005,
 *  Copyright (C) Brian Moran                2005.
 *  Copyright (C) Gerald (Jerry) Carter      2005.
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

#ifndef _REG_EVENTLOG_H
#define _REG_EVENTLOG_H

bool eventlog_init_keys(void);
bool eventlog_add_source( const char *eventlog, const char *sourcename,
			  const char *messagefile );

#endif /* _REG_EVENTLOG_H */
