/*
 *  Unix SMB/CIFS implementation.
 *
 *  elasticsearch common routines
 *
 *  Copyright (c) Ralph Boehme
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

#ifndef __ELASTIC_UTIL__
#define __ELASTIC_UTIL__


char *es_escape_str(TALLOC_CTX *mem_ctx,
		    const char *in,
		    const char *json_escape_list,
		    const char *exceptions);
#endif
