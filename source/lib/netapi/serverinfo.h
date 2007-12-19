/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Support
 *  Copyright (C) Guenther Deschner 2007
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

#ifndef __LIB_NETAPI_SERVERINFO_H__
#define __LIB_NETAPI_SERVERINFO_H__

NET_API_STATUS NetServerGetInfo(const char *server_name,
				uint32_t level,
				uint8_t **buffer);
NET_API_STATUS NetServerSetInfo(const char *server_name,
				uint32_t level,
				uint8_t *buffer,
				uint32_t *parm_error);
#endif
