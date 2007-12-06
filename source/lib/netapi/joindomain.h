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

WERROR NetJoinDomain(const char *server,
		     const char *domain,
		     const char *account_ou,
		     const char *account,
		     const char *password,
		     uint32_t join_options);
WERROR NetUnjoinDomain(const char *server_name,
		       const char *account,
		       const char *password,
		       uint32_t unjoin_flags);
WERROR NetGetJoinInformation(const char *server_name,
			     const char **name_buffer,
			     uint16_t *name_type);
