/*
 *  Samba Unix/Linux SMB client library
 *  Distributed SMB/CIFS Server Management Utility
 *  Configuration interface
 *
 *  Copyright (C) Michael Adam 2013
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

#ifndef __NET_CONF_UTIL_H__
#define __NET_CONF_UTIL_H__

/*
 * Utility functions for net conf and net rpc conf.
 */

bool net_conf_param_valid(const char *service,
			  const char *param,
			  const char *valstr);

#endif /* __NET_CONF_UTIL_H__ */
