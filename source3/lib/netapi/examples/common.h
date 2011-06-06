#ifndef __LIB_NETAPI_EXAMPLES_COMMON_H__
#define __LIB_NETAPI_EXAMPLES_COMMON_H__
/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

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

#include <popt.h>

void popt_common_callback(poptContext con,
			 enum poptCallbackReason reason,
			 const struct poptOption *opt,
			 const char *arg, const void *data);

extern struct poptOption popt_common_netapi_examples[];

#define POPT_COMMON_LIBNETAPI_EXAMPLES { NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_netapi_examples, 0, "Common samba netapi example options:", NULL },
#endif
