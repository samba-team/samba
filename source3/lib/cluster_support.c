/*
   Unix SMB/CIFS implementation.
   Copyright (C) 2014 Stefan Metzmacher

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

#include "includes.h"
#include <tdb.h>
#include "cluster_support.h"

#ifdef CLUSTER_SUPPORT
#include <ctdb_protocol.h>
#endif

bool cluster_support_available(void)
{
#ifdef CLUSTER_SUPPORT
	return true;
#else
	return false;
#endif
}

const char *cluster_support_features(void)
{
#define _LINE_DEF(x) "   " #x "\n"
#define _LINE_STR(x) "   " #x ": " x "\n"
#define _LINE_INT(x) "   " #x ": " __STRINGSTRING(x) "\n"
	static const char *v = "Cluster support features:\n"
#ifdef CLUSTER_SUPPORT
	_LINE_DEF(CLUSTER_SUPPORT)
#else
	"   NONE\n"
#endif
#ifdef CTDB_SOCKET
	_LINE_STR(CTDB_SOCKET)
#endif
#ifdef CTDB_PROTOCOL
	_LINE_INT(CTDB_PROTOCOL)
#endif
	"";

	return v;
}

const char *lp_ctdbd_socket(void)
{
	const char *ret;

	ret = lp__ctdbd_socket();
	if (ret != NULL && strlen(ret) > 0) {
		return ret;
	}

#ifdef CTDB_SOCKET
	return CTDB_SOCKET;
#else
	return "";
#endif
}
