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

#ifdef HAVE_CTDB_H
#include <ctdb.h>
#endif

#ifdef HAVE_CTDB_PROTOCOL_H
#include <ctdb_protocol.h>
#else
#ifdef HAVE_CTDB_PRIVATE_H
#include <ctdb_private.h>
#endif
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
#ifdef HAVE_CTDB_H
	_LINE_DEF(HAVE_CTDB_H)
#endif
#ifdef HAVE_CTDB_PRIVATE_H
	_LINE_DEF(HAVE_CTDB_PRIVATE_H)
#endif
#ifdef HAVE_CTDB_PROTOCOL_H
	_LINE_DEF(HAVE_CTDB_PROTOCOL_H)
#endif
#ifdef HAVE_CTDB_CONTROL_TRANS3_COMMIT_DECL
	_LINE_DEF(HAVE_CTDB_CONTROL_TRANS3_COMMIT_DECL)
#endif
#ifdef HAVE_CTDB_CONTROL_SCHEDULE_FOR_DELETION_DECL
	_LINE_DEF(HAVE_CTDB_CONTROL_SCHEDULE_FOR_DELETION_DECL)
#endif
#ifdef HAVE_CTDB_WANT_READONLY_DECL
	_LINE_DEF(HAVE_CTDB_WANT_READONLY_DECL)
#endif
#ifdef HAVE_STRUCT_CTDB_CONTROL_TCP
	_LINE_DEF(HAVE_STRUCT_CTDB_CONTROL_TCP)
#endif
#ifdef HAVE_STRUCT_CTDB_CONTROL_TCP_ADDR
	_LINE_DEF(HAVE_STRUCT_CTDB_CONTROL_TCP_ADDR)
#endif
#ifdef HAVE_CTDB_CONTROL_CHECK_SRVIDS_DECL
	_LINE_DEF(HAVE_CTDB_CONTROL_CHECK_SRVIDS_DECL)
#endif
#ifdef CTDB_PATH
	_LINE_STR(CTDB_PATH)
#endif
#ifdef CTDB_VERSION
	_LINE_INT(CTDB_VERSION)
#endif
	"";

	return v;
}
