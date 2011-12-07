/*
   ctdb test include file

   Copyright (C) Martin Schwenke  2011

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

#ifndef _CTDBD_TEST_C
#define _CTDBD_TEST_C

#define main(argc, argv) main_foobar(argc, argv)
#define usage usage_foobar
#include "tools/ctdb.c"
#undef main
#undef usage

#undef TIMELIMIT
#include "tools/ctdb_vacuum.c"

/* UTIL_OBJ */
#include "lib/util/idtree.c"
#include "lib/util/db_wrap.c"
#include "lib/util/strlist.c"
#include "lib/util/util.c"
#include "lib/util/util_time.c"
#include "lib/util/util_file.c"
#include "lib/util/fault.c"
#include "lib/util/substitute.c"
#include "lib/util/signal.c"

/* CTDB_COMMON_OBJ */
#include "common/ctdb_io.c"
#include "common/ctdb_util.c"
#include "common/ctdb_ltdb.c"
#include "common/ctdb_message.c"
#include "common/cmdline.c"
#include "lib/util/debug.c"
#include "common/rb_tree.c"
#ifdef _LINUX_ERRNO_H
#include "common/system_linux.c"
#endif
#include "common/system_common.c"
#include "common/ctdb_logging.c"

/* CTDB_CLIENT_OBJ */
#include "client/ctdb_client.c"

#endif /* _CTDBD_TEST_C */
