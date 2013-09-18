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

#ifdef CTDB_TEST_OVERRIDE_MAIN

/* Define our own main() and usage() functions */
#define main(argc, argv) main_foobar(argc, argv)
#define usage usage_foobar

#endif /* CTDB_TEST_USE_MAIN */

#define ctdb_cmdline_client(x, y) \
	ctdb_cmdline_client_stub(x, y)
#define ctdb_ctrl_getnodemap(ctdb, timelimit, pnn, tmp_ctx, nodemap) \
	ctdb_ctrl_getnodemap_stub(ctdb, timelimit, pnn, tmp_ctx, nodemap)
#define ctdb_ctrl_get_ifaces(ctdb, timelimit, pnn, tmp_ctx, ifaces) \
	ctdb_ctrl_get_ifaces_stub(ctdb, timelimit, pnn, tmp_ctx, ifaces)
#define ctdb_ctrl_getpnn(ctdb, timelimit, pnn) \
	ctdb_ctrl_getpnn_stub(ctdb, timelimit, pnn)
#define ctdb_ctrl_getrecmode(ctdb, tmp_ctx, timelimit, pnn, recmode) \
	ctdb_ctrl_getrecmode_stub(ctdb, tmp_ctx, timelimit, pnn, recmode)
#define ctdb_ctrl_getrecmaster(ctdb, tmp_ctx, timelimit, pnn, recmaster) \
	ctdb_ctrl_getrecmaster_stub(ctdb, tmp_ctx, timelimit, pnn, recmaster)
#define ctdb_ctrl_getvnnmap(ctdb, timelimit, pnn, tmp_ctx, vnnmap) \
	ctdb_ctrl_getvnnmap_stub(ctdb, timelimit, pnn, tmp_ctx, vnnmap)
#define ctdb_ctrl_getdebseqnum(ctdb, timelimit, pnn, db_id, seqnum) \
	ctdb_ctrl_getvnnmap_stub(ctdb, timelimit, pnn, db_id, seqnum)
#define ctdb_client_check_message_handlers(ctdb, ids, argc, result) \
	ctdb_client_check_message_handlers_stub(ctdb, ids, argc, result)
#define ctdb_ctrl_getcapabilities(ctdb, timeout, destnode, capabilities) \
	ctdb_ctrl_getcapabilities_stub(ctdb, timeout, destnode, capabilities)

#include "tools/ctdb.c"

#ifndef CTDB_TEST_USE_MAIN
#undef main
#undef usage
#endif /* CTDB_TEST_USE_MAIN */

#undef ctdb_cmdline_client

#include "common/cmdline.c"

#undef ctdb_ctrl_getnodemap
#undef ctdb_ctrl_get_ifaces 
#undef ctdb_ctrl_getpnn
#undef ctdb_ctrl_getrecmode
#undef ctdb_ctrl_getrecmaster
#undef ctdb_ctrl_getvnnmap
#undef ctdb_ctrl_getdebseqnum
#undef ctdb_client_check_message_handlers
#undef ctdb_ctrl_getcapabilities

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
#include "lib/util/debug.c"
#include "common/rb_tree.c"
#include "common/system_common.c"
#include "common/ctdb_logging.c"
#include "common/ctdb_fork.c"

/* CTDB_CLIENT_OBJ */
#include "client/ctdb_client.c"

/* TEST STUBS */
#include "libctdb_test.c"

#endif /* _CTDBD_TEST_C */
