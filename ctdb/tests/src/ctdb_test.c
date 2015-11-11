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
int main_foobar(int argc, const char **argv);
#define usage usage_foobar

#endif /* CTDB_TEST_USE_MAIN */

#define ctdb_cmdline_client(x, y) \
	ctdb_cmdline_client_stub(x, y)
#define tevent_context_init(x) \
	tevent_context_init_stub(x)
#define ctdb_ctrl_getnodemap(ctdb, timelimit, pnn, tmp_ctx, nodemap) \
	ctdb_ctrl_getnodemap_stub(ctdb, timelimit, pnn, tmp_ctx, nodemap)
#define ctdb_ctrl_getnodesfile(ctdb, timeout, destnode, mem_ctx, nodemap) \
	ctdb_ctrl_getnodesfile_stub(ctdb, timeout, destnode, mem_ctx, nodemap)
#define ctdb_ctrl_get_ifaces(ctdb, timelimit, pnn, tmp_ctx, ifaces) \
	ctdb_ctrl_get_ifaces_stub(ctdb, timelimit, pnn, tmp_ctx, ifaces)
#define ctdb_ctrl_getpnn(ctdb, timelimit, pnn) \
	ctdb_ctrl_getpnn_stub(ctdb, timelimit, pnn)
#define ctdb_ctrl_getrecmode(ctdb, tmp_ctx, timelimit, pnn, recmode) \
	ctdb_ctrl_getrecmode_stub(ctdb, tmp_ctx, timelimit, pnn, recmode)
#define ctdb_ctrl_setrecmode(ctdb, timeout, destnode, recmode) \
	ctdb_ctrl_setrecmode_stub(ctdb, timeout, destnode, recmode)
#define ctdb_ctrl_getrecmaster(ctdb, tmp_ctx, timelimit, pnn, recmaster) \
	ctdb_ctrl_getrecmaster_stub(ctdb, tmp_ctx, timelimit, pnn, recmaster)
#define ctdb_ctrl_getvnnmap(ctdb, timelimit, pnn, tmp_ctx, vnnmap) \
	ctdb_ctrl_getvnnmap_stub(ctdb, timelimit, pnn, tmp_ctx, vnnmap)
#define ctdb_ctrl_getdebseqnum(ctdb, timelimit, pnn, db_id, seqnum) \
	ctdb_ctrl_getvnnmap_stub(ctdb, timelimit, pnn, db_id, seqnum)
#define ctdb_client_set_message_handler(ctdb, srvid, handler, private_data) \
	ctdb_client_set_message_handler_stub(ctdb, srvid, handler, private_data)
#define ctdb_client_remove_message_handler(ctdb, srvid, private_data) \
	ctdb_client_remove_message_handler_stub(ctdb, srvid, private_data)
#define ctdb_client_send_message(ctdb, pnn, srvid, data) \
	ctdb_client_send_message_stub(ctdb, pnn, srvid, data)
#define ctdb_client_check_message_handlers(ctdb, ids, argc, result) \
	ctdb_client_check_message_handlers_stub(ctdb, ids, argc, result)
#define ctdb_ctrl_getcapabilities(ctdb, timeout, destnode, capabilities) \
	ctdb_ctrl_getcapabilities_stub(ctdb, timeout, destnode, capabilities)
#define ctdb_ctrl_reload_nodes_file(ctdb, timeout, destnode) \
	ctdb_ctrl_reload_nodes_file_stub(ctdb, timeout, destnode)
#define ctdb_sys_have_ip(addr) \
	ctdb_sys_have_ip_stub(addr)
#define ctdb_client_async_control(ctdb, opcode, nodes, srvid, timeout, dont_log_errors, data, client_callback, fail_callback, callback_data) \
	ctdb_client_async_control_stub(ctdb, opcode, nodes, srvid, timeout, dont_log_errors, data, client_callback, fail_callback, callback_data)
#define ctdb_get_capabilities(ctdb, mem_ctx, timeout, nodemap) \
	ctdb_get_capabilities_stub(ctdb, mem_ctx, timeout, nodemap)

#include "tools/ctdb.c"

#ifndef CTDB_TEST_USE_MAIN
#undef main
#undef usage
#endif /* CTDB_TEST_USE_MAIN */

#undef ctdb_cmdline_client
#undef tevent_context_init
/* This is called in client/ctdb_client.c so needs a declaration... */
struct ctdb_context *ctdb_cmdline_client(struct tevent_context *ev,
					 struct timeval req_timeout);
struct tevent_context *tevent_context_init(TALLOC_CTX *mem_ctx);
#include "common/cmdline.c"

#undef ctdb_ctrl_getnodemap
#undef ctdb_ctrl_getnodesfile
#undef ctdb_ctrl_get_ifaces 
#undef ctdb_ctrl_getpnn
#undef ctdb_ctrl_getrecmode
#undef ctdb_ctrl_setrecmode
#undef ctdb_ctrl_getrecmaster
#undef ctdb_ctrl_getvnnmap
#undef ctdb_ctrl_getdebseqnum
#undef ctdb_client_set_message_handler
#undef ctdb_client_remove_message_handler
#undef ctdb_client_send_message
#undef ctdb_client_check_message_handlers
#undef ctdb_ctrl_getcapabilities
#undef ctdb_ctrl_reload_nodes_file
#undef ctdb_sys_have_ip
#undef ctdb_client_async_control
#undef ctdb_get_capabilities

int ctdb_ctrl_getnodemap(struct ctdb_context *ctdb,
		    struct timeval timeout, uint32_t destnode,
		    TALLOC_CTX *mem_ctx, struct ctdb_node_map_old **nodemap);
int ctdb_ctrl_getnodesfile(struct ctdb_context *ctdb,
			   struct timeval timeout, uint32_t destnode,
			   TALLOC_CTX *mem_ctx,
			   struct ctdb_node_map_old **nodemap);
int ctdb_ctrl_get_ifaces(struct ctdb_context *ctdb,
			 struct timeval timeout, uint32_t destnode,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_iface_list_old **ifaces);
int ctdb_ctrl_getpnn(struct ctdb_context *ctdb, struct timeval timeout,
		     uint32_t destnode);
int ctdb_ctrl_getrecmode(struct ctdb_context *ctdb,
			 TALLOC_CTX *mem_ctx, struct timeval timeout,
			 uint32_t destnode, uint32_t *recmode);
int ctdb_ctrl_setrecmode(struct ctdb_context *ctdb, struct timeval timeout,
			 uint32_t destnode, uint32_t recmode);
int ctdb_ctrl_getrecmaster(struct ctdb_context *ctdb,
			   TALLOC_CTX *mem_ctx, struct timeval timeout,
			   uint32_t destnode, uint32_t *recmaster);
int ctdb_ctrl_getvnnmap(struct ctdb_context *ctdb,
		struct timeval timeout, uint32_t destnode,
		TALLOC_CTX *mem_ctx, struct ctdb_vnn_map **vnnmap);
int ctdb_ctrl_getdbseqnum(struct ctdb_context *ctdb, struct timeval timeout,
			  uint32_t destnode, uint32_t dbid, uint64_t *seqnum);
int ctdb_client_set_message_handler(struct ctdb_context *ctdb,
				    uint64_t srvid,
				    srvid_handler_fn handler,
				    void *private_data);
int ctdb_client_remove_message_handler(struct ctdb_context *ctdb,
				       uint64_t srvid,
				       void *private_data);
int ctdb_client_send_message(struct ctdb_context *ctdb,
			     uint32_t pnn,
			     uint64_t srvid, TDB_DATA data);
int ctdb_client_check_message_handlers(struct ctdb_context *ctdb,
				       uint64_t *ids, uint32_t num,
				       uint8_t *result);
int ctdb_ctrl_getcapabilities(struct ctdb_context *ctdb,
			      struct timeval timeout, uint32_t destnode,
			      uint32_t *capabilities);
int ctdb_ctrl_reload_nodes_file(struct ctdb_context *ctdb,
				struct timeval timeout, uint32_t destnode);
bool ctdb_sys_have_ip(ctdb_sock_addr *addr);
int
ctdb_client_async_control(struct ctdb_context *ctdb,
			  enum ctdb_controls opcode,
			  uint32_t *nodes,
			  uint64_t srvid,
			  struct timeval timeout,
			  bool dont_log_errors,
			  TDB_DATA data,
			  client_async_callback client_callback,
			  client_async_callback fail_callback,
			  void *callback_data);
struct ctdb_node_capabilities *
ctdb_get_capabilities(struct ctdb_context *ctdb,
		      TALLOC_CTX *mem_ctx,
		      struct timeval timeout,
		      struct ctdb_node_map_old *nodemap);

#undef TIMELIMIT

/* CTDB_COMMON_OBJ */
#include "common/ctdb_io.c"
#include "common/ctdb_util.c"
#include "common/ctdb_ltdb.c"
#include "common/db_hash.c"
#include "common/srvid.c"
#include "common/rb_tree.c"
#include "common/reqid.c"
#include "common/logging.c"

/* CTDB_CLIENT_OBJ */
#include "client/ctdb_client.c"

/* TEST STUBS */
#include "ctdb_test_stubs.c"

#endif /* _CTDBD_TEST_C */
