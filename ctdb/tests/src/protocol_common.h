/*
   protocol tests - common functions

   Copyright (C) Amitay Isaacs  2015-2017

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

#ifndef __CTDB_PROTOCOL_COMMON_H__
#define __CTDB_PROTOCOL_COMMON_H__

#include "replace.h"
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

#include "protocol/protocol.h"

#include "tests/src/protocol_common_basic.h"

void fill_tdb_data_nonnull(TALLOC_CTX *mem_ctx, TDB_DATA *p);
void fill_tdb_data(TALLOC_CTX *mem_ctx, TDB_DATA *p);
void verify_tdb_data(TDB_DATA *p1, TDB_DATA *p2);

void fill_ctdb_tdb_data(TALLOC_CTX *mem_ctx, TDB_DATA *p);
void verify_ctdb_tdb_data(TDB_DATA *p1, TDB_DATA *p2);

void fill_ctdb_tdb_datan(TALLOC_CTX *mem_ctx, TDB_DATA *p);
void verify_ctdb_tdb_datan(TDB_DATA *p1, TDB_DATA *p2);

void fill_ctdb_latency_counter(struct ctdb_latency_counter *p);
void verify_ctdb_latency_counter(struct ctdb_latency_counter *p1,
				 struct ctdb_latency_counter *p2);

void fill_ctdb_statistics(TALLOC_CTX *mem_ctx, struct ctdb_statistics *p);
void verify_ctdb_statistics(struct ctdb_statistics *p1,
			    struct ctdb_statistics *p2);

void fill_ctdb_vnn_map(TALLOC_CTX *mem_ctx, struct ctdb_vnn_map *p);
void verify_ctdb_vnn_map(struct ctdb_vnn_map *p1, struct ctdb_vnn_map *p2);

void fill_ctdb_dbid(TALLOC_CTX *mem_ctx, struct ctdb_dbid *p);
void verify_ctdb_dbid(struct ctdb_dbid *p1, struct ctdb_dbid *p2);

void fill_ctdb_dbid_map(TALLOC_CTX *mem_ctx, struct ctdb_dbid_map *p);
void verify_ctdb_dbid_map(struct ctdb_dbid_map *p1, struct ctdb_dbid_map *p2);

void fill_ctdb_pulldb(TALLOC_CTX *mem_ctx, struct ctdb_pulldb *p);
void verify_ctdb_pulldb(struct ctdb_pulldb *p1, struct ctdb_pulldb *p2);

void fill_ctdb_pulldb_ext(TALLOC_CTX *mem_ctx, struct ctdb_pulldb_ext *p);
void verify_ctdb_pulldb_ext(struct ctdb_pulldb_ext *p1,
			    struct ctdb_pulldb_ext *p2);

void fill_ctdb_db_vacuum(TALLOC_CTX *mem_ctx, struct ctdb_db_vacuum *p);
void verify_ctdb_db_vacuum(struct ctdb_db_vacuum *p1,
			   struct ctdb_db_vacuum *p2);

void fill_ctdb_echo_data(TALLOC_CTX *mem_ctx, struct ctdb_echo_data *p);
void verify_ctdb_echo_data(struct ctdb_echo_data *p1,
			   struct ctdb_echo_data *p2);

void fill_ctdb_ltdb_header(struct ctdb_ltdb_header *p);
void verify_ctdb_ltdb_header(struct ctdb_ltdb_header *p1,
			     struct ctdb_ltdb_header *p2);

void fill_ctdb_rec_data(TALLOC_CTX *mem_ctx, struct ctdb_rec_data *p);
void verify_ctdb_rec_data(struct ctdb_rec_data *p1, struct ctdb_rec_data *p2);

void fill_ctdb_rec_buffer(TALLOC_CTX *mem_ctx, struct ctdb_rec_buffer *p);
void verify_ctdb_rec_buffer(struct ctdb_rec_buffer *p1,
			    struct ctdb_rec_buffer *p2);

void fill_ctdb_traverse_start(TALLOC_CTX *mem_ctx,
			      struct ctdb_traverse_start *p);
void verify_ctdb_traverse_start(struct ctdb_traverse_start *p1,
				struct ctdb_traverse_start *p2);

void fill_ctdb_traverse_all(TALLOC_CTX *mem_ctx,
			    struct ctdb_traverse_all *p);
void verify_ctdb_traverse_all(struct ctdb_traverse_all *p1,
			      struct ctdb_traverse_all *p2);

void fill_ctdb_traverse_start_ext(TALLOC_CTX *mem_ctx,
				  struct ctdb_traverse_start_ext *p);
void verify_ctdb_traverse_start_ext(struct ctdb_traverse_start_ext *p1,
				    struct ctdb_traverse_start_ext *p2);

void fill_ctdb_traverse_all_ext(TALLOC_CTX *mem_ctx,
				struct ctdb_traverse_all_ext *p);
void verify_ctdb_traverse_all_ext(struct ctdb_traverse_all_ext *p1,
				  struct ctdb_traverse_all_ext *p2);

void fill_ctdb_sock_addr(TALLOC_CTX *mem_ctx, ctdb_sock_addr *p);
void verify_ctdb_sock_addr(ctdb_sock_addr *p1, ctdb_sock_addr *p2);

void fill_ctdb_connection(TALLOC_CTX *mem_ctx, struct ctdb_connection *p);
void verify_ctdb_connection(struct ctdb_connection *p1,
			    struct ctdb_connection *p2);

void fill_ctdb_connection_list(TALLOC_CTX *mem_ctx,
			       struct ctdb_connection_list *p);
void verify_ctdb_connection_list(struct ctdb_connection_list *p1,
				 struct ctdb_connection_list *p2);

void fill_ctdb_tunable(TALLOC_CTX *mem_ctx, struct ctdb_tunable *p);
void verify_ctdb_tunable(struct ctdb_tunable *p1, struct ctdb_tunable *p2);

void fill_ctdb_node_flag_change(TALLOC_CTX *mem_ctx,
				struct ctdb_node_flag_change *p);
void verify_ctdb_node_flag_change(struct ctdb_node_flag_change *p1,
				  struct ctdb_node_flag_change *p2);

void fill_ctdb_var_list(TALLOC_CTX *mem_ctx, struct ctdb_var_list *p);
void verify_ctdb_var_list(struct ctdb_var_list *p1, struct ctdb_var_list *p2);

void fill_ctdb_tunable_list(TALLOC_CTX *mem_ctx, struct ctdb_tunable_list *p);
void verify_ctdb_tunable_list(struct ctdb_tunable_list *p1,
			      struct ctdb_tunable_list *p2);

void fill_ctdb_tickle_list(TALLOC_CTX *mem_ctx, struct ctdb_tickle_list *p);
void verify_ctdb_tickle_list(struct ctdb_tickle_list *p1,
			     struct ctdb_tickle_list *p2);

void fill_ctdb_addr_info(TALLOC_CTX *mem_ctx, struct ctdb_addr_info *p);
void verify_ctdb_addr_info(struct ctdb_addr_info *p1,
			   struct ctdb_addr_info *p2);

void fill_ctdb_transdb(TALLOC_CTX *mem_ctx, struct ctdb_transdb *p);
void verify_ctdb_transdb(struct ctdb_transdb *p1, struct ctdb_transdb *p2);

void fill_ctdb_uptime(TALLOC_CTX *mem_ctx, struct ctdb_uptime *p);
void verify_ctdb_uptime(struct ctdb_uptime *p1, struct ctdb_uptime *p2);

void fill_ctdb_public_ip(TALLOC_CTX *mem_ctx, struct ctdb_public_ip *p);
void verify_ctdb_public_ip(struct ctdb_public_ip *p1,
			   struct ctdb_public_ip *p2);

void fill_ctdb_public_ip_list(TALLOC_CTX *mem_ctx,
			      struct ctdb_public_ip_list *p);
void verify_ctdb_public_ip_list(struct ctdb_public_ip_list *p1,
				struct ctdb_public_ip_list *p2);

void fill_ctdb_node_and_flags(TALLOC_CTX *mem_ctx,
			      struct ctdb_node_and_flags *p);
void verify_ctdb_node_and_flags(struct ctdb_node_and_flags *p1,
				struct ctdb_node_and_flags *p2);

void fill_ctdb_node_map(TALLOC_CTX *mem_ctx, struct ctdb_node_map *p);
void verify_ctdb_node_map(struct ctdb_node_map *p1, struct ctdb_node_map *p2);

void fill_ctdb_script(TALLOC_CTX *mem_ctx, struct ctdb_script *p);
void verify_ctdb_script(struct ctdb_script *p1, struct ctdb_script *p2);

void fill_ctdb_script_list(TALLOC_CTX *mem_ctx, struct ctdb_script_list *p);
void verify_ctdb_script_list(struct ctdb_script_list *p1,
			     struct ctdb_script_list *p2);

void fill_ctdb_ban_state(TALLOC_CTX *mem_ctx, struct ctdb_ban_state *p);
void verify_ctdb_ban_state(struct ctdb_ban_state *p1,
			   struct ctdb_ban_state *p2);

void fill_ctdb_notify_data(TALLOC_CTX *mem_ctx, struct ctdb_notify_data *p);
void verify_ctdb_notify_data(struct ctdb_notify_data *p1,
			     struct ctdb_notify_data *p2);

void fill_ctdb_iface(TALLOC_CTX *mem_ctx, struct ctdb_iface *p);
void verify_ctdb_iface(struct ctdb_iface *p1, struct ctdb_iface *p2);

void fill_ctdb_iface_list(TALLOC_CTX *mem_ctx, struct ctdb_iface_list *p);
void verify_ctdb_iface_list(struct ctdb_iface_list *p1,
			    struct ctdb_iface_list *p2);

void fill_ctdb_public_ip_info(TALLOC_CTX *mem_ctx,
			      struct ctdb_public_ip_info *p);
void verify_ctdb_public_ip_info(struct ctdb_public_ip_info *p1,
				struct ctdb_public_ip_info *p2);

void fill_ctdb_statistics_list(TALLOC_CTX *mem_ctx,
			       struct ctdb_statistics_list *p);
void verify_ctdb_statistics_list(struct ctdb_statistics_list *p1,
				 struct ctdb_statistics_list *p2);

void fill_ctdb_key_data(TALLOC_CTX *mem_ctx, struct ctdb_key_data *p);
void verify_ctdb_key_data(struct ctdb_key_data *p1, struct ctdb_key_data *p2);

void fill_ctdb_db_statistics(TALLOC_CTX *mem_ctx,
			     struct ctdb_db_statistics *p);
void verify_ctdb_db_statistics(struct ctdb_db_statistics *p1,
			       struct ctdb_db_statistics *p2);

void fill_ctdb_pid_srvid(TALLOC_CTX *mem_ctx, struct ctdb_pid_srvid *p);
void verify_ctdb_pid_srvid(struct ctdb_pid_srvid *p1,
			   struct ctdb_pid_srvid *p2);

void fill_ctdb_election_message(TALLOC_CTX *mem_ctx,
				struct ctdb_election_message *p);
void verify_ctdb_election_message(struct ctdb_election_message *p1,
				  struct ctdb_election_message *p2);

void fill_ctdb_srvid_message(TALLOC_CTX *mem_ctx,
			     struct ctdb_srvid_message *p);
void verify_ctdb_srvid_message(struct ctdb_srvid_message *p1,
			       struct ctdb_srvid_message *p2);

void fill_ctdb_disable_message(TALLOC_CTX *mem_ctx,
			       struct ctdb_disable_message *p);
void verify_ctdb_disable_message(struct ctdb_disable_message *p1,
				 struct ctdb_disable_message *p2);

void fill_ctdb_server_id(struct ctdb_server_id *p);
void verify_ctdb_server_id(struct ctdb_server_id *p1,
			   struct ctdb_server_id *p2);

void fill_ctdb_g_lock(struct ctdb_g_lock *p);
void verify_ctdb_g_lock(struct ctdb_g_lock *p1, struct ctdb_g_lock *p2);

void fill_ctdb_g_lock_list(TALLOC_CTX *mem_ctx, struct ctdb_g_lock_list *p);
void verify_ctdb_g_lock_list(struct ctdb_g_lock_list *p1,
			     struct ctdb_g_lock_list *p2);

void fill_sock_packet_header(struct sock_packet_header *p);
void verify_sock_packet_header(struct sock_packet_header *p1,
			       struct sock_packet_header *p2);

#endif /* __CTDB_PROTOCOL_COMMON_H__ */
