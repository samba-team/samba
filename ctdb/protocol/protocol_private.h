/*
   CTDB protocol marshalling

   Copyright (C) Amitay Isaacs  2015

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

#ifndef __PROTOCOL_PRIVATE_H__
#define __PROTOCOL_PRIVATE_H__

#include "protocol.h"
#include "protocol_basic.h"

/*
 * From protocol/protocol_types.c
 */

size_t ctdb_tdb_data_len(TDB_DATA *in);
void ctdb_tdb_data_push(TDB_DATA *in, uint8_t *buf, size_t *npush);
int ctdb_tdb_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       TDB_DATA *out, size_t *npull);

size_t ctdb_tdb_datan_len(TDB_DATA *in);
void ctdb_tdb_datan_push(TDB_DATA *in, uint8_t *buf, size_t *npush);
int ctdb_tdb_datan_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			TDB_DATA *out, size_t *npull);

size_t ctdb_latency_counter_len(struct ctdb_latency_counter *in);
void ctdb_latency_counter_push(struct ctdb_latency_counter *in, uint8_t *buf,
			       size_t *npush);
int ctdb_latency_counter_pull(uint8_t *buf, size_t buflen,
			      struct ctdb_latency_counter *out, size_t *npull);

size_t ctdb_statistics_len(struct ctdb_statistics *in);
void ctdb_statistics_push(struct ctdb_statistics *in, uint8_t *buf,
			  size_t *npush);
int ctdb_statistics_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_statistics **out, size_t *npull);

size_t ctdb_statistics_list_len(struct ctdb_statistics_list *in);
void ctdb_statistics_list_push(struct ctdb_statistics_list *in,
			       uint8_t *buf, size_t *npull);
int ctdb_statistics_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_statistics_list **out,
			      size_t *npull);

size_t ctdb_vnn_map_len(struct ctdb_vnn_map *in);
void ctdb_vnn_map_push(struct ctdb_vnn_map *in, uint8_t *buf, size_t *npush);
int ctdb_vnn_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_vnn_map **out, size_t  *npull);

size_t ctdb_dbid_len(struct ctdb_dbid *in);
void ctdb_dbid_push(struct ctdb_dbid *in, uint8_t *buf, size_t *npush);
int ctdb_dbid_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		   struct ctdb_dbid **out, size_t *npull);

size_t ctdb_dbid_map_len(struct ctdb_dbid_map *in);
void ctdb_dbid_map_push(struct ctdb_dbid_map *in, uint8_t *buf,
			size_t *npush);
int ctdb_dbid_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_dbid_map **out, size_t *npull);

size_t ctdb_pulldb_len(struct ctdb_pulldb *in);
void ctdb_pulldb_push(struct ctdb_pulldb *in, uint8_t *buf, size_t *npush);
int ctdb_pulldb_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_pulldb **out, size_t *npull);

size_t ctdb_pulldb_ext_len(struct ctdb_pulldb_ext *in);
void ctdb_pulldb_ext_push(struct ctdb_pulldb_ext *in, uint8_t *buf,
			  size_t *npush);
int ctdb_pulldb_ext_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_pulldb_ext **out, size_t *npull);

size_t ctdb_db_vacuum_len(struct ctdb_db_vacuum *in);
void ctdb_db_vacuum_push(struct ctdb_db_vacuum *in,
			 uint8_t *buf,
			 size_t *npush);
int ctdb_db_vacuum_pull(uint8_t *buf,
			size_t buflen,
			TALLOC_CTX *mem_ctx,
			struct ctdb_db_vacuum **out,
			size_t *npull);

size_t ctdb_echo_data_len(struct ctdb_echo_data *in);
void ctdb_echo_data_push(struct ctdb_echo_data *in,
			 uint8_t *buf,
			 size_t *npush);
int ctdb_echo_data_pull(uint8_t *buf,
			size_t buflen,
			TALLOC_CTX *mem_ctx,
			struct ctdb_echo_data **out,
			size_t *npull);

size_t ctdb_traverse_start_len(struct ctdb_traverse_start *in);
void ctdb_traverse_start_push(struct ctdb_traverse_start *in, uint8_t *buf,
			      size_t *npush);
int ctdb_traverse_start_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_traverse_start **out, size_t *npull);

size_t ctdb_traverse_all_len(struct ctdb_traverse_all *in);
void ctdb_traverse_all_push(struct ctdb_traverse_all *in, uint8_t *buf,
			    size_t *npush);
int ctdb_traverse_all_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_traverse_all **out, size_t *npull);

size_t ctdb_traverse_start_ext_len(struct ctdb_traverse_start_ext *in);
void ctdb_traverse_start_ext_push(struct ctdb_traverse_start_ext *in,
				  uint8_t *buf, size_t *npush);
int ctdb_traverse_start_ext_pull(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_traverse_start_ext **out,
				 size_t *npull);

size_t ctdb_traverse_all_ext_len(struct ctdb_traverse_all_ext *in);
void ctdb_traverse_all_ext_push(struct ctdb_traverse_all_ext *in,
				uint8_t *buf, size_t *npush);
int ctdb_traverse_all_ext_pull(uint8_t *buf, size_t buflen,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_traverse_all_ext **out,
			       size_t *npull);

size_t ctdb_sock_addr_len(ctdb_sock_addr *in);
void ctdb_sock_addr_push(ctdb_sock_addr *in, uint8_t *buf, size_t *npush);
int ctdb_sock_addr_pull_elems(uint8_t *buf, size_t buflen,
			      TALLOC_CTX *mem_ctx, ctdb_sock_addr *out,
			      size_t *npull);
int ctdb_sock_addr_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			ctdb_sock_addr **out, size_t *npull);

size_t ctdb_connection_len(struct ctdb_connection *in);
void ctdb_connection_push(struct ctdb_connection *in, uint8_t *buf,
			  size_t *npush);
int ctdb_connection_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_connection **out, size_t *npull);

size_t ctdb_connection_list_len(struct ctdb_connection_list *in);
void ctdb_connection_list_push(struct ctdb_connection_list *in, uint8_t *buf,
			       size_t *npush);
int ctdb_connection_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_connection_list **out, size_t *npull);

size_t ctdb_tunable_len(struct ctdb_tunable *in);
void ctdb_tunable_push(struct ctdb_tunable *in, uint8_t *buf, size_t *npush);
int ctdb_tunable_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_tunable **out, size_t *npull);

size_t ctdb_node_flag_change_len(struct ctdb_node_flag_change *in);
void ctdb_node_flag_change_push(struct ctdb_node_flag_change *in,
				uint8_t *buf, size_t *npush);
int ctdb_node_flag_change_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			       struct ctdb_node_flag_change **out,
			       size_t *npull);

size_t ctdb_var_list_len(struct ctdb_var_list *in);
void ctdb_var_list_push(struct ctdb_var_list *in, uint8_t *buf, size_t *npush);
int ctdb_var_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_var_list **out, size_t *npull);

size_t ctdb_tunable_list_len(struct ctdb_tunable_list *in);
void ctdb_tunable_list_push(struct ctdb_tunable_list *in, uint8_t *buf,
			    size_t *npush);
int ctdb_tunable_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_tunable_list **out, size_t *npull);

size_t ctdb_tickle_list_len(struct ctdb_tickle_list *in);
void ctdb_tickle_list_push(struct ctdb_tickle_list *in, uint8_t *buf,
			   size_t *npush);
int ctdb_tickle_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_tickle_list **out, size_t *npull);

size_t ctdb_addr_info_len(struct ctdb_addr_info *in);
void ctdb_addr_info_push(struct ctdb_addr_info *in, uint8_t *buf,
			 size_t *npush);
int ctdb_addr_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_addr_info **out, size_t *npull);

size_t ctdb_transdb_len(struct ctdb_transdb *in);
void ctdb_transdb_push(struct ctdb_transdb *in, uint8_t *buf, size_t *npush);
int ctdb_transdb_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_transdb **out, size_t *npull);

size_t ctdb_uptime_len(struct ctdb_uptime *in);
void ctdb_uptime_push(struct ctdb_uptime *in, uint8_t *buf, size_t *npush);
int ctdb_uptime_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_uptime **out, size_t *npull);

size_t ctdb_public_ip_len(struct ctdb_public_ip *in);
void ctdb_public_ip_push(struct ctdb_public_ip *in, uint8_t *buf,
			 size_t *npush);
int ctdb_public_ip_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_public_ip **out, size_t *npull);

size_t ctdb_public_ip_list_len(struct ctdb_public_ip_list *in);
void ctdb_public_ip_list_push(struct ctdb_public_ip_list *in, uint8_t *buf,
			      size_t *npush);
int ctdb_public_ip_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_list **out, size_t *npull);

size_t ctdb_node_and_flags_len(struct ctdb_node_and_flags *in);
void ctdb_node_and_flags_push(struct ctdb_node_and_flags *in, uint8_t *buf,
			      size_t *npush);
int ctdb_node_and_flags_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_node_and_flags **out, size_t *npull);

size_t ctdb_node_map_len(struct ctdb_node_map *in);
void ctdb_node_map_push(struct ctdb_node_map *in, uint8_t *buf, size_t *npush);
int ctdb_node_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_node_map **out, size_t *npull);

size_t ctdb_script_len(struct ctdb_script *in);
void ctdb_script_push(struct ctdb_script *in, uint8_t *buf, size_t *npush);
int ctdb_script_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_script **out, size_t *npull);

size_t ctdb_script_list_len(struct ctdb_script_list *in);
void ctdb_script_list_push(struct ctdb_script_list *in, uint8_t *buf,
			   size_t *npush);
int ctdb_script_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_script_list **out, size_t *npull);

size_t ctdb_ban_state_len(struct ctdb_ban_state *in);
void ctdb_ban_state_push(struct ctdb_ban_state *in, uint8_t *buf,
			 size_t *npush);
int ctdb_ban_state_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_ban_state **out, size_t *npull);

size_t ctdb_notify_data_len(struct ctdb_notify_data *in);
void ctdb_notify_data_push(struct ctdb_notify_data *in, uint8_t *buf,
			   size_t *npush);
int ctdb_notify_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_notify_data **out, size_t *npull);

size_t ctdb_iface_len(struct ctdb_iface *in);
void ctdb_iface_push(struct ctdb_iface *in, uint8_t *buf, size_t *npush);
int ctdb_iface_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		    struct ctdb_iface **out, size_t *npull);

size_t ctdb_iface_list_len(struct ctdb_iface_list *in);
void ctdb_iface_list_push(struct ctdb_iface_list *in, uint8_t *buf,
			  size_t *npush);
int ctdb_iface_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_iface_list **out, size_t *npull);

size_t ctdb_public_ip_info_len(struct ctdb_public_ip_info *in);
void ctdb_public_ip_info_push(struct ctdb_public_ip_info *in, uint8_t *buf,
			      size_t *npush);
int ctdb_public_ip_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_info **out, size_t *npull);

size_t ctdb_key_data_len(struct ctdb_key_data *in);
void ctdb_key_data_push(struct ctdb_key_data *in, uint8_t *buf, size_t *npush);
int ctdb_key_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_key_data **out, size_t *npull);

size_t ctdb_db_statistics_len(struct ctdb_db_statistics *in);
void ctdb_db_statistics_push(struct ctdb_db_statistics *in, uint8_t *buf,
			     size_t *npush);
int ctdb_db_statistics_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_db_statistics **out, size_t *npull);

size_t ctdb_pid_srvid_len(struct ctdb_pid_srvid *in);
void ctdb_pid_srvid_push(struct ctdb_pid_srvid *in, uint8_t *buf,
			 size_t *npush);
int ctdb_pid_srvid_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_pid_srvid **out, size_t *npull);

size_t ctdb_election_message_len(struct ctdb_election_message *in);
void ctdb_election_message_push(struct ctdb_election_message *in,
				uint8_t *buf, size_t *npush);
int ctdb_election_message_pull(uint8_t *buf, size_t buflen,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_election_message **out,
			       size_t *npull);

size_t ctdb_srvid_message_len(struct ctdb_srvid_message *in);
void ctdb_srvid_message_push(struct ctdb_srvid_message *in, uint8_t *buf,
			     size_t *npush);
int ctdb_srvid_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_srvid_message **out, size_t *npull);

size_t ctdb_disable_message_len(struct ctdb_disable_message *in);
void ctdb_disable_message_push(struct ctdb_disable_message *in, uint8_t *buf,
			       size_t *npush);
int ctdb_disable_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_disable_message **out,
			      size_t *npull);

#endif /* __PROTOCOL_PRIVATE_H__ */
