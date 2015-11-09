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

int allocate_pkt(TALLOC_CTX *mem_ctx, size_t length,
		 uint8_t **buf, size_t *buflen);

size_t ctdb_uint32_len(uint32_t val);
void ctdb_uint32_push(uint32_t val, uint8_t *buf);
int ctdb_uint32_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     uint32_t *out);

size_t ctdb_uint64_len(uint64_t val);
void ctdb_uint64_push(uint64_t val, uint8_t *buf);
int ctdb_uint64_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     uint64_t *out);

size_t ctdb_double_len(double val);
void ctdb_double_push(double val, uint8_t *buf);
int ctdb_double_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     double *out);

size_t ctdb_uint8_array_len(struct ctdb_uint8_array *array);
void ctdb_uint8_array_push(struct ctdb_uint8_array *array, uint8_t *buf);
int ctdb_uint8_array_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_uint8_array **out);

size_t ctdb_uint64_array_len(struct ctdb_uint64_array *array);
void ctdb_uint64_array_push(struct ctdb_uint64_array *array, uint8_t *buf);
int ctdb_uint64_array_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_uint64_array **out);

size_t ctdb_pid_len(pid_t pid);
void ctdb_pid_push(pid_t pid, uint8_t *buf);
int ctdb_pid_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		  pid_t *out);

size_t ctdb_string_len(const char *str);
void ctdb_string_push(const char *str, uint8_t *buf);
int ctdb_string_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     const char **out);

size_t ctdb_stringn_len(const char *str);
void ctdb_stringn_push(const char *str, uint8_t *buf);
int ctdb_stringn_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      const char **out);

size_t ctdb_statistics_len(struct ctdb_statistics *stats);
void ctdb_statistics_push(struct ctdb_statistics *stats, uint8_t *buf);
int ctdb_statistics_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_statistics **out);

size_t ctdb_statistics_list_len(struct ctdb_statistics_list *stats_list);
void ctdb_statistics_list_push(struct ctdb_statistics_list *stats_list,
			       uint8_t *buf);
int ctdb_statistics_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_statistics_list **out);

size_t ctdb_vnn_map_len(struct ctdb_vnn_map *vnnmap);
void ctdb_vnn_map_push(struct ctdb_vnn_map *vnnmap, uint8_t *buf);
int ctdb_vnn_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_vnn_map **out);

size_t ctdb_dbid_map_len(struct ctdb_dbid_map *dbmap);
void ctdb_dbid_map_push(struct ctdb_dbid_map *dbmap, uint8_t *buf);
int ctdb_dbid_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_dbid_map **out);

size_t ctdb_pulldb_len(struct ctdb_pulldb *pulldb);
void ctdb_pulldb_push(struct ctdb_pulldb *pulldb, uint8_t *buf);
int ctdb_pulldb_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_pulldb **out);

size_t ctdb_traverse_start_len(struct ctdb_traverse_start *traverse);
void ctdb_traverse_start_push(struct ctdb_traverse_start *traverse,
			      uint8_t *buf);
int ctdb_traverse_start_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_traverse_start **out);

size_t ctdb_traverse_all_len(struct ctdb_traverse_all *traverse);
void ctdb_traverse_all_push(struct ctdb_traverse_all *traverse, uint8_t *buf);
int ctdb_traverse_all_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_traverse_all **out);

size_t ctdb_traverse_start_ext_len(struct ctdb_traverse_start_ext *traverse);
void ctdb_traverse_start_ext_push(struct ctdb_traverse_start_ext *traverse,
				  uint8_t *buf);
int ctdb_traverse_start_ext_pull(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_traverse_start_ext **out);

size_t ctdb_traverse_all_ext_len(struct ctdb_traverse_all_ext *traverse);
void ctdb_traverse_all_ext_push(struct ctdb_traverse_all_ext *traverse,
				uint8_t *buf);
int ctdb_traverse_all_ext_pull(uint8_t *buf, size_t buflen,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_traverse_all_ext **out);

size_t ctdb_sock_addr_len(ctdb_sock_addr *addr);
void ctdb_sock_addr_push(ctdb_sock_addr *addr, uint8_t *buf);
int ctdb_sock_addr_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			ctdb_sock_addr **out);

size_t ctdb_connection_len(struct ctdb_connection *conn);
void ctdb_connection_push(struct ctdb_connection *conn, uint8_t *buf);
int ctdb_connection_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_connection **out);

size_t ctdb_tunable_len(struct ctdb_tunable *tunable);
void ctdb_tunable_push(struct ctdb_tunable *tunable, uint8_t *buf);
int ctdb_tunable_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_tunable **out);

size_t ctdb_node_flag_change_len(struct ctdb_node_flag_change *flag_change);
void ctdb_node_flag_change_push(struct ctdb_node_flag_change *flag_change,
				uint8_t *buf);
int ctdb_node_flag_change_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			       struct ctdb_node_flag_change **out);

size_t ctdb_var_list_len(struct ctdb_var_list *var_list);
void ctdb_var_list_push(struct ctdb_var_list *var_list, uint8_t *buf);
int ctdb_var_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_var_list **out);

size_t ctdb_tunable_list_len(struct ctdb_tunable_list *tun_list);
void ctdb_tunable_list_push(struct ctdb_tunable_list *tun_list, uint8_t *buf);
int ctdb_tunable_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_tunable_list **out);

size_t ctdb_tickle_list_len(struct ctdb_tickle_list *tickles);
void ctdb_tickle_list_push(struct ctdb_tickle_list *tickles, uint8_t *buf);
int ctdb_tickle_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_tickle_list **out);

size_t ctdb_client_id_len(struct ctdb_client_id *cid);
void ctdb_client_id_push(struct ctdb_client_id *cid, uint8_t *buf);
int ctdb_client_id_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_client_id **out);

size_t ctdb_client_id_list_len(struct ctdb_client_id_list *cid_list);
void ctdb_client_id_list_push(struct ctdb_client_id_list *cid_list,
			      uint8_t *buf);
int ctdb_client_id_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_client_id_list **out);

size_t ctdb_client_id_map_len(struct ctdb_client_id_map *cid_map);
void ctdb_client_id_map_push(struct ctdb_client_id_map *cid_map, uint8_t *buf);
int ctdb_client_id_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_client_id_map **out);

size_t ctdb_addr_info_len(struct ctdb_addr_info *addr_info);
void ctdb_addr_info_push(struct ctdb_addr_info *addr_info, uint8_t *buf);
int ctdb_addr_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_addr_info **out);

size_t ctdb_transdb_len(struct ctdb_transdb *transdb);
void ctdb_transdb_push(struct ctdb_transdb *transdb, uint8_t *buf);
int ctdb_transdb_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_transdb **out);

size_t ctdb_uptime_len(struct ctdb_uptime *uptime);
void ctdb_uptime_push(struct ctdb_uptime *uptime, uint8_t *buf);
int ctdb_uptime_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_uptime **out);

size_t ctdb_public_ip_len(struct ctdb_public_ip *public_ip);
void ctdb_public_ip_push(struct ctdb_public_ip *public_ip, uint8_t *buf);
int ctdb_public_ip_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_public_ip **out);

size_t ctdb_public_ip_list_len(struct ctdb_public_ip_list *pubip_list);
void ctdb_public_ip_list_push(struct ctdb_public_ip_list *pubip_list,
			      uint8_t *buf);
int ctdb_public_ip_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_list **out);

size_t ctdb_node_and_flags_len(struct ctdb_node_and_flags *node);
void ctdb_node_and_flags_push(struct ctdb_node_and_flags *node, uint8_t *buf);
int ctdb_node_and_flags_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_node_and_flags **out);

size_t ctdb_node_map_len(struct ctdb_node_map *nodemap);
void ctdb_node_map_push(struct ctdb_node_map *nodemap, uint8_t *buf);
int ctdb_node_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_node_map **out);

size_t ctdb_script_len(struct ctdb_script *script);
void ctdb_script_push(struct ctdb_script *script, uint8_t *buf);
int ctdb_script_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_script **out);

size_t ctdb_script_list_len(struct ctdb_script_list *script_list);
void ctdb_script_list_push(struct ctdb_script_list *script_list, uint8_t *buf);
int ctdb_script_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_script_list **out);

size_t ctdb_ban_state_len(struct ctdb_ban_state *ban_state);
void ctdb_ban_state_push(struct ctdb_ban_state *ban_state, uint8_t *buf);
int ctdb_ban_state_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_ban_state **out);

size_t ctdb_db_priority_len(struct ctdb_db_priority *db_prio);
void ctdb_db_priority_push(struct ctdb_db_priority *db_prio, uint8_t *buf);
int ctdb_db_priority_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_db_priority **out);

size_t ctdb_notify_data_len(struct ctdb_notify_data *notify);
void ctdb_notify_data_push(struct ctdb_notify_data *notify, uint8_t *buf);
int ctdb_notify_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_notify_data **out);

size_t ctdb_iface_len(struct ctdb_iface *iface);
void ctdb_iface_push(struct ctdb_iface *iface, uint8_t *buf);
int ctdb_iface_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		    struct ctdb_iface **out);

size_t ctdb_iface_list_len(struct ctdb_iface_list *iface_list);
void ctdb_iface_list_push(struct ctdb_iface_list *iface_list, uint8_t *buf);
int ctdb_iface_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_iface_list **out);

size_t ctdb_public_ip_info_len(struct ctdb_public_ip_info *ipinfo);
void ctdb_public_ip_info_push(struct ctdb_public_ip_info *ipinfo, uint8_t *buf);
int ctdb_public_ip_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_info **out);

size_t ctdb_key_data_len(struct ctdb_key_data *key);
void ctdb_key_data_push(struct ctdb_key_data *key, uint8_t *buf);
int ctdb_key_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_key_data **out);

size_t ctdb_db_statistics_len(struct ctdb_db_statistics *dbstats);
void ctdb_db_statistics_push(struct ctdb_db_statistics *dbstats, void *buf);
int ctdb_db_statistics_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_db_statistics **out);

size_t ctdb_election_message_len(struct ctdb_election_message *election);
void ctdb_election_message_push(struct ctdb_election_message *election,
				uint8_t *buf);
int ctdb_election_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			       struct ctdb_election_message **out);

size_t ctdb_srvid_message_len(struct ctdb_srvid_message *msg);
void ctdb_srvid_message_push(struct ctdb_srvid_message *msg, uint8_t *buf);
int ctdb_srvid_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_srvid_message **out);

size_t ctdb_tdb_data_len(TDB_DATA data);
void ctdb_tdb_data_push(TDB_DATA data, uint8_t *buf);
int ctdb_tdb_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       TDB_DATA *out);

size_t ctdb_disable_message_len(struct ctdb_disable_message *disable);
void ctdb_disable_message_push(struct ctdb_disable_message *disable,
			       uint8_t *buf);
int ctdb_disable_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_disable_message **out);

#endif /* __PROTOCOL_PRIVATE_H__ */
