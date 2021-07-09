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

#ifndef __CTDB_PROTOCOL_API_H__
#define __CTDB_PROTOCOL_API_H__

#include <talloc.h>

#include "protocol/protocol.h"

/* From protocol/protocol_types.c */

size_t ctdb_ltdb_header_len(struct ctdb_ltdb_header *in);
void ctdb_ltdb_header_push(struct ctdb_ltdb_header *in, uint8_t *buf,
			   size_t *npush);
int ctdb_ltdb_header_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_ltdb_header *out, size_t *npull);

int ctdb_ltdb_header_extract(TDB_DATA *data, struct ctdb_ltdb_header *header);

size_t ctdb_rec_data_len(struct ctdb_rec_data *in);
void ctdb_rec_data_push(struct ctdb_rec_data *in, uint8_t *buf, size_t *npush);
int ctdb_rec_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_rec_data **out, size_t *npull);

size_t ctdb_rec_buffer_len(struct ctdb_rec_buffer *in);
void ctdb_rec_buffer_push(struct ctdb_rec_buffer *in, uint8_t *buf,
			  size_t *npush);
int ctdb_rec_buffer_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_rec_buffer **out, size_t *npull);

struct ctdb_rec_buffer *ctdb_rec_buffer_init(TALLOC_CTX *mem_ctx,
					     uint32_t db_id);
int ctdb_rec_buffer_add(TALLOC_CTX *mem_ctx, struct ctdb_rec_buffer *recbuf,
			uint32_t reqid, struct ctdb_ltdb_header *header,
			TDB_DATA key, TDB_DATA data);
int ctdb_rec_buffer_traverse(struct ctdb_rec_buffer *recbuf,
			     ctdb_rec_parser_func_t func,
			     void *private_data);

int ctdb_rec_buffer_write(struct ctdb_rec_buffer *recbuf, int fd);
int ctdb_rec_buffer_read(int fd, TALLOC_CTX *mem_ctx,
			 struct ctdb_rec_buffer **out);

size_t ctdb_server_id_len(struct ctdb_server_id *in);
void ctdb_server_id_push(struct ctdb_server_id *in, uint8_t *buf,
			 size_t *npush);
int ctdb_server_id_pull(uint8_t *buf, size_t buflen,
			struct ctdb_server_id *out, size_t *npull);

size_t ctdb_g_lock_len(struct ctdb_g_lock *in);
void ctdb_g_lock_push(struct ctdb_g_lock *in, uint8_t *buf, size_t *npush);
int ctdb_g_lock_pull(uint8_t *buf, size_t buflen, struct ctdb_g_lock *out,
		     size_t *npull);

size_t ctdb_g_lock_list_len(struct ctdb_g_lock_list *in);
void ctdb_g_lock_list_push(struct ctdb_g_lock_list *in, uint8_t *buf,
			   size_t *npush);
int ctdb_g_lock_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_g_lock_list **out, size_t *npull);

/* From protocol/protocol_header.c */

void ctdb_req_header_fill(struct ctdb_req_header *h, uint32_t generation,
			  uint32_t operation, uint32_t destnode,
			  uint32_t srcnode, uint32_t reqid);

size_t ctdb_req_header_len(struct ctdb_req_header *in);
void ctdb_req_header_push(struct ctdb_req_header *in, uint8_t *buf,
			  size_t *npush);
int ctdb_req_header_pull(uint8_t *buf, size_t buflen,
			 struct ctdb_req_header *out, size_t *npull);

int ctdb_req_header_verify(struct ctdb_req_header *h, uint32_t operation);

/* From protocol/protocol_call.c */

size_t ctdb_req_call_len(struct ctdb_req_header *h,
			 struct ctdb_req_call *c);

int ctdb_req_call_push(struct ctdb_req_header *h,
		       struct ctdb_req_call *c,
		       uint8_t *buf, size_t *buflen);

int ctdb_req_call_pull(uint8_t *buf, size_t buflen,
		       struct ctdb_req_header *h,
		       TALLOC_CTX *mem_ctx,
		       struct ctdb_req_call *c);

size_t ctdb_reply_call_len(struct ctdb_req_header *h,
			   struct ctdb_reply_call *c);

int ctdb_reply_call_push(struct ctdb_req_header *h,
			 struct ctdb_reply_call *c,
			 uint8_t *buf, size_t *buflen);

int ctdb_reply_call_pull(uint8_t *buf, size_t buflen,
			 struct ctdb_req_header *h,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_reply_call *c);

size_t ctdb_reply_error_len(struct ctdb_req_header *h,
			    struct ctdb_reply_error *c);

int ctdb_reply_error_push(struct ctdb_req_header *h,
			  struct ctdb_reply_error *c,
			  uint8_t *buf, size_t *buflen);

int ctdb_reply_error_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_reply_error *c);

size_t ctdb_req_dmaster_len(struct ctdb_req_header *h,
			    struct ctdb_req_dmaster *c);

int ctdb_req_dmaster_push(struct ctdb_req_header *h,
			  struct ctdb_req_dmaster *c,
			  uint8_t *buf, size_t *buflen);

int ctdb_req_dmaster_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_dmaster *c);

size_t ctdb_reply_dmaster_len(struct ctdb_req_header *h,
			      struct ctdb_reply_dmaster *c);

int ctdb_reply_dmaster_push(struct ctdb_req_header *h,
			    struct ctdb_reply_dmaster *c,
			    uint8_t *buf, size_t *buflen);

int ctdb_reply_dmaster_pull(uint8_t *buf, size_t buflen,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_reply_dmaster *c);

/* From protocol/protocol_control.c */

size_t ctdb_req_control_len(struct ctdb_req_header *h,
			    struct ctdb_req_control *c);

int ctdb_req_control_push(struct ctdb_req_header *h,
			  struct ctdb_req_control *c,
			  uint8_t *buf, size_t *buflen);

int ctdb_req_control_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_control *c);

size_t ctdb_reply_control_len(struct ctdb_req_header *h,
			      struct ctdb_reply_control *c);

int ctdb_reply_control_push(struct ctdb_req_header *h,
			    struct ctdb_reply_control *c,
			    uint8_t *buf, size_t *buflen);

int ctdb_reply_control_pull(uint8_t *buf, size_t buflen, uint32_t opcode,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_reply_control *c);

/* From protocol/protocol_client.c */

void ctdb_req_control_process_exists(struct ctdb_req_control *request,
				     pid_t pid);
int ctdb_reply_control_process_exists(struct ctdb_reply_control *reply,
				      int *status);

void ctdb_req_control_statistics(struct ctdb_req_control *request);

int ctdb_reply_control_statistics(struct ctdb_reply_control *reply,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_statistics **stats);

void ctdb_req_control_ping(struct ctdb_req_control *request);
int ctdb_reply_control_ping(struct ctdb_reply_control *reply,
			    int *num_clients);

void ctdb_req_control_getdbpath(struct ctdb_req_control *request,
				uint32_t db_id);
int ctdb_reply_control_getdbpath(struct ctdb_reply_control *reply,
				 TALLOC_CTX *mem_ctx, const char **db_path);

void ctdb_req_control_getvnnmap(struct ctdb_req_control *request);
int ctdb_reply_control_getvnnmap(struct ctdb_reply_control *reply,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_vnn_map **vnnmap);

void ctdb_req_control_setvnnmap(struct ctdb_req_control *request,
				struct ctdb_vnn_map *vnnmap);
int ctdb_reply_control_setvnnmap(struct ctdb_reply_control *reply);

void ctdb_req_control_get_debug(struct ctdb_req_control *request);
int ctdb_reply_control_get_debug(struct ctdb_reply_control *reply,
				 int *debug_level);

void ctdb_req_control_set_debug(struct ctdb_req_control *request,
				int debug_level);
int ctdb_reply_control_set_debug(struct ctdb_reply_control *reply);

void ctdb_req_control_get_dbmap(struct ctdb_req_control *request);
int ctdb_reply_control_get_dbmap(struct ctdb_reply_control *reply,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_dbid_map **dbmap);

void ctdb_req_control_pull_db(struct ctdb_req_control *request,
			      struct ctdb_pulldb *pulldb);
int ctdb_reply_control_pull_db(struct ctdb_reply_control *reply,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_rec_buffer **recbuf);

void ctdb_req_control_push_db(struct ctdb_req_control *request,
			      struct ctdb_rec_buffer *recbuf);
int ctdb_reply_control_push_db(struct ctdb_reply_control *reply);

void ctdb_req_control_get_recmode(struct ctdb_req_control *request);
int ctdb_reply_control_get_recmode(struct ctdb_reply_control *reply,
				   int *recmode);

void ctdb_req_control_set_recmode(struct ctdb_req_control *request,
				  int recmode);
int ctdb_reply_control_set_recmode(struct ctdb_reply_control *reply);

void ctdb_req_control_statistics_reset(struct ctdb_req_control *request);
int ctdb_reply_control_statistics_reset(struct ctdb_reply_control *reply);

void ctdb_req_control_db_attach(struct ctdb_req_control *request,
				const char *db_name);
int ctdb_reply_control_db_attach(struct ctdb_reply_control *reply,
				 uint32_t *db_id);

void ctdb_req_control_traverse_start(struct ctdb_req_control *request,
				     struct ctdb_traverse_start *traverse);
int ctdb_reply_control_traverse_start(struct ctdb_reply_control *reply);

void ctdb_req_control_register_srvid(struct ctdb_req_control *request,
				     uint64_t srvid);
int ctdb_reply_control_register_srvid(struct ctdb_reply_control *reply);

void ctdb_req_control_deregister_srvid(struct ctdb_req_control *request,
				       uint64_t srvid);
int ctdb_reply_control_deregister_srvid(struct ctdb_reply_control *reply);

void ctdb_req_control_get_dbname(struct ctdb_req_control *request,
				 uint32_t db_id);
int ctdb_reply_control_get_dbname(struct ctdb_reply_control *reply,
				  TALLOC_CTX *mem_ctx, const char **db_name);

void ctdb_req_control_enable_seqnum(struct ctdb_req_control *request,
				    uint32_t db_id);
int ctdb_reply_control_enable_seqnum(struct ctdb_reply_control *reply);

void ctdb_req_control_update_seqnum(struct ctdb_req_control *request,
				    uint32_t db_id);
int ctdb_reply_control_update_seqnum(struct ctdb_reply_control *reply);

void ctdb_req_control_dump_memory(struct ctdb_req_control *request);
int ctdb_reply_control_dump_memory(struct ctdb_reply_control *reply,
				   TALLOC_CTX *mem_ctx, const char **mem_str);

void ctdb_req_control_get_pid(struct ctdb_req_control *request);
int ctdb_reply_control_get_pid(struct ctdb_reply_control *reply,
			       pid_t *pid);

void ctdb_req_control_get_recmaster(struct ctdb_req_control *request);
int ctdb_reply_control_get_recmaster(struct ctdb_reply_control *reply,
				     uint32_t *recmaster);

void ctdb_req_control_set_recmaster(struct ctdb_req_control *request,
				    int recmaster);
int ctdb_reply_control_set_recmaster(struct ctdb_reply_control *reply);

void ctdb_req_control_freeze(struct ctdb_req_control *request,
			     uint32_t priority);
int ctdb_reply_control_freeze(struct ctdb_reply_control *reply);

void ctdb_req_control_get_pnn(struct ctdb_req_control *request);
int ctdb_reply_control_get_pnn(struct ctdb_reply_control *reply,
			       uint32_t *pnn);

void ctdb_req_control_shutdown(struct ctdb_req_control *request);
int ctdb_reply_control_shutdown(struct ctdb_reply_control *reply);

void ctdb_req_control_tcp_client(struct ctdb_req_control *request,
				 struct ctdb_connection *conn);
int ctdb_reply_control_tcp_client(struct ctdb_reply_control *reply);

void ctdb_req_control_tcp_add(struct ctdb_req_control *request,
			      struct ctdb_connection *conn);
int ctdb_reply_control_tcp_add(struct ctdb_reply_control *reply);

void ctdb_req_control_tcp_remove(struct ctdb_req_control *request,
				 struct ctdb_connection *conn);
int ctdb_reply_control_tcp_remove(struct ctdb_reply_control *reply);

void ctdb_req_control_startup(struct ctdb_req_control *request);
int ctdb_reply_control_startup(struct ctdb_reply_control *reply);

void ctdb_req_control_set_tunable(struct ctdb_req_control *request,
				  struct ctdb_tunable *tunable);
int ctdb_reply_control_set_tunable(struct ctdb_reply_control *reply);

void ctdb_req_control_get_tunable(struct ctdb_req_control *request,
				  const char *name);
int ctdb_reply_control_get_tunable(struct ctdb_reply_control *reply,
				   uint32_t *value);

void ctdb_req_control_list_tunables(struct ctdb_req_control *request);
int ctdb_reply_control_list_tunables(struct ctdb_reply_control *reply,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_var_list **tun_var_list);

void ctdb_req_control_modify_flags(struct ctdb_req_control *request,
				   struct ctdb_node_flag_change *flag_change);
int ctdb_reply_control_modify_flags(struct ctdb_reply_control *reply);

void ctdb_req_control_get_all_tunables(struct ctdb_req_control *request);
int ctdb_reply_control_get_all_tunables(struct ctdb_reply_control *reply,
					TALLOC_CTX *mem_ctx,
					struct ctdb_tunable_list **tun_list);

void ctdb_req_control_get_tcp_tickle_list(struct ctdb_req_control *request,
					  ctdb_sock_addr *addr);
int ctdb_reply_control_get_tcp_tickle_list(struct ctdb_reply_control *reply,
					   TALLOC_CTX *mem_ctx,
					   struct ctdb_tickle_list **tickles);

void ctdb_req_control_set_tcp_tickle_list(struct ctdb_req_control *request,
					  struct ctdb_tickle_list *tickles);
int ctdb_reply_control_set_tcp_tickle_list(struct ctdb_reply_control *reply);

void ctdb_req_control_db_attach_persistent(struct ctdb_req_control *request,
					   const char *name);
int ctdb_reply_control_db_attach_persistent(struct ctdb_reply_control *reply,
					    uint32_t *db_id);

void ctdb_req_control_update_record(struct ctdb_req_control *request,
				    struct ctdb_rec_buffer *recbuf);
int ctdb_reply_control_update_record(struct ctdb_reply_control *reply);

void ctdb_req_control_send_gratuitous_arp(struct ctdb_req_control *request,
					  struct ctdb_addr_info *addr_info);
int ctdb_reply_control_send_gratuitous_arp(struct ctdb_reply_control *reply);

void ctdb_req_control_wipe_database(struct ctdb_req_control *request,
				    struct ctdb_transdb *transdb);
int ctdb_reply_control_wipe_database(struct ctdb_reply_control *reply);

void ctdb_req_control_uptime(struct ctdb_req_control *request);
int ctdb_reply_control_uptime(struct ctdb_reply_control *reply,
			      TALLOC_CTX *mem_ctx,
			      struct ctdb_uptime **uptime);

void ctdb_req_control_start_recovery(struct ctdb_req_control *request);
int ctdb_reply_control_start_recovery(struct ctdb_reply_control *reply);

void ctdb_req_control_end_recovery(struct ctdb_req_control *request);
int ctdb_reply_control_end_recovery(struct ctdb_reply_control *reply);

void ctdb_req_control_reload_nodes_file(struct ctdb_req_control *request);
int ctdb_reply_control_reload_nodes_file(struct ctdb_reply_control *reply);

void ctdb_req_control_try_delete_records(struct ctdb_req_control *request,
					 struct ctdb_rec_buffer *recbuf);
int ctdb_reply_control_try_delete_records(struct ctdb_reply_control *reply,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_rec_buffer **recbuf);

void ctdb_req_control_add_public_ip(struct ctdb_req_control *request,
				    struct ctdb_addr_info *addr_info);
int ctdb_reply_control_add_public_ip(struct ctdb_reply_control *reply);

void ctdb_req_control_del_public_ip(struct ctdb_req_control *request,
				    struct ctdb_addr_info *addr_info);
int ctdb_reply_control_del_public_ip(struct ctdb_reply_control *reply);

void ctdb_req_control_get_capabilities(struct ctdb_req_control *request);
int ctdb_reply_control_get_capabilities(struct ctdb_reply_control *reply,
					uint32_t *caps);

void ctdb_req_control_recd_ping(struct ctdb_req_control *request);
int ctdb_reply_control_recd_ping(struct ctdb_reply_control *reply);

void ctdb_req_control_release_ip(struct ctdb_req_control *request,
				 struct ctdb_public_ip *pubip);
int ctdb_reply_control_release_ip(struct ctdb_reply_control *reply);

void ctdb_req_control_takeover_ip(struct ctdb_req_control *request,
				  struct ctdb_public_ip *pubip);
int ctdb_reply_control_takeover_ip(struct ctdb_reply_control *reply);

void ctdb_req_control_get_public_ips(struct ctdb_req_control *request,
				     bool available_only);
int ctdb_reply_control_get_public_ips(struct ctdb_reply_control *reply,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_public_ip_list **pubip_list);

void ctdb_req_control_get_nodemap(struct ctdb_req_control *request);
int ctdb_reply_control_get_nodemap(struct ctdb_reply_control *reply,
				   TALLOC_CTX *mem_ctx,
				   struct ctdb_node_map **nodemap);

void ctdb_req_control_traverse_kill(struct ctdb_req_control *request,
				    struct ctdb_traverse_start *traverse);
int ctdb_reply_control_traverse_kill(struct ctdb_reply_control *reply);

void ctdb_req_control_recd_reclock_latency(struct ctdb_req_control *request,
					   double reclock_latency);
int ctdb_reply_control_recd_reclock_latency(struct ctdb_reply_control *reply);

void ctdb_req_control_get_reclock_file(struct ctdb_req_control *request);
int ctdb_reply_control_get_reclock_file(struct ctdb_reply_control *reply,
					TALLOC_CTX *mem_ctx,
					const char **reclock_file);

void ctdb_req_control_stop_node(struct ctdb_req_control *request);
int ctdb_reply_control_stop_node(struct ctdb_reply_control *reply);

void ctdb_req_control_continue_node(struct ctdb_req_control *request);
int ctdb_reply_control_continue_node(struct ctdb_reply_control *reply);

void ctdb_req_control_set_lmasterrole(struct ctdb_req_control *request,
				      uint32_t lmaster_role);
int ctdb_reply_control_set_lmasterrole(struct ctdb_reply_control *reply);

void ctdb_req_control_set_recmasterrole(struct ctdb_req_control *request,
					uint32_t recmaster_role);
int ctdb_reply_control_set_recmasterrole(struct ctdb_reply_control *reply);

void ctdb_req_control_set_ban_state(struct ctdb_req_control *request,
				    struct ctdb_ban_state *ban_state);
int ctdb_reply_control_set_ban_state(struct ctdb_reply_control *reply);

void ctdb_req_control_get_ban_state(struct ctdb_req_control *request);
int ctdb_reply_control_get_ban_state(struct ctdb_reply_control *reply,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_ban_state **ban_state);

void ctdb_req_control_register_notify(struct ctdb_req_control *request,
				      struct ctdb_notify_data *notify);
int ctdb_reply_control_register_notify(struct ctdb_reply_control *reply);

void ctdb_req_control_deregister_notify(struct ctdb_req_control *request,
					uint64_t srvid);
int ctdb_reply_control_deregister_notify(struct ctdb_reply_control *reply);

void ctdb_req_control_trans3_commit(struct ctdb_req_control *request,
				    struct ctdb_rec_buffer *recbuf);
int ctdb_reply_control_trans3_commit(struct ctdb_reply_control *reply);

void ctdb_req_control_get_db_seqnum(struct ctdb_req_control *request,
				    uint32_t db_id);
int ctdb_reply_control_get_db_seqnum(struct ctdb_reply_control *reply,
				     uint64_t *seqnum);

void ctdb_req_control_db_set_healthy(struct ctdb_req_control *request,
				     uint32_t db_id);
int ctdb_reply_control_db_set_healthy(struct ctdb_reply_control *reply);

void ctdb_req_control_db_get_health(struct ctdb_req_control *request,
				    uint32_t db_id);
int ctdb_reply_control_db_get_health(struct ctdb_reply_control *reply,
				     TALLOC_CTX *mem_ctx,
				     const char **reason);

void ctdb_req_control_get_public_ip_info(struct ctdb_req_control *request,
					 ctdb_sock_addr *addr);
int ctdb_reply_control_get_public_ip_info(struct ctdb_reply_control *reply,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_public_ip_info **ipinfo);

void ctdb_req_control_get_ifaces(struct ctdb_req_control *request);
int ctdb_reply_control_get_ifaces(struct ctdb_reply_control *reply,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_iface_list **iface_list);

void ctdb_req_control_set_iface_link_state(struct ctdb_req_control *request,
					   struct ctdb_iface *iface);
int ctdb_reply_control_set_iface_link_state(struct ctdb_reply_control *reply);

void ctdb_req_control_tcp_add_delayed_update(struct ctdb_req_control *request,
					     struct ctdb_connection *conn);
int ctdb_reply_control_tcp_add_delayed_update(struct ctdb_reply_control *reply);

void ctdb_req_control_get_stat_history(struct ctdb_req_control *request);
int ctdb_reply_control_get_stat_history(struct ctdb_reply_control *reply,
					TALLOC_CTX *mem_ctx,
					struct ctdb_statistics_list **stats_list);

void ctdb_req_control_schedule_for_deletion(struct ctdb_req_control *request,
					    struct ctdb_key_data *key);
int ctdb_reply_control_schedule_for_deletion(struct ctdb_reply_control *reply);

void ctdb_req_control_set_db_readonly(struct ctdb_req_control *request,
				      uint32_t db_id);
int ctdb_reply_control_set_db_readonly(struct ctdb_reply_control *reply);

void ctdb_req_control_traverse_start_ext(struct ctdb_req_control *request,
					 struct ctdb_traverse_start_ext *traverse);
int ctdb_reply_control_traverse_start_ext(struct ctdb_reply_control *reply);

void ctdb_req_control_get_db_statistics(struct ctdb_req_control *request,
					uint32_t db_id);
int ctdb_reply_control_get_db_statistics(struct ctdb_reply_control *reply,
					 TALLOC_CTX *mem_ctx,
					 struct ctdb_db_statistics **dbstats);

void ctdb_req_control_set_db_sticky(struct ctdb_req_control *request,
				    uint32_t db_id);
int ctdb_reply_control_set_db_sticky(struct ctdb_reply_control *reply);

void ctdb_req_control_reload_public_ips(struct ctdb_req_control *request);
int ctdb_reply_control_reload_public_ips(struct ctdb_reply_control *reply);

void ctdb_req_control_ipreallocated(struct ctdb_req_control *request);
int ctdb_reply_control_ipreallocated(struct ctdb_reply_control *reply);

void ctdb_req_control_get_runstate(struct ctdb_req_control *request);
int ctdb_reply_control_get_runstate(struct ctdb_reply_control *reply,
				    enum ctdb_runstate *runstate);

void ctdb_req_control_db_detach(struct ctdb_req_control *request,
				uint32_t db_id);
int ctdb_reply_control_db_detach(struct ctdb_reply_control *reply);

void ctdb_req_control_get_nodes_file(struct ctdb_req_control *request);
int ctdb_reply_control_get_nodes_file(struct ctdb_reply_control *reply,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_node_map **nodemap);

void ctdb_req_control_db_freeze(struct ctdb_req_control *request,
				uint32_t db_id);
int ctdb_reply_control_db_freeze(struct ctdb_reply_control *reply);

void ctdb_req_control_db_thaw(struct ctdb_req_control *request,
			      uint32_t db_id);
int ctdb_reply_control_db_thaw(struct ctdb_reply_control *reply);

void ctdb_req_control_db_transaction_start(struct ctdb_req_control *request,
					   struct ctdb_transdb *transdb);
int ctdb_reply_control_db_transaction_start(struct ctdb_reply_control *reply);

void ctdb_req_control_db_transaction_commit(struct ctdb_req_control *request,
					    struct ctdb_transdb *transdb);
int ctdb_reply_control_db_transaction_commit(struct ctdb_reply_control *reply);

void ctdb_req_control_db_transaction_cancel(struct ctdb_req_control *request,
					    uint32_t db_id);
int ctdb_reply_control_db_transaction_cancel(struct ctdb_reply_control *reply);

void ctdb_req_control_db_pull(struct ctdb_req_control *request,
			      struct ctdb_pulldb_ext *pulldb_ext);
int ctdb_reply_control_db_pull(struct ctdb_reply_control *reply,
			       uint32_t *num_records);

void ctdb_req_control_db_push_start(struct ctdb_req_control *request,
				    struct ctdb_pulldb_ext *pulldb_ext);
int ctdb_reply_control_db_push_start(struct ctdb_reply_control *reply);

void ctdb_req_control_db_push_confirm(struct ctdb_req_control *request,
				      uint32_t db_id);
int ctdb_reply_control_db_push_confirm(struct ctdb_reply_control *reply,
				       uint32_t *num_records);

void ctdb_req_control_db_open_flags(struct ctdb_req_control *request,
				    uint32_t db_id);
int ctdb_reply_control_db_open_flags(struct ctdb_reply_control *reply,
				     int *tdb_flags);

void ctdb_req_control_db_attach_replicated(struct ctdb_req_control *request,
					   const char *db_name);
int ctdb_reply_control_db_attach_replicated(struct ctdb_reply_control *reply,
					    uint32_t *db_id);

void ctdb_req_control_check_pid_srvid(struct ctdb_req_control *request,
				      struct ctdb_pid_srvid *pid_srvid);
int ctdb_reply_control_check_pid_srvid(struct ctdb_reply_control *reply,
				       int *status);

void ctdb_req_control_tunnel_register(struct ctdb_req_control *request,
				      uint64_t tunnel_id);
int ctdb_reply_control_tunnel_register(struct ctdb_reply_control *reply);

void ctdb_req_control_tunnel_deregister(struct ctdb_req_control *request,
					uint64_t tunnel_id);
int ctdb_reply_control_tunnel_deregister(struct ctdb_reply_control *reply);

void ctdb_req_control_vacuum_fetch(struct ctdb_req_control *request,
				   struct ctdb_rec_buffer *recbuf);
int ctdb_reply_control_vacuum_fetch(struct ctdb_reply_control *reply);

void ctdb_req_control_db_vacuum(struct ctdb_req_control *request,
				struct ctdb_db_vacuum *db_vacuum);
int ctdb_reply_control_db_vacuum(struct ctdb_reply_control *reply);

void ctdb_req_control_echo_data(struct ctdb_req_control *request,
				struct ctdb_echo_data *echo_data);
int ctdb_reply_control_echo_data(struct ctdb_reply_control *reply);

void ctdb_req_control_disable_node(struct ctdb_req_control *request);
int ctdb_reply_control_disable_node(struct ctdb_reply_control *reply);

void ctdb_req_control_enable_node(struct ctdb_req_control *request);
int ctdb_reply_control_enable_node(struct ctdb_reply_control *reply);

/* From protocol/protocol_debug.c */

void ctdb_packet_print(uint8_t *buf, size_t buflen, FILE *fp);

/* From protocol/protocol_message.c */

size_t ctdb_req_message_len(struct ctdb_req_header *h,
			    struct ctdb_req_message *c);

int ctdb_req_message_push(struct ctdb_req_header *h,
			  struct ctdb_req_message *c,
			  uint8_t *buf, size_t *buflen);

int ctdb_req_message_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_message *c);

size_t ctdb_req_message_data_len(struct ctdb_req_header *h,
				 struct ctdb_req_message_data *c);

int ctdb_req_message_data_push(struct ctdb_req_header *h,
			       struct ctdb_req_message_data *c,
			       uint8_t *buf, size_t *buflen);

int ctdb_req_message_data_pull(uint8_t *buf, size_t buflen,
			       struct ctdb_req_header *h,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_req_message_data *c);

/* From protocol/protocol_keepalive.c */

size_t ctdb_req_keepalive_len(struct ctdb_req_header *h,
			      struct ctdb_req_keepalive *c);

int ctdb_req_keepalive_push(struct ctdb_req_header *h,
			    struct ctdb_req_keepalive *c,
			    uint8_t *buf, size_t *buflen);

int ctdb_req_keepalive_pull(uint8_t *buf, size_t buflen,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_req_keepalive *c);

/* From protocol/protocol_tunnel.c */

size_t ctdb_req_tunnel_len(struct ctdb_req_header *h,
			   struct ctdb_req_tunnel *c);

int ctdb_req_tunnel_push(struct ctdb_req_header *h,
			 struct ctdb_req_tunnel *c,
			 uint8_t *buf, size_t *buflen);

int ctdb_req_tunnel_pull(uint8_t *buf, size_t buflen,
			 struct ctdb_req_header *h,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_req_tunnel *c);

/* From protocol/protocol_packet.c */

int ctdb_allocate_pkt(TALLOC_CTX *mem_ctx, size_t datalen,
		      uint8_t **buf, size_t *buflen);

/* From protocol/protocol_sock.c */

size_t sock_packet_header_len(struct sock_packet_header *in);
void sock_packet_header_push(struct sock_packet_header *in, uint8_t *buf,
			     size_t *npush);
int sock_packet_header_pull(uint8_t *buf, size_t buflen,
			    struct sock_packet_header *out, size_t *npull);

void sock_packet_header_set_reqid(struct sock_packet_header *h,
				  uint32_t reqid);
void sock_packet_header_set_length(struct sock_packet_header *h,
				   uint32_t length);

#endif /* __CTDB_PROTOCOL_API_H__ */
