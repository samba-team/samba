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

size_t ctdb_ltdb_header_len(struct ctdb_ltdb_header *header);
void ctdb_ltdb_header_push(struct ctdb_ltdb_header *header, uint8_t *buf);
int ctdb_ltdb_header_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_ltdb_header *header);

int ctdb_ltdb_header_extract(TDB_DATA *data, struct ctdb_ltdb_header *header);

size_t ctdb_rec_data_len(struct ctdb_rec_data *rec);
void ctdb_rec_data_push(struct ctdb_rec_data *rec, uint8_t *buf);
int ctdb_rec_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_rec_data **out);

size_t ctdb_rec_buffer_len(struct ctdb_rec_buffer *recbuf);
void ctdb_rec_buffer_push(struct ctdb_rec_buffer *recbuf, uint8_t *buf);
int ctdb_rec_buffer_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_rec_buffer **out);

struct ctdb_rec_buffer *ctdb_rec_buffer_init(TALLOC_CTX *mem_ctx,
					     uint32_t db_id);
int ctdb_rec_buffer_add(TALLOC_CTX *mem_ctx, struct ctdb_rec_buffer *recbuf,
			uint32_t reqid, struct ctdb_ltdb_header *header,
			TDB_DATA key, TDB_DATA data);
int ctdb_rec_buffer_traverse(struct ctdb_rec_buffer *recbuf,
			     ctdb_rec_parser_func_t func,
			     void *private_data);

size_t ctdb_server_id_len(struct ctdb_server_id *sid);
void ctdb_server_id_push(struct ctdb_server_id *sid, uint8_t *buf);
int ctdb_server_id_pull(uint8_t *buf, size_t buflen,
			 struct ctdb_server_id *sid);

size_t ctdb_g_lock_len(struct ctdb_g_lock *lock);
void ctdb_g_lock_push(struct ctdb_g_lock *lock, uint8_t *buf);
int ctdb_g_lock_pull(uint8_t *buf, size_t buflen, struct ctdb_g_lock *lock);

size_t ctdb_g_lock_list_len(struct ctdb_g_lock_list *lock_list);
void ctdb_g_lock_list_push(struct ctdb_g_lock_list *lock_list, uint8_t *buf);
int ctdb_g_lock_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_g_lock_list **out);

/* From protocol/protocol_header.c */

void ctdb_req_header_fill(struct ctdb_req_header *h, uint32_t generation,
			  uint32_t operation, uint32_t destnode,
			  uint32_t srcnode, uint32_t reqid);

int ctdb_req_header_pull(uint8_t *pkt, size_t pkt_len,
			 struct ctdb_req_header *h);

int ctdb_req_header_verify(struct ctdb_req_header *h, uint32_t operation);

/* From protocol/protocol_call.c */

int ctdb_req_call_push(struct ctdb_req_header *h,
		       struct ctdb_req_call *c,
		       TALLOC_CTX *mem_ctx,
		       uint8_t **pkt, size_t *pkt_len);

int ctdb_req_call_pull(uint8_t *pkt, size_t pkt_len,
		       struct ctdb_req_header *h,
		       TALLOC_CTX *mem_ctx,
		       struct ctdb_req_call *c);

int ctdb_reply_call_push(struct ctdb_req_header *h,
			 struct ctdb_reply_call *c,
			 TALLOC_CTX *mem_ctx,
			 uint8_t **pkt, size_t *pkt_len);

int ctdb_reply_call_pull(uint8_t *pkt, size_t pkt_len,
			 struct ctdb_req_header *h,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_reply_call *c);

int ctdb_reply_error_push(struct ctdb_req_header *h,
			  struct ctdb_reply_error *c,
			  TALLOC_CTX *mem_ctx,
			  uint8_t **pkt, size_t *pkt_len);

int ctdb_reply_error_pull(uint8_t *pkt, size_t pkt_len,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_reply_error *c);

int ctdb_req_dmaster_push(struct ctdb_req_header *h,
			  struct ctdb_req_dmaster *c,
			  TALLOC_CTX *mem_ctx,
			  uint8_t **pkt, size_t *pkt_len);

int ctdb_req_dmaster_pull(uint8_t *pkt, size_t pkt_len,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_dmaster *c);

int ctdb_reply_dmaster_push(struct ctdb_req_header *h,
			    struct ctdb_reply_dmaster *c,
			    TALLOC_CTX *mem_ctx,
			    uint8_t **pkt, size_t *pkt_len);

int ctdb_reply_dmaster_pull(uint8_t *pkt, size_t pkt_len,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_reply_dmaster *c);

/* From protocol/protocol_control.c */

int ctdb_req_control_push(struct ctdb_req_header *h,
			  struct ctdb_req_control *c,
			  TALLOC_CTX *mem_ctx,
			  uint8_t **pkt, size_t *pkt_len);

int ctdb_req_control_pull(uint8_t *pkt, size_t pkt_len,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_control *c);

int ctdb_reply_control_push(struct ctdb_req_header *h,
			    struct ctdb_reply_control *c,
			    TALLOC_CTX *mem_ctx,
			    uint8_t **pkt, size_t *pkt_len);

int ctdb_reply_control_pull(uint8_t *pkt, size_t pkt_len, uint32_t opcode,
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
				 uint32_t *debug_level);

void ctdb_req_control_set_debug(struct ctdb_req_control *request,
				uint32_t debug_level);
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
				const char *db_name, uint32_t tdb_flags);
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

void ctdb_req_control_thaw(struct ctdb_req_control *request,
			   uint32_t priority);
int ctdb_reply_control_thaw(struct ctdb_reply_control *reply);

void ctdb_req_control_get_pnn(struct ctdb_req_control *request);
int ctdb_reply_control_get_pnn(struct ctdb_reply_control *reply,
			       uint32_t *pnn);

void ctdb_req_control_shutdown(struct ctdb_req_control *request);
int ctdb_reply_control_shutdown(struct ctdb_reply_control *reply);

void ctdb_req_control_get_monmode(struct ctdb_req_control *request);
int ctdb_reply_control_get_monmode(struct ctdb_reply_control *reply,
				   int *mon_mode);

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

void ctdb_req_control_kill_tcp(struct ctdb_req_control *request,
			       struct ctdb_connection *conn);
int ctdb_reply_control_kill_tcp(struct ctdb_reply_control *reply);

void ctdb_req_control_get_tcp_tickle_list(struct ctdb_req_control *request,
					  ctdb_sock_addr *addr);
int ctdb_reply_control_get_tcp_tickle_list(struct ctdb_reply_control *reply,
					   TALLOC_CTX *mem_ctx,
					   struct ctdb_tickle_list **tickles);

void ctdb_req_control_set_tcp_tickle_list(struct ctdb_req_control *request,
					  struct ctdb_tickle_list *tickles);
int ctdb_reply_control_set_tcp_tickle_list(struct ctdb_reply_control *reply);

void ctdb_req_control_register_server_id(struct ctdb_req_control *request,
					 struct ctdb_client_id *sid);
int ctdb_reply_control_register_server_id(struct ctdb_reply_control *reply);

void ctdb_req_control_unregister_server_id(struct ctdb_req_control *request,
					   struct ctdb_client_id *sid);
int ctdb_reply_control_unregister_server_id(struct ctdb_reply_control *reply);

void ctdb_req_control_check_server_id(struct ctdb_req_control *request,
				      struct ctdb_client_id *sid);
int ctdb_reply_control_check_server_id(struct ctdb_reply_control *reply);

void ctdb_req_control_get_server_id_list(struct ctdb_req_control *request);
int ctdb_reply_control_get_server_id_list(struct ctdb_reply_control *reply,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_client_id_map **cid_map);

void ctdb_req_control_db_attach_persistent(struct ctdb_req_control *request,
					   const char *name,
					   uint32_t tdb_flags);
int ctdb_reply_control_db_attach_persistent(struct ctdb_reply_control *reply,
					    uint32_t *db_id);

void ctdb_req_control_update_record(struct ctdb_req_control *request,
				    struct ctdb_rec_buffer *recbuf);
int ctdb_reply_control_update_record(struct ctdb_reply_control *reply);

void ctdb_req_control_send_gratuitous_arp(struct ctdb_req_control *request,
					  struct ctdb_addr_info *addr_info);
int ctdb_reply_control_send_gratuitous_arp(struct ctdb_reply_control *reply);

void ctdb_req_control_transaction_start(struct ctdb_req_control *request,
					uint32_t tid);
int ctdb_reply_control_transaction_start(struct ctdb_reply_control *reply);

void ctdb_req_control_transaction_commit(struct ctdb_req_control *request,
					 uint32_t tid);
int ctdb_reply_control_transaction_commit(struct ctdb_reply_control *reply);

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

void ctdb_req_control_enable_monitor(struct ctdb_req_control *request);
int ctdb_reply_control_enable_monitor(struct ctdb_reply_control *reply);

void ctdb_req_control_disable_monitor(struct ctdb_req_control *request);
int ctdb_reply_control_disable_monitor(struct ctdb_reply_control *reply);

void ctdb_req_control_add_public_ip(struct ctdb_req_control *request,
				    struct ctdb_addr_info *addr_info);
int ctdb_reply_control_add_public_ip(struct ctdb_reply_control *reply);

void ctdb_req_control_del_public_ip(struct ctdb_req_control *request,
				    struct ctdb_addr_info *addr_info);
int ctdb_reply_control_del_public_ip(struct ctdb_reply_control *reply);

void ctdb_req_control_run_eventscripts(struct ctdb_req_control *request,
				       const char *event_str);
int ctdb_reply_control_run_eventscripts(struct ctdb_reply_control *reply);

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

void ctdb_req_control_get_public_ips(struct ctdb_req_control *request);
int ctdb_reply_control_get_public_ips(struct ctdb_reply_control *reply,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_public_ip_list **pubip_list);

void ctdb_req_control_get_nodemap(struct ctdb_req_control *request);
int ctdb_reply_control_get_nodemap(struct ctdb_reply_control *reply,
				   TALLOC_CTX *mem_ctx,
				   struct ctdb_node_map **nodemap);

void ctdb_req_control_get_event_script_status(struct ctdb_req_control *request,
					      uint32_t event);
int ctdb_reply_control_get_event_script_status(struct ctdb_reply_control *reply,
					       TALLOC_CTX *mem_ctx,
					       struct ctdb_script_list **script_list);

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

void ctdb_req_control_set_reclock_file(struct ctdb_req_control *request,
				       const char *reclock_file);
int ctdb_reply_control_set_reclock_file(struct ctdb_reply_control *reply);

void ctdb_req_control_stop_node(struct ctdb_req_control *request);
int ctdb_reply_control_stop_node(struct ctdb_reply_control *reply);

void ctdb_req_control_continue_node(struct ctdb_req_control *request);
int ctdb_reply_control_continue_node(struct ctdb_reply_control *reply);

void ctdb_req_control_set_natgwstate(struct ctdb_req_control *request,
				     uint32_t natgw_role);
int ctdb_reply_control_set_natgwstate(struct ctdb_reply_control *reply);

void ctdb_req_control_set_lmasterrole(struct ctdb_req_control *request,
				      uint32_t lmaster_role);
int ctdb_reply_control_set_lmasterrole(struct ctdb_reply_control *reply);

void ctdb_req_control_set_recmasterrole(struct ctdb_req_control *request,
					uint32_t recmaster_role);
int ctdb_reply_control_set_recmasterrole(struct ctdb_reply_control *reply);

void ctdb_req_control_enable_script(struct ctdb_req_control *request,
				    const char *script);
int ctdb_reply_control_enable_script(struct ctdb_reply_control *reply);

void ctdb_req_control_disable_script(struct ctdb_req_control *request,
				     const char *script);
int ctdb_reply_control_disable_script(struct ctdb_reply_control *reply);

void ctdb_req_control_set_ban_state(struct ctdb_req_control *request,
				    struct ctdb_ban_state *ban_state);
int ctdb_reply_control_set_ban_state(struct ctdb_reply_control *reply);

void ctdb_req_control_get_ban_state(struct ctdb_req_control *request);
int ctdb_reply_control_get_ban_state(struct ctdb_reply_control *reply,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_ban_state **ban_state);

void ctdb_req_control_set_db_priority(struct ctdb_req_control *request,
				      struct ctdb_db_priority *db_prio);
int ctdb_reply_control_set_db_priority(struct ctdb_reply_control *reply);

void ctdb_req_control_get_db_priority(struct ctdb_req_control *request,
				      uint32_t db_id);
int ctdb_reply_control_get_db_priority(struct ctdb_reply_control *reply,
				       uint32_t *priority);

void ctdb_req_control_transaction_cancel(struct ctdb_req_control *request,
					 uint32_t tid);
int ctdb_reply_control_transaction_cancel(struct ctdb_reply_control *reply);

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

void ctdb_req_control_check_srvids(struct ctdb_req_control *request,
				   struct ctdb_uint64_array *u64_array);
int ctdb_reply_control_check_srvids(struct ctdb_reply_control *reply,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_uint8_array **u8_array);

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

void ctdb_req_control_receive_records(struct ctdb_req_control *request,
				      struct ctdb_rec_buffer *recbuf);
int ctdb_reply_control_receive_records(struct ctdb_reply_control *reply,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_rec_buffer **recbuf);

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

/* From protocol/protocol_message.c */

int ctdb_req_message_push(struct ctdb_req_header *h,
			  struct ctdb_req_message *c,
			  TALLOC_CTX *mem_ctx,
			  uint8_t **pkt, size_t *pkt_len);

int ctdb_req_message_pull(uint8_t *pkt, size_t pkt_len,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_message *c);

int ctdb_req_message_data_push(struct ctdb_req_header *h,
			       struct ctdb_req_message_data *message,
			       TALLOC_CTX *mem_ctx,
			       uint8_t **pkt, size_t *pkt_len);

int ctdb_req_message_data_pull(uint8_t *pkt, size_t pkt_len,
			       struct ctdb_req_header *h,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_req_message_data *message);

/* From protocol/protocol_util.c */

const char *ctdb_runstate_to_string(enum ctdb_runstate runstate);
enum ctdb_runstate ctdb_runstate_from_string(const char *runstate_str);

const char *ctdb_event_to_string(enum ctdb_event event);
enum ctdb_event ctdb_event_from_string(const char *event_str);

const char *ctdb_sock_addr_to_string(TALLOC_CTX *mem_ctx, ctdb_sock_addr *addr);

#endif /* __CTDB_PROTOCOL_API_H__ */
