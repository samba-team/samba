/*
   CTDB client code - sync api

   Copyright (C) Amitay Isaacs  2017

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

#ifndef __CTDB_CLIENT_SYNC_H__
#define __CTDB_CLIENT_SYNC_H__

#include <talloc.h>
#include <tevent.h>

/* from client/client_control_sync.c */

int ctdb_ctrl_process_exists(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     pid_t pid, int *status);

int ctdb_ctrl_statistics(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 struct ctdb_statistics **stats);

int ctdb_ctrl_ping(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		   struct ctdb_client_context *client,
		   int destnode, struct timeval timeout,
		   int *num_clients);

int ctdb_ctrl_getdbpath(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			uint32_t db_id, const char **db_path);

int ctdb_ctrl_getvnnmap(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			struct ctdb_vnn_map **vnnmap);

int ctdb_ctrl_getdebug(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct ctdb_client_context *client,
		       int destnode, struct timeval timeout,
		       int *loglevel);

int ctdb_ctrl_setdebug(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct ctdb_client_context *client,
		       int destnode, struct timeval timeout,
		       int loglevel);

int ctdb_ctrl_get_dbmap(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			struct ctdb_dbid_map **dbmap);

int ctdb_ctrl_pull_db(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client, int destnode,
		      struct timeval timeout, struct ctdb_pulldb *pulldb,
		      struct ctdb_rec_buffer **recbuf);

int ctdb_ctrl_push_db(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client, int destnode,
		      struct timeval timeout, struct ctdb_rec_buffer *recbuf);

int ctdb_ctrl_get_recmode(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  int *recmode);

int ctdb_ctrl_set_recmode(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  int recmode);

int ctdb_ctrl_statistics_reset(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout);

int ctdb_ctrl_db_attach(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			const char *db_name, uint32_t *db_id);

int ctdb_ctrl_traverse_start(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     struct ctdb_traverse_start *traverse);

int ctdb_ctrl_register_srvid(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     uint64_t srvid);

int ctdb_ctrl_deregister_srvid(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       uint64_t srvid);

int ctdb_ctrl_get_dbname(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 uint32_t db_id, const char **db_name);

int ctdb_ctrl_enable_seqnum(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id);

int ctdb_ctrl_update_seqnum(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id);

int ctdb_ctrl_dump_memory(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  const char **mem_str);

int ctdb_ctrl_get_pid(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout,
		      pid_t *pid);

int ctdb_ctrl_get_recmaster(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t *recmaster);

int ctdb_ctrl_set_recmaster(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t recmaster);

int ctdb_ctrl_freeze(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     struct ctdb_client_context *client,
		     int destnode, struct timeval timeout,
		     int priority);

int ctdb_ctrl_get_pnn(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout,
		      uint32_t *pnn);

int ctdb_ctrl_shutdown(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct ctdb_client_context *client,
		       int destnode, struct timeval timeout);

int ctdb_ctrl_tcp_add(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout,
		      struct ctdb_connection *conn);

int ctdb_ctrl_tcp_remove(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 struct ctdb_connection *conn);

int ctdb_ctrl_set_tunable(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  struct ctdb_tunable *tunable);

int ctdb_ctrl_get_tunable(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  const char *var, uint32_t *value);

int ctdb_ctrl_list_tunables(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_var_list **var_list);

int ctdb_ctrl_modify_flags(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   int destnode, struct timeval timeout,
			   uint32_t pnn, uint32_t old_flags,
			   uint32_t new_flags);

int ctdb_ctrl_get_all_tunables(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       struct ctdb_tunable_list **tun_list);

int ctdb_ctrl_get_tcp_tickle_list(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct ctdb_client_context *client,
				  int destnode, struct timeval timeout,
				  ctdb_sock_addr *addr,
				  struct ctdb_tickle_list **tickles);

int ctdb_ctrl_set_tcp_tickle_list(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct ctdb_client_context *client,
				  int destnode, struct timeval timeout,
				  struct ctdb_tickle_list *tickles);

int ctdb_ctrl_db_attach_persistent(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct ctdb_client_context *client,
				   int destnode, struct timeval timeout,
				   const char *db_name, uint32_t *db_id);

int ctdb_ctrl_send_gratuitous_arp(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct ctdb_client_context *client,
				  int destnode, struct timeval timeout,
				  struct ctdb_addr_info *addr_info);

int ctdb_ctrl_wipe_database(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id, uint32_t tid);

int ctdb_ctrl_uptime(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     struct ctdb_client_context *client,
		     int destnode, struct timeval timeout,
		     struct ctdb_uptime **uptime);

int ctdb_ctrl_start_recovery(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout);

int ctdb_ctrl_end_recovery(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   int destnode, struct timeval timeout);

int ctdb_ctrl_reload_nodes_file(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout);

int ctdb_ctrl_add_public_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_addr_info *addr_info);

int ctdb_ctrl_del_public_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_addr_info *addr_info);

int ctdb_ctrl_get_capabilities(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       uint32_t *caps);

int ctdb_ctrl_release_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 struct ctdb_public_ip *pubip);

int ctdb_ctrl_takeover_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  struct ctdb_public_ip *pubip);

int ctdb_ctrl_get_public_ips(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     bool available_only,
			     struct ctdb_public_ip_list **pubip_list);

int ctdb_ctrl_get_nodemap(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  struct ctdb_node_map **nodemap);

int ctdb_ctrl_traverse_kill(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_traverse_start *traverse);

int ctdb_ctrl_get_reclock_file(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       const char **reclock_file);

int ctdb_ctrl_stop_node(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout);

int ctdb_ctrl_continue_node(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout);

int ctdb_ctrl_set_lmasterrole(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      uint32_t lmaster_role);

int ctdb_ctrl_set_recmasterrole(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout,
				uint32_t recmaster_role);

int ctdb_ctrl_set_ban_state(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_ban_state *ban_state);

int ctdb_ctrl_get_ban_state(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_ban_state **ban_state);

int ctdb_ctrl_register_notify(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      struct ctdb_notify_data *notify);

int ctdb_ctrl_deregister_notify(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout,
				uint64_t srvid);

int ctdb_ctrl_trans3_commit(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_rec_buffer *recbuf);

int ctdb_ctrl_get_db_seqnum(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id, uint64_t *seqnum);

int ctdb_ctrl_db_set_healthy(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     uint32_t db_id);

int ctdb_ctrl_db_get_health(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id, const char **reason);

int ctdb_ctrl_get_public_ip_info(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct ctdb_client_context *client,
				 int destnode, struct timeval timeout,
				 ctdb_sock_addr *addr,
				 struct ctdb_public_ip_info **ipinfo);

int ctdb_ctrl_get_ifaces(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int destnode, struct timeval timeout,
			 struct ctdb_iface_list **iface_list);

int ctdb_ctrl_set_iface_link_state(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct ctdb_client_context *client,
				   int destnode, struct timeval timeout,
				   struct ctdb_iface *iface);

int ctdb_ctrl_tcp_add_delayed_update(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct ctdb_client_context *client,
				     int destnode, struct timeval timeout,
				     struct ctdb_connection *conn);

int ctdb_ctrl_get_stat_history(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       struct ctdb_statistics_list **stats_list);

int ctdb_ctrl_schedule_for_deletion(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    int destnode, struct timeval timeout,
				    struct ctdb_key_data *key);

int ctdb_ctrl_set_db_readonly(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      uint32_t db_id);

int ctdb_ctrl_traverse_start_ext(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct ctdb_client_context *client,
				 int destnode, struct timeval timeout,
				 struct ctdb_traverse_start_ext *traverse);

int ctdb_ctrl_get_db_statistics(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout,
				uint32_t db_id,
				struct ctdb_db_statistics **dbstats);

int ctdb_ctrl_set_db_sticky(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id);

int ctdb_ctrl_reload_public_ips(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout);

int ctdb_ctrl_ipreallocated(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout);

int ctdb_ctrl_get_runstate(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   int destnode, struct timeval timeout,
			   enum ctdb_runstate *runstate);

int ctdb_ctrl_db_detach(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout,
			uint32_t db_id);

int ctdb_ctrl_get_nodes_file(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     struct ctdb_node_map **nodemap);

int ctdb_ctrl_db_freeze(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			int destnode, struct timeval timeout, uint32_t db_id);

int ctdb_ctrl_db_thaw(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout, uint32_t db_id);

int ctdb_ctrl_db_transaction_start(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct ctdb_client_context *client,
				   int destnode, struct timeval timeout,
				   struct ctdb_transdb *transdb);

int ctdb_ctrl_db_transaction_commit(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    int destnode, struct timeval timeout,
				    struct ctdb_transdb *transdb);

int ctdb_ctrl_db_transaction_cancel(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    int destnode, struct timeval timeout,
				    uint32_t db_id);

int ctdb_ctrl_db_pull(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client,
		      int destnode, struct timeval timeout,
		      struct ctdb_pulldb_ext *pulldb, uint32_t *num_records);

int ctdb_ctrl_db_push_start(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    struct ctdb_pulldb_ext *pulldb);

int ctdb_ctrl_db_push_confirm(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      uint32_t db_id, uint32_t *num_records);

int ctdb_ctrl_db_open_flags(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    uint32_t db_id, int *tdb_flags);

int ctdb_ctrl_db_attach_replicated(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct ctdb_client_context *client,
				   int destnode, struct timeval timeout,
				   const char *db_name, uint32_t *db_id);

int ctdb_ctrl_check_pid_srvid(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      struct ctdb_pid_srvid *pid_srvid, int *status);

int ctdb_ctrl_tunnel_register(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct timeval timeout,
			      uint64_t tunnel_id);

int ctdb_ctrl_tunnel_deregister(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct timeval timeout,
				uint64_t tunnel_id);

int ctdb_ctrl_disable_node(TALLOC_CTX *mem_ctx,
			   struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   int destnode,
			   struct timeval timeout);

int ctdb_ctrl_enable_node(TALLOC_CTX *mem_ctx,
			  struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode,
			  struct timeval timeout);

/* from client/client_message_sync.c */

int ctdb_message_recd_update_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct ctdb_public_ip *pubip);

int ctdb_message_mem_dump(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct ctdb_srvid_message *msg);

int ctdb_message_reload_nodes(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode);

int ctdb_message_takeover_run(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct ctdb_srvid_message *msg);

int ctdb_message_rebalance_node(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, uint32_t pnn);

int ctdb_message_disable_takeover_runs(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_client_context *client,
				       int destnode,
				       struct ctdb_disable_message *disable);

int ctdb_message_disable_recoveries(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    int destnode,
				    struct ctdb_disable_message *disable);

int ctdb_message_disable_ip_check(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct ctdb_client_context *client,
				  int destnode, uint32_t timeout);

#endif /* __CTDB_CLIENT_SYNC_H__ */
