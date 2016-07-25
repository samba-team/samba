/*
   CTDB client code

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

#ifndef __CTDB_CLIENT_H__
#define __CTDB_CLIENT_H__

#include <talloc.h>
#include <tevent.h>

#include "protocol/protocol.h"
#include "common/srvid.h"

struct ctdb_client_context;
struct ctdb_db_context;
struct ctdb_record_handle;

typedef void (*ctdb_client_callback_func_t)(void *private_data);

/* from client/client_connect.c */

int ctdb_client_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     const char *sockpath, struct ctdb_client_context **ret);

void ctdb_client_set_disconnect_callback(struct ctdb_client_context *client,
					 ctdb_client_callback_func_t func,
					 void *private_data);

uint32_t ctdb_client_pnn(struct ctdb_client_context *client);

void ctdb_client_wait(struct tevent_context *ev, bool *done);

int ctdb_client_wait_timeout(struct tevent_context *ev, bool *done,
			     struct timeval timeout);

struct tevent_req *ctdb_recovery_wait_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client);

bool ctdb_recovery_wait_recv(struct tevent_req *req, int *perr);

bool ctdb_recovery_wait(struct tevent_context *ev,
			struct ctdb_client_context *client);

/* from client/client_call.c */

struct tevent_req *ctdb_client_call_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_req_call *request);

bool ctdb_client_call_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct ctdb_reply_call **reply, int *perr);


/* from client/client_message.c */

struct tevent_req *ctdb_client_message_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_client_context *client,
					    uint32_t destnode,
					    struct ctdb_req_message *message);

bool ctdb_client_message_recv(struct tevent_req *req, int *perr);

struct tevent_req *ctdb_client_message_multi_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t *pnn_list, int count,
				struct ctdb_req_message *message);

bool ctdb_client_message_multi_recv(struct tevent_req *req, int *perr,
				    TALLOC_CTX *mem_ctx, int **perr_list);

int ctdb_client_message(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t destnode, struct ctdb_req_message *message);

int ctdb_client_message_multi(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      uint32_t *pnn_list, int count,
			      struct ctdb_req_message *message,
			      int **perr_list);

struct tevent_req *ctdb_client_set_message_handler_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint64_t srvid,
					srvid_handler_fn handler,
					void *private_data);
bool ctdb_client_set_message_handler_recv(struct tevent_req *req, int *perr);

struct tevent_req *ctdb_client_remove_message_handler_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint64_t srvid,
					void *private_data);
bool ctdb_client_remove_message_handler_recv(struct tevent_req *req,
					     int *perr);

int ctdb_client_set_message_handler(struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    uint64_t srvid, srvid_handler_fn handler,
				    void *private_data);

int ctdb_client_remove_message_handler(struct tevent_context *ev,
				       struct ctdb_client_context *client,
				       uint64_t srvid, void *private_data);

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

/* from client/client_control.c */

struct tevent_req *ctdb_client_control_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_client_context *client,
					    uint32_t destnode,
					    struct timeval timeout,
					    struct ctdb_req_control *request);

bool ctdb_client_control_recv(struct tevent_req *req, int *perr,
			      TALLOC_CTX *mem_ctx,
			      struct ctdb_reply_control **preply);

struct tevent_req *ctdb_client_control_multi_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t *pnn_list, int count,
				struct timeval timeout,
				struct ctdb_req_control *request);

bool ctdb_client_control_multi_recv(struct tevent_req *req, int *perr,
				    TALLOC_CTX *mem_ctx, int **perr_list,
				    struct ctdb_reply_control ***preply);

int ctdb_client_control_multi_error(uint32_t *pnn_list, int count,
				    int *err_list, uint32_t *pnn);

int ctdb_client_control(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t destnode,
			struct timeval timeout,
			struct ctdb_req_control *c,
			struct ctdb_reply_control **preply);

int ctdb_client_control_multi(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      uint32_t *pnn_list, int count,
			      struct timeval timeout,
			      struct ctdb_req_control *request,
			      int **perr,
			      struct ctdb_reply_control ***preply);

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
		       uint32_t *loglevel);

int ctdb_ctrl_setdebug(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct ctdb_client_context *client,
		       int destnode, struct timeval timeout,
		       uint32_t loglevel);

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
			const char *db_name, uint32_t tdb_flags,
			uint32_t *db_id);

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

int ctdb_ctrl_get_monmode(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  int *mon_mode);

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
				   const char *db_name, int tdb_flags,
				   uint32_t *db_id);

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

int ctdb_ctrl_enable_monitor(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout);

int ctdb_ctrl_disable_monitor(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
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

int ctdb_ctrl_run_eventscripts(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct ctdb_client_context *client,
			       int destnode, struct timeval timeout,
			       const char *event);

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
			     struct ctdb_public_ip_list **pubip_list);

int ctdb_ctrl_get_nodemap(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct timeval timeout,
			  struct ctdb_node_map **nodemap);

int ctdb_ctrl_get_event_script_status(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct ctdb_client_context *client,
				      int destnode, struct timeval timeout,
				      enum ctdb_event event,
				      struct ctdb_script_list **slist);

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

int ctdb_ctrl_enable_script(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			    struct ctdb_client_context *client,
			    int destnode, struct timeval timeout,
			    const char *script);

int ctdb_ctrl_disable_script(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     struct ctdb_client_context *client,
			     int destnode, struct timeval timeout,
			     const char *script);

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

int ctdb_ctrl_check_srvids(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   int destnode, struct timeval timeout,
			   uint64_t *srvid, int count, uint8_t **result);

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

/* from client/client_db.c */

struct tevent_req *ctdb_attach_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    struct timeval timeout,
				    const char *db_name, uint8_t db_flags);

bool ctdb_attach_recv(struct tevent_req *req, int *perr,
		      struct ctdb_db_context **out);

int ctdb_attach(struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout,
		const char *db_name, uint8_t db_flags,
		struct ctdb_db_context **out);

int ctdb_detach(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout, uint32_t db_id);

uint32_t ctdb_db_id(struct ctdb_db_context *db);

int ctdb_db_traverse(struct ctdb_db_context *db, bool readonly,
		     bool extract_header,
		     ctdb_rec_parser_func_t parser, void *private_data);

int ctdb_ltdb_fetch(struct ctdb_db_context *db, TDB_DATA key,
		    struct ctdb_ltdb_header *header,
		    TALLOC_CTX *mem_ctx, TDB_DATA *data);

struct tevent_req *ctdb_fetch_lock_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					struct ctdb_db_context *db,
					TDB_DATA key, bool readonly);

struct ctdb_record_handle *ctdb_fetch_lock_recv(struct tevent_req *req,
						struct ctdb_ltdb_header *header,
						TALLOC_CTX *mem_ctx,
						TDB_DATA *data, int *perr);

int ctdb_fetch_lock(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		    struct ctdb_client_context *client,
		    struct ctdb_db_context *db, TDB_DATA key, bool readonly,
		    struct ctdb_record_handle **out,
		    struct ctdb_ltdb_header *header, TDB_DATA *data);

int ctdb_store_record(struct ctdb_record_handle *h, TDB_DATA data);

struct tevent_req *ctdb_delete_record_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_record_handle *h);

bool ctdb_delete_record_recv(struct tevent_req *req, int *perr);

int ctdb_delete_record(struct ctdb_record_handle *h);

struct tevent_req *ctdb_g_lock_lock_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_db_context *db,
					 const char *keyname,
					 struct ctdb_server_id *sid,
					 bool readonly);

bool ctdb_g_lock_lock_recv(struct tevent_req *req, int *perr);

struct tevent_req *ctdb_g_lock_unlock_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client,
					   struct ctdb_db_context *db,
					   const char *keyname,
					   struct ctdb_server_id sid);

bool ctdb_g_lock_unlock_recv(struct tevent_req *req, int *perr);

struct tevent_req *ctdb_transaction_start_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct ctdb_client_context *client,
					       struct timeval timeout,
					       struct ctdb_db_context *db,
					       bool readonly);

struct ctdb_transaction_handle *ctdb_transaction_start_recv(
					struct tevent_req *req,
					int *perr);

int ctdb_transaction_start(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   struct timeval timeout,
			   struct ctdb_db_context *db, bool readonly,
			   struct ctdb_transaction_handle **out);

int ctdb_transaction_fetch_record(struct ctdb_transaction_handle *h,
				  TDB_DATA key,
				  TALLOC_CTX *mem_ctx, TDB_DATA *data);

int ctdb_transaction_store_record(struct ctdb_transaction_handle *h,
				  TDB_DATA key, TDB_DATA data);

int ctdb_transaction_delete_record(struct ctdb_transaction_handle *h,
				   TDB_DATA key);

struct tevent_req *ctdb_transaction_commit_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct timeval timeout,
					struct ctdb_transaction_handle *h);

bool ctdb_transaction_commit_recv(struct tevent_req *req, int *perr);

int ctdb_transaction_commit(struct ctdb_transaction_handle *h);

struct tevent_req *ctdb_transaction_cancel_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct timeval timeout,
					struct ctdb_transaction_handle *h);

bool ctdb_transaction_cancel_recv(struct tevent_req *req, int *perr);

int ctdb_transaction_cancel(struct ctdb_transaction_handle *h);

/* from client/client_util.c */

int list_of_nodes(struct ctdb_node_map *nodemap,
		  uint32_t flags_mask, uint32_t exclude_pnn,
		  TALLOC_CTX *mem_ctx, uint32_t **pnn_list);

int list_of_active_nodes(struct ctdb_node_map *nodemap, uint32_t exclude_pnn,
			 TALLOC_CTX *mem_ctx, uint32_t **pnn_list);

int list_of_connected_nodes(struct ctdb_node_map *nodemap,
			    uint32_t exclude_pnn,
			    TALLOC_CTX *mem_ctx, uint32_t **pnn_list);

int ctdb_ctrl_modflags(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct ctdb_client_context *client,
		       uint32_t destnode, struct timeval timeout,
		       uint32_t set, uint32_t clear);

struct ctdb_server_id ctdb_client_get_server_id(
				struct ctdb_client_context *client,
				uint32_t task_id);

bool ctdb_server_id_equal(struct ctdb_server_id *sid1,
			  struct ctdb_server_id *sid2);

int ctdb_server_id_exists(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  struct ctdb_server_id *sid, bool *exists);

#endif /* __CTDB_CLIENT_H__ */
