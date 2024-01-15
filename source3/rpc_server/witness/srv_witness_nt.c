/*
 *  Unix SMB/CIFS implementation.
 *
 *  Copyright (C) 2012,2023 Stefan Metzmacher
 *  Copyright (C) 2015 Guenther Deschner
 *  Copyright (C) 2018 Samuel Cabrero
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "ctdbd_conn.h"
#include "ctdb/protocol/protocol.h"
#include "ctdb_srvids.h"
#include "messages.h"
#include "lib/messages_ctdb.h"
#include "lib/global_contexts.h"
#include "lib/util/util_tdb.h"
#include "lib/util/util_str_escape.h"
#include "source3/include/util_tdb.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "lib/dbwrap/dbwrap_open.h"
#include "lib/param/param.h"
#include "lib/util/tevent_werror.h"
#include "lib/tsocket/tsocket.h"
#include "librpc/rpc/dcesrv_core.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/auth.h"
#include "librpc/gen_ndr/ndr_witness.h"
#include "librpc/gen_ndr/ndr_witness_scompat.h"
#include "librpc/gen_ndr/ndr_rpcd_witness.h"
#include "rpc_server/rpc_server.h"

#define SWN_SERVICE_CONTEXT_HANDLE_REGISTRATION 0x01

struct swn_service_interface;
struct swn_service_registration;
struct swn_service_async_notify_state;

struct swn_service_globals {
	struct dcesrv_context *dce_ctx;
	struct db_context *dce_conn_register;

	const char *server_global_name;
	uint32_t local_vnn;

	struct {
		bool valid;
		uint64_t generation;
		struct swn_service_interface *list;
	} interfaces;

	struct {
		uint32_t unused_timeout_secs;
		struct swn_service_registration *list;
		struct db_context *db;
	} registrations;
};

struct swn_service_interface {
	struct swn_service_interface *prev, *next;

	const char *group_name;
	struct samba_sockaddr addr;
	enum witness_interfaceInfo_state state;
	bool local_iface;
	uint32_t current_vnn;
	uint64_t change_generation;
	uint64_t check_generation;
};

struct swn_service_registration {
	struct swn_service_registration *prev, *next;

	struct swn_service_globals *swn;

	struct {
		struct tevent_context *ev_ctx;
		struct messaging_context *msg_ctx;
		struct tevent_req *subreq;
	} msg;

	struct {
		struct policy_handle handle;
		void *ptr;
	} key;

	struct {
		enum witness_version version;
		const char *computer_name;
	} client;

	const char *net_name;
	const char *share_name;
	struct samba_sockaddr ip_address;

	struct {
		bool triggered;
		struct witness_notifyResponse *response;
		WERROR result;
	} forced_response;

	struct {
		bool triggered;
		/*
		 * We only do ip based RESOURCE_CHANGE notifications for now
		 * and it means we do just one notification at a time
		 * and don't need to queue pending notifications.
		 */
		enum witness_interfaceInfo_state last_ip_state;
	} change_notification;

	struct {
		bool triggered;
		uint32_t new_node;
		struct samba_sockaddr new_ip;
	} move_notification;

	struct {
		bool required;
		bool triggered;
		uint32_t new_node;
		struct samba_sockaddr new_ip;
	} share_notification;

	struct {
		bool required;
		bool triggered;
		/*
		 * TODO: find how this works on windows and implement
		 * Windows Server 2022 as client doesn't use it...
		 */
	} ip_notification;

	struct {
		struct timeval create_time;
		struct timeval last_time;
		uint32_t unused_timeout_secs;
		struct timeval expire_time;
		struct tevent_timer *timer;
	} usage;

	struct {
		/*
		 * In order to let a Windows server 2022
		 * correctly re-register after moving
		 * to a new connection, we force an
		 * unregistration after 5 seconds.
		 *
		 * It means the client gets WERR_NOT_FOUND
		 * from a pending AsyncNotify() and calls
		 * Unregister() (which also gets WERR_NOT_FOUND).
		 * Then the client calls GetInterfaceList()
		 * and RegisterEx() again.
		 */
		struct tevent_timer *timer;
	} forced_unregister;

	struct {
		uint32_t timeout_secs;
		struct tevent_queue *queue;
		struct swn_service_async_notify_state *list;
	} async_notify;
};

static struct swn_service_globals *swn_globals = NULL;

static int swn_service_globals_destructor(struct swn_service_globals *swn)
{
	SMB_ASSERT(swn == swn_globals);
	swn_globals = NULL;

	while (swn->registrations.list != NULL) {
		/*
		 * NO TALLOC_FREE() because of DLIST_REMOVE()
		 * in swn_service_registration_destructor()
		 */
		talloc_free(swn->registrations.list);
	}

	return 0;
}

static void swn_service_async_notify_reg_destroyed(struct swn_service_async_notify_state *state);

static int swn_service_registration_destructor(struct swn_service_registration *reg)
{
	struct swn_service_globals *swn = reg->swn;
	struct GUID_txt_buf key_buf;
	const char *key_str = GUID_buf_string(&reg->key.handle.uuid, &key_buf);
	DATA_BLOB key_blob = data_blob_string_const(key_str);
	TDB_DATA key = make_tdb_data(key_blob.data, key_blob.length);
	NTSTATUS status;

	tevent_queue_stop(reg->async_notify.queue);
	while (reg->async_notify.list != NULL) {
		swn_service_async_notify_reg_destroyed(reg->async_notify.list);
	}

	status = dbwrap_delete(reg->swn->registrations.db, key);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("rpcd_witness_registration: key '%s' delete - %s\n",
			    tdb_data_dbg(key),
			    nt_errstr(status));
	} else if (DEBUGLVL(DBGLVL_DEBUG)) {
		DBG_DEBUG("rpcd_witness_registration: key '%s' deleted\n",
			  tdb_data_dbg(key));
	}

	DLIST_REMOVE(swn->registrations.list, reg);
	reg->swn = NULL;

	/*
	 * make sure to drop the policy/context handle from
	 * the assoc_group
	 */
	TALLOC_FREE(reg->key.ptr);

	return 0;
}

static void swn_service_registration_update_usage(struct swn_service_registration *reg,
						  struct timeval now)
{
	uint64_t expire_timeout_secs = 0;
	uint64_t max_expire_timeout_secs = TIME_T_MAX;

	reg->usage.last_time = now;

	if (max_expire_timeout_secs > reg->usage.last_time.tv_sec) {
		max_expire_timeout_secs -= reg->usage.last_time.tv_sec;
	} else {
		/*
		 * This should never happen unless
		 * a 32 bit system hits its limit
		 */
		max_expire_timeout_secs = 0;
	}

	if (tevent_queue_length(reg->async_notify.queue) != 0) {
		expire_timeout_secs += reg->async_notify.timeout_secs;
	}

	expire_timeout_secs += reg->usage.unused_timeout_secs;
	expire_timeout_secs = MIN(expire_timeout_secs, max_expire_timeout_secs);

	reg->usage.expire_time = timeval_add(&reg->usage.last_time,
					     expire_timeout_secs, 0);

	if (expire_timeout_secs == 0) {
		/*
		 * No timer needed, witness v1
		 * or max_expire_timeout_secs = 0
		 */
		TALLOC_FREE(reg->usage.timer);
	}

	if (reg->usage.timer == NULL) {
		/* no timer to update */
		reg->usage.expire_time = (struct timeval) { .tv_sec = TIME_T_MAX, };
		return;
	}

	tevent_update_timer(reg->usage.timer, reg->usage.expire_time);
}

static void swn_service_registration_unused(struct tevent_context *ev,
					    struct tevent_timer *te,
					    struct timeval current_time,
					    void *private_data)
{
	struct swn_service_registration *reg =
		talloc_get_type_abort(private_data,
		struct swn_service_registration);

	reg->usage.timer = NULL;

	TALLOC_FREE(reg);
}

static void swn_service_registration_force_unregister(struct tevent_context *ev,
						      struct tevent_timer *te,
						      struct timeval current_time,
						      void *private_data)
{
	struct swn_service_registration *reg =
		talloc_get_type_abort(private_data,
		struct swn_service_registration);

	reg->forced_unregister.timer = NULL;

	TALLOC_FREE(reg);
}

static int swn_service_ctdb_ipreallocated(struct tevent_context *ev,
					  uint32_t src_vnn, uint32_t dst_vnn,
					  uint64_t dst_srvid,
					  const uint8_t *msg, size_t msglen,
					  void *private_data);

static NTSTATUS swn_service_init_globals(struct dcesrv_context *dce_ctx)
{
	struct swn_service_globals *swn = NULL;
	char *global_path = NULL;
	int ret;

	if (swn_globals != NULL) {
		SMB_ASSERT(swn_globals->dce_ctx == dce_ctx);
		return NT_STATUS_OK;
	}

	swn = talloc_zero(dce_ctx, struct swn_service_globals);
	if (swn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	swn->dce_ctx = dce_ctx;

	swn->dce_conn_register = db_open_rbt(swn);
	if (swn->dce_conn_register == NULL) {
		TALLOC_FREE(swn);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * This contains secret information like client keys!
	 */
	global_path = lock_path(swn, "rpcd_witness_registration.tdb");
	if (global_path == NULL) {
		TALLOC_FREE(swn);
		return NT_STATUS_NO_MEMORY;
	}

	swn->registrations.db = db_open(swn, global_path,
					0, /* hash_size */
					TDB_DEFAULT |
					TDB_CLEAR_IF_FIRST |
					TDB_INCOMPATIBLE_HASH,
					O_RDWR | O_CREAT, 0600,
					DBWRAP_LOCK_ORDER_1,
					DBWRAP_FLAG_NONE);
	if (swn->registrations.db == NULL) {
		NTSTATUS status;

		status = map_nt_error_from_unix_common(errno);
		TALLOC_FREE(swn);

		return status;
	}
	TALLOC_FREE(global_path);

	swn->server_global_name = lpcfg_dns_hostname(dce_ctx->lp_ctx);
	if (swn->server_global_name == NULL) {
		TALLOC_FREE(swn);
		return NT_STATUS_NO_MEMORY;
	}
	swn->local_vnn = get_my_vnn();

	ret = register_with_ctdbd(messaging_ctdb_connection(),
				  CTDB_SRVID_IPREALLOCATED,
				  swn_service_ctdb_ipreallocated,
				  swn);
	if (ret != 0) {
		TALLOC_FREE(swn);
		return NT_STATUS_INTERNAL_ERROR;
	}

	swn->registrations.unused_timeout_secs = 30;

	talloc_set_destructor(swn, swn_service_globals_destructor);
	swn_globals = swn;
	return NT_STATUS_OK;
}

static struct swn_service_interface *swn_service_interface_by_addr(
					struct swn_service_globals *swn,
					const struct samba_sockaddr *addr)
{
	struct swn_service_interface *iface = NULL;

	for (iface = swn->interfaces.list; iface != NULL; iface = iface->next) {
		bool ok;

		ok = sockaddr_equal(&iface->addr.u.sa, &addr->u.sa);
		if (ok) {
			return iface;
		}
	}

	return NULL;
}

static void swn_service_interface_changed(struct swn_service_globals *swn,
					  struct swn_service_interface *iface)
{
	struct swn_service_registration *reg = NULL;
	char addr[INET6_ADDRSTRLEN] = { 0, };

	print_sockaddr(addr, sizeof(addr), &iface->addr.u.ss);
	DBG_NOTICE("addr[%s] state[%u] local_iface[%u] "
		   "current_vnn[%"PRIu32"] generation[%"PRIu64"][%"PRIu64"]\n",
		   addr,
		   iface->state,
		   iface->local_iface,
		   iface->current_vnn,
		   iface->change_generation,
		   iface->check_generation);

	for (reg = swn->registrations.list; reg != NULL; reg = reg->next) {
		bool match;

		/*
		 * We only check the ip address,
		 * we do not make real use of the group name.
		 */

		match = sockaddr_equal(&reg->ip_address.u.sa,
				       &iface->addr.u.sa);
		if (!match) {
			continue;
		}

		if (reg->change_notification.last_ip_state
		    != WITNESS_STATE_UNAVAILABLE)
		{
			/*
			 * Remember the current state unless we already
			 * hit WITNESS_STATE_UNAVAILABLE before we notified
			 * the client
			 */
			reg->change_notification.last_ip_state = iface->state;
		}

		reg->change_notification.triggered = true;

		tevent_queue_start(reg->async_notify.queue);
	}

	return;
}

static NTSTATUS swn_service_add_or_update_interface(struct swn_service_globals *swn,
					const char *group_name,
					const struct samba_sockaddr *addr,
					enum witness_interfaceInfo_state state,
					bool local_iface,
					uint32_t current_vnn)
{
	struct swn_service_interface *iface = NULL;
	bool changed = false;
	bool force_unavailable = false;
	bool filter;

	if (addr->u.sa.sa_family != AF_INET &&
	    addr->u.sa.sa_family != AF_INET6)
	{
		/*
		 * We only support ipv4 and ipv6
		 */
		return NT_STATUS_OK;
	}

	filter = is_loopback_addr(&addr->u.sa);
	if (filter) {
		return NT_STATUS_OK;
	}
	filter = is_linklocal_addr(&addr->u.ss);
	if (filter) {
		return NT_STATUS_OK;
	}

	for (iface = swn->interfaces.list; iface != NULL; iface = iface->next) {
		bool match;

		match = strequal(group_name, iface->group_name);
		if (!match) {
			continue;
		}

		match = sockaddr_equal(&addr->u.sa, &iface->addr.u.sa);
		if (!match) {
			continue;
		}

		break;
	}

	if (iface == NULL) {
		iface = talloc_zero(swn, struct swn_service_interface);
		if (iface == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		iface->group_name = talloc_strdup(iface, group_name);
		if (iface->group_name == NULL) {
			TALLOC_FREE(iface);
			return NT_STATUS_NO_MEMORY;
		}

		iface->addr = *addr;

		iface->state = WITNESS_STATE_UNKNOWN;
		iface->current_vnn = NONCLUSTER_VNN;
		DLIST_ADD_END(swn->interfaces.list, iface);

		iface->change_generation = swn->interfaces.generation;
	}

	if (iface->state != state) {
		changed = true;
		iface->state = state;
	}

	if (iface->current_vnn != current_vnn) {
		changed = true;
		if (iface->current_vnn != NONCLUSTER_VNN) {
			force_unavailable = true;
		}
		iface->current_vnn = current_vnn;
	}

	if (iface->local_iface != local_iface) {
		changed = true;
		force_unavailable = true;
		iface->local_iface = local_iface;
	}

	iface->check_generation = swn->interfaces.generation;

	if (!changed) {
		return NT_STATUS_OK;
	}

	iface->change_generation = swn->interfaces.generation;

	if (force_unavailable) {
		iface->state = WITNESS_STATE_UNAVAILABLE;
	}

	swn_service_interface_changed(swn, iface);

	if (force_unavailable) {
		iface->state = state;
	}

	return NT_STATUS_OK;
};

static int swn_service_ctdb_all_ip_cb(uint32_t total_ip_count,
				      const struct sockaddr_storage *ip,
				      uint32_t pinned_vnn,
				      uint32_t current_vnn,
				      void *private_data)
{
	struct swn_service_globals *swn =
		talloc_get_type_abort(private_data,
		struct swn_service_globals);
	enum witness_interfaceInfo_state state = WITNESS_STATE_UNKNOWN;
	struct samba_sockaddr addr = {
		.u = {
			.ss = *ip,
		},
	};
	NTSTATUS status;
	bool local_iface = false;

	SMB_ASSERT(swn->local_vnn != NONCLUSTER_VNN);

	if (current_vnn == NONCLUSTER_VNN) {
		/*
		 * No node hosts this address
		 */
		state = WITNESS_STATE_UNAVAILABLE;
	} else {
		state = WITNESS_STATE_AVAILABLE;
	}

	if (current_vnn == swn->local_vnn || pinned_vnn == swn->local_vnn) {
		local_iface = true;
	}

	status = swn_service_add_or_update_interface(swn,
						     swn->server_global_name,
						     &addr,
						     state,
						     local_iface,
						     current_vnn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("swn_service_add_or_update_interface() failed: %s\n",
			nt_errstr(status));
		return map_errno_from_nt_status(status);
	}

	return 0;
}

static NTSTATUS swn_service_reload_interfaces(struct dcesrv_context *dce_ctx)
{
	struct swn_service_interface *iface = NULL;
	struct swn_service_interface *next = NULL;
	bool include_node_ips = false;
	bool include_public_ips = true;
	int ret;
	NTSTATUS status;

	status = swn_service_init_globals(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (swn_globals->interfaces.valid) {
		return NT_STATUS_OK;
	}

	swn_globals->interfaces.generation += 1;

	include_node_ips = lpcfg_parm_bool(dce_ctx->lp_ctx,
					   NULL,
					   "rpcd witness",
					   "include node ips",
					   include_node_ips);
	include_public_ips = lpcfg_parm_bool(dce_ctx->lp_ctx,
					     NULL,
					     "rpcd witness",
					     "include public ips",
					     include_public_ips);

	ret = ctdbd_all_ip_foreach(messaging_ctdb_connection(),
				   include_node_ips,
				   include_public_ips,
				   swn_service_ctdb_all_ip_cb,
				   swn_globals);
	if (ret != 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (iface = swn_globals->interfaces.list; iface != NULL; iface = next) {
		next = iface->next;

		if (iface->check_generation == swn_globals->interfaces.generation) {
			continue;
		}

		status = swn_service_add_or_update_interface(swn_globals,
							     iface->group_name,
							     &iface->addr,
							     WITNESS_STATE_UNAVAILABLE,
							     iface->local_iface,
							     iface->current_vnn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		DLIST_REMOVE(swn_globals->interfaces.list, iface);
		TALLOC_FREE(iface);
	}

	/* CTDB_SRVID_IPREALLOCATED is still registered */

	swn_globals->interfaces.valid = true;
	return NT_STATUS_OK;
}

static int swn_service_ctdb_ipreallocated(struct tevent_context *ev,
					  uint32_t src_vnn, uint32_t dst_vnn,
					  uint64_t dst_srvid,
					  const uint8_t *msg, size_t msglen,
					  void *private_data)
{
	struct swn_service_globals *swn =
		talloc_get_type_abort(private_data,
		struct swn_service_globals);
	NTSTATUS status;

	DBG_DEBUG("PID[%d] swn[%p] IPREALLOCATED\n", getpid(), swn);

	swn->interfaces.valid = false;
	status = swn_service_reload_interfaces(swn->dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		swn->interfaces.valid = false;
		return 0;
	}

	return 0;
}

struct swn_dcesrv_connection {
	struct db_context *rbt;
	struct dcesrv_connection *conn;
	struct samba_sockaddr cli_addr;
	struct samba_sockaddr srv_addr;
	char addr[INET6_ADDRSTRLEN];
};

static int swn_dcesrv_connection_release_ip(struct tevent_context *ev,
					    uint32_t src_vnn,
					    uint32_t dst_vnn,
					    uint64_t dst_srvid,
					    const uint8_t *msg,
					    size_t msglen,
					    void *private_data)
{
	struct swn_dcesrv_connection *sc =
		talloc_get_type_abort(private_data,
		struct swn_dcesrv_connection);
	struct dcesrv_connection *conn = sc->conn;
	const char *ip = NULL;
	const char *addr = sc->addr;
	const char *p = addr;

	if (conn->terminate != NULL) {
		/* avoid recursion */
		return 0;
	}

	if (msglen == 0) {
		return 0;
	}
	if (msg[msglen-1] != '\0') {
		return 0;
	}

	ip = (const char *)msg;

	if (strncmp("::ffff:", addr, 7) == 0) {
		p = addr + 7;
	}

	DBG_DEBUG("Got release IP message for %s, our address is %s\n", ip, p);

	if ((strcmp(p, ip) == 0) || ((p != addr) && strcmp(addr, ip) == 0)) {
		DBG_NOTICE("Got release IP message for our IP %s - exiting immediately\n",
			   ip);
		talloc_free(sc);
		dcesrv_terminate_connection(conn, "CTDB_SRVID_RELEASE_IP");
		return EADDRNOTAVAIL;
	}

	return 0;

}

static int swn_dcesrv_connection_destructor(struct swn_dcesrv_connection *sc)
{
	struct ctdbd_connection *cconn = messaging_ctdb_connection();
	struct dcesrv_connection *conn = sc->conn;
	uintptr_t conn_ptr = (uintptr_t)conn;
	NTSTATUS status;
	TDB_DATA key;

	key = make_tdb_data((uint8_t *)&conn_ptr, sizeof(conn_ptr));

	status = dbwrap_delete(sc->rbt, key);
	SMB_ASSERT(NT_STATUS_IS_OK(status));

	if (cconn == NULL) {
		return 0;
	}

	ctdbd_unregister_ips(cconn,
			     &sc->srv_addr.u.ss,
			     &sc->cli_addr.u.ss,
			     swn_dcesrv_connection_release_ip,
			     sc);

	return 0;
}

static NTSTATUS dcesrv_interface_witness_register_ips(struct dcesrv_connection *conn)
{
	struct ctdbd_connection *cconn = messaging_ctdb_connection();
	struct dcesrv_context *dce_ctx = conn->dce_ctx;
	const struct tsocket_address *client_address =
		dcesrv_connection_get_remote_address(conn);
	const struct tsocket_address *server_address =
		dcesrv_connection_get_local_address(conn);
	NTSTATUS status;
	uintptr_t conn_ptr = (uintptr_t)conn;
	struct swn_dcesrv_connection *sc = NULL;
	uintptr_t sc_ptr;
	const char *addr = NULL;
	TDB_DATA key;
	TDB_DATA val;
	bool exists;
	int ret;

	status = swn_service_init_globals(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("swn_service_init_globals() failed: %s\n",
			nt_errstr(status));
		return status;
	}

	key = make_tdb_data((uint8_t *)&conn_ptr, sizeof(conn_ptr));

	exists = dbwrap_exists(swn_globals->dce_conn_register, key);
	if (exists) {
		/* Already registered */
		return NT_STATUS_OK;
	}

	sc = talloc_zero(conn, struct swn_dcesrv_connection);
	if (sc == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	sc->rbt = swn_globals->dce_conn_register;
	sc->conn = conn;

	if (tsocket_address_is_inet(client_address, "ip")) {
		ssize_t sret;

		sret = tsocket_address_bsd_sockaddr(client_address,
						    &sc->cli_addr.u.sa,
						    sizeof(sc->cli_addr.u.ss));
		if (sret == -1) {
			TALLOC_FREE(sc);
			return NT_STATUS_INTERNAL_ERROR;
		}
		sc->cli_addr.sa_socklen = sret;
	}

	if (tsocket_address_is_inet(server_address, "ip")) {
		ssize_t sret;

		sret = tsocket_address_bsd_sockaddr(server_address,
						    &sc->srv_addr.u.sa,
						    sizeof(sc->srv_addr.u.ss));
		if (sret == -1) {
			TALLOC_FREE(sc);
			return NT_STATUS_INTERNAL_ERROR;
		}
		sc->srv_addr.sa_socklen = sret;
	}

	addr = print_sockaddr(sc->addr, sizeof(sc->addr), &sc->srv_addr.u.ss);
	if (addr == NULL) {
		TALLOC_FREE(sc);
		return NT_STATUS_NO_MEMORY;
	}

	sc_ptr = (uintptr_t)sc;
	val = make_tdb_data((uint8_t *)&sc_ptr, sizeof(sc_ptr));

	status = dbwrap_store(sc->rbt, key, val, TDB_INSERT);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sc);
		return status;
	}

	talloc_set_destructor(sc, swn_dcesrv_connection_destructor);


	ret = ctdbd_register_ips(cconn,
				 &sc->srv_addr.u.ss,
				 &sc->cli_addr.u.ss,
				 swn_dcesrv_connection_release_ip,
				 sc);
	if (ret != 0) {
		TALLOC_FREE(sc);
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}

#define DCESRV_INTERFACE_WITNESS_BIND(context, iface) \
	dcesrv_interface_witness_bind(context, iface)
static NTSTATUS dcesrv_interface_witness_bind(struct dcesrv_connection_context *context,
					      const struct dcesrv_interface *iface)
{
	NTSTATUS status;

	status = dcesrv_interface_witness_register_ips(context->conn);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * This is not really critical, so we just print
		 * as warning...
		 */
		DBG_WARNING("dcesrv_interface_witness_register_ips() failed: %s\n",
			    nt_errstr(status));
	}

	/*
	 * [MS-SWN] Section 7. If the authentication level is not
	 * integrity or privacy level, Windows servers will fail the call
	 * with access denied
	 */
	return dcesrv_interface_bind_require_integrity(context, iface);
}

/****************************************************************
 _witness_GetInterfaceList
****************************************************************/

WERROR _witness_GetInterfaceList(struct pipes_struct *p,
				 struct witness_GetInterfaceList *r)
{
	struct dcesrv_context *dce_ctx = p->dce_call->conn->dce_ctx;
	struct swn_service_interface *iface = NULL;
	struct witness_interfaceList *list = NULL;
	size_t num_interfaces = 0;
	NTSTATUS status;

	status = swn_service_reload_interfaces(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	for (iface = swn_globals->interfaces.list; iface != NULL; iface = iface->next) {
		num_interfaces += 1;
	}

	list = talloc_zero(p->mem_ctx, struct witness_interfaceList);
	if (list == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	list->interfaces = talloc_zero_array(list,
					     struct witness_interfaceInfo,
					     num_interfaces);
	if (list->interfaces == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	for (iface = swn_globals->interfaces.list; iface != NULL; iface = iface->next) {
		struct witness_interfaceInfo *info =
			&list->interfaces[list->num_interfaces++];
		char addr[INET6_ADDRSTRLEN] = { 0, };
		const char *ipv4 = "0.0.0.0";
		const char *ipv6 = "::";
		uint32_t flags = 0;

		print_sockaddr(addr, sizeof(addr), &iface->addr.u.ss);
		if (iface->addr.u.sa.sa_family == AF_INET) {
			flags |= WITNESS_INFO_IPv4_VALID;
			ipv4 = addr;
		} else if (iface->addr.u.sa.sa_family == AF_INET6) {
			flags |= WITNESS_INFO_IPv6_VALID;
			ipv6 = addr;
		}

		if (!iface->local_iface) {
			/*
			 * If it's not a local interface
			 * it is able to serve as
			 * witness server
			 */
			flags |= WITNESS_INFO_WITNESS_IF;
		}

		info->group_name = talloc_strdup(list, iface->group_name);
		if (info->group_name == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		info->version = WITNESS_V2; /* WitnessServiceVersion; */
		info->state = iface->state;
		info->ipv4 = talloc_strdup(list, ipv4);
		if (info->ipv4 == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		info->ipv6 = talloc_strdup(list, ipv6);
		if (info->ipv6 == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		info->flags = flags;
	}

	*r->out.interface_list = list;
	return WERR_OK;
}

static bool swn_server_registration_message_filter(struct messaging_rec *rec, void *private_data)
{
	struct swn_service_registration *reg = NULL;
	struct policy_handle context_handle;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	bool match;

	if (rec->msg_type != MSG_RPCD_WITNESS_REGISTRATION_UPDATE) {
		return false;
	}

	if (rec->num_fds != 0) {
		return false;
	}

	if (rec->buf.length < 20) {
		return false;
	}

	reg = talloc_get_type_abort(private_data, struct swn_service_registration);

	blob = data_blob_const(rec->buf.data, 20);
	ndr_err = ndr_pull_struct_blob_all_noalloc(&blob, &context_handle,
				(ndr_pull_flags_fn_t)ndr_pull_policy_handle);
	SMB_ASSERT(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

	match = ndr_policy_handle_equal(&context_handle, &reg->key.handle);
	if (!match) {
		return false;
	}

	return true;
}

static void swn_server_registration_client_move_to_node(
	struct swn_service_registration *reg,
	struct rpcd_witness_registration_update_move_to_node *move)
{
	reg->move_notification.triggered = true;
	reg->move_notification.new_node = move->new_node;
	reg->move_notification.new_ip = (struct samba_sockaddr) {
		.sa_socklen = 0,
	};

	tevent_queue_start(reg->async_notify.queue);
}

static void swn_server_registration_client_move_to_ip(
	struct swn_service_registration *reg,
	const char *new_ip_str)
{
	struct samba_sockaddr new_ip = {
		.sa_socklen = 0,
	};
	bool ok;

	ok = is_ipaddress(new_ip_str);
	if (!ok) {
		return;
	}
	ok = interpret_string_addr(&new_ip.u.ss,
				   new_ip_str,
				   AI_PASSIVE|AI_NUMERICHOST);
	if (!ok) {
		return;
	}

	reg->move_notification.triggered = true;
	reg->move_notification.new_node = NONCLUSTER_VNN;
	reg->move_notification.new_ip = new_ip;

	tevent_queue_start(reg->async_notify.queue);
}

static void swn_server_registration_client_move_to_ipv4(
	struct swn_service_registration *reg,
	struct rpcd_witness_registration_update_move_to_ipv4 *move)
{
	swn_server_registration_client_move_to_ip(reg, move->new_ipv4);
}

static void swn_server_registration_client_move_to_ipv6(
	struct swn_service_registration *reg,
	struct rpcd_witness_registration_update_move_to_ipv6 *move)
{
	swn_server_registration_client_move_to_ip(reg, move->new_ipv6);
}

static void swn_server_registration_share_move_to_node(
	struct swn_service_registration *reg,
	struct rpcd_witness_registration_update_move_to_node *move)
{
	if (!reg->share_notification.required) {
		return;
	}

	reg->share_notification.triggered = true;
	reg->share_notification.new_node = move->new_node;
	reg->share_notification.new_ip = (struct samba_sockaddr) {
		.sa_socklen = 0,
	};

	tevent_queue_start(reg->async_notify.queue);
}

static void swn_server_registration_share_move_to_ip(
	struct swn_service_registration *reg,
	const char *new_ip_str)
{
	struct samba_sockaddr new_ip = {
		.sa_socklen = 0,
	};
	bool ok;

	ok = is_ipaddress(new_ip_str);
	if (!ok) {
		return;
	}
	ok = interpret_string_addr(&new_ip.u.ss,
				   new_ip_str,
				   AI_PASSIVE|AI_NUMERICHOST);
	if (!ok) {
		return;
	}

	if (!reg->share_notification.required) {
		return;
	}

	reg->share_notification.triggered = true;
	reg->share_notification.new_node = NONCLUSTER_VNN;
	reg->share_notification.new_ip = new_ip;

	tevent_queue_start(reg->async_notify.queue);
}

static void swn_server_registration_share_move_to_ipv4(
	struct swn_service_registration *reg,
	struct rpcd_witness_registration_update_move_to_ipv4 *move)
{
	swn_server_registration_share_move_to_ip(reg, move->new_ipv4);
}

static void swn_server_registration_share_move_to_ipv6(
	struct swn_service_registration *reg,
	struct rpcd_witness_registration_update_move_to_ipv6 *move)
{
	swn_server_registration_share_move_to_ip(reg, move->new_ipv6);
}

static void swn_server_registration_force_response(
	struct swn_service_registration *reg,
	struct rpcd_witness_registration_update_force_response *response)
{
	reg->forced_response.triggered = true;
	reg->forced_response.response = talloc_move(reg, &response->response);
	reg->forced_response.result = response->result;

	tevent_queue_start(reg->async_notify.queue);
}

static void swn_server_registration_message_done(struct tevent_req *subreq)
{
	struct swn_service_registration *reg =
		tevent_req_callback_data(subreq,
		struct swn_service_registration);
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_rec *rec = NULL;
	struct rpcd_witness_registration_updateB update_blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	int ret;

	SMB_ASSERT(reg->msg.subreq == subreq);
	reg->msg.subreq = NULL;

	ret = messaging_filtered_read_recv(subreq, frame, &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(ret);
		DBG_ERR("messaging_filtered_read_recv() - %s\n",
			nt_errstr(status));
		goto wait_for_next;
	}

	DBG_DEBUG("MSG_RPCD_WITNESS_REGISTRATION_UPDATE: received...\n");

	ndr_err = ndr_pull_struct_blob(&rec->buf, frame, &update_blob,
			(ndr_pull_flags_fn_t)ndr_pull_rpcd_witness_registration_updateB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("ndr_pull_struct_blob - %s\n", nt_errstr(status));
		goto wait_for_next;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(rpcd_witness_registration_updateB, &update_blob);
	}

	switch (update_blob.type) {
	case RPCD_WITNESS_REGISTRATION_UPDATE_CLIENT_MOVE_TO_NODE:
		swn_server_registration_client_move_to_node(reg,
			&update_blob.update.client_move_to_node);
		break;
	case RPCD_WITNESS_REGISTRATION_UPDATE_CLIENT_MOVE_TO_IPV4:
		swn_server_registration_client_move_to_ipv4(reg,
			&update_blob.update.client_move_to_ipv4);
		break;
	case RPCD_WITNESS_REGISTRATION_UPDATE_CLIENT_MOVE_TO_IPV6:
		swn_server_registration_client_move_to_ipv6(reg,
			&update_blob.update.client_move_to_ipv6);
		break;
	case RPCD_WITNESS_REGISTRATION_UPDATE_SHARE_MOVE_TO_NODE:
		swn_server_registration_share_move_to_node(reg,
			&update_blob.update.share_move_to_node);
		break;
	case RPCD_WITNESS_REGISTRATION_UPDATE_SHARE_MOVE_TO_IPV4:
		swn_server_registration_share_move_to_ipv4(reg,
			&update_blob.update.share_move_to_ipv4);
		break;
	case RPCD_WITNESS_REGISTRATION_UPDATE_SHARE_MOVE_TO_IPV6:
		swn_server_registration_share_move_to_ipv6(reg,
			&update_blob.update.share_move_to_ipv6);
		break;
	case RPCD_WITNESS_REGISTRATION_UPDATE_FORCE_UNREGISTER:
		TALLOC_FREE(reg);
		TALLOC_FREE(frame);
		return;
	case RPCD_WITNESS_REGISTRATION_UPDATE_FORCE_RESPONSE:
		swn_server_registration_force_response(reg,
			&update_blob.update.force_response);
		break;
	}

wait_for_next:
	TALLOC_FREE(frame);
	reg->msg.subreq = messaging_filtered_read_send(reg,
						       reg->msg.ev_ctx,
						       reg->msg.msg_ctx,
						       swn_server_registration_message_filter,
						       reg);
	if (reg->msg.subreq == NULL) {
		DBG_ERR("messaging_filtered_read_send() failed\n");
		return;
	}
	tevent_req_set_callback(reg->msg.subreq,
				swn_server_registration_message_done,
				reg);
}

static WERROR swn_server_registration_create(struct swn_service_globals *swn,
					     struct pipes_struct *p,
					     const struct witness_RegisterEx *r,
					     const struct swn_service_interface *iface,
					     struct swn_service_registration **preg)
{
	struct swn_service_registration *reg = NULL;
	const struct tsocket_address *client_address =
		dcesrv_connection_get_remote_address(p->dce_call->conn);
	const struct tsocket_address *server_address =
		dcesrv_connection_get_local_address(p->dce_call->conn);
	struct auth_session_info *session_info =
		dcesrv_call_session_info(p->dce_call);
	struct rpcd_witness_registration rg = { .version = 0, };
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	struct GUID_txt_buf key_buf = {};
	const char *key_str = NULL;
	DATA_BLOB key_blob = { .length = 0, };
	TDB_DATA key = { .dsize = 0, };
	DATA_BLOB val_blob = { .length = 0, };
	TDB_DATA val = { .dsize = 0, };

	/*
	 * [MS-SWN] 3.1.4.5
	 * The server MUST create a WitnessRegistration entry as follows and
	 * insert it into the WitnessRegistrationList.
	 */
	reg = talloc_zero(p->mem_ctx, struct swn_service_registration);
	if (reg == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	reg->swn = swn;

	reg->client.version = r->in.version;

	/*
	 * all other string values are checked against
	 * well known expected values.
	 *
	 * So we better escape the client_computer_name
	 * if it contains strange things...
	 */
	reg->client.computer_name = log_escape(reg, r->in.client_computer_name);
	if (reg->client.computer_name == NULL) {
		TALLOC_FREE(reg);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	reg->net_name = talloc_strdup(reg, r->in.net_name);
	if (reg->net_name == NULL) {
		TALLOC_FREE(reg);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	reg->ip_address = iface->addr;

	if (r->in.share_name != NULL) {
		reg->share_name = talloc_strdup(reg, r->in.share_name);
		if (reg->share_name == NULL) {
			TALLOC_FREE(reg);
			return WERR_NOT_ENOUGH_MEMORY;
		}
		reg->share_notification.required = true;
	}

	reg->async_notify.timeout_secs = r->in.timeout;
	reg->async_notify.queue = tevent_queue_create(reg, "async_notify");
	if (reg->async_notify.queue == NULL) {
		TALLOC_FREE(reg);
		return WERR_NOT_ENOUGH_MEMORY;
	}
	tevent_queue_stop(reg->async_notify.queue);

	reg->ip_notification.required = (r->in.flags &
			WITNESS_REGISTER_IP_NOTIFICATION);

	reg->usage.create_time = p->dce_call->time;
	reg->usage.unused_timeout_secs =
		swn_globals->registrations.unused_timeout_secs;
	/*
	 * swn_service_registration_update_usage() below
	 * will update the timer to its real expire time!
	 */
	reg->usage.expire_time = (struct timeval) { .tv_sec = TIME_T_MAX, };
	reg->usage.timer = tevent_add_timer(p->dce_call->event_ctx,
					    reg,
					    reg->usage.expire_time,
					    swn_service_registration_unused,
					    reg);
	if (reg->usage.timer == NULL) {
		TALLOC_FREE(reg);
		return WERR_NOT_ENOUGH_MEMORY;
	}
	swn_service_registration_update_usage(reg, reg->usage.create_time);

	reg->msg.ev_ctx = p->dce_call->event_ctx;
	reg->msg.msg_ctx = p->msg_ctx;
	reg->msg.subreq = messaging_filtered_read_send(reg,
						       reg->msg.ev_ctx,
						       reg->msg.msg_ctx,
						       swn_server_registration_message_filter,
						       reg);
	if (reg->msg.subreq == NULL) {
		TALLOC_FREE(reg);
		return WERR_NOT_ENOUGH_MEMORY;
	}
	tevent_req_set_callback(reg->msg.subreq,
				swn_server_registration_message_done,
				reg);

	reg->key.ptr = create_policy_hnd(p, &reg->key.handle,
					 SWN_SERVICE_CONTEXT_HANDLE_REGISTRATION,
					 reg);
	if (reg->key.ptr == NULL) {
		TALLOC_FREE(reg);
		return WERR_NO_SYSTEM_RESOURCES;
	}

	DLIST_ADD_END(swn_globals->registrations.list, reg);
	talloc_set_destructor(reg, swn_service_registration_destructor);

	key_str = GUID_buf_string(&reg->key.handle.uuid, &key_buf);
	key_blob = data_blob_string_const(key_str);
	key = make_tdb_data(key_blob.data, key_blob.length);

	rg = (struct rpcd_witness_registration) {
		.version = r->in.version,
		.net_name = r->in.net_name,
		.share_name = r->in.share_name,
		.ip_address = r->in.ip_address,
		.client_computer_name = reg->client.computer_name,
		.flags = r->in.flags,
		.timeout = r->in.timeout,
		.context_handle = reg->key.handle,
		.server_id = messaging_server_id(p->msg_ctx),
		.account_name = session_info->info->account_name,
		.domain_name = session_info->info->domain_name,
		.account_sid = session_info->security_token->sids[PRIMARY_USER_SID_INDEX],
		.local_address = tsocket_address_string(server_address, p->mem_ctx),
		.remote_address = tsocket_address_string(client_address, p->mem_ctx),
		.registration_time = timeval_to_nttime(&p->dce_call->time),
	};

	ndr_err = ndr_push_struct_blob(&val_blob, p->mem_ctx, &rg,
			(ndr_push_flags_fn_t)ndr_push_rpcd_witness_registration);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("rpcd_witness_registration: key '%s' ndr_push - %s\n",
			 tdb_data_dbg(key),
			 nt_errstr(status));
		TALLOC_FREE(reg);
		return WERR_NO_SYSTEM_RESOURCES;
	}
	val = make_tdb_data(val_blob.data, val_blob.length);

	status = dbwrap_store(reg->swn->registrations.db, key, val, TDB_INSERT);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("rpcd_witness_registration: key '%s' store - %s\n",
			 tdb_data_dbg(key),
			 nt_errstr(status));
		TALLOC_FREE(reg);
		return WERR_NO_SYSTEM_RESOURCES;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		DBG_DEBUG("rpcd_witness_registration: key '%s' stored\n",
			  tdb_data_dbg(key));
		NDR_PRINT_DEBUG(rpcd_witness_registration, &rg);
	}

	*preg = reg;
	return WERR_OK;
}

static WERROR swn_server_check_net_name(struct swn_service_globals *swn,
					const char *net_name)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *stripped_net_name = NULL;
	char *p = NULL;
	bool ok;

	ok = strequal(swn->server_global_name, net_name);
	if (ok) {
		TALLOC_FREE(frame);
		return WERR_OK;
	}

	stripped_net_name = talloc_strdup(frame, net_name);
	if (stripped_net_name == NULL) {
		TALLOC_FREE(frame);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	p = strchr(stripped_net_name, '.');
	if (p != NULL) {
		*p = '\0';
	}

	ok = is_myname(stripped_net_name);
	if (ok) {
		TALLOC_FREE(frame);
		return WERR_OK;
	}

	TALLOC_FREE(frame);
	return WERR_INVALID_PARAMETER;
}

/****************************************************************
 _witness_Register
****************************************************************/

WERROR _witness_Register(struct pipes_struct *p,
			 struct witness_Register *r)
{
	struct dcesrv_context *dce_ctx = p->dce_call->conn->dce_ctx;
	struct swn_service_registration *reg = NULL;
	struct samba_sockaddr addr = { .sa_socklen = 0, };
	struct swn_service_interface *iface = NULL;
	const struct witness_RegisterEx rex = {
		.in = {
			.version = r->in.version,
			.net_name = r->in.net_name,
			.ip_address = r->in.ip_address,
			.client_computer_name = r->in.client_computer_name,
		},
	};
	NTSTATUS status;
	WERROR werr;
	bool ok;

	/*
	 * [MS-SWN] 3.1.4.2
	 * If the Version field of the request is not 0x00010001, the server
	 * MUST stop processing the request and return the error code
	 * ERROR_REVISION_MISMATCH
	 */
	if (r->in.version != WITNESS_V1) {
		return WERR_REVISION_MISMATCH;
	}

	/*
	 * [MS-SWN] 3.1.4.2
	 * If NetName, IpAddress or ClientComputerName is NULL, the server
	 * MUST fail the request and return the error code
	 * ERROR_INVALID_PARAMETER
	 */
	if (r->in.net_name == NULL ||
	    r->in.ip_address == NULL ||
	    r->in.client_computer_name == NULL)
	{
		return WERR_INVALID_PARAMETER;
	}

	status = swn_service_reload_interfaces(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	/*
	 * [MS-SWN] 3.1.4.2
	 * If the NetName parameter is not equal to ServerGlobalName, the
	 * server MUST fail the request and return the error code
	 * ERROR_INVALID_PARAMETER
	 */
	werr = swn_server_check_net_name(swn_globals, r->in.net_name);
	if (!W_ERROR_IS_OK(werr)) {
		DBG_INFO("Invalid net_name[%s], "
			 "server_global_name[%s]: %s\n",
			 log_escape(p->mem_ctx, r->in.net_name),
			 swn_globals->server_global_name,
			 win_errstr(werr));
		return werr;
	}

	/*
	 * [MS-SWN] 3.1.4.2
	 * The server MUST enumerate the shares by calling NetrShareEnum as
	 * specified in [MS-SRVS] section 3.1.4.8. In the enumerated list,
	 * if any of the shares has shi*_type set to STYPE_CLUSTER_SOFS, as
	 * specified in [MS-SRVS] section 2.2.2.4, the server MUST search for
	 * an Interface in InterfaceList, where Interface.IPv4Address or
	 * Interface.IPv6Address matches the IpAddress parameter based on its
	 * format. If no matching entry is found, the server MUST fail the
	 * request and return the error code ERROR_INVALID_STATE.
	 *
	 * After clarifying this point with dochelp:
	 * A server only sets the CLUSTER_SOFS, CLUSTER_FS, or CLUSTER_DFS bit
	 * flags in NetrShareEnum when the call is local and never will be set
	 * by remote calls. This point only serves the purpose of identifying
	 * the SOFS shares.
	 * The server returns the error code ERROR_INVALID_STATE if the share
	 * enumeration of SMB share resources fails with any error other than
	 * STATUS_SUCCESS. It’s not the absence of SOFS shares, or just the
	 * call to ShareEnum. When the server enumerates the shares by calling
	 * NetrShareEnum locally, it tries to filter out only shares with
	 * STYPE_CLUSTER_SOFS. The scope of 'If no matching entry is found'
	 * is broader. Even if shares have STYPE_CLUSTER_SOFS, but no match
	 * could be found with the IpAddress, ERROR_INVALID_STATE will be
	 * returned too.
	 *
	 * In a CTDB cluster, all shares in the clustered filesystem are
	 * scale-out. We can skip this check and proceed to find the matching
	 * IP address.
	 */
	ok = is_ipaddress(r->in.ip_address);
	if (!ok) {
		DBG_INFO("Invalid ip_address[%s]\n",
			 log_escape(p->mem_ctx, r->in.ip_address));
		return WERR_INVALID_STATE;
	}
	ok = interpret_string_addr(&addr.u.ss,
				   r->in.ip_address,
				   AI_PASSIVE|AI_NUMERICHOST);
	if (!ok) {
		DBG_INFO("Invalid ip_address[%s]\n",
			 log_escape(p->mem_ctx, r->in.ip_address));
		return WERR_INVALID_STATE;
	}
	iface = swn_service_interface_by_addr(swn_globals, &addr);
	if (iface == NULL) {
		DBG_INFO("Invalid ip_address[%s]\n",
			 log_escape(p->mem_ctx, r->in.ip_address));
		return WERR_INVALID_STATE;
	}

	werr = swn_server_registration_create(swn_globals, p, &rex, iface, &reg);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	*r->out.context_handle = reg->key.handle;
	return WERR_OK;
}


/****************************************************************
 _witness_UnRegister
****************************************************************/

WERROR _witness_UnRegister(struct pipes_struct *p,
			   struct witness_UnRegister *r)
{
	bool ok;

	/*
	 * [MS-SWN] 3.1.4.3
	 * The server MUST search for the WitnessRegistration in
	 * WitnessRegistrationList, where WitnessRegistration.RegistrationKey
	 * matches the pContext parameter. If no matching entry is found,
	 * the server SHOULD<4> stop processing the request and return the
	 * error code ERROR_NOT_FOUND.
	 */
	ok = close_policy_hnd(p, &r->in.context_handle);
	if (!ok) {
		if (p->fault_state != 0) {
			p->fault_state = 0;
		}
		return WERR_NOT_FOUND;
	}

	return WERR_OK;
}

/****************************************************************
 _witness_AsyncNotify
****************************************************************/

struct swn_service_async_notify_state {
	struct swn_service_async_notify_state *prev, *next;
	struct tevent_context *ev;
	struct tevent_req *req;
	TALLOC_CTX *r_mem_ctx;
	struct witness_AsyncNotify *r;
	struct swn_service_registration *reg;
	struct tevent_queue_entry *qe;
};

static void swn_service_async_notify_trigger(struct tevent_req *req,
					     void *private_data);

static void swn_service_async_notify_cleanup(struct tevent_req *req,
					     enum tevent_req_state req_state)
{
	struct swn_service_async_notify_state *state =
		tevent_req_data(req,
		struct swn_service_async_notify_state);

	TALLOC_FREE(state->qe);

	if (state->reg != NULL) {
		DLIST_REMOVE(state->reg->async_notify.list, state);
		state->reg = NULL;
	}
}

static void swn_service_async_notify_reg_destroyed(struct swn_service_async_notify_state *state)
{
	swn_service_async_notify_cleanup(state->req, TEVENT_REQ_USER_ERROR);
	swn_service_async_notify_trigger(state->req, NULL);
}

static bool swn_service_async_notify_cancel(struct tevent_req *req)
{
	return false;
}

static struct tevent_req *swn_service_async_notify_send(TALLOC_CTX *mem_ctx,
							struct tevent_context *ev,
							TALLOC_CTX *r_mem_ctx,
							struct witness_AsyncNotify *r,
							struct swn_service_registration *reg)
{
	struct tevent_req *req = NULL;
	struct swn_service_async_notify_state *state = NULL;
	struct timeval now = timeval_current();

	req = tevent_req_create(mem_ctx, &state,
				struct swn_service_async_notify_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->req = req;
	state->r_mem_ctx = r_mem_ctx;
	state->r = r;
	state->reg = reg;

	/*
	 * triggered changes likely wakeup
	 * more than one waiter, so we better
	 * let all individual waiters go through
	 * a tevent_immediate round.
	 */
	tevent_req_defer_callback(req, ev);

	tevent_req_set_cleanup_fn(req, swn_service_async_notify_cleanup);
	tevent_req_set_cancel_fn(req, swn_service_async_notify_cancel);

	if (!reg->forced_response.triggered &&
	    !reg->change_notification.triggered &&
	    !reg->move_notification.triggered &&
	    !reg->share_notification.triggered &&
	    !reg->ip_notification.triggered)
	{
		tevent_queue_stop(reg->async_notify.queue);
	}

	DLIST_ADD_END(reg->async_notify.list, state);

	state->qe = tevent_queue_add_entry(reg->async_notify.queue, ev, req,
					   swn_service_async_notify_trigger,
					   NULL)
	if (tevent_req_nomem(state->qe, req)) {
		return tevent_req_post(req, ev);
	}

	if (reg->async_notify.timeout_secs != 0) {
		struct timeval endtime;
		bool ok;

		endtime = timeval_add(&now, reg->async_notify.timeout_secs, 0);
		ok = tevent_req_set_endtime(req, ev, endtime);
		if (!ok) {
			tevent_req_oom(req);
			return tevent_req_post(req, ev);
		}
	}

	/*
	 * Once we added the queue entry
	 * swn_service_registration_update_usage()
	 * will adjust the registration expire time...
	 */
	swn_service_registration_update_usage(state->reg, now);

	/*
	 * Wait for trigger or timeout...
	 */
	return req;
}

static void swn_service_async_notify_trigger(struct tevent_req *req,
					     void *private_data)
{
	struct swn_service_async_notify_state *state =
		tevent_req_data(req,
		struct swn_service_async_notify_state);
	struct swn_service_registration *reg = state->reg;
	struct witness_notifyResponse *resp = NULL;
	WERROR forced_result = WERR_OK;
	bool defer_forced_unregister = false;

	if (reg == NULL) {
		tevent_req_werror(req, WERR_NOT_FOUND);
		return;
	}

	if (reg->forced_response.triggered) {
		resp = talloc_move(state, &reg->forced_response.response);
		forced_result = reg->forced_response.result;

		reg->forced_response.triggered = false;
		reg->forced_response.result = WERR_OK;
		goto finished;
	}

	if (reg->change_notification.triggered) {
		struct swn_service_globals *swn = reg->swn;
		const struct swn_service_interface *iface = NULL;
		union witness_notifyResponse_message *msgs = NULL;
		char reg_ip[INET6_ADDRSTRLEN] = { 0, };
		struct witness_ResourceChange *rc = NULL;
		enum witness_interfaceInfo_state cur_state;

		print_sockaddr(reg_ip, sizeof(reg_ip), &reg->ip_address.u.ss);

		iface = swn_service_interface_by_addr(swn, &reg->ip_address);
		if (iface != NULL) {
			cur_state = iface->state;
		} else {
			/*
			 * If the interface is no longer in our list
			 * it must be unavailable
			 */
			cur_state = WITNESS_STATE_UNAVAILABLE;
		}
		if (cur_state != WITNESS_STATE_AVAILABLE) {
			reg->change_notification.last_ip_state = cur_state;
		}

		resp = talloc_zero(state, struct witness_notifyResponse);
		if (tevent_req_nomem(resp, req)) {
			return;
		}

		msgs = talloc_zero_array(resp,
					 union witness_notifyResponse_message,
					 1);
		if (tevent_req_nomem(msgs, req)) {
			return;
		}

		resp->type = WITNESS_NOTIFY_RESOURCE_CHANGE;
		resp->num = 0;
		resp->messages = msgs;

		rc = &msgs[resp->num].resource_change;

		switch (reg->change_notification.last_ip_state) {
		case WITNESS_STATE_AVAILABLE:
			rc->type = WITNESS_RESOURCE_STATE_AVAILABLE;
			break;
		case WITNESS_STATE_UNAVAILABLE:
			rc->type = WITNESS_RESOURCE_STATE_UNAVAILABLE;
			break;
		case WITNESS_STATE_UNKNOWN:
			rc->type = WITNESS_RESOURCE_STATE_UNKNOWN;
			break;
		}

		/*
		 * We use the ip address as resource name
		 */
		rc->name = talloc_strdup(msgs, reg_ip);
		if (tevent_req_nomem(rc->name, req)) {
			return;
		}

		resp->num += 1;

		if (rc->type != WITNESS_RESOURCE_STATE_AVAILABLE) {
			/*
			 * In order to let a Windows server 2022
			 * correctly re-register after moving
			 * to a new connection, we force an
			 * unregistration after 5 seconds.
			 *
			 * It means the client gets WERR_NOT_FOUND
			 * from a pending AsyncNotify() and calls
			 * Unregister() (which also gets WERR_NOT_FOUND).
			 * Then the client calls GetInterfaceList()
			 * and RegisterEx() again.
			 */
			defer_forced_unregister = true;
		}

		if (reg->change_notification.last_ip_state != cur_state) {
			/*
			 * This means the last_ip_state was *not* available,
			 * and the current_state *is* available.
			 *
			 * keep the queue running and return the available
			 * message in the next run
			 */
			reg->change_notification.last_ip_state = cur_state;
			goto finished;
		}

		reg->change_notification.triggered = false;
		reg->change_notification.last_ip_state = WITNESS_STATE_UNKNOWN;
		goto finished;
	}

	if (reg->move_notification.triggered) {
		struct swn_service_globals *swn = reg->swn;
		struct swn_service_interface *iface = NULL;
		union witness_notifyResponse_message *msgs = NULL;
		struct witness_IPaddrInfoList *list = NULL;
		uint32_t num_ips = 0;
		const uint32_t *new_node = NULL;
		const struct samba_sockaddr *new_ip = NULL;

		if (reg->move_notification.new_node != NONCLUSTER_VNN) {
			new_node = &reg->move_notification.new_node;
		}
		if (!is_zero_addr(&reg->move_notification.new_ip.u.ss)) {
			new_ip = &reg->move_notification.new_ip;
		}

		for (iface = swn->interfaces.list;
		     iface != NULL;
		     iface = iface->next)
		{
			if (new_node != NULL &&
			    iface->current_vnn != *new_node)
			{
				continue;
			}

			if (new_ip != NULL &&
			    !sockaddr_equal(&new_ip->u.sa, &iface->addr.u.sa))
			{
				continue;
			}

			num_ips += 1;
		}

		if (num_ips == 0) {
			goto no_moves;
		}

		resp = talloc_zero(state, struct witness_notifyResponse);
		if (tevent_req_nomem(resp, req)) {
			return;
		}

		msgs = talloc_zero_array(resp,
					 union witness_notifyResponse_message,
					 1);
		if (tevent_req_nomem(msgs, req)) {
			return;
		}

		list = &msgs[0].client_move;
		list->addr = talloc_zero_array(msgs,
					       struct witness_IPaddrInfo,
					       num_ips);
		if (tevent_req_nomem(list->addr, req)) {
			return;
		}

		for (iface = swn->interfaces.list;
		     iface != NULL;
		     iface = iface->next)
		{
			struct witness_IPaddrInfo *info = &list->addr[list->num];
			char addr[INET6_ADDRSTRLEN] = { 0, };
			const char *ipv4 = "0.0.0.0";
			const char *ipv6 = "::";
			uint32_t flags = 0;
			bool is_reg_ip = false;

			if (new_node != NULL &&
			    iface->current_vnn != *new_node)
			{
				continue;
			}

			if (new_ip != NULL &&
			    !sockaddr_equal(&new_ip->u.sa, &iface->addr.u.sa))
			{
				continue;
			}

			switch (iface->state) {
			case WITNESS_STATE_AVAILABLE:
				flags |= WITNESS_IPADDR_ONLINE;
				break;
			case WITNESS_STATE_UNAVAILABLE:
				flags |= WITNESS_IPADDR_OFFLINE;
				break;
			case WITNESS_STATE_UNKNOWN:
				/* We map unknown also to offline */
				flags |= WITNESS_IPADDR_OFFLINE;
				break;
			}

			print_sockaddr(addr, sizeof(addr), &iface->addr.u.ss);
			if (iface->addr.u.sa.sa_family == AF_INET) {
				flags |= WITNESS_IPADDR_V4;
				ipv4 = addr;
			} else if (iface->addr.u.sa.sa_family == AF_INET6) {
				flags |= WITNESS_IPADDR_V6;
				ipv6 = addr;
			}

			info->ipv4 = talloc_strdup(list, ipv4);
			if (tevent_req_nomem(info->ipv4, req)) {
				return;
			}
			info->ipv6 = talloc_strdup(list, ipv6);
			if (tevent_req_nomem(info->ipv6, req)) {
				return;
			}
			info->flags = flags;
			list->num += 1;

			is_reg_ip = sockaddr_equal(&reg->ip_address.u.sa,
						   &iface->addr.u.sa);
			if (!is_reg_ip) {
				/*
				 * In order to let a Windows server 2022
				 * correctly re-register after moving
				 * to a new connection, we force an
				 * unregistration after 5 seconds.
				 *
				 * It means the client gets WERR_NOT_FOUND from
				 * a pending AsyncNotify() and calls
				 * Unregister() (which also gets
				 * WERR_NOT_FOUND).  Then the client calls
				 * GetInterfaceList() and RegisterEx() again.
				 */
				defer_forced_unregister = true;
			}
		}

		resp->type = WITNESS_NOTIFY_CLIENT_MOVE;
		resp->num = talloc_array_length(msgs);
		resp->messages = msgs;

no_moves:
		reg->move_notification.triggered = false;
		if (resp != NULL) {
			goto finished;
		}
	}

	if (reg->share_notification.triggered) {
		struct swn_service_globals *swn = reg->swn;
		struct swn_service_interface *iface = NULL;
		union witness_notifyResponse_message *msgs = NULL;
		struct witness_IPaddrInfoList *list = NULL;
		uint32_t num_ips = 0;
		const uint32_t *new_node = NULL;
		const struct samba_sockaddr *new_ip = NULL;

		if (reg->share_notification.new_node != NONCLUSTER_VNN) {
			new_node = &reg->share_notification.new_node;
		}
		if (!is_zero_addr(&reg->share_notification.new_ip.u.ss)) {
			new_ip = &reg->share_notification.new_ip;
		}

		for (iface = swn->interfaces.list;
		     iface != NULL;
		     iface = iface->next)
		{
			if (new_node != NULL &&
			    iface->current_vnn != *new_node)
			{
				continue;
			}

			if (new_ip != NULL &&
			    !sockaddr_equal(&new_ip->u.sa, &iface->addr.u.sa))
			{
				continue;
			}

			num_ips += 1;
		}

		if (num_ips == 0) {
			goto no_share_moves;
		}

		resp = talloc_zero(state, struct witness_notifyResponse);
		if (tevent_req_nomem(resp, req)) {
			return;
		}

		msgs = talloc_zero_array(resp,
					 union witness_notifyResponse_message,
					 1);
		if (tevent_req_nomem(msgs, req)) {
			return;
		}

		list = &msgs[0].client_move;
		list->addr = talloc_zero_array(msgs,
					       struct witness_IPaddrInfo,
					       num_ips);
		if (tevent_req_nomem(list->addr, req)) {
			return;
		}

		for (iface = swn->interfaces.list;
		     iface != NULL;
		     iface = iface->next)
		{
			struct witness_IPaddrInfo *info = &list->addr[list->num];
			char addr[INET6_ADDRSTRLEN] = { 0, };
			const char *ipv4 = "0.0.0.0";
			const char *ipv6 = "::";
			uint32_t flags = 0;
			bool is_reg_ip = false;

			if (new_node != NULL &&
			    iface->current_vnn != *new_node)
			{
				continue;
			}

			if (new_ip != NULL &&
			    !sockaddr_equal(&new_ip->u.sa, &iface->addr.u.sa))
			{
				continue;
			}

			switch (iface->state) {
			case WITNESS_STATE_AVAILABLE:
				flags |= WITNESS_IPADDR_ONLINE;
				break;
			case WITNESS_STATE_UNAVAILABLE:
				flags |= WITNESS_IPADDR_OFFLINE;
				break;
			case WITNESS_STATE_UNKNOWN:
				/* We map unknown also to offline */
				flags |= WITNESS_IPADDR_OFFLINE;
				break;
			}

			print_sockaddr(addr, sizeof(addr), &iface->addr.u.ss);
			if (iface->addr.u.sa.sa_family == AF_INET) {
				flags |= WITNESS_IPADDR_V4;
				ipv4 = addr;
			} else if (iface->addr.u.sa.sa_family == AF_INET6) {
				flags |= WITNESS_IPADDR_V6;
				ipv6 = addr;
			}

			info->ipv4 = talloc_strdup(list, ipv4);
			if (tevent_req_nomem(info->ipv4, req)) {
				return;
			}
			info->ipv6 = talloc_strdup(list, ipv6);
			if (tevent_req_nomem(info->ipv6, req)) {
				return;
			}
			info->flags = flags;
			list->num += 1;

			is_reg_ip = sockaddr_equal(&reg->ip_address.u.sa,
						   &iface->addr.u.sa);
			if (!is_reg_ip) {
				/*
				 * In order to let a Windows server 2022
				 * correctly re-register after moving
				 * to a new connection, we force an
				 * unregistration after 5 seconds.
				 *
				 * It means the client gets WERR_NOT_FOUND from
				 * a pending AsyncNotify() and calls
				 * Unregister() (which also gets
				 * WERR_NOT_FOUND).  Then the client calls
				 * GetInterfaceList() and RegisterEx() again.
				 */
				defer_forced_unregister = true;
			}
		}

		resp->type = WITNESS_NOTIFY_SHARE_MOVE;
		resp->num = talloc_array_length(msgs);
		resp->messages = msgs;

no_share_moves:
		reg->share_notification.triggered = false;
		if (resp != NULL) {
			goto finished;
		}
	}

finished:
	if (!reg->forced_response.triggered &&
	    !reg->change_notification.triggered &&
	    !reg->move_notification.triggered &&
	    !reg->share_notification.triggered &&
	    !reg->ip_notification.triggered)
	{
		tevent_queue_stop(reg->async_notify.queue);
	}

	if (defer_forced_unregister) {
		struct tevent_timer *te = NULL;

		/*
		 * In order to let a Windows server 2022
		 * correctly re-register after moving
		 * to a new connection, we force an
		 * unregistration after 5 seconds.
		 *
		 * It means the client gets WERR_NOT_FOUND
		 * from a pending AsyncNotify() and calls
		 * Unregister() (which also gets WERR_NOT_FOUND).
		 * Then the client calls GetInterfaceList()
		 * and RegisterEx() again.
		 */
		TALLOC_FREE(reg->forced_unregister.timer);
		te = tevent_add_timer(state->ev,
				      reg,
				      timeval_current_ofs(5,0),
				      swn_service_registration_force_unregister,
				      reg);
		if (tevent_req_nomem(te, req)) {
			return;
		}
		reg->forced_unregister.timer = te;
	}

	*state->r->out.response = talloc_move(state->r_mem_ctx, &resp);
	state->r->out.result = forced_result;
	if (!W_ERROR_IS_OK(forced_result)) {
		tevent_req_werror(req, forced_result);
		return;
	}
	tevent_req_done(req);
}

static WERROR swn_service_async_notify_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_werror(req);
}

struct _witness_AsyncNotify_state {
	struct dcesrv_call_state *dce_call;
	struct witness_AsyncNotify *r;
	struct swn_service_registration *reg;
	struct tevent_req *subreq;
};

static bool _witness_AsyncNotify_cancel(struct tevent_req *req);
static void _witness_AsyncNotify_done(struct tevent_req *subreq);

WERROR _witness_AsyncNotify(struct pipes_struct *p,
			    struct witness_AsyncNotify *r)
{
	struct tevent_req *req = NULL;
	struct _witness_AsyncNotify_state *state = NULL;
	struct swn_service_registration *reg = NULL;
	NTSTATUS status = NT_STATUS_INTERNAL_ERROR;

	/*
	 * [MS-SWN] 3.1.4.4
	 * The server MUST search for the WitnessRegistration in
	 * WitnessRegistrationList, where WitnessRegistration.RegistrationKey
	 * matches the pContext parameter. If no matching entry is found, the
	 * server MUST fail the request and return the error code
	 * ERROR_NOT_FOUND.
	 */
	reg = find_policy_by_hnd(p, &r->in.context_handle,
				 SWN_SERVICE_CONTEXT_HANDLE_REGISTRATION,
				 struct swn_service_registration,
				 &status);
	if (!NT_STATUS_IS_OK(status)) {
		if (p->fault_state != 0) {
			p->fault_state = 0;
		}
		return WERR_NOT_FOUND;
	}

	swn_service_registration_update_usage(reg, p->dce_call->time);

	req = tevent_req_create(p->mem_ctx, &state,
				struct _witness_AsyncNotify_state);
	if (req == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	state->dce_call = p->dce_call;
	state->r = r;
	state->reg = reg;

	tevent_req_set_cancel_fn(req, _witness_AsyncNotify_cancel);

	state->subreq = swn_service_async_notify_send(state,
						      state->dce_call->event_ctx,
						      state->dce_call,
						      state->r,
						      state->reg);
	if (state->subreq == NULL) {
		TALLOC_FREE(state);
		return WERR_NOT_ENOUGH_MEMORY;
	}
	tevent_req_set_callback(state->subreq,
				_witness_AsyncNotify_done,
				req);

	state->dce_call->subreq = req;
	state->dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;
	return WERR_EVENT_PENDING; /* hidden by DCESRV_CALL_STATE_FLAG_ASYNC */
}

static bool _witness_AsyncNotify_cancel(struct tevent_req *req)
{
	struct _witness_AsyncNotify_state *state =
		tevent_req_data(req,
		struct _witness_AsyncNotify_state);
	struct dcesrv_call_state *dce_call = state->dce_call;

	SMB_ASSERT(dce_call->subreq == req);
	dce_call->subreq = NULL;

	TALLOC_FREE(state->subreq);

	if (dce_call->got_orphaned) {
		dce_call->fault_code = DCERPC_FAULT_SERVER_UNAVAILABLE;
	} else {
		dce_call->fault_code = DCERPC_NCA_S_FAULT_CANCEL;
	}
	state->r->out.result = WERR_RPC_S_CALL_CANCELLED;

	dcesrv_async_reply(dce_call);
	return true;
}

static void _witness_AsyncNotify_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct _witness_AsyncNotify_state *state =
		tevent_req_data(req,
		struct _witness_AsyncNotify_state);
	struct dcesrv_call_state *dce_call = state->dce_call;

	SMB_ASSERT(dce_call->subreq == req);
	dce_call->subreq = NULL;

	SMB_ASSERT(state->subreq == subreq);
	state->subreq = NULL;

	state->r->out.result = swn_service_async_notify_recv(subreq);
	TALLOC_FREE(subreq);

	if (W_ERROR_EQUAL(state->r->out.result, WERR_NOT_FOUND)) {
		state->reg = NULL;
	}

	if (state->reg != NULL &&
	    tevent_queue_length(state->reg->async_notify.queue) == 0)
	{
		struct timeval now = timeval_current();
		swn_service_registration_update_usage(state->reg, now);
	}

	dcesrv_async_reply(dce_call);
}

/****************************************************************
 _witness_RegisterEx
****************************************************************/

WERROR _witness_RegisterEx(struct pipes_struct *p,
			   struct witness_RegisterEx *r)
{
	struct dcesrv_context *dce_ctx = p->dce_call->conn->dce_ctx;
	struct swn_service_registration *reg = NULL;
	struct samba_sockaddr addr = { .sa_socklen = 0, };
	struct swn_service_interface *iface = NULL;
	NTSTATUS status;
	WERROR werr;
	bool ok;

	/*
	 * [MS-SWN] 3.1.4.5
	 * If the Version field of the request is not 0x00020000, the server
	 * MUST stop processing the request and return the error code
	 * ERROR_REVISION_MISMATCH
	 */
	if (r->in.version != WITNESS_V2) {
		return WERR_REVISION_MISMATCH;
	}

	/*
	 * [MS-SWN] 3.1.4.5
	 * If NetName, IpAddress or ClientComputerName is NULL, the server
	 * MUST fail the request and return the error code
	 * ERROR_INVALID_PARAMETER
	 */
	if (r->in.net_name == NULL ||
	    r->in.ip_address == NULL ||
	    r->in.client_computer_name == NULL)
	{
		return WERR_INVALID_PARAMETER;
	}

	status = swn_service_reload_interfaces(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	/*
	 * [MS-SWN] 3.1.4.5
	 * If the NetName parameter is not equal to ServerGlobalName, the
	 * server MUST fail the request and return the error code
	 * ERROR_INVALID_PARAMETER
	 */
	werr = swn_server_check_net_name(swn_globals, r->in.net_name);
	if (!W_ERROR_IS_OK(werr)) {
		DBG_INFO("Invalid net_name[%s], "
			 "server_global_name[%s]: %s\n",
			 log_escape(p->mem_ctx, r->in.net_name),
			 swn_globals->server_global_name,
			 win_errstr(werr));
		return werr;
	}

	/*
	 * [MS-SWN] 3.1.4.5
	 * If ShareName is not NULL, the server MUST enumerate the shares by
	 * calling NetrShareEnum as specified in [MS-SRVS] section 3.1.4.8.
	 * If the enumeration fails or if no shares are returned, the server
	 * MUST return the error code ERROR_INVALID_STATE.
	 *
	 * If none of the shares in the list has shi*_type set to
	 * STYPE_CLUSTER_SOFS as specified in [MS-SRVS] section 3.1.4.8,
	 * the server MUST ignore ShareName.
	 *
	 * In a CTDB cluster, all shares in the clustered filesystem are
	 * scale-out. Check if the provided share name is in a clustered FS
	 */
	if (r->in.share_name != NULL) {
		char *save_share = NULL;
		int cmp;

		/*
		 * For now we allow all shares...
		 *
		 * The main reason is that windows
		 * clients typically connect as
		 * machine account, so things like %U
		 * wouldn't work anyway.
		 *
		 * And in the end it's just a string,
		 * so we just check it's sane.
		 */
		save_share = log_escape(p->mem_ctx, r->in.share_name);
		if (save_share == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		cmp = strcmp(save_share, r->in.share_name);
		if (cmp != 0) {
			DBG_INFO("Invalid share_name[%s]\n",
				 save_share);
			return WERR_INVALID_STATE;
		}
		TALLOC_FREE(save_share);
	}

	/*
	 * [MS-SWN] 3.1.4.5
	 * The server MUST search for an Interface in InterfaceList, where
	 * Interface.IPv4Address or Interface.IPv6Address matches the
	 * IpAddress parameter based on its format. If no matching entry is
	 * found, the server MUST fail the request and return the error code
	 * ERROR_INVALID_STATE.
	 */
	ok = is_ipaddress(r->in.ip_address);
	if (!ok) {
		DBG_INFO("Invalid ip_address[%s]\n",
			 log_escape(p->mem_ctx, r->in.ip_address));
		return WERR_INVALID_STATE;
	}
	ok = interpret_string_addr(&addr.u.ss,
				   r->in.ip_address,
				   AI_PASSIVE|AI_NUMERICHOST);
	if (!ok) {
		DBG_INFO("Invalid ip_address[%s]\n",
			 log_escape(p->mem_ctx, r->in.ip_address));
		return WERR_INVALID_STATE;
	}
	iface = swn_service_interface_by_addr(swn_globals, &addr);
	if (iface == NULL) {
		DBG_INFO("Invalid ip_address[%s]\n",
			 log_escape(p->mem_ctx, r->in.ip_address));
		return WERR_INVALID_STATE;
	}

	werr = swn_server_registration_create(swn_globals, p, r, iface, &reg);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	*r->out.context_handle = reg->key.handle;
	return WERR_OK;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_witness_scompat.c"
