/*
   Unix SMB/CIFS implementation.

   KDC Server startup

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2008
   Copyright (C) Andrew Tridgell	2005
   Copyright (C) Stefan Metzmacher	2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "smbd/process_model.h"
#include "lib/tsocket/tsocket.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "lib/socket/netif.h"
#include "param/param.h"
#include "kdc/kdc-server.h"
#include "kdc/kdc-proxy.h"
#include "kdc/kdc-glue.h"
#include "kdc/pac-glue.h"
#include "kdc/kpasswd-service.h"
#include "dsdb/samdb/samdb.h"
#include "auth/session.h"
#include "libds/common/roles.h"
#include <kdc.h>
#include <hdb.h>

NTSTATUS server_service_kdc_init(TALLOC_CTX *);

extern struct krb5plugin_windc_ftable windc_plugin_table;

/**
   Wrapper for krb5_kdc_process_krb5_request, converting to/from Samba
   calling conventions
*/

static kdc_code kdc_process(struct kdc_server *kdc,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *input,
			    DATA_BLOB *reply,
			    struct tsocket_address *peer_addr,
			    struct tsocket_address *my_addr,
			    int datagram_reply)
{
	int ret;
	char *pa;
	struct sockaddr_storage ss;
	krb5_data k5_reply;
	krb5_kdc_configuration *kdc_config =
		(krb5_kdc_configuration *)kdc->private_data;

	krb5_data_zero(&k5_reply);

	krb5_kdc_update_time(NULL);

	ret = tsocket_address_bsd_sockaddr(peer_addr, (struct sockaddr *) &ss,
				sizeof(struct sockaddr_storage));
	if (ret < 0) {
		return KDC_ERROR;
	}
	pa = tsocket_address_string(peer_addr, mem_ctx);
	if (pa == NULL) {
		return KDC_ERROR;
	}

	DBG_DEBUG("Received KDC packet of length %lu from %s\n",
		  (long)input->length - 4, pa);

	ret = krb5_kdc_process_krb5_request(kdc->smb_krb5_context->krb5_context,
					    kdc_config,
					    input->data, input->length,
					    &k5_reply,
					    pa,
					    (struct sockaddr *) &ss,
					    datagram_reply);
	if (ret == -1) {
		*reply = data_blob(NULL, 0);
		return KDC_ERROR;
	}

	if (ret == HDB_ERR_NOT_FOUND_HERE) {
		*reply = data_blob(NULL, 0);
		return KDC_PROXY_REQUEST;
	}

	if (k5_reply.length) {
		*reply = data_blob_talloc(mem_ctx, k5_reply.data, k5_reply.length);
		krb5_data_free(&k5_reply);
	} else {
		*reply = data_blob(NULL, 0);
	}
	return KDC_OK;
}

/*
  setup our listening sockets on the configured network interfaces
*/
static NTSTATUS kdc_startup_interfaces(struct kdc_server *kdc,
				       struct loadparm_context *lp_ctx,
				       struct interface *ifaces,
				       const struct model_ops *model_ops)
{
	int num_interfaces;
	TALLOC_CTX *tmp_ctx = talloc_new(kdc);
	NTSTATUS status;
	int i;
	uint16_t kdc_port = lpcfg_krb5_port(lp_ctx);
	uint16_t kpasswd_port = lpcfg_kpasswd_port(lp_ctx);
	bool done_wildcard = false;

	num_interfaces = iface_list_count(ifaces);

	/* if we are allowing incoming packets from any address, then
	   we need to bind to the wildcard address */
	if (!lpcfg_bind_interfaces_only(lp_ctx)) {
		size_t num_binds = 0;
		char **wcard = iface_list_wildcard(kdc);
		NT_STATUS_HAVE_NO_MEMORY(wcard);
		for (i=0; wcard[i]; i++) {
			if (kdc_port) {
				status = kdc_add_socket(kdc, model_ops,
							"kdc", wcard[i], kdc_port,
							kdc_process, false);
				if (NT_STATUS_IS_OK(status)) {
					num_binds++;
				}
			}

			if (kpasswd_port) {
				status = kdc_add_socket(kdc, model_ops,
							"kpasswd", wcard[i], kpasswd_port,
							kpasswd_process, false);
				if (NT_STATUS_IS_OK(status)) {
					num_binds++;
				}
			}
		}
		talloc_free(wcard);
		if (num_binds == 0) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}
		done_wildcard = true;
	}

	for (i=0; i<num_interfaces; i++) {
		const char *address = talloc_strdup(tmp_ctx, iface_list_n_ip(ifaces, i));

		if (kdc_port) {
			status = kdc_add_socket(kdc, model_ops,
						"kdc", address, kdc_port,
						kdc_process, done_wildcard);
			NT_STATUS_NOT_OK_RETURN(status);
		}

		if (kpasswd_port) {
			status = kdc_add_socket(kdc, model_ops,
						"kpasswd", address, kpasswd_port,
						kpasswd_process, done_wildcard);
			NT_STATUS_NOT_OK_RETURN(status);
		}
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS kdc_check_generic_kerberos(struct irpc_message *msg,
				 struct kdc_check_generic_kerberos *r)
{
	struct PAC_Validate pac_validate;
	DATA_BLOB srv_sig;
	struct PAC_SIGNATURE_DATA kdc_sig;
	struct kdc_server *kdc = talloc_get_type(msg->private_data, struct kdc_server);
	krb5_kdc_configuration *kdc_config =
		(krb5_kdc_configuration *)kdc->private_data;
	enum ndr_err_code ndr_err;
	int ret;
	hdb_entry_ex ent;
	krb5_principal principal;


	/* There is no reply to this request */
	r->out.generic_reply = data_blob(NULL, 0);

	ndr_err = ndr_pull_struct_blob(&r->in.generic_request, msg, &pac_validate,
				       (ndr_pull_flags_fn_t)ndr_pull_PAC_Validate);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (pac_validate.MessageType != NETLOGON_GENERIC_KRB5_PAC_VALIDATE) {
		/* We don't implement any other message types - such as certificate validation - yet */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (pac_validate.ChecksumAndSignature.length != (pac_validate.ChecksumLength + pac_validate.SignatureLength)
	    || pac_validate.ChecksumAndSignature.length < pac_validate.ChecksumLength
	    || pac_validate.ChecksumAndSignature.length < pac_validate.SignatureLength ) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	srv_sig = data_blob_const(pac_validate.ChecksumAndSignature.data,
				  pac_validate.ChecksumLength);

	ret = krb5_make_principal(kdc->smb_krb5_context->krb5_context, &principal,
				  lpcfg_realm(kdc->task->lp_ctx),
				  "krbtgt", lpcfg_realm(kdc->task->lp_ctx),
				  NULL);

	if (ret != 0) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = kdc_config->db[0]->hdb_fetch_kvno(kdc->smb_krb5_context->krb5_context,
						 kdc_config->db[0],
						 principal,
						 HDB_F_GET_KRBTGT | HDB_F_DECRYPT,
						 0,
						 &ent);

	if (ret != 0) {
		hdb_free_entry(kdc->smb_krb5_context->krb5_context, &ent);
		krb5_free_principal(kdc->smb_krb5_context->krb5_context, principal);

		return NT_STATUS_LOGON_FAILURE;
	}

	kdc_sig.type = pac_validate.SignatureType;
	kdc_sig.signature = data_blob_const(&pac_validate.ChecksumAndSignature.data[pac_validate.ChecksumLength],
					    pac_validate.SignatureLength);

	ret = kdc_check_pac(kdc->smb_krb5_context->krb5_context, srv_sig, &kdc_sig, &ent);

	hdb_free_entry(kdc->smb_krb5_context->krb5_context, &ent);
	krb5_free_principal(kdc->smb_krb5_context->krb5_context, principal);

	if (ret != 0) {
		return NT_STATUS_LOGON_FAILURE;
	}

	return NT_STATUS_OK;
}


/*
  startup the kdc task
*/
static NTSTATUS kdc_task_init(struct task_server *task)
{
	struct kdc_server *kdc;
	NTSTATUS status;
	struct interface *ifaces;

	switch (lpcfg_server_role(task->lp_ctx)) {
	case ROLE_STANDALONE:
		task_server_terminate(task, "kdc: no KDC required in standalone configuration", false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task, "kdc: no KDC required in member server configuration", false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_DOMAIN_PDC:
	case ROLE_DOMAIN_BDC:
	case ROLE_IPA_DC:
		task_server_terminate(
		    task, "Cannot start KDC as a 'classic Samba' DC", false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_ACTIVE_DIRECTORY_DC:
		/* Yes, we want a KDC */
		break;
	}

	load_interface_list(task, task->lp_ctx, &ifaces);

	if (iface_list_count(ifaces) == 0) {
		task_server_terminate(task, "kdc: no network interfaces configured", false);
		return NT_STATUS_UNSUCCESSFUL;
	}

	task_server_set_title(task, "task[kdc]");

	kdc = talloc_zero(task, struct kdc_server);
	if (kdc == NULL) {
		task_server_terminate(task, "kdc: out of memory", true);
		return NT_STATUS_NO_MEMORY;
	}

	kdc->task = task;
	task->private_data = kdc;

	/* start listening on the configured network interfaces */
	status = kdc_startup_interfaces(kdc, task->lp_ctx, ifaces,
					task->model_ops);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "kdc failed to setup interfaces", true);
		return status;
	}


	return NT_STATUS_OK;
}

/*
  initialise the kdc task after a fork
*/
static void kdc_post_fork(struct task_server *task, struct process_details *pd)
{
	struct kdc_server *kdc;
	krb5_kdc_configuration *kdc_config = NULL;
	NTSTATUS status;
	krb5_error_code ret;
	int ldb_ret;

	if (task == NULL) {
		task_server_terminate(task, "kdc: Null task", true);
		return;
	}
	if (task->private_data == NULL) {
		task_server_terminate(task, "kdc: No kdc_server info", true);
		return;
	}
	kdc = talloc_get_type_abort(task->private_data, struct kdc_server);

	/* get a samdb connection */
	kdc->samdb = samdb_connect(kdc,
				   kdc->task->event_ctx,
				   kdc->task->lp_ctx,
				   system_session(kdc->task->lp_ctx),
				   NULL,
				   0);
	if (!kdc->samdb) {
		DBG_WARNING("kdc_task_init: unable to connect to samdb\n");
		task_server_terminate(task, "kdc: krb5_init_context samdb connect failed", true);
		return;
	}

	ldb_ret = samdb_rodc(kdc->samdb, &kdc->am_rodc);
	if (ldb_ret != LDB_SUCCESS) {
		DBG_WARNING("kdc_task_init: "
			    "Cannot determine if we are an RODC: %s\n",
			    ldb_errstring(kdc->samdb));
		task_server_terminate(task, "kdc: krb5_init_context samdb RODC connect failed", true);
		return;
	}

	kdc->proxy_timeout = lpcfg_parm_int(kdc->task->lp_ctx, NULL, "kdc", "proxy timeout", 5);

	initialize_krb5_error_table();

	ret = smb_krb5_init_context(kdc, task->lp_ctx, &kdc->smb_krb5_context);
	if (ret) {
		DBG_WARNING("kdc_task_init: krb5_init_context failed (%s)\n",
			    error_message(ret));
		task_server_terminate(task, "kdc: krb5_init_context failed", true);
		return;
	}

	krb5_add_et_list(kdc->smb_krb5_context->krb5_context, initialize_hdb_error_table_r);

	ret = krb5_kdc_get_config(kdc->smb_krb5_context->krb5_context,
				  &kdc_config);
	if(ret) {
		task_server_terminate(task, "kdc: failed to get KDC configuration", true);
		return;
	}

	kdc_config->logf = (krb5_log_facility *)kdc->smb_krb5_context->pvt_log_data;
	kdc_config->db = talloc(kdc, struct HDB *);
	if (!kdc_config->db) {
		task_server_terminate(task, "kdc: out of memory", true);
		return;
	}
	kdc_config->num_db = 1;

	/*
	 * This restores the behavior before
	 * commit 255e3e18e00f717d99f3bc57c8a8895ff624f3c3
	 * s4:heimdal: import lorikeet-heimdal-201107150856
	 * (commit 48936803fae4a2fb362c79365d31f420c917b85b)
	 *
	 * as_use_strongest_session_key,preauth_use_strongest_session_key
	 * and tgs_use_strongest_session_key are input to the
	 * _kdc_find_etype() function. The old bahavior is in
	 * the use_strongest_session_key=FALSE code path.
	 * (The only remaining difference in _kdc_find_etype()
	 *  is the is_preauth parameter.)
	 *
	 * The old behavior in the _kdc_get_preferred_key()
	 * function is use_strongest_server_key=TRUE.
	 */
	kdc_config->as_use_strongest_session_key = false;
	kdc_config->preauth_use_strongest_session_key = false;
	kdc_config->tgs_use_strongest_session_key = false;
	kdc_config->use_strongest_server_key = true;

	kdc_config->autodetect_referrals = false;

	/* Register hdb-samba4 hooks for use as a keytab */

	kdc->base_ctx = talloc_zero(kdc, struct samba_kdc_base_context);
	if (!kdc->base_ctx) {
		task_server_terminate(task, "kdc: out of memory", true);
		return;
	}

	kdc->base_ctx->ev_ctx = task->event_ctx;
	kdc->base_ctx->lp_ctx = task->lp_ctx;
	kdc->base_ctx->msg_ctx = task->msg_ctx;

	status = hdb_samba4_create_kdc(kdc->base_ctx,
				       kdc->smb_krb5_context->krb5_context,
				       &kdc_config->db[0]);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "kdc: hdb_samba4_create_kdc (setup KDC database) failed", true);
		return;
	}

	ret = krb5_plugin_register(kdc->smb_krb5_context->krb5_context,
				   PLUGIN_TYPE_DATA, "hdb",
				   &hdb_samba4_interface);
	if(ret) {
		task_server_terminate(task, "kdc: failed to register hdb plugin", true);
		return;
	}

	ret = krb5_kt_register(kdc->smb_krb5_context->krb5_context, &hdb_kt_ops);
	if(ret) {
		task_server_terminate(task, "kdc: failed to register keytab plugin", true);
		return;
	}

	kdc->keytab_name = talloc_asprintf(kdc, "HDB:samba4&%p", kdc->base_ctx);
	if (kdc->keytab_name == NULL) {
		task_server_terminate(task,
				      "kdc: Failed to set keytab name",
				      true);
		return;
	}

	/* Register WinDC hooks */
	ret = krb5_plugin_register(kdc->smb_krb5_context->krb5_context,
				   PLUGIN_TYPE_DATA, "windc",
				   &windc_plugin_table);
	if(ret) {
		task_server_terminate(task, "kdc: failed to register windc plugin", true);
		return;
	}

	ret = krb5_kdc_windc_init(kdc->smb_krb5_context->krb5_context);

	if(ret) {
		task_server_terminate(task, "kdc: failed to init windc plugin", true);
		return;
	}

	ret = krb5_kdc_pkinit_config(kdc->smb_krb5_context->krb5_context, kdc_config);

	if(ret) {
		task_server_terminate(task, "kdc: failed to init kdc pkinit subsystem", true);
		return;
	}
	kdc->private_data = kdc_config;

	status = IRPC_REGISTER(task->msg_ctx, irpc, KDC_CHECK_GENERIC_KERBEROS,
			       kdc_check_generic_kerberos, kdc);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "kdc failed to setup monitoring", true);
		return;
	}

	irpc_add_name(task->msg_ctx, "kdc_server");
}


/* called at smbd startup - register ourselves as a server service */
NTSTATUS server_service_kdc_init(TALLOC_CTX *ctx)
{
	static const struct service_details details = {
		.inhibit_fork_on_accept = true,
		.inhibit_pre_fork = false,
		.task_init = kdc_task_init,
		.post_fork = kdc_post_fork
	};
	return register_server_service(ctx, "kdc", &details);
}
