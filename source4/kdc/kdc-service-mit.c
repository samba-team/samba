/*
   Unix SMB/CIFS implementation.

   Start MIT krb5kdc server within Samba AD

   Copyright (c) 2014-2016 Andreas Schneider <asn@samba.org>

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
#include "talloc.h"
#include "tevent.h"
#include "system/filesys.h"
#include "lib/param/param.h"
#include "lib/util/samba_util.h"
#include "source4/smbd/service.h"
#include "source4/smbd/process_model.h"
#include "kdc/kdc-service-mit.h"
#include "dynconfig.h"
#include "libds/common/roles.h"
#include "lib/socket/netif.h"
#include "samba/session.h"
#include "dsdb/samdb/samdb.h"
#include "kdc/samba_kdc.h"
#include "kdc/kdc-server.h"
#include "kdc/kpasswd-service.h"
#include <kadm5/admin.h>
#include <kdb.h>

#include "source4/kdc/mit_kdc_irpc.h"

/* PROTOTYPES */
static void mitkdc_server_done(struct tevent_req *subreq);

static int kdc_server_destroy(struct kdc_server *kdc)
{
	if (kdc->private_data != NULL) {
		kadm5_destroy(kdc->private_data);
	}

	return 0;
}

static NTSTATUS startup_kpasswd_server(TALLOC_CTX *mem_ctx,
				       struct kdc_server *kdc,
				       struct loadparm_context *lp_ctx,
				       struct interface *ifaces)
{
	int num_interfaces;
	int i;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	uint16_t kpasswd_port;
	bool done_wildcard = false;
	bool ok;

	kpasswd_port = lpcfg_kpasswd_port(lp_ctx);
	if (kpasswd_port == 0) {
		return NT_STATUS_OK;
	}

	tmp_ctx = talloc_named_const(mem_ctx, 0, "kpasswd");
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	num_interfaces = iface_list_count(ifaces);

	ok = lpcfg_bind_interfaces_only(lp_ctx);
	if (!ok) {
		int num_binds = 0;
		char **wcard;

		wcard = iface_list_wildcard(tmp_ctx);
		if (wcard == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		for (i = 0; wcard[i] != NULL; i++) {
			status = kdc_add_socket(kdc,
						kdc->task->model_ops,
						"kpasswd",
						wcard[i],
						kpasswd_port,
						kpasswd_process,
						false);
			if (NT_STATUS_IS_OK(status)) {
				num_binds++;
			}
		}
		talloc_free(wcard);

		if (num_binds == 0) {
			status = NT_STATUS_INVALID_PARAMETER_MIX;
			goto out;
		}

		done_wildcard = true;
	}

	for (i = 0; i < num_interfaces; i++) {
		const char *address = talloc_strdup(tmp_ctx, iface_list_n_ip(ifaces, i));

		status = kdc_add_socket(kdc,
					kdc->task->model_ops,
					"kpasswd",
					address,
					kpasswd_port,
					kpasswd_process,
					done_wildcard);
		if (NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

out:
	talloc_free(tmp_ctx);
	return status;
}

/*
 * Startup a copy of the krb5kdc as a child daemon
 */
NTSTATUS mitkdc_task_init(struct task_server *task)
{
	struct tevent_req *subreq;
	const char * const *kdc_cmd;
	struct interface *ifaces;
	char *kdc_config = NULL;
	struct kdc_server *kdc;
	krb5_error_code code;
	NTSTATUS status;
	kadm5_ret_t ret;
	kadm5_config_params config;
	void *server_handle;

	task_server_set_title(task, "task[mitkdc_parent]");

	switch (lpcfg_server_role(task->lp_ctx)) {
	case ROLE_STANDALONE:
		task_server_terminate(task,
				      "The KDC is not required in standalone "
				      "server configuration, terminate!",
				      false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task,
				      "The KDC is not required in member "
				      "server configuration",
				      false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_ACTIVE_DIRECTORY_DC:
		/* Yes, we want to start the KDC */
		break;
	}

	/* Load interfaces for kpasswd */
	load_interface_list(task, task->lp_ctx, &ifaces);
	if (iface_list_count(ifaces) == 0) {
		task_server_terminate(task,
				      "KDC: no network interfaces configured",
				      false);
		return NT_STATUS_UNSUCCESSFUL;
	}

	kdc_config = talloc_asprintf(task,
				     "%s/kdc.conf",
				     lpcfg_private_dir(task->lp_ctx));
	if (kdc_config == NULL) {
		task_server_terminate(task,
				      "KDC: no memory",
				      false);
		return NT_STATUS_NO_MEMORY;
	}
	setenv("KRB5_KDC_PROFILE", kdc_config, 0);
	TALLOC_FREE(kdc_config);

	/* start it as a child process */
	kdc_cmd = lpcfg_mit_kdc_command(task->lp_ctx);

	subreq = samba_runcmd_send(task,
				   task->event_ctx,
				   timeval_zero(),
				   1, /* stdout log level */
				   0, /* stderr log level */
				   kdc_cmd,
				   "-n", /* Don't go into background */
#if 0
				   "-w 2", /* Start two workers */
#endif
				   NULL);
	if (subreq == NULL) {
		DEBUG(0, ("Failed to start MIT KDC as child daemon\n"));

		task_server_terminate(task,
				      "Failed to startup mitkdc task",
				      true);
		return NT_STATUS_INTERNAL_ERROR;
	}

	tevent_req_set_callback(subreq, mitkdc_server_done, task);

	DEBUG(5,("Started krb5kdc process\n"));

	status = samba_setup_mit_kdc_irpc(task);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task,
				      "Failed to setup kdc irpc service",
				      true);
	}

	DEBUG(5,("Started irpc service for kdc_server\n"));

	kdc = talloc_zero(task, struct kdc_server);
	if (kdc == NULL) {
		task_server_terminate(task, "KDC: Out of memory", true);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(kdc, kdc_server_destroy);

	kdc->task = task;

	kdc->base_ctx = talloc_zero(kdc, struct samba_kdc_base_context);
	if (kdc->base_ctx == NULL) {
		task_server_terminate(task, "KDC: Out of memory", true);
		return NT_STATUS_NO_MEMORY;
	}

	kdc->base_ctx->ev_ctx = task->event_ctx;
	kdc->base_ctx->lp_ctx = task->lp_ctx;

	initialize_krb5_error_table();

	code = smb_krb5_init_context(kdc,
				     kdc->task->lp_ctx,
				     &kdc->smb_krb5_context);
	if (code != 0) {
		task_server_terminate(task,
				      "KDC: Unable to initialize krb5 context",
				      true);
		return NT_STATUS_INTERNAL_ERROR;
	}

	code = kadm5_init_krb5_context(&kdc->smb_krb5_context->krb5_context);
	if (code != 0) {
		task_server_terminate(task,
				      "KDC: Unable to init kadm5 krb5_context",
				      true);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ZERO_STRUCT(config);
	config.mask = KADM5_CONFIG_REALM;
	config.realm = discard_const_p(char, lpcfg_realm(kdc->task->lp_ctx));

	ret = kadm5_init(kdc->smb_krb5_context->krb5_context,
			 discard_const_p(char, "kpasswd"),
			 NULL, /* pass */
			 discard_const_p(char, "kpasswd"),
			 &config,
			 KADM5_STRUCT_VERSION,
			 KADM5_API_VERSION_4,
			 NULL,
			 &server_handle);
	if (ret != 0) {
		task_server_terminate(task,
				      "KDC: Initialize kadm5",
				      true);
		return NT_STATUS_INTERNAL_ERROR;
	}
	kdc->private_data = server_handle;

	code = krb5_db_register_keytab(kdc->smb_krb5_context->krb5_context);
	if (code != 0) {
		task_server_terminate(task,
				      "KDC: Unable to KDB",
				      true);
		return NT_STATUS_INTERNAL_ERROR;
	}

	kdc->keytab_name = talloc_asprintf(kdc, "KDB:");
	if (kdc->keytab_name == NULL) {
		task_server_terminate(task,
				      "KDC: Out of memory",
				      true);
		return NT_STATUS_NO_MEMORY;
	}

	kdc->samdb = samdb_connect(kdc,
				   kdc->task->event_ctx,
				   kdc->task->lp_ctx,
				   system_session(kdc->task->lp_ctx),
				   NULL,
				   0);
	if (kdc->samdb == NULL) {
		task_server_terminate(task,
				      "KDC: Unable to connect to samdb",
				      true);
		return NT_STATUS_CONNECTION_INVALID;
	}

	status = startup_kpasswd_server(kdc,
				    kdc,
				    task->lp_ctx,
				    ifaces);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task,
				      "KDC: Unable to start kpasswd server",
				      true);
		return status;
	}

	DEBUG(5,("Started kpasswd service for kdc_server\n"));

	return NT_STATUS_OK;
}

/*
 * This gets called the kdc exits.
 */
static void mitkdc_server_done(struct tevent_req *subreq)
{
	struct task_server *task =
		tevent_req_callback_data(subreq,
		struct task_server);
	int sys_errno;
	int ret;

	ret = samba_runcmd_recv(subreq, &sys_errno);
	if (ret != 0) {
		DEBUG(0, ("The MIT KDC daemon died with exit status %d\n",
			  sys_errno));
	} else {
		DEBUG(0,("The MIT KDC daemon exited normally\n"));
	}

	task_server_terminate(task, "mitkdc child process exited", true);
}

/* Called at MIT KRB5 startup - register ourselves as a server service */
NTSTATUS server_service_mitkdc_init(TALLOC_CTX *mem_ctx);

NTSTATUS server_service_mitkdc_init(TALLOC_CTX *mem_ctx)
{
	static const struct service_details details = {
		.inhibit_fork_on_accept = true,
		/* 
		 * Need to prevent pre-forking on kdc.
		 * The task_init function is run on the master process only
		 * and the irpc process name is registered in it's event loop.
		 * The child worker processes initialise their event loops on
		 * fork, so are not listening for the irpc event.
		 *
		 * The master process does not wait on that event context
		 * the master process is responsible for managing the worker
		 * processes not performing work.
		 */
		.inhibit_pre_fork = true,
		.task_init = mitkdc_task_init,
		.post_fork = NULL
	};
	return register_server_service(mem_ctx, "kdc", &details);
}
