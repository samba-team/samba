/*
   Unix SMB/CIFS mplementation.

   DNS update service

   Copyright (C) Andrew Tridgell 2009

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

/*
  this module auto-creates the named.conf.update file, which tells
  bind9 what KRB5 principals it should accept for updates to our zone

  It also uses the samba_dnsupdate script to auto-create the right DNS
  names for ourselves as a DC in the domain, using TSIG-GSS
 */

#include "includes.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "smbd/service.h"
#include "lib/messaging/irpc.h"
#include "param/param.h"
#include "system/filesys.h"
#include "libcli/composite/composite.h"

struct dnsupdate_service {
	struct task_server *task;
	struct auth_session_info *system_session_info;
	struct ldb_context *samdb;

	/* status for periodic config file update */
	struct {
		uint32_t interval;
		struct tevent_timer *te;
		struct tevent_req *subreq;
		NTSTATUS status;
	} confupdate;

	/* status for periodic DNS name check */
	struct {
		uint32_t interval;
		struct tevent_timer *te;
		struct tevent_req *subreq;
		struct tevent_req *spnreq;
		NTSTATUS status;
	} nameupdate;
};

/*
  called when rndc reload has finished
 */
static void dnsupdate_rndc_done(struct tevent_req *subreq)
{
	struct dnsupdate_service *service = tevent_req_callback_data(subreq,
					    struct dnsupdate_service);
	int ret;
	int sys_errno;

	service->confupdate.subreq = NULL;

	ret = samba_runcmd_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		service->confupdate.status = map_nt_error_from_unix(sys_errno);
	} else {
		service->confupdate.status = NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(service->confupdate.status)) {
		DEBUG(0,(__location__ ": Failed rndc update - %s\n",
			 nt_errstr(service->confupdate.status)));
	} else {
		DEBUG(3,("Completed rndc reload OK\n"));
	}
}

/*
  called every 'dnsupdate:conf interval' seconds
 */
static void dnsupdate_rebuild(struct dnsupdate_service *service)
{
	int ret;
	size_t size;
	struct ldb_result *res;
	const char *tmp_path, *path, *path_static;
	char *static_policies;
	int fd;
	unsigned int i;
	const char *attrs[] = { "sAMAccountName", NULL };
	const char *realm = lpcfg_realm(service->task->lp_ctx);
	TALLOC_CTX *tmp_ctx = talloc_new(service);
	const char * const *rndc_command = lpcfg_rndc_command(service->task->lp_ctx);

	/* abort any pending script run */
	TALLOC_FREE(service->confupdate.subreq);

	ret = ldb_search(service->samdb, tmp_ctx, &res, NULL, LDB_SCOPE_SUBTREE,
			 attrs, "(&(primaryGroupID=%u)(objectClass=computer))",
			 DOMAIN_RID_DCS);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Unable to find DCs list - %s", ldb_errstring(service->samdb)));
		talloc_free(tmp_ctx);
		return;
	}

	path = lpcfg_parm_string(service->task->lp_ctx, NULL, "dnsupdate", "path");
	if (path == NULL) {
		path = private_path(tmp_ctx, service->task->lp_ctx, "named.conf.update");
	}

	path_static = lpcfg_parm_string(service->task->lp_ctx, NULL, "dnsupdate", "extra_static_grant_rules");
	if (path_static == NULL) {
		path_static = private_path(tmp_ctx, service->task->lp_ctx, "named.conf.update.static");
	}

	tmp_path = talloc_asprintf(tmp_ctx, "%s.tmp", path);
	if (path == NULL || tmp_path == NULL || path_static == NULL ) {
		DEBUG(0,(__location__ ": Unable to get paths\n"));
		talloc_free(tmp_ctx);
		return;
	}

	static_policies = file_load(path_static, &size, 0, tmp_ctx);

	unlink(tmp_path);
	fd = open(tmp_path, O_CREAT|O_TRUNC|O_WRONLY, 0444);
	if (fd == -1) {
		DEBUG(1,(__location__ ": Unable to open %s - %s\n", tmp_path, strerror(errno)));
		talloc_free(tmp_ctx);
		return;
	}

	dprintf(fd, "/* this file is auto-generated - do not edit */\n");
	dprintf(fd, "update-policy {\n");
	if( static_policies != NULL ) {
		dprintf(fd, "/* Start of static entries */\n");
		dprintf(fd, "%s\n",static_policies);
		dprintf(fd, "/* End of static entries */\n");
	}
	dprintf(fd, "\tgrant %s ms-self * A AAAA;\n", realm);
	dprintf(fd, "\tgrant administrator@%s wildcard * A AAAA SRV CNAME TXT;\n", realm);

	for (i=0; i<res->count; i++) {
		const char *acctname;
		acctname = ldb_msg_find_attr_as_string(res->msgs[i],
						       "sAMAccountName", NULL);
		if (!acctname) continue;
		dprintf(fd, "\tgrant %s@%s wildcard * A AAAA SRV CNAME;\n",
			acctname, realm);
	}
	dprintf(fd, "};\n");
	close(fd);


	if (NT_STATUS_IS_OK(service->confupdate.status) &&
	    file_compare(tmp_path, path) == true) {
		unlink(tmp_path);
		talloc_free(tmp_ctx);
		return;
	}

	if (rename(tmp_path, path) != 0) {
		DEBUG(0,(__location__ ": Failed to rename %s to %s - %s\n",
			 tmp_path, path, strerror(errno)));
		talloc_free(tmp_ctx);
		return;
	}

	DEBUG(2,("Loading new DNS update grant rules\n"));
	service->confupdate.subreq = samba_runcmd_send(service,
						       service->task->event_ctx,
						       timeval_current_ofs(10, 0),
						       2, 0,
						       rndc_command,
						       "reload", NULL);
	if (service->confupdate.subreq == NULL) {
		DEBUG(0,(__location__ ": samba_runcmd_send() failed with no memory\n"));
		talloc_free(tmp_ctx);
		return;
	}
	tevent_req_set_callback(service->confupdate.subreq,
				dnsupdate_rndc_done,
				service);

	talloc_free(tmp_ctx);
}

static NTSTATUS dnsupdate_confupdate_schedule(struct dnsupdate_service *service);

/*
  called every 'dnsupdate:conf interval' seconds
 */
static void dnsupdate_confupdate_handler_te(struct tevent_context *ev, struct tevent_timer *te,
					  struct timeval t, void *ptr)
{
	struct dnsupdate_service *service = talloc_get_type(ptr, struct dnsupdate_service);

	dnsupdate_rebuild(service);
	dnsupdate_confupdate_schedule(service);
}


static NTSTATUS dnsupdate_confupdate_schedule(struct dnsupdate_service *service)
{
	service->confupdate.te = tevent_add_timer(service->task->event_ctx, service,
						timeval_current_ofs(service->confupdate.interval, 0),
						dnsupdate_confupdate_handler_te, service);
	NT_STATUS_HAVE_NO_MEMORY(service->confupdate.te);
	return NT_STATUS_OK;
}


/*
  called when dns update script has finished
 */
static void dnsupdate_nameupdate_done(struct tevent_req *subreq)
{
	struct dnsupdate_service *service = tevent_req_callback_data(subreq,
					    struct dnsupdate_service);
	int ret;
	int sys_errno;

	service->nameupdate.subreq = NULL;

	ret = samba_runcmd_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		service->nameupdate.status = map_nt_error_from_unix(sys_errno);
	} else {
		service->nameupdate.status = NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(service->nameupdate.status)) {
		DEBUG(0,(__location__ ": Failed DNS update - %s\n",
			 nt_errstr(service->nameupdate.status)));
	} else {
		DEBUG(3,("Completed DNS update check OK\n"));
	}
}


/*
  called when spn update script has finished
 */
static void dnsupdate_spnupdate_done(struct tevent_req *subreq)
{
	struct dnsupdate_service *service = tevent_req_callback_data(subreq,
					    struct dnsupdate_service);
	int ret;
	int sys_errno;

	service->nameupdate.spnreq = NULL;

	ret = samba_runcmd_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		service->nameupdate.status = map_nt_error_from_unix(sys_errno);
	} else {
		service->nameupdate.status = NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(service->nameupdate.status)) {
		DEBUG(0,(__location__ ": Failed SPN update - %s\n",
			 nt_errstr(service->nameupdate.status)));
	} else {
		DEBUG(3,("Completed SPN update check OK\n"));
	}
}

/*
  called every 'dnsupdate:name interval' seconds
 */
static void dnsupdate_check_names(struct dnsupdate_service *service)
{
	const char * const *dns_update_command = lpcfg_dns_update_command(service->task->lp_ctx);
	const char * const *spn_update_command = lpcfg_spn_update_command(service->task->lp_ctx);

	/* kill any existing child */
	TALLOC_FREE(service->nameupdate.subreq);

	DEBUG(3,("Calling DNS name update script\n"));
	service->nameupdate.subreq = samba_runcmd_send(service,
						       service->task->event_ctx,
						       timeval_current_ofs(10, 0),
						       2, 0,
						       dns_update_command,
						       NULL);
	if (service->nameupdate.subreq == NULL) {
		DEBUG(0,(__location__ ": samba_runcmd_send() failed with no memory\n"));
		return;
	}
	tevent_req_set_callback(service->nameupdate.subreq,
				dnsupdate_nameupdate_done,
				service);

	DEBUG(3,("Calling SPN name update script\n"));
	service->nameupdate.spnreq = samba_runcmd_send(service,
						       service->task->event_ctx,
						       timeval_current_ofs(10, 0),
						       2, 0,
						       spn_update_command,
						       NULL);
	if (service->nameupdate.spnreq == NULL) {
		DEBUG(0,(__location__ ": samba_runcmd_send() failed with no memory\n"));
		return;
	}
	tevent_req_set_callback(service->nameupdate.spnreq,
				dnsupdate_spnupdate_done,
				service);
}

static NTSTATUS dnsupdate_nameupdate_schedule(struct dnsupdate_service *service);

/*
  called every 'dnsupdate:name interval' seconds
 */
static void dnsupdate_nameupdate_handler_te(struct tevent_context *ev, struct tevent_timer *te,
					    struct timeval t, void *ptr)
{
	struct dnsupdate_service *service = talloc_get_type(ptr, struct dnsupdate_service);

	dnsupdate_check_names(service);
	dnsupdate_nameupdate_schedule(service);
}


static NTSTATUS dnsupdate_nameupdate_schedule(struct dnsupdate_service *service)
{
	service->nameupdate.te = tevent_add_timer(service->task->event_ctx, service,
						  timeval_current_ofs(service->nameupdate.interval, 0),
						  dnsupdate_nameupdate_handler_te, service);
	NT_STATUS_HAVE_NO_MEMORY(service->nameupdate.te);
	return NT_STATUS_OK;
}

/*
  startup the dns update task
*/
static void dnsupdate_task_init(struct task_server *task)
{
	NTSTATUS status;
	struct dnsupdate_service *service;

	if (lpcfg_server_role(task->lp_ctx) != ROLE_DOMAIN_CONTROLLER) {
		/* not useful for non-DC */
		return;
	}

	task_server_set_title(task, "task[dnsupdate]");

	service = talloc_zero(task, struct dnsupdate_service);
	if (!service) {
		task_server_terminate(task, "dnsupdate_task_init: out of memory", true);
		return;
	}
	service->task		= task;
	task->private_data	= service;

	service->system_session_info = system_session(service->task->lp_ctx);
	if (!service->system_session_info) {
		task_server_terminate(task,
				      "dnsupdate: Failed to obtain server credentials\n",
				      true);
		return;
	}

	service->samdb = samdb_connect(service, service->task->event_ctx, task->lp_ctx,
				       service->system_session_info);
	if (!service->samdb) {
		task_server_terminate(task, "dnsupdate: Failed to connect to local samdb\n",
				      true);
		return;
	}

	service->confupdate.interval	= lpcfg_parm_int(task->lp_ctx, NULL,
						      "dnsupdate", "config interval", 60); /* in seconds */

	service->nameupdate.interval	= lpcfg_parm_int(task->lp_ctx, NULL,
						      "dnsupdate", "name interval", 600); /* in seconds */

	dnsupdate_rebuild(service);
	status = dnsupdate_confupdate_schedule(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dnsupdate: Failed to confupdate schedule: %s\n",
							    nt_errstr(status)), true);
		return;
	}

	dnsupdate_check_names(service);
	status = dnsupdate_nameupdate_schedule(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dnsupdate: Failed to nameupdate schedule: %s\n",
							    nt_errstr(status)), true);
		return;
	}

	irpc_add_name(task->msg_ctx, "dnsupdate");

	/* create the intial file */
	dnsupdate_rebuild(service);

}

/*
  register ourselves as a available server
*/
NTSTATUS server_service_dnsupdate_init(void)
{
	return register_server_service("dnsupdate", dnsupdate_task_init);
}
