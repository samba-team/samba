/*
   Unix SMB/CIFS mplementation.

   DNS udpate service

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
		struct composite_context *c;
		NTSTATUS status;
	} confupdate;

	/* status for periodic DNS name check */
	struct {
		uint32_t interval;
		struct tevent_timer *te;
		struct composite_context *c;
		NTSTATUS status;
	} nameupdate;
};

/*
  called when rndc reload has finished
 */
static void dnsupdate_rndc_done(struct composite_context *c)
{
	struct dnsupdate_service *service = talloc_get_type_abort(c->async.private_data,
								  struct dnsupdate_service);
	service->confupdate.status = composite_wait(c);
	if (!NT_STATUS_IS_OK(service->confupdate.status)) {
		DEBUG(0,(__location__ ": Failed rndc update - %s\n",
			 nt_errstr(service->confupdate.status)));
		return;
	}
	talloc_free(c);
	service->confupdate.c = NULL;
}

/*
  called every 'dnsupdate:conf interval' seconds
 */
static void dnsupdate_rebuild(struct dnsupdate_service *service)
{
	int ret;
	struct ldb_result *res;
	const char *tmp_path, *path;
	int fd, i;
	const char *attrs[] = { "sAMAccountName", NULL };
	const char *realm = lp_realm(service->task->lp_ctx);
	TALLOC_CTX *tmp_ctx = talloc_new(service);

	ret = ldb_search(service->samdb, tmp_ctx, &res, NULL, LDB_SCOPE_SUBTREE,
			 attrs, "(&(primaryGroupID=%u)(objectClass=computer))",
			 DOMAIN_RID_DCS);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Unable to find DCs list - %s", ldb_errstring(service->samdb)));
		talloc_free(tmp_ctx);
		return;
	}

	path = lp_parm_string(service->task->lp_ctx, NULL, "dnsupdate", "path");
	if (path == NULL) {
		path = private_path(tmp_ctx, service->task->lp_ctx, "named.conf.update");
	}

	tmp_path = talloc_asprintf(tmp_ctx, "%s.tmp", path);
	if (path == NULL || tmp_path == NULL) {
		DEBUG(0,(__location__ ": Unable to get paths"));
		talloc_free(tmp_ctx);
		return;
	}

	unlink(tmp_path);
	fd = open(tmp_path, O_CREAT|O_TRUNC|O_WRONLY, 0444);
	if (fd == -1) {
		DEBUG(1,(__location__ ": Unable to open %s - %s\n", tmp_path, strerror(errno)));
		talloc_free(tmp_ctx);
		return;
	}

	dprintf(fd, "/* this file is auto-generated - do not edit */\n");
	dprintf(fd, "update-policy {\n");
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

	if (service->confupdate.c != NULL) {
		talloc_free(service->confupdate.c);
		service->confupdate.c = NULL;
	}

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
	service->confupdate.c = samba_runcmd(service->task->event_ctx, service,
					   timeval_current_ofs(10, 0),
					   2, 0,
					   lp_rndc_command(service->task->lp_ctx),
					   "reload", NULL);
	service->confupdate.c->async.fn = dnsupdate_rndc_done;
	service->confupdate.c->async.private_data = service;

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
static void dnsupdate_nameupdate_done(struct composite_context *c)
{
	struct dnsupdate_service *service = talloc_get_type_abort(c->async.private_data,
								  struct dnsupdate_service);
	service->nameupdate.status = composite_wait(c);
	if (!NT_STATUS_IS_OK(service->nameupdate.status)) {
		DEBUG(0,(__location__ ": Failed DNS update - %s\n",
			 nt_errstr(service->nameupdate.status)));
		return;
	}
	talloc_free(c);
	service->nameupdate.c = NULL;
}

/*
  called every 'dnsupdate:name interval' seconds
 */
static void dnsupdate_check_names(struct dnsupdate_service *service)
{
	/* kill any existing child */
	if (service->nameupdate.c != NULL) {
		talloc_free(service->nameupdate.c);
		service->nameupdate.c = NULL;
	}

	DEBUG(3,("Calling DNS name update script\n"));
	service->nameupdate.c = samba_runcmd(service->task->event_ctx, service,
					     timeval_current_ofs(10, 0),
					     2, 0,
					     lp_dns_update_command(service->task->lp_ctx),
					     NULL);
	service->nameupdate.c->async.fn = dnsupdate_nameupdate_done;
	service->nameupdate.c->async.private_data = service;
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

	if (lp_server_role(task->lp_ctx) != ROLE_DOMAIN_CONTROLLER) {
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

	service->confupdate.interval	= lp_parm_int(task->lp_ctx, NULL,
						      "dnsupdate", "config interval", 60); /* in seconds */

	service->nameupdate.interval	= lp_parm_int(task->lp_ctx, NULL,
						      "dnsupdate", "name interval", 600); /* in seconds */

	status = dnsupdate_confupdate_schedule(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dnsupdate: Failed to confupdate schedule: %s\n",
							    nt_errstr(status)), true);
		return;
	}

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
