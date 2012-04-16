/*
   Unix SMB/CIFS implementation.

   run s3 file server within Samba4

   Copyright (C) Andrew Tridgell	2011

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
#include "source4/smbd/service.h"
#include "source4/smbd/process_model.h"
#include "file_server/file_server.h"
#include "dynconfig.h"

/*
  generate a smbd config file for the file server
 */
static const char *generate_smb_conf(struct task_server *task)
{
	int fd;
	struct loadparm_context *lp_ctx = task->lp_ctx;
	const char *path = smbd_tmp_path(task, lp_ctx, "fileserver.conf");

	if (path == NULL) {
		return NULL;
	}

	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd == -1) {
		DEBUG(0,("Failed to create %s", path));
		return NULL;
	}

	fdprintf(fd, "# auto-generated config for fileserver\n");
	fdprintf(fd, "auth methods = guest samba4\n");
	fdprintf(fd, "passdb backend = samba4\n");
        fdprintf(fd, "rpc_server:default = external\n");
        fdprintf(fd, "rpc_server:dssetup = disabled\n");
	fdprintf(fd, "rpc_server:spoolss = embedded\n");
	fdprintf(fd, "rpc_daemon:spoolssd = disabled\n");
	fdprintf(fd, "rpc_server:tcpip = no\n");

	/* If we are using xattr_tdb:file or posix:eadb then we need to load another VFS object */
	if (lpcfg_parm_string(lp_ctx, NULL, "xattr_tdb", "file")) {
		fdprintf(fd, "vfs objects = acl_xattr xattr_tdb\n");
	} else if (lpcfg_parm_string(lp_ctx, NULL, "posix", "eadb")) {
		fdprintf(fd, "vfs objects = acl_xattr posix_eadb\n");
	} else {
		fdprintf(fd, "vfs objects = acl_xattr\n");
	}

	fdprintf(fd, "include = %s\n", lpcfg_configfile(lp_ctx));

	fdprintf(fd, "[IPC$]\n");
	fdprintf(fd, " vfs objects = dfs_samba4\n");

	close(fd);
	return path;
}

/*
  called if smbd exits
 */
static void file_server_smbd_done(struct tevent_req *subreq)
{
	int sys_errno;
	int ret;

	ret = samba_runcmd_recv(subreq, &sys_errno);
	if (ret != 0) {
		DEBUG(0,("file_server smbd daemon died with exit status %d\n", sys_errno));
	} else {
		DEBUG(0,("file_server smbd daemon exited normally\n"));
	}
}


/*
  startup a copy of smbd as a child daemon
*/
static void s3fs_task_init(struct task_server *task)
{
	const char *fileserver_conf;
	struct tevent_req *req;
	const char *smbd_path;
	const char *smbd_cmd[2] = { NULL, NULL };

	task_server_set_title(task, "task[s3fs_parent]");

	/* create a smb.conf for smbd to use */
	fileserver_conf = generate_smb_conf(task);

	smbd_path = talloc_asprintf(task, "%s/smbd", dyn_SBINDIR);
	smbd_cmd[0] = smbd_path;

	/* start it as a child process */
	req = samba_runcmd_send(task, task->event_ctx, timeval_zero(), 1, 0,
				smbd_cmd,
				"--configfile", fileserver_conf,
				"--foreground",
				debug_get_output_is_stdout()?"--log-stdout":NULL,
				NULL);
	if (req == NULL) {
		DEBUG(0, ("Failed to start smbd as child daemon\n"));
		goto failed;
	}

	tevent_req_set_callback(req, file_server_smbd_done, task);

	DEBUG(1,("Started file server smbd with config %s\n", fileserver_conf));
	return;
failed:
	task_server_terminate(task, "Failed to startup s3fs smb task", true);
}

/* called at smbd startup - register ourselves as a server service */
NTSTATUS server_service_s3fs_init(void);

NTSTATUS server_service_s3fs_init(void)
{
	return register_server_service("s3fs", s3fs_task_init);
}
