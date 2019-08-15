/*
   Samba-VirusFilter VFS modules
   ClamAV clamd support
   Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan

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

/* Default values for standard "extra" configuration variables */

#ifdef CLAMAV_DEFAULT_SOCKET_PATH
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	CLAMAV_DEFAULT_SOCKET_PATH
#else
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	"/var/run/clamav/clamd.ctl"
#endif

#include "modules/vfs_virusfilter_common.h"
#include "modules/vfs_virusfilter_utils.h"

static int virusfilter_clamav_connect(struct vfs_handle_struct *handle,
				      struct virusfilter_config *config,
				      const char *svc,
				      const char *user)
{

	/* To use clamd "zXXXX" commands */
	virusfilter_io_set_writel_eol(config->io_h, "\0", 1);
	virusfilter_io_set_readl_eol(config->io_h, "\0", 1);

	return 0;
}

static virusfilter_result virusfilter_clamav_scan_init(
	struct virusfilter_config *config)
{
	struct virusfilter_io_handle *io_h = config->io_h;
	bool ok;

	DBG_INFO("clamd: Connecting to socket: %s\n",
		 config->socket_path);

	become_root();
	ok = virusfilter_io_connect_path(io_h, config->socket_path);
	unbecome_root();

	if (!ok) {
		DBG_ERR("clamd: Connecting to socket failed: %s: %s\n",
			config->socket_path, strerror(errno));
		return VIRUSFILTER_RESULT_ERROR;
	}

	DBG_INFO("clamd: Connected\n");

	return VIRUSFILTER_RESULT_OK;
}

static void virusfilter_clamav_scan_end(
	struct virusfilter_config *config)
{
	struct virusfilter_io_handle *io_h = config->io_h;

	DBG_INFO("clamd: Disconnecting\n");

	virusfilter_io_disconnect(io_h);
}

static virusfilter_result virusfilter_clamav_scan(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const struct files_struct *fsp,
	char **reportp)
{
	char *cwd_fname = fsp->conn->cwd_fsp->fsp_name->base_name;
	const char *fname = fsp->fsp_name->base_name;
	size_t filepath_len = strlen(cwd_fname) + 1 /* slash */ + strlen(fname);
	struct virusfilter_io_handle *io_h = config->io_h;
	virusfilter_result result = VIRUSFILTER_RESULT_CLEAN;
	char *report = NULL;
	char *reply = NULL;
	char *reply_msg = NULL;
	char *reply_token;
	bool ok;

	DBG_INFO("Scanning file: %s/%s\n", cwd_fname, fname);

	ok = virusfilter_io_writefl_readl(io_h, &reply, "zSCAN %s/%s",
					  cwd_fname, fname);
	if (!ok) {
		DBG_ERR("clamd: zSCAN: I/O error: %s\n", strerror(errno));
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
					 "Scanner I/O error: %s\n",
					 strerror(errno));
		goto virusfilter_clamav_scan_return;
	}

	if (reply[filepath_len] != ':' ||
	    reply[filepath_len+1] != ' ')
	{
		DBG_ERR("clamd: zSCAN: Invalid reply: %s\n",
			reply);
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
					 "Scanner communication error");
		goto virusfilter_clamav_scan_return;
	}
	reply_msg = reply + filepath_len + 2;

	reply_token = strrchr(reply, ' ');

	if (reply_token == NULL) {
		DBG_ERR("clamd: zSCAN: Invalid reply: %s\n",
			reply);
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
					 "Scanner communication error");
		goto virusfilter_clamav_scan_return;
	}
	*reply_token = '\0';
	reply_token++;

	if (strcmp(reply_token, "OK") == 0) {

		/* <FILEPATH>: OK */
		result = VIRUSFILTER_RESULT_CLEAN;
		report = talloc_asprintf(talloc_tos(), "Clean");
	} else if (strcmp(reply_token, "FOUND") == 0) {

		/* <FILEPATH>: <REPORT> FOUND */
		result = VIRUSFILTER_RESULT_INFECTED;
		report = talloc_strdup(talloc_tos(), reply_msg);
	} else if (strcmp(reply_token, "ERROR") == 0) {

		/* <FILEPATH>: <REPORT> ERROR */
		DBG_ERR("clamd: zSCAN: Error: %s\n", reply_msg);
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
					 "Scanner error: %s\t", reply_msg);
	} else {
		DBG_ERR("clamd: zSCAN: Invalid reply: %s\n", reply_token);
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
					 "Scanner communication error");
	}

virusfilter_clamav_scan_return:
	TALLOC_FREE(reply);
	if (report == NULL) {
		*reportp = talloc_asprintf(talloc_tos(),
					   "Scanner report memory error");
	} else {
		*reportp = report;
	}

	return result;
}

static struct virusfilter_backend_fns virusfilter_backend_clamav = {
	.connect = virusfilter_clamav_connect,
	.disconnect = NULL,
	.scan_init = virusfilter_clamav_scan_init,
	.scan = virusfilter_clamav_scan,
	.scan_end = virusfilter_clamav_scan_end,
};

int virusfilter_clamav_init(struct virusfilter_config *config)
{
	struct virusfilter_backend *backend = NULL;

	if (config->socket_path == NULL) {
		config->socket_path = VIRUSFILTER_DEFAULT_SOCKET_PATH;
	}

	backend = talloc_zero(config, struct virusfilter_backend);
	if (backend == NULL) {
		return -1;
	}

	backend->fns = &virusfilter_backend_clamav;
	backend->name = "clamav";

	config->backend = backend;
	return 0;
}
