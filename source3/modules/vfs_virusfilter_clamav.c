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

#define VIRUSFILTER_ENGINE clamav
#define VIRUSFILTER_MODULE_ENGINE "clamav"

/* Default values for standard "extra" configuration variables */
#ifdef CLAMAV_DEFAULT_SOCKET_PATH
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	CLAMAV_DEFAULT_SOCKET_PATH
#else
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	"/var/run/clamav/clamd.ctl"
#endif
#define VIRUSFILTER_DEFAULT_CONNECT_TIMEOUT	30000 /* msec */
#define VIRUSFILTER_DEFAULT_TIMEOUT		60000 /* msec */

#define virusfilter_module_connect		virusfilter_clamav_connect
#define virusfilter_module_scan_init		virusfilter_clamav_scan_init
#define virusfilter_module_scan_end		virusfilter_clamav_scan_end
#define virusfilter_module_scan			virusfilter_clamav_scan

#include "modules/vfs_virusfilter_vfs.c"

/* ====================================================================== */

#include "modules/vfs_virusfilter_utils.h"

/* ====================================================================== */

static int virusfilter_clamav_connect(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const char *svc,
	const char *user)
{

	/* To use clamd "zXXXX" commands */
        virusfilter_io_set_writel_eol(virusfilter_h->io_h, "\0", 1);
        virusfilter_io_set_readl_eol(virusfilter_h->io_h, "\0", 1);

	return 0;
}

static virusfilter_result virusfilter_clamav_scan_init(
	virusfilter_handle *virusfilter_h)
{
	virusfilter_io_handle *io_h = virusfilter_h->io_h;
	virusfilter_result result;

	DBG_INFO("clamd: Connecting to socket: %s\n",
		 virusfilter_h->socket_path);

	become_root();
	result = virusfilter_io_connect_path(io_h, virusfilter_h->socket_path);
	unbecome_root();

	if (result != VIRUSFILTER_RESULT_OK) {
		DBG_ERR("clamd: Connecting to socket failed: %s: %s\n",
			virusfilter_h->socket_path, strerror(errno));
		return VIRUSFILTER_RESULT_ERROR;
	}

	DBG_INFO("clamd: Connected\n");

	return VIRUSFILTER_RESULT_OK;
}

static void virusfilter_clamav_scan_end(virusfilter_handle *virusfilter_h)
{
	virusfilter_io_handle *io_h = virusfilter_h->io_h;

	DBG_INFO("clamd: Disconnecting\n");

	virusfilter_io_disconnect(io_h);
}

static virusfilter_result virusfilter_clamav_scan(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const struct smb_filename *smb_fname,
	const char **reportp)
{
	const char *connectpath = vfs_h->conn->connectpath;
	const char *fname = smb_fname->base_name;
	size_t filepath_len = strlen(connectpath) + 1 /* slash */ + strlen(fname);
	virusfilter_io_handle *io_h = virusfilter_h->io_h;
	virusfilter_result result = VIRUSFILTER_RESULT_CLEAN;
	const char *report = NULL;
	char *reply;
	char *reply_token;

	DBG_INFO("Scanning file: %s/%s\n", connectpath, fname);

	if (virusfilter_io_writefl_readl(io_h, "zSCAN %s/%s",
	    connectpath, fname) != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("clamd: zSCAN: I/O error: %s\n", strerror(errno));
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
					 "Scanner I/O error: %s\n",
					 strerror(errno));
		goto virusfilter_clamav_scan_return;
	}

	if (io_h->r_buffer[filepath_len] != ':' ||
	    io_h->r_buffer[filepath_len+1] != ' ')
	{
		DBG_ERR("clamd: zSCAN: Invalid reply: %s\n",
			io_h->r_buffer);
		result = VIRUSFILTER_RESULT_ERROR;
		report = "Scanner communication error";
		goto virusfilter_clamav_scan_return;
	}
	reply = io_h->r_buffer + filepath_len + 2;

	reply_token = strrchr(io_h->r_buffer, ' ');
	if (!reply_token) {
		DBG_ERR("clamd: zSCAN: Invalid reply: %s\n",
			io_h->r_buffer);
		result = VIRUSFILTER_RESULT_ERROR;
		report = "Scanner communication error";
		goto virusfilter_clamav_scan_return;
	}
	*reply_token = '\0';
	reply_token++;

	if (strcmp(reply_token, "OK") == 0) {

		/* <FILEPATH>: OK */
		result = VIRUSFILTER_RESULT_CLEAN;
		report = "Clean";
	} else if (strcmp(reply_token, "FOUND") == 0) {

		/* <FILEPATH>: <REPORT> FOUND */
		result = VIRUSFILTER_RESULT_INFECTED;
		report = talloc_strdup(talloc_tos(), reply);
	} else if (strcmp(reply_token, "ERROR") == 0) {

		/* <FILEPATH>: <REPORT> ERROR */
		DBG_ERR("clamd: zSCAN: Error: %s\n", reply);
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
			"Scanner error: %s\t", reply);
	} else {
		DBG_ERR("clamd: zSCAN: Invalid reply: %s\n", reply_token);
		result = VIRUSFILTER_RESULT_ERROR;
		report = "Scanner communication error";
	}

virusfilter_clamav_scan_return:
	if (report == NULL) {
		*reportp = "Scanner report memory error";
	} else {
		*reportp = report;
	}

	return result;
}

