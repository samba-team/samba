/*
   Samba-VirusFilter VFS modules
   F-Secure Anti-Virus fsavd support
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

#define VIRUSFILTER_ENGINE fsav
#define VIRUSFILTER_MODULE_ENGINE "fsav"

/* Default values for standard "extra" configuration variables */
#define VIRUSFILTER_DEFAULT_SOCKET_PATH			"/tmp/.fsav-0"
#define VIRUSFILTER_DEFAULT_CONNECT_TIMEOUT		30000 /* msec */
#define VIRUSFILTER_DEFAULT_TIMEOUT			60000 /* msec */
#define VIRUSFILTER_DEFAULT_SCAN_ARCHIVE		false
#define VIRUSFILTER_DEFAULT_MAX_NESTED_SCAN_ARCHIVE	1
#define VIRUSFILTER_DEFAULT_SCAN_REQUEST_LIMIT		0
#define VIRUSFILTER_DEFAULT_SCAN_MIME			false
#define VIRUSFILTER_DEFAULT_BLOCK_SUSPECTED_FILE	false

/* Default values for module-specific configuration variables */
/* 5 = F-Secure Linux 7 or later? */
#define VIRUSFILTER_DEFAULT_FSAV_PROTOCOL		5
#define VIRUSFILTER_DEFAULT_SCAN_RISKWARE		false
#define VIRUSFILTER_DEFAULT_STOP_SCAN_ON_FIRST		true
#define VIRUSFILTER_DEFAULT_FILTER_FILENAME		false

#define VIRUSFILTER_MODULE_CONFIG_MEMBERS \
	int fsav_protocol; \
	bool scan_riskware; \
	bool stop_scan_on_first; \
	bool filter_filename; \
	/* End of VIRUSFILTER_MODULE_CONFIG_MEMBERS */

#define virusfilter_module_connect		virusfilter_fsav_connect
#define virusfilter_module_destruct_config	\
	virusfilter_fsav_destruct_config
#define virusfilter_module_scan_init		virusfilter_fsav_scan_init
#define virusfilter_module_scan_end		virusfilter_fsav_scan_end
#define virusfilter_module_scan			virusfilter_fsav_scan

#include "vfs_virusfilter_vfs.c"

/* ====================================================================== */

#include "vfs_virusfilter_utils.h"

/* ====================================================================== */

static int virusfilter_fsav_connect(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const char *svc,
	const char *user)
{
	int snum = SNUM(vfs_h->conn);

        virusfilter_h->fsav_protocol = lp_parm_int(snum,
		VIRUSFILTER_MODULE_NAME, "fsav protocol",
		VIRUSFILTER_DEFAULT_FSAV_PROTOCOL);

        virusfilter_h->scan_riskware = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "scan riskware",
		VIRUSFILTER_DEFAULT_SCAN_RISKWARE);

        virusfilter_h->stop_scan_on_first = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "stop scan on first",
		VIRUSFILTER_DEFAULT_STOP_SCAN_ON_FIRST);

        virusfilter_h->filter_filename = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "filter filename",
		VIRUSFILTER_DEFAULT_FILTER_FILENAME);

        virusfilter_h->block_suspected_file = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "block suspected file",
		VIRUSFILTER_DEFAULT_BLOCK_SUSPECTED_FILE);

	return 0;
}

static int virusfilter_fsav_destruct_config(
	virusfilter_handle *virusfilter_h)
{
	virusfilter_fsav_scan_end(virusfilter_h);

	return 0;
}

static virusfilter_result virusfilter_fsav_scan_init(
	virusfilter_handle *virusfilter_h)
{
	virusfilter_io_handle *io_h = virusfilter_h->io_h;
	virusfilter_result result;

	if (io_h->socket != -1) {
		DBG_DEBUG("fsavd: Checking if connection is alive\n");

		/* FIXME: I don't know the correct PING command format... */
		if (virusfilter_io_writefl_readl(io_h, "PING") ==
		    VIRUSFILTER_RESULT_OK)
		{
			if (strncmp(io_h->r_buffer, "ERROR\t", 6) == 0) {
				DBG_DEBUG("fsavd: Re-using existent "
					  "connection\n");
				return VIRUSFILTER_RESULT_OK;
			}
		}

		DBG_DEBUG("fsavd: Closing dead connection\n");
		virusfilter_fsav_scan_end(virusfilter_h);
	}

	DBG_INFO("fsavd: Connecting to socket: %s\n",
		 virusfilter_h->socket_path);

	become_root();
	result = virusfilter_io_connect_path(io_h, virusfilter_h->socket_path);
	unbecome_root();

	if (result != VIRUSFILTER_RESULT_OK) {
		DBG_ERR("fsavd: Connecting to socket failed: %s: %s\n",
			virusfilter_h->socket_path, strerror(errno));
		return VIRUSFILTER_RESULT_ERROR;
	}

	if (virusfilter_io_readl(io_h) != VIRUSFILTER_RESULT_OK) {
		DBG_ERR("fsavd: Reading greeting message failed: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	if (strncmp(io_h->r_buffer, "DBVERSION\t", 10) != 0) {
		DBG_ERR("fsavd: Invalid greeting message: %s\n",
			io_h->r_buffer);
		goto virusfilter_fsav_init_failed;
	}

	DBG_DEBUG("fsavd: Connected\n");

	DBG_INFO("fsavd: Configuring\n");

	if (virusfilter_io_writefl_readl(io_h,
	    "PROTOCOL\t%d", virusfilter_h->fsav_protocol)
	    != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("fsavd: PROTOCOL: I/O error: %s\n", strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	if (strncmp(io_h->r_buffer, "OK\t", 3) != 0) {
		DBG_ERR("fsavd: PROTOCOL: Not accepted: %s\n",
			io_h->r_buffer);
		goto virusfilter_fsav_init_failed;
	}

	if (virusfilter_io_writefl_readl(io_h,
	    "CONFIGURE\tSTOPONFIRST\t%d", virusfilter_h->stop_scan_on_first ?
	    1 : 0) != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("fsavd: CONFIGURE STOPONFIRST: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	if (strncmp(io_h->r_buffer, "OK\t", 3) != 0) {
		DBG_ERR("fsavd: CONFIGURE STOPONFIRST: Not accepted: %s\n",
			io_h->r_buffer);
		goto virusfilter_fsav_init_failed;
	}

	if (virusfilter_io_writefl_readl(io_h,
	    "CONFIGURE\tFILTER\t%d", virusfilter_h->filter_filename ? 1 : 0)
	    != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("fsavd: CONFIGURE FILTER: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	if (strncmp(io_h->r_buffer, "OK\t", 3) != 0) {
		DBG_ERR("fsavd: CONFIGURE FILTER: Not accepted: %s\n",
			io_h->r_buffer);
		goto virusfilter_fsav_init_failed;
	}

	if (virusfilter_io_writefl_readl(io_h,
	    "CONFIGURE\tARCHIVE\t%d", virusfilter_h->scan_archive ? 1 : 0)
	    != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("fsavd: CONFIGURE ARCHIVE: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	if (strncmp(io_h->r_buffer, "OK\t", 3) != 0) {
		DBG_ERR("fsavd: CONFIGURE ARCHIVE: Not accepted: %s\n",
			io_h->r_buffer);
		goto virusfilter_fsav_init_failed;
	}

	if (virusfilter_io_writefl_readl(io_h,
	    "CONFIGURE\tMAXARCH\t%d", virusfilter_h->max_nested_scan_archive)
	    != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("fsavd: CONFIGURE MAXARCH: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	if (strncmp(io_h->r_buffer, "OK\t", 3) != 0) {
		DBG_ERR("fsavd: CONFIGURE MAXARCH: Not accepted: %s\n",
			io_h->r_buffer);
		goto virusfilter_fsav_init_failed;
	}

	if (virusfilter_io_writefl_readl(io_h,
	    "CONFIGURE\tMIME\t%d", virusfilter_h->scan_mime ? 1 : 0)
	    != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("fsavd: CONFIGURE MIME: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	if (strncmp(io_h->r_buffer, "OK\t", 3) != 0) {
		DBG_ERR("fsavd: CONFIGURE MIME: Not accepted: %s\n",
			io_h->r_buffer);
		goto virusfilter_fsav_init_failed;
	}

	if (virusfilter_io_writefl_readl(io_h,
	    "CONFIGURE\tRISKWARE\t%d", virusfilter_h->scan_riskware ? 1 : 0)
	    != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("fsavd: CONFIGURE RISKWARE: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	if (strncmp(io_h->r_buffer, "OK\t", 3) != 0) {
		DBG_ERR("fsavd: CONFIGURE RISKWARE: Not accepted: %s\n",
			io_h->r_buffer);
		goto virusfilter_fsav_init_failed;
	}

	DBG_DEBUG("fsavd: Configured\n");

	return VIRUSFILTER_RESULT_OK;

virusfilter_fsav_init_failed:
	virusfilter_fsav_scan_end(virusfilter_h);

	return VIRUSFILTER_RESULT_ERROR;
}

static void virusfilter_fsav_scan_end(virusfilter_handle *virusfilter_h)
{
	virusfilter_io_handle *io_h = virusfilter_h->io_h;

	DBG_INFO("fsavd: Disconnecting\n");
	virusfilter_io_disconnect(io_h);
}

static virusfilter_result virusfilter_fsav_scan(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const struct smb_filename *smb_fname,
	const char **reportp)
{
	const char *connectpath = vfs_h->conn->connectpath;
	const char *fname = smb_fname->base_name;
	virusfilter_io_handle *io_h = virusfilter_h->io_h;
	virusfilter_result result = VIRUSFILTER_RESULT_CLEAN;
	const char *report = NULL;
	char *reply_token, *reply_saveptr;

	DBG_INFO("Scanning file: %s/%s\n", connectpath, fname);

	if (virusfilter_io_writevl(io_h, "SCAN\t", 5, connectpath,
	    (int)strlen(connectpath), "/", 1, fname, (int)strlen(fname), NULL)
	    != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("fsavd: SCAN: Write error: %s\n", strerror(errno));
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
					 "Scanner I/O error: %s\n",
					 strerror(errno));
		goto virusfilter_fsav_scan_return;
	}

	for (;;) {
		if (virusfilter_io_readl(io_h) != VIRUSFILTER_RESULT_OK) {
			DBG_ERR("fsavd: SCANFILE: Read error: %s\n",
				strerror(errno));
			result = VIRUSFILTER_RESULT_ERROR;
			report = talloc_asprintf(talloc_tos(),
						 "Scanner I/O error: %s\n",
						 strerror(errno));
			break;
		}

		reply_token = strtok_r(io_h->r_buffer, "\t", &reply_saveptr);

		if (strcmp(reply_token, "OK") == 0) {
			break;
		} else if (strcmp(reply_token, "CLEAN") == 0) {

			/* CLEAN\t<FILEPATH> */
			result = VIRUSFILTER_RESULT_CLEAN;
			report = "Clean";
		} else if (strcmp(reply_token, "INFECTED") == 0 ||
			   strcmp(reply_token, "ARCHIVE_INFECTED") == 0 ||
		           strcmp(reply_token, "MIME_INFECTED") == 0 ||
			   strcmp(reply_token, "RISKWARE") == 0 ||
			   strcmp(reply_token, "ARCHIVE_RISKWARE") == 0 ||
			   strcmp(reply_token, "MIME_RISKWARE") == 0)
		{

			/* INFECTED\t<FILEPATH>\t<REPORT>\t<ENGINE> */
			result = VIRUSFILTER_RESULT_INFECTED;
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			if (reply_token) {
				  report = talloc_strdup(talloc_tos(),
							 reply_token);
			} else {
				  report = "UNKNOWN INFECTION";
			}
		} else if (strcmp(reply_token, "OPEN_ARCHIVE") == 0) {

			/* Ignore */
		} else if (strcmp(reply_token, "CLOSE_ARCHIVE") == 0) {

			/* Ignore */
		} else if ((strcmp(reply_token, "SUSPECTED") == 0 ||
			   strcmp(reply_token, "ARCHIVE_SUSPECTED") == 0 ||
			   strcmp(reply_token, "MIME_SUSPECTED") == 0) &&
			   virusfilter_h->block_suspected_file)
		{
			result = VIRUSFILTER_RESULT_SUSPECTED;
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			if (reply_token) {
				  report = talloc_strdup(talloc_tos(),
							 reply_token);
			} else {
				  report = "UNKNOWN REASON SUSPECTED";
			}
		} else if (strcmp(reply_token, "SCAN_FAILURE") == 0) {

			/* SCAN_FAILURE\t<FILEPATH>\t0x<CODE>\t<REPORT> [<ENGINE>] */
			result = VIRUSFILTER_RESULT_ERROR;
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			DBG_ERR("fsavd: SCANFILE: Scaner error: %s\n",
				reply_token ? reply_token : "UNKNOWN ERROR");
			report = talloc_asprintf(talloc_tos(),
						 "Scanner error: %s",
						 reply_token ? reply_token :
						 "UNKNOWN ERROR");
		} else {
			result = VIRUSFILTER_RESULT_ERROR;
			DBG_ERR("fsavd: SCANFILE: Invalid reply: %s\t",
				reply_token);
			report = "Scanner communication error";
		}
	}

virusfilter_fsav_scan_return:
	if (report == NULL) {
		*reportp = "Scanner report memory error";
	} else {
		*reportp = report;
	}

	return result;
}

