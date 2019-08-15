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

#include "vfs_virusfilter_common.h"
#include "vfs_virusfilter_utils.h"

#ifdef FSAV_DEFAULT_SOCKET_PATH
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	FSAV_DEFAULT_SOCKET_PATH
#else
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	"/tmp/.fsav-0"
#endif

/* Default values for module-specific configuration variables */
/* 5 = F-Secure Linux 7 or later? */

#define VIRUSFILTER_DEFAULT_FSAV_PROTOCOL		5
#define VIRUSFILTER_DEFAULT_SCAN_RISKWARE		false
#define VIRUSFILTER_DEFAULT_STOP_SCAN_ON_FIRST		true
#define VIRUSFILTER_DEFAULT_FILTER_FILENAME		false

struct virusfilter_fsav_config {
	/* Backpointer */
	struct virusfilter_config *config;

	int fsav_protocol;
	bool scan_riskware;
	bool stop_scan_on_first;
	bool filter_filename;
};

static void virusfilter_fsav_scan_end(struct virusfilter_config *config);

static int virusfilter_fsav_destruct_config(
	struct virusfilter_fsav_config *fsav_config)
{
	virusfilter_fsav_scan_end(fsav_config->config);
	return 0;
}

static int virusfilter_fsav_connect(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const char *svc,
	const char *user)
{
	int snum = SNUM(handle->conn);
	struct virusfilter_fsav_config *fsav_config = NULL;

	fsav_config = talloc_zero(config->backend,
				  struct virusfilter_fsav_config);
	if (fsav_config == NULL) {
		return -1;
	}

	fsav_config->config = config;

	fsav_config->fsav_protocol = lp_parm_int(
		snum, "virusfilter", "fsav protocol",
		VIRUSFILTER_DEFAULT_FSAV_PROTOCOL);

	fsav_config->scan_riskware = lp_parm_bool(
		snum, "virusfilter", "scan riskware",
		VIRUSFILTER_DEFAULT_SCAN_RISKWARE);

	fsav_config->stop_scan_on_first = lp_parm_bool(
		snum, "virusfilter", "stop scan on first",
		VIRUSFILTER_DEFAULT_STOP_SCAN_ON_FIRST);

	fsav_config->filter_filename = lp_parm_bool(
		snum, "virusfilter", "filter filename",
		VIRUSFILTER_DEFAULT_FILTER_FILENAME);

	talloc_set_destructor(fsav_config, virusfilter_fsav_destruct_config);

	config->backend->backend_private = fsav_config;

	config->block_suspected_file = lp_parm_bool(
		snum, "virusfilter", "block suspected file", false);

	return 0;
}

static virusfilter_result virusfilter_fsav_scan_init(
	struct virusfilter_config *config)
{
	struct virusfilter_fsav_config *fsav_config = NULL;
	struct virusfilter_io_handle *io_h = config->io_h;
	char *reply = NULL;
	bool ok;
	int ret;

	fsav_config = talloc_get_type_abort(config->backend->backend_private,
					    struct virusfilter_fsav_config);

	if (io_h->stream != NULL) {
		DBG_DEBUG("fsavd: Checking if connection is alive\n");

		/* FIXME: I don't know the correct PING command format... */
		ok = virusfilter_io_writefl_readl(io_h, &reply, "PING");
		if (ok)	{
			ret = strncmp(reply, "ERROR\t", 6);
			if (ret == 0) {
				DBG_DEBUG("fsavd: Re-using existent "
					  "connection\n");
				goto virusfilter_fsav_init_succeed;
			}
		}

		DBG_DEBUG("fsavd: Closing dead connection\n");
		virusfilter_fsav_scan_end(config);
	}

	DBG_INFO("fsavd: Connecting to socket: %s\n",
		 config->socket_path);

	become_root();
	ok = virusfilter_io_connect_path(io_h, config->socket_path);
	unbecome_root();

	if (!ok) {
		DBG_ERR("fsavd: Connecting to socket failed: %s: %s\n",
			config->socket_path, strerror(errno));
		goto virusfilter_fsav_init_failed;
	}

	TALLOC_FREE(reply);

	ok = virusfilter_io_readl(talloc_tos(), io_h, &reply);
	if (!ok) {
		DBG_ERR("fsavd: Reading greeting message failed: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	ret = strncmp(reply, "DBVERSION\t", 10);
	if (ret != 0) {
		DBG_ERR("fsavd: Invalid greeting message: %s\n",
			reply);
		goto virusfilter_fsav_init_failed;
	}

	DBG_DEBUG("fsavd: Connected\n");

	DBG_INFO("fsavd: Configuring\n");

	TALLOC_FREE(reply);

	ok = virusfilter_io_writefl_readl(io_h, &reply, "PROTOCOL\t%d",
					  fsav_config->fsav_protocol);
	if (!ok) {
		DBG_ERR("fsavd: PROTOCOL: I/O error: %s\n", strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	ret = strncmp(reply, "OK\t", 3);
	if (ret != 0) {
		DBG_ERR("fsavd: PROTOCOL: Not accepted: %s\n",
			reply);
		goto virusfilter_fsav_init_failed;
	}

	TALLOC_FREE(reply);

	ok = virusfilter_io_writefl_readl(io_h, &reply,
					  "CONFIGURE\tSTOPONFIRST\t%d",
					  fsav_config->stop_scan_on_first ?
					  1 : 0);
	if (!ok) {
		DBG_ERR("fsavd: CONFIGURE STOPONFIRST: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	ret = strncmp(reply, "OK\t", 3);
	if (ret != 0) {
		DBG_ERR("fsavd: CONFIGURE STOPONFIRST: Not accepted: %s\n",
			reply);
		goto virusfilter_fsav_init_failed;
	}

	TALLOC_FREE(reply);

	ok = virusfilter_io_writefl_readl(io_h, &reply, "CONFIGURE\tFILTER\t%d",
					  fsav_config->filter_filename ? 1 : 0);
	if (!ok) {
		DBG_ERR("fsavd: CONFIGURE FILTER: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	ret = strncmp(reply, "OK\t", 3);
	if (ret != 0) {
		DBG_ERR("fsavd: CONFIGURE FILTER: Not accepted: %s\n",
			reply);
		goto virusfilter_fsav_init_failed;
	}

	TALLOC_FREE(reply);

	ok = virusfilter_io_writefl_readl(io_h, &reply,
					  "CONFIGURE\tARCHIVE\t%d",
					  config->scan_archive ? 1 : 0);
	if (!ok) {
		DBG_ERR("fsavd: CONFIGURE ARCHIVE: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	ret = strncmp(reply, "OK\t", 3);
	if (ret != 0) {
		DBG_ERR("fsavd: CONFIGURE ARCHIVE: Not accepted: %s\n",
			reply);
		goto virusfilter_fsav_init_failed;
	}

	TALLOC_FREE(reply);

	ok = virusfilter_io_writefl_readl(io_h, &reply,
					  "CONFIGURE\tMAXARCH\t%d",
					  config->max_nested_scan_archive);
	if (!ok) {
		DBG_ERR("fsavd: CONFIGURE MAXARCH: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	ret = strncmp(reply, "OK\t", 3);
	if (ret != 0) {
		DBG_ERR("fsavd: CONFIGURE MAXARCH: Not accepted: %s\n",
			reply);
		goto virusfilter_fsav_init_failed;
	}

	TALLOC_FREE(reply);

	ok = virusfilter_io_writefl_readl(io_h, &reply,
					  "CONFIGURE\tMIME\t%d",
					  config->scan_mime ? 1 : 0);
	if (!ok) {
		DBG_ERR("fsavd: CONFIGURE MIME: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	ret = strncmp(reply, "OK\t", 3);
	if (ret != 0) {
		DBG_ERR("fsavd: CONFIGURE MIME: Not accepted: %s\n",
			reply);
		goto virusfilter_fsav_init_failed;
	}

	TALLOC_FREE(reply);

	ok = virusfilter_io_writefl_readl(io_h, &reply, "CONFIGURE\tRISKWARE\t%d",
					  fsav_config->scan_riskware ? 1 : 0);
	if (!ok) {
		DBG_ERR("fsavd: CONFIGURE RISKWARE: I/O error: %s\n",
			strerror(errno));
		goto virusfilter_fsav_init_failed;
	}
	ret = strncmp(reply, "OK\t", 3);
	if (ret != 0) {
		DBG_ERR("fsavd: CONFIGURE RISKWARE: Not accepted: %s\n",
			reply);
		goto virusfilter_fsav_init_failed;
	}

	DBG_DEBUG("fsavd: Configured\n");

virusfilter_fsav_init_succeed:
	TALLOC_FREE(reply);
	return VIRUSFILTER_RESULT_OK;

virusfilter_fsav_init_failed:
	TALLOC_FREE(reply);
	virusfilter_fsav_scan_end(config);

	return VIRUSFILTER_RESULT_ERROR;
}

static void virusfilter_fsav_scan_end(struct virusfilter_config *config)
{
	struct virusfilter_io_handle *io_h = config->io_h;

	DBG_INFO("fsavd: Disconnecting\n");
	virusfilter_io_disconnect(io_h);
}

static virusfilter_result virusfilter_fsav_scan(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const struct files_struct *fsp,
	char **reportp)
{
	char *cwd_fname = fsp->conn->cwd_fsp->fsp_name->base_name;
	const char *fname = fsp->fsp_name->base_name;
	struct virusfilter_io_handle *io_h = config->io_h;
	virusfilter_result result = VIRUSFILTER_RESULT_CLEAN;
	char *report = NULL;
	char *reply = NULL;
	char *reply_token = NULL, *reply_saveptr = NULL;
	bool ok;

	DBG_INFO("Scanning file: %s/%s\n", cwd_fname, fname);

	ok = virusfilter_io_writevl(io_h, "SCAN\t", 5, cwd_fname,
				    (int)strlen(cwd_fname), "/", 1, fname,
				    (int)strlen(fname), NULL);
	if (!ok) {
		DBG_ERR("fsavd: SCAN: Write error: %s\n", strerror(errno));
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(),
					 "Scanner I/O error: %s\n",
					 strerror(errno));
		goto virusfilter_fsav_scan_return;
	}

	TALLOC_FREE(reply);

	for (;;) {
		if (virusfilter_io_readl(talloc_tos(), io_h, &reply) != true) {
			DBG_ERR("fsavd: SCANFILE: Read error: %s\n",
				strerror(errno));
			result = VIRUSFILTER_RESULT_ERROR;
			report = talloc_asprintf(talloc_tos(),
						 "Scanner I/O error: %s\n",
						 strerror(errno));
			break;
		}

		reply_token = strtok_r(reply, "\t", &reply_saveptr);

		if (strcmp(reply_token, "OK") == 0) {
			break;
		} else if (strcmp(reply_token, "CLEAN") == 0) {

			/* CLEAN\t<FILEPATH> */
			result = VIRUSFILTER_RESULT_CLEAN;
			report = talloc_asprintf(talloc_tos(), "Clean");
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
			if (reply_token != NULL) {
				  report = talloc_strdup(talloc_tos(),
							 reply_token);
			} else {
				  report = talloc_asprintf(talloc_tos(),
							"UNKNOWN INFECTION");
			}
		} else if (strcmp(reply_token, "OPEN_ARCHIVE") == 0) {

			/* Ignore */
		} else if (strcmp(reply_token, "CLOSE_ARCHIVE") == 0) {

			/* Ignore */
		} else if ((strcmp(reply_token, "SUSPECTED") == 0 ||
			   strcmp(reply_token, "ARCHIVE_SUSPECTED") == 0 ||
			   strcmp(reply_token, "MIME_SUSPECTED") == 0) &&
			   config->block_suspected_file)
		{
			result = VIRUSFILTER_RESULT_SUSPECTED;
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			reply_token = strtok_r(NULL, "\t", &reply_saveptr);
			if (reply_token != NULL) {
				  report = talloc_strdup(talloc_tos(),
							 reply_token);
			} else {
				  report = talloc_asprintf(talloc_tos(),
						"UNKNOWN REASON SUSPECTED");
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
			report = talloc_asprintf(talloc_tos(),
						 "Scanner communication error");
		}

		TALLOC_FREE(reply);
	}

virusfilter_fsav_scan_return:
	TALLOC_FREE(reply);

	if (report == NULL) {
		*reportp = talloc_asprintf(talloc_tos(), "Scanner report memory "
					   "error");
	} else {
		*reportp = report;
	}

	return result;
}

static struct virusfilter_backend_fns virusfilter_backend_fsav ={
	.connect = virusfilter_fsav_connect,
	.disconnect = NULL,
	.scan_init = virusfilter_fsav_scan_init,
	.scan = virusfilter_fsav_scan,
	.scan_end = virusfilter_fsav_scan_end,
};

int virusfilter_fsav_init(struct virusfilter_config *config)
{
	struct virusfilter_backend *backend = NULL;

	if (config->socket_path == NULL) {
		config->socket_path = VIRUSFILTER_DEFAULT_SOCKET_PATH;
	}

	backend = talloc_zero(config, struct virusfilter_backend);
	if (backend == NULL) {
		return -1;
	}

	backend->fns = &virusfilter_backend_fsav;
	backend->name = "fsav";

	config->backend = backend;
	return 0;
}
