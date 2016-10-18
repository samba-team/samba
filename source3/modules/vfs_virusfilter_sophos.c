/*
   Samba-VirusFilter VFS modules
   Sophos Anti-Virus savdid (SSSP/1.0) support
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

#define VIRUSFILTER_ENGINE sophos
#define VIRUSFILTER_MODULE_ENGINE "sophos"

/* Default values for standard "extra" configuration variables */
#ifdef SOPHOS_DEFAULT_SOCKET_PATH
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	SOPHOS_DEFAULT_SOCKET_PATH
#else
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	"/var/run/savdi/sssp.sock"
#endif
#define VIRUSFILTER_DEFAULT_CONNECT_TIMEOUT	30000 /* msec */
#define VIRUSFILTER_DEFAULT_TIMEOUT		60000 /* msec */
#define VIRUSFILTER_DEFAULT_SCAN_REQUEST_LIMIT	0
#define VIRUSFILTER_DEFAULT_SCAN_ARCHIVE	false

#define virusfilter_module_connect		virusfilter_sophos_connect
#define virusfilter_module_scan_init		virusfilter_sophos_scan_init
#define virusfilter_module_scan_end		virusfilter_sophos_scan_end
#define virusfilter_module_scan			virusfilter_sophos_scan

#include "modules/vfs_virusfilter_vfs.c"

/* ====================================================================== */

#include "modules/vfs_virusfilter_utils.h"

/* ====================================================================== */

static int virusfilter_sophos_connect(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const char *svc,
	const char *user)
{
        virusfilter_io_set_readl_eol(virusfilter_h->io_h, "\x0D\x0A", 2);

	return 0;
}

static virusfilter_result virusfilter_sophos_scan_ping(
	virusfilter_handle *virusfilter_h)
{
	virusfilter_io_handle *io_h = virusfilter_h->io_h;

	/* SSSP/1.0 has no "PING" command */
	if (virusfilter_io_writel(io_h, "SSSP/1.0 OPTIONS\n", 17) !=
	    VIRUSFILTER_RESULT_OK)
	{
		return VIRUSFILTER_RESULT_ERROR;
	}

	for (;;) {
		if (virusfilter_io_readl(io_h) != VIRUSFILTER_RESULT_OK) {
			return VIRUSFILTER_RESULT_ERROR;
		}
		if (strcmp(io_h->r_buffer, "") == 0) {
			break;
		}
	}

	return VIRUSFILTER_RESULT_OK;
}

static virusfilter_result virusfilter_sophos_scan_init(
	virusfilter_handle *virusfilter_h)
{
	virusfilter_io_handle *io_h = virusfilter_h->io_h;
	virusfilter_result result;

	if (io_h->socket != -1) {
		DBG_DEBUG("SSSP: Checking if connection is alive\n");

		if (virusfilter_sophos_scan_ping(virusfilter_h) ==
		    VIRUSFILTER_RESULT_OK)
		{
			DBG_DEBUG("SSSP: Re-using existent connection\n");
			return VIRUSFILTER_RESULT_OK;
		}

		DBG_INFO("SSSP: Closing dead connection\n");
		virusfilter_sophos_scan_end(virusfilter_h);
	}


	DBG_INFO("SSSP: Connecting to socket: %s\n",
		virusfilter_h->socket_path);

	become_root();
	result = virusfilter_io_connect_path(io_h, virusfilter_h->socket_path);
	unbecome_root();

	if (result != VIRUSFILTER_RESULT_OK) {
		DBG_ERR("SSSP: Connecting to socket failed: %s: %s\n",
			virusfilter_h->socket_path, strerror(errno));
		return VIRUSFILTER_RESULT_ERROR;
	}

	if (virusfilter_io_readl(io_h) != VIRUSFILTER_RESULT_OK) {
		DBG_ERR("SSSP: Reading greeting message failed: %s\n",
			strerror(errno));
		goto virusfilter_sophos_scan_init_failed;
	}
	if (strncmp(io_h->r_buffer, "OK SSSP/1.0", 11) != 0) {
		DBG_ERR("SSSP: Invalid greeting message: %s\n",
			io_h->r_buffer);
		goto virusfilter_sophos_scan_init_failed;
	}

	DBG_DEBUG("SSSP: Connected\n");

	DBG_INFO("SSSP: Configuring\n");

	if (virusfilter_io_writefl_readl(io_h, "SSSP/1.0 OPTIONS\noutput:brief"
	    "\nsavigrp:GrpArchiveUnpack %d\n", virusfilter_h->scan_archive
	    ? 1 : 0) != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("SSSP: OPTIONS: I/O error: %s\n", strerror(errno));
		goto virusfilter_sophos_scan_init_failed;
	}
	if (strncmp(io_h->r_buffer, "ACC ", 4) != 0) {
		DBG_ERR("SSSP: OPTIONS: Not accepted: %s\n", io_h->r_buffer);
		goto virusfilter_sophos_scan_init_failed;
	}
	if (virusfilter_io_readl(io_h) != VIRUSFILTER_RESULT_OK) {
		DBG_ERR("SSSP: OPTIONS: Read error: %s\n", strerror(errno));
		goto virusfilter_sophos_scan_init_failed;
	}
	if (strncmp(io_h->r_buffer, "DONE OK ", 8) != 0) {
		DBG_ERR("SSSP: OPTIONS failed: %s\n", io_h->r_buffer);
		goto virusfilter_sophos_scan_init_failed;
	}
	if (virusfilter_io_readl(io_h) != VIRUSFILTER_RESULT_OK) {
		DBG_ERR("SSSP: OPTIONS: Read error: %s\n", strerror(errno));
		goto virusfilter_sophos_scan_init_failed;
	}
	if (strcmp(io_h->r_buffer, "") != 0) {
		DBG_ERR("SSSP: OPTIONS: Invalid reply: %s\n", io_h->r_buffer);
		goto virusfilter_sophos_scan_init_failed;
	}

	DBG_DEBUG("SSSP: Configured\n");

	return VIRUSFILTER_RESULT_OK;

virusfilter_sophos_scan_init_failed:

	virusfilter_sophos_scan_end(virusfilter_h);

	return VIRUSFILTER_RESULT_ERROR;
}

static void virusfilter_sophos_scan_end(virusfilter_handle *virusfilter_h)
{
	virusfilter_io_handle *io_h = virusfilter_h->io_h;

	DBG_INFO("SSSP: Disconnecting\n");

	virusfilter_io_disconnect(io_h);
}

static virusfilter_result virusfilter_sophos_scan(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const struct smb_filename *smb_fname,
	const char **reportp)
{
	const char *connectpath = vfs_h->conn->connectpath;
	const char *fname = smb_fname->base_name;
	char fileurl[VIRUSFILTER_IO_URL_MAX+1];
	int fileurl_len, fileurl_len2;
	virusfilter_io_handle *io_h = virusfilter_h->io_h;
	virusfilter_result result = VIRUSFILTER_RESULT_ERROR;
	const char *report = NULL;
	char *reply_token, *reply_saveptr;

	DBG_INFO("Scanning file: %s/%s\n", connectpath, fname);

	fileurl_len = virusfilter_url_quote(connectpath, fileurl,
					    VIRUSFILTER_IO_URL_MAX);
	if (fileurl_len < 0) {
		DBG_ERR("virusfilter_url_quote failed: File path too long: "
			"%s/%s\n", connectpath, fname);
		result = VIRUSFILTER_RESULT_ERROR;
		report = "File path too long";
		goto virusfilter_sophos_scan_return;
	}
	fileurl[fileurl_len] = '/';
	fileurl_len++;

	fileurl_len += fileurl_len2 = virusfilter_url_quote(fname,
		fileurl + fileurl_len, VIRUSFILTER_IO_URL_MAX - fileurl_len);
	if (fileurl_len2 < 0) {
		DBG_ERR("virusfilter_url_quote failed: File path too long: "
			"%s/%s\n", connectpath, fname);
		result = VIRUSFILTER_RESULT_ERROR;
		report = "File path too long";
		goto virusfilter_sophos_scan_return;
	}
	fileurl_len += fileurl_len2;

	if (virusfilter_io_writevl(io_h, "SSSP/1.0 SCANFILE ", 18, fileurl,
	    fileurl_len, NULL) != VIRUSFILTER_RESULT_OK)
	{
		DBG_ERR("SSSP: SCANFILE: Write error: %s\n",
		      strerror(errno));
		goto virusfilter_sophos_scan_io_error;
	}

	if (virusfilter_io_readl(io_h) != VIRUSFILTER_RESULT_OK) {
		DBG_ERR("SSSP: SCANFILE: Read error: %s\n", strerror(errno));
		goto virusfilter_sophos_scan_io_error;
	}
	if (strncmp(io_h->r_buffer, "ACC ", 4) != 0) {
		DBG_ERR("SSSP: SCANFILE: Not accepted: %s\n",
			io_h->r_buffer);
		result = VIRUSFILTER_RESULT_ERROR;
		goto virusfilter_sophos_scan_return;
	}

	result = VIRUSFILTER_RESULT_CLEAN;
	for (;;) {
		if (virusfilter_io_readl(io_h) != VIRUSFILTER_RESULT_OK) {
			DBG_ERR("SSSP: SCANFILE: Read error: %s\n",
				strerror(errno));
			goto virusfilter_sophos_scan_io_error;
		}

		if (strcmp(io_h->r_buffer, "") == 0) {
			break;
		}

		reply_token = strtok_r(io_h->r_buffer, " ", &reply_saveptr);

		if (strcmp(reply_token, "VIRUS") == 0) {
			result = VIRUSFILTER_RESULT_INFECTED;
			reply_token = strtok_r(NULL, " ", &reply_saveptr);
			if (reply_token) {
				  report = talloc_strdup(talloc_tos(),
							 reply_token);
			} else {
				  report = "UNKNOWN INFECTION";
			}
		} else if (strcmp(reply_token, "OK") == 0) {

			/* Ignore */
		} else if (strcmp(reply_token, "DONE") == 0) {
			reply_token = strtok_r(NULL, "", &reply_saveptr);
			if (reply_token &&

			    /* Succeed */
			    strncmp(reply_token, "OK 0000 ", 8) != 0 &&

			    /* Infected */
			    strncmp(reply_token, "OK 0203 ", 8) != 0)
			{
				DBG_ERR("SSSP: SCANFILE: Error: %s\n",
					reply_token);
				result = VIRUSFILTER_RESULT_ERROR;
				report = talloc_asprintf(talloc_tos(),
							 "Scanner error: %s\n",
							 reply_token);
			}
		} else {
			DBG_ERR("SSSP: SCANFILE: Invalid reply: %s\n",
				reply_token);
			result = VIRUSFILTER_RESULT_ERROR;
			report = "Scanner communication error";
		}
	}

virusfilter_sophos_scan_return:
	if (report == NULL) {
		*reportp = "Scanner report memory error";
	} else {
		*reportp = report;
	}

	return result;

virusfilter_sophos_scan_io_error:
	*reportp = talloc_asprintf(talloc_tos(),
				   "Scanner I/O error: %s\n", strerror(errno));
	if (reportp == NULL) {
		*reportp = "Scanner I/O error and unable to talloc\n";
	}

	return result;
}

