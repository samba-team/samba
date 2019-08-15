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

#include "vfs_virusfilter_common.h"
#include "vfs_virusfilter_utils.h"

/* Default values for standard "extra" configuration variables */
#ifdef SOPHOS_DEFAULT_SOCKET_PATH
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	SOPHOS_DEFAULT_SOCKET_PATH
#else
#  define VIRUSFILTER_DEFAULT_SOCKET_PATH	"/var/run/savdi/sssp.sock"
#endif

static void virusfilter_sophos_scan_end(struct virusfilter_config *config);

/* Python's urllib.quote(string[, safe]) clone */
static int virusfilter_url_quote(const char *src, char *dst, int dst_size)
{
	char *dst_c = dst;
	static char hex[] = "0123456789ABCDEF";

	for (; *src != '\0'; src++) {
		if ((*src < '0' && *src != '-' && *src != '.' && *src != '/') ||
		    (*src > '9' && *src < 'A') ||
		    (*src > 'Z' && *src < 'a' && *src != '_') ||
		    (*src > 'z'))
		{
			if (dst_size < 4) {
				return -1;
			}
			*dst_c++ = '%';
			*dst_c++ = hex[(*src >> 4) & 0x0F];
			*dst_c++ = hex[*src & 0x0F];
			dst_size -= 3;
		} else {
			if (dst_size < 2) {
				return -1;
			}
			*dst_c++ = *src;
			dst_size--;
		}
	}

	*dst_c = '\0';

	return (dst_c - dst);
}

static int virusfilter_sophos_connect(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const char *svc,
	const char *user)
{
	virusfilter_io_set_readl_eol(config->io_h, "\x0D\x0A", 2);

	return 0;
}

static virusfilter_result virusfilter_sophos_scan_ping(
	struct virusfilter_config *config)
{
	struct virusfilter_io_handle *io_h = config->io_h;
	char *reply = NULL;
	bool ok;
	int ret;

	/* SSSP/1.0 has no "PING" command */
	ok = virusfilter_io_writel(io_h, "SSSP/1.0 OPTIONS\n", 17);
	if (!ok) {
		return VIRUSFILTER_RESULT_ERROR;
	}

	for (;;) {
		ok = virusfilter_io_readl(talloc_tos(), io_h, &reply);
		if (!ok) {
			return VIRUSFILTER_RESULT_ERROR;
		}
		ret = strcmp(reply, "");
		if (ret == 0) {
			break;
		}
		TALLOC_FREE(reply);
	}

	TALLOC_FREE(reply);
	return VIRUSFILTER_RESULT_OK;
}

static virusfilter_result virusfilter_sophos_scan_init(
	struct virusfilter_config *config)
{
	struct virusfilter_io_handle *io_h = config->io_h;
	char *reply = NULL;
	int ret;
	bool ok;

	if (io_h->stream != NULL) {
		DBG_DEBUG("SSSP: Checking if connection is alive\n");

		ret = virusfilter_sophos_scan_ping(config);
		if (ret == VIRUSFILTER_RESULT_OK)
		{
			DBG_DEBUG("SSSP: Re-using existent connection\n");
			return VIRUSFILTER_RESULT_OK;
		}

		DBG_INFO("SSSP: Closing dead connection\n");
		virusfilter_sophos_scan_end(config);
	}


	DBG_INFO("SSSP: Connecting to socket: %s\n",
		config->socket_path);

	become_root();
	ok = virusfilter_io_connect_path(io_h, config->socket_path);
	unbecome_root();

	if (!ok) {
		DBG_ERR("SSSP: Connecting to socket failed: %s: %s\n",
			config->socket_path, strerror(errno));
		return VIRUSFILTER_RESULT_ERROR;
	}

	ok = virusfilter_io_readl(talloc_tos(), io_h, &reply);
	if (!ok) {
		DBG_ERR("SSSP: Reading greeting message failed: %s\n",
			strerror(errno));
		goto virusfilter_sophos_scan_init_failed;
	}
	ret = strncmp(reply, "OK SSSP/1.0", 11);
	if (ret != 0) {
		DBG_ERR("SSSP: Invalid greeting message: %s\n",
			reply);
		goto virusfilter_sophos_scan_init_failed;
	}

	DBG_DEBUG("SSSP: Connected\n");

	DBG_INFO("SSSP: Configuring\n");

	TALLOC_FREE(reply);

	ok = virusfilter_io_writefl_readl(io_h, &reply,
	    "SSSP/1.0 OPTIONS\noutput:brief\nsavigrp:GrpArchiveUnpack %d\n",
	    config->scan_archive ? 1 : 0);
	if (!ok) {
		DBG_ERR("SSSP: OPTIONS: I/O error: %s\n", strerror(errno));
		goto virusfilter_sophos_scan_init_failed;
	}
	ret = strncmp(reply, "ACC ", 4);
	if (ret != 0) {
		DBG_ERR("SSSP: OPTIONS: Not accepted: %s\n", reply);
		goto virusfilter_sophos_scan_init_failed;
	}

	TALLOC_FREE(reply);

	ok = virusfilter_io_readl(talloc_tos(), io_h, &reply);
	if (!ok) {
		DBG_ERR("SSSP: OPTIONS: Read error: %s\n", strerror(errno));
		goto virusfilter_sophos_scan_init_failed;
	}
	ret = strncmp(reply, "DONE OK ", 8);
	if (ret != 0) {
		DBG_ERR("SSSP: OPTIONS failed: %s\n", reply);
		goto virusfilter_sophos_scan_init_failed;
	}

	TALLOC_FREE(reply);

	ok = virusfilter_io_readl(talloc_tos(), io_h, &reply);
	if (!ok) {
		DBG_ERR("SSSP: OPTIONS: Read error: %s\n", strerror(errno));
		goto virusfilter_sophos_scan_init_failed;
	}
	ret = strcmp(reply, "");
	if (ret != 0) {
		DBG_ERR("SSSP: OPTIONS: Invalid reply: %s\n", reply);
		goto virusfilter_sophos_scan_init_failed;
	}

	DBG_DEBUG("SSSP: Configured\n");

	return VIRUSFILTER_RESULT_OK;

virusfilter_sophos_scan_init_failed:

	TALLOC_FREE(reply);

	virusfilter_sophos_scan_end(config);

	return VIRUSFILTER_RESULT_ERROR;
}

static void virusfilter_sophos_scan_end(
	struct virusfilter_config *config)
{
	struct virusfilter_io_handle *io_h = config->io_h;

	DBG_INFO("SSSP: Disconnecting\n");

	virusfilter_io_disconnect(io_h);
}

static virusfilter_result virusfilter_sophos_scan(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const struct files_struct *fsp,
	char **reportp)
{
	char *cwd_fname = fsp->conn->cwd_fsp->fsp_name->base_name;
	const char *fname = fsp->fsp_name->base_name;
	char fileurl[VIRUSFILTER_IO_URL_MAX+1];
	int fileurl_len, fileurl_len2;
	struct virusfilter_io_handle *io_h = config->io_h;
	virusfilter_result result = VIRUSFILTER_RESULT_ERROR;
	char *report = NULL;
	char *reply = NULL;
	char *reply_token = NULL, *reply_saveptr = NULL;
	int ret;
	bool ok;

	DBG_INFO("Scanning file: %s/%s\n", cwd_fname, fname);

	fileurl_len = virusfilter_url_quote(cwd_fname, fileurl,
					    VIRUSFILTER_IO_URL_MAX);
	if (fileurl_len < 0) {
		DBG_ERR("virusfilter_url_quote failed: File path too long: "
			"%s/%s\n", cwd_fname, fname);
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(), "File path too long");
		goto virusfilter_sophos_scan_return;
	}
	fileurl[fileurl_len] = '/';
	fileurl_len++;

	fileurl_len += fileurl_len2 = virusfilter_url_quote(fname,
		fileurl + fileurl_len, VIRUSFILTER_IO_URL_MAX - fileurl_len);
	if (fileurl_len2 < 0) {
		DBG_ERR("virusfilter_url_quote failed: File path too long: "
			"%s/%s\n", cwd_fname, fname);
		result = VIRUSFILTER_RESULT_ERROR;
		report = talloc_asprintf(talloc_tos(), "File path too long");
		goto virusfilter_sophos_scan_return;
	}
	fileurl_len += fileurl_len2;

	ok = virusfilter_io_writevl(io_h, "SSSP/1.0 SCANFILE ", 18, fileurl,
				    fileurl_len, NULL);
	if (!ok) {
		DBG_ERR("SSSP: SCANFILE: Write error: %s\n",
		      strerror(errno));
		goto virusfilter_sophos_scan_io_error;
	}

	ok = virusfilter_io_readl(talloc_tos(), io_h, &reply);
	if (!ok) {
		DBG_ERR("SSSP: SCANFILE: Read error: %s\n", strerror(errno));
		goto virusfilter_sophos_scan_io_error;
	}
	ret = strncmp(reply, "ACC ", 4);
	if (ret != 0) {
		DBG_ERR("SSSP: SCANFILE: Not accepted: %s\n",
			reply);
		result = VIRUSFILTER_RESULT_ERROR;
		goto virusfilter_sophos_scan_return;
	}

	TALLOC_FREE(reply);

	result = VIRUSFILTER_RESULT_CLEAN;
	for (;;) {
		ok = virusfilter_io_readl(talloc_tos(), io_h, &reply);
		if (!ok) {
			DBG_ERR("SSSP: SCANFILE: Read error: %s\n",
				strerror(errno));
			goto virusfilter_sophos_scan_io_error;
		}

		ret = strcmp(reply, "");
		if (ret == 0) {
			break;
		}

		reply_token = strtok_r(reply, " ", &reply_saveptr);

		if (strcmp(reply_token, "VIRUS") == 0) {
			result = VIRUSFILTER_RESULT_INFECTED;
			reply_token = strtok_r(NULL, " ", &reply_saveptr);
			if (reply_token != NULL) {
				  report = talloc_strdup(talloc_tos(),
							 reply_token);
			} else {
				  report = talloc_asprintf(talloc_tos(),
							"UNKNOWN INFECTION");
			}
		} else if (strcmp(reply_token, "OK") == 0) {

			/* Ignore */
		} else if (strcmp(reply_token, "DONE") == 0) {
			reply_token = strtok_r(NULL, "", &reply_saveptr);
			if (reply_token != NULL &&

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
			report = talloc_asprintf(talloc_tos(), "Scanner "
						 "communication error");
		}

		TALLOC_FREE(reply);
	}

virusfilter_sophos_scan_return:
	TALLOC_FREE(reply);

	if (report == NULL) {
		*reportp = talloc_asprintf(talloc_tos(),
					   "Scanner report memory error");
	} else {
		*reportp = report;
	}

	return result;

virusfilter_sophos_scan_io_error:
	*reportp = talloc_asprintf(talloc_tos(),
				   "Scanner I/O error: %s\n", strerror(errno));

	return result;
}

static struct virusfilter_backend_fns virusfilter_backend_sophos ={
	.connect = virusfilter_sophos_connect,
	.disconnect = NULL,
	.scan_init = virusfilter_sophos_scan_init,
	.scan = virusfilter_sophos_scan,
	.scan_end = virusfilter_sophos_scan_end,
};

int virusfilter_sophos_init(struct virusfilter_config *config)
{
	struct virusfilter_backend *backend = NULL;

	if (config->socket_path == NULL) {
		config->socket_path = VIRUSFILTER_DEFAULT_SOCKET_PATH;
	}

	backend = talloc_zero(config, struct virusfilter_backend);
	if (backend == NULL) {
		return -1;
	}

	backend->fns = &virusfilter_backend_sophos;
	backend->name = "sophos";

	config->backend = backend;
	return 0;
}
