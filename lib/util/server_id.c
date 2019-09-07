/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Bartlett 2011

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

#include "replace.h"
#include "lib/util/debug.h"
#include "lib/util/fault.h"
#include "lib/util/server_id.h"
#include "lib/util/byteorder.h"
#include "librpc/gen_ndr/server_id.h"

bool server_id_same_process(const struct server_id *p1,
			    const struct server_id *p2)
{
	return ((p1->pid == p2->pid) && (p1->vnn == p2->vnn));
}

int server_id_cmp(const struct server_id *p1, const struct server_id *p2)
{
	if (p1->vnn != p2->vnn) {
		return (p1->vnn < p2->vnn) ? -1 : 1;
	}
	if (p1->pid != p2->pid) {
		return (p1->pid < p2->pid) ? -1 : 1;
	}
	if (p1->task_id != p2->task_id) {
		return (p1->task_id < p2->task_id) ? -1 : 1;
	}
	if (p1->unique_id != p2->unique_id) {
		return (p1->unique_id < p2->unique_id) ? -1 : 1;
	}
	return 0;
}

bool server_id_equal(const struct server_id *p1, const struct server_id *p2)
{
	int cmp = server_id_cmp(p1, p2);
	return (cmp == 0);
}

char *server_id_str_buf(struct server_id id, struct server_id_buf *dst)
{
	if (server_id_is_disconnected(&id)) {
		strlcpy(dst->buf, "disconnected", sizeof(dst->buf));
	} else if ((id.vnn == NONCLUSTER_VNN) && (id.task_id == 0)) {
		snprintf(dst->buf, sizeof(dst->buf), "%llu",
			 (unsigned long long)id.pid);
	} else if (id.vnn == NONCLUSTER_VNN) {
		snprintf(dst->buf, sizeof(dst->buf), "%llu.%u",
			 (unsigned long long)id.pid, (unsigned)id.task_id);
	} else if (id.task_id == 0) {
		snprintf(dst->buf, sizeof(dst->buf), "%u:%llu",
			 (unsigned)id.vnn, (unsigned long long)id.pid);
	} else {
		snprintf(dst->buf, sizeof(dst->buf), "%u:%llu.%u",
			 (unsigned)id.vnn,
			 (unsigned long long)id.pid,
			 (unsigned)id.task_id);
	}
	return dst->buf;
}

size_t server_id_str_buf_unique(struct server_id id, char *buf, size_t buflen)
{
	struct server_id_buf idbuf;
	char unique_buf[21];	/* 2^64 is 18446744073709551616, 20 chars */
	size_t idlen, unique_len, needed;

	server_id_str_buf(id, &idbuf);

	idlen = strlen(idbuf.buf);
	unique_len = snprintf(unique_buf, sizeof(unique_buf), "%"PRIu64,
			      id.unique_id);
	needed = idlen + unique_len + 2;

	if (buflen >= needed) {
		memcpy(buf, idbuf.buf, idlen);
		buf[idlen] = '/';
		memcpy(buf + idlen + 1, unique_buf, unique_len+1);
	}

	return needed;
}

struct server_id server_id_from_string(uint32_t local_vnn,
				       const char *pid_string)
{
	struct server_id templ = {
		.vnn = NONCLUSTER_VNN, .pid = UINT64_MAX
	};
	struct server_id result;
	int ret;

	/*
	 * We accept various forms with 1, 2 or 3 component forms
	 * because the server_id_str_buf() can print different forms, and
	 * we want backwards compatibility for scripts that may call
	 * smbclient.
	 */

	result = templ;
	ret = sscanf(pid_string, "%"SCNu32":%"SCNu64".%"SCNu32"/%"SCNu64,
		     &result.vnn, &result.pid, &result.task_id,
		     &result.unique_id);
	if (ret == 4) {
		return result;
	}

	result = templ;
	ret = sscanf(pid_string, "%"SCNu32":%"SCNu64".%"SCNu32,
		     &result.vnn, &result.pid, &result.task_id);
	if (ret == 3) {
		return result;
	}

	result = templ;
	ret = sscanf(pid_string, "%"SCNu32":%"SCNu64"/%"SCNu64,
		     &result.vnn, &result.pid, &result.unique_id);
	if (ret == 3) {
		return result;
	}

	result = templ;
	ret = sscanf(pid_string, "%"SCNu32":%"SCNu64,
		     &result.vnn, &result.pid);
	if (ret == 2) {
		return result;
	}

	result = templ;
	ret = sscanf(pid_string, "%"SCNu64".%"SCNu32"/%"SCNu64,
		     &result.pid, &result.task_id, &result.unique_id);
	if (ret == 3) {
		result.vnn = local_vnn;
		return result;
	}

	result = templ;
	ret = sscanf(pid_string, "%"SCNu64".%"SCNu32,
		     &result.pid, &result.task_id);
	if (ret == 2) {
		result.vnn = local_vnn;
		return result;
	}

	result = templ;
	ret = sscanf(pid_string, "%"SCNu64"/%"SCNu64,
		     &result.pid, &result.unique_id);
	if (ret == 2) {
		result.vnn = local_vnn;
		return result;
	}

	result = templ;
	ret = sscanf(pid_string, "%"SCNu64, &result.pid);
	if (ret == 1) {
		result.vnn = local_vnn;
		return result;
	}

	if (strcmp(pid_string, "disconnected") == 0) {
		server_id_set_disconnected(&result);
		return result;
	}

	return templ;
}

/**
 * Set the serverid to the special value that represents a disconnected
 * client for (e.g.) durable handles.
 */
void server_id_set_disconnected(struct server_id *id)
{
	SMB_ASSERT(id != NULL);

	id->pid = UINT64_MAX;
	id->task_id = UINT32_MAX;
	id->vnn = NONCLUSTER_VNN;
	id->unique_id = SERVERID_UNIQUE_ID_NOT_TO_VERIFY;

	return;
}

/**
 * check whether a serverid is the special placeholder for
 * a disconnected client
 */
bool server_id_is_disconnected(const struct server_id *id)
{
	struct server_id dis;

	SMB_ASSERT(id != NULL);

	server_id_set_disconnected(&dis);

	return server_id_equal(id, &dis);
}

void server_id_put(uint8_t buf[SERVER_ID_BUF_LENGTH],
		   const struct server_id id)
{
	SBVAL(buf, 0,  id.pid);
	SIVAL(buf, 8,  id.task_id);
	SIVAL(buf, 12, id.vnn);
	SBVAL(buf, 16, id.unique_id);
}

void server_id_get(struct server_id *id,
		   const uint8_t buf[SERVER_ID_BUF_LENGTH])
{
	id->pid       = BVAL(buf, 0);
	id->task_id   = IVAL(buf, 8);
	id->vnn       = IVAL(buf, 12);
	id->unique_id = BVAL(buf, 16);
}
