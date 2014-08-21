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

#include "includes.h"
#include "librpc/gen_ndr/server_id.h"

bool server_id_same_process(const struct server_id *p1,
			    const struct server_id *p2)
{
	return ((p1->pid == p2->pid) && (p1->vnn == p2->vnn));
}

bool server_id_equal(const struct server_id *p1, const struct server_id *p2)
{
	if (!server_id_same_process(p1, p2)) {
		return false;
	}

	if (p1->task_id != p2->task_id) {
		return false;
	}

	if (p1->unique_id != p2->unique_id) {
		return false;
	}

	return true;
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

char *server_id_str(TALLOC_CTX *mem_ctx, const struct server_id *id)
{
	struct server_id_buf tmp;
	char *result;

	result = talloc_strdup(mem_ctx, server_id_str_buf(*id, &tmp));
	if (result == NULL) {
		return NULL;
	}

	/*
	 * beautify the talloc_report output
	 */
	talloc_set_name_const(result, result);
	return result;
}

struct server_id server_id_from_string(uint32_t local_vnn,
				       const char *pid_string)
{
	struct server_id result;
	unsigned long long pid;
	unsigned int vnn, task_id = 0;

	ZERO_STRUCT(result);

	/*
	 * We accept various forms with 1, 2 or 3 component forms
	 * because the server_id_str() can print different forms, and
	 * we want backwards compatibility for scripts that may call
	 * smbclient.
	 */
	if (sscanf(pid_string, "%u:%llu.%u", &vnn, &pid, &task_id) == 3) {
		result.vnn = vnn;
		result.pid = pid;
		result.task_id = task_id;
	} else if (sscanf(pid_string, "%u:%llu", &vnn, &pid) == 2) {
		result.vnn = vnn;
		result.pid = pid;
	} else if (sscanf(pid_string, "%llu.%u", &pid, &task_id) == 2) {
		result.vnn = local_vnn;
		result.pid = pid;
		result.task_id = task_id;
	} else if (sscanf(pid_string, "%llu", &pid) == 1) {
		result.vnn = local_vnn;
		result.pid = pid;
	} else if (strcmp(pid_string, "disconnected") ==0) {
		server_id_set_disconnected(&result);
	} else {
		result.vnn = NONCLUSTER_VNN;
		result.pid = UINT64_MAX;
	}
	return result;
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
