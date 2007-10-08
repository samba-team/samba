/*
   Unix SMB/CIFS implementation.

   Async helpers for blocking functions

   Copyright (C) Volker Lendecke 2005
   Copyright (C) Gerald Carter 2006
   Copyright (C) Simo Sorce 2007

   The helpers always consist of three functions:

   * A request setup function that takes the necessary parameters together
     with a continuation function that is to be called upon completion

   * A private continuation function that is internal only. This is to be
     called by the lower-level functions in do_async(). Its only task is to
     properly call the continuation function named above.

   * A worker function that is called inside the appropriate child process.

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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static const struct winbindd_child_dispatch_table idmap_dispatch_table[];

static struct winbindd_child static_idmap_child;

void init_idmap_child(void)
{
	setup_domain_child(NULL,
			   &static_idmap_child,
			   idmap_dispatch_table,
			   "idmap");
}

struct winbindd_child *idmap_child(void)
{
	return &static_idmap_child;
}

static void winbindd_set_mapping_recv(TALLOC_CTX *mem_ctx, BOOL success,
				   struct winbindd_response *response,
				   void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ) = (void (*)(void *, BOOL))c;

	if (!success) {
		DEBUG(5, ("Could not trigger idmap_set_mapping\n"));
		cont(private_data, False);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("idmap_set_mapping returned an error\n"));
		cont(private_data, False);
		return;
	}

	cont(private_data, True);
}

void winbindd_set_mapping_async(TALLOC_CTX *mem_ctx, const struct id_map *map,
			     void (*cont)(void *private_data, BOOL success),
			     void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_SET_MAPPING;
	request.data.dual_idmapset.id = map->xid.id;
	request.data.dual_idmapset.type = map->xid.type;
	sid_to_string(request.data.dual_idmapset.sid, map->sid);

	do_async(mem_ctx, idmap_child(), &request, winbindd_set_mapping_recv,
		 (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_set_mapping(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state)
{
	struct id_map map;
	DOM_SID sid;
	NTSTATUS result;

	DEBUG(3, ("[%5lu]: dual_idmapset\n", (unsigned long)state->pid));

	if (!string_to_sid(&sid, state->request.data.dual_idmapset.sid))
		return WINBINDD_ERROR;

	map.sid = &sid;
	map.xid.id = state->request.data.dual_idmapset.id;
	map.xid.type = state->request.data.dual_idmapset.type;
	map.status = ID_MAPPED;

	result = idmap_set_mapping(&map);
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

static void winbindd_set_hwm_recv(TALLOC_CTX *mem_ctx, BOOL success,
				   struct winbindd_response *response,
				   void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ) = (void (*)(void *, BOOL))c;

	if (!success) {
		DEBUG(5, ("Could not trigger idmap_set_hwm\n"));
		cont(private_data, False);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("idmap_set_hwm returned an error\n"));
		cont(private_data, False);
		return;
	}

	cont(private_data, True);
}

void winbindd_set_hwm_async(TALLOC_CTX *mem_ctx, const struct unixid *xid,
			     void (*cont)(void *private_data, BOOL success),
			     void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_SET_HWM;
	request.data.dual_idmapset.id = xid->id;
	request.data.dual_idmapset.type = xid->type;

	do_async(mem_ctx, idmap_child(), &request, winbindd_set_hwm_recv,
		 (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_set_hwm(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state)
{
	struct unixid xid;
	NTSTATUS result;

	DEBUG(3, ("[%5lu]: dual_set_hwm\n", (unsigned long)state->pid));

	xid.id = state->request.data.dual_idmapset.id;
	xid.type = state->request.data.dual_idmapset.type;

	switch (xid.type) {
	case ID_TYPE_UID:
		result = idmap_set_uid_hwm(&xid);
		break;
	case ID_TYPE_GID:
		result = idmap_set_gid_hwm(&xid);
		break;
	default:
		return WINBINDD_ERROR;
	}
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

static void winbindd_sids2xids_recv(TALLOC_CTX *mem_ctx, BOOL success,
			       struct winbindd_response *response,
			       void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ, void *, int) =
		(void (*)(void *, BOOL, void *, int))c;

	if (!success) {
		DEBUG(5, ("Could not trigger sids2xids\n"));
		cont(private_data, False, NULL, 0);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("sids2xids returned an error\n"));
		cont(private_data, False, NULL, 0);
		return;
	}

	cont(private_data, True, response->extra_data.data, response->length - sizeof(response));
}

void winbindd_sids2xids_async(TALLOC_CTX *mem_ctx, void *sids, int size,
			 void (*cont)(void *private_data, BOOL success, void *data, int len),
			 void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_SIDS2XIDS;
	request.extra_data.data = (char *)sids;
	request.extra_len = size;
	do_async(mem_ctx, idmap_child(), &request, winbindd_sids2xids_recv,
		 (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_sids2xids(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state)
{
	DOM_SID *sids;
	struct unixid *xids;
	struct id_map **ids;
	NTSTATUS result;
	int num, i;

	DEBUG(3, ("[%5lu]: sids to unix ids\n", (unsigned long)state->pid));

	if (state->request.extra_len == 0) {
		DEBUG(0, ("Invalid buffer size!\n"));
		return WINBINDD_ERROR;
	}

	sids = (DOM_SID *)state->request.extra_data.data;
	num = state->request.extra_len / sizeof(DOM_SID);

	ids = TALLOC_ZERO_ARRAY(state->mem_ctx, struct id_map *, num + 1);
	if ( ! ids) {
		DEBUG(0, ("Out of memory!\n"));
		return WINBINDD_ERROR;
	}
	for (i = 0; i < num; i++) {
		ids[i] = TALLOC_P(ids, struct id_map);
		if ( ! ids[i]) {
			DEBUG(0, ("Out of memory!\n"));
			talloc_free(ids);
			return WINBINDD_ERROR;
		}
		ids[i]->sid = &sids[i];
	}

	result = idmap_sids_to_unixids(ids);

	if (NT_STATUS_IS_OK(result)) {

		xids = SMB_MALLOC_ARRAY(struct unixid, num);
		if ( ! xids) {
			DEBUG(0, ("Out of memory!\n"));
			talloc_free(ids);
			return WINBINDD_ERROR;
		}

		for (i = 0; i < num; i++) {
			if (ids[i]->status == ID_MAPPED) {
				xids[i].type = ids[i]->xid.type;
				xids[i].id = ids[i]->xid.id;
			} else {
				xids[i].type = -1;
			}
		}

		state->response.length = sizeof(state->response) + (sizeof(struct unixid) * num);
		state->response.extra_data.data = xids;

	} else {
		DEBUG (2, ("idmap_sids_to_unixids returned an error: 0x%08x\n", NT_STATUS_V(result)));
		talloc_free(ids);
		return WINBINDD_ERROR;
	}

	talloc_free(ids);
	return WINBINDD_OK;
}

static void winbindd_sid2uid_recv(TALLOC_CTX *mem_ctx, BOOL success,
			       struct winbindd_response *response,
			       void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ, uid_t uid) =
		(void (*)(void *, BOOL, uid_t))c;

	if (!success) {
		DEBUG(5, ("Could not trigger sid2uid\n"));
		cont(private_data, False, 0);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("sid2uid returned an error\n"));
		cont(private_data, False, 0);
		return;
	}

	cont(private_data, True, response->data.uid);
}

void winbindd_sid2uid_async(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
			 void (*cont)(void *private_data, BOOL success, uid_t uid),
			 void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_SID2UID;
	sid_to_string(request.data.dual_sid2id.sid, sid);
	do_async(mem_ctx, idmap_child(), &request, winbindd_sid2uid_recv,
		 (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_sid2uid(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state)
{
	DOM_SID sid;
	NTSTATUS result;

	DEBUG(3, ("[%5lu]: sid to uid %s\n", (unsigned long)state->pid,
		  state->request.data.dual_sid2id.sid));

	if (!string_to_sid(&sid, state->request.data.dual_sid2id.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request.data.dual_sid2id.sid));
		return WINBINDD_ERROR;
	}

	/* Find uid for this sid and return it, possibly ask the slow remote idmap */

	result = idmap_sid_to_uid(&sid, &(state->response.data.uid));

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

#if 0	/* not used */
static void uid2name_recv(TALLOC_CTX *mem_ctx, BOOL success,
			  struct winbindd_response *response,
			  void *c, void *private_data);

void winbindd_uid2name_async(TALLOC_CTX *mem_ctx, uid_t uid,
			     void (*cont)(void *private_data, BOOL success,
					  const char *name),
			     void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_UID2NAME;
	request.data.uid = uid;
	do_async(mem_ctx, idmap_child(), &request, uid2name_recv,
		 (void *)cont, private_data);
}
#endif	/* not used */

enum winbindd_result winbindd_dual_uid2name(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state)
{
	struct passwd *pw;

	DEBUG(3, ("[%5lu]: uid2name %lu\n", (unsigned long)state->pid,
		  (unsigned long)state->request.data.uid));

	pw = getpwuid(state->request.data.uid);
	if (pw == NULL) {
		DEBUG(5, ("User %lu not found\n",
			  (unsigned long)state->request.data.uid));
		return WINBINDD_ERROR;
	}

	fstrcpy(state->response.data.name.name, pw->pw_name);
	return WINBINDD_OK;
}

#if 0	/* not used */
static void uid2name_recv(TALLOC_CTX *mem_ctx, BOOL success,
			  struct winbindd_response *response,
			  void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ, const char *name) =
		(void (*)(void *, BOOL, const char *))c;

	if (!success) {
		DEBUG(5, ("Could not trigger uid2name\n"));
		cont(private_data, False, NULL);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("uid2name returned an error\n"));
		cont(private_data, False, NULL);
		return;
	}

	cont(private_data, True, response->data.name.name);
}

static void name2uid_recv(TALLOC_CTX *mem_ctx, BOOL success,
			  struct winbindd_response *response,
			  void *c, void *private_data);

static void winbindd_name2uid_async(TALLOC_CTX *mem_ctx, const char *name,
				    void (*cont)(void *private_data, BOOL success,
						 uid_t uid),
				    void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_NAME2UID;
	fstrcpy(request.data.username, name);
	do_async(mem_ctx, idmap_child(), &request, name2uid_recv,
		 (void *)cont, private_data);
}
#endif	/* not used */

enum winbindd_result winbindd_dual_name2uid(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state)
{
	struct passwd *pw;

	/* Ensure null termination */
	state->request.data.username
		[sizeof(state->request.data.username)-1] = '\0';

	DEBUG(3, ("[%5lu]: name2uid %s\n", (unsigned long)state->pid,
		  state->request.data.username));

	pw = getpwnam(state->request.data.username);
	if (pw == NULL) {
		return WINBINDD_ERROR;
	}

	state->response.data.uid = pw->pw_uid;
	return WINBINDD_OK;
}

#if 0	/* not used */
static void name2uid_recv(TALLOC_CTX *mem_ctx, BOOL success,
			  struct winbindd_response *response,
			  void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ, uid_t uid) =
		(void (*)(void *, BOOL, uid_t))c;

	if (!success) {
		DEBUG(5, ("Could not trigger name2uid\n"));
		cont(private_data, False, 0);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("name2uid returned an error\n"));
		cont(private_data, False, 0);
		return;
	}

	cont(private_data, True, response->data.uid);
}
#endif	/* not used */

static void winbindd_sid2gid_recv(TALLOC_CTX *mem_ctx, BOOL success,
			       struct winbindd_response *response,
			       void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ, gid_t gid) =
		(void (*)(void *, BOOL, gid_t))c;

	if (!success) {
		DEBUG(5, ("Could not trigger sid2gid\n"));
		cont(private_data, False, 0);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("sid2gid returned an error\n"));
		cont(private_data, False, 0);
		return;
	}

	cont(private_data, True, response->data.gid);
}

void winbindd_sid2gid_async(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
			 void (*cont)(void *private_data, BOOL success, gid_t gid),
			 void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_SID2GID;
	sid_to_string(request.data.dual_sid2id.sid, sid);

	DEBUG(7,("winbindd_sid2gid_async: Resolving %s to a gid\n",
		request.data.dual_sid2id.sid));

	do_async(mem_ctx, idmap_child(), &request, winbindd_sid2gid_recv,
		 (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_sid2gid(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state)
{
	DOM_SID sid;
	NTSTATUS result;

	DEBUG(3, ("[%5lu]: sid to gid %s\n", (unsigned long)state->pid,
		  state->request.data.dual_sid2id.sid));

	if (!string_to_sid(&sid, state->request.data.dual_sid2id.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request.data.dual_sid2id.sid));
		return WINBINDD_ERROR;
	}

	/* Find gid for this sid and return it, possibly ask the slow remote idmap */

	result = idmap_sid_to_gid(&sid, &state->response.data.gid);

	DEBUG(10, ("winbindd_dual_sid2gid: 0x%08x - %s - %u\n", NT_STATUS_V(result), sid_string_static(&sid), state->response.data.gid));

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

static void gid2name_recv(TALLOC_CTX *mem_ctx, BOOL success,
			  struct winbindd_response *response,
			  void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ, const char *name) =
		(void (*)(void *, BOOL, const char *))c;

	if (!success) {
		DEBUG(5, ("Could not trigger gid2name\n"));
		cont(private_data, False, NULL);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("gid2name returned an error\n"));
		cont(private_data, False, NULL);
		return;
	}

	cont(private_data, True, response->data.name.name);
}

void winbindd_gid2name_async(TALLOC_CTX *mem_ctx, gid_t gid,
			     void (*cont)(void *private_data, BOOL success,
					  const char *name),
			     void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_GID2NAME;
	request.data.gid = gid;
	do_async(mem_ctx, idmap_child(), &request, gid2name_recv,
		 (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_gid2name(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state)
{
	struct group *gr;

	DEBUG(3, ("[%5lu]: gid2name %lu\n", (unsigned long)state->pid,
		  (unsigned long)state->request.data.gid));

	gr = getgrgid(state->request.data.gid);
	if (gr == NULL)
		return WINBINDD_ERROR;

	fstrcpy(state->response.data.name.name, gr->gr_name);
	return WINBINDD_OK;
}

#if 0	/* not used */
static void name2gid_recv(TALLOC_CTX *mem_ctx, BOOL success,
			  struct winbindd_response *response,
			  void *c, void *private_data);

static void winbindd_name2gid_async(TALLOC_CTX *mem_ctx, const char *name,
				    void (*cont)(void *private_data, BOOL success,
						 gid_t gid),
				    void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_NAME2GID;
	fstrcpy(request.data.groupname, name);
	do_async(mem_ctx, idmap_child(), &request, name2gid_recv,
		 (void *)cont, private_data);
}
#endif	/* not used */

enum winbindd_result winbindd_dual_name2gid(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state)
{
	struct group *gr;

	/* Ensure null termination */
	state->request.data.groupname
		[sizeof(state->request.data.groupname)-1] = '\0';

	DEBUG(3, ("[%5lu]: name2gid %s\n", (unsigned long)state->pid,
		  state->request.data.groupname));

	gr = getgrnam(state->request.data.groupname);
	if (gr == NULL) {
		return WINBINDD_ERROR;
	}

	state->response.data.gid = gr->gr_gid;
	return WINBINDD_OK;
}

#if 0	/* not used */
static void name2gid_recv(TALLOC_CTX *mem_ctx, BOOL success,
			  struct winbindd_response *response,
			  void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ, gid_t gid) =
		(void (*)(void *, BOOL, gid_t))c;

	if (!success) {
		DEBUG(5, ("Could not trigger name2gid\n"));
		cont(private_data, False, 0);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("name2gid returned an error\n"));
		cont(private_data, False, 0);
		return;
	}

	cont(private_data, True, response->data.gid);
}
#endif	/* not used */

/* The following uid2sid/gid2sid functions has been contributed by
 * Keith Reynolds <Keith.Reynolds@centrify.com> */

static void winbindd_uid2sid_recv(TALLOC_CTX *mem_ctx, BOOL success,
				  struct winbindd_response *response,
				  void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ, const char *sid) =
		(void (*)(void *, BOOL, const char *))c;

	if (!success) {
		DEBUG(5, ("Could not trigger uid2sid\n"));
		cont(private_data, False, NULL);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("uid2sid returned an error\n"));
		cont(private_data, False, NULL);
		return;
	}

	cont(private_data, True, response->data.sid.sid);
}

void winbindd_uid2sid_async(TALLOC_CTX *mem_ctx, uid_t uid,
			    void (*cont)(void *private_data, BOOL success, const char *sid),
			    void *private_data)
{
	struct winbindd_request request;

	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_UID2SID;
	request.data.uid = uid;
	do_async(mem_ctx, idmap_child(), &request, winbindd_uid2sid_recv,
		 (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_uid2sid(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state)
{
	DOM_SID sid;
	NTSTATUS result;

	DEBUG(3,("[%5lu]: uid to sid %lu\n",
		 (unsigned long)state->pid,
		 (unsigned long) state->request.data.uid));

	/* Find sid for this uid and return it, possibly ask the slow remote idmap */
	result = idmap_uid_to_sid(&sid, state->request.data.uid);

	if (NT_STATUS_IS_OK(result)) {
		sid_to_string(state->response.data.sid.sid, &sid);
		state->response.data.sid.type = SID_NAME_USER;
		return WINBINDD_OK;
	}

	return WINBINDD_ERROR;
}

static void winbindd_gid2sid_recv(TALLOC_CTX *mem_ctx, BOOL success,
				  struct winbindd_response *response,
				  void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ, const char *sid) =
		(void (*)(void *, BOOL, const char *))c;

	if (!success) {
		DEBUG(5, ("Could not trigger gid2sid\n"));
		cont(private_data, False, NULL);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("gid2sid returned an error\n"));
		cont(private_data, False, NULL);
		return;
	}

	cont(private_data, True, response->data.sid.sid);
}

void winbindd_gid2sid_async(TALLOC_CTX *mem_ctx, gid_t gid,
			    void (*cont)(void *private_data, BOOL success, const char *sid),
			    void *private_data)
{
	struct winbindd_request request;

	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_GID2SID;
	request.data.gid = gid;
	do_async(mem_ctx, idmap_child(), &request, winbindd_gid2sid_recv,
		 (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_gid2sid(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state)
{
	DOM_SID sid;
	NTSTATUS result;

	DEBUG(3,("[%5lu]: gid %lu to sid\n",
		(unsigned long)state->pid,
		(unsigned long) state->request.data.gid));

	/* Find sid for this gid and return it, possibly ask the slow remote idmap */
	result = idmap_gid_to_sid(&sid, state->request.data.gid);

	if (NT_STATUS_IS_OK(result)) {
		sid_to_string(state->response.data.sid.sid, &sid);
		DEBUG(10, ("[%5lu]: retrieved sid: %s\n",
			   (unsigned long)state->pid,
			   state->response.data.sid.sid));
		state->response.data.sid.type = SID_NAME_DOM_GRP;
		return WINBINDD_OK;
	}

	return WINBINDD_ERROR;
}

static void winbindd_dump_id_maps_recv(TALLOC_CTX *mem_ctx, BOOL success,
			       struct winbindd_response *response,
			       void *c, void *private_data)
{
	void (*cont)(void *priv, BOOL succ) =
		(void (*)(void *, BOOL))c;

	if (!success) {
		DEBUG(5, ("Could not trigger a map dump\n"));
		cont(private_data, False);
		return;
	}

	if (response->result != WINBINDD_OK) {
		DEBUG(5, ("idmap dump maps returned an error\n"));
		cont(private_data, False);
		return;
	}

	cont(private_data, True);
}

void winbindd_dump_maps_async(TALLOC_CTX *mem_ctx, void *data, int size,
			 void (*cont)(void *private_data, BOOL success),
			 void *private_data)
{
	struct winbindd_request request;
	ZERO_STRUCT(request);
	request.cmd = WINBINDD_DUAL_DUMP_MAPS;
	request.extra_data.data = (char *)data;
	request.extra_len = size;
	do_async(mem_ctx, idmap_child(), &request, winbindd_dump_id_maps_recv,
		 (void *)cont, private_data);
}

enum winbindd_result winbindd_dual_dump_maps(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state)
{
	DEBUG(3, ("[%5lu]: dual dump maps\n", (unsigned long)state->pid));

	idmap_dump_maps((char *)state->request.extra_data.data);

	return WINBINDD_OK;
}

static const struct winbindd_child_dispatch_table idmap_dispatch_table[] = {

	{ WINBINDD_DUAL_SID2UID,         winbindd_dual_sid2uid,               "DUAL_SID2UID" },
	{ WINBINDD_DUAL_SID2GID,         winbindd_dual_sid2gid,               "DUAL_SID2GID" },
#if 0   /* DISABLED until we fix the interface in Samba 3.0.26 --jerry */
	{ WINBINDD_DUAL_SIDS2XIDS,       winbindd_dual_sids2xids,             "DUAL_SIDS2XIDS" },
#endif  /* end DISABLED */
	{ WINBINDD_DUAL_UID2SID,         winbindd_dual_uid2sid,               "DUAL_UID2SID" },
	{ WINBINDD_DUAL_GID2SID,         winbindd_dual_gid2sid,               "DUAL_GID2SID" },
	{ WINBINDD_DUAL_UID2NAME,        winbindd_dual_uid2name,              "DUAL_UID2NAME" },
	{ WINBINDD_DUAL_NAME2UID,        winbindd_dual_name2uid,              "DUAL_NAME2UID" },
	{ WINBINDD_DUAL_GID2NAME,        winbindd_dual_gid2name,              "DUAL_GID2NAME" },
	{ WINBINDD_DUAL_NAME2GID,        winbindd_dual_name2gid,              "DUAL_NAME2GID" },
	{ WINBINDD_DUAL_SET_MAPPING,     winbindd_dual_set_mapping,           "DUAL_SET_MAPPING" },
	{ WINBINDD_DUAL_SET_HWM,         winbindd_dual_set_hwm,               "DUAL_SET_HWMS" },
	{ WINBINDD_DUAL_DUMP_MAPS,       winbindd_dual_dump_maps,             "DUAL_DUMP_MAPS" },
	{ WINBINDD_ALLOCATE_UID,         winbindd_dual_allocate_uid,          "ALLOCATE_UID" },
	{ WINBINDD_ALLOCATE_GID,         winbindd_dual_allocate_gid,          "ALLOCATE_GID" },
	/* End of list */

	{ WINBINDD_NUM_CMDS, NULL, "NONE" }
};
