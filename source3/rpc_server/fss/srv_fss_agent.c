/*
 * File Server Remote VSS Protocol (FSRVP) server
 *
 * Copyright (C) David Disseldorp	2012-2015
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "ntdomain.h"
#include "include/messages.h"
#include "serverid.h"
#include "include/auth.h"
#include "../libcli/security/security.h"
#include "../libcli/util/hresult.h"
#include "../lib/smbconf/smbconf.h"
#include "smbd/proto.h"
#include "lib/smbconf/smbconf_init.h"
#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_fsrvp_scompat.h"
#include "librpc/gen_ndr/ndr_fsrvp.h"
#include "rpc_server/rpc_server.h"
#include "srv_fss_private.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static struct fss_global fss_global;

/* errmap NTSTATUS->fsrvp */
static const struct {
	NTSTATUS status;
	uint32_t fsrvp_err;
} ntstatus_to_fsrvp_map[] = {
	{NT_STATUS_INVALID_SERVER_STATE, FSRVP_E_BAD_STATE},
	{NT_STATUS_INVALID_DISPOSITION, FSRVP_E_SHADOW_COPY_SET_IN_PROGRESS},
	{NT_STATUS_NOT_SUPPORTED, FSRVP_E_NOT_SUPPORTED},
	{NT_STATUS_IO_TIMEOUT, FSRVP_E_WAIT_TIMEOUT},
	{NT_STATUS_CANT_WAIT, FSRVP_E_WAIT_FAILED},
	{NT_STATUS_OBJECTID_EXISTS, FSRVP_E_OBJECT_ALREADY_EXISTS},
	{NT_STATUS_OBJECTID_NOT_FOUND, FSRVP_E_OBJECT_NOT_FOUND},
	{NT_STATUS_OBJECT_NAME_INVALID, FSRVP_E_BAD_ID},
};

/* errmap NTSTATUS->hresult */
static const struct {
	NTSTATUS status;
	HRESULT hres;
} ntstatus_to_hres_map[] = {
	{NT_STATUS_ACCESS_DENIED, HRES_E_ACCESSDENIED},
	{NT_STATUS_INVALID_PARAMETER, HRES_E_INVALIDARG},
	{NT_STATUS_NO_MEMORY, HRES_E_OUTOFMEMORY},
};

static uint32_t fss_ntstatus_map(NTSTATUS status)
{
	size_t i;

	if (NT_STATUS_IS_OK(status))
		return 0;

	/* check fsrvp specific errors first */
	for (i = 0; i < ARRAY_SIZE(ntstatus_to_fsrvp_map); i++) {
		if (NT_STATUS_EQUAL(status, ntstatus_to_fsrvp_map[i].status)) {
			return ntstatus_to_fsrvp_map[i].fsrvp_err;
		}
	}
	/* fall-back to generic hresult values */
	for (i = 0; i < ARRAY_SIZE(ntstatus_to_hres_map); i++) {
		if (NT_STATUS_EQUAL(status, ntstatus_to_hres_map[i].status)) {
			return HRES_ERROR_V(ntstatus_to_hres_map[i].hres);
		}
	}

	return HRES_ERROR_V(HRES_E_FAIL);
}

static NTSTATUS fss_unc_parse(TALLOC_CTX *mem_ctx,
			      const char *unc,
			      char **_server,
			      char **_share)
{
	char *s;
	char *server;
	char *share;

	if (unc == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = strstr_m(unc, "\\\\");
	if (s == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	server = talloc_strdup(mem_ctx, s + 2);
	if (server == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	s = strchr_m(server, '\\');
	if ((s == NULL) || (s == server)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	*s = '\0';
	share = s + 1;

	s = strchr_m(share, '\\');
	if (s != NULL) {
		/* diskshadow.exe adds a trailing '\' to the share-name */
		*s = '\0';
	}
	if (strlen(share) == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (_server != NULL) {
		*_server = server;
	}
	if (_share != NULL) {
		*_share = share;
	}

	return NT_STATUS_OK;
}

static NTSTATUS fss_conn_create_tos(struct messaging_context *msg_ctx,
				    struct auth_session_info *session_info,
				    int snum,
				    struct connection_struct **conn_out);

/* test if system path exists */
static bool snap_path_exists(TALLOC_CTX *ctx, struct messaging_context *msg_ctx,
			     struct fss_sc *sc)
{
	TALLOC_CTX *frame = talloc_stackframe();
	SMB_STRUCT_STAT st;
	struct connection_struct *conn = NULL;
	struct smb_filename *smb_fname = NULL;
	char *service = NULL;
	char *share;
	int snum;
	int ret;
	NTSTATUS status;
	bool result = false;

	ZERO_STRUCT(st);

	if ((sc->smaps_count == 0) || (sc->sc_path == NULL)) {
		goto out;
	}

	share = sc->smaps->share_name;
	snum = find_service(frame, share, &service);

	if ((snum == -1) || (service == NULL)) {
		goto out;
	}

	status = fss_conn_create_tos(msg_ctx, NULL, snum, &conn);
	if(!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	smb_fname = synthetic_smb_fname(service,
					sc->sc_path,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		goto out;
	}

	ret = SMB_VFS_STAT(conn, smb_fname);
	if ((ret == -1) && (errno == ENOENT)) {
		goto out;
	}
	result = true;
out:
	TALLOC_FREE(frame);
	return result;
}

static NTSTATUS sc_smap_unexpose(struct messaging_context *msg_ctx,
				 struct fss_sc_smap *sc_smap, bool delete_all);

static NTSTATUS fss_prune_stale(struct messaging_context *msg_ctx,
				const char *db_path)
{
	struct fss_sc_set *sc_sets;
	uint32_t sc_sets_count = 0;
	struct fss_sc_set *sc_set;
	struct fss_sc_smap *prunable_sc_smaps = NULL;
	bool is_modified = false;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *ctx = talloc_new(NULL);

	if (!ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* work with temporary state for simple cleanup on failure */
	become_root();
	status = fss_state_retrieve(ctx, &sc_sets, &sc_sets_count, db_path);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to retrieve fss server state: %s\n",
			  nt_errstr(status)));
		goto out;
	}

	/* walk the cache and pick up any entries to be deleted */
	sc_set = sc_sets;
	DEBUG(10, ("pruning shared shadow copies\n"));
	while (sc_set) {
		struct fss_sc *sc;
		struct fss_sc_set *sc_set_next = sc_set->next;
		char *set_id = GUID_string(ctx, &sc_set->id);
		if (set_id == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		DEBUGADD(10, ("\tprocessing shadow set id %s\n", set_id));
		sc = sc_set->scs;
		while (sc) {
			struct fss_sc_smap *sc_smap;
			struct fss_sc *sc_next = sc->next;
			DEBUGADD(10, ("\tprocessing shadow copy path %s\n",
				 sc->sc_path));
			if (snap_path_exists(ctx, msg_ctx, sc)) {
				sc = sc_next;
				continue;
			}

			/* move missing snapshot state to purge list */
			sc_smap = sc->smaps;
			while (sc_smap != NULL) {
				struct fss_sc_smap *smap_next = sc_smap->next;
				DLIST_REMOVE(sc->smaps, sc_smap);
				DLIST_ADD_END(prunable_sc_smaps, sc_smap);
				sc->smaps_count--;
				sc_smap = smap_next;
			}

			DLIST_REMOVE(sc_set->scs, sc);
			sc_set->scs_count--;
			is_modified = true;
			sc = sc_next;
		}
		if (sc_set->scs_count == 0) {
			DLIST_REMOVE(sc_sets, sc_set);
			sc_sets_count--;
		}
		sc_set = sc_set_next;
	}

	if (is_modified) {
		/* unexpose all shares in a single transaction */
		status = sc_smap_unexpose(msg_ctx, prunable_sc_smaps, true);
		if (!NT_STATUS_IS_OK(status)) {
			/* exit without storing updated state */
			goto out;
		}

		become_root();
		status = fss_state_store(ctx, sc_sets, sc_sets_count, db_path);
		unbecome_root();
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("pruning failed to store fss server state: %s\n",
				  nt_errstr(status)));
			goto out;
		}
	}
	status = NT_STATUS_OK;
out:
	TALLOC_FREE(ctx);
	return status;
}

static NTSTATUS fss_conn_create_tos(struct messaging_context *msg_ctx,
				    struct auth_session_info *session_info,
				    int snum,
				    struct connection_struct **conn_out)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct conn_struct_tos *c = NULL;
	NTSTATUS status;

	status = create_conn_struct_tos(msg_ctx,
					snum,
					lp_path(talloc_tos(), lp_sub, snum),
					session_info,
					&c);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("failed to create conn for vfs: %s\n",
			 nt_errstr(status)));
		return status;
	}

	status = set_conn_force_user_group(c->conn, snum);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("failed set force user / group\n"));
		TALLOC_FREE(c);
		return status;
	}

	*conn_out = c->conn;
	return NT_STATUS_OK;
}

static struct fss_sc_set *sc_set_lookup(struct fss_sc_set *sc_set_head,
					struct GUID *sc_set_id)
{

	struct fss_sc_set *sc_set;
	char *guid_str;

	for (sc_set = sc_set_head; sc_set; sc_set = sc_set->next) {
		if (GUID_equal(&sc_set->id, sc_set_id)) {
			return sc_set;
		}
	}
	guid_str = GUID_string(sc_set_head, sc_set_id);
	DEBUG(4, ("shadow copy set with GUID %s not found\n",
		  guid_str ? guid_str : "NO MEM"));
	talloc_free(guid_str);

	return NULL;
}

static struct fss_sc *sc_lookup(struct fss_sc *sc_head, struct GUID *sc_id)
{

	struct fss_sc *sc;
	char *guid_str;

	for (sc = sc_head; sc; sc = sc->next) {
		if (GUID_equal(&sc->id, sc_id)) {
			return sc;
		}
	}
	guid_str = GUID_string(sc_head, sc_id);
	DEBUG(4, ("shadow copy with GUID %s not found\n",
		  guid_str ? guid_str : "NO MEM"));
	talloc_free(guid_str);

	return NULL;
}

static struct fss_sc *sc_lookup_volname(struct fss_sc *sc_head,
					const char *volname)
{
	struct fss_sc *sc;

	for (sc = sc_head; sc; sc = sc->next) {
		if (!strcmp(sc->volume_name, volname)) {
			return sc;
		}
	}
	DEBUG(4, ("shadow copy with base volume %s not found\n", volname));
	return NULL;
}

/* lookup is case-insensitive */
static struct fss_sc_smap *sc_smap_lookup(struct fss_sc_smap *smaps_head,
					  const char *share)
{
	struct fss_sc_smap *sc_smap;
	for (sc_smap = smaps_head; sc_smap; sc_smap = sc_smap->next) {
		if (!strcasecmp_m(sc_smap->share_name, share)) {
			return sc_smap;
		}
	}
	DEBUG(4, ("shadow copy share mapping for %s not found\n", share));
	return NULL;
}

static void srv_fssa_cleanup(void)
{
	talloc_free(fss_global.db_path);
	talloc_free(fss_global.mem_ctx);
	ZERO_STRUCT(fss_global);
}

static NTSTATUS srv_fssa_start(struct messaging_context *msg_ctx)
{
	NTSTATUS status;
	fss_global.mem_ctx = talloc_named_const(NULL, 0,
						"parent fss rpc server ctx");
	if (fss_global.mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fss_global.db_path = lock_path(talloc_tos(), FSS_DB_NAME);
	if (fss_global.db_path == NULL) {
		talloc_free(fss_global.mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	fss_global.min_vers = FSRVP_RPC_VERSION_1;
	fss_global.max_vers = FSRVP_RPC_VERSION_1;
	/*
	 * The server MUST populate the GlobalShadowCopySetTable with the
	 * ShadowCopySet entries read from the configuration store.
	 */
	if (lp_parm_bool(GLOBAL_SECTION_SNUM, "fss", "prune stale", false)) {
		fss_prune_stale(msg_ctx, fss_global.db_path);
	}
	become_root();
	status = fss_state_retrieve(fss_global.mem_ctx, &fss_global.sc_sets,
				    &fss_global.sc_sets_count,
				    fss_global.db_path);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to retrieve fss server state: %s\n",
			  nt_errstr(status)));
	}
	return NT_STATUS_OK;
}

/*
 * Determine whether to process an FSRVP operation from connected user @p.
 * Windows checks for Administrators or Backup Operators group membership. We
 * also allow for the SEC_PRIV_BACKUP privilege.
 */
static bool fss_permitted(struct pipes_struct *p)
{
	if (p->session_info->unix_token->uid == sec_initial_uid()) {
		DEBUG(6, ("Granting FSRVP op, user started smbd\n"));
		return true;
	}

	if (nt_token_check_sid(&global_sid_Builtin_Administrators,
			       p->session_info->security_token)) {
		DEBUG(6, ("Granting FSRVP op, administrators group member\n"));
		return true;
	}
	if (nt_token_check_sid(&global_sid_Builtin_Backup_Operators,
			       p->session_info->security_token)) {
		DEBUG(6, ("Granting FSRVP op, backup operators group member\n"));
		return true;
	}
	if (security_token_has_privilege(p->session_info->security_token,
					 SEC_PRIV_BACKUP)) {
		DEBUG(6, ("Granting FSRVP op, backup privilege present\n"));
		return true;
	}

	DEBUG(2, ("FSRVP operation blocked due to lack of backup privilege "
		  "or Administrators/Backup Operators group membership\n"));

	return false;
}

static void fss_seq_tout_handler(struct tevent_context *ev,
				 struct tevent_timer *te,
				 struct timeval t,
				 void *private_data)
{
	struct GUID *sc_set_id = NULL;
	struct fss_sc_set *sc_set;

	/*
	 * MS-FSRVP: 3.1.5 Timer Events
	 * Message Sequence Timer elapses: When the Message Sequence Timer
	 * elapses, the server MUST delete the ShadowCopySet in the
	 * GlobalShadowCopySetTable where ShadowCopySet.Status is not equal to
	 * "Recovered", ContextSet MUST be set to FALSE, and the ShadowCopySet
	 * object MUST be freed.
	 */
	DEBUG(2, ("FSRVP msg seq timeout fired\n"));

	if (private_data == NULL) {
		DEBUG(4, ("timeout without sc_set\n"));
		goto out_init_ctx;
	}

	sc_set_id = talloc_get_type_abort(private_data, struct GUID);
	sc_set = sc_set_lookup(fss_global.sc_sets, sc_set_id);
	if (sc_set == NULL) {
		DEBUG(0, ("timeout for unknown sc_set\n"));
		goto out_init_ctx;
	} else if ((sc_set->state == FSS_SC_EXPOSED)
			|| (sc_set->state == FSS_SC_RECOVERED)) {
		DEBUG(2, ("timeout for finished sc_set %s\n", sc_set->id_str));
		goto out_init_ctx;
	}
	DEBUG(2, ("cleaning up sc_set %s\n", sc_set->id_str));
	SMB_ASSERT(fss_global.sc_sets_count > 0);
	DLIST_REMOVE(fss_global.sc_sets, sc_set);
	fss_global.sc_sets_count--;
	talloc_free(sc_set);

out_init_ctx:
	fss_global.ctx_set = false;
	fss_global.seq_tmr = NULL;
	talloc_free(sc_set_id);
}

static void fss_seq_tout_set(TALLOC_CTX *mem_ctx,
			     uint32_t timeout_s,
			     struct fss_sc_set *sc_set,
			     struct tevent_timer **tmr_out)
{
	struct tevent_timer *tmr;
	struct GUID *sc_set_id = NULL;
	uint32_t tout;

	/* allow changes to timeout for testing/debugging purposes */
	tout = lp_parm_int(GLOBAL_SECTION_SNUM, "fss",
			   "sequence timeout", timeout_s);
	if (tout == 0) {
		DEBUG(2, ("FSRVP message sequence timeout disabled\n"));
		*tmr_out = NULL;
		return;
	}

	if (sc_set) {
		/* don't use talloc_memdup(), need explicit type for callback */
		sc_set_id = talloc(mem_ctx, struct GUID);
		if (sc_set_id == NULL) {
			smb_panic("no memory");
		}
		memcpy(sc_set_id, &sc_set->id, sizeof(*sc_set_id));
	}

	tmr = tevent_add_timer(global_event_context(),
			      mem_ctx,
			      timeval_current_ofs(tout, 0),
			      fss_seq_tout_handler, sc_set_id);
	if (tmr == NULL) {
		talloc_free(sc_set_id);
		smb_panic("no memory");
	}

	*tmr_out = tmr;
}

uint32_t _fss_GetSupportedVersion(struct pipes_struct *p,
				  struct fss_GetSupportedVersion *r)
{
	if (!fss_permitted(p)) {
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}

	*r->out.MinVersion = fss_global.min_vers;
	*r->out.MaxVersion = fss_global.max_vers;

	return 0;
}

uint32_t _fss_SetContext(struct pipes_struct *p,
			 struct fss_SetContext *r)
{
	if (!fss_permitted(p)) {
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}

	/* ATTR_AUTO_RECOVERY flag can be applied to any */
	switch (r->in.Context & (~ATTR_AUTO_RECOVERY)) {
	case FSRVP_CTX_BACKUP:
		DEBUG(6, ("fss ctx set backup\n"));
		break;
	case FSRVP_CTX_FILE_SHARE_BACKUP:
		DEBUG(6, ("fss ctx set file share backup\n"));
		break;
	case FSRVP_CTX_NAS_ROLLBACK:
		DEBUG(6, ("fss ctx set nas rollback\n"));
		break;
	case FSRVP_CTX_APP_ROLLBACK:
		DEBUG(6, ("fss ctx set app rollback\n"));
		break;
	default:
		DEBUG(0, ("invalid fss ctx set value: 0x%x\n", r->in.Context));
		return HRES_ERROR_V(HRES_E_INVALIDARG);
		break;	/* not reached */
	}

	fss_global.ctx_set = true;
	fss_global.cur_ctx = r->in.Context;

	TALLOC_FREE(fss_global.seq_tmr);	/* kill timer if running */
	fss_seq_tout_set(fss_global.mem_ctx, 180, NULL, &fss_global.seq_tmr);

	fss_global.cur_ctx = r->in.Context;

	return 0;
}

static bool sc_set_active(struct fss_sc_set *sc_set_head)
{

	struct fss_sc_set *sc_set;

	for (sc_set = sc_set_head; sc_set; sc_set = sc_set->next) {
		if ((sc_set->state != FSS_SC_EXPOSED)
		 && (sc_set->state != FSS_SC_RECOVERED)) {
			return true;
		}
	}

	return false;
}

uint32_t _fss_StartShadowCopySet(struct pipes_struct *p,
				 struct fss_StartShadowCopySet *r)
{
	struct fss_sc_set *sc_set;
	uint32_t ret;

	if (!fss_permitted(p)) {
		ret = HRES_ERROR_V(HRES_E_ACCESSDENIED);
		goto err_out;
	}

	if (!fss_global.ctx_set) {
		DEBUG(3, ("invalid sequence: start sc set requested without "
			  "prior context set\n"));
		ret = FSRVP_E_BAD_STATE;
		goto err_out;
	}

	/*
	 * At any given time, Windows servers allow only one shadow copy set to
	 * be going through the creation process.
	 */
	if (sc_set_active(fss_global.sc_sets)) {
		DEBUG(3, ("StartShadowCopySet called while in progress\n"));
		ret = FSRVP_E_SHADOW_COPY_SET_IN_PROGRESS;
		goto err_out;
	}

	/* stop msg seq timer */
	TALLOC_FREE(fss_global.seq_tmr);

	sc_set = talloc_zero(fss_global.mem_ctx, struct fss_sc_set);
	if (sc_set == NULL) {
		ret = HRES_ERROR_V(HRES_E_OUTOFMEMORY);
		goto err_tmr_restart;
	}

	sc_set->id = GUID_random();	/* Windows servers ignore client ids */
	sc_set->id_str = GUID_string(sc_set, &sc_set->id);
	if (sc_set->id_str == NULL) {
		ret = HRES_ERROR_V(HRES_E_OUTOFMEMORY);
		goto err_sc_set_free;
	}
	sc_set->state = FSS_SC_STARTED;
	sc_set->context = fss_global.cur_ctx;
	DLIST_ADD_END(fss_global.sc_sets, sc_set);
	fss_global.sc_sets_count++;
	DEBUG(6, ("%s: shadow-copy set %u added\n",
		  sc_set->id_str, fss_global.sc_sets_count));

	/* start msg seq timer */
	fss_seq_tout_set(fss_global.mem_ctx, 180, sc_set, &fss_global.seq_tmr);

	r->out.pShadowCopySetId = &sc_set->id;

	return 0;

err_sc_set_free:
	talloc_free(sc_set);
err_tmr_restart:
	fss_seq_tout_set(fss_global.mem_ctx, 180, NULL, &fss_global.seq_tmr);
err_out:
	return ret;
}

static uint32_t map_share_name(struct fss_sc_smap *sc_smap,
			       const struct fss_sc *sc)
{
	bool hidden_base = false;

	if (*(sc_smap->share_name + strlen(sc_smap->share_name) - 1) == '$') {
		/*
		 * If MappedShare.ShareName ends with a $ character (meaning
		 * that the share is hidden), then the exposed share name will
		 * have the $ suffix appended.
		 * FIXME: turns out Windows doesn't do this, contrary to docs
		 */
		hidden_base = true;
	}

	sc_smap->sc_share_name = talloc_asprintf(sc_smap, "%s@{%s}%s",
						sc_smap->share_name,
						sc->id_str,
						hidden_base ? "$" : "");
	if (sc_smap->sc_share_name == NULL) {
		return HRES_ERROR_V(HRES_E_OUTOFMEMORY);
	}

	return 0;
}

static uint32_t map_share_comment(struct fss_sc_smap *sc_smap,
				  const struct fss_sc *sc)
{
	char *time_str;

	time_str = http_timestring(sc_smap, sc->create_ts);
	if (time_str == NULL) {
		return HRES_ERROR_V(HRES_E_OUTOFMEMORY);
	}

	sc_smap->sc_share_comment = talloc_asprintf(sc_smap, "Shadow copy of %s taken %s",
						   sc_smap->share_name, time_str);
	if (sc_smap->sc_share_comment == NULL) {
		return HRES_ERROR_V(HRES_E_OUTOFMEMORY);
	}

	return 0;
}

uint32_t _fss_AddToShadowCopySet(struct pipes_struct *p,
				 struct fss_AddToShadowCopySet *r)
{
	uint32_t ret;
	struct fss_sc_set *sc_set;
	struct fss_sc *sc;
	struct fss_sc_smap *sc_smap;
	int snum;
	char *service;
	char *base_vol;
	char *share;
	char *path_name;
	struct connection_struct *conn;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	if (!fss_permitted(p)) {
		ret = HRES_ERROR_V(HRES_E_ACCESSDENIED);
		goto err_tmp_free;
	}

	sc_set = sc_set_lookup(fss_global.sc_sets, &r->in.ShadowCopySetId);
	if (sc_set == NULL) {
		ret = HRES_ERROR_V(HRES_E_INVALIDARG);
		goto err_tmp_free;
	}

	status = fss_unc_parse(frame, r->in.ShareName, NULL, &share);
	if (!NT_STATUS_IS_OK(status)) {
		ret = fss_ntstatus_map(status);
		goto err_tmp_free;
	}

	snum = find_service(frame, share, &service);
	if ((snum == -1) || (service == NULL)) {
		DEBUG(0, ("share at %s not found\n", r->in.ShareName));
		ret = HRES_ERROR_V(HRES_E_INVALIDARG);
		goto err_tmp_free;
	}

	path_name = lp_path(frame, lp_sub, snum);
	if (path_name == NULL) {
		ret = HRES_ERROR_V(HRES_E_OUTOFMEMORY);
		goto err_tmp_free;
	}

	status = fss_conn_create_tos(p->msg_ctx, p->session_info, snum, &conn);
	if (!NT_STATUS_IS_OK(status)) {
		ret = HRES_ERROR_V(HRES_E_ACCESSDENIED);
		goto err_tmp_free;
	}
	if (!become_user_without_service_by_session(conn, p->session_info)) {
		DEBUG(0, ("failed to become user\n"));
		ret = HRES_ERROR_V(HRES_E_ACCESSDENIED);
		goto err_tmp_free;
	}

	status = SMB_VFS_SNAP_CHECK_PATH(conn, frame, path_name, &base_vol);
	unbecome_user_without_service();
	if (!NT_STATUS_IS_OK(status)) {
		ret = FSRVP_E_NOT_SUPPORTED;
		goto err_tmp_free;
	}

	if ((sc_set->state != FSS_SC_STARTED)
	 && (sc_set->state != FSS_SC_ADDED)) {
		ret = FSRVP_E_BAD_STATE;
		goto err_tmp_free;
	}

	/* stop msg seq timer */
	TALLOC_FREE(fss_global.seq_tmr);

	/*
	 * server MUST look up the ShadowCopy in ShadowCopySet.ShadowCopyList
	 * where ShadowCopy.VolumeName matches the file store on which the
	 * share identified by ShareName is hosted. If an entry is found, the
	 * server MUST fail the call with FSRVP_E_OBJECT_ALREADY_EXISTS.
	 * If no entry is found, the server MUST create a new ShadowCopy
	 * object
	 * XXX Windows appears to allow multiple mappings for the same vol!
	 */
	sc = sc_lookup_volname(sc_set->scs, base_vol);
	if (sc != NULL) {
		ret = FSRVP_E_OBJECT_ALREADY_EXISTS;
		goto err_tmr_restart;
	}

	sc = talloc_zero(sc_set, struct fss_sc);
	if (sc == NULL) {
		ret = HRES_ERROR_V(HRES_E_OUTOFMEMORY);
		goto err_tmr_restart;
	}
	talloc_steal(sc, base_vol);
	sc->volume_name = base_vol;
	sc->sc_set = sc_set;
	sc->create_ts = time(NULL);

	sc->id = GUID_random();	/* Windows servers ignore client ids */
	sc->id_str = GUID_string(sc, &sc->id);
	if (sc->id_str == NULL) {
		ret = HRES_ERROR_V(HRES_E_OUTOFMEMORY);
		goto err_sc_free;
	}

	sc_smap = talloc_zero(sc, struct fss_sc_smap);
	if (sc_smap == NULL) {
		ret = HRES_ERROR_V(HRES_E_OUTOFMEMORY);
		goto err_sc_free;
	}

	talloc_steal(sc_smap, service);
	sc_smap->share_name = service;
	sc_smap->is_exposed = false;
	/*
	 * generate the sc_smap share name now. It is a unique identifier for
	 * the smap used as a tdb key for state storage.
	 */
	ret = map_share_name(sc_smap, sc);
	if (ret) {
		goto err_sc_free;
	}

	/* add share map to shadow-copy */
	DLIST_ADD_END(sc->smaps, sc_smap);
	sc->smaps_count++;
	/* add shadow-copy to shadow-copy set */
	DLIST_ADD_END(sc_set->scs, sc);
	sc_set->scs_count++;
	DEBUG(4, ("added volume %s to shadow copy set with GUID %s\n",
		  sc->volume_name, sc_set->id_str));

	/* start the Message Sequence Timer with timeout of 1800 seconds */
	fss_seq_tout_set(fss_global.mem_ctx, 1800, sc_set, &fss_global.seq_tmr);

	sc_set->state = FSS_SC_ADDED;
	r->out.pShadowCopyId = &sc->id;

	TALLOC_FREE(frame);
	return 0;

err_sc_free:
	talloc_free(sc);
err_tmr_restart:
	fss_seq_tout_set(fss_global.mem_ctx, 180, sc_set, &fss_global.seq_tmr);
err_tmp_free:
	TALLOC_FREE(frame);
	return ret;
}

static NTSTATUS commit_sc_with_conn(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct messaging_context *msg_ctx,
				    struct auth_session_info *session_info,
				    struct fss_sc *sc,
				    char **base_path,
				    char **snap_path)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	bool rw;
	struct connection_struct *conn;
	int snum;
	char *service;

	snum = find_service(frame, sc->smaps->share_name, &service);
	if ((snum == -1) || (service == NULL)) {
		DEBUG(0, ("share at %s not found\n", sc->smaps->share_name));
		TALLOC_FREE(frame);
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = fss_conn_create_tos(msg_ctx, session_info, snum, &conn);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	if (!become_user_without_service_by_session(conn, session_info)) {
		DEBUG(0, ("failed to become user\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_ACCESS_DENIED;
	}
	rw = ((sc->sc_set->context & ATTR_AUTO_RECOVERY) == ATTR_AUTO_RECOVERY);
	status = SMB_VFS_SNAP_CREATE(conn, mem_ctx,
				     sc->volume_name,
				     &sc->create_ts, rw,
				     base_path, snap_path);
	unbecome_user_without_service();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("snap create failed: %s\n", nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	TALLOC_FREE(frame);
	return status;
}

uint32_t _fss_CommitShadowCopySet(struct pipes_struct *p,
				  struct fss_CommitShadowCopySet *r)
{
	struct fss_sc_set *sc_set;
	struct fss_sc *sc;
	uint32_t commit_count;
	NTSTATUS status;
	NTSTATUS saved_status;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!fss_permitted(p)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto err_tmp_free;
	}

	sc_set = sc_set_lookup(fss_global.sc_sets, &r->in.ShadowCopySetId);
	if (sc_set == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_tmp_free;
	}

	if (sc_set->state != FSS_SC_ADDED) {
		status = NT_STATUS_INVALID_SERVER_STATE;
		goto err_tmp_free;
	}

	/* stop Message Sequence Timer */
	TALLOC_FREE(fss_global.seq_tmr);
	sc_set->state = FSS_SC_CREATING;
	commit_count = 0;
	saved_status = NT_STATUS_OK;
	for (sc = sc_set->scs; sc; sc = sc->next) {
		char *base_path;
		char *snap_path;
		status = commit_sc_with_conn(frame, global_event_context(),
					     p->msg_ctx, p->session_info, sc,
					     &base_path, &snap_path);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("snap create failed for shadow copy of "
				  "%s\n", sc->volume_name));
			/* dispatch all scs in set, but retain last error */
			saved_status = status;
			continue;
		}
		/* XXX set timeout r->in.TimeOutInMilliseconds */
		commit_count++;
		DEBUG(10, ("good snap create %d\n",
			   commit_count));
		sc->sc_path = talloc_steal(sc, snap_path);
	}
	if (!NT_STATUS_IS_OK(saved_status)) {
		status = saved_status;
		goto err_state_revert;
	}

	sc_set->state = FSS_SC_COMMITED;
	become_root();
	status = fss_state_store(fss_global.mem_ctx, fss_global.sc_sets,
				 fss_global.sc_sets_count,
				 fss_global.db_path);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to store fss server state: %s\n",
			  nt_errstr(status)));
	}

	fss_seq_tout_set(fss_global.mem_ctx, 180, sc_set,
			 &fss_global.seq_tmr);
	TALLOC_FREE(frame);
	return 0;

err_state_revert:
	sc_set->state = FSS_SC_ADDED;
	fss_seq_tout_set(fss_global.mem_ctx, 180, sc_set,
			 &fss_global.seq_tmr);
err_tmp_free:
	TALLOC_FREE(frame);
	return fss_ntstatus_map(status);
}

static sbcErr fss_conf_get_share_def(struct smbconf_ctx *fconf_ctx,
				     struct smbconf_ctx *rconf_ctx,
				     TALLOC_CTX *mem_ctx,
				     char *share,
				     struct smbconf_service **service_def)
{
	sbcErr cerr;
	struct smbconf_service *def;

	*service_def = NULL;
	cerr = smbconf_get_share(fconf_ctx, mem_ctx, share, &def);
	if (SBC_ERROR_IS_OK(cerr)) {
		*service_def = def;
		return SBC_ERR_OK;
	}

	cerr = smbconf_get_share(rconf_ctx, mem_ctx, share, &def);
	if (SBC_ERROR_IS_OK(cerr)) {
		*service_def = def;
		return SBC_ERR_OK;
	}
	return cerr;
}

/*
 * Expose a new share using libsmbconf, cloning the existing configuration
 * from the base share. The base share may be defined in either the registry
 * or smb.conf.
 * XXX this is called as root
 */
static uint32_t fss_sc_expose(struct smbconf_ctx *fconf_ctx,
			      struct smbconf_ctx *rconf_ctx,
			      TALLOC_CTX *mem_ctx,
			      struct fss_sc *sc)
{
	struct fss_sc_smap *sc_smap;
	uint32_t err = 0;

	for (sc_smap = sc->smaps; sc_smap; sc_smap = sc_smap->next) {
		sbcErr cerr;
		struct smbconf_service *base_service = NULL;
		struct security_descriptor *sd;
		size_t sd_size;

		cerr = fss_conf_get_share_def(fconf_ctx, rconf_ctx, mem_ctx,
					    sc_smap->share_name, &base_service);
		if (!SBC_ERROR_IS_OK(cerr)) {
			DEBUG(0, ("failed to get base share %s definition: "
				  "%s\n", sc_smap->share_name,
				  sbcErrorString(cerr)));
			err = HRES_ERROR_V(HRES_E_FAIL);
			break;
		}

		/* smap share name already defined when added */
		err = map_share_comment(sc_smap, sc);
		if (err) {
			DEBUG(0, ("failed to map share comment\n"));
			break;
		}

		base_service->name = sc_smap->sc_share_name;

		cerr = smbconf_create_set_share(rconf_ctx, base_service);
		if (!SBC_ERROR_IS_OK(cerr)) {
			DEBUG(0, ("failed to create share %s: %s\n",
				  base_service->name, sbcErrorString(cerr)));
			err = HRES_ERROR_V(HRES_E_FAIL);
			break;
		}
		cerr = smbconf_set_parameter(rconf_ctx, sc_smap->sc_share_name,
					     "path", sc->sc_path);
		if (!SBC_ERROR_IS_OK(cerr)) {
			DEBUG(0, ("failed to set path param: %s\n",
				  sbcErrorString(cerr)));
			err = HRES_ERROR_V(HRES_E_FAIL);
			break;
		}
		if (sc_smap->sc_share_comment != NULL) {
			cerr = smbconf_set_parameter(rconf_ctx,
						    sc_smap->sc_share_name,
						    "comment",
						    sc_smap->sc_share_comment);
			if (!SBC_ERROR_IS_OK(cerr)) {
				DEBUG(0, ("failed to set comment param: %s\n",
					  sbcErrorString(cerr)));
				err = HRES_ERROR_V(HRES_E_FAIL);
				break;
			}
		}
		talloc_free(base_service);

		/*
		 * Obtain the base share SD, which also needs to be cloned.
		 * Share SDs are stored in share_info.tdb, so are not covered by
		 * the registry transaction.
		 * The base share SD should be cloned at the time of exposure,
		 * rather than when the snapshot is taken. This matches Windows
		 * Server 2012 behaviour.
		 */
		sd = get_share_security(mem_ctx, sc_smap->share_name, &sd_size);
		if (sd == NULL) {
			DEBUG(2, ("no share SD to clone for %s snapshot\n",
				  sc_smap->share_name));
		} else {
			NTSTATUS status;
			status = set_share_security(sc_smap->sc_share_name, sd);
			TALLOC_FREE(sd);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0, ("failed to set %s share SD\n",
					  sc_smap->sc_share_name));
				err = HRES_ERROR_V(HRES_E_FAIL);
				break;
			}
		}
	}

	return err;
}

uint32_t _fss_ExposeShadowCopySet(struct pipes_struct *p,
				  struct fss_ExposeShadowCopySet *r)
{
	NTSTATUS status;
	struct fss_sc_set *sc_set;
	struct fss_sc *sc;
	uint32_t ret;
	struct smbconf_ctx *fconf_ctx;
	struct smbconf_ctx *rconf_ctx;
	sbcErr cerr;
	char *fconf_path;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!fss_permitted(p)) {
		ret = HRES_ERROR_V(HRES_E_ACCESSDENIED);
		goto err_out;
	}

	sc_set = sc_set_lookup(fss_global.sc_sets, &r->in.ShadowCopySetId);
	if (sc_set == NULL) {
		ret = HRES_ERROR_V(HRES_E_INVALIDARG);
		goto err_out;
	}

	if (sc_set->state != FSS_SC_COMMITED) {
		ret = FSRVP_E_BAD_STATE;
		goto err_out;
	}

	/* stop message sequence timer */
	TALLOC_FREE(fss_global.seq_tmr);

	/*
	 * Prepare to clone the base share definition for the snapshot share.
	 * Create both registry and file conf contexts, as the base share
	 * definition may be located in either. The snapshot share definition
	 * is always written to the registry.
	 */
	cerr = smbconf_init(frame, &rconf_ctx, "registry");
	if (!SBC_ERROR_IS_OK(cerr)) {
		DEBUG(0, ("failed registry smbconf init: %s\n",
			  sbcErrorString(cerr)));
		ret = HRES_ERROR_V(HRES_E_FAIL);
		goto err_tmr_restart;
	}
	fconf_path = talloc_asprintf(frame, "file:%s", get_dyn_CONFIGFILE());
	if (fconf_path == NULL) {
		ret = HRES_ERROR_V(HRES_E_OUTOFMEMORY);
		goto err_tmr_restart;
	}
	cerr = smbconf_init(frame, &fconf_ctx, fconf_path);
	if (!SBC_ERROR_IS_OK(cerr)) {
		DEBUG(0, ("failed %s smbconf init: %s\n",
			  fconf_path, sbcErrorString(cerr)));
		ret = HRES_ERROR_V(HRES_E_FAIL);
		goto err_tmr_restart;
	}

	/* registry IO must be done as root */
	become_root();
	cerr = smbconf_transaction_start(rconf_ctx);
	if (!SBC_ERROR_IS_OK(cerr)) {
		DEBUG(0, ("error starting transaction: %s\n",
			 sbcErrorString(cerr)));
		ret = HRES_ERROR_V(HRES_E_FAIL);
		unbecome_root();
		goto err_tmr_restart;
	}

	for (sc = sc_set->scs; sc; sc = sc->next) {
		ret = fss_sc_expose(fconf_ctx, rconf_ctx, frame, sc);
		if (ret) {
			DEBUG(0,("failed to expose shadow copy of %s\n",
				 sc->volume_name));
			goto err_cancel;
		}
	}

	cerr = smbconf_transaction_commit(rconf_ctx);
	if (!SBC_ERROR_IS_OK(cerr)) {
		DEBUG(0, ("error committing transaction: %s\n",
			  sbcErrorString(cerr)));
		ret = HRES_ERROR_V(HRES_E_FAIL);
		goto err_cancel;
	}
	unbecome_root();

	messaging_send_all(p->msg_ctx, MSG_SMB_CONF_UPDATED, NULL, 0);
	for (sc = sc_set->scs; sc; sc = sc->next) {
		struct fss_sc_smap *sm;
		for (sm = sc->smaps; sm; sm = sm->next)
			sm->is_exposed = true;
	}
	sc_set->state = FSS_SC_EXPOSED;
	become_root();
	status = fss_state_store(fss_global.mem_ctx, fss_global.sc_sets,
				 fss_global.sc_sets_count, fss_global.db_path);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to store fss server state: %s\n",
			  nt_errstr(status)));
	}
	/* start message sequence timer */
	fss_seq_tout_set(fss_global.mem_ctx, 180, sc_set, &fss_global.seq_tmr);
	TALLOC_FREE(frame);
	return 0;

err_cancel:
	smbconf_transaction_cancel(rconf_ctx);
	unbecome_root();
err_tmr_restart:
	fss_seq_tout_set(fss_global.mem_ctx, 180, sc_set, &fss_global.seq_tmr);
err_out:
	TALLOC_FREE(frame);
	return ret;
}

uint32_t _fss_RecoveryCompleteShadowCopySet(struct pipes_struct *p,
				struct fss_RecoveryCompleteShadowCopySet *r)
{
	NTSTATUS status;
	struct fss_sc_set *sc_set;

	if (!fss_permitted(p)) {
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}

	sc_set = sc_set_lookup(fss_global.sc_sets, &r->in.ShadowCopySetId);
	if (sc_set == NULL) {
		return HRES_ERROR_V(HRES_E_INVALIDARG);
	}

	if (sc_set->state != FSS_SC_EXPOSED) {
		return FSRVP_E_BAD_STATE;
	}

	/* stop msg sequence timer */
	TALLOC_FREE(fss_global.seq_tmr);

	if (sc_set->context & ATTR_NO_AUTO_RECOVERY) {
		/* TODO set read-only */
	}

	sc_set->state = FSS_SC_RECOVERED;
	fss_global.cur_ctx = 0;
	fss_global.ctx_set = false;

	become_root();
	status = fss_state_store(fss_global.mem_ctx, fss_global.sc_sets,
				 fss_global.sc_sets_count, fss_global.db_path);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to store fss server state: %s\n",
			  nt_errstr(status)));
	}

	return 0;
}

uint32_t _fss_AbortShadowCopySet(struct pipes_struct *p,
				 struct fss_AbortShadowCopySet *r)
{
	NTSTATUS status;
	struct fss_sc_set *sc_set;

	if (!fss_permitted(p)) {
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}

	sc_set = sc_set_lookup(fss_global.sc_sets, &r->in.ShadowCopySetId);
	if (sc_set == NULL) {
		return HRES_ERROR_V(HRES_E_INVALIDARG);
	}

	DEBUG(6, ("%s: aborting shadow-copy set\n", sc_set->id_str));

	if ((sc_set->state == FSS_SC_COMMITED)
	 || (sc_set->state == FSS_SC_EXPOSED)
	 || (sc_set->state == FSS_SC_RECOVERED)) {
		return 0;
	}

	if (sc_set->state == FSS_SC_CREATING) {
		return FSRVP_E_BAD_STATE;
	}

	DLIST_REMOVE(fss_global.sc_sets, sc_set);
	talloc_free(sc_set);
	fss_global.sc_sets_count--;
	become_root();
	status = fss_state_store(fss_global.mem_ctx, fss_global.sc_sets,
				 fss_global.sc_sets_count, fss_global.db_path);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to store fss server state: %s\n",
			  nt_errstr(status)));
	}

	return 0;
}

uint32_t _fss_IsPathSupported(struct pipes_struct *p,
			      struct fss_IsPathSupported *r)
{
	int snum;
	char *service;
	char *base_vol;
	NTSTATUS status;
	struct connection_struct *conn;
	char *share;
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	if (!fss_permitted(p)) {
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}

	status = fss_unc_parse(frame, r->in.ShareName, NULL, &share);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return fss_ntstatus_map(status);
	}

	snum = find_service(frame, share, &service);
	if ((snum == -1) || (service == NULL)) {
		DEBUG(0, ("share at %s not found\n", r->in.ShareName));
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_INVALIDARG);
	}

	status = fss_conn_create_tos(p->msg_ctx, p->session_info, snum, &conn);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}
	if (!become_user_without_service_by_session(conn, p->session_info)) {
		DEBUG(0, ("failed to become user\n"));
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}
	status = SMB_VFS_SNAP_CHECK_PATH(conn, frame,
					 lp_path(frame, lp_sub, snum),
					 &base_vol);
	unbecome_user_without_service();
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return FSRVP_E_NOT_SUPPORTED;
	}

	*r->out.OwnerMachineName = lp_netbios_name();
	*r->out.SupportedByThisProvider = 1;
	TALLOC_FREE(frame);
	return 0;
}

uint32_t _fss_IsPathShadowCopied(struct pipes_struct *p,
				 struct fss_IsPathShadowCopied *r)
{
	if (!fss_permitted(p)) {
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}

	/* not yet supported */
	return FSRVP_E_NOT_SUPPORTED;
}

uint32_t _fss_GetShareMapping(struct pipes_struct *p,
			      struct fss_GetShareMapping *r)
{
	NTSTATUS status;
	struct fss_sc_set *sc_set;
	struct fss_sc *sc;
	struct fss_sc_smap *sc_smap;
	char *share;
	struct fssagent_share_mapping_1 *sm_out;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!fss_permitted(p)) {
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}

	sc_set = sc_set_lookup(fss_global.sc_sets, &r->in.ShadowCopySetId);
	if (sc_set == NULL) {
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_INVALIDARG);
	}

	/*
	 * If ShadowCopySet.Status is not "Exposed", the server SHOULD<9> fail
	 * the call with FSRVP_E_BAD_STATE.
	 * <9> If ShadowCopySet.Status is "Started", "Added",
	 * "CreationInProgress", or "Committed", Windows Server 2012 FSRVP
	 * servers return an error value of 0x80042311.
	 */
	if ((sc_set->state == FSS_SC_STARTED)
	 || (sc_set->state == FSS_SC_ADDED)
	 || (sc_set->state == FSS_SC_CREATING)
	 || (sc_set->state == FSS_SC_COMMITED)) {
		TALLOC_FREE(frame);
		return 0x80042311;	/* documented magic value */
	}

	sc = sc_lookup(sc_set->scs, &r->in.ShadowCopyId);
	if (sc == NULL) {
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_INVALIDARG);
	}

	status = fss_unc_parse(frame, r->in.ShareName, NULL, &share);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return fss_ntstatus_map(status);
	}

	sc_smap = sc_smap_lookup(sc->smaps, share);
	if (sc_smap == NULL) {
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_INVALIDARG);
	}

	if (r->in.Level != 1) {
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_INVALIDARG);
	}

	sm_out = talloc_zero(p->mem_ctx, struct fssagent_share_mapping_1);
	if (sm_out == NULL) {
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_OUTOFMEMORY);
	}
	sm_out->ShadowCopySetId = sc_set->id;
	sm_out->ShadowCopyId = sc->id;
	sm_out->ShareNameUNC = talloc_asprintf(sm_out, "\\\\%s\\%s",
					       lp_netbios_name(),
					       sc_smap->share_name);
	if (sm_out->ShareNameUNC == NULL) {
		talloc_free(sm_out);
		TALLOC_FREE(frame);
		return HRES_ERROR_V(HRES_E_OUTOFMEMORY);
	}
	sm_out->ShadowCopyShareName = sc_smap->sc_share_name;
	unix_to_nt_time(&sm_out->tstamp, sc->create_ts);
	r->out.ShareMapping->ShareMapping1 = sm_out;
	TALLOC_FREE(frame);

	/* reset msg sequence timer */
	TALLOC_FREE(fss_global.seq_tmr);
	fss_seq_tout_set(fss_global.mem_ctx, 1800, sc_set, &fss_global.seq_tmr);

	return 0;
}

static NTSTATUS sc_smap_unexpose(struct messaging_context *msg_ctx,
				 struct fss_sc_smap *sc_smap, bool delete_all)
{
	NTSTATUS ret;
	struct smbconf_ctx *conf_ctx;
	sbcErr cerr;
	bool is_modified = false;
	TALLOC_CTX *frame = talloc_stackframe();

	cerr = smbconf_init(frame, &conf_ctx, "registry");
	if (!SBC_ERROR_IS_OK(cerr)) {
		DEBUG(0, ("failed registry smbconf init: %s\n",
			  sbcErrorString(cerr)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto err_tmp;
	}

	/* registry IO must be done as root */
	become_root();

	cerr = smbconf_transaction_start(conf_ctx);
	if (!SBC_ERROR_IS_OK(cerr)) {
		DEBUG(0, ("error starting transaction: %s\n",
			 sbcErrorString(cerr)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto err_conf;
	}

	while (sc_smap) {
		struct fss_sc_smap *sc_map_next = sc_smap->next;
		if (!smbconf_share_exists(conf_ctx, sc_smap->sc_share_name)) {
			DEBUG(2, ("no such share: %s\n", sc_smap->sc_share_name));
			if (!delete_all) {
				ret = NT_STATUS_OK;
				goto err_cancel;
			}
			sc_smap = sc_map_next;
			continue;
		}

		cerr = smbconf_delete_share(conf_ctx, sc_smap->sc_share_name);
		if (!SBC_ERROR_IS_OK(cerr)) {
			DEBUG(0, ("error deleting share: %s\n",
				 sbcErrorString(cerr)));
			ret = NT_STATUS_UNSUCCESSFUL;
			goto err_cancel;
		}
		is_modified = true;
		sc_smap->is_exposed = false;
		if (delete_all) {
			sc_smap = sc_map_next;
		} else {
			sc_smap = NULL; /* only process single sc_map entry */
		}
	}
	if (is_modified) {
		cerr = smbconf_transaction_commit(conf_ctx);
		if (!SBC_ERROR_IS_OK(cerr)) {
			DEBUG(0, ("error committing transaction: %s\n",
				  sbcErrorString(cerr)));
			ret = NT_STATUS_UNSUCCESSFUL;
			goto err_cancel;
		}
		messaging_send_all(msg_ctx, MSG_SMB_CONF_UPDATED, NULL, 0);
	} else {
		ret = NT_STATUS_OK;
		goto err_cancel;
	}
	ret = NT_STATUS_OK;

err_conf:
	talloc_free(conf_ctx);
	unbecome_root();
err_tmp:
	TALLOC_FREE(frame);
	return ret;

err_cancel:
	smbconf_transaction_cancel(conf_ctx);
	talloc_free(conf_ctx);
	unbecome_root();
	TALLOC_FREE(frame);
	return ret;
}

uint32_t _fss_DeleteShareMapping(struct pipes_struct *p,
				 struct fss_DeleteShareMapping *r)
{
	struct fss_sc_set *sc_set;
	struct fss_sc *sc;
	struct fss_sc_smap *sc_smap;
	char *share;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct connection_struct *conn;
	int snum;
	char *service;

	if (!fss_permitted(p)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto err_tmp_free;
	}

	sc_set = sc_set_lookup(fss_global.sc_sets, &r->in.ShadowCopySetId);
	if (sc_set == NULL) {
		/* docs say HRES_E_INVALIDARG */
		status = NT_STATUS_OBJECTID_NOT_FOUND;
		goto err_tmp_free;
	}

	if ((sc_set->state != FSS_SC_EXPOSED)
	 && (sc_set->state != FSS_SC_RECOVERED)) {
		status = NT_STATUS_INVALID_SERVER_STATE;
		goto err_tmp_free;
	}

	sc = sc_lookup(sc_set->scs, &r->in.ShadowCopyId);
	if (sc == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_tmp_free;
	}

	status = fss_unc_parse(frame, r->in.ShareName, NULL, &share);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_tmp_free;
	}

	sc_smap = sc_smap_lookup(sc->smaps, share);
	if (sc_smap == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_tmp_free;
	}

	status = sc_smap_unexpose(p->msg_ctx, sc_smap, false);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("failed to remove share %s: %s\n",
			  sc_smap->sc_share_name, nt_errstr(status)));
		goto err_tmp_free;
	}

	messaging_send_all(p->msg_ctx, MSG_SMB_FORCE_TDIS,
			   sc_smap->sc_share_name,
			   strlen(sc_smap->sc_share_name) + 1);

	if (sc->smaps_count > 1) {
		/* do not delete the underlying snapshot - still in use */
		status = NT_STATUS_OK;
		goto err_tmp_free;
	}

	snum = find_service(frame, sc_smap->share_name, &service);
	if ((snum == -1) || (service == NULL)) {
		DEBUG(0, ("share at %s not found\n", sc_smap->share_name));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_tmp_free;
	}

	status = fss_conn_create_tos(p->msg_ctx, p->session_info, snum, &conn);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_tmp_free;
	}
	if (!become_user_without_service_by_session(conn, p->session_info)) {
		DEBUG(0, ("failed to become user\n"));
		status = NT_STATUS_ACCESS_DENIED;
		goto err_tmp_free;
	}

	status = SMB_VFS_SNAP_DELETE(conn, frame, sc->volume_name,
				     sc->sc_path);
	unbecome_user_without_service();
	if (!NT_STATUS_IS_OK(status)) {
		goto err_tmp_free;
	}

	/* XXX set timeout r->in.TimeOutInMilliseconds */
	DEBUG(6, ("good snap delete\n"));
	DLIST_REMOVE(sc->smaps, sc_smap);
	sc->smaps_count--;
	talloc_free(sc_smap);
	if (sc->smaps_count == 0) {
		DLIST_REMOVE(sc_set->scs, sc);
		sc_set->scs_count--;
		talloc_free(sc);

		if (sc_set->scs_count == 0) {
			DLIST_REMOVE(fss_global.sc_sets, sc_set);
			fss_global.sc_sets_count--;
			talloc_free(sc_set);
		}
	}

	become_root();
	status = fss_state_store(fss_global.mem_ctx, fss_global.sc_sets,
				 fss_global.sc_sets_count, fss_global.db_path);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("failed to store fss server state: %s\n",
			  nt_errstr(status)));
	}

	status = NT_STATUS_OK;
err_tmp_free:
	TALLOC_FREE(frame);
	return fss_ntstatus_map(status);
}

uint32_t _fss_PrepareShadowCopySet(struct pipes_struct *p,
				   struct fss_PrepareShadowCopySet *r)
{
	struct fss_sc_set *sc_set;

	if (!fss_permitted(p)) {
		return HRES_ERROR_V(HRES_E_ACCESSDENIED);
	}

	sc_set = sc_set_lookup(fss_global.sc_sets, &r->in.ShadowCopySetId);
	if (sc_set == NULL) {
		return HRES_ERROR_V(HRES_E_INVALIDARG);
	}

	if (sc_set->state != FSS_SC_ADDED) {
		return FSRVP_E_BAD_STATE;
	}

	/* stop msg sequence timer */
	TALLOC_FREE(fss_global.seq_tmr);

	/*
	 * Windows Server "8" Beta takes ~60s here, presumably flushing
	 * everything to disk. We may want to do something similar.
	 */

	/* start msg sequence timer, 1800 on success */
	fss_seq_tout_set(fss_global.mem_ctx, 1800, sc_set, &fss_global.seq_tmr);

	return 0;
}

static NTSTATUS FileServerVssAgent__op_init_server(
		struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server);

static NTSTATUS FileServerVssAgent__op_shutdown_server(
		struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server);

#define DCESRV_INTERFACE_FILESERVERVSSAGENT_INIT_SERVER \
	fileservervssagent_init_server

#define DCESRV_INTERFACE_FILESERVERVSSAGENT_SHUTDOWN_SERVER \
	fileservervssagent_shutdown_server

static NTSTATUS fileservervssagent_shutdown_server(
		struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server)
{
	srv_fssa_cleanup();
	return FileServerVssAgent__op_shutdown_server(dce_ctx, ep_server);
}

static NTSTATUS fileservervssagent_init_server(
		struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server)
{
	NTSTATUS status;
	struct messaging_context *msg_ctx = global_messaging_context();

	status = srv_fssa_start(msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return FileServerVssAgent__op_init_server(dce_ctx, ep_server);
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_fsrvp_scompat.c"
