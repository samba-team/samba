/*
 * File Server Remote VSS Protocol (FSRVP) persistent server state
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

#include "source3/include/includes.h"
#include <fcntl.h>
#include "source3/include/util_tdb.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_open.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_fsrvp_state.h"
#include "srv_fss_private.h"

#define FSS_DB_KEY_VERSION "db_version"
#define FSS_DB_KEY_CONTEXT "context"
#define FSS_DB_KEY_SC_SET_COUNT "sc_set_count"
#define FSS_DB_KEY_PFX_SC_SET "sc_set/"
#define FSS_DB_KEY_PFX_SC "sc/"
#define FSS_DB_KEY_PFX_SMAP "smap/"

static NTSTATUS fss_state_smap_store(TALLOC_CTX *mem_ctx,
				     struct db_context *db,
				     const char *sc_key_str,
				     struct fss_sc_smap *smap)
{
	NTSTATUS status;
	TDB_DATA val;
	const char *smap_key_str;
	struct fsrvp_state_smap smap_state;
	enum ndr_err_code ndr_ret;
	DATA_BLOB smap_state_blob;

	/* becomes sc_set/@sc_set_id/sc/@sc_id/smap/@sc_share_name */
	smap_key_str = talloc_asprintf(mem_ctx, "%s/%s%s", sc_key_str,
				       FSS_DB_KEY_PFX_SMAP,
				       smap->sc_share_name);
	if (smap_key_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	smap_state.share_name = smap->share_name;
	smap_state.sc_share_name = smap->sc_share_name;
	/* @smap->sc_share_comment may be null if not exposed. */
	if (smap->sc_share_comment != NULL) {
		smap_state.sc_share_comment = smap->sc_share_comment;
	} else {
		smap_state.sc_share_comment = "";
	}
	smap_state.is_exposed = smap->is_exposed;

	ndr_ret = ndr_push_struct_blob(&smap_state_blob, mem_ctx,
				       &smap_state,
				(ndr_push_flags_fn_t)ndr_push_fsrvp_state_smap);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	val.dsize = smap_state_blob.length;
	val.dptr = smap_state_blob.data;

	status = dbwrap_store(db, string_term_tdb_data(smap_key_str), val, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS fss_state_sc_store(TALLOC_CTX *mem_ctx,
				   struct db_context *db,
				   const char *sc_set_key_str,
				   struct fss_sc *sc)
{
	NTSTATUS status;
	TDB_DATA val;
	const char *sc_key_str;
	struct fsrvp_state_sc sc_state;
	struct fss_sc_smap *smap;
	enum ndr_err_code ndr_ret;
	DATA_BLOB sc_state_blob;

	/* becomes sc_set/@sc_set.id/sc/@sc_id */
	sc_key_str = talloc_asprintf(mem_ctx, "%s/%s%s", sc_set_key_str,
				     FSS_DB_KEY_PFX_SC, sc->id_str);
	if (sc_key_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sc_state.id_str = sc->id_str;
	sc_state.volume_name = sc->volume_name;
	/* @sc->sc_path may be null if not committed, store empty str */
	sc_state.sc_path = (sc->sc_path ? sc->sc_path : "");
	sc_state.create_ts = sc->create_ts;
	sc_state.smaps_count = sc->smaps_count;

	ndr_ret = ndr_push_struct_blob(&sc_state_blob, mem_ctx,
				       &sc_state,
				(ndr_push_flags_fn_t)ndr_push_fsrvp_state_sc);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	val.dsize = sc_state_blob.length;
	val.dptr = sc_state_blob.data;

	status = dbwrap_store(db, string_term_tdb_data(sc_key_str), val, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (smap = sc->smaps; smap; smap = smap->next) {
		status = fss_state_smap_store(mem_ctx, db, sc_key_str, smap);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS fss_state_sc_set_store(TALLOC_CTX *mem_ctx,
				       struct db_context *db,
				       struct fss_sc_set *sc_set)
{
	NTSTATUS status;
	TDB_DATA val;
	const char *sc_set_key_str;
	struct fss_sc *sc;
	struct fsrvp_state_sc_set sc_set_state;
	DATA_BLOB sc_set_state_blob;
	enum ndr_err_code ndr_ret;

	sc_set_key_str = talloc_asprintf(mem_ctx, "%s%s",
					 FSS_DB_KEY_PFX_SC_SET,
					 sc_set->id_str);
	if (sc_set_key_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sc_set_state.id_str = sc_set->id_str;
	sc_set_state.state = sc_set->state;
	sc_set_state.context = sc_set->context;
	sc_set_state.scs_count = sc_set->scs_count;

	ndr_ret = ndr_push_struct_blob(&sc_set_state_blob, mem_ctx,
				       &sc_set_state,
			(ndr_push_flags_fn_t)ndr_push_fsrvp_state_sc_set);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	val.dsize = sc_set_state_blob.length;
	val.dptr = sc_set_state_blob.data;

	status = dbwrap_store(db, string_term_tdb_data(sc_set_key_str), val, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (sc = sc_set->scs; sc; sc = sc->next) {
		status = fss_state_sc_store(mem_ctx, db, sc_set_key_str, sc);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

/*
 * write out the current fsrvp server state to a TDB. This clears any content
 * currently written to the TDB.
 */
_PRIVATE_ NTSTATUS fss_state_store(TALLOC_CTX *mem_ctx,
			 struct fss_sc_set *sc_sets,
			 uint32_t sc_sets_count,
			 const char *db_path)
{
	TALLOC_CTX *tmp_ctx;
	struct db_context *db;
	NTSTATUS status;
	int ret;
	struct fss_sc_set *sc_set;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	db = db_open(tmp_ctx, db_path, 0, TDB_DEFAULT,  O_RDWR | O_CREAT,
		     0600, DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (db == NULL) {
		DEBUG(0, ("Failed to open fss state database %s\n", db_path));
		status = NT_STATUS_ACCESS_DENIED;
		goto err_ctx_free;
	}

	ret = dbwrap_wipe(db);
	if (ret != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_db_free;
	}

	status = dbwrap_store_int32_bystring(db, FSS_DB_KEY_VERSION,
					     FSRVP_STATE_DB_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_db_free;
	}

	ret = dbwrap_transaction_start(db);
	if (ret != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_db_free;
	}

	status = dbwrap_store_int32_bystring(db, FSS_DB_KEY_SC_SET_COUNT,
					     sc_sets_count);
	if (!NT_STATUS_IS_OK(status)) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_trans_cancel;
	}

	for (sc_set = sc_sets; sc_set; sc_set = sc_set->next) {
		status = fss_state_sc_set_store(tmp_ctx, db, sc_set);
		if (!NT_STATUS_IS_OK(status)) {
			goto err_trans_cancel;
		}
	}

	ret = dbwrap_transaction_commit(db);
	if (ret != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_trans_cancel;
	}

	talloc_free(db);
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;

err_trans_cancel:
	dbwrap_transaction_cancel(db);
err_db_free:
	talloc_free(db);
err_ctx_free:
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS fss_state_smap_retrieve(TALLOC_CTX *mem_ctx,
					TDB_DATA *key,
					TDB_DATA *val,
					struct fss_sc_smap **smap_out)
{
	struct fss_sc_smap *smap;
	struct fsrvp_state_smap smap_state;
	DATA_BLOB smap_state_blob;
	enum ndr_err_code ndr_ret;

	smap_state_blob.length = val->dsize;
	smap_state_blob.data = val->dptr;

	ndr_ret = ndr_pull_struct_blob(&smap_state_blob, mem_ctx, &smap_state,
				(ndr_pull_flags_fn_t)ndr_pull_fsrvp_state_smap);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	smap = talloc_zero(mem_ctx, struct fss_sc_smap);
	if (smap == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	smap->share_name = talloc_strdup(smap, smap_state.share_name);
	if (smap->share_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* store the full path so that the hierarchy can be rebuilt */
	smap->sc_share_name = talloc_strdup(smap, (char *)key->dptr);
	if (smap->sc_share_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* sc_share_comment may be empty, keep null in such a case */
	if (strlen(smap_state.sc_share_comment) > 0) {
		smap->sc_share_comment = talloc_strdup(smap,
						smap_state.sc_share_comment);
		if (smap->sc_share_comment == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	smap->is_exposed = smap_state.is_exposed;

	*smap_out = smap;
	return NT_STATUS_OK;
}

static NTSTATUS fss_state_sc_retrieve(TALLOC_CTX *mem_ctx,
				      TDB_DATA *key,
				      TDB_DATA *val,
				      struct fss_sc **sc_out)
{
	struct fss_sc *sc;
	struct fsrvp_state_sc sc_state;
	DATA_BLOB sc_state_blob;
	enum ndr_err_code ndr_ret;

	sc_state_blob.length = val->dsize;
	sc_state_blob.data = val->dptr;

	ndr_ret = ndr_pull_struct_blob(&sc_state_blob, mem_ctx, &sc_state,
				(ndr_pull_flags_fn_t)ndr_pull_fsrvp_state_sc);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	sc = talloc_zero(mem_ctx, struct fss_sc);
	if (sc == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* store the full path so that the hierarchy can be rebuilt */
	sc->id_str = talloc_strdup(sc, (char *)key->dptr);
	if (sc->id_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sc->volume_name = talloc_strdup(sc, sc_state.volume_name);
	if (sc->volume_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* sc_path may be empty, keep null in such a case */
	if (strlen(sc_state.sc_path) > 0) {
		sc->sc_path = talloc_strdup(sc, sc_state.sc_path);
		if (sc->sc_path == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	sc->create_ts = sc_state.create_ts;
	sc->smaps_count = sc_state.smaps_count;

	*sc_out = sc;
	return NT_STATUS_OK;
}

static NTSTATUS fss_state_sc_set_retrieve(TALLOC_CTX *mem_ctx,
					  TDB_DATA *key,
					  TDB_DATA *val,
					  struct fss_sc_set **sc_set_out)
{
	struct fss_sc_set *sc_set;
	struct fsrvp_state_sc_set sc_set_state;
	DATA_BLOB sc_set_state_blob;
	enum ndr_err_code ndr_ret;

	sc_set_state_blob.length = val->dsize;
	sc_set_state_blob.data = val->dptr;

	ndr_ret = ndr_pull_struct_blob(&sc_set_state_blob, mem_ctx,
				       &sc_set_state,
			(ndr_pull_flags_fn_t)ndr_pull_fsrvp_state_sc_set);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	sc_set = talloc_zero(mem_ctx, struct fss_sc_set);
	if (sc_set == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* store the full path so that the hierarchy can be rebuilt */
	sc_set->id_str = talloc_strdup(sc_set, (char *)key->dptr);
	if (sc_set->id_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	sc_set->state = sc_set_state.state;
	sc_set->context = sc_set_state.context;
	sc_set->scs_count = sc_set_state.scs_count;

	*sc_set_out = sc_set;
	return NT_STATUS_OK;
}

struct fss_traverse_state {
	TALLOC_CTX *mem_ctx;
	struct fss_sc_smap *smaps;
	uint32_t smaps_count;
	struct fss_sc *scs;
	uint32_t scs_count;
	struct fss_sc_set *sc_sets;
	uint32_t sc_sets_count;
	NTSTATUS (*smap_retrieve)(TALLOC_CTX *mem_ctx,
				  TDB_DATA *key,
				  TDB_DATA *val,
				  struct fss_sc_smap **smap_out);
	NTSTATUS (*sc_retrieve)(TALLOC_CTX *mem_ctx,
				TDB_DATA *key,
				TDB_DATA *val,
				struct fss_sc **sc_out);
	NTSTATUS (*sc_set_retrieve)(TALLOC_CTX *mem_ctx,
				    TDB_DATA *key,
				    TDB_DATA *val,
				    struct fss_sc_set **sc_set_out);
};

static int fss_state_retrieve_traverse(struct db_record *rec,
				       void *private_data)
{
	NTSTATUS status;
	struct fss_traverse_state *trv_state
			= (struct fss_traverse_state *)private_data;
	TDB_DATA key = dbwrap_record_get_key(rec);
	TDB_DATA val = dbwrap_record_get_value(rec);

	/* order of checking is important here */
	if (strstr((char *)key.dptr, FSS_DB_KEY_PFX_SMAP) != NULL) {
		struct fss_sc_smap *smap;
		status = trv_state->smap_retrieve(trv_state->mem_ctx,
						  &key, &val, &smap);
		if (!NT_STATUS_IS_OK(status)) {
			return -1;
		}
		DLIST_ADD_END(trv_state->smaps, smap);
		trv_state->smaps_count++;
	} else if (strstr((char *)key.dptr, FSS_DB_KEY_PFX_SC) != NULL) {
		struct fss_sc *sc;
		status = trv_state->sc_retrieve(trv_state->mem_ctx,
						&key, &val, &sc);
		if (!NT_STATUS_IS_OK(status)) {
			return -1;
		}
		DLIST_ADD_END(trv_state->scs, sc);
		trv_state->scs_count++;
	} else if (strstr((char *)key.dptr, FSS_DB_KEY_PFX_SC_SET) != NULL) {
		struct fss_sc_set *sc_set;
		status = trv_state->sc_set_retrieve(trv_state->mem_ctx,
						    &key, &val, &sc_set);
		if (!NT_STATUS_IS_OK(status)) {
			return -1;
		}
		DLIST_ADD_END(trv_state->sc_sets, sc_set);
		trv_state->sc_sets_count++;
	} else {
		/* global context and db vers */
		DEBUG(4, ("Ignoring fss srv db entry with key %s\n", key.dptr));
	}

	return 0;
}

static bool fss_state_smap_is_child(struct fss_sc *sc,
				    struct fss_sc_smap *smap)
{
	return (strstr(smap->sc_share_name, sc->id_str) != NULL);
}

static NTSTATUS fss_state_hierarchize_smaps(struct fss_traverse_state *trv_state,
					    struct fss_sc *sc)
{
	struct fss_sc_smap *smap;
	struct fss_sc_smap *smap_n;
	uint32_t smaps_moved = 0;

	for (smap = trv_state->smaps; smap; smap = smap_n) {
		smap_n = smap->next;
		if (!fss_state_smap_is_child(sc, smap))
			continue;

		/* smap mem should be owned by parent sc */
		talloc_steal(sc, smap);
		DLIST_REMOVE(trv_state->smaps, smap);
		trv_state->smaps_count--;
		DLIST_ADD_END(sc->smaps, smap);
		smaps_moved++;

		/* last component of the tdb key path is the sc share name */
		SMB_ASSERT(strrchr(smap->sc_share_name, '/') != NULL);
		smap->sc_share_name = strrchr(smap->sc_share_name, '/') + 1;
	}

	if (sc->smaps_count != smaps_moved) {
		DEBUG(0, ("Inconsistent smaps_count, expected %u, moved %u\n",
			  sc->smaps_count, smaps_moved));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

static bool fss_state_sc_is_child(struct fss_sc_set *sc_set,
				  struct fss_sc *sc)
{
	return (strstr(sc->id_str, sc_set->id_str) != NULL);
}

static NTSTATUS fss_state_hierarchize_scs(struct fss_traverse_state *trv_state,
					  struct fss_sc_set *sc_set)
{
	NTSTATUS status;
	struct fss_sc *sc;
	struct fss_sc *sc_n;
	uint32_t scs_moved = 0;

	for (sc = trv_state->scs; sc; sc = sc_n) {
		sc_n = sc->next;
		if (!fss_state_sc_is_child(sc_set, sc))
			continue;

		/* sc mem should be owned by parent sc_set */
		talloc_steal(sc_set, sc);
		DLIST_REMOVE(trv_state->scs, sc);
		trv_state->scs_count--;
		DLIST_ADD_END(sc_set->scs, sc);
		scs_moved++;

		sc->sc_set = sc_set;

		/* last component of the tdb key path is the sc GUID str */
		SMB_ASSERT(strrchr(sc->id_str, '/') != NULL);
		sc->id_str = strrchr(sc->id_str, '/') + 1;

		status = GUID_from_string(sc->id_str, &sc->id);
		if (!NT_STATUS_IS_OK(status)) {
			goto err_out;
		}

		status = fss_state_hierarchize_smaps(trv_state, sc);
		if (!NT_STATUS_IS_OK(status)) {
			goto err_out;
		}
	}

	if (sc_set->scs_count != scs_moved) {
		DEBUG(0, ("Inconsistent scs_count, expected %u, moved %u\n",
			  sc_set->scs_count, scs_moved));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	return NT_STATUS_OK;

err_out:
	return status;
}

static NTSTATUS fss_state_hierarchize(struct fss_traverse_state *trv_state,
				      struct fss_sc_set **sc_sets,
				      uint32_t *sc_sets_count)
{
	NTSTATUS status;
	struct fss_sc_set *sc_set;
	struct fss_sc_set *sc_set_n;
	uint32_t i = 0;

	*sc_sets = NULL;
	for (sc_set = trv_state->sc_sets; sc_set; sc_set = sc_set_n) {
		sc_set_n = sc_set->next;
		/* sc_set mem already owned by trv_state->mem_ctx */
		DLIST_REMOVE(trv_state->sc_sets, sc_set);
		trv_state->sc_sets_count--;
		DLIST_ADD_END(*sc_sets, sc_set);
		i++;

		/* last component of the tdb key path is the sc_set GUID str */
		SMB_ASSERT(strrchr(sc_set->id_str, '/') != NULL);
		sc_set->id_str = strrchr(sc_set->id_str, '/') + 1;

		status = GUID_from_string(sc_set->id_str, &sc_set->id);
		if (!NT_STATUS_IS_OK(status)) {
			goto err_out;
		}

		status = fss_state_hierarchize_scs(trv_state, sc_set);
		if (!NT_STATUS_IS_OK(status)) {
			goto err_out;
		}
	}
	*sc_sets_count = i;
	return NT_STATUS_OK;

err_out:
	return status;
}

_PRIVATE_ NTSTATUS fss_state_retrieve(TALLOC_CTX *mem_ctx,
			    struct fss_sc_set **sc_sets,
			    uint32_t *sc_sets_count,
			    const char *db_path)
{
	struct db_context *db;
	NTSTATUS status;
	struct fss_traverse_state trv_state;
	int err;
	int rec_count;
	int vers;
	*sc_sets = NULL;
	*sc_sets_count = 0;

	memset(&trv_state, 0, sizeof(trv_state));
	trv_state.mem_ctx = talloc_new(mem_ctx);
	if (trv_state.mem_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}

	/* set callbacks for unmarshalling on-disk structures */
	trv_state.smap_retrieve = fss_state_smap_retrieve;
	trv_state.sc_retrieve = fss_state_sc_retrieve;
	trv_state.sc_set_retrieve = fss_state_sc_set_retrieve;

	db = db_open(trv_state.mem_ctx, db_path, 0, TDB_DEFAULT,
		     O_RDONLY, 0600, DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	err = errno;
	if ((db == NULL) && (err == ENOENT)) {
		DEBUG(4, ("fss state TDB does not exist for retrieval\n"));
		status = NT_STATUS_OK;
		goto err_ts_free;
	} else if (db == NULL) {
		DEBUG(0, ("Failed to open fss state TDB: %s\n",
			  strerror(err)));
		status = NT_STATUS_ACCESS_DENIED;
		goto err_ts_free;
	}

	status = dbwrap_fetch_int32_bystring(db, FSS_DB_KEY_VERSION,
					     &vers);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("failed to fetch version from fss state tdb: %s\n",
			  nt_errstr(status)));
		goto err_db_free;
	} else if (vers != FSRVP_STATE_DB_VERSION) {
		DEBUG(0, ("Unsupported fss tdb version %d, expected %d\n",
			  vers, FSRVP_STATE_DB_VERSION));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_db_free;
	}

	status = dbwrap_traverse_read(db,
				      fss_state_retrieve_traverse,
				      &trv_state,
				      &rec_count);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_db_free;
	}

	status = fss_state_hierarchize(&trv_state, sc_sets, sc_sets_count);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to form fss state hierarchy\n"));
		goto err_db_free;
	}

	/* check whether anything was left without a parent */
	if (trv_state.sc_sets_count != 0) {
		DEBUG(0, ("%d shadow copy set orphans in %s tdb\n",
			  trv_state.sc_sets_count, db_path));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_db_free;
	}
	if (trv_state.scs_count != 0) {
		DEBUG(0, ("%d shadow copy orphans in %s tdb\n",
			  trv_state.scs_count, db_path));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_db_free;
	}
	if (trv_state.smaps_count != 0) {
		DEBUG(0, ("%d share map orphans in %s tdb\n",
			  trv_state.smaps_count, db_path));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_db_free;
	}
	talloc_free(db);

	return NT_STATUS_OK;

err_db_free:
	talloc_free(db);
err_ts_free:
	talloc_free(trv_state.mem_ctx);
err_out:
	return status;
}
