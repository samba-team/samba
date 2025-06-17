/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Stefan Metzmacher 2012
 * Copyright (C) Michael Adam 2012
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

#ifndef __SMBXSRV_OPEN_H__
#define __SMBXSRV_OPEN_H__

#include "replace.h"
#include "libcli/util/ntstatus.h"
#include "lib/util/time.h"
#include "lib/util/data_blob.h"
#include "librpc/gen_ndr/misc.h"

struct smbXsrv_connection;
struct auth_session_info;
struct smbXsrv_open;
struct smbXsrv_open_global0;
struct smbXsrv_client;

NTSTATUS smbXsrv_open_global_init(void);
NTSTATUS smbXsrv_open_create(struct smbXsrv_connection *conn,
			     struct smbXsrv_session *session,
			     struct smbXsrv_tcon *tcon,
			     NTTIME now,
			     struct smbXsrv_open **_open);
NTSTATUS smbXsrv_open_update(struct smbXsrv_open *_open);
NTSTATUS smbXsrv_open_close(struct smbXsrv_open *op, NTTIME now);
NTSTATUS smb1srv_open_table_init(struct smbXsrv_connection *conn);
NTSTATUS smb1srv_open_lookup(struct smbXsrv_connection *conn,
			     uint16_t fnum, NTTIME now,
			     struct smbXsrv_open **_open);
NTSTATUS smb2srv_open_table_init(struct smbXsrv_connection *conn);
NTSTATUS smb2srv_open_lookup(struct smbXsrv_connection *conn,
			     uint64_t persistent_id,
			     uint64_t volatile_id,
			     NTTIME now,
			     struct smbXsrv_open **_open);
NTSTATUS smbXsrv_open_purge_replay_cache(struct smbXsrv_client *client,
					 const struct GUID *create_guid);
NTSTATUS smb2srv_open_lookup_replay_cache(struct smbXsrv_connection *conn,
					  struct smbXsrv_session *session,
					  struct GUID create_guid,
					  const char *name,
					  NTTIME now,
					  uint64_t *persistent_id,
					  struct smbXsrv_open **_open);
struct smb2_lease_key;
NTSTATUS smb2srv_open_recreate(struct smbXsrv_connection *conn,
			       struct smbXsrv_session *session,
			       struct smbXsrv_tcon *tcon,
			       uint64_t persistent_id,
			       const struct GUID *create_guid,
			       const struct smb2_lease_key *lease_key,
			       NTTIME now,
			       struct smbXsrv_open **_open);

struct db_record;
NTSTATUS smbXsrv_open_global_traverse(
	int (*fn)(struct db_record *rec,
		  struct smbXsrv_open_global0 *global,
		  void *private_data),
	void *private_data);

NTSTATUS smbXsrv_open_cleanup(uint64_t persistent_id);
NTSTATUS smbXsrv_replay_cleanup(const struct GUID *client_guid,
				const struct GUID *create_guid);

#endif
