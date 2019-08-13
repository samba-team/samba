/*
 *  Unix SMB/CIFS implementation.
 *  leases.tdb functions
 *
 *  Copyright (C) Volker Lendecke 2014
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LEASES_DB_H_
#define _LEASES_DB_H_

struct GUID;
struct smb2_lease_key;
struct file_id;
struct leases_db_file;

bool leases_db_init(bool read_only);
NTSTATUS leases_db_add(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id,
		       uint32_t current_state,
		       uint16_t lease_version,
		       uint16_t epoch,
		       const char *servicepath,
		       const char *filename,
		       const char *stream_name);
NTSTATUS leases_db_del(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id);
NTSTATUS leases_db_parse(const struct GUID *client_guid,
			 const struct smb2_lease_key *lease_key,
			 void (*parser)(uint32_t num_files,
					const struct leases_db_file *files,
					void *private_data),
			 void *private_data);
NTSTATUS leases_db_rename(const struct GUID *client_guid,
			const struct smb2_lease_key *lease_key,
			const struct file_id *id,
			const char *servicepath_new,
			const char *filename_new,
			const char *stream_name_new);
NTSTATUS leases_db_set(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       uint32_t current_state,
		       bool breaking,
		       uint32_t breaking_to_requested,
		       uint32_t	breaking_to_required,
		       uint16_t lease_version,
		       uint16_t epoch);
NTSTATUS leases_db_get(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *file_id,
		       uint32_t *current_state,
		       bool *breaking,
		       uint32_t *breaking_to_requested,
		       uint32_t	*breaking_to_required,
		       uint16_t *lease_version,
		       uint16_t *epoch);
NTSTATUS leases_db_get_current_state(
	const struct GUID *client_guid,
	const struct smb2_lease_key *lease_key,
	int *database_seqnum,
	uint32_t *current_state);
NTSTATUS leases_db_copy_file_ids(TALLOC_CTX *mem_ctx,
			uint32_t num_files,
			const struct leases_db_file *files,
			struct file_id **pp_ids);
#endif /* _LEASES_DB_H_ */
