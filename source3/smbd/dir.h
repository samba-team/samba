/*
 * Unix SMB/Netbios implementation.
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

#ifndef _SOURCE3_SMBD_DIR_H_
#define _SOURCE3_SMBD_DIR_H_

#include "includes.h"

struct smb_Dir;
struct dptr_struct;

NTSTATUS can_delete_directory_hnd(struct smb_Dir *dir_hnd);
NTSTATUS can_delete_directory_fsp(files_struct *fsp);
struct files_struct *dir_hnd_fetch_fsp(struct smb_Dir *dir_hnd);
uint16_t dptr_attr(struct smbd_server_connection *sconn, int key);
bool dptr_case_sensitive(struct dptr_struct *dptr);
void dptr_closecnum(connection_struct *conn);
void dptr_CloseDir(files_struct *fsp);
NTSTATUS dptr_create(connection_struct *conn,
		     struct smb_request *req,
		     files_struct *fsp,
		     bool old_handle,
		     const char *wcard,
		     uint32_t attr,
		     struct dptr_struct **dptr_ret);
int dptr_dnum(struct dptr_struct *dptr);
files_struct *dptr_fetch_lanman2_fsp(struct smbd_server_connection *sconn,
				     int dptr_num);
unsigned int dptr_FileNumber(struct dptr_struct *dptr);
bool dptr_get_priv(struct dptr_struct *dptr);
bool dptr_has_wild(struct dptr_struct *dptr);
const char *dptr_path(struct smbd_server_connection *sconn, int key);
char *dptr_ReadDirName(TALLOC_CTX *ctx, struct dptr_struct *dptr);
void dptr_RewindDir(struct dptr_struct *dptr);
void dptr_set_priv(struct dptr_struct *dptr);
const char *dptr_wcard(struct smbd_server_connection *sconn, int key);
bool have_file_open_below(struct files_struct *fsp);
bool opens_below_forall(struct connection_struct *conn,
			const struct smb_filename *dir_name,
			int (*fn)(struct share_mode_data *data,
				  struct share_mode_entry *e,
				  void *private_data),
			void *private_data);
bool opens_below_forall_read(struct connection_struct *conn,
			     const struct smb_filename *dir_name,
			     int (*fn)(const struct share_mode_data *data,
				       const struct share_mode_entry *e,
				       void *private_data),
			     void *private_data);
bool init_dptrs(struct smbd_server_connection *sconn);
bool is_visible_fsp(files_struct *fsp);
NTSTATUS OpenDir(TALLOC_CTX *mem_ctx,
		 connection_struct *conn,
		 const struct smb_filename *smb_dname,
		 const char *mask,
		 uint32_t attr,
		 struct smb_Dir **_dir_hnd);
NTSTATUS OpenDir_from_pathref(TALLOC_CTX *mem_ctx,
			      struct files_struct *dirfsp,
			      const char *mask,
			      uint32_t attr,
			      struct smb_Dir **_dir_hnd);
const char *ReadDirName(struct smb_Dir *dir_hnd, char **talloced);
void RewindDir(struct smb_Dir *dir_hnd);
bool smbd_dirptr_get_entry(TALLOC_CTX *ctx,
			   struct dptr_struct *dirptr,
			   const char *mask,
			   uint32_t dirtype,
			   bool dont_descend,
			   bool get_dosmode,
			   bool (*match_fn)(TALLOC_CTX *ctx,
					    void *private_data,
					    const char *dname,
					    const char *mask,
					    char **_fname),
			   void *private_data,
			   char **_fname,
			   struct smb_filename **_smb_fname,
			   uint32_t *_mode);
char *smbd_dirptr_get_last_name_sent(struct dptr_struct *dirptr);
void smbd_dirptr_push_overflow(struct dptr_struct *dirptr,
			       char **_fname,
			       struct smb_filename **_smb_fname,
			       uint32_t mode);
void smbd_dirptr_set_last_name_sent(struct dptr_struct *dirptr, char **_fname);
#endif
