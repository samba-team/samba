/*
   Unix SMB/CIFS implementation.
   Main SMB server routines

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

#ifndef _SMBD_SMBD_H
#define _SMBD_SMBD_H

struct dptr_struct;

#include "smb_acls.h"
#include "vfs.h"
#include "smbd/proto.h"
#include "locking/proto.h"

/*
 * Pathnames used if request done
 * under privilege.
 */
struct privilege_paths {
	struct smb_filename parent_name;
	struct smb_filename file_name;
};

struct trans_state {
	struct trans_state *next, *prev;
	uint64_t vuid; /* SMB2 compat */
	uint64_t mid;

	uint32 max_param_return;
	uint32 max_data_return;
	uint32 max_setup_return;

	uint8 cmd;		/* SMBtrans or SMBtrans2 */

	char *name;		/* for trans requests */
	uint16 call;		/* for trans2 and nttrans requests */

	bool close_on_completion;
	bool one_way;

	unsigned int setup_count;
	uint16 *setup;

	size_t received_data;
	size_t received_param;

	size_t total_param;
	char *param;

	size_t total_data;
	char *data;
};

/*
 * unix_convert_flags
 */
#define UCF_SAVE_LCOMP			0x00000001
#define UCF_ALWAYS_ALLOW_WCARD_LCOMP	0x00000002
#define UCF_COND_ALLOW_WCARD_LCOMP	0x00000004
#define UCF_POSIX_PATHNAMES		0x00000008
#define UCF_UNIX_NAME_LOOKUP		0x00000010
#define UCF_PREP_CREATEFILE		0x00000020

#endif /* _SMBD_SMBD_H */
