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
	uint16 vuid;
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

#endif /* _SMBD_SMBD_H */
