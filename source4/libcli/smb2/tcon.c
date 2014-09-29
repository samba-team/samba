/* 
   Unix SMB/CIFS implementation.

   SMB2 client tree handling

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "../libcli/smb/smbXcli_base.h"

/*
  initialise a smb2_session structure
 */
struct smb2_tree *smb2_tree_init(struct smb2_session *session,
				 TALLOC_CTX *parent_ctx, bool primary)
{
	struct smb2_tree *tree;

	tree = talloc_zero(parent_ctx, struct smb2_tree);
	if (!session) {
		return NULL;
	}
	if (primary) {
		tree->session = talloc_steal(tree, session);
	} else {
		tree->session = talloc_reference(tree, session);
	}

	tree->smbXcli = smbXcli_tcon_create(tree);
	if (tree->smbXcli == NULL) {
		talloc_free(tree);
		return NULL;
	}

	return tree;
}
