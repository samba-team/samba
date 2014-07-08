/*
   Unix SMB/CIFS implementation.

   vfs_fruit tests

   Copyright (C) Ralph Boehme 2014

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

#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "torture/vfs/proto.h"

/*
 * Note: This test depends on "vfs objects = catia fruit
 * streams_xattr".  Note: To run this test, use
 * "--option=torture:share1=<SHARENAME1>
 * --option=torture:share2=<SHARENAME2>
 * --option=torture:localpath=<SHAREPATH>"
 */
struct torture_suite *torture_vfs_fruit(void)
{
	struct torture_suite *suite = torture_suite_create(
		talloc_autofree_context(), "fruit");

	suite->description = talloc_strdup(suite, "vfs_fruit tests");

	return suite;
}
