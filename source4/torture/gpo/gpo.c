/*
   Unix SMB/CIFS implementation.

   Copyright (C) David Mulder 2017

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
#include "torture/smbtorture.h"
#include "torture/gpo/proto.h"

NTSTATUS torture_gpo_init(TALLOC_CTX *ctx)
{
    struct torture_suite *suite = torture_suite_create(ctx, "gpo");

    torture_suite_add_suite(suite, gpo_apply_suite(suite));

    suite->description = talloc_strdup(suite, "Group Policy tests");

    torture_register_suite(ctx, suite);

    return NT_STATUS_OK;
}
