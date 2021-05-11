/*
 *  Unix SMB/CIFS implementation.
 *  libnet Join offline support
 *  Copyright (C) Guenther Deschner 2021
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
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

WERROR libnet_odj_compose_ODJ_PROVISION_DATA(TALLOC_CTX *mem_ctx,
					     const struct libnet_JoinCtx *r,
					     struct ODJ_PROVISION_DATA **b_p);
WERROR libnet_odj_find_win7blob(const struct ODJ_PROVISION_DATA *r,
				struct ODJ_WIN7BLOB *win7blob);
WERROR libnet_odj_find_joinprov3(const struct ODJ_PROVISION_DATA *r,
				 struct OP_JOINPROV3_PART *joinprov3);
