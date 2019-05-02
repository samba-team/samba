/*
   Unix SMB/CIFS implementation.
   mdssvc client functions

   Copyright (C) Ralph Boehme			2019

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

#ifndef _MDSCLI_PRIVATE_H_
#define _MDSCLI_PRIVATE_H_

struct mdsctx_id {
	uint64_t id;
	uint64_t connection;
};

struct mdscli_ctx {
	uint64_t async_pending;

	struct dcerpc_binding_handle *bh;
	struct policy_handle ph;

	struct mdsctx_id ctx_id;
	size_t max_fragment_size;

	/* Known fields used across multiple commands */
	uint32_t dev;
	uint32_t flags;

	/* cmd specific or unknown fields */
	struct {
		char share_path[1025];
		uint32_t unkn2;
		uint32_t unkn3;
	} mdscmd_open;
	struct {
		uint32_t status;
		uint32_t unkn7;
	} mdscmd_unknown1;
	struct {
		uint32_t fragment;
		uint32_t unkn9;
	} mdscmd_cmd;
	struct {
		uint32_t status;
	} mdscmd_close;
};

struct mdscli_search_ctx {
	struct mdscli_ctx *mdscli_ctx;
	struct mdsctx_id ctx_id;
	uint64_t unique_id;
	bool live;
	char *path_scope;
	char *mds_query;
};

#endif /* _MDSCLI_PRIVATE_H_ */
