/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight client functions

   Copyright (C) Ralph Boehme 2019

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

#ifndef _MDSCLI_UTIL_H_
#define _MDSCLI_UTIL_H_

NTSTATUS mdscli_blob_search(TALLOC_CTX *mem_ctx,
			    struct mdscli_search_ctx *search,
			    struct mdssvc_blob *blob);

NTSTATUS mdscli_blob_get_results(TALLOC_CTX *mem_ctx,
				 struct mdscli_search_ctx *search,
				 struct mdssvc_blob *blob);

NTSTATUS mdscli_blob_get_path(TALLOC_CTX *mem_ctx,
			      struct mdscli_ctx *mdscli_ctx,
			      uint64_t cnid,
			      struct mdssvc_blob *blob);

NTSTATUS mdscli_blob_close_search(TALLOC_CTX *mem_ctx,
				  struct mdscli_search_ctx *search,
				  struct mdssvc_blob *blob);

#endif /* _MDSCLI_UTIL_H_ */
