/* 
   Unix SMB/CIFS implementation.

   endpoint server for the drsuapi pipe

   Copyright (C) Stefan Metzmacher 2004
   
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

/*
  this type allows us to distinguish handle types
*/
enum drsuapi_handle {
	DRSUAPI_BIND_HANDLE,
};

/*
  state asscoiated with a drsuapi_DsBind*() operation
*/
struct drsuapi_bind_state {
	struct ldb_context *sam_ctx;
	struct GUID remote_bind_guid;
	struct drsuapi_DsBindInfo28 remote_info28;
	struct drsuapi_DsBindInfo28 local_info28;
};
