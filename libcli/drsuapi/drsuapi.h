/* 
   Unix SMB/CIFS implementation.
   Helper functions for applying replicated objects
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
    
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

WERROR drsuapi_decrypt_attribute(TALLOC_CTX *mem_ctx, 
				 const DATA_BLOB *gensec_skey,
				 uint32_t rid,
				 uint32_t dsdb_repl_flags,
				 struct drsuapi_DsReplicaAttribute *attr);


WERROR drsuapi_encrypt_attribute(TALLOC_CTX *mem_ctx, 
				 const DATA_BLOB *gensec_skey,
				 uint32_t rid,
				 struct drsuapi_DsReplicaAttribute *attr);
